use std::path::Path;

use tracing::{debug, info, warn};

use innerwarden_dna::anomaly::AnomalyDetector;
use innerwarden_dna::attack_chain::AttackChainTracker;
use innerwarden_dna::classifier;
use innerwarden_dna::fingerprint;
use innerwarden_dna::sequence::*;
use innerwarden_dna::store::DnaStore;

use crate::correlation_engine;

/// State for inline DNA processing within the agent.
pub(crate) struct DnaState {
    pub store: DnaStore,
    pub anomaly_detector: AnomalyDetector,
    pub chain_tracker: AttackChainTracker,
    sessions: std::collections::HashMap<String, BehaviorSequence>,
    min_sequence: usize,
    session_timeout_secs: i64,
    /// Inverted index: fuzzy_hash → list of IPs that exhibited this behavior.
    /// Used for cross-IP tracking: same attacker, different IP.
    pub dna_ip_index: std::collections::HashMap<String, Vec<String>>,
}

impl DnaState {
    pub fn new(
        dna_dir: &Path,
        min_sequence: usize,
        anomaly_threshold: f64,
        session_timeout_secs: i64,
    ) -> Self {
        std::fs::create_dir_all(dna_dir).ok();
        let store = DnaStore::load(dna_dir).expect("dna: failed to initialize store");
        // Spec 037 I-07 slice 4: rebuild `dna_ip_index` from the
        // already-persisted `DnaStore` instead of resetting to empty.
        // Pre-PR every restart wiped cross-IP rotation memory, so an
        // attacker pivoting IPs during a restart window escaped the
        // `dna.ip_rotation` correlation event. The rebuild is purely
        // derived (no new persistence) — `ThreatDna.source_ip` +
        // `ThreatDna.fuzzy_hash` are already on disk; we just group
        // them at boot.
        let dna_ip_index = rebuild_ip_index(&store);
        Self {
            store,
            anomaly_detector: AnomalyDetector::with_config(dna_dir, 100, anomaly_threshold),
            chain_tracker: AttackChainTracker::load(dna_dir),
            sessions: std::collections::HashMap::new(),
            min_sequence,
            session_timeout_secs,
            dna_ip_index,
        }
    }
}

/// Rebuild the `fuzzy_hash → [source_ip]` inverted index from the
/// persisted `DnaStore`. Spec 037 I-07 slice 4 — purely derived warm
/// cache; no new storage path is added.
///
/// Cap behaviour: the runtime path in `process_events` enforces a
/// 50-IPs-per-fuzzy-hash cap via a front-drain. The rebuild does NOT
/// re-enforce that cap — `DnaStore` is bounded at 10_000 entries, so
/// the worst-case rebuilt index is bounded too, and the runtime path
/// will evict on the next growth event for any over-cap bucket. The
/// alternative (apply the cap at rebuild) would require an arbitrary
/// "which 50?" choice since `DnaStore::all()` returns a HashMap
/// iteration with no insertion-order guarantee — accepting temporary
/// over-cap is simpler and converges to the same steady state.
///
/// Empty `source_ip` entries are skipped: the runtime path only
/// builds `BehaviorSequence`s for events that resolved a source IP
/// (`dna_inline.rs` line ~95), so on disk this should be vanishingly
/// rare, but the defensive skip keeps a stale row from a previous
/// agent version from polluting the index with a blank-string key.
pub(crate) fn rebuild_ip_index(store: &DnaStore) -> std::collections::HashMap<String, Vec<String>> {
    let mut index: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for dna in store.all() {
        if dna.source_ip.is_empty() {
            continue;
        }
        let ips = index.entry(dna.fuzzy_hash.clone()).or_default();
        if !ips.contains(&dna.source_ip) {
            ips.push(dna.source_ip.clone());
        }
    }
    index
}

/// Process sensor events through the DNA engine.
/// Builds behavioral sequences, fingerprints them, detects anomalies,
/// and feeds the correlation engine.
/// `attacker_profiles` is used for cross-IP risk score inheritance when
/// DNA detects the same attacker on a new IP.
pub(crate) fn process_events(
    dna: &mut DnaState,
    events: &[innerwarden_core::event::Event],
    correlation_engine: &mut correlation_engine::CorrelationEngine,
    attacker_profiles: &mut std::collections::HashMap<
        String,
        crate::attacker_intel::AttackerProfile,
    >,
) {
    let now = chrono::Utc::now();

    for event in events {
        // Extract atom from event.
        let Some((source_ip, atom, atom_key, comm)) = event_to_atom(event) else {
            continue;
        };

        // Feed anomaly detector with per-process behavior.
        if !comm.is_empty() {
            let alerts =
                dna.anomaly_detector
                    .process_events(&comm, std::slice::from_ref(&atom_key), now);
            for alert in &alerts {
                let kind = match alert.alert_type {
                    innerwarden_dna::anomaly::AnomalyType::BehaviorDeviation => {
                        "dna.behavior_deviation"
                    }
                    innerwarden_dna::anomaly::AnomalyType::RateSpike => "dna.rate_spike",
                    innerwarden_dna::anomaly::AnomalyType::NewBehavior => "dna.new_behavior",
                };
                let corr = correlation_engine::CorrelationEngine::dna_event(
                    kind,
                    serde_json::json!({
                        "comm": alert.comm,
                        "score": alert.score,
                        "details": alert.details,
                    }),
                );
                correlation_engine.observe(corr);
            }
        }

        // Build/update behavior session by source IP.
        if let Some(ref ip) = source_ip {
            let session = dna
                .sessions
                .entry(ip.clone())
                .or_insert_with(|| BehaviorSequence {
                    source_ip: ip.clone(),
                    atoms: Vec::new(),
                    first_seen: event.ts,
                    last_seen: event.ts,
                    pids: Vec::new(),
                });
            session.atoms.push(atom);
            session.last_seen = event.ts;
        }
    }

    // Close stale sessions and fingerprint them.
    let timeout = chrono::Duration::seconds(dna.session_timeout_secs);
    let stale_ips: Vec<String> = dna
        .sessions
        .iter()
        .filter(|(_, s)| now - s.last_seen > timeout)
        .map(|(ip, _)| ip.clone())
        .collect();

    for ip in stale_ips {
        if let Some(session) = dna.sessions.remove(&ip) {
            if session.atoms.len() >= dna.min_sequence {
                let mut threat_dna = fingerprint::fingerprint(&session);
                classifier::classify(&mut threat_dna);

                // Cross-IP tracking: check if this behavioral fingerprint
                // was seen from a different IP (attacker IP rotation).
                let fuzzy = &threat_dna.fuzzy_hash;
                let known_ips = dna.dna_ip_index.entry(fuzzy.clone()).or_default();

                if !known_ips.contains(&ip) {
                    // Check if OTHER IPs had this same behavior
                    let previous_ips: Vec<String> = known_ips
                        .iter()
                        .filter(|prev| *prev != &ip)
                        .cloned()
                        .collect();

                    if !previous_ips.is_empty() {
                        // Inherit risk score from the highest-risk previous IP.
                        let mut inherited_risk: u8 = 0;
                        let mut inherited_detectors: Vec<String> = Vec::new();
                        for prev_ip in &previous_ips {
                            if let Some(prev_profile) = attacker_profiles.get(prev_ip) {
                                if prev_profile.risk_score > inherited_risk {
                                    inherited_risk = prev_profile.risk_score;
                                }
                                for d in &prev_profile.detectors_triggered {
                                    if !inherited_detectors.contains(d) {
                                        inherited_detectors.push(d.clone());
                                    }
                                }
                            }
                        }

                        // Apply inheritance to the new IP's profile.
                        if inherited_risk > 0 {
                            let new_profile =
                                attacker_profiles.entry(ip.clone()).or_insert_with(|| {
                                    crate::attacker_intel::new_profile(&ip, chrono::Utc::now())
                                });
                            // Floor: new IP starts at least at the previous risk level.
                            if new_profile.risk_score < inherited_risk {
                                new_profile.risk_score = inherited_risk;
                            }
                            // Inherit detector knowledge.
                            for d in &inherited_detectors {
                                new_profile.detectors_triggered.insert(d.clone());
                            }
                            info!(
                                new_ip = %ip,
                                inherited_risk,
                                inherited_detectors = ?inherited_detectors,
                                "dna: risk score inherited from previous IP"
                            );
                        }

                        info!(
                            new_ip = %ip,
                            previous_ips = ?previous_ips,
                            fuzzy_hash = %fuzzy,
                            "dna: IP rotation detected — same behavioral DNA from different IP"
                        );

                        // Emit correlation event for cross-IP tracking.
                        let corr = correlation_engine::CorrelationEngine::dna_event(
                            "dna.ip_rotation",
                            serde_json::json!({
                                "new_ip": ip,
                                "previous_ips": previous_ips,
                                "fuzzy_hash": fuzzy,
                                "atoms_count": session.atoms.len(),
                                "inherited_risk": inherited_risk,
                            }),
                        );
                        correlation_engine.observe(corr);
                    }

                    known_ips.push(ip.clone());
                    // Cap index entries per hash
                    if known_ips.len() > 50 {
                        known_ips.drain(0..known_ips.len() - 50);
                    }
                }

                let is_new = dna.store.insert(threat_dna);
                if is_new {
                    debug!(ip = %ip, "dna: new behavioral fingerprint captured");
                }
            }
        }
    }
}

/// Process incidents through the MITRE ATT&CK chain tracker.
pub(crate) fn process_incidents(
    dna: &mut DnaState,
    incidents: &[innerwarden_core::incident::Incident],
    correlation_engine: &mut correlation_engine::CorrelationEngine,
) {
    for incident in incidents {
        // Extract detector from incident_id (format: "detector:detail:...")
        let detector = incident.incident_id.split(':').next().unwrap_or("");
        if detector.is_empty() {
            continue;
        }

        // Extract IP from entities.
        let ip = incident
            .entities
            .iter()
            .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
            .map(|e| e.value.clone())
            .unwrap_or_default();
        if ip.is_empty() {
            continue;
        }

        let advanced = dna
            .chain_tracker
            .ingest_incident(&ip, detector, incident.ts);
        if advanced {
            if let Some(chain) = dna.chain_tracker.get_chain(&ip) {
                let kind = format!(
                    "dna.attack_chain.{}",
                    chain.chain_level.to_string().to_lowercase()
                );
                let corr = correlation_engine::CorrelationEngine::dna_event(
                    &kind,
                    serde_json::json!({
                        "ip": ip,
                        "chain_score": chain.chain_score,
                        "tactics_count": chain.tactics_observed.len(),
                        "total_incidents": chain.total_incidents,
                    }),
                );
                correlation_engine.observe(corr);
            }
        }
    }
}

/// Persist DNA state to disk (called periodically).
pub(crate) fn save(dna: &DnaState) {
    if let Err(e) = dna.store.save() {
        warn!(error = %e, "dna: failed to save store");
    }
    if let Err(e) = dna.anomaly_detector.save() {
        warn!(error = %e, "dna: failed to save anomaly profiles");
    }
    if let Err(e) = dna.chain_tracker.save() {
        warn!(error = %e, "dna: failed to save attack chains");
    }
}

/// Convert a core Event to an atom + metadata for DNA processing.
fn event_to_atom(
    event: &innerwarden_core::event::Event,
) -> Option<(Option<String>, Atom, String, String)> {
    let details = &event.details;
    let kind = event.kind.as_str();

    // Spec 037 I-15: trim + filter empty/whitespace so DNA fingerprints
    // never key on an unactionable "" IP, which would collapse multiple
    // distinct attackers into a single fake DNA bucket.
    let source_ip = details
        .get("src_ip")
        .or_else(|| details.get("ip"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| {
            event
                .entities
                .iter()
                .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
                .map(|e| e.value.trim().to_string())
                .filter(|s| !s.is_empty())
        });

    let comm = details
        .get("comm")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let (atom, atom_key) = match kind {
        "shell.command_exec" | "process.exec" => {
            let cmd = details
                .get("cmdline")
                .or_else(|| details.get("comm"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let category = classify_exec(cmd);
            let key = format!("exec:{category:?}");
            (Atom::Exec { category }, key)
        }
        "network.outbound_connect" | "network.connection" => {
            let port = details
                .get("port")
                .or_else(|| details.get("dst_port"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u16;
            let port_class = classify_port(port);
            let key = format!("connect:{port_class:?}");
            (Atom::Connect { port_class }, key)
        }
        "file.read_access" | "file.open" => {
            let path = details
                .get("path")
                .or_else(|| details.get("filename"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let sensitivity = classify_file(path);
            let key = format!("file:{sensitivity:?}");
            (Atom::FileAccess { sensitivity }, key)
        }
        "auth.login_success" => {
            let key = "login:success".to_string();
            (Atom::Login { success: true }, key)
        }
        "auth.login_failure" => {
            let key = "login:failure".to_string();
            (Atom::Login { success: false }, key)
        }
        "privilege.escalation" => {
            let key = "privesc".to_string();
            (Atom::PrivEsc, key)
        }
        _ => return None,
    };

    Some((source_ip, atom, atom_key, comm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::{entities::EntityRef, event::Event};
    use innerwarden_dna::fingerprint::ThreatDna;
    use tempfile::TempDir;

    fn event(kind: &str, details: serde_json::Value, entities: Vec<EntityRef>) -> Event {
        Event {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            source: "test".to_string(),
            kind: kind.to_string(),
            summary: "test event".to_string(),
            severity: innerwarden_core::event::Severity::Info,
            details,
            tags: Vec::new(),
            entities,
        }
    }

    fn dna_store_with_entries(entries: Vec<ThreatDna>) -> (TempDir, DnaStore) {
        let dir = TempDir::new().expect("tempdir");
        let mut store = DnaStore::load(dir.path()).expect("load fresh store");
        for dna in entries {
            store.insert(dna);
        }
        (dir, store)
    }

    fn mk_dna(fuzzy: &str, source_ip: &str, exact_suffix: &str) -> ThreatDna {
        let now = chrono::Utc::now();
        ThreatDna {
            // `exact_hash` is the HashMap key inside DnaStore — must
            // be unique per row or `insert` will treat the row as a
            // duplicate update.
            exact_hash: format!("{fuzzy}-{source_ip}-{exact_suffix}"),
            fuzzy_hash: fuzzy.to_string(),
            length: 5,
            atoms: Vec::new(),
            source_ip: source_ip.to_string(),
            first_seen: now,
            last_seen: now,
            seen_count: 1,
            classification: None,
        }
    }

    // ── Spec 037 I-07 slice 4 — `rebuild_ip_index` warm-cache anchors ──
    //
    // Slice 4 makes `dna_ip_index` survive a restart by deriving it
    // from the already-persisted `DnaStore` at boot, instead of
    // adding a new persistence path. These anchors pin the rebuild
    // contract:
    //
    //   1. Empty store → empty index (degraded fallback; pre-PR
    //      behaviour preserved).
    //   2. Multiple ThreatDna entries with the same fuzzy_hash but
    //      different source_ips group together — this is the property
    //      the cross-IP rotation detection relies on.
    //   3. Repeated source_ip across multiple ThreatDna rows is
    //      deduped in the resulting Vec — the runtime `process_events`
    //      contract is "each IP appears at most once per fuzzy hash".
    //   4. ThreatDna with empty `source_ip` is skipped — defensive
    //      against a stale row from a previous agent version
    //      polluting the index with a blank-string key.

    #[test]
    fn event_to_atom_converts_supported_event_kinds_and_prefers_trimmed_details_ip() {
        let cases = [
            (
                "shell.command_exec",
                serde_json::json!({"src_ip":" 203.0.113.10 ","cmdline":"cat /etc/shadow","comm":"bash"}),
                "exec:Other",
                "bash",
            ),
            (
                "process.exec",
                serde_json::json!({"ip":"198.51.100.10","comm":"/bin/sh"}),
                "exec:Shell",
                "/bin/sh",
            ),
            (
                "network.outbound_connect",
                serde_json::json!({"src_ip":"203.0.113.11","dst_port":22}),
                "connect:Ssh",
                "",
            ),
            (
                "network.connection",
                serde_json::json!({"src_ip":"203.0.113.12","port":443}),
                "connect:Http",
                "",
            ),
            (
                "file.read_access",
                serde_json::json!({"src_ip":"203.0.113.13","path":"/etc/passwd"}),
                "file:Credentials",
                "",
            ),
            (
                "file.open",
                serde_json::json!({"src_ip":"203.0.113.14","filename":"/tmp/note.txt"}),
                "file:Tmp",
                "",
            ),
            (
                "auth.login_success",
                serde_json::json!({"src_ip":"203.0.113.15"}),
                "login:success",
                "",
            ),
            (
                "auth.login_failure",
                serde_json::json!({"src_ip":"203.0.113.16"}),
                "login:failure",
                "",
            ),
            (
                "privilege.escalation",
                serde_json::json!({"src_ip":"203.0.113.17"}),
                "privesc",
                "",
            ),
        ];

        for (kind, details, expected_key, expected_comm) in cases {
            let (source_ip, _atom, atom_key, comm) =
                event_to_atom(&event(kind, details, Vec::new())).expect("supported event kind");
            assert_eq!(atom_key, expected_key, "kind {kind}");
            assert_eq!(comm, expected_comm, "kind {kind}");
            assert!(source_ip
                .as_deref()
                .expect("details IP should be present")
                .starts_with(|c: char| c.is_ascii_digit()));
        }
    }

    #[test]
    fn event_to_atom_uses_entity_ip_when_details_ip_is_blank() {
        let ev = event(
            "auth.login_failure",
            serde_json::json!({"src_ip":"   "}),
            vec![EntityRef::ip(" 198.51.100.25 ")],
        );
        let (source_ip, _atom, atom_key, _comm) = event_to_atom(&ev).expect("login failure atom");

        assert_eq!(source_ip.as_deref(), Some("198.51.100.25"));
        assert_eq!(atom_key, "login:failure");
    }

    #[test]
    fn event_to_atom_ignores_unknown_event_kind() {
        let ev = event(
            "dns.query",
            serde_json::json!({"src_ip":"203.0.113.30","query":"example.test"}),
            Vec::new(),
        );

        assert!(event_to_atom(&ev).is_none());
    }

    #[test]
    fn rebuild_dna_ip_index_is_empty_on_fresh_store() {
        let (_dir, store) = dna_store_with_entries(Vec::new());
        let index = rebuild_ip_index(&store);
        assert!(
            index.is_empty(),
            "fresh store MUST yield an empty rebuilt index — pre-PR boot behaviour"
        );
    }

    #[test]
    fn rebuild_dna_ip_index_groups_ips_by_fuzzy_hash() {
        // Two ThreatDna entries share fuzzy_hash "fhA" but came from
        // different IPs — the cross-IP rotation case the runtime
        // path is built to detect. After rebuild, both IPs MUST sit
        // in the same Vec under "fhA".
        let entries = vec![
            mk_dna("fhA", "203.0.113.1", "ex1"),
            mk_dna("fhA", "203.0.113.2", "ex2"),
            mk_dna("fhB", "198.51.100.5", "ex3"),
        ];
        let (_dir, store) = dna_store_with_entries(entries);
        let index = rebuild_ip_index(&store);

        let fha_ips = index.get("fhA").expect("fhA bucket must exist");
        assert_eq!(
            fha_ips.len(),
            2,
            "both IPs sharing fuzzy_hash fhA must land in the same bucket"
        );
        assert!(fha_ips.contains(&"203.0.113.1".to_string()));
        assert!(fha_ips.contains(&"203.0.113.2".to_string()));

        let fhb_ips = index.get("fhB").expect("fhB bucket must exist");
        assert_eq!(fhb_ips.len(), 1);
        assert_eq!(fhb_ips[0], "198.51.100.5");
    }

    #[test]
    fn rebuild_dna_ip_index_dedupes_repeated_source_ip() {
        // Same IP can appear in multiple ThreatDna rows for the same
        // fuzzy_hash (e.g. behaviour repeated across sessions and
        // re-fingerprinted). The rebuilt Vec MUST list it once,
        // matching the runtime `process_events` contract that uses
        // `if !known_ips.contains(&ip) { known_ips.push(ip) }` to
        // dedupe at insertion time.
        let entries = vec![
            mk_dna("fhDup", "203.0.113.42", "ex1"),
            mk_dna("fhDup", "203.0.113.42", "ex2"),
            mk_dna("fhDup", "203.0.113.42", "ex3"),
        ];
        let (_dir, store) = dna_store_with_entries(entries);
        let index = rebuild_ip_index(&store);

        let ips = index.get("fhDup").expect("fhDup bucket must exist");
        assert_eq!(
            ips.len(),
            1,
            "repeated source_ip across rows must dedupe to a single Vec entry"
        );
        assert_eq!(ips[0], "203.0.113.42");
    }

    #[test]
    fn rebuild_dna_ip_index_skips_empty_source_ip() {
        // A stale row from a previous agent version with an empty
        // source_ip MUST NOT pollute the index with a blank-string
        // entry. Defensive: today's runtime path filters such rows
        // before they reach the store, but rebuild reads whatever
        // is on disk.
        let entries = vec![
            mk_dna("fhA", "", "blank"),
            mk_dna("fhA", "203.0.113.7", "valid"),
        ];
        let (_dir, store) = dna_store_with_entries(entries);
        let index = rebuild_ip_index(&store);

        let ips = index.get("fhA").expect("fhA bucket must exist");
        assert_eq!(
            ips.len(),
            1,
            "empty source_ip row must be skipped, valid sibling must still load"
        );
        assert_eq!(ips[0], "203.0.113.7");
        assert!(
            !ips.contains(&String::new()),
            "blank-string IP must NEVER appear in the rebuilt Vec"
        );
    }
}
