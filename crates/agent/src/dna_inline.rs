use std::path::Path;

use tracing::{debug, warn};

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
}

impl DnaState {
    pub fn new(
        dna_dir: &Path,
        min_sequence: usize,
        anomaly_threshold: f64,
        session_timeout_secs: i64,
    ) -> Self {
        std::fs::create_dir_all(dna_dir).ok();
        Self {
            store: DnaStore::load(dna_dir).expect("dna: failed to initialize store"),
            anomaly_detector: AnomalyDetector::with_config(dna_dir, 100, anomaly_threshold),
            chain_tracker: AttackChainTracker::load(dna_dir),
            sessions: std::collections::HashMap::new(),
            min_sequence,
            session_timeout_secs,
        }
    }
}

/// Process sensor events through the DNA engine.
/// Builds behavioral sequences, fingerprints them, detects anomalies,
/// and feeds the correlation engine.
pub(crate) fn process_events(
    dna: &mut DnaState,
    events: &[innerwarden_core::event::Event],
    correlation_engine: &mut correlation_engine::CorrelationEngine,
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

    let source_ip = details
        .get("src_ip")
        .or_else(|| details.get("ip"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            event
                .entities
                .iter()
                .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
                .map(|e| e.value.clone())
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
