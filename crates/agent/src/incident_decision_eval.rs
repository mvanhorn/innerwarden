use std::path::Path;

use tracing::{info, warn};

use crate::{ai, config, correlation, defender_brain, AgentState};

/// Capacity of the rolling `recent_event_kinds` buffer that feeds defender
/// brain feature positions 36..=59. Matches the `hist` window in
/// `innerwarden-gym::environment` (line 31) so training and serving see the
/// same shape of signal.
pub const BRAIN_FEATURE_HISTORY_CAP: usize = 20;

/// Push an event kind into the rolling history, dropping oldest entries to
/// stay at or under `BRAIN_FEATURE_HISTORY_CAP`. Extracted so the slow-loop
/// hot path stays a one-liner and the bounded-buffer logic has a direct
/// unit test.
pub(crate) fn push_event_kind_history(buf: &mut std::collections::VecDeque<String>, kind: &str) {
    buf.push_back(kind.to_string());
    while buf.len() > BRAIN_FEATURE_HISTORY_CAP {
        buf.pop_front();
    }
}

/// Apply correlation confidence boost, query defender brain, and emit the canonical decision log.
pub(crate) fn apply_correlation_boost_and_log_decision(
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    decision: &mut ai::AiDecision,
    data_dir: &Path,
) {
    // If the same IP triggered multiple distinct detectors within the
    // correlation window, boost the confidence.
    let (boosted_confidence, correlated_detectors) = if cfg.correlation.enabled {
        let (b, k) = correlation::cross_detector_boost(
            &mut state.correlator,
            incident,
            decision.confidence as f64,
        );
        (b as f32, k)
    } else {
        (decision.confidence, vec![])
    };

    if boosted_confidence > decision.confidence {
        info!(
            incident_id = %incident.incident_id,
            base_confidence = decision.confidence,
            boosted_confidence,
            correlated_detectors = ?correlated_detectors,
            "cross-detector correlation boost applied"
        );
        decision.confidence = boosted_confidence;
        decision.reason = format!(
            "{} [correlated: {}]",
            decision.reason,
            correlated_detectors.join(", ")
        );
    }

    // Attacker intel risk score boost: if this IP has a known risk profile,
    // enrich the decision with context and boost confidence for repeat offenders.
    {
        let ip = incident
            .entities
            .iter()
            .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
            .map(|e| e.value.as_str());
        if let Some(ip) = ip {
            if let Some(profile) = state.attacker_profiles.get(ip) {
                let risk = profile.risk_score;
                if risk > 50 {
                    let boost = (risk as f32 - 50.0) / 500.0; // 50→0%, 100→10%
                    let new_conf = (decision.confidence + boost).min(1.0);
                    if new_conf > decision.confidence {
                        let pattern = &profile.dna.pattern_class;
                        info!(
                            incident_id = %incident.incident_id,
                            ip,
                            risk_score = risk,
                            pattern = pattern.as_str(),
                            visits = profile.visit_count,
                            boost = format!("{:.3}", boost),
                            "attacker intel: known threat — confidence boosted"
                        );
                        decision.confidence = new_conf;
                        decision.reason = format!(
                            "{} [intel: risk {}, {}, {} visits]",
                            decision.reason, risk, pattern, profile.visit_count
                        );
                    }
                }
            }
        }
    }

    // Autoencoder signal boost: if the neural model also flagged unusual activity
    // in this time window, boost confidence by up to 10%.
    // This makes the autoencoder a "silent intuition" that reinforces real detections.
    if let Some(anomaly_score) = state.latest_anomaly_score.take() {
        if anomaly_score > 0.7 {
            let boost = (anomaly_score - 0.7) * 0.33; // 0.7→0%, 1.0→10%
            let new_conf = (decision.confidence + boost).min(1.0);
            if new_conf > decision.confidence {
                info!(
                    incident_id = %incident.incident_id,
                    anomaly_score = format!("{:.3}", anomaly_score),
                    boost = format!("{:.3}", boost),
                    "autoencoder signal: neural model agrees — confidence boosted"
                );
                decision.confidence = new_conf;
                decision.reason = format!(
                    "{} [neural: {:.0}% anomaly]",
                    decision.reason,
                    anomaly_score * 100.0
                );
            }
        }
    }

    info!(
        incident_id = %incident.incident_id,
        action = ?decision.action,
        confidence = decision.confidence,
        auto_execute = decision.auto_execute,
        reason = %decision.reason,
        "AI decision"
    );

    // Query defender brain for a second opinion (AlphaZero-trained model).
    // Logs the suggestion and records to history for dashboard + FP audit.
    if state.defender_brain.is_loaded() {
        let features = build_brain_features(incident, state);
        if let Some(suggestion) = state.defender_brain.suggest(&features) {
            let ai_action_str = format!("{:?}", decision.action);
            let brain_agrees = is_brain_agreeing_with_ai(suggestion.action_name, &ai_action_str);

            info!(
                incident_id = %incident.incident_id,
                brain_action = suggestion.action_name,
                brain_confidence = format!("{:.1}%", suggestion.confidence * 100.0),
                brain_value = format!("{:.2}", suggestion.value),
                agreed = brain_agrees,
                "defender brain suggestion"
            );

            let det = incident.incident_id.split(':').next().unwrap_or("unknown");
            let log_entry = defender_brain::BrainLogEntry {
                ts: chrono::Utc::now(),
                incident_id: incident.incident_id.clone(),
                detector: det.to_string(),
                severity: format!("{:?}", incident.severity),
                brain_action: suggestion.action_name,
                brain_confidence: suggestion.confidence,
                brain_value: suggestion.value,
                brain_top3: suggestion.top_actions.clone(),
                ai_action: ai_action_str,
                ai_confidence: decision.confidence,
                agreed: brain_agrees,
                feedback: None,
                features: features.to_vec(),
            };

            // Persist to file for dashboard access
            let log_path = data_dir.join("brain-log.json");
            let mut entries: Vec<serde_json::Value> = std::fs::read_to_string(&log_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            if let Ok(v) = serde_json::to_value(&log_entry) {
                entries.push(v);
                // Keep last 10000 entries (includes features for training)
                if entries.len() > 10000 {
                    entries.drain(0..entries.len() - 10000);
                }
                if let Err(e) = std::fs::write(
                    &log_path,
                    serde_json::to_string(&entries).unwrap_or_default(),
                ) {
                    warn!("failed to write brain-log.json: {e}");
                }
            }

            // Track agreement for brain evolution stats
            let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
            state.brain_stats.record(brain_agrees, &today);

            state.brain_history.record(log_entry);
        }
    }

    // Persist brain stats every call (lightweight — just a small JSON)
    state.brain_stats.save(data_dir);
}

/// Build 72-dim feature vector for the defender brain from incident + agent state.
/// Enriched with IP reputation, attacker profile, correlation, baseline — gives
/// the brain enough context to distinguish real attacks from FPs.
pub(crate) fn build_brain_features(
    incident: &innerwarden_core::incident::Incident,
    state: &AgentState,
) -> [f32; 72] {
    use innerwarden_core::event::Severity;

    let mut f = [0.0f32; 72];

    // Extract IP from incident entities or incident_id
    let ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str())
        .or_else(|| {
            let parts: Vec<&str> = incident.incident_id.split(':').collect();
            if parts.len() >= 2 && parts[1].contains('.') {
                Some(parts[1])
            } else {
                None
            }
        });

    let det = incident.incident_id.split(':').next().unwrap_or("");

    // [0-3] severity
    match incident.severity {
        Severity::Low | Severity::Info | Severity::Debug => f[0] = 1.0,
        Severity::Medium => f[1] = 1.0,
        Severity::High => f[2] = 1.0,
        Severity::Critical => f[3] = 1.0,
    }

    // [4] total incidents from this IP (from attacker profile)
    if let Some(ip_str) = ip {
        if let Some(profile) = state.attacker_profiles.get(ip_str) {
            f[4] = (profile.total_incidents as f32 / 50.0).min(1.0);
            // [5] risk score from attacker profile (0-100 normalized)
            f[5] = profile.risk_score as f32 / 100.0;
            // [6] number of distinct detectors that flagged this IP
            f[6] = (profile.detectors_triggered.len() as f32 / 10.0).min(1.0);
            // [7] recurrence: how many times this IP has been seen
            f[7] = (profile.visit_dates.len() as f32 / 10.0).min(1.0);
        }

        // [8] is this IP already blocked?
        f[8] = if state.blocklist.contains(ip_str) {
            1.0
        } else {
            0.0
        };

        // [9] IP reputation from local cache
        if let Some(rep) = state.ip_reputations.get(ip_str) {
            f[9] = (rep.reputation_score / 100.0).min(1.0);
        }

        // [10] is internal/private IP?
        let is_internal = ip_str.starts_with("10.")
            || ip_str.starts_with("192.168.")
            || ip_str.starts_with("172.")
            || ip_str.starts_with("127.");
        f[10] = if is_internal { 1.0 } else { 0.0 };
    }

    // [11] blocked IPs count as proxy for correlation activity
    f[11] = (state.blocklist.len() as f32 / 20.0).min(1.0);

    // [12-17] detector flags
    f[12] = if det == "ssh_bruteforce" { 1.0 } else { 0.0 };
    f[13] = if det == "reverse_shell" { 1.0 } else { 0.0 };
    f[14] = if det == "privesc" { 1.0 } else { 0.0 };
    f[15] = if det == "ransomware" { 1.0 } else { 0.0 };
    f[16] = if det == "log_tampering" { 1.0 } else { 0.0 };
    f[17] = if det == "web_shell" { 1.0 } else { 0.0 };

    // [18-23] more detector flags
    f[18] = if det == "data_exfil_ebpf" || det == "data_exfil_cmd" {
        1.0
    } else {
        0.0
    };
    f[19] = if det == "c2_callback" { 1.0 } else { 0.0 };
    f[20] = if det == "dns_tunneling" || det == "dns_tunneling_ebpf" {
        1.0
    } else {
        0.0
    };
    f[21] = if det == "credential_stuffing" || det == "distributed_ssh" {
        1.0
    } else {
        0.0
    };
    f[22] = if det == "rootkit" { 1.0 } else { 0.0 };
    f[23] = if det == "neural_anomaly" { 1.0 } else { 0.0 };

    // [24] baseline maturity (is baseline learning complete?)
    f[24] = if state.baseline.is_mature() { 1.0 } else { 0.0 };

    // [25] baseline anomaly recently?
    f[25] = if state
        .last_baseline_anomaly_ts
        .is_some_and(|ts| (chrono::Utc::now() - ts).num_seconds() < 300)
    {
        1.0
    } else {
        0.0
    };

    // [26] autoencoder anomaly recently?
    f[26] = if state
        .last_autoencoder_anomaly_ts
        .is_some_and(|ts| (chrono::Utc::now() - ts).num_seconds() < 300)
    {
        1.0
    } else {
        0.0
    };

    // [27] total blocked IPs (how active is the defense?)
    f[27] = (state.blocklist.len() as f32 / 50.0).min(1.0);

    // [28] hour of day (normalized, for off-hours detection)
    f[28] = chrono::Timelike::hour(&chrono::Utc::now()) as f32 / 24.0;

    // [29] is this a known FP pattern? (neural_anomaly with low maturity)
    f[29] = if det == "neural_anomaly" {
        if let Some(evidence) = incident.evidence.get(0) {
            let maturity = evidence
                .get("maturity")
                .and_then(|v| v.as_f64())
                .unwrap_or(1.0);
            if maturity < 0.5 {
                1.0
            } else {
                0.0
            } // low maturity = likely FP
        } else {
            0.0
        }
    } else {
        0.0
    };

    // Spec 031: positions 30..=71 mirror the gym's enriched observation
    // (innerwarden-gym/src/environment.rs). Derived from the rolling
    // event-kind window maintained in AgentState plus the incident itself.
    // Position semantics must stay in sync with
    // `innerwarden-gym/src/production_features.rs` — update both sides
    // together when extending.
    fill_history_features(&mut f, state);
    fill_new_detector_flags(&mut f, det);

    f
}

/// Classify an event kind into one of the six layers the gym uses for
/// feature positions 30..=35. Heuristic on the `kind` prefix/substring.
/// Any kind that does not match lands in `Layer::Userspace` (index 3).
fn event_kind_layer(kind: &str) -> usize {
    // Firmware, SMM, UEFI integrity events.
    if kind.starts_with("firmware.") || kind.starts_with("smm.") || kind.contains("uefi") {
        return 0;
    }
    // Hypervisor/ring-1 events.
    if kind.starts_with("hypervisor.") || kind.contains("blue_pill") || kind.contains("vm_escape") {
        return 1;
    }
    // Kernel, eBPF, rootkit, kernel module, integrity.
    if kind.starts_with("kernel.")
        || kind.starts_with("ebpf.")
        || kind.starts_with("integrity.")
        || kind.contains("rootkit")
        || kind.contains("kernel_module")
    {
        return 2;
    }
    // Network: DNS, HTTP, TLS, outbound, port scan, DDoS, proto anomaly.
    if kind.starts_with("dns.")
        || kind.starts_with("http.")
        || kind.starts_with("tls.")
        || kind.starts_with("net.")
        || kind.starts_with("proto_anomaly")
        || kind.starts_with("packet_flood")
        || kind.contains("port_scan")
        || kind.contains("c2_callback")
        || kind.contains("dns_tunneling")
    {
        return 4;
    }
    // AI agent guard / MCP.
    if kind.starts_with("agent_guard.") || kind.starts_with("mcp.") || kind.starts_with("atr.") {
        return 5;
    }
    // Fallback: userspace (auth, docker, exec, suspicious binaries).
    3
}

/// Populate features 30..=67 from `state.recent_event_kinds`. Positions
/// 68..=71 are handled separately by `fill_new_detector_flags` so they
/// reflect the *current* incident's detector rather than the window.
fn fill_history_features(f: &mut [f32; 72], state: &AgentState) {
    let hist: Vec<&str> = state
        .recent_event_kinds
        .iter()
        .map(|s| s.as_str())
        .collect();

    // [30..=35] layer counts (firmware, hypervisor, kernel, userspace, network, ai_agent).
    let mut layer_counts = [0u32; 6];
    for kind in &hist {
        let idx = event_kind_layer(kind);
        layer_counts[idx] = layer_counts[idx].saturating_add(1);
    }
    for (i, &c) in layer_counts.iter().enumerate() {
        f[30 + i] = (c as f32 / 5.0).min(1.0);
    }

    // [36..=39] kill chain stage presence.
    let has_recon = hist.iter().any(|k| {
        k.contains("port_scan")
            || k.contains("web_scan")
            || k.contains("DnsRecon")
            || k.contains("discovery")
    });
    let has_access = hist.iter().any(|k| {
        k.contains("ssh_bruteforce")
            || k.contains("credential_stuffing")
            || k.contains("web_shell")
            || k.contains("WebExploit")
    });
    let has_exec = hist.iter().any(|k| {
        k.contains("reverse_shell")
            || k.contains("shell.command")
            || k.contains("exec.")
            || k.contains("fileless")
    });
    let has_persist = hist.iter().any(|k| {
        k.contains("persistence")
            || k.contains("crontab")
            || k.contains("systemd_persistence")
            || k.contains("ssh_key_injection")
    });
    f[36] = if has_recon { 1.0 } else { 0.0 };
    f[37] = if has_access { 1.0 } else { 0.0 };
    f[38] = if has_exec { 1.0 } else { 0.0 };
    f[39] = if has_persist { 1.0 } else { 0.0 };

    // [40] kill chain depth (stages completed / 4).
    let kc_stages = has_recon as u8 + has_access as u8 + has_exec as u8 + has_persist as u8;
    f[40] = kc_stages as f32 / 4.0;

    // [41] event diversity (unique kinds / 10, saturating).
    let mut unique: Vec<&str> = hist.clone();
    unique.sort();
    unique.dedup();
    f[41] = (unique.len() as f32 / 10.0).min(1.0);

    // [42] event burst density (window fullness).
    f[42] = (hist.len() as f32 / BRAIN_FEATURE_HISTORY_CAP as f32).min(1.0);

    // [43..=47] technique category counts (saturating at 1.0).
    let cat_recon = hist
        .iter()
        .filter(|k| {
            k.contains("scan")
                || k.contains("port_scan")
                || k.contains("web_scan")
                || k.contains("discovery")
                || k.contains("DnsRecon")
        })
        .count();
    let cat_exploit = hist
        .iter()
        .filter(|k| {
            k.contains("exploit")
                || k.contains("bruteforce")
                || k.contains("credential_stuffing")
                || k.contains("web_shell")
        })
        .count();
    let cat_privesc = hist
        .iter()
        .filter(|k| {
            k.contains("privesc")
                || k.contains("sudo_abuse")
                || k.contains("kernel_module")
                || k.contains("container_escape")
                || k.contains("ld_preload")
        })
        .count();
    let cat_evasion = hist
        .iter()
        .filter(|k| {
            k.contains("log_tampering")
                || k.contains("timestomp")
                || k.contains("process_injection")
                || k.contains("rootkit")
        })
        .count();
    let cat_exfil = hist
        .iter()
        .filter(|k| {
            k.contains("data_exfil") || k.contains("exfiltration") || k.contains("dns_tunneling")
        })
        .count();
    f[43] = (cat_recon as f32 / 5.0).min(1.0);
    f[44] = (cat_exploit as f32 / 5.0).min(1.0);
    f[45] = (cat_privesc as f32 / 3.0).min(1.0);
    f[46] = (cat_evasion as f32 / 3.0).min(1.0);
    f[47] = (cat_exfil as f32 / 3.0).min(1.0);

    // [48..=59] attack bigram transitions. 12 patterns matching the gym's
    // `bigram_patterns` array. Use substring match so agent-side event
    // kinds (`exec.shell_command` etc.) line up with gym's
    // (`attack.ShellCommand`) via the tail keyword.
    const BIGRAM_PATTERNS: &[(&str, &str)] = &[
        ("ssh_bruteforce", "shell"),
        ("shell", "shadow"),
        ("shadow", "exfil"),
        ("shell", "exfil"),
        ("reverse_shell", "shell"),
        ("sudo_abuse", "shell"),
        ("shell", "log_tampering"),
        ("shell", "timestomp"),
        ("kernel_module", "rootkit"),
        ("shell", "crontab"),
        ("shell", "ssh_key_injection"),
        ("ld_preload", "shell"),
    ];
    for (i, &(a, b)) in BIGRAM_PATTERNS.iter().enumerate() {
        let count = hist
            .windows(2)
            .filter(|w| w[0].contains(a) && w[1].contains(b))
            .count();
        f[48 + i] = (count as f32 / 3.0).min(1.0);
    }

    // [60..=63] kernel/firmware state. Derived from recent history since
    // the agent does not carry a separate kernel/firmware struct today.
    let kmod_count = hist.iter().filter(|k| k.contains("kernel_module")).count();
    f[60] = (kmod_count as f32 / 20.0).min(1.0);
    f[61] = if hist.iter().any(|k| k.contains("rootkit")) {
        1.0
    } else {
        0.0
    };
    f[62] = if hist
        .iter()
        .any(|k| k.starts_with("firmware.") || k.contains("uefi") || k.starts_with("smm."))
    {
        1.0
    } else {
        0.0
    };
    f[63] = hist.iter().filter(|k| k.starts_with("smm.")).count() as f32 / 100.0;

    // [64..=67] network state.
    let net_conn = hist
        .iter()
        .filter(|k| {
            k.starts_with("net.")
                || k.starts_with("http.")
                || k.starts_with("tls.")
                || k.contains("connect")
        })
        .count();
    f[64] = (net_conn as f32 / 20.0).min(1.0);
    let dns_queries = hist.iter().filter(|k| k.starts_with("dns.")).count();
    f[65] = (dns_queries as f32 / 100.0).min(1.0);
    let exfil_like = hist
        .iter()
        .filter(|k| k.contains("data_exfil") || k.contains("dns_tunneling"))
        .count();
    f[66] = (exfil_like as f32 / 5.0).min(1.0);
    f[67] = if hist.iter().any(|k| k.contains("honeypot")) {
        1.0
    } else {
        0.0
    };
}

/// Spec 031 FR-3: grouped one-hot flags for production detectors not
/// covered by the V5 slots at 12..=23. Lives in the reserved block
/// 68..=71 to preserve the V5 contract on existing positions.
fn fill_new_detector_flags(f: &mut [f32; 72], det: &str) {
    f[68] = if det == "host_drift" || det == "sigma" {
        1.0
    } else {
        0.0
    };
    f[69] = if det == "network_sniffing" || det == "discovery_burst" {
        1.0
    } else {
        0.0
    };
    f[70] = if det == "proto_anomaly" || det == "packet_flood" {
        1.0
    } else {
        0.0
    };
    f[71] = if det == "correlation" { 1.0 } else { 0.0 };
}

/// Log a deterministic (Layer 1/2) decision to the brain so it learns from
/// high-quality ground-truth labels. Called by auto-rules and correlation-response.
///
/// The `ai_action` string is formatted the same way as AI decisions so the
/// brain's `retrain_from_log` treats them identically.
pub(crate) fn log_deterministic_decision_to_brain(
    incident: &innerwarden_core::incident::Incident,
    action_str: &str,
    confidence: f32,
    provider_label: &str,
    data_dir: &std::path::Path,
    state: &mut AgentState,
) {
    if !state.defender_brain.is_loaded() {
        return;
    }

    let features = build_brain_features(incident, state);
    let suggestion = state.defender_brain.suggest(&features);

    let (brain_action, brain_confidence, brain_value, brain_top3, brain_agrees) =
        if let Some(ref s) = suggestion {
            (
                s.action_name,
                s.confidence,
                s.value,
                s.top_actions.clone(),
                is_brain_agreeing_with_ai(s.action_name, action_str),
            )
        } else {
            ("unknown", 0.0, 0.0, vec![], false)
        };

    let det = incident.incident_id.split(':').next().unwrap_or("unknown");
    let log_entry = defender_brain::BrainLogEntry {
        ts: chrono::Utc::now(),
        incident_id: incident.incident_id.clone(),
        detector: det.to_string(),
        severity: format!("{:?}", incident.severity),
        brain_action,
        brain_confidence,
        brain_value,
        brain_top3,
        ai_action: action_str.to_string(),
        ai_confidence: confidence,
        agreed: brain_agrees,
        feedback: None,
        features: features.to_vec(),
    };

    // Persist to brain-log.json (same format as Layer 3 entries).
    let log_path = data_dir.join("brain-log.json");
    let mut entries: Vec<serde_json::Value> = std::fs::read_to_string(&log_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    if let Ok(v) = serde_json::to_value(&log_entry) {
        entries.push(v);
        if entries.len() > 10000 {
            entries.drain(0..entries.len() - 10000);
        }
        if let Err(e) = std::fs::write(
            &log_path,
            serde_json::to_string(&entries).unwrap_or_default(),
        ) {
            warn!("failed to write brain-log.json: {e}");
        }
    }

    // Track agreement stats.
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    state.brain_stats.record(brain_agrees, &today);
    state.brain_history.record(log_entry);

    info!(
        incident_id = %incident.incident_id,
        provider = provider_label,
        brain_agrees,
        "brain: logged deterministic decision for training"
    );
}

pub(crate) fn is_brain_agreeing_with_ai(brain_action: &str, ai_action_str: &str) -> bool {
    (brain_action == "block_ip" && ai_action_str.contains("BlockIp"))
        || (brain_action == "kill_process" && ai_action_str.contains("KillProcess"))
        || (brain_action == "observe"
            && (ai_action_str.contains("Ignore") || ai_action_str.contains("Monitor")))
        || (brain_action == "alert" && ai_action_str.contains("Monitor"))
        || (brain_action == "escalate" && ai_action_str.contains("Escalate"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_is_brain_agreeing_with_ai() {
        assert!(is_brain_agreeing_with_ai("block_ip", "BlockIp(10.0.0.1)"));
        assert!(!is_brain_agreeing_with_ai("block_ip", "Monitor"));

        assert!(is_brain_agreeing_with_ai("observe", "Ignore"));
        assert!(is_brain_agreeing_with_ai("observe", "Monitor"));

        assert!(is_brain_agreeing_with_ai("alert", "Monitor"));
        assert!(!is_brain_agreeing_with_ai("alert", "Ignore"));

        assert!(is_brain_agreeing_with_ai("kill_process", "KillProcess"));
        assert!(!is_brain_agreeing_with_ai(
            "kill_process",
            "SuspendUserSudo"
        ));
    }

    #[test]
    fn build_brain_features_populates_profile_and_detector_signals() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let ip = "8.8.8.8";
        state.blocklist.insert(ip.to_string());
        state.last_baseline_anomaly_ts = Some(chrono::Utc::now());
        state.last_autoencoder_anomaly_ts = Some(chrono::Utc::now());

        let mut profile = crate::attacker_intel::new_profile(ip, chrono::Utc::now());
        profile.total_incidents = 12;
        profile.risk_score = 82;
        profile
            .detectors_triggered
            .insert("neural_anomaly".to_string());
        profile.visit_dates = vec!["2026-04-16".to_string(), "2026-04-17".to_string()];
        state.attacker_profiles.insert(ip.to_string(), profile);

        let mut local_rep = crate::ip_reputation::LocalIpReputation::new();
        local_rep.reputation_score = 77.0;
        state.ip_reputations.insert(ip.to_string(), local_rep);

        let mut incident = crate::tests::test_incident_with_kind(ip, "neural_anomaly");
        incident.evidence = serde_json::json!([{"maturity": 0.2}]);

        let features = build_brain_features(&incident, &state);

        // High severity
        assert_eq!(features[2], 1.0);
        // Profile + IP-dependent features
        assert!(features[4] > 0.0);
        assert!(features[5] > 0.8);
        assert_eq!(features[8], 1.0);
        assert!(features[9] > 0.7);
        assert_eq!(features[10], 0.0);
        // Detector flags
        assert_eq!(features[23], 1.0);
        // Recent anomaly markers
        assert_eq!(features[25], 1.0);
        assert_eq!(features[26], 1.0);
        // Neural anomaly + low maturity => likely FP pattern flag
        assert_eq!(features[29], 1.0);
    }

    #[test]
    fn apply_correlation_boost_and_log_decision_enriches_and_persists_brain_log() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        state.defender_brain = crate::defender_brain::DefenderBrain::load("embedded");
        state.latest_anomaly_score = Some(0.93);

        let ip = "9.9.9.9";
        let mut profile = crate::attacker_intel::new_profile(ip, chrono::Utc::now());
        profile.risk_score = 90;
        profile.visit_count = 4;
        profile.dna.pattern_class = "targeted".to_string();
        state.attacker_profiles.insert(ip.to_string(), profile);

        let mut previous = crate::tests::test_incident_with_kind(ip, "ssh_bruteforce");
        previous.ts = chrono::Utc::now() - chrono::Duration::minutes(1);
        state.correlator.observe(&previous);

        let incident = crate::tests::test_incident_with_kind(ip, "port_scan");
        let mut cfg = config::AgentConfig::default();
        cfg.correlation.enabled = true;

        let mut decision = ai::AiDecision {
            action: ai::AiAction::BlockIp {
                ip: ip.to_string(),
                skill_id: "block-ip-ufw".to_string(),
            },
            confidence: 0.55,
            auto_execute: true,
            reason: "base decision".to_string(),
            alternatives: vec!["monitor".to_string()],
            estimated_threat: "high".to_string(),
        };

        apply_correlation_boost_and_log_decision(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            dir.path(),
        );

        assert!(decision.confidence > 0.55, "confidence should be boosted");
        assert!(
            decision.reason.contains("[correlated:")
                || decision.reason.contains("[intel: risk")
                || decision.reason.contains("[neural:"),
            "reason should include enrichment markers"
        );
        assert!(
            !state.brain_history.recent(1).is_empty(),
            "brain history should receive a log entry"
        );
        assert!(dir.path().join("brain-log.json").exists());
        assert!(
            state.brain_stats.total_since_retrain > 0,
            "brain stats should track agreement counters"
        );
        assert!(
            state.latest_anomaly_score.is_none(),
            "anomaly score should be consumed by decision evaluation"
        );
    }

    // ─── Spec 031: feature positions 30..=71 ──────────────────────────

    fn push_kinds(state: &mut AgentState, kinds: &[&str]) {
        for k in kinds {
            state.recent_event_kinds.push_back((*k).into());
        }
    }

    #[test]
    fn event_kind_layer_classifies_all_six_buckets() {
        assert_eq!(event_kind_layer("firmware.tampered"), 0);
        assert_eq!(event_kind_layer("smm.breach"), 0);
        assert_eq!(event_kind_layer("hypervisor.vm_escape"), 1);
        assert_eq!(event_kind_layer("blue_pill.detected"), 1);
        assert_eq!(event_kind_layer("kernel.module_load"), 2);
        assert_eq!(event_kind_layer("rootkit.installed"), 2);
        assert_eq!(event_kind_layer("ebpf.syscall"), 2);
        assert_eq!(event_kind_layer("integrity.altered"), 2);
        assert_eq!(event_kind_layer("dns.query"), 4);
        assert_eq!(event_kind_layer("http.request"), 4);
        assert_eq!(event_kind_layer("tls.clienthello"), 4);
        assert_eq!(event_kind_layer("net.connect"), 4);
        assert_eq!(event_kind_layer("proto_anomaly:SlowConnection"), 4);
        assert_eq!(event_kind_layer("packet_flood:rate_anomaly"), 4);
        assert_eq!(event_kind_layer("port_scan"), 4);
        assert_eq!(event_kind_layer("c2_callback"), 4);
        assert_eq!(event_kind_layer("dns_tunneling"), 4);
        assert_eq!(event_kind_layer("agent_guard.prompt_injection"), 5);
        assert_eq!(event_kind_layer("mcp.tool_call"), 5);
        assert_eq!(event_kind_layer("atr.rule_match"), 5);
        // Fallback: userspace.
        assert_eq!(event_kind_layer("exec.shell"), 3);
        assert_eq!(event_kind_layer("random_unknown_kind"), 3);
        assert_eq!(event_kind_layer(""), 3);
    }

    #[test]
    fn build_brain_features_empty_history_zeros_30_to_67() {
        let dir = TempDir::new().unwrap();
        let state = crate::tests::triage_test_state(dir.path());
        let incident = crate::tests::test_incident_with_kind("1.2.3.4", "neural_anomaly");

        let f = build_brain_features(&incident, &state);

        for i in 30..=67 {
            assert_eq!(
                f[i], 0.0,
                "position {i} should be zero when history is empty"
            );
        }
    }

    #[test]
    fn build_brain_features_layer_counts_saturate_and_distribute() {
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        push_kinds(
            &mut state,
            &[
                "firmware.tampered",
                "hypervisor.vm_escape",
                "kernel.module_load",
                "dns.query",
                "http.request",
                "agent_guard.prompt_injection",
                "exec.shell",
                "exec.shell",
            ],
        );
        let incident = crate::tests::test_incident_with_kind("1.2.3.4", "neural_anomaly");
        let f = build_brain_features(&incident, &state);

        assert!(f[30] > 0.0, "firmware layer count populated");
        assert!(f[31] > 0.0, "hypervisor layer count populated");
        assert!(f[32] > 0.0, "kernel layer count populated");
        assert!(f[33] > 0.0, "userspace layer count populated");
        assert!(f[34] > 0.0, "network layer count populated");
        assert!(f[35] > 0.0, "ai_agent layer count populated");
    }

    #[test]
    fn build_brain_features_kill_chain_stages_and_depth() {
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        push_kinds(
            &mut state,
            &[
                "port_scan",           // recon
                "ssh_bruteforce",      // access
                "exec.shell_command",  // exec
                "crontab_persistence", // persist
            ],
        );
        let incident = crate::tests::test_incident_with_kind("1.2.3.4", "neural_anomaly");
        let f = build_brain_features(&incident, &state);

        assert_eq!(f[36], 1.0, "recon stage");
        assert_eq!(f[37], 1.0, "access stage");
        assert_eq!(f[38], 1.0, "exec stage");
        assert_eq!(f[39], 1.0, "persist stage");
        assert!((f[40] - 1.0).abs() < f32::EPSILON, "full depth");
    }

    #[test]
    fn build_brain_features_diversity_and_burst() {
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        // 6 unique kinds out of 10 total events.
        push_kinds(
            &mut state,
            &[
                "a.x", "a.x", "b.y", "c.z", "d.w", "d.w", "e.v", "f.u", "f.u", "a.x",
            ],
        );
        let incident = crate::tests::test_incident_with_kind("1.2.3.4", "neural_anomaly");
        let f = build_brain_features(&incident, &state);

        assert!((f[41] - 0.6).abs() < 0.05, "diversity ~6/10");
        assert!((f[42] - 0.5).abs() < 0.05, "burst ~10/20");
    }

    #[test]
    fn build_brain_features_technique_categories() {
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        push_kinds(
            &mut state,
            &[
                "port_scan",       // recon
                "web_scan",        // recon
                "ssh_bruteforce",  // exploit
                "sudo_abuse",      // privesc
                "log_tampering",   // evasion
                "data_exfil_ebpf", // exfil
            ],
        );
        let incident = crate::tests::test_incident_with_kind("1.2.3.4", "neural_anomaly");
        let f = build_brain_features(&incident, &state);

        assert!(f[43] > 0.0, "recon category");
        assert!(f[44] > 0.0, "exploit category");
        assert!(f[45] > 0.0, "privesc category");
        assert!(f[46] > 0.0, "evasion category");
        assert!(f[47] > 0.0, "exfil category");
    }

    #[test]
    fn build_brain_features_bigrams_detect_known_sequence() {
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        push_kinds(
            &mut state,
            &[
                "ssh_bruteforce",
                "exec.shell_command",
                "exec.shell_command",
                "log_tampering",
            ],
        );
        let incident = crate::tests::test_incident_with_kind("1.2.3.4", "neural_anomaly");
        let f = build_brain_features(&incident, &state);

        assert!(f[48] > 0.0, "ssh_bruteforce -> shell bigram");
        assert!(f[54] > 0.0, "shell -> log_tampering bigram");
    }

    #[test]
    fn build_brain_features_kernel_and_network_state() {
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        push_kinds(
            &mut state,
            &[
                "kernel_module.load",
                "rootkit.detected",
                "firmware.tampered",
                "smm.breach",
                "net.connect",
                "dns.query",
                "data_exfil_cmd",
                "honeypot.ssh_session",
            ],
        );
        let incident = crate::tests::test_incident_with_kind("1.2.3.4", "neural_anomaly");
        let f = build_brain_features(&incident, &state);

        assert!(f[60] > 0.0, "kernel module count populated");
        assert_eq!(f[61], 1.0, "rootkit flag");
        assert_eq!(f[62], 1.0, "firmware tampered flag");
        assert!(f[63] > 0.0, "smm count");
        assert!(f[64] > 0.0, "network connection count");
        assert!(f[65] > 0.0, "dns queries count");
        assert!(f[66] > 0.0, "exfil-like count");
        assert_eq!(f[67], 1.0, "honeypot active flag");
    }

    #[test]
    fn build_brain_features_new_detector_flags_map_to_68_71() {
        let dir = TempDir::new().unwrap();
        let state = crate::tests::triage_test_state(dir.path());
        let ip = "1.2.3.4";

        for (det, slot) in [
            ("host_drift", 68),
            ("sigma", 68),
            ("network_sniffing", 69),
            ("discovery_burst", 69),
            ("proto_anomaly", 70),
            ("packet_flood", 70),
            ("correlation", 71),
        ] {
            let incident = crate::tests::test_incident_with_kind(ip, det);
            let f = build_brain_features(&incident, &state);
            assert_eq!(
                f[slot],
                1.0,
                "{det} should flip slot {slot}, got {:?}",
                &f[68..=71]
            );
            // V5 slots 12..=23 should not be set for these new detectors.
            assert!(
                f[12..=23].iter().all(|v| *v == 0.0),
                "V5 contract preserved for {det}"
            );
        }
    }

    #[test]
    fn build_brain_features_produces_distinct_vectors_for_distinct_incidents() {
        // Spec 031 FR-5: the regression guard. Three incidents with meaningfully
        // different severity/detector/profile must yield non-identical 72-dim
        // feature vectors.
        let dir = TempDir::new().unwrap();
        let mut state = crate::tests::triage_test_state(dir.path());
        push_kinds(&mut state, &["port_scan", "ssh_bruteforce", "exec.shell"]);

        let neural = crate::tests::test_incident_with_kind("10.0.0.1", "neural_anomaly");
        let drift = crate::tests::test_incident_with_kind("8.8.8.8", "host_drift");
        let brute = crate::tests::test_incident_with_kind("9.9.9.9", "ssh_bruteforce");

        let fa = build_brain_features(&neural, &state);
        let fb = build_brain_features(&drift, &state);
        let fc = build_brain_features(&brute, &state);

        assert_ne!(fa, fb, "neural_anomaly vs host_drift must differ");
        assert_ne!(fb, fc, "host_drift vs ssh_bruteforce must differ");
        assert_ne!(fa, fc, "neural_anomaly vs ssh_bruteforce must differ");
    }

    #[test]
    fn brain_feature_history_cap_matches_gym_window() {
        // If the gym and the agent disagree on the window size the
        // bigram/diversity features go out of distribution. Pin to 20.
        assert_eq!(BRAIN_FEATURE_HISTORY_CAP, 20);
    }

    #[test]
    fn fill_new_detector_flags_all_zero_for_unrelated_detector() {
        let mut f = [0.0f32; 72];
        fill_new_detector_flags(&mut f, "reverse_shell");
        assert_eq!(&f[68..=71], &[0.0, 0.0, 0.0, 0.0]);
    }

    #[test]
    fn push_event_kind_history_respects_cap_and_preserves_order() {
        let mut buf = std::collections::VecDeque::new();
        for i in 0..(BRAIN_FEATURE_HISTORY_CAP + 5) {
            push_event_kind_history(&mut buf, &format!("k{i}"));
        }
        assert_eq!(buf.len(), BRAIN_FEATURE_HISTORY_CAP);
        // Oldest 5 dropped; newest (cap+4) is the tail.
        assert_eq!(buf.front().unwrap(), "k5");
        assert_eq!(
            buf.back().unwrap(),
            &format!("k{}", BRAIN_FEATURE_HISTORY_CAP + 4)
        );
    }

    #[test]
    fn push_event_kind_history_empty_string_is_accepted() {
        let mut buf = std::collections::VecDeque::new();
        push_event_kind_history(&mut buf, "");
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.front().unwrap(), "");
    }
}
