use std::path::Path;

use tracing::{info, warn};

use crate::{ai, config, correlation, defender_brain, AgentState};

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
            let brain_agrees = {
                let ba = suggestion.action_name;
                let aa = &ai_action_str;
                (ba == "block_ip" && aa.contains("BlockIp"))
                    || (ba == "kill_process" && aa.contains("KillProcess"))
                    || (ba == "observe" && (aa.contains("Ignore") || aa.contains("Monitor")))
                    || (ba == "alert" && aa.contains("Monitor"))
                    || (ba == "escalate" && aa.contains("Escalate"))
            };

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
            };

            // Persist to file for dashboard access
            let log_path = data_dir.join("brain-log.json");
            let mut entries: Vec<serde_json::Value> = std::fs::read_to_string(&log_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            if let Ok(v) = serde_json::to_value(&log_entry) {
                entries.push(v);
                // Keep last 500 entries
                if entries.len() > 500 {
                    entries.drain(0..entries.len() - 500);
                }
                if let Err(e) = std::fs::write(
                    &log_path,
                    serde_json::to_string(&entries).unwrap_or_default(),
                ) {
                    warn!("failed to write brain-log.json: {e}");
                }
            }

            state.brain_history.record(log_entry);
        }
    }
}

/// Build 72-dim feature vector for the defender brain from incident + agent state.
/// Enriched with IP reputation, attacker profile, correlation, baseline — gives
/// the brain enough context to distinguish real attacks from FPs.
fn build_brain_features(
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

    f
}
