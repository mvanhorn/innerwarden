use tracing::info;

use crate::{ai, config, correlation, defender_brain, AgentState};

/// Apply correlation confidence boost, query defender brain, and emit the canonical decision log.
pub(crate) fn apply_correlation_boost_and_log_decision(
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    decision: &mut ai::AiDecision,
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
    // Logs the suggestion but does NOT override the AI decision — advisory only.
    if state.defender_brain.is_loaded() {
        let features = build_brain_features(incident, state);
        if let Some(suggestion) = state.defender_brain.suggest(&features) {
            info!(
                incident_id = %incident.incident_id,
                brain_action = suggestion.action_name,
                brain_confidence = format!("{:.1}%", suggestion.confidence * 100.0),
                brain_value = format!("{:.2}", suggestion.value),
                brain_top3 = ?suggestion.top_actions.iter().map(|(_, name, p)| format!("{}: {:.0}%", name, p * 100.0)).collect::<Vec<_>>(),
                "defender brain suggestion"
            );
        }
    }
}

/// Build 72-dim feature vector for the defender brain from incident + agent state.
fn build_brain_features(
    incident: &innerwarden_core::incident::Incident,
    state: &AgentState,
) -> [f32; 72] {
    use innerwarden_core::event::Severity;

    let mut f = [0.0f32; 72];

    // [0-3] severity
    match incident.severity {
        Severity::Low | Severity::Info | Severity::Debug => f[0] = 1.0,
        Severity::Medium => f[1] = 1.0,
        Severity::High => f[2] = 1.0,
        Severity::Critical => f[3] = 1.0,
    }

    // [5] composite score — use next_chain_id as proxy for chains detected
    // (completed_chains is private, but chain_id counter reflects activity)
    f[5] = 0.0; // Will be enriched when scoring integration is complete

    // [12-17] detector flags from incident_id prefix
    let det = incident.incident_id.split(':').next().unwrap_or("");
    f[12] = if det == "ssh_bruteforce" { 1.0 } else { 0.0 };
    f[13] = if det == "reverse_shell" { 1.0 } else { 0.0 };
    f[14] = if det == "privesc" { 1.0 } else { 0.0 };
    f[15] = if det == "ransomware" { 1.0 } else { 0.0 };
    f[16] = if det == "log_tampering" { 1.0 } else { 0.0 };
    f[17] = if det == "web_shell" { 1.0 } else { 0.0 };

    f
}
