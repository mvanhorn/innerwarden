use tracing::info;

use crate::{config, decisions, AgentState};

/// Auto-dismiss gate for low-severity noise when Guard mode is ON.
///
/// Called when `evaluate_pre_ai_flow` returns `SkipBelowSeverity` — the
/// incident's severity is below the AI threshold, so no AI call will be made.
/// Instead of leaving the incident without a decision (which shows as
/// "needs attention" / "monitoring" in the dashboard), write a rule-based
/// dismiss decision so every incident has a clear outcome.
///
/// Returns true when the incident was handled (dismiss decision written).
pub(crate) fn try_autodismiss_noise(
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> bool {
    // Only auto-dismiss when the responder is active (Guard mode ON).
    // In Watch/DryRun mode the operator wants to see everything.
    if !is_noise_gate_eligible(cfg.responder.enabled, cfg.responder.dry_run) {
        return false;
    }

    let detector = detector_from_incident_id(&incident.incident_id);

    let reason = autodismiss_reason(detector, &incident.severity);

    info!(
        incident_id = %incident.incident_id,
        detector,
        severity = ?incident.severity,
        "noise gate: auto-dismissing low-severity incident"
    );

    // Write decision entry to audit trail
    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.clone());

    let entry = decisions::DecisionEntry {
        ts: chrono::Utc::now(),
        incident_id: incident.incident_id.clone(),
        host: incident.host.clone(),
        ai_provider: "noise-gate".to_string(),
        action_type: "dismiss".to_string(),
        target_ip: primary_ip,
        target_user: None,
        skill_id: None,
        confidence: 1.0,
        auto_executed: true,
        dry_run: false,
        reason: reason.clone(),
        estimated_threat: "none".to_string(),
        execution_result: "dismissed".to_string(),
        prev_hash: None,
    };
    if let Some(writer) = &mut state.decision_writer {
        if let Err(e) = writer.write(&entry) {
            tracing::warn!("failed to write noise-gate decision: {e:#}");
        }
    }

    // Feed into knowledge graph so dashboard picks it up
    {
        let mut graph = state.knowledge_graph.write().unwrap();
        graph.ingest_decision(
            &incident.incident_id,
            "dismiss",
            None,
            1.0,
            &reason,
            true,
            chrono::Utc::now(),
        );
    }

    true
}

pub(crate) fn is_noise_gate_eligible(responder_enabled: bool, responder_dry_run: bool) -> bool {
    responder_enabled && !responder_dry_run
}

fn detector_from_incident_id(incident_id: &str) -> &str {
    incident_id.split(':').next().unwrap_or("")
}

fn autodismiss_reason(detector: &str, severity: &innerwarden_core::event::Severity) -> String {
    format!(
        "Low-priority {detector} ({:?}). Filed, not firing.",
        severity,
    )
}

// Integration tests for autodismiss live in main.rs test harness where
// AgentState can be constructed via triage_test_state().

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;

    #[test]
    fn test_is_noise_gate_eligible() {
        // Ensures the gate is active only in Guard mode (enabled and not dry-run).
        assert!(is_noise_gate_eligible(true, false));
        assert!(!is_noise_gate_eligible(false, false));
        assert!(!is_noise_gate_eligible(true, true));
        assert!(!is_noise_gate_eligible(false, true));
    }

    #[test]
    fn detector_from_incident_id_extracts_prefix_before_colon() {
        // Verifies detector extraction stays consistent for routing and audit reason text.
        assert_eq!(
            detector_from_incident_id("ssh_bruteforce:abc"),
            "ssh_bruteforce"
        );
        assert_eq!(detector_from_incident_id("single-token"), "single-token");
    }

    #[test]
    fn autodismiss_reason_mentions_detector_and_severity() {
        // Guards explanatory reason formatting stored in decision audit entries.
        let reason = autodismiss_reason("suspicious_login", &Severity::Low);
        assert!(reason.contains("suspicious_login"));
        assert!(reason.contains("Low"));
    }
}
