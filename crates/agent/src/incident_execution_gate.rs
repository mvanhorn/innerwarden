use std::path::Path;

use tracing::info;

use crate::agent_context::incident_detector;
use crate::{ai, config, execute_decision, is_trusted, AgentState};

pub(crate) enum GateResult {
    Execute { trusted_override: bool },
    Skip(String),
}

pub(crate) fn evaluate_execution_gate(
    auto_execute: bool,
    confidence: f32,
    confidence_threshold: f32,
    responder_enabled: bool,
    trusted: bool,
) -> GateResult {
    if (auto_execute || trusted) && confidence >= confidence_threshold && responder_enabled {
        GateResult::Execute {
            trusted_override: trusted && !auto_execute,
        }
    } else if !responder_enabled {
        GateResult::Skip("skipped: responder disabled".to_string())
    } else if !auto_execute && !trusted {
        GateResult::Skip("skipped: AI did not recommend auto-execution (no trust rule)".to_string())
    } else {
        GateResult::Skip(format!(
            "skipped: confidence {:.2} below threshold {:.2}",
            confidence, confidence_threshold
        ))
    }
}

/// Execute a decision when it passes trust/confidence/responder gates,
/// otherwise return a deterministic skip reason.
pub(crate) async fn execute_or_skip_decision(
    incident: &innerwarden_core::incident::Incident,
    decision: &ai::AiDecision,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> (String, bool) {
    let detector = incident_detector(&incident.incident_id);
    let action_name = decision.action.name();
    let trusted = is_trusted(&state.trust_rules, detector, action_name);

    match evaluate_execution_gate(
        decision.auto_execute,
        decision.confidence,
        cfg.ai.confidence_threshold,
        cfg.responder.enabled,
        trusted,
    ) {
        GateResult::Execute { trusted_override } => {
            if trusted_override {
                info!(
                    incident_id = %incident.incident_id,
                    detector,
                    action = action_name,
                    "trust rule override: executing without AI auto_execute flag"
                );
            }
            state
                .telemetry
                .observe_execution_path(cfg.responder.dry_run);
            execute_decision(decision, incident, data_dir, cfg, state).await
        }
        GateResult::Skip(reason) => (reason, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_allows_auto_execute_when_confidence_high() {
        let result = evaluate_execution_gate(true, 0.9, 0.8, true, false);
        assert!(matches!(
            result,
            GateResult::Execute {
                trusted_override: false
            }
        ));
    }

    #[test]
    fn gate_allows_trusted_override_even_if_no_auto_execute() {
        let result = evaluate_execution_gate(false, 0.9, 0.8, true, true);
        assert!(matches!(
            result,
            GateResult::Execute {
                trusted_override: true
            }
        ));
    }

    #[test]
    fn gate_blocks_if_responder_disabled() {
        let result = evaluate_execution_gate(true, 0.9, 0.8, false, false);
        if let GateResult::Skip(msg) = result {
            assert!(msg.contains("responder disabled"));
        } else {
            panic!("expected skip");
        }
    }

    #[test]
    fn gate_blocks_if_not_auto_execute_and_not_trusted() {
        let result = evaluate_execution_gate(false, 0.9, 0.8, true, false);
        if let GateResult::Skip(msg) = result {
            assert!(msg.contains("did not recommend auto-execution"));
        } else {
            panic!("expected skip");
        }
    }

    #[test]
    fn gate_blocks_if_confidence_below_threshold() {
        let result = evaluate_execution_gate(true, 0.7, 0.8, true, false);
        if let GateResult::Skip(msg) = result {
            assert!(msg.contains("below threshold"));
        } else {
            panic!("expected skip");
        }
    }

    /// Coverage anchor (test/coverage-batch-3 — 2026-05-07): exercise
    /// the skip path of `execute_or_skip_decision` end-to-end. With
    /// `auto_execute = false`, no trust rule, and `responder.enabled =
    /// false`, the gate returns Skip BEFORE calling execute_decision —
    /// which means no telemetry observation, no audit row, and the
    /// returned `(reason, false)` carries the responder-disabled
    /// message. Anti-regression for accidentally swapping the order
    /// of gate checks (any swap that lets the responder-disabled
    /// branch fall through to execute would auto-block on hosts that
    /// explicitly opted out).
    #[tokio::test]
    async fn execute_or_skip_decision_returns_skip_when_responder_disabled() {
        use innerwarden_core::incident::Incident;
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = config::AgentConfig::default();
        cfg.responder.enabled = false; // primary gate
        cfg.ai.confidence_threshold = 0.5;

        let incident = Incident {
            ts: chrono::Utc::now(),
            host: "h".into(),
            incident_id: "ssh_bruteforce:198.51.100.1:1".into(),
            severity: innerwarden_core::event::Severity::High,
            title: "SSH brute force".into(),
            summary: "many failed logins".into(),
            tags: vec![],
            entities: vec![innerwarden_core::entities::EntityRef::ip("198.51.100.1")],
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
        };
        let decision = ai::AiDecision {
            action: ai::AiAction::BlockIp {
                ip: "198.51.100.1".into(),
                skill_id: "block-ip-ufw".into(),
            },
            confidence: 0.95,
            reason: "test".into(),
            auto_execute: true, // would normally execute; gated by responder.enabled=false
            alternatives: vec![],
            estimated_threat: "high".into(),
        };

        let (reason, executed) =
            execute_or_skip_decision(&incident, &decision, dir.path(), &cfg, &mut state).await;
        assert!(!executed, "responder.enabled=false must short-circuit");
        assert!(
            reason.contains("responder disabled"),
            "reason should explicitly mention responder gate, got: {reason}"
        );
    }
}
