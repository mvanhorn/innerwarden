use std::collections::HashSet;

use tracing::{info, warn};

use crate::{ai, allowlist, config, state_store, AgentState};

pub(crate) enum PreAiFlowDecision {
    Proceed,
    SkipHandled,
    /// Entity is in allowlist — skip AI but mark in graph.
    SkipAllowlisted,
    PipelineTestHandled,
    /// Incident severity is below the configured AI min_severity threshold.
    /// Eligible for rule-based auto-dismiss (noise gate) when Guard mode is ON.
    SkipBelowSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PreAiGuardDecision {
    Proceed,
    PipelineTestHandled,
    SkipAdvisoryDetector,
    SkipAiDisabled,
    SkipAllowlisted,
    SkipBelowSeverity,
    SkipPrivateOrBlocked,
    SkipDecisionCooldown,
    SkipAiCallBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PreAiGuardInputs {
    pub is_pipeline_test: bool,
    pub is_advisory_detector: bool,
    pub ai_enabled: bool,
    pub is_allowlisted: bool,
    pub passes_ai_gate: bool,
    pub below_severity_threshold: bool,
    pub in_decision_cooldown: bool,
    pub ai_calls_this_tick: usize,
    pub max_ai_calls_per_tick: usize,
}

pub(super) fn decide_pre_ai_guard(inputs: PreAiGuardInputs) -> PreAiGuardDecision {
    if inputs.is_pipeline_test {
        return PreAiGuardDecision::PipelineTestHandled;
    }

    // Neural model detectors remain advisory-only and never go through AI.
    if inputs.is_advisory_detector {
        return PreAiGuardDecision::SkipAdvisoryDetector;
    }

    if !inputs.ai_enabled {
        return PreAiGuardDecision::SkipAiDisabled;
    }

    if inputs.is_allowlisted {
        return PreAiGuardDecision::SkipAllowlisted;
    }

    if !inputs.passes_ai_gate {
        if inputs.below_severity_threshold {
            return PreAiGuardDecision::SkipBelowSeverity;
        }
        return PreAiGuardDecision::SkipPrivateOrBlocked;
    }

    if inputs.in_decision_cooldown {
        return PreAiGuardDecision::SkipDecisionCooldown;
    }

    if inputs.max_ai_calls_per_tick > 0 && inputs.ai_calls_this_tick >= inputs.max_ai_calls_per_tick
    {
        return PreAiGuardDecision::SkipAiCallBudget;
    }

    PreAiGuardDecision::Proceed
}

/// Evaluate all pre-AI gates for one incident.
/// This keeps `process_incidents` focused on orchestration and leaves
/// eligibility logic in one cohesive place.
pub(crate) fn evaluate_pre_ai_flow(
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    ai_enabled: bool,
    blocked_set: &HashSet<String>,
    ai_calls_this_tick: usize,
) -> PreAiFlowDecision {
    let detector = incident.incident_id.split(':').next().unwrap_or("");
    let mut guard_inputs = PreAiGuardInputs {
        is_pipeline_test: incident.tags.iter().any(|tag| tag == "pipeline-test"),
        is_advisory_detector: detector == "neural_anomaly" || detector == "host_drift",
        ai_enabled,
        is_allowlisted: false,
        passes_ai_gate: true,
        below_severity_threshold: false,
        in_decision_cooldown: false,
        ai_calls_this_tick,
        max_ai_calls_per_tick: cfg.ai.max_ai_calls_per_tick,
    };

    if ai_enabled {
        // Allowlist gate - skip AI for explicitly trusted IPs and users.
        // Merges static config allowlist with dynamic allowlist.toml (hot-reloaded every 30s).
        use innerwarden_core::entities::EntityType;
        let ip_allowlisted = incident
            .entities
            .iter()
            .find(|e| e.r#type == EntityType::Ip)
            .is_some_and(|e| {
                allowlist::is_ip_allowlisted(&e.value, &cfg.allowlist.trusted_ips)
                    || allowlist::is_ip_allowlisted(&e.value, &state.dynamic_trusted_ips)
            });
        let user_allowlisted = incident
            .entities
            .iter()
            .find(|e| e.r#type == EntityType::User)
            .is_some_and(|e| {
                allowlist::is_user_allowlisted(&e.value, &cfg.allowlist.trusted_users)
                    || allowlist::is_user_allowlisted(&e.value, &state.dynamic_trusted_users)
            });
        guard_inputs.is_allowlisted = ip_allowlisted || user_allowlisted;

        if !guard_inputs.is_allowlisted {
            let min_severity = cfg.ai.parsed_min_severity();
            guard_inputs.passes_ai_gate =
                ai::should_invoke_ai(incident, blocked_set, &min_severity);
            guard_inputs.below_severity_threshold =
                ai::is_below_severity_threshold(&incident.severity, &min_severity);

            if guard_inputs.passes_ai_gate {
                // Decision cooldown - suppress repeated AI decisions for the same
                // action:detector:entity scope within a 1-hour window.
                let cooldown_cutoff =
                    chrono::Utc::now() - chrono::Duration::seconds(crate::DECISION_COOLDOWN_SECS);
                let candidates = crate::decision_cooldown_candidates(incident);
                guard_inputs.in_decision_cooldown = candidates.iter().any(|k| {
                    state
                        .store
                        .get_cooldown(state_store::CooldownTable::Decision, k)
                        .is_some_and(|ts| ts > cooldown_cutoff)
                });
            }
        }
    }

    match decide_pre_ai_guard(guard_inputs) {
        PreAiGuardDecision::PipelineTestHandled => {
            // Pipeline test: recognise `innerwarden test` incidents by tag and
            // write an acknowledgement decision without calling the AI provider.
            info!(
                incident_id = %incident.incident_id,
                "pipeline test incident detected - writing acknowledgement decision"
            );
            let test_ip = incident
                .entities
                .iter()
                .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
                .map(|e| e.value.clone());
            let entry = crate::decisions::DecisionEntry {
                ts: chrono::Utc::now(),
                incident_id: incident.incident_id.clone(),
                host: incident.host.clone(),
                ai_provider: "pipeline-test".to_string(),
                action_type: "monitor".to_string(),
                target_ip: test_ip,
                target_user: None,
                skill_id: None,
                confidence: 1.0,
                auto_executed: false,
                dry_run: true,
                reason: "Pipeline test acknowledged - sensor → agent → decision path is working"
                    .to_string(),
                estimated_threat: "none".to_string(),
                execution_result: "test-ok".to_string(),
                prev_hash: None,
            };
            if let Some(writer) = &mut state.decision_writer {
                if let Err(e) = writer.write(&entry) {
                    warn!("failed to write pipeline-test decision: {e:#}");
                }
            }
            PreAiFlowDecision::PipelineTestHandled
        }
        // Neural model is advisory only — observes and logs but never triggers
        // blocks or notifications. The brain records its suggestion in brain-log.json
        // for operator review; actual blocking is left to rule-based detectors.
        PreAiGuardDecision::SkipAdvisoryDetector | PreAiGuardDecision::SkipAiDisabled => {
            PreAiFlowDecision::SkipHandled
        }
        PreAiGuardDecision::SkipAllowlisted => {
            info!(
                incident_id = %incident.incident_id,
                "AI gate: skipping (entity is in allowlist)"
            );
            PreAiFlowDecision::SkipAllowlisted
        }
        PreAiGuardDecision::SkipBelowSeverity => {
            info!(
                incident_id = %incident.incident_id,
                severity = ?incident.severity,
                "AI gate: skipping (below min_severity threshold)"
            );
            PreAiFlowDecision::SkipBelowSeverity
        }
        PreAiGuardDecision::SkipPrivateOrBlocked => {
            info!(
                incident_id = %incident.incident_id,
                severity = ?incident.severity,
                "AI gate: skipping (private IP / already blocked)"
            );
            PreAiFlowDecision::SkipHandled
        }
        PreAiGuardDecision::SkipDecisionCooldown => {
            info!(
                incident_id = %incident.incident_id,
                "AI gate: skipping (decision cooldown active)"
            );
            PreAiFlowDecision::SkipHandled
        }
        PreAiGuardDecision::SkipAiCallBudget => {
            // max_ai_calls_per_tick: enforce per-tick AI call budget.
            let max_calls = cfg.ai.max_ai_calls_per_tick;
            info!(
                incident_id = %incident.incident_id,
                ai_calls_this_tick,
                max_calls,
                "AI gate: skipping (max_ai_calls_per_tick reached - deferred to next tick)"
            );
            PreAiFlowDecision::SkipHandled
        }
        PreAiGuardDecision::Proceed => PreAiFlowDecision::Proceed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_guard_inputs() -> PreAiGuardInputs {
        PreAiGuardInputs {
            is_pipeline_test: false,
            is_advisory_detector: false,
            ai_enabled: true,
            is_allowlisted: false,
            passes_ai_gate: true,
            below_severity_threshold: false,
            in_decision_cooldown: false,
            ai_calls_this_tick: 0,
            max_ai_calls_per_tick: 10,
        }
    }

    #[test]
    fn decide_pre_ai_guard_pipeline_test_has_highest_priority() {
        // Invariant: pipeline-test incidents must short-circuit all later guard checks.
        let mut inputs = default_guard_inputs();
        inputs.is_pipeline_test = true;
        inputs.is_advisory_detector = true;
        inputs.ai_enabled = false;
        inputs.is_allowlisted = true;
        inputs.passes_ai_gate = false;
        inputs.below_severity_threshold = true;
        inputs.in_decision_cooldown = true;
        inputs.ai_calls_this_tick = 99;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::PipelineTestHandled
        );
    }

    #[test]
    fn decide_pre_ai_guard_advisory_detector_short_circuits_ai_disabled() {
        // Invariant: advisory-only detectors stay in observe mode even when AI is disabled.
        let mut inputs = default_guard_inputs();
        inputs.is_advisory_detector = true;
        inputs.ai_enabled = false;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipAdvisoryDetector
        );
    }

    #[test]
    fn decide_pre_ai_guard_skips_when_ai_is_disabled() {
        // Invariant: when AI is disabled, incidents should skip the entire AI guard chain.
        let mut inputs = default_guard_inputs();
        inputs.ai_enabled = false;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipAiDisabled
        );
    }

    #[test]
    fn decide_pre_ai_guard_allowlist_takes_precedence_over_ai_gate_outcome() {
        // Invariant: allowlisted entities must bypass AI before private/block/noise gate evaluation.
        let mut inputs = default_guard_inputs();
        inputs.is_allowlisted = true;
        inputs.passes_ai_gate = false;
        inputs.below_severity_threshold = true;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipAllowlisted
        );
    }

    #[test]
    fn decide_pre_ai_guard_returns_skip_below_severity_when_min_severity_dominates() {
        // Invariant: below-min-severity incidents must route to the dedicated noise-gate branch.
        let mut inputs = default_guard_inputs();
        inputs.passes_ai_gate = false;
        inputs.below_severity_threshold = true;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipBelowSeverity
        );
    }

    #[test]
    fn decide_pre_ai_guard_returns_skip_private_or_blocked_for_non_severity_gate_failures() {
        // Invariant: AI-gate failures unrelated to min severity map to private/already-blocked skips.
        let mut inputs = default_guard_inputs();
        inputs.passes_ai_gate = false;
        inputs.below_severity_threshold = false;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipPrivateOrBlocked
        );
    }

    #[test]
    fn decide_pre_ai_guard_returns_skip_decision_cooldown_after_gate_pass() {
        // Invariant: cooldown must suppress repeated AI decisions when earlier gates already passed.
        let mut inputs = default_guard_inputs();
        inputs.in_decision_cooldown = true;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipDecisionCooldown
        );
    }

    #[test]
    fn decide_pre_ai_guard_returns_skip_ai_call_budget_when_limit_reached() {
        // Invariant: per-tick AI call budgets must defer additional incidents to the next tick.
        let mut inputs = default_guard_inputs();
        inputs.ai_calls_this_tick = 3;
        inputs.max_ai_calls_per_tick = 3;

        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipAiCallBudget
        );
    }

    #[test]
    fn decide_pre_ai_guard_returns_proceed_when_all_guards_pass() {
        // Invariant: incidents should proceed only when every pre-AI guard check passes.
        let inputs = default_guard_inputs();

        assert_eq!(decide_pre_ai_guard(inputs), PreAiGuardDecision::Proceed);
    }
}
