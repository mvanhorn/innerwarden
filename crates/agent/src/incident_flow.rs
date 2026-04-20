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
    /// Spec 028-b skip-fase3: detector prefix matches the operator's
    /// high-signal skip list (e.g. `threat_intel:`, `sudo_abuse:`,
    /// `suspicious_execution:`). When true, the below-severity and
    /// decision-cooldown guards are bypassed so the incident reaches
    /// decide(). Allowlist and per-tick budget still apply because
    /// those are safety, not noise.
    pub skip_fase3: bool,
}

/// Spec 028-b skip-fase3: return true when the incident_id is either
/// an exact match for an entry in the skip list or has the entry as a
/// prefix followed by `:`. Prefix matching handles both the
/// "just-the-detector" form (`threat_intel`) and the qualified form
/// (`threat_intel:threat_ip`). The colon guard prevents accidental
/// substring collisions (e.g. `threat_intel` must not match
/// `threat_intel_something_else` if such a thing ever appeared).
pub(super) fn matches_skip_fase3(incident_id: &str, skip_list: &[String]) -> bool {
    skip_list.iter().any(|entry| {
        if entry.is_empty() {
            return false;
        }
        incident_id == entry || incident_id.starts_with(&format!("{entry}:"))
    })
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

    // Spec 028-b skip-fase3: high-signal detectors bypass the
    // below-severity and decision-cooldown guards but still respect
    // allowlist (above) and the per-tick budget (below). The point is
    // that threat_intel / sudo_abuse / suspicious_execution should
    // never be noise-gated away — operators enable this list after
    // seeing zero-decision evidence in prod.
    if !inputs.skip_fase3 {
        if !inputs.passes_ai_gate {
            if inputs.below_severity_threshold {
                return PreAiGuardDecision::SkipBelowSeverity;
            }
            return PreAiGuardDecision::SkipPrivateOrBlocked;
        }

        if inputs.in_decision_cooldown {
            return PreAiGuardDecision::SkipDecisionCooldown;
        }
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
    // Spec 028-b skip-fase3: delegate the skip-list match to the pure
    // helper so it can be unit tested without a full AgentState.
    let skip_fase3 = matches_skip_fase3(
        &incident.incident_id,
        &cfg.incident_flow.detectors_skip_fase3,
    );
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
        skip_fase3,
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
            skip_fase3: false,
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

    // Spec 028-b skip-fase3: when the detector is on the operator's
    // skip list, the below-severity and decision-cooldown guards are
    // bypassed. This is the fix for the spec 028 evidence where
    // threat_intel / suspicious_execution / sudo_abuse had zero
    // decisions because they never survived the pre-AI gate.
    #[test]
    fn skip_fase3_bypasses_below_severity_guard() {
        let mut inputs = default_guard_inputs();
        inputs.passes_ai_gate = false;
        inputs.below_severity_threshold = true;
        // Without the skip: would return SkipBelowSeverity.
        inputs.skip_fase3 = true;
        assert_eq!(decide_pre_ai_guard(inputs), PreAiGuardDecision::Proceed);
    }

    #[test]
    fn skip_fase3_bypasses_decision_cooldown_guard() {
        let mut inputs = default_guard_inputs();
        inputs.in_decision_cooldown = true;
        // Without the skip: would return SkipDecisionCooldown.
        inputs.skip_fase3 = true;
        assert_eq!(decide_pre_ai_guard(inputs), PreAiGuardDecision::Proceed);
    }

    #[test]
    fn skip_fase3_still_respects_allowlist() {
        // Allowlist is safety, not noise — skip_fase3 must not bypass
        // it. A threat_intel hit on an allowlisted IP still skips AI.
        let mut inputs = default_guard_inputs();
        inputs.skip_fase3 = true;
        inputs.is_allowlisted = true;
        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipAllowlisted
        );
    }

    #[test]
    fn skip_fase3_still_respects_per_tick_budget() {
        // Per-tick AI budget is the operator's cost cap; skip_fase3
        // must respect it so a burst of threat_intel hits does not
        // exhaust the budget in a single tick.
        let mut inputs = default_guard_inputs();
        inputs.skip_fase3 = true;
        inputs.ai_calls_this_tick = 3;
        inputs.max_ai_calls_per_tick = 3;
        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipAiCallBudget
        );
    }

    #[test]
    fn skip_fase3_still_respects_ai_disabled() {
        // If AI is turned off entirely, skip_fase3 is meaningless.
        let mut inputs = default_guard_inputs();
        inputs.skip_fase3 = true;
        inputs.ai_enabled = false;
        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipAiDisabled
        );
    }

    #[test]
    fn skip_fase3_off_default_preserves_existing_behaviour() {
        // Regression guard: the new field must default to false so
        // incidents that do not match the operator's skip list behave
        // identically to the pre-028-b gate.
        let mut inputs = default_guard_inputs();
        inputs.skip_fase3 = false;
        inputs.passes_ai_gate = false;
        inputs.below_severity_threshold = true;
        assert_eq!(
            decide_pre_ai_guard(inputs),
            PreAiGuardDecision::SkipBelowSeverity
        );
    }

    // Spec 028-b skip-fase3: matches_skip_fase3 covers the prefix /
    // exact / colon-separator matching rules. Kept pure so the match
    // logic can be tested without an AgentState or AgentConfig.
    #[test]
    fn matches_skip_fase3_exact_match() {
        let skip = vec!["threat_intel:threat_ip".to_string()];
        assert!(matches_skip_fase3("threat_intel:threat_ip", &skip));
    }

    #[test]
    fn matches_skip_fase3_prefix_match_with_colon() {
        let skip = vec!["sudo_abuse".to_string()];
        assert!(matches_skip_fase3("sudo_abuse:ubuntu", &skip));
        assert!(matches_skip_fase3("sudo_abuse:root:2026-04-20", &skip));
    }

    #[test]
    fn matches_skip_fase3_rejects_substring_without_colon() {
        // `threat_intel` must not match `threat_intel_extended` because
        // that is a different detector. The colon guard enforces this.
        let skip = vec!["threat_intel".to_string()];
        assert!(!matches_skip_fase3("threat_intel_extended:foo", &skip));
        assert!(!matches_skip_fase3("threat_intelligence_feed", &skip));
    }

    #[test]
    fn matches_skip_fase3_empty_list_returns_false() {
        assert!(!matches_skip_fase3("threat_intel:threat_ip", &[]));
    }

    #[test]
    fn matches_skip_fase3_ignores_empty_entries() {
        // Defensive: operator typo in the config that leaves an empty
        // string in the list must not match every incident.
        let skip = vec!["".to_string()];
        assert!(!matches_skip_fase3("any:incident:id", &skip));
    }

    #[test]
    fn matches_skip_fase3_mixed_list() {
        let skip = vec![
            "threat_intel:threat_ip".to_string(),
            "sudo_abuse".to_string(),
            "suspicious_execution".to_string(),
        ];
        assert!(matches_skip_fase3("threat_intel:threat_ip", &skip));
        assert!(matches_skip_fase3("sudo_abuse:ubuntu", &skip));
        assert!(matches_skip_fase3("suspicious_execution:unknown", &skip));
        assert!(!matches_skip_fase3("ssh_bruteforce:1.2.3.4", &skip));
    }
}
