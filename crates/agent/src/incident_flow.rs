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
    // Pipeline test: recognise `innerwarden test` incidents by tag and
    // write an acknowledgement decision without calling the AI provider.
    if incident.tags.contains(&"pipeline-test".to_string()) {
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
        return PreAiFlowDecision::PipelineTestHandled;
    }

    // Neural model is advisory only — observes and logs but never triggers
    // blocks or notifications. The brain records its suggestion in brain-log.json
    // for operator review; actual blocking is left to rule-based detectors.
    let detector = incident.incident_id.split(':').next().unwrap_or("");
    if detector == "neural_anomaly" || detector == "host_drift" {
        return PreAiFlowDecision::SkipHandled;
    }

    if !ai_enabled {
        return PreAiFlowDecision::SkipHandled;
    }

    // Allowlist gate - skip AI for explicitly trusted IPs and users.
    // Merges static config allowlist with dynamic allowlist.toml (hot-reloaded every 30s).
    {
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
        if ip_allowlisted || user_allowlisted {
            info!(
                incident_id = %incident.incident_id,
                "AI gate: skipping (entity is in allowlist)"
            );
            return PreAiFlowDecision::SkipAllowlisted;
        }
    }

    if !ai::should_invoke_ai(incident, blocked_set, &cfg.ai.parsed_min_severity()) {
        // Distinguish "below severity threshold" from other skip reasons so
        // the caller can route low-severity noise to the auto-dismiss gate.
        let dominated_by_min = ai::is_below_severity_threshold(
            &incident.severity,
            &cfg.ai.parsed_min_severity(),
        );
        if dominated_by_min {
            info!(
                incident_id = %incident.incident_id,
                severity = ?incident.severity,
                "AI gate: skipping (below min_severity threshold)"
            );
            return PreAiFlowDecision::SkipBelowSeverity;
        }
        info!(
            incident_id = %incident.incident_id,
            severity = ?incident.severity,
            "AI gate: skipping (private IP / already blocked)"
        );
        return PreAiFlowDecision::SkipHandled;
    }

    // Decision cooldown - suppress repeated AI decisions for the same
    // action:detector:entity scope within a 1-hour window.
    let cooldown_cutoff =
        chrono::Utc::now() - chrono::Duration::seconds(crate::DECISION_COOLDOWN_SECS);
    let candidates = crate::decision_cooldown_candidates(incident);
    let in_cooldown = candidates.iter().any(|k| {
        state
            .store
            .get_cooldown(state_store::CooldownTable::Decision, k)
            .is_some_and(|ts| ts > cooldown_cutoff)
    });
    if in_cooldown {
        info!(
            incident_id = %incident.incident_id,
            "AI gate: skipping (decision cooldown active)"
        );
        return PreAiFlowDecision::SkipHandled;
    }

    // max_ai_calls_per_tick: enforce per-tick AI call budget.
    let max_calls = cfg.ai.max_ai_calls_per_tick;
    if max_calls > 0 && ai_calls_this_tick >= max_calls {
        info!(
            incident_id = %incident.incident_id,
            ai_calls_this_tick,
            max_calls,
            "AI gate: skipping (max_ai_calls_per_tick reached - deferred to next tick)"
        );
        return PreAiFlowDecision::SkipHandled;
    }

    PreAiFlowDecision::Proceed
}
