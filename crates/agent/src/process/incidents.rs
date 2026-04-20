use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use tracing::{info, warn};

use crate::dashboard::AdvisoryEntry;
use crate::{
    ai, config, dna_inline, incident_abuseipdb, incident_action_report, incident_advisory,
    incident_ai_context, incident_ai_failure, incident_attacker_profile, incident_audit_write,
    incident_auto_rules, incident_autodismiss, incident_crowdsec, incident_decision_eval,
    incident_enrichment, incident_execution_gate, incident_flow, incident_forensics,
    incident_honeypot_router, incident_honeypot_suggestion, incident_notifications,
    incident_obvious, incident_playbook, incident_post_decision, incident_prelude,
    incident_reputation, process::telegram_approval::process_telegram_approval, reader, skills,
    telegram, telemetry_tick, AgentState,
};

// ---------------------------------------------------------------------------
// Incident tick - runs every 2s
//
// Responsibilities (in order, for every new incident):
//   1. Webhook: notify immediately for all incidents above min_severity
//   2. AI analysis: only for High/Critical that pass the algorithm gate
//
// The incident cursor is advanced and saved after every tick, so a crash
// between ticks never causes double-processing or lost webhook notifications.
// ---------------------------------------------------------------------------

/// Returns the number of incidents handled (webhook sent and/or AI analyzed).
pub(crate) async fn process_incidents(
    data_dir: &Path,
    cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    advisory_cache: &Arc<RwLock<VecDeque<AdvisoryEntry>>>,
) -> usize {
    if cfg.responder.enabled
        && cfg
            .responder
            .allowed_skills
            .iter()
            .any(|id| id == "suspend-user-sudo")
    {
        match skills::builtin::cleanup_expired_sudo_suspensions(data_dir, cfg.responder.dry_run)
            .await
        {
            Ok(removed) => {
                if removed > 0 {
                    info!(removed, "expired sudo suspensions cleaned up");
                }
            }
            Err(e) => {
                state.telemetry.observe_error("suspend_user_sudo_cleanup");
                warn!("failed to cleanup expired sudo suspensions: {e:#}");
            }
        }
    }

    if cfg.responder.enabled
        && cfg
            .responder
            .allowed_skills
            .iter()
            .any(|id| id == "rate-limit-nginx")
    {
        match skills::builtin::cleanup_expired_nginx_blocks(data_dir, cfg.responder.dry_run).await {
            Ok(removed) => {
                if removed > 0 {
                    info!(removed, "expired nginx deny rules cleaned up");
                }
            }
            Err(e) => {
                state.telemetry.observe_error("rate_limit_nginx_cleanup");
                warn!("failed to cleanup expired nginx blocks: {e:#}");
            }
        }
    }

    if cfg.responder.enabled
        && cfg
            .responder
            .allowed_skills
            .iter()
            .any(|id| id == "block-container")
    {
        match skills::builtin::cleanup_expired_container_blocks(data_dir, cfg.responder.dry_run)
            .await
        {
            Ok(removed) => {
                if removed > 0 {
                    info!(removed, "expired container pauses lifted");
                }
            }
            Err(e) => {
                state.telemetry.observe_error("block_container_cleanup");
                warn!("failed to cleanup expired container blocks: {e:#}");
            }
        }
    }

    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    let new_incidents = if let Some(ref sq) = state.sqlite_store {
        let cval = sq.get_agent_cursor("incidents").unwrap_or(0);
        match sq.incidents_since(cval, 5000) {
            Ok(rows) if !rows.is_empty() => {
                let max_id = rows.last().unwrap().0;
                let entries = rows.into_iter().map(|(_, inc)| inc).collect();
                let _ = sq.set_agent_cursor("incidents", max_id);
                reader::ReadResult {
                    entries,
                    new_offset: 0,
                }
            }
            _ => reader::ReadResult {
                entries: vec![],
                new_offset: 0,
            },
        }
    } else {
        warn!("sqlite_store not available — cannot read incidents");
        return 0;
    };

    // Drain any pending T.2/T.3 approval results from the Telegram polling task.
    // This MUST run before the early-return below, otherwise bot commands
    // (/status, /menu, etc.) would never be processed when there are no new incidents.
    let pending_approvals: Vec<telegram::ApprovalResult> = {
        let mut results = Vec::new();
        if let Some(rx) = state.approval_rx.as_mut() {
            while let Ok(r) = rx.try_recv() {
                results.push(r);
            }
        }
        results
    };
    for approval in pending_approvals {
        process_telegram_approval(approval, data_dir, cfg, state).await;
    }

    // Expire stale pending confirmations and honeypot choices
    let now = chrono::Utc::now();
    state
        .pending_confirmations
        .retain(|_, (pending, _, _)| pending.expires_at > now);
    state
        .pending_honeypot_choices
        .retain(|_, choice| choice.expires_at > now);

    // Drain neural incidents (autoencoder) into the processing pipeline.
    // These couldn't be written to the sensor's file (different user).
    let neural = std::mem::take(&mut state.neural_incidents);
    if !neural.is_empty() {
        info!(count = neural.len(), "processing buffered neural incidents");
    }

    if new_incidents.entries.is_empty() && neural.is_empty() {
        return 0;
    }

    // Advance cursor before any async work - prevents double-processing on crash/restart
    cursor.set_incidents_offset(&today, new_incidents.new_offset);

    let notification_thresholds =
        incident_notifications::compute_notification_thresholds(cfg, state);

    // Circuit breaker: if a previous tick tripped the breaker, check if cooldown expired
    if let Some(until) = state.circuit_breaker_until {
        if chrono::Utc::now() < until {
            info!(
                until = %until,
                incident_count = new_incidents.entries.len(),
                "AI circuit breaker open - skipping AI analysis for this tick"
            );
            // Still process webhooks/notifications below, just skip AI
        } else {
            info!("AI circuit breaker reset after cooldown");
            state.circuit_breaker_until = None;
        }
    }

    // Trip circuit breaker if incident volume exceeds threshold
    let circuit_breaker_open = if cfg.ai.circuit_breaker_threshold > 0
        && new_incidents.entries.len() >= cfg.ai.circuit_breaker_threshold
        && state.circuit_breaker_until.is_none()
    {
        let until = chrono::Utc::now()
            + chrono::Duration::seconds(cfg.ai.circuit_breaker_cooldown_secs as i64);
        warn!(
            incident_count = new_incidents.entries.len(),
            threshold = cfg.ai.circuit_breaker_threshold,
            cooldown_secs = cfg.ai.circuit_breaker_cooldown_secs,
            until = %until,
            "AI circuit breaker TRIPPED - high-volume incident burst detected, skipping AI"
        );
        state.circuit_breaker_until = Some(until);
        true
    } else {
        state.circuit_breaker_until.is_some()
    };

    // Pre-compute AI context (only if AI is configured and circuit breaker is not open).
    //
    // Spec 029 PR-C.2: provider resolution migrated to the capability
    // router. This is the Decide path, so we pull from
    // `state.ai_router.provider_for(Capability::Decide)`. When the
    // operator has configured a dedicated classifier via
    // `[ai.classifier]`, this now routes triage through the
    // classifier without touching the rest of the decision pipeline.
    // The legacy `state.ai_provider` field still populates both
    // router slots during PR-C (removed in PR-C.3), so behaviour is
    // identical for legacy configs.
    let decide_provider = state.ai_router.provider_for(ai::Capability::Decide);
    let ai_enabled = cfg.ai.enabled && decide_provider.is_some() && !circuit_breaker_open;
    let (all_events, skill_infos, ai_provider, provider_name, already_blocked, mut blocked_set) =
        if ai_enabled {
            let events = if let Some(ref sq) = state.sqlite_store {
                sq.events_since(0, 50_000)
                    .map(|rows| rows.into_iter().map(|(_, ev)| ev).collect())
                    .unwrap_or_default()
            } else {
                warn!("sqlite_store not available — AI context will have no events");
                vec![]
            };
            let infos = state.skill_registry.infos();
            // Owned handle from the router, no borrow of `state` across
            // async calls below.
            let prov: Arc<dyn ai::AiProvider> = decide_provider.expect("decide_provider checked");
            let pname = prov.name();
            let blocked = state.blocklist.as_vec();
            // Mutable so we can update it mid-tick to prevent duplicate AI calls
            // for the same IP when multiple incidents arrive in the same 2s window.
            let blocked_set: HashSet<String> = blocked.iter().cloned().collect();
            (events, infos, Some(prov), pname, blocked, blocked_set)
        } else {
            (vec![], vec![], None, "", vec![], HashSet::new())
        };

    let mut handled = 0;
    let mut ai_calls_this_tick: usize = 0;

    let all_incidents: Vec<&innerwarden_core::incident::Incident> =
        new_incidents.entries.iter().chain(neural.iter()).collect();

    // Feed incidents into knowledge graph
    {
        let mut graph = state.knowledge_graph.write().unwrap();
        for incident in &all_incidents {
            graph.ingest_incident(incident);
        }
    }

    // Feed incidents into DNA attack chain tracker (MITRE ATT&CK progression).
    if cfg.dna.enabled {
        let incident_refs: Vec<innerwarden_core::incident::Incident> =
            all_incidents.iter().map(|i| (*i).clone()).collect();
        dna_inline::process_incidents(
            &mut state.dna_state,
            &incident_refs,
            &mut state.correlation_engine,
        );
    }

    for incident in &all_incidents {
        state.telemetry.observe_incident(incident);

        // Dedup: suppress sensor incident if graph handles this detector
        {
            let sensor_detector = incident.incident_id.split(':').next().unwrap_or("");
            let entity_value = incident
                .entities
                .first()
                .map(|e| e.value.as_str())
                .unwrap_or("");

            // Phase 3D: if detector is in graph_only_detectors, always suppress sensor version
            if cfg
                .graph_only_detectors
                .iter()
                .any(|d| d == sensor_detector)
            {
                tracing::debug!(
                    incident_id = %incident.incident_id,
                    "sensor incident suppressed: detector is graph-only"
                );
                handled += 1;
                continue;
            }

            // Otherwise, suppress if graph recently detected same entity
            if state.graph_detector_state.should_suppress_sensor(
                sensor_detector,
                entity_value,
                chrono::Utc::now(),
            ) {
                tracing::debug!(
                    incident_id = %incident.incident_id,
                    "sensor incident suppressed: graph already detected"
                );
                handled += 1;
                continue;
            }
        }

        // VirusTotal enrichment: when YARA scanner detects a binary, check its
        // SHA-256 hash against VT. Result logged for operator context.
        if incident.incident_id.starts_with("yara_scan:") {
            if let Some(hash) = incident
                .evidence
                .get(0)
                .and_then(|e| e.get("sha256"))
                .and_then(|v| v.as_str())
            {
                if let Some(ref tf) = state.threat_feed {
                    match tf.check_virustotal(hash).await {
                        Some(vt) if vt.is_malicious => {
                            info!(
                                incident_id = %incident.incident_id,
                                sha256 = %hash,
                                malicious = vt.malicious,
                                suspicious = vt.suspicious,
                                "VirusTotal CONFIRMED malicious: {}/{} engines",
                                vt.malicious,
                                vt.malicious + vt.suspicious + vt.undetected
                            );
                        }
                        Some(vt) => {
                            info!(
                                incident_id = %incident.incident_id,
                                sha256 = %hash,
                                malicious = vt.malicious,
                                "VirusTotal: {}/{} engines flagged",
                                vt.malicious,
                                vt.malicious + vt.suspicious + vt.undetected
                            );
                        }
                        None => {} // VT not configured or request failed
                    }
                }
            }
        }

        incident_attacker_profile::update_incident_ip_profiles(incident, state);

        incident_forensics::maybe_capture_incident_forensics(incident, state);

        let related_incidents =
            incident_prelude::prepare_incident_prelude(incident, cfg, state).await;

        incident_notifications::dispatch_incident_notifications(
            incident,
            data_dir,
            cfg,
            state,
            &notification_thresholds,
        )
        .await;

        incident_advisory::handle_advisory_violation(incident, advisory_cache, state).await;

        // 1b. Enrichment — runs for ALL incidents regardless of severity.
        // GeoIP + AbuseIPDB + attacker profile update must happen before the
        // AI gate filters out low-severity incidents, otherwise auto-blocked
        // and low-severity IPs never get country/abuse_confidence data.
        let ip_geo_early = incident_enrichment::lookup_incident_geoip(incident, state).await;
        let ip_rep_early = incident_reputation::lookup_abuseipdb_reputation(incident, state).await;
        incident_enrichment::enrich_attacker_identity(
            incident,
            state,
            ip_geo_early.as_ref(),
            ip_rep_early.as_ref(),
        );
        incident_enrichment::log_threat_feed_match(incident, state);

        // 2. Auto-response rules (Layer 1) — deterministic, no AI needed.
        //    Runs BEFORE noise-gate so it sees ALL incidents regardless of severity.
        if incident_auto_rules::try_handle_auto_rule(incident, data_dir, cfg, state).await {
            state.grouping_engine.mark_auto_resolved(incident);
            handled += 1;
            continue;
        }

        // 3. AI analysis - only when AI is enabled and incident passes the gate.
        match incident_flow::evaluate_pre_ai_flow(
            incident,
            cfg,
            state,
            ai_enabled,
            &blocked_set,
            ai_calls_this_tick,
        ) {
            incident_flow::PreAiFlowDecision::Proceed => {}
            incident_flow::PreAiFlowDecision::SkipAllowlisted => {
                // Mark the incident node as allowlisted in the knowledge graph
                let mut graph = state.knowledge_graph.write().unwrap();
                graph.set_allowlisted(&incident.incident_id, true);
                drop(graph);
                handled += 1;
                continue;
            }
            incident_flow::PreAiFlowDecision::SkipBelowSeverity => {
                // Low-severity noise: write auto-dismiss decision so the
                // dashboard shows a clear outcome instead of "needs attention".
                if incident_autodismiss::try_autodismiss_noise(incident, cfg, state) {
                    state.grouping_engine.mark_auto_resolved(incident);
                }
                handled += 1;
                continue;
            }
            incident_flow::PreAiFlowDecision::SkipHandled
            | incident_flow::PreAiFlowDecision::PipelineTestHandled => {
                handled += 1;
                continue;
            }
        }

        if incident_obvious::try_handle_obvious_incident(incident, data_dir, cfg, state).await {
            state.grouping_engine.mark_auto_resolved(incident);
            handled += 1;
            continue;
        }

        state.telemetry.observe_gate_pass();

        // ai_provider is Some when ai_enabled - safe to unwrap
        let provider = ai_provider.as_ref().unwrap();

        info!(
            incident_id = %incident.incident_id,
            provider = provider_name,
            correlated_count = related_incidents.len(),
            "sending incident to AI for analysis"
        );

        let ai_context_inputs = incident_ai_context::build_ai_context_inputs(
            incident,
            &all_events,
            &related_incidents,
            cfg.ai.context_events,
        );

        // ── Auto-handle decisions (may `continue` to skip AI) ──────────
        // Enrichment already ran in step 1b. Reuse the results.
        let ip_reputation = ip_rep_early;

        if incident_abuseipdb::try_handle_abuseipdb_autoblock(
            incident,
            data_dir,
            cfg,
            state,
            ip_reputation.as_ref(),
            &mut blocked_set,
        )
        .await
        {
            state.grouping_engine.mark_auto_resolved(incident);
            handled += 1;
            continue;
        }

        if incident_crowdsec::try_handle_crowdsec_autoblock(
            incident,
            data_dir,
            cfg,
            state,
            &mut blocked_set,
        )
        .await
        {
            state.grouping_engine.mark_auto_resolved(incident);
            handled += 1;
            continue;
        }

        if incident_honeypot_router::try_handle_honeypot_routing(
            incident,
            data_dir,
            cfg,
            state,
            &blocked_set,
        )
        .await
        {
            handled += 1;
            continue;
        }

        // Build graph context: attack narrative from knowledge graph neighborhood.
        // Phase 015: prefer the Incident node as center (richest context after 014-D
        // incident enrichment links incidents to processes), fall back to entity nodes.
        //
        // Spec 025: alongside the prose narrative, also emit the same
        // neighbourhood as a structured JSON subgraph. Providers prefer
        // the subgraph; prose stays as a fallback for providers that
        // haven't been updated and for the decision audit pipeline.
        // The subgraph is gated by `ai.use_structured_subgraph` (default
        // true) so operators can A/B compare against the prose-only prod
        // behaviour for 48h on existing installs before flipping over.
        let (graph_context, graph_subgraph) = {
            let graph = state.knowledge_graph.read().unwrap();
            let center_node = graph.find_by_incident(&incident.incident_id).or_else(|| {
                incident.entities.iter().find_map(|e| match e.r#type {
                    innerwarden_core::entities::EntityType::Ip => graph.find_by_ip(&e.value),
                    innerwarden_core::entities::EntityType::User => graph.find_by_user(&e.value),
                    innerwarden_core::entities::EntityType::Path => graph.find_by_path(&e.value),
                    innerwarden_core::entities::EntityType::Container => {
                        graph.find_by_container(&e.value)
                    }
                    _ => None,
                })
            });
            match center_node {
                Some(node) => {
                    let narrative = Some(graph.attack_narrative(node, 3));
                    let subgraph = if cfg.ai.use_structured_subgraph {
                        Some(graph.attack_subgraph_json(node, 3))
                    } else {
                        None
                    };
                    (narrative, subgraph)
                }
                None => (None, None),
            }
        };

        let ctx = ai::DecisionContext {
            incident,
            recent_events: ai_context_inputs.recent_events,
            related_incidents: ai_context_inputs.related_incidents,
            already_blocked: already_blocked.clone(),
            available_skills: skill_infos
                .iter()
                .map(|s| ai::SkillInfo {
                    id: s.id.clone(),
                    applicable_to: s.applicable_to.clone(),
                })
                .collect(),
            ip_reputation: ip_reputation.clone(),
            ip_geo: ip_geo_early.clone(),
            graph_context,
            graph_subgraph,
        };

        state.telemetry.observe_ai_sent();
        let decision_start = Instant::now();
        let mut decision = match provider.decide(&ctx).await {
            Ok(d) => d,
            Err(e) => {
                incident_ai_failure::handle_ai_decision_failure(
                    incident,
                    provider_name,
                    cfg,
                    state,
                    &e,
                );

                handled += 1;
                continue;
            }
        };
        let latency_ms = decision_start.elapsed().as_millis();
        state
            .telemetry
            .observe_ai_decision(&decision.action, latency_ms);
        ai_calls_this_tick += 1;

        incident_post_decision::apply_post_decision_safeguards(
            incident,
            cfg,
            state,
            &mut decision,
            &mut blocked_set,
        );

        incident_decision_eval::apply_correlation_boost_and_log_decision(
            incident,
            cfg,
            state,
            &mut decision,
            data_dir,
        );

        if incident_honeypot_suggestion::maybe_defer_honeypot_to_operator(
            incident,
            provider_name,
            &decision,
            cfg,
            state,
        )
        .await
        {
            handled += 1;
            continue;
        }

        let (execution_result, cloudflare_pushed) =
            incident_execution_gate::execute_or_skip_decision(
                incident, &decision, data_dir, cfg, state,
            )
            .await;

        incident_audit_write::write_decision_audit_entry(
            incident,
            provider_name,
            &decision,
            &execution_result,
            cfg,
            state,
        );

        // Feed decision into knowledge graph
        {
            let (action_type, action_target) = match &decision.action {
                ai::AiAction::BlockIp { ip, .. } => ("block_ip", Some(ip.as_str())),
                ai::AiAction::Monitor { ip } => ("monitor", Some(ip.as_str())),
                ai::AiAction::Honeypot { ip } => ("honeypot", Some(ip.as_str())),
                ai::AiAction::SuspendUserSudo { user, .. } => {
                    ("suspend_user_sudo", Some(user.as_str()))
                }
                ai::AiAction::KillProcess { user, .. } => ("kill_process", Some(user.as_str())),
                ai::AiAction::BlockContainer { container_id, .. } => {
                    ("block_container", Some(container_id.as_str()))
                }
                ai::AiAction::Ignore { .. } => ("ignore", None),
                ai::AiAction::RequestConfirmation { .. } => ("request_confirmation", None),
                ai::AiAction::KillChainResponse { .. } => ("kill_chain_response", None),
            };
            let auto_executed = decision.auto_execute && !execution_result.is_empty();
            let mut graph = state.knowledge_graph.write().unwrap();
            graph.ingest_decision(
                &incident.incident_id,
                action_type,
                action_target,
                decision.confidence,
                &decision.reason,
                auto_executed,
                chrono::Utc::now(),
            );
        }

        incident_playbook::maybe_evaluate_and_persist_playbook(incident, data_dir, state);

        incident_action_report::maybe_send_post_execution_telegram_report(
            incident,
            &decision,
            &execution_result,
            cloudflare_pushed,
            cfg,
            state,
            ip_reputation.as_ref(),
            ip_geo_early.as_ref(),
        );

        handled += 1;
    }

    telemetry_tick::write_tick_snapshot(state, "incident_tick");

    handled
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn advisory_cache() -> Arc<RwLock<VecDeque<AdvisoryEntry>>> {
        Arc::new(RwLock::new(VecDeque::new()))
    }

    #[tokio::test]
    async fn process_incidents_returns_zero_without_sqlite_store() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cursor = reader::AgentCursor::default();
        let cfg = config::AgentConfig::default();

        let handled =
            process_incidents(dir.path(), &mut cursor, &cfg, &mut state, &advisory_cache()).await;

        assert_eq!(handled, 0);
    }

    #[tokio::test]
    async fn process_incidents_prunes_expired_pending_entries_without_new_incidents() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let store = crate::tests::test_sqlite_store(dir.path());
        state.sqlite_store = Some(store);
        state.pending_confirmations.insert(
            "expired".to_string(),
            (
                crate::telegram::PendingConfirmation {
                    incident_id: "inc-1".to_string(),
                    telegram_message_id: 1,
                    action_description: "test".to_string(),
                    created_at: chrono::Utc::now() - chrono::Duration::minutes(10),
                    expires_at: chrono::Utc::now() - chrono::Duration::minutes(1),
                    detector: "ssh_bruteforce".to_string(),
                    action_name: "block_ip".to_string(),
                },
                crate::ai::AiDecision::ignore("test pending confirmation"),
                crate::tests::test_incident("198.51.100.10"),
            ),
        );
        state.pending_honeypot_choices.insert(
            "198.51.100.10".to_string(),
            crate::PendingHoneypotChoice {
                ip: "198.51.100.10".to_string(),
                incident_id: "inc-2".to_string(),
                incident: crate::tests::test_incident("198.51.100.10"),
                expires_at: chrono::Utc::now() - chrono::Duration::minutes(1),
            },
        );
        let mut cursor = reader::AgentCursor::default();
        let cfg = config::AgentConfig::default();

        let handled =
            process_incidents(dir.path(), &mut cursor, &cfg, &mut state, &advisory_cache()).await;

        assert_eq!(handled, 0);
        assert!(state.pending_confirmations.is_empty());
        assert!(state.pending_honeypot_choices.is_empty());
    }

    #[tokio::test]
    async fn process_incidents_trips_circuit_breaker_on_burst() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let store = crate::tests::test_sqlite_store(dir.path());
        crate::tests::insert_test_incident(&store, &crate::tests::test_incident("203.0.113.20"));
        state.sqlite_store = Some(store);
        let mut cfg = config::AgentConfig::default();
        cfg.ai.enabled = false;
        cfg.ai.circuit_breaker_threshold = 1;
        cfg.ai.circuit_breaker_cooldown_secs = 30;
        let mut cursor = reader::AgentCursor::default();

        let handled =
            process_incidents(dir.path(), &mut cursor, &cfg, &mut state, &advisory_cache()).await;

        assert!(handled >= 1);
        assert!(state.circuit_breaker_until.is_some());
    }

    #[tokio::test]
    async fn process_incidents_suppresses_graph_only_detector_incident() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let store = crate::tests::test_sqlite_store(dir.path());
        let incident = crate::tests::test_incident_with_kind("203.0.113.21", "graph_only_signal");
        crate::tests::insert_test_incident(&store, &incident);
        state.sqlite_store = Some(store);
        let mut cfg = config::AgentConfig::default();
        cfg.ai.enabled = false;
        cfg.graph_only_detectors = vec!["graph_only_signal".to_string()];
        let mut cursor = reader::AgentCursor::default();

        let handled =
            process_incidents(dir.path(), &mut cursor, &cfg, &mut state, &advisory_cache()).await;

        assert_eq!(handled, 1);
    }
}
