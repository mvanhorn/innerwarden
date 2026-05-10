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
    incident_obvious, incident_post_decision, incident_prelude, incident_reputation,
    process::telegram_approval::process_telegram_approval, reader, skills, telegram,
    telemetry_tick, AgentState,
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
                // Spec 037 I-13 PR-4: surface persistent SQLite
                // degradation. A cursor-write failure is safe (next
                // tick re-reads the same incidents); downstream AI
                // triage + skill executor dedupe via cooldowns and
                // the decision audit hash chain, but re-processing
                // is operator-visible noise. Same pattern as
                // narrative_incident_ingest.rs and slow_loop.rs.
                if let Err(e) = sq.set_agent_cursor("incidents", max_id) {
                    warn!(
                        cursor = "incidents",
                        max_id,
                        error = %e,
                        "agent cursor advance failed; incidents will be re-read next tick"
                    );
                }
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
    // operator has configured a dedicated Local Warden Model via
    // `[ai.warden]`, triage routes through it without touching the
    // rest of the decision pipeline. Legacy configs (no `[ai.warden]`
    // / `[ai.llm]`) populate both slots with the primary provider,
    // so behaviour is identical.
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

        // 2026-04-30: defense-in-depth for the sensor's NSS_INIT_CLI_TOOLS
        // suppression. If a sensor detector emits the
        // "comm = libc-using CLI tool + sensitive_file = /etc/passwd"
        // shape (the standard NSS uid->name lookup at process startup
        // followed by the outbound connect every CLI tool makes),
        // dismiss inline so the operator never sees the FP in
        // "needs attention" — even if the sensor binary is older than
        // the agent and missing the new suppression list.
        // See `incident_autodismiss::try_autodismiss_sensor_self_traffic_fp`
        // for the full safety analysis.
        if incident_autodismiss::try_autodismiss_sensor_self_traffic_fp(incident, state) {
            handled += 1;
            continue;
        }

        // Spec 043 Phase 3 (CDN-noise companion fix, 2026-05-06):
        // suppress proto_anomaly incidents whose primary IP is a known
        // CDN / cloud-provider edge (Wave-9-followup at the network
        // layer; the HTTP-layer fix in PR #469 only catches HTTP
        // events, not raw TCP). Operator-visible delta: 24-of-25
        // "needs attention" entries from CF edges go to "Dismissed"
        // and stop polluting the dashboard.
        if incident_autodismiss::try_dismiss_cdn_noise(incident, state) {
            handled += 1;
            continue;
        }

        // Spec 046 Phase A.5 follow-up: a malformed SSH banner on the
        // honeypot port is BY DEFINITION the honeypot doing its job
        // (scanner hits the listener, fails at protocol level, never
        // reaches auth). Operator surfaced this 2026-05-10 looking at
        // 175.110.112.8 in threats — Low-severity proto_anomaly with
        // no AI decision was wasting an "needs attention" slot. The
        // helper has the same KG-hardening as cdn-noise: keep visible
        // if the IP has other (non-proto_anomaly) incidents in 24h.
        if incident_autodismiss::try_dismiss_honeypot_probe_proto_anomaly(
            incident,
            cfg.honeypot.port,
            state,
        ) {
            handled += 1;
            continue;
        }

        // Spec 043 Phase 7 — KG-based FP suppression (shadow-first).
        // Generic suppression that runs AFTER the targeted
        // self-traffic-FP and CDN-noise paths so those keep their
        // narrow, easily-audited reasons in the JSONL. Phase 7 is
        // the catch-all: any incident whose primary entity has a
        // strongly benign KG history gets suppressed (or in shadow,
        // logged for operator review). Critical floor is hardcoded
        // in `kg_fp_suppression::classify`.
        if try_kg_fp_suppression(incident, cfg, state, data_dir) {
            handled += 1;
            continue;
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
                // Phase 7 (audit RC-2): also persist the allowlisted
                // flag on the SQLite incident row so the dashboard's
                // /api/overview snapshot can group allowlisted
                // attackers separately from "needs attention" without
                // re-running the dynamic allowlist match per request.
                // Best-effort: a SQLite write failure here only loses
                // the dashboard's allowlist visibility for this row,
                // not the actual allowlist enforcement (which already
                // happened via the SkipAllowlisted decision above).
                if let Some(store) = state.sqlite_store.as_ref() {
                    if let Err(e) = store.set_incident_allowlisted(&incident.incident_id) {
                        tracing::warn!(
                            incident_id = %incident.incident_id,
                            error = %e,
                            "failed to persist is_allowlisted flag on incident row"
                        );
                    }
                }
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
                ai::AiAction::Dismiss { .. } => ("dismiss", None),
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

        // 2026-05-03 (PR #413): playbook engine removed from the free
        // version. The 3 step types that worked (notify /
        // capture_forensics / escalate) already have independent
        // triggers — incident_notifications.rs sends Telegram on
        // severity threshold; incident_forensics::maybe_capture_incident_forensics
        // fires pcap on high/critical; warn-loud is a tracing macro.
        // No operational regression. Future home for declarative
        // playbook-style orchestration: Spec 042 active defense (Lua).

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

/// Spec 043 Phase 7 wiring — generic KG-based FP suppression. Runs
/// AFTER the targeted self-traffic-FP and CDN-noise paths so those
/// keep their narrow audit-trail reasons. This is the catch-all:
/// any incident whose primary entity has a strongly benign KG
/// history gets suppressed.
///
/// Returns `true` when the incident was handled (suppressed in
/// `enforce` mode). Returns `false` for shadow / off / pass-through.
/// Critical floor is enforced inside `kg_fp_suppression::classify`
/// — Critical incidents NEVER reach the suppress branch.
fn try_kg_fp_suppression(
    incident: &innerwarden_core::incident::Incident,
    cfg: &crate::config::AgentConfig,
    state: &mut crate::AgentState,
    data_dir: &Path,
) -> bool {
    use crate::kg_fp_suppression::{
        classify, fp_likelihood, make_shadow_record, parse_mode, write_shadow_log, FpAction,
        FpSuppressionMode,
    };

    let mode = parse_mode(&cfg.kg.fp_suppression_mode);
    if matches!(mode, FpSuppressionMode::Off) {
        return false;
    }

    // Compute likelihood + classify under read lock.
    let (likelihood, action, features) = {
        let kg = match state.knowledge_graph.read() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(
                    "kg_fp_suppression: knowledge_graph lock poisoned: {e}; \
                     skipping suppression check"
                );
                return false;
            }
        };
        let now = chrono::Utc::now();
        let likelihood = fp_likelihood(&kg, incident, now);
        let action = classify(likelihood, &incident.severity, cfg.kg.fp_suppress_threshold);
        // Reach back into kg_decide_features for the same feature set
        // we'd log; OK to skip if extract_features returns None.
        let features = crate::kg_decide_features::extract_features(&kg, incident, now).unwrap_or(
            crate::kg_decide_features::KgDecideFeatures {
                prior_incidents_24h: 0,
                benign_history_score: 0.5,
                related_campaigns: 0,
                cluster_size: 0,
                risk_score: 0,
                first_seen_age_days: 0,
            },
        );
        (likelihood, action, features)
    };

    // Shadow mode: log + return false (passthrough). Operator inspects
    // log to validate before promoting.
    if matches!(mode, FpSuppressionMode::Shadow) {
        let record = make_shadow_record(incident, likelihood, action, features, chrono::Utc::now());
        write_shadow_log(data_dir, &record);
        if matches!(action, FpAction::Suppress) {
            tracing::info!(
                incident_id = %incident.incident_id,
                likelihood,
                "kg_fp_suppression: shadow — would have suppressed"
            );
        }
        return false;
    }

    // Enforce mode + Suppress: write dismiss decision, return handled.
    if !matches!(action, FpAction::Suppress) {
        return false;
    }

    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.clone());
    let reason = format!(
        "Auto-dismissed by Spec 043 Phase 7 (KG FP suppression): \
         likelihood={:.2} (threshold {:.2}). Entity has strongly benign \
         KG history (benign_history={:.2}, prior_24h={}, age={}d, \
         risk={}). See kg_shadow_fp_suppression_*.jsonl for the \
         per-evaluation audit trail.",
        likelihood,
        cfg.kg.fp_suppress_threshold,
        features.benign_history_score,
        features.prior_incidents_24h,
        features.first_seen_age_days,
        features.risk_score
    );
    let entry = crate::decisions::DecisionEntry {
        ts: chrono::Utc::now(),
        incident_id: incident.incident_id.clone(),
        host: incident.host.clone(),
        ai_provider: "kg-fp-suppression".to_string(),
        action_type: "dismiss".to_string(),
        target_ip: primary_ip,
        target_user: None,
        skill_id: None,
        confidence: likelihood,
        auto_executed: true,
        dry_run: false,
        reason: reason.clone(),
        estimated_threat: "none".to_string(),
        execution_result: "dismissed".to_string(),
        prev_hash: None,
    };
    if let Some(writer) = &mut state.decision_writer {
        if let Err(e) = writer.write(&entry) {
            tracing::warn!("kg_fp_suppression: failed to write dismiss: {e:#}");
            return false;
        }
    }
    {
        let mut graph = state.knowledge_graph.write().unwrap();
        graph.ingest_decision(
            &incident.incident_id,
            "dismiss",
            None,
            likelihood,
            &reason,
            true,
            chrono::Utc::now(),
        );
    }
    tracing::info!(
        incident_id = %incident.incident_id,
        likelihood,
        "kg_fp_suppression: enforce — incident suppressed"
    );
    true
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

    // ── Spec 043 Phase 7 wiring anchors (try_kg_fp_suppression) ────────
    //
    // The pure helpers (fp_likelihood, classify, parse_mode,
    // write_shadow_log) have unit tests in `kg_fp_suppression.rs`.
    // These integration tests cover the wiring in `try_kg_fp_suppression`:
    // mode dispatch, KG read-lock recovery, decision write in enforce
    // mode, log write in shadow mode, no-op when Off / PassThrough.

    fn make_fp_test_incident(
        ip: &str,
        sev: innerwarden_core::event::Severity,
    ) -> innerwarden_core::incident::Incident {
        use innerwarden_core::entities::EntityRef;
        innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: format!(
                "test_phase7:{ip}:{}",
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ),
            severity: sev,
            title: "phase 7 wiring test".to_string(),
            summary: String::new(),
            evidence: serde_json::Value::Null,
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    /// Seed an IP with N dismissed-Medium incidents so its
    /// `benign_history_score` is 1.0 (combined with the Phase 1 tweak
    /// that counts dismiss as benign). Crosses the 0.80 suppress
    /// threshold cleanly: history * 0.70 = 0.70 ... well actually 0.70
    /// alone is BELOW 0.80. We need at least one false_positive=true
    /// edge to push past via the bonus. Adds 5 FP edges to ensure
    /// likelihood >= 0.95.
    fn seed_strongly_benign_history(
        kg: &std::sync::Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
        ip: &str,
    ) {
        use crate::knowledge_graph::types::{Edge, Node, Relation};
        use chrono::{Duration, Utc};
        let mut g = kg.write().unwrap();
        let now = Utc::now();
        let ip_id = g.add_node(Node::Ip {
            addr: ip.to_string(),
            is_internal: false,
            datasets: vec![],
            risk_score: 5,
            is_tor: false,
            first_seen: now - Duration::days(30),
            last_seen: now,
            attempted_usernames: vec![],
        });
        // 10 dismissed-Medium → benign_history_score = 1.0
        // 5 false_positive=true → bonus capped at 0.30
        // → likelihood = 1.0 * 0.70 + 0.30 = 1.0 (clamp)
        for i in 0..10 {
            let inc = g.add_node(Node::Incident {
                incident_id: format!("benign:{i}"),
                detector: "test".to_string(),
                severity: "medium".to_string(),
                title: "benign".to_string(),
                summary: String::new(),
                ts: now - Duration::hours(6),
                mitre_ids: vec![],
                decision: Some("dismiss".to_string()),
                confidence: None,
                decision_reason: None,
                decision_target: None,
                auto_executed: false,
                is_allowlisted: false,
                false_positive: false,
                fp_reporter: None,
                fp_reported_at: None,
                research_only: false,
            });
            g.add_edge(Edge::new(
                inc,
                ip_id,
                Relation::TriggeredBy,
                now - Duration::hours(6),
            ));
        }
        for i in 0..5 {
            let inc = g.add_node(Node::Incident {
                incident_id: format!("fp:{i}"),
                detector: "test".to_string(),
                severity: "high".to_string(),
                title: "fp".to_string(),
                summary: String::new(),
                ts: now - Duration::hours(6),
                mitre_ids: vec![],
                decision: None,
                confidence: None,
                decision_reason: None,
                decision_target: None,
                auto_executed: false,
                is_allowlisted: false,
                false_positive: true,
                fp_reporter: Some("operator".to_string()),
                fp_reported_at: Some(now - Duration::hours(5)),
                research_only: false,
            });
            g.add_edge(Edge::new(
                inc,
                ip_id,
                Relation::TriggeredBy,
                now - Duration::hours(6),
            ));
        }
    }

    /// Phase 7 wiring anchor: with `mode = "off"`, the helper returns
    /// false immediately, no log written, no decision written.
    #[test]
    fn try_kg_fp_suppression_off_mode_is_noop() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = crate::config::AgentConfig::default();
        cfg.kg.fp_suppression_mode = "off".to_string();
        let inc = make_fp_test_incident("203.0.113.50", innerwarden_core::event::Severity::High);
        let handled = try_kg_fp_suppression(&inc, &cfg, &mut state, dir.path());
        assert!(!handled, "off mode must return false");
        // No shadow log file should have been created.
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let log = dir
            .path()
            .join(format!("kg_shadow_fp_suppression_{}.jsonl", date));
        assert!(!log.exists(), "off mode must not write shadow log");
    }

    /// Phase 7 wiring anchor: shadow mode writes the JSONL log AND
    /// returns false (no suppression). Pre-fix this would have been
    /// the only operator-visible difference — the dismiss decision
    /// must NOT be written in shadow.
    #[test]
    fn try_kg_fp_suppression_shadow_mode_logs_but_does_not_handle() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = crate::config::AgentConfig::default();
        cfg.kg.fp_suppression_mode = "shadow".to_string();
        let ip = "203.0.113.51";
        seed_strongly_benign_history(&state.knowledge_graph, ip);
        let inc = make_fp_test_incident(ip, innerwarden_core::event::Severity::High);
        let handled = try_kg_fp_suppression(&inc, &cfg, &mut state, dir.path());
        assert!(
            !handled,
            "shadow mode must NEVER return true (no suppression)"
        );
        // Shadow log file MUST exist.
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let log = dir
            .path()
            .join(format!("kg_shadow_fp_suppression_{}.jsonl", date));
        assert!(log.exists(), "shadow mode must write log file");
        let body = std::fs::read_to_string(&log).expect("read");
        assert!(body.contains(&inc.incident_id));
        assert!(body.contains("\"action\":\"suppress\""));
        assert!(body.contains("\"would_change_action\":true"));
    }

    /// Phase 7 wiring anchor: enforce mode + likelihood >= threshold +
    /// non-Critical → writes dismiss decision AND returns true (handled).
    #[test]
    fn try_kg_fp_suppression_enforce_mode_writes_dismiss_for_high_likelihood() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = crate::config::AgentConfig::default();
        cfg.kg.fp_suppression_mode = "enforce".to_string();
        let ip = "203.0.113.52";
        seed_strongly_benign_history(&state.knowledge_graph, ip);
        let inc = make_fp_test_incident(ip, innerwarden_core::event::Severity::Medium);
        let handled = try_kg_fp_suppression(&inc, &cfg, &mut state, dir.path());
        assert!(
            handled,
            "enforce mode must return true (handled) when likelihood >= threshold"
        );
        // Decision JSONL must contain the dismiss with ai_provider="kg-fp-suppression"
        let decisions_path = dir.path().join(format!(
            "decisions-{}.jsonl",
            chrono::Local::now().date_naive().format("%Y-%m-%d")
        ));
        assert!(decisions_path.exists(), "decision file must be created");
        let body = std::fs::read_to_string(&decisions_path).expect("read");
        assert!(
            body.contains("\"ai_provider\":\"kg-fp-suppression\""),
            "decision must be tagged with kg-fp-suppression provider; got: {body}"
        );
        assert!(body.contains(&inc.incident_id));
    }

    /// Phase 7 wiring anchor: the Critical floor holds at the wiring
    /// layer too. Even with strongly benign history (likelihood == 1.0)
    /// and enforce mode, a Critical incident MUST return false (not
    /// handled, not suppressed). Mirror of the pure helper anchor.
    #[test]
    fn try_kg_fp_suppression_critical_severity_never_suppressed_via_wiring() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = crate::config::AgentConfig::default();
        cfg.kg.fp_suppression_mode = "enforce".to_string();
        let ip = "203.0.113.53";
        seed_strongly_benign_history(&state.knowledge_graph, ip);
        let inc = make_fp_test_incident(ip, innerwarden_core::event::Severity::Critical);
        let handled = try_kg_fp_suppression(&inc, &cfg, &mut state, dir.path());
        assert!(
            !handled,
            "Critical severity MUST NEVER be suppressed even at likelihood=1.0 in enforce mode"
        );
    }

    /// Phase 7 wiring anchor: enforce mode + low likelihood (no benign
    /// history seeded) returns false. Pure helper covers this too but
    /// the wiring path has its own early-return logic that needs an
    /// anchor.
    #[test]
    fn try_kg_fp_suppression_enforce_mode_passthrough_for_low_likelihood() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut cfg = crate::config::AgentConfig::default();
        cfg.kg.fp_suppression_mode = "enforce".to_string();
        // No KG seeding → IP is not in graph → likelihood = 0.0
        let inc = make_fp_test_incident("203.0.113.54", innerwarden_core::event::Severity::High);
        let handled = try_kg_fp_suppression(&inc, &cfg, &mut state, dir.path());
        assert!(
            !handled,
            "enforce mode must NOT suppress when likelihood is below threshold"
        );
    }
}
