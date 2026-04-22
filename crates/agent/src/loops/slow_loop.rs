use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use tracing::{info, warn};

use crate::{
    attacker_intel, cloud_safelist, config, correlation_engine, correlation_response, dashboard,
    decisions, dna_inline, killchain_inline, knowledge_graph, narrative_anomaly, narrative_autofp,
    narrative_daily_summary, narrative_incident_ingest, narrative_observation_verify, reader,
    shield_inline, telemetry_tick, AgentState,
};

/// Refresh operator IPs from active SSH sessions.
/// Replaces the entire set - IPs whose sessions ended are automatically removed.
pub(crate) fn refresh_operator_ips(state: &mut AgentState, allowlist: &config::AllowlistConfig) {
    let now = std::time::Instant::now();
    let mut active_ips = std::collections::HashMap::new();

    // Check active sessions via `who -i`
    if let Ok(output) = std::process::Command::new("who").arg("-i").output() {
        let who_out = String::from_utf8_lossy(&output.stdout);
        active_ips = operator_ips_from_who_output(&who_out, &allowlist.trusted_users, now);
    }

    // Log removed sessions
    for old_ip in state.operator_ips.keys() {
        if !active_ips.contains_key(old_ip) {
            info!(ip = %old_ip, "operator session ended — IP protection removed");
        }
    }
    // Log new sessions
    for new_ip in active_ips.keys() {
        if !state.operator_ips.contains_key(new_ip) {
            info!(ip = %new_ip, "operator session detected — IP protected");
        }
    }

    state.operator_ips = active_ips;
}

// ---------------------------------------------------------------------------
// Narrative tick - runs every 30s
//
// Responsibility: regenerate the daily Markdown summary when new events arrive.
// Webhook and incident processing have been moved to process_incidents so that
// all incidents are notified in real-time, not batched every 30 seconds.
// ---------------------------------------------------------------------------

/// Returns the number of new events seen this tick.
pub(crate) async fn process_narrative_tick(
    data_dir: &Path,
    _cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> Result<usize> {
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    let (events_entries, events_count) = if let Some(ref sq) = state.sqlite_store {
        let cval = sq.get_agent_cursor("events").unwrap_or(0);
        match sq.events_since(cval, 5000) {
            Ok(rows) if !rows.is_empty() => {
                let max_id = rows.last().unwrap().0;
                let entries: Vec<_> = rows.into_iter().map(|(_, ev)| ev).collect();
                let count = entries.len();
                let _ = sq.set_agent_cursor("events", max_id);
                (entries, count)
            }
            _ => (Vec::new(), 0),
        }
    } else {
        warn!("sqlite_store not available — cannot read events");
        (Vec::new(), 0)
    };

    state.telemetry.observe_events(&events_entries);

    // Track operator IPs: any SSH login via publickey is an operator (has the private key).
    for ev in &events_entries {
        if ev.kind == "ssh.login_success"
            || ev.kind == "auth.login_success"
            || ev.kind == "auth.session_opened"
        {
            let method = ev
                .details
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if method == "publickey" {
                let ip = ev
                    .details
                    .get("ip")
                    .or_else(|| ev.details.get("src_ip"))
                    .and_then(|v| v.as_str());
                if let Some(ip) = ip {
                    let is_new = !state.operator_ips.contains_key(ip);
                    state
                        .operator_ips
                        .insert(ip.to_string(), std::time::Instant::now());
                    if is_new {
                        let user = ev
                            .details
                            .get("user")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?");
                        info!(
                            user,
                            ip, "operator session detected (publickey) — IP protected"
                        );
                    }
                }
            }
        }
    }

    // Feed new events into the narrative accumulator (incremental, no file re-read)
    state.narrative_acc.reset_for_date(&today);
    state.narrative_acc.ingest_events(&events_entries);

    // Feed events into knowledge graph (in-memory attack context)
    let trigger_incidents = {
        let mut graph = state.knowledge_graph.write().unwrap();
        // Set host label for trigger incidents (once)
        if graph.trigger_host.is_empty() {
            let host_label = graph
                .system_node()
                .and_then(|id| graph.get_node(id))
                .map(|n| n.label())
                .unwrap_or_else(|| "unknown".to_string());
            graph.set_trigger_host(&host_label);
        }
        for ev in &events_entries {
            graph.ingest(ev);
        }
        graph.drain_trigger_incidents()
    };

    // Process real-time trigger incidents (CRITICAL detectors, <2s latency)
    if !trigger_incidents.is_empty() {
        tracing::info!(count = trigger_incidents.len(), "real-time triggers fired");
        // Ingest trigger incidents into the graph
        {
            let mut graph = state.knowledge_graph.write().unwrap();
            for inc in &trigger_incidents {
                graph.ingest_incident(inc);
            }
        }
        // Phase 6E: trigger incidents are already in the knowledge graph
        // (ingested above). No separate JSONL write needed.
    }

    // Periodic graph maintenance (cleanup expired + dated snapshot every 60s)
    if state.last_graph_snapshot.elapsed().as_secs() >= 60 {
        {
            let mut graph = state.knowledge_graph.write().unwrap();
            graph.cleanup_expired(chrono::Utc::now());
            graph.compact_edges();
            graph.enforce_memory_limit();
            // Phase 7: save to dated snapshot (graph-snapshot-YYYY-MM-DD.json)
            if let Err(e) = graph.save_dated_snapshot(data_dir) {
                warn!("knowledge graph snapshot failed: {e:#}");
            }
            // Spec 016: also save to SQLite store
            if let Some(ref sq) = state.sqlite_store {
                if let Err(e) = graph.save_to_store(sq) {
                    warn!("knowledge graph SQLite snapshot failed: {e:#}");
                }
            }
            let metrics = graph.metrics();
            if let Ok(json) = serde_json::to_vec(&metrics) {
                let _ = std::fs::write(data_dir.join("graph-stats.json"), json);
            }
            // Phase 7: cleanup old snapshots (keep 7 days)
            knowledge_graph::KnowledgeGraph::cleanup_old_snapshots(data_dir, 7);
            // Spec 016: also cleanup SQLite snapshots
            if let Some(ref sq) = state.sqlite_store {
                knowledge_graph::KnowledgeGraph::cleanup_store_snapshots(sq, 7);
            }
        }
        state.last_graph_snapshot = std::time::Instant::now();
    }

    // Update neural autoencoder with graph structural features
    {
        let graph = state.knowledge_graph.read().unwrap();
        let gf = graph.extract_neural_features();
        state.anomaly_engine.set_graph_features(gf);
    }

    // Run graph-based detectors (parallel to sensor detectors)
    {
        let (graph_incidents, _host_label) = {
            let graph = state.knowledge_graph.read().unwrap();
            let host = graph
                .system_node()
                .and_then(|id| graph.get_node(id))
                .map(|n| n.label())
                .unwrap_or_else(|| "unknown".to_string());
            let calibration_ctx = knowledge_graph::detectors::CalibrationContext {
                is_cloud: state.environment_profile.is_cloud(),
                human_uids: state.environment_profile.human_uids.clone(),
            };
            let incidents = knowledge_graph::detectors::run_all_with_calibration(
                &graph,
                &mut state.graph_detector_state,
                &host,
                chrono::Utc::now(),
                &calibration_ctx,
            );
            (incidents, host)
        };
        {
            let mut graph = state.knowledge_graph.write().unwrap();
            for inc in &graph_incidents {
                graph.ingest_incident(inc);
            }
        }
        if !graph_incidents.is_empty() {
            // Phase 6E: graph detector incidents are already in the knowledge graph
            // (ingested above). No separate JSONL write needed.
            tracing::info!(count = graph_incidents.len(), "graph detectors fired");
        }
    }

    // Feed events into cross-layer correlation engine and baseline learning.
    // Events from trusted processes are excluded — they make legitimate
    // outbound connections that would false-positive on data-exfil chains.
    //
    // Two filters:
    // 1. PID-based: exclude our own process tree (agent, sensor, watchdog children).
    //    Catches tokio-rt-worker threads that eBPF reports with the thread comm.
    // 2. Comm-based: exclude known system services (crowdsec, apt, certbot, etc.)
    let trusted_procs = &cfg.responder.trusted_processes;
    let own_pid = std::process::id();
    for ev in &events_entries {
        let ev_comm = ev
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let ev_pid = ev.details.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        // Filter 1: own process tree (agent + its threads).
        // eBPF reports thread comm ("tokio-rt-worker") not binary name.
        // Check if event PID belongs to us by reading /proc/PID/status PPid.
        let is_own_tree = ev_pid > 0 && is_pid_in_own_tree(ev_pid, own_pid);

        // Filter 2: trusted process comm names from config.
        let is_trusted_comm = !ev_comm.is_empty()
            && trusted_procs
                .iter()
                .any(|tp| ev_comm.starts_with(tp.as_str()));

        if is_own_tree || is_trusted_comm {
            // Still feed to baseline (we want to learn their normal patterns)
            let _ = state.baseline.observe_event(ev);
            continue;
        }
        let corr_event = correlation_engine::CorrelationEngine::classify_event(ev);
        let ev_entities = corr_event.entities.clone();
        state.correlation_engine.observe(corr_event);
        let anomalies = state.baseline.observe_event(ev);
        if !anomalies.is_empty() {
            state.last_baseline_anomaly_ts = Some(chrono::Utc::now());
        }
        for anomaly in &anomalies {
            info!(
                anomaly_type = ?anomaly.anomaly_type,
                description = %anomaly.description,
                "baseline anomaly detected"
            );

            // Inject baseline anomalies into correlation engine.
            let kind = match anomaly.anomaly_type {
                crate::baseline::AnomalyType::EventRateDrop => "baseline.silence",
                crate::baseline::AnomalyType::EventRateSpike => "baseline.rate_spike",
                crate::baseline::AnomalyType::ProcessLineage => "baseline.new_process",
                crate::baseline::AnomalyType::UserLoginTime => "baseline.unusual_login",
                crate::baseline::AnomalyType::NewDestination => "baseline.new_destination",
            };
            let baseline_corr = correlation_engine::CorrelationEngine::baseline_event(
                kind,
                anomaly.severity.clone(),
                ev_entities.clone(),
                serde_json::json!({
                    "description": anomaly.description,
                    "expected": anomaly.expected,
                    "observed": anomaly.observed,
                }),
            );
            state.correlation_engine.observe(baseline_corr);
        }
    }

    // Feed eBPF events through kill chain tracker (inline pattern detection).
    // Filter out trusted processes to prevent false kill chain matches.
    if cfg.killchain.enabled {
        let kc_events: Vec<_> = events_entries
            .iter()
            .filter(|ev| {
                let comm = ev
                    .details
                    .get("comm")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let pid = ev.details.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let own_tree = pid > 0 && is_pid_in_own_tree(pid, own_pid);
                let trusted = !comm.is_empty()
                    && trusted_procs.iter().any(|tp| comm.starts_with(tp.as_str()));
                !own_tree && !trusted
            })
            .cloned()
            .collect();
        let kc_incidents = killchain_inline::process_events(
            &mut state.killchain_tracker,
            &kc_events,
            &mut state.correlation_engine,
        );
        killchain_inline::write_incidents(data_dir, state.sqlite_store.as_deref(), &kc_incidents);
        let gate_counter = state.telemetry.gate_suppressed_counter();
        killchain_inline::notify_telegram(
            &state.telegram_client,
            &kc_incidents,
            &state.notification_burst_tracker,
            &mut state.telegram_deferred,
            gate_counter.as_ref(),
        );

        // Periodic stale PID cleanup (every 60s).
        if state.last_killchain_cleanup.elapsed().as_secs() >= 60 {
            killchain_inline::cleanup_stale(&mut state.killchain_tracker);
            state.last_killchain_cleanup = std::time::Instant::now();
        }
    }

    // Feed events through threat DNA engine (behavioral fingerprinting + anomaly detection).
    if cfg.dna.enabled {
        dna_inline::process_events(
            &mut state.dna_state,
            &events_entries,
            &mut state.correlation_engine,
            &mut state.attacker_profiles,
        );

        // Periodic DNA state persistence (every 5 min).
        if state.last_dna_save.elapsed().as_secs() >= 300 {
            dna_inline::save(&state.dna_state);
            state.last_dna_save = std::time::Instant::now();
        }
    }

    // Feed events through DDoS shield (rate limiting, SYN tracking, escalation).
    if let Some(ref mut shield) = state.shield_state {
        // Build risk score lookup for pre-emptive rate limiting.
        let ip_risks: std::collections::HashMap<String, u8> = state
            .attacker_profiles
            .iter()
            .filter(|(_, p)| p.risk_score > 60)
            .map(|(ip, p)| (ip.clone(), p.risk_score))
            .collect();
        let (_drops, shield_incidents, shield_blocked) =
            shield_inline::process_events(shield, &events_entries, &ip_risks);
        shield_inline::write_incidents(data_dir, &shield_incidents);
        let gate_counter = state.telemetry.gate_suppressed_counter();
        shield_inline::notify_telegram(
            &state.telegram_client,
            &shield_incidents,
            &state.notification_burst_tracker,
            &mut state.telegram_deferred,
            gate_counter.as_ref(),
        );
        // Sync: register shield blocks in agent blocklist and attacker intel.
        for ip in &shield_blocked {
            state.blocklist.insert(ip.clone());
            // Enrich attacker profiles with shield block data.
            let profile = state
                .attacker_profiles
                .entry(ip.clone())
                .or_insert_with(|| attacker_intel::new_profile(ip, chrono::Utc::now()));
            attacker_intel::observe_shield_block(profile, "shield:rate_limit");
        }
        // Inject shield escalation incidents into correlation engine.
        for inc in &shield_incidents {
            if let Some(title) = inc.get("title").and_then(|t| t.as_str()) {
                let kind = if title.contains("Critical") {
                    "shield.escalation.critical"
                } else if title.contains("UnderAttack") {
                    "shield.escalation.under_attack"
                } else if title.contains("Elevated") {
                    "shield.escalation.elevated"
                } else {
                    "shield.escalation.transition"
                };
                let corr = correlation_engine::CorrelationEngine::shield_event(kind, inc.clone());
                state.correlation_engine.observe(corr);
            }
        }
    }

    // Layer 2: Correlation-driven escalation (spec 018 Phase B).
    // Drains completed attack chains and checks repeat offenders / multi-technique.
    correlation_response::process_correlation_escalations(data_dir, cfg, state).await;

    narrative_anomaly::process_anomalies(data_dir, &today, &events_entries, state);

    narrative_incident_ingest::ingest_new_incidents(data_dir, &today, state)?;

    // Spec 021 — Observation verification (Fase 3).
    // Score undecided incidents and auto-dismiss/escalate clear-cut cases.
    // Ambiguous items go to AI batch verification.
    //
    // Spec 028-b: verify_observing_incidents is async because the Escalate
    // branch can now promote the incident all the way through decide() and
    // the skill executor when the operator has enabled the feature flag.
    let ambiguous_items =
        narrative_observation_verify::verify_observing_incidents(cfg, state, data_dir).await;
    narrative_observation_verify::ai_verify_ambiguous(ambiguous_items, cfg, state).await;

    narrative_daily_summary::maybe_write_daily_summary_and_digest(
        data_dir,
        &today,
        events_count,
        cfg,
        state,
    )
    .await;

    narrative_autofp::maybe_suggest_allowlist_from_fp_reports(data_dir, state).await;

    // Update deep security snapshot for dashboard.
    if let Some(ref ds) = state.deep_security_snapshot {
        let (kc_tracked, kc_pre, kc_full) = killchain_inline::stats(&state.killchain_tracker);
        let snap = dashboard::DeepSecuritySnapshot {
            firmware_trust_score: None, // updated by firmware_tick
            firmware_last_audit: None,
            hypervisor_environment: state
                .hypervisor_environment
                .as_ref()
                .map(|e| format!("{e:?}")),
            hypervisor_trust_score: None, // updated by hypervisor_tick
            killchain_pids_tracked: kc_tracked,
            killchain_pre_chains: kc_pre,
            killchain_full_matches: kc_full,
            dna_fingerprints: state.dna_state.store.len(),
            dna_anomaly_alerts: state.dna_state.anomaly_detector.anomaly_count(),
            dna_attack_chains: state.dna_state.chain_tracker.len(),
        };
        if let Ok(mut guard) = ds.write() {
            *guard = snap;
        }
    }

    telemetry_tick::write_tick_snapshot(state, "narrative_tick");

    Ok(events_count)
}

// ---------------------------------------------------------------------------
// LSM auto-enable helpers
// ---------------------------------------------------------------------------

// LSM enforcement and trust rules moved to trust_rules.rs

// ---------------------------------------------------------------------------
// Boot self-test — verify self-awareness is working on startup
// ---------------------------------------------------------------------------

/// One-time reconciliation: read all decisions-*.jsonl files and write
/// missing decisions to the knowledge graph. This fixes historical data
/// where auto-block gates (obvious, CrowdSec) wrote decisions to JSONL
/// but not to the graph.
pub(crate) fn backfill_graph_decisions(data_dir: &std::path::Path, state: &mut AgentState) {
    use std::io::BufRead;

    let mut filled = 0usize;
    let mut scanned = 0usize;

    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return;
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("decisions-") || !name.ends_with(".jsonl") {
            continue;
        }
        let Ok(file) = std::fs::File::open(entry.path()) else {
            continue;
        };
        for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(d) = serde_json::from_str::<decisions::DecisionEntry>(&line) else {
                continue;
            };
            scanned += 1;

            // Backfill all decisions that have an action type
            if d.action_type.is_empty() || d.dry_run {
                continue;
            }

            // Check if the graph incident node is missing a decision
            let mut graph = state.knowledge_graph.write().unwrap();
            let needs_backfill = graph
                .find_by_incident(&d.incident_id)
                .and_then(|nid| {
                    if let Some(crate::knowledge_graph::types::Node::Incident {
                        decision, ..
                    }) = graph.get_node(nid)
                    {
                        Some(decision.is_none())
                    } else {
                        None
                    }
                })
                .unwrap_or(false);

            if needs_backfill {
                graph.ingest_decision(
                    &d.incident_id,
                    &d.action_type,
                    d.target_ip.as_deref(),
                    d.confidence,
                    &d.reason,
                    true,
                    d.ts,
                );
                filled += 1;
            }
        }
    }

    if filled > 0 {
        info!(
            filled,
            scanned, "backfill: reconciled JSONL decisions with knowledge graph"
        );
    }

    // Phase 2: dismiss visible incidents that never received any decision.
    // These are historical incidents from before the noise-gate was deployed.
    // Without this, they show as "OBSERVING" forever in the dashboard.
    //
    // Age gate: only dismiss incidents older than RETROACTIVE_DISMISS_AGE_SECS
    // (15 min). Before this gate the scan raced process_incidents + AI triage,
    // which takes up to ~30s cold-start on local Ollama — every Caldera SIGMA
    // or crypto_miner hit got dismissed here before the AI ever saw it,
    // zeroing out the responder (47 of 61 decisions on test001 on 2026-04-18).
    const RETROACTIVE_DISMISS_AGE_SECS: i64 = 15 * 60;
    {
        use crate::knowledge_graph::types::{Node, NodeType};
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(RETROACTIVE_DISMISS_AGE_SECS);
        let mut graph = state.knowledge_graph.write().unwrap();
        let orphan_ids: Vec<_> = graph
            .nodes_of_type(NodeType::Incident)
            .iter()
            .filter_map(|&id| {
                if let Some(Node::Incident {
                    incident_id,
                    decision,
                    research_only,
                    ts,
                    ..
                }) = graph.get_node(id)
                {
                    if decision.is_none() && !research_only && *ts < cutoff {
                        return Some((id, incident_id.clone()));
                    }
                }
                None
            })
            .collect();

        let dismissed = orphan_ids.len();
        for (_nid, iid) in &orphan_ids {
            graph.ingest_decision(
                iid,
                "dismiss",
                None,
                1.0,
                "Retroactive dismiss: historical incident with no decision",
                true,
                chrono::Utc::now(),
            );
        }

        if dismissed > 0 {
            info!(
                dismissed,
                "backfill: dismissed orphan incidents with no decision"
            );
        }
    }
}

/// Quick validation at agent startup that the host inventory (own IPs,
/// listening ports) was loaded correctly by the sensor, and cloud safelist
/// is initialized. Logs warnings for anything that looks wrong.
pub(crate) fn boot_self_test() {
    use tracing::{info, warn};

    // Check cloud safelist initialized (own IPs loaded)
    let local_ips = cloud_safelist::local_ip_count();
    if local_ips > 0 {
        info!(local_ips, "boot self-test: local interface IPs loaded");
    } else {
        warn!(
            "boot self-test: no local interface IPs detected — self-traffic filtering may not work"
        );
    }

    // Check that cloud safelist ranges are loaded
    let cloud_ranges = cloud_safelist::cloud_range_count();
    if cloud_ranges > 0 {
        info!(
            cloud_ranges,
            "boot self-test: cloud provider IP ranges loaded"
        );
    } else {
        warn!("boot self-test: no cloud IP ranges loaded");
    }

    info!("boot self-test: passed");
}

// ---------------------------------------------------------------------------
/// Check if a PID belongs to our own process tree by walking PPid up to 3 levels.
/// Used to filter eBPF events from agent/sensor threads out of correlation detection.
/// Reads /proc/PID/status which is cheap (procfs, no disk I/O).
pub(crate) fn is_pid_in_own_tree(pid: u32, own_pid: u32) -> bool {
    if pid == own_pid {
        return true;
    }
    // Check /proc/PID/status for Tgid (thread group leader) and PPid.
    // Tokio threads report PPid=1 (init) but Tgid=agent_pid.
    let status_path = format!("/proc/{pid}/status");
    let Ok(content) = std::fs::read_to_string(&status_path) else {
        return false;
    };
    // Tgid = thread group ID. For threads, this is the main process PID.
    if status_tgid(&content) == Some(own_pid) {
        return true;
    }
    // Walk PPid chain (max 3 hops) for child processes (not threads).
    let mut current = pid;
    for _ in 0..3 {
        let path = format!("/proc/{current}/status");
        let Ok(c) = std::fs::read_to_string(&path) else {
            return false;
        };
        let ppid = status_ppid(&c);
        match ppid {
            Some(p) if p == own_pid => return true,
            Some(0) | Some(1) | None => return false,
            Some(p) => current = p,
        }
    }
    false
}

pub(crate) fn status_field_u32(content: &str, field: &str) -> Option<u32> {
    content
        .lines()
        .find(|line| line.starts_with(field))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u32>().ok())
}

pub(crate) fn status_tgid(content: &str) -> Option<u32> {
    status_field_u32(content, "Tgid:")
}

pub(crate) fn status_ppid(content: &str) -> Option<u32> {
    status_field_u32(content, "PPid:")
}

pub(crate) fn operator_ips_from_who_output(
    who_output: &str,
    trusted_users: &[String],
    now: std::time::Instant,
) -> HashMap<String, std::time::Instant> {
    let mut active_ips = HashMap::new();
    for line in who_output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let (Some(user), Some(ip_raw)) = (parts.first(), parts.last()) {
            let ip = ip_raw.trim_matches(|c| c == '(' || c == ')');
            if trusted_users.iter().any(|trusted| trusted == *user) && !ip.is_empty() && ip != ":" {
                active_ips.insert(ip.to_string(), now);
            }
        }
    }
    active_ips
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge_graph::types::Node;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn operator_ips_from_who_output_filters_and_strips_parentheses() {
        let now = std::time::Instant::now();
        let trusted = vec!["ubuntu".to_string(), "ops".to_string()];
        let who = "\
ubuntu pts/0 2026-04-17 10:00 (198.51.100.42)
guest pts/1 2026-04-17 10:01 (198.51.100.43)
ops pts/2 2026-04-17 10:02 (:)
ops pts/3 2026-04-17 10:03 (203.0.113.8)
";

        let ips = operator_ips_from_who_output(who, &trusted, now);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains_key("198.51.100.42"));
        assert!(ips.contains_key("203.0.113.8"));
        assert!(!ips.contains_key("198.51.100.43"));
    }

    #[test]
    fn proc_status_helpers_parse_expected_fields() {
        let status = "Name:\tagent\nTgid:\t4242\nPPid:\t7\n";
        assert_eq!(status_tgid(status), Some(4242));
        assert_eq!(status_ppid(status), Some(7));
        assert_eq!(status_field_u32(status, "Pid:"), None);
    }

    #[test]
    fn backfill_graph_decisions_ingests_missing_decision_and_dismisses_orphans() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let incident_with_jsonl = crate::tests::test_incident("198.51.100.50");
        // Orphan is "old" (older than RETROACTIVE_DISMISS_AGE_SECS = 15 min).
        // The retroactive-dismiss pass must only touch stale incidents so it
        // does not race with live AI triage on recently-created ones. Without
        // this, Caldera SIGMA/crypto_miner hits were dismissed before the AI
        // ever saw them (see bug #5 in docs/internal/bug-hunt-2026-04-18.md).
        let mut orphan_incident = crate::tests::test_incident_with_kind("198.51.100.51", "orphan");
        orphan_incident.ts = chrono::Utc::now() - chrono::Duration::minutes(30);
        {
            let mut graph = state.knowledge_graph.write().expect("graph write");
            graph.ingest_incident(&incident_with_jsonl);
            graph.ingest_incident(&orphan_incident);
        }

        let entry = crate::decisions::DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: incident_with_jsonl.incident_id.clone(),
            host: incident_with_jsonl.host.clone(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("198.51.100.50".to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.97,
            auto_executed: true,
            dry_run: false,
            reason: "unit test".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
        };
        let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let line = serde_json::to_string(&entry).expect("serialize decision");
        std::fs::write(&decisions_path, format!("{line}\n")).expect("write decisions file");

        backfill_graph_decisions(dir.path(), &mut state);

        let graph = state.knowledge_graph.read().expect("graph read");
        let id1 = graph
            .find_by_incident(&incident_with_jsonl.incident_id)
            .expect("incident present");
        let id2 = graph
            .find_by_incident(&orphan_incident.incident_id)
            .expect("orphan present");
        match graph.get_node(id1) {
            Some(Node::Incident {
                decision: Some(decision),
                ..
            }) => assert_eq!(decision, "block_ip"),
            other => panic!("expected incident decision to be backfilled, got {other:?}"),
        }
        match graph.get_node(id2) {
            Some(Node::Incident {
                decision: Some(decision),
                ..
            }) => assert_eq!(decision, "dismiss"),
            other => panic!("expected orphan incident to be dismissed, got {other:?}"),
        }
    }

    #[test]
    fn backfill_graph_decisions_preserves_recent_orphans_for_ai_triage() {
        // Regression guard for bug #5 (Caldera exercise 2026-04-18): a fresh
        // incident (ts < RETROACTIVE_DISMISS_AGE_SECS) must NOT be dismissed
        // by the backfill, so that the AI triage loop has a chance to classify
        // it before it disappears from the queue.
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let fresh = crate::tests::test_incident_with_kind("198.51.100.77", "fresh");
        {
            let mut graph = state.knowledge_graph.write().expect("graph write");
            graph.ingest_incident(&fresh);
        }

        backfill_graph_decisions(dir.path(), &mut state);

        let graph = state.knowledge_graph.read().expect("graph read");
        let id = graph
            .find_by_incident(&fresh.incident_id)
            .expect("fresh present");
        match graph.get_node(id) {
            Some(Node::Incident { decision, .. }) => assert!(
                decision.is_none(),
                "fresh orphan must stay open for AI triage, got {decision:?}"
            ),
            other => panic!("expected Incident node, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn process_narrative_tick_reads_sqlite_events_and_updates_operator_ips() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let store = crate::tests::test_sqlite_store(dir.path());
        let event = crate::tests::test_event(
            "ssh.login_success",
            innerwarden_core::event::Severity::Info,
            serde_json::json!({
                "method": "publickey",
                "ip": "198.51.100.99",
                "user": "ubuntu",
                "pid": std::process::id(),
                "comm": "innerwarden-agent",
            }),
        );
        crate::tests::insert_test_event(&store, &event);
        state.sqlite_store = Some(store);
        state.last_graph_snapshot = std::time::Instant::now() - Duration::from_secs(90);
        state.last_dna_save = std::time::Instant::now() - Duration::from_secs(360);
        state.last_killchain_cleanup = std::time::Instant::now() - Duration::from_secs(90);
        state.deep_security_snapshot = Some(std::sync::Arc::new(std::sync::RwLock::new(
            crate::dashboard::DeepSecuritySnapshot::default(),
        )));
        let cfg = config::AgentConfig::default();
        let mut cursor = reader::AgentCursor::default();

        let count = process_narrative_tick(dir.path(), &mut cursor, &cfg, &mut state)
            .await
            .expect("narrative tick");

        assert_eq!(count, 1);
        assert!(state.operator_ips.contains_key("198.51.100.99"));
    }

    #[tokio::test]
    async fn process_narrative_tick_returns_zero_without_sqlite_store() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = config::AgentConfig::default();
        let mut cursor = reader::AgentCursor::default();

        let count = process_narrative_tick(dir.path(), &mut cursor, &cfg, &mut state)
            .await
            .expect("narrative tick");

        assert_eq!(count, 0);
    }
}
