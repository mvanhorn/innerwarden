//! Narrative tick integration for observation verification (spec 021 Phase B).
//!
//! Scans the knowledge graph for undecided (OBSERVING) incidents and runs the
//! behavioural scorer from `observation_verify`.  High scores auto-dismiss,
//! low scores escalate, and ambiguous items are collected for AI verification
//! (Phase C).

use crate::knowledge_graph::types::{Node, NodeType};
use crate::knowledge_graph::KnowledgeGraph;
use crate::observation_verify::{self, ScoreBreakdown, VerificationResult};
use crate::AgentState;

use tracing::{debug, info};

/// Item queued for AI verification (score 40-69). Phase C consumes these.
#[derive(Debug)]
#[allow(dead_code)] // Phase C reads these fields
pub(crate) struct AmbiguousItem {
    pub incident_id: String,
    pub score: u8,
    pub evidence: serde_json::Value,
    pub detector: String,
    pub title: String,
}

/// Run observation verification on all OBSERVING incidents in the knowledge graph.
///
/// Returns the list of ambiguous items that need AI verification (Phase C).
pub(crate) fn verify_observing_incidents(
    cfg: &crate::config::AgentConfig,
    state: &mut AgentState,
) -> Vec<AmbiguousItem> {
    if !cfg.observation.enabled {
        return Vec::new();
    }

    let dismiss_threshold = cfg.observation.auto_dismiss_threshold;
    let escalate_threshold = cfg.observation.auto_escalate_threshold;

    // Determine temporal context from agent state
    let operator_active = !state.operator_ips.is_empty();

    // Check recent package activity — look at event kinds seen this narrative date.
    let recent_package_activity = state.narrative_acc.events_by_kind.keys().any(|k| {
        k.starts_with("package.")
            || k.starts_with("apt.")
            || k.starts_with("dpkg.")
            || k.starts_with("dnf.")
            || k.starts_with("snap.")
    });

    // Check if systemctl restart ran recently
    let recent_service_restart = state
        .narrative_acc
        .events_by_kind
        .keys()
        .any(|k| k.contains("systemd.") || k.contains("service.restart"));

    // Check maintenance window
    let now = chrono::Local::now();
    let in_maintenance = observation_verify::in_maintenance_window(
        &cfg.observation.maintenance_windows,
        now.hour(),
        now.minute(),
    );

    // Collect undecided incident data from the graph (read lock)
    let undecided: Vec<(String, String, String, serde_json::Value, Option<String>)> = {
        let graph = state.knowledge_graph.read().unwrap();
        collect_undecided_incidents(&graph)
    };

    if undecided.is_empty() {
        return Vec::new();
    }

    let mut dismissed = 0u32;
    let mut escalated = 0u32;
    let mut ambiguous_items = Vec::new();

    for (incident_id, detector, title, evidence, primary_ip) in undecided {
        let (result, breakdown) = observation_verify::behaviour_score(
            &evidence,
            operator_active,
            recent_package_activity,
            recent_service_restart,
            in_maintenance,
            dismiss_threshold,
            escalate_threshold,
        );

        match result {
            VerificationResult::Dismiss { score, reason } => {
                let mut graph = state.knowledge_graph.write().unwrap();
                graph.ingest_decision(
                    &incident_id,
                    "dismiss",
                    None,
                    1.0,
                    &format!("obs-verify score {score}/100: {reason}"),
                    true,
                    chrono::Utc::now(),
                );
                dismissed += 1;
                debug!(
                    incident_id,
                    score, reason, "observation-verify: auto-dismissed"
                );
            }
            VerificationResult::Escalate { score, reason } => {
                // Spec 028-c: also record the escalate decision in the decisions
                // JSONL via state.decision_writer so dashboard bucketing (which
                // reads decisions, not the graph) can classify the IP as "needs
                // attention" instead of leaving it in "observing".
                //
                // The graph write and the JSONL write are kept separate scopes
                // so the graph write lock is released before we grab the
                // decision_writer (separate fields, but easier reasoning).
                {
                    let mut graph = state.knowledge_graph.write().unwrap();
                    graph.ingest_decision(
                        &incident_id,
                        "escalate",
                        primary_ip.as_deref(),
                        0.8,
                        &format!("obs-verify score {score}/100: {reason}"),
                        true,
                        chrono::Utc::now(),
                    );
                }
                if let Some(writer) = state.decision_writer.as_mut() {
                    let entry = crate::decisions::DecisionEntry {
                        ts: chrono::Utc::now(),
                        incident_id: incident_id.clone(),
                        host: String::new(),
                        ai_provider: "observation-verify".to_string(),
                        action_type: "escalate".to_string(),
                        target_ip: primary_ip.clone(),
                        target_user: None,
                        skill_id: None,
                        confidence: 0.8,
                        auto_executed: true,
                        dry_run: false,
                        reason: format!("obs-verify score {score}/100: {reason}"),
                        estimated_threat: "medium".to_string(),
                        execution_result: "pending-fase4".to_string(),
                        prev_hash: None,
                    };
                    if let Err(e) = writer.write(&entry) {
                        // Don't propagate; the graph already has the decision.
                        tracing::warn!(
                            incident_id = %incident_id,
                            error = %e,
                            "observation-verify: failed to write escalate decision to JSONL"
                        );
                    }
                }
                // Spec 028-b stub: the flag is read here so operators can
                // already toggle it in agent.toml, but the actual forwarding
                // into Fase 4 is a follow-up PR. Once the provider + skill
                // executor are threaded through this function (async
                // conversion required), replace this log with the real call.
                if cfg.incident_flow.escalate_to_decide {
                    tracing::info!(
                        incident_id = %incident_id,
                        target_ip = ?primary_ip,
                        "observation-verify: spec 028-b flag on - decide() call pending (follow-up PR threading)"
                    );
                }
                escalated += 1;
                debug!(
                    incident_id,
                    score, reason, "observation-verify: escalated to Fase 4"
                );
            }
            VerificationResult::NeedsAiVerification { score } => {
                ambiguous_items.push(AmbiguousItem {
                    incident_id,
                    score,
                    evidence,
                    detector,
                    title,
                });
            }
        }

        // Store breakdown for dashboard (Phase D)
        store_breakdown(&breakdown);
    }

    if dismissed > 0 || escalated > 0 || !ambiguous_items.is_empty() {
        info!(
            dismissed,
            escalated,
            ambiguous = ambiguous_items.len(),
            "observation-verify: processed OBSERVING queue"
        );
    }

    ambiguous_items
}

/// Collect undecided incident data from the knowledge graph.
///
/// The last tuple element is the primary IP entity connected to the incident,
/// if any. Spec 028-c uses this so the escalate decision written below can
/// link back to a target IP and the dashboard can bucket the IP as "needs
/// attention" instead of "observing".
fn collect_undecided_incidents(
    graph: &KnowledgeGraph,
) -> Vec<(String, String, String, serde_json::Value, Option<String>)> {
    graph
        .nodes_of_type(NodeType::Incident)
        .iter()
        .filter_map(|&id| {
            if let Some(Node::Incident {
                incident_id,
                decision,
                research_only,
                detector,
                title,
                summary,
                severity,
                ..
            }) = graph.get_node(id)
            {
                if decision.is_some() || *research_only {
                    return None;
                }

                let mut evidence = serde_json::json!({
                    "detector": detector,
                    "severity": severity,
                    "title": title,
                    "summary": summary,
                });

                // Enrich evidence from connected graph nodes.
                // Track the first IP entity we see as the primary attacker IP.
                let mut primary_ip: Option<String> = None;
                for edge in graph.edges_slice() {
                    if edge.from != id && edge.to != id {
                        continue;
                    }
                    let other_id = if edge.from == id { edge.to } else { edge.from };
                    if let Some(node) = graph.get_node(other_id) {
                        if primary_ip.is_none() {
                            if let Node::Ip { addr, .. } = node {
                                primary_ip = Some(addr.clone());
                            }
                        }
                        enrich_evidence_from_node(&mut evidence, node, graph);
                    }
                }

                Some((
                    incident_id.clone(),
                    detector.clone(),
                    title.clone(),
                    evidence,
                    primary_ip,
                ))
            } else {
                None
            }
        })
        .collect()
}

/// Add fields to the evidence JSON from a connected graph node.
fn enrich_evidence_from_node(
    evidence: &mut serde_json::Value,
    node: &Node,
    graph: &KnowledgeGraph,
) {
    let obj = evidence.as_object_mut().unwrap();
    match node {
        Node::Process {
            comm, exe, ppid, ..
        } => {
            obj.insert("comm".into(), serde_json::Value::String(comm.clone()));
            if let Some(exe) = exe {
                obj.insert("binary_path".into(), serde_json::Value::String(exe.clone()));
            }
            if *ppid > 0 {
                if let Some(parent_comm) = find_process_comm_by_pid(graph, *ppid) {
                    obj.insert("ppid_comm".into(), serde_json::Value::String(parent_comm));
                }
            }
        }
        Node::Ip { addr, .. } => {
            obj.insert("dst_ip".into(), serde_json::Value::String(addr.clone()));
        }
        Node::Port {
            number, protocol, ..
        } => {
            obj.insert("dst_port".into(), serde_json::json!(*number));
            obj.insert(
                "protocol".into(),
                serde_json::Value::String(protocol.clone()),
            );
        }
        Node::File { path, .. } => {
            obj.insert("path".into(), serde_json::Value::String(path.clone()));
        }
        _ => {}
    }
}

/// Find a process node by PID and return its comm name.
fn find_process_comm_by_pid(graph: &KnowledgeGraph, pid: u32) -> Option<String> {
    for &nid in &graph.nodes_of_type(NodeType::Process) {
        if let Some(Node::Process {
            pid: p, comm: c, ..
        }) = graph.get_node(nid)
        {
            if *p == pid {
                return Some(c.clone());
            }
        }
    }
    None
}

/// AI batch verification for ambiguous items (spec 021 Phase C).
///
/// Takes the ambiguous items collected by `verify_observing_incidents`,
/// builds a prompt, sends to the AI provider, parses verdicts, and
/// applies dismiss/escalate decisions to the knowledge graph.
pub(crate) async fn ai_verify_ambiguous(
    items: Vec<AmbiguousItem>,
    cfg: &crate::config::AgentConfig,
    state: &mut AgentState,
) {
    if items.is_empty() || !cfg.observation.ai_verification {
        return;
    }

    let ai = match &state.ai_provider {
        Some(ai) => ai.clone(),
        None => return,
    };

    // Build host profile from environment
    let host_profile = build_host_profile(state);

    // Process in batches
    let batch_size = cfg.observation.ai_batch_size.max(1);
    for chunk in items.chunks(batch_size) {
        let batch_items: Vec<observation_verify::AiBatchItem> = chunk
            .iter()
            .enumerate()
            .map(|(i, item)| observation_verify::AiBatchItem {
                index: i + 1,
                incident_id: item.incident_id.clone(),
                score: item.score,
                process: item
                    .evidence
                    .get("comm")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                event_summary: item
                    .evidence
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                binary_path: item
                    .evidence
                    .get("binary_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                parent_chain: item
                    .evidence
                    .get("ppid_comm")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                detector: item.detector.clone(),
            })
            .collect();

        let system_prompt = observation_verify::ai_verify_system_prompt(&host_profile);
        let user_message = observation_verify::ai_verify_user_message(&batch_items);

        let response = match ai.chat(&system_prompt, &user_message).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("observation-verify AI batch failed: {e:#}");
                continue;
            }
        };

        let verdicts = observation_verify::parse_ai_verdicts(&response);

        let mut ai_dismissed = 0u32;
        let mut ai_escalated = 0u32;

        for verdict in &verdicts {
            // Map 1-based index back to the chunk item
            let Some(item) = chunk.get(verdict.item_index.saturating_sub(1)) else {
                continue;
            };

            let mut graph = state.knowledge_graph.write().unwrap();
            match verdict.verdict {
                observation_verify::AiVerdictKind::Normal => {
                    graph.ingest_decision(
                        &item.incident_id,
                        "dismiss",
                        None,
                        0.9,
                        &format!("obs-verify AI: NORMAL — {}", verdict.reason),
                        true,
                        chrono::Utc::now(),
                    );
                    ai_dismissed += 1;
                }
                observation_verify::AiVerdictKind::Suspicious => {
                    graph.ingest_decision(
                        &item.incident_id,
                        "escalate",
                        None,
                        0.85,
                        &format!("obs-verify AI: SUSPICIOUS — {}", verdict.reason),
                        true,
                        chrono::Utc::now(),
                    );
                    ai_escalated += 1;
                }
            }
        }

        if ai_dismissed > 0 || ai_escalated > 0 {
            info!(
                ai_dismissed,
                ai_escalated,
                batch_size = chunk.len(),
                "observation-verify: AI batch complete"
            );
        }
    }
}

/// Build a host profile string from the agent's environment profile.
fn build_host_profile(state: &AgentState) -> String {
    build_host_profile_from_env(&state.environment_profile)
}

/// Pure helper: build host profile string from an EnvironmentProfile.
fn build_host_profile_from_env(env: &crate::environment_profile::EnvironmentProfile) -> String {
    let services = if env.services.is_empty() {
        "unknown".to_string()
    } else {
        env.services.join(", ")
    };
    format!(
        "Platform: {} ({})\nServices: {}",
        env.platform, env.provider, services,
    )
}

/// Store the score breakdown for dashboard display (Phase D stub).
fn store_breakdown(_breakdown: &ScoreBreakdown) {
    // Phase D will implement dashboard display of score breakdowns.
    // For now, the breakdown is included in the decision reason string.
}

// ── chrono import for Local time ────────────────────────────────────────
use chrono::Timelike;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambiguous_item_captures_fields() {
        let item = AmbiguousItem {
            incident_id: "test-123".to_string(),
            score: 55,
            evidence: serde_json::json!({"detector": "data_exfiltration"}),
            detector: "data_exfiltration".to_string(),
            title: "Data Exfiltration Detected".to_string(),
        };
        assert_eq!(item.score, 55);
        assert_eq!(item.incident_id, "test-123");
    }

    #[test]
    fn verification_result_serializes() {
        let r = VerificationResult::Dismiss {
            score: 85,
            reason: "package managed binary, trusted parent chain".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("Dismiss"));
        assert!(json.contains("85"));
    }

    #[test]
    fn score_breakdown_default() {
        let bd = ScoreBreakdown::default();
        assert_eq!(bd.total, 0);
        assert_eq!(bd.installation, 0);
    }

    #[test]
    fn find_process_comm_returns_none_on_empty_graph() {
        let graph = KnowledgeGraph::new();
        assert_eq!(find_process_comm_by_pid(&graph, 1234), None);
    }

    #[test]
    fn collect_undecided_on_empty_graph() {
        let graph = KnowledgeGraph::new();
        let result = collect_undecided_incidents(&graph);
        assert!(result.is_empty());
    }

    #[test]
    fn enrich_evidence_from_ip_node() {
        let mut evidence = serde_json::json!({});
        let node = Node::Ip {
            addr: "10.0.0.1".to_string(),
            is_internal: true,
            datasets: vec![],
            risk_score: 0,
            is_tor: false,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            attempted_usernames: vec![],
        };
        let graph = KnowledgeGraph::new();
        enrich_evidence_from_node(&mut evidence, &node, &graph);
        assert_eq!(evidence["dst_ip"], "10.0.0.1");
    }

    #[test]
    fn enrich_evidence_from_port_node() {
        let mut evidence = serde_json::json!({});
        let node = Node::Port {
            number: 443,
            protocol: "tcp".to_string(),
        };
        let graph = KnowledgeGraph::new();
        enrich_evidence_from_node(&mut evidence, &node, &graph);
        assert_eq!(evidence["dst_port"], 443);
        assert_eq!(evidence["protocol"], "tcp");
    }

    #[test]
    fn enrich_evidence_from_process_node() {
        let mut evidence = serde_json::json!({});
        let node = Node::Process {
            pid: 1234,
            ppid: 1,
            comm: "nginx".to_string(),
            exe: Some("/usr/sbin/nginx".to_string()),
            uid: 0,
            container_id: None,
            start_ts: chrono::Utc::now(),
            exit_ts: None,
        };
        let graph = KnowledgeGraph::new();
        enrich_evidence_from_node(&mut evidence, &node, &graph);
        assert_eq!(evidence["comm"], "nginx");
        assert_eq!(evidence["binary_path"], "/usr/sbin/nginx");
    }

    #[test]
    fn enrich_evidence_from_file_node() {
        let mut evidence = serde_json::json!({});
        let node = Node::File {
            path: "/etc/shadow".to_string(),
            sha256: None,
            size: None,
            entropy: None,
            is_sensitive: true,
            yara_matches: vec![],
        };
        let graph = KnowledgeGraph::new();
        enrich_evidence_from_node(&mut evidence, &node, &graph);
        assert_eq!(evidence["path"], "/etc/shadow");
    }

    // ── find_process_comm_by_pid: 3 tests ───────────────────────────────

    #[test]
    fn find_process_comm_finds_existing_pid() {
        let mut graph = KnowledgeGraph::new();
        graph.add_node(Node::Process {
            pid: 42,
            ppid: 1,
            comm: "systemd".to_string(),
            exe: Some("/usr/lib/systemd/systemd".to_string()),
            uid: 0,
            container_id: None,
            start_ts: chrono::Utc::now(),
            exit_ts: None,
        });
        assert_eq!(
            find_process_comm_by_pid(&graph, 42),
            Some("systemd".to_string())
        );
    }

    #[test]
    fn find_process_comm_returns_none_for_missing_pid() {
        let mut graph = KnowledgeGraph::new();
        graph.add_node(Node::Process {
            pid: 42,
            ppid: 1,
            comm: "systemd".to_string(),
            exe: None,
            uid: 0,
            container_id: None,
            start_ts: chrono::Utc::now(),
            exit_ts: None,
        });
        assert_eq!(find_process_comm_by_pid(&graph, 999), None);
    }

    // ── collect_undecided_incidents: 3 tests ────────────────────────────

    #[test]
    fn collect_undecided_skips_decided_incidents() {
        let mut graph = KnowledgeGraph::new();
        let inc = innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            incident_id: "inc-1".to_string(),
            severity: innerwarden_core::event::Severity::Medium,
            title: "Test".to_string(),
            summary: "Test summary".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        };
        graph.ingest_incident(&inc);
        // Mark as decided
        graph.ingest_decision(
            "inc-1",
            "dismiss",
            None,
            1.0,
            "test",
            true,
            chrono::Utc::now(),
        );
        let result = collect_undecided_incidents(&graph);
        assert!(result.is_empty(), "decided incident should be skipped");
    }

    #[test]
    fn collect_undecided_returns_undecided_incidents() {
        let mut graph = KnowledgeGraph::new();
        let inc = innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            incident_id: "inc-2".to_string(),
            severity: innerwarden_core::event::Severity::Medium,
            title: "Data Exfil".to_string(),
            summary: "Suspicious outbound".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["data_exfiltration".to_string()],
            entities: vec![],
        };
        graph.ingest_incident(&inc);
        let result = collect_undecided_incidents(&graph);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "inc-2");
    }

    #[test]
    fn collect_undecided_includes_incident_metadata() {
        let mut graph = KnowledgeGraph::new();
        let inc = innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test".to_string(),
            incident_id: "inc-3".to_string(),
            severity: innerwarden_core::event::Severity::High,
            title: "Data Exfiltration".to_string(),
            summary: "Large outbound transfer".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["data_exfiltration".to_string()],
            entities: vec![],
        };
        graph.ingest_incident(&inc);
        let result = collect_undecided_incidents(&graph);
        assert_eq!(result.len(), 1);
        // Check the evidence includes detector and severity from node
        assert_eq!(result[0].2, "Data Exfiltration"); // title
        assert!(result[0].3["severity"].is_string()); // severity present
    }

    // ── enrich_evidence_from_node: edge cases ───────────────────────────

    #[test]
    fn enrich_evidence_process_no_exe() {
        let mut evidence = serde_json::json!({});
        let node = Node::Process {
            pid: 1,
            ppid: 0,
            comm: "init".to_string(),
            exe: None,
            uid: 0,
            container_id: None,
            start_ts: chrono::Utc::now(),
            exit_ts: None,
        };
        let graph = KnowledgeGraph::new();
        enrich_evidence_from_node(&mut evidence, &node, &graph);
        assert_eq!(evidence["comm"], "init");
        assert!(evidence.get("binary_path").is_none());
    }

    #[test]
    fn enrich_evidence_domain_node_ignored() {
        let mut evidence = serde_json::json!({});
        let node = Node::Domain {
            name: "example.com".to_string(),
            datasets: vec![],
            is_dga: None,
            entropy: None,
        };
        let graph = KnowledgeGraph::new();
        enrich_evidence_from_node(&mut evidence, &node, &graph);
        // Domain nodes are not enriched (matched by _ => {})
        assert!(evidence.as_object().unwrap().is_empty());
    }

    #[test]
    fn enrich_evidence_preserves_existing_fields() {
        let mut evidence = serde_json::json!({"existing_key": "existing_value"});
        let node = Node::Ip {
            addr: "1.2.3.4".to_string(),
            is_internal: false,
            datasets: vec![],
            risk_score: 50,
            is_tor: false,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            attempted_usernames: vec![],
        };
        let graph = KnowledgeGraph::new();
        enrich_evidence_from_node(&mut evidence, &node, &graph);
        assert_eq!(evidence["existing_key"], "existing_value");
        assert_eq!(evidence["dst_ip"], "1.2.3.4");
    }

    // ── build_host_profile_from_env: 3 tests ──────────────────────────

    #[test]
    fn host_profile_with_services() {
        use crate::environment_profile::EnvironmentProfile;
        let env = EnvironmentProfile {
            platform: "cloud_vps".into(),
            provider: "oracle".into(),
            services: vec!["nginx".into(), "postgres".into()],
            ..Default::default()
        };
        let profile = build_host_profile_from_env(&env);
        assert!(profile.contains("cloud_vps"));
        assert!(profile.contains("oracle"));
        assert!(profile.contains("nginx"));
        assert!(profile.contains("postgres"));
    }

    #[test]
    fn host_profile_no_services() {
        use crate::environment_profile::EnvironmentProfile;
        let env = EnvironmentProfile::default();
        let profile = build_host_profile_from_env(&env);
        assert!(profile.contains("unknown"));
    }

    #[test]
    fn host_profile_bare_metal() {
        use crate::environment_profile::EnvironmentProfile;
        let env = EnvironmentProfile {
            platform: "bare_metal".into(),
            provider: "none".into(),
            services: vec!["sshd".into()],
            ..Default::default()
        };
        let profile = build_host_profile_from_env(&env);
        assert!(profile.contains("bare_metal"));
        assert!(profile.contains("sshd"));
    }
}
