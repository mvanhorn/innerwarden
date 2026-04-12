//! Daily AI Intelligence Briefing — generates structured threat summary from knowledge graph.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::{Arc, RwLock};

use crate::knowledge_graph::types::{Node, NodeType, Relation};
use crate::knowledge_graph::KnowledgeGraph;

/// The generated briefing result.
#[derive(Debug, Clone, Serialize)]
pub struct Briefing {
    pub generated_at: DateTime<Utc>,
    pub date: String,
    pub threat_level: String,
    pub summary: String,
}

/// Build the structured context from the knowledge graph for LLM consumption.
/// Separates contained (resolved) from unresolved, marks internal IPs,
/// and shows actions already taken.
pub fn build_briefing_context(kg: &Arc<RwLock<KnowledgeGraph>>) -> String {
    let graph = kg.read().unwrap();

    let incident_nodes = graph.nodes_of_type(NodeType::Incident);

    // Categorize incidents
    let mut contained = 0usize;
    let mut ignored = 0usize;
    let mut unresolved = 0usize;
    let mut unresolved_high_crit = 0usize;
    let mut by_detector: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut by_severity: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut actions_taken: Vec<String> = Vec::new();
    let mut unresolved_list: Vec<(String, String, String)> = Vec::new(); // (severity, title, entity)

    for &id in &incident_nodes {
        if let Some(Node::Incident {
            detector,
            severity,
            title,
            decision,
            decision_target,
            auto_executed,
            research_only,
            ..
        }) = graph.get_node(id)
        {
            // Skip research-only incidents — these are self-traffic (agent
            // notifications, cloud metadata, CrowdSec polling) that pollute
            // the briefing with false "threats" like Telegram API IPs.
            if *research_only {
                continue;
            }
            *by_detector.entry(detector.clone()).or_default() += 1;
            *by_severity.entry(severity.to_lowercase()).or_default() += 1;

            match decision.as_deref() {
                Some("block_ip") => {
                    contained += 1;
                    let target = decision_target.as_deref().unwrap_or("?");
                    let mode = if *auto_executed {
                        "auto-blocked"
                    } else {
                        "manual"
                    };
                    actions_taken.push(format!("Blocked IP {} ({}) — {}", target, mode, title));
                }
                Some("monitor") => {
                    contained += 1;
                }
                Some("honeypot") => {
                    contained += 1;
                }
                Some("kill_process") => {
                    contained += 1;
                    actions_taken.push(format!("Killed process — {}", title));
                }
                Some("suspend_user_sudo") => {
                    contained += 1;
                    actions_taken.push(format!("Suspended sudo — {}", title));
                }
                Some("ignore") => {
                    ignored += 1;
                }
                Some(_) => {
                    contained += 1;
                }
                None => {
                    // Check if this "unresolved" incident only involves
                    // self-traffic IPs — if so, it's a pre-fix FP that
                    // wasn't marked research_only. Don't count it as
                    // needing attention.
                    let entities: Vec<String> = graph
                        .outgoing_edges(id)
                        .iter()
                        .filter(|e| e.relation == Relation::TriggeredBy)
                        .filter_map(|e| graph.get_node(e.to))
                        .filter_map(|n| {
                            if let Node::Ip { addr, .. } = n {
                                Some(addr.clone())
                            } else {
                                None
                            }
                        })
                        .collect();
                    let all_self = !entities.is_empty()
                        && entities
                            .iter()
                            .all(|ip| crate::cloud_safelist::is_self_traffic_ip(ip));
                    if all_self {
                        ignored += 1; // Treat as noise for briefing purposes
                    } else {
                        unresolved += 1;
                        let sev = severity.to_lowercase();
                        if sev == "high" || sev == "critical" {
                            unresolved_high_crit += 1;
                            let entity = entities.first().cloned().unwrap_or_default();
                            if unresolved_list.len() < 10 {
                                unresolved_list.push((sev, title.clone(), entity));
                            }
                        }
                    }
                }
            }
        }
    }

    // Top attackers — ONLY external IPs, annotate if already blocked
    let mut ip_data: std::collections::HashMap<String, (usize, Vec<String>, bool)> =
        std::collections::HashMap::new();
    for &inc_id in &incident_nodes {
        if let Some(Node::Incident {
            detector,
            decision,
            decision_target,
            research_only,
            ..
        }) = graph.get_node(inc_id)
        {
            if *research_only {
                continue;
            }
            for edge in graph.outgoing_edges(inc_id) {
                if edge.relation != Relation::TriggeredBy {
                    continue;
                }
                if let Some(Node::Ip {
                    addr, is_internal, ..
                }) = graph.get_node(edge.to)
                {
                    if *is_internal {
                        continue;
                    }
                    // Skip self-traffic IPs (cloud providers, agent services,
                    // local interfaces) — same filter as investigation.rs
                    if crate::cloud_safelist::is_self_traffic_ip(addr) {
                        continue;
                    }
                    let entry = ip_data
                        .entry(addr.clone())
                        .or_insert((0, Vec::new(), false));
                    entry.0 += 1;
                    if !entry.1.contains(detector) {
                        entry.1.push(detector.clone());
                    }
                    if decision.as_deref() == Some("block_ip")
                        && decision_target.as_deref() == Some(addr.as_str())
                    {
                        entry.2 = true; // Already blocked
                    }
                }
            }
        }
    }
    let mut top_attackers: Vec<_> = ip_data.into_iter().collect();
    top_attackers.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    top_attackers.truncate(10);

    // Detectors sorted
    let mut sorted_detectors: Vec<_> = by_detector.into_iter().collect();
    sorted_detectors.sort_by(|a, b| b.1.cmp(&a.1));
    sorted_detectors.truncate(10);

    // Threat level — based on UNRESOLVED, not total
    let _threat_level = if unresolved_high_crit > 5 {
        "CRITICAL"
    } else if unresolved_high_crit > 0 {
        "ELEVATED"
    } else if unresolved > 10 {
        "MODERATE"
    } else {
        "LOW"
    };

    // Count unique blocked IPs (not decisions — matches dashboard KPI)
    let blocked_ips: std::collections::HashSet<&str> = actions_taken
        .iter()
        .filter_map(|a| {
            if a.starts_with("Blocked IP ") {
                a.split_whitespace().nth(2)
            } else {
                None
            }
        })
        .collect();

    // Build context
    let operator_incidents = contained + unresolved; // excludes research_only
    let mut ctx = format!(
        "SECURITY INTELLIGENCE CONTEXT — {}\n\n\
         SITUATION STATUS:\n\
         - Operator-relevant incidents today: {}\n\
         - BLOCKED: {} unique IP{} auto-blocked by AI\n\
         - OBSERVING: {} incidents being monitored (AI is handling, no human action needed)\n\
         - IGNORED: {} confirmed non-threats\n\
         - The server uses SSH key-only authentication — password brute-force cannot succeed\n\
         - Most external activity is routine internet scanning that fails at protocol level\n\n\
         IMPORTANT: The AI is handling everything. {} of {} incidents are already resolved or being monitored.\n\
         Human attention needed: {}.\n\n",
        Utc::now().format("%Y-%m-%d"),
        operator_incidents,
        blocked_ips.len(),
        if blocked_ips.len() == 1 { "" } else { "s" },
        unresolved,
        ignored,
        contained + unresolved, operator_incidents,
        if unresolved_high_crit == 0 {
            "NONE — everything is handled".to_string()
        } else {
            format!("{} high/critical items to review", unresolved_high_crit)
        },
    );

    if !actions_taken.is_empty() {
        ctx.push_str("ACTIONS ALREADY TAKEN BY AI:\n");
        for (i, action) in actions_taken.iter().take(10).enumerate() {
            ctx.push_str(&format!("  {}. {}\n", i + 1, action));
        }
        if actions_taken.len() > 10 {
            ctx.push_str(&format!(
                "  ... and {} more actions\n",
                actions_taken.len() - 10
            ));
        }
        ctx.push('\n');
    }

    if !unresolved_list.is_empty() {
        ctx.push_str("UNRESOLVED THREATS NEEDING ATTENTION:\n");
        for (sev, title, entity) in &unresolved_list {
            ctx.push_str(&format!(
                "  - [{}] {} ({})\n",
                sev.to_uppercase(),
                title,
                entity
            ));
        }
        ctx.push('\n');
    }

    ctx.push_str("TOP ATTACKERS (external IPs only):\n");
    for (ip, (count, dets, blocked)) in &top_attackers {
        let status = if *blocked { " [ALREADY BLOCKED]" } else { "" };
        ctx.push_str(&format!(
            "  - {} — {} incidents, detectors: {}{}\n",
            ip,
            count,
            dets.join(", "),
            status
        ));
    }

    ctx.push_str("\nDETECTOR ACTIVITY:\n");
    for (det, count) in &sorted_detectors {
        ctx.push_str(&format!("  - {}: {}\n", det, count));
    }

    ctx.push_str(&format!(
        "\nKNOWLEDGE GRAPH: {} nodes, {} edges\n\
         EVENTS INGESTED: {}\n",
        graph.metrics().node_count,
        graph.metrics().edge_count,
        graph.total_events_ingested,
    ));

    ctx
}

/// The LLM prompt for generating the briefing.
pub fn briefing_prompt(context: &str) -> String {
    format!(
        "You are the AI security agent writing a daily briefing for a non-technical server operator.\n\
         \n\
         This server is protected by InnerWarden — an autonomous AI security agent that blocks \
         threats automatically. The operator does NOT need to take action on most items. \
         SSH uses key-only authentication (password login disabled). Most activity from \
         external IPs is routine internet scanning that fails at the protocol level.\n\
         \n\
         CRITICAL RULES:\n\
         - CONTAINED/BLOCKED items are RESOLVED — present them as success, not active threats\n\
         - IGNORED items are confirmed noise — do not mention them\n\
         - UNRESOLVED items are being OBSERVED by the AI — only flag if genuinely dangerous\n\
         - Routine scanners (SSH malformed strings, port probes) are NOT dangerous and NOT urgent\n\
         - Do NOT recommend 'updating passwords' or generic security advice\n\
         - Be reassuring when the server is safe. Be direct only when something is genuinely dangerous.\n\
         - Write for someone who is NOT a security professional\n\
         \n\
         Write a SHORT briefing (under 150 words) with:\n\
         1. **STATUS** — one sentence: is the server safe right now?\n\
         2. **WHAT THE AI DID** — 2-3 bullets of actions taken (blocks, monitoring)\n\
         3. **NEEDS ATTENTION** — only if something genuinely requires human decision (rare)\n\
         \n\
         Tone: calm, confident, specific. Like a trusted security guard giving a morning report.\n\
         \n\
         ---\n\
         \n\
         {context}"
    )
}

/// Parse the LLM response into a structured Briefing.
pub fn parse_briefing(llm_response: &str, context_threat_level: &str) -> Briefing {
    Briefing {
        generated_at: Utc::now(),
        date: Utc::now().format("%Y-%m-%d").to_string(),
        threat_level: context_threat_level.to_string(),
        summary: llm_response.to_string(),
    }
}
