use super::graph::KnowledgeGraph;
use super::types::*;

impl KnowledgeGraph {
    /// Generate an attack narrative from a node's neighborhood.
    /// Used by AI triage to provide full context about an incident.
    pub fn attack_narrative(&self, center: NodeId, depth: usize) -> String {
        let sub = self.neighborhood(center, depth);
        if sub.nodes.is_empty() {
            return String::from("No graph context available.");
        }

        let mut lines = Vec::new();
        lines.push("ATTACK CONTEXT (from knowledge graph):".to_string());
        lines.push(String::new());

        // Timeline section
        let mut sorted_edges: Vec<&Edge> = sub.edges.iter().collect();
        sorted_edges.sort_by_key(|e| e.ts);

        lines.push("  Timeline:".to_string());
        for edge in &sorted_edges {
            if edge.is_snapshot() {
                continue;
            }
            let from_label = sub
                .nodes
                .get(&edge.from)
                .map(|n| n.label())
                .unwrap_or_else(|| format!("node:{}", edge.from));
            let to_label = sub
                .nodes
                .get(&edge.to)
                .map(|n| n.label())
                .unwrap_or_else(|| format!("node:{}", edge.to));

            let ts_str = edge.ts.format("%H:%M:%S").to_string();
            let rel = format!("{:?}", edge.relation);
            let mut detail = format!("    {} {} --[{}]--> {}", ts_str, from_label, rel, to_label);

            // Add important properties inline
            for (key, val) in &edge.properties {
                match &**key {
                    "port" | "signal" | "method" | "command" | "module_name" => {
                        let val_str = match val {
                            serde_json::Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        detail.push_str(&format!(" ({}={})", key, val_str));
                    }
                    "success" if val == &serde_json::Value::Bool(false) => {
                        detail.push_str(" (FAILED)");
                    }
                    _ => {}
                }
            }
            lines.push(detail);
        }

        // Risk indicators section
        lines.push(String::new());
        lines.push("  Risk indicators:".to_string());

        let mut risk_count = 0;

        // Threat intel IPs
        for node in sub.nodes.values() {
            if let Node::Ip {
                datasets,
                is_tor,
                risk_score,
                addr,
                ..
            } = node
            {
                if !datasets.is_empty() {
                    lines.push(format!(
                        "    - IP {} in threat intel: {}",
                        addr,
                        datasets.join(", ")
                    ));
                    risk_count += 1;
                }
                if *is_tor {
                    lines.push(format!("    - IP {} is Tor exit node", addr));
                    risk_count += 1;
                }
                if *risk_score > 50 {
                    lines.push(format!("    - IP {} risk score: {}/100", addr, risk_score));
                    risk_count += 1;
                }
            }
        }

        // High entropy files
        for node in sub.nodes.values() {
            if let Node::File {
                path,
                entropy: Some(ent),
                ..
            } = node
            {
                if *ent > 7.0 {
                    lines.push(format!(
                        "    - File {} has high entropy ({:.1} bits, packed/encrypted)",
                        path, ent
                    ));
                    risk_count += 1;
                }
            }
        }

        // Sensitive file access
        for node in sub.nodes.values() {
            if let Node::File {
                path,
                is_sensitive: true,
                ..
            } = node
            {
                // Check if there's a Read or Wrote edge to this file
                let has_access = sorted_edges.iter().any(|e| {
                    let target_id = sub
                        .nodes
                        .iter()
                        .find(|(_, n)| matches!(n, Node::File { path: p, .. } if p == path))
                        .map(|(&id, _)| id);
                    target_id.is_some_and(|tid| {
                        (e.to == tid || e.from == tid)
                            && matches!(e.relation, Relation::Read | Relation::Wrote)
                    })
                });
                if has_access {
                    lines.push(format!("    - Sensitive file accessed: {}", path));
                    risk_count += 1;
                }
            }
        }

        // Persistence indicators
        let persistence_paths = ["/etc/cron", "authorized_keys", "/etc/systemd"];
        for edge in &sorted_edges {
            if edge.relation == Relation::Wrote {
                if let Some(Node::File { path, .. }) = sub.nodes.get(&edge.to) {
                    if persistence_paths.iter().any(|p| path.contains(p)) {
                        lines.push(format!("    - Persistence mechanism: wrote to {}", path));
                        risk_count += 1;
                    }
                }
            }
        }

        if risk_count == 0 {
            lines.push("    - No specific risk indicators found".to_string());
        }

        // Process tree depth — try center first, then any process in the neighborhood.
        let process_pid = match self.get_node(center) {
            Some(Node::Process { pid, .. }) => Some(*pid),
            _ => sub.nodes.values().find_map(|n| match n {
                Node::Process { pid, .. } => Some(*pid),
                _ => None,
            }),
        };
        if let Some(pid) = process_pid {
            let ancestors = self.ancestors(pid);
            if ancestors.len() >= 2 {
                let proc_id = self.find_by_pid(pid);
                let chain: Vec<String> = proc_id
                    .into_iter()
                    .chain(ancestors.iter().copied())
                    .filter_map(|id| self.get_node(id))
                    .map(|n| n.label())
                    .collect();
                lines.push(String::new());
                lines.push(format!("  Process chain: {}", chain.join(" → ")));
            }
        }

        // Phase 015: surface incident-specific signals when center is an Incident node.
        if let Some(Node::Incident {
            decision,
            confidence,
            false_positive,
            ..
        }) = self.get_node(center)
        {
            if *false_positive {
                lines.push(String::new());
                lines.push(
                    "  ⚠ This incident was previously marked as FALSE POSITIVE by an operator"
                        .to_string(),
                );
            }
            if let Some(action) = decision {
                let conf = confidence.unwrap_or(0.0);
                lines.push(String::new());
                lines.push(format!(
                    "  Prior decision: {} (confidence {:.0}%)",
                    action,
                    conf * 100.0
                ));
            }
        }

        lines.join("\n")
    }

    /// Analyze the impact of blocking an IP or killing a process.
    #[allow(dead_code)] // kept on graph narrative surface; wired in spec 016 proposal UI
    pub fn impact_analysis(&self, action: &str, target: &str) -> String {
        match action {
            "block_ip" => self.impact_block_ip(target),
            "kill_process" => {
                if let Ok(pid) = target.parse::<u32>() {
                    self.impact_kill_process(pid)
                } else {
                    "Invalid PID".to_string()
                }
            }
            _ => format!("Unknown action: {}", action),
        }
    }

    #[allow(dead_code)]
    fn impact_block_ip(&self, ip: &str) -> String {
        let ip_id = match self.find_by_ip(ip) {
            Some(id) => id,
            None => return format!("IP {} not in graph — safe to block", ip),
        };

        // Find all processes connected to this IP
        let mut affected_processes = Vec::new();
        let mut production_impact = false;

        let production_comms = [
            "nginx",
            "apache",
            "httpd",
            "postgresql",
            "postgres",
            "mysql",
            "mysqld",
            "redis-server",
            "redis",
            "haproxy",
            "sshd",
            "mongod",
            "node",
            "java",
            "python3",
            "gunicorn",
            "uwsgi",
        ];

        for edge in self.incoming_edges(ip_id) {
            if edge.relation == Relation::ConnectedTo {
                if let Some(Node::Process { pid, comm, .. }) = self.get_node(edge.from) {
                    affected_processes.push(format!("PID {} ({})", pid, comm));
                    if production_comms.iter().any(|p| comm.contains(p)) {
                        production_impact = true;
                    }
                }
            }
        }

        if affected_processes.is_empty() {
            return format!("IP {} — no active connections, safe to block", ip);
        }

        let mut lines = Vec::new();
        if production_impact {
            lines.push(format!(
                "WARNING: Blocking {} affects production processes:",
                ip
            ));
        } else {
            lines.push(format!(
                "Safe to block {} — {} process(es) affected, no production impact:",
                ip,
                affected_processes.len()
            ));
        }
        for p in &affected_processes {
            lines.push(format!("  - {}", p));
        }
        lines.join("\n")
    }

    #[allow(dead_code)]
    fn impact_kill_process(&self, pid: u32) -> String {
        let proc_id = match self.find_by_pid(pid) {
            Some(id) => id,
            None => return format!("PID {} not in graph", pid),
        };

        let children = self.descendants(pid);
        let node = self.get_node(proc_id);
        let comm = node.map(|n| n.label()).unwrap_or_default();

        let mut lines = Vec::new();
        lines.push(format!(
            "Killing PID {} ({}) — {} child process(es):",
            pid,
            comm,
            children.len()
        ));
        for child_id in &children {
            if let Some(n) = self.get_node(*child_id) {
                lines.push(format!("  - {}", n.label()));
            }
        }
        if children.is_empty() {
            lines.push("  No children — safe to kill".to_string());
        }
        lines.join("\n")
    }

    /// Generate confidence signals for an incident based on graph structure.
    #[allow(dead_code)] // surfaced in future neural/dashboard confidence hover panels
    pub fn confidence_signals(&self, node: NodeId) -> Vec<(String, f32)> {
        let mut signals = Vec::new();

        // Process chain depth
        if let Some(Node::Process { pid, .. }) = self.get_node(node) {
            let anc = self.ancestors(*pid);
            if anc.len() >= 2 {
                signals.push(("deep_process_chain".to_string(), 0.2));
            }
            if anc.len() >= 4 {
                signals.push(("very_deep_chain".to_string(), 0.3));
            }
        }

        // Fan-out (many connections = suspicious)
        let out_edges = self.outgoing_edges(node);
        let connect_count = out_edges
            .iter()
            .filter(|e| e.relation == Relation::ConnectedTo)
            .count();
        if connect_count > 10 {
            signals.push(("high_fan_out".to_string(), 0.2));
        }
        if connect_count > 50 {
            signals.push(("extreme_fan_out".to_string(), 0.3));
        }

        // Threat intel nodes in neighborhood
        let sub = self.neighborhood(node, 2);
        let ti_count = sub
            .nodes
            .values()
            .filter(|n| matches!(n, Node::Ip { datasets, .. } if !datasets.is_empty()))
            .count();
        if ti_count > 0 {
            signals.push((
                format!("{}_threat_intel_ips", ti_count),
                0.15 * ti_count as f32,
            ));
        }

        // Sensitive file access
        let sensitive_access = sub.edges.iter().any(|e| {
            matches!(e.relation, Relation::Read | Relation::Wrote)
                && sub.nodes.get(&e.to).is_some_and(|n| n.is_sensitive_file())
        });
        if sensitive_access {
            signals.push(("sensitive_file_access".to_string(), 0.15));
        }

        // Persistence indicators
        let has_persistence = sub.edges.iter().any(|e| {
            e.relation == Relation::Wrote
                && sub.nodes.get(&e.to).is_some_and(|n| {
                    if let Node::File { path, .. } = n {
                        path.contains("/etc/cron")
                            || path.contains("authorized_keys")
                            || path.contains("/etc/systemd")
                    } else {
                        false
                    }
                })
        });
        if has_persistence {
            signals.push(("persistence_detected".to_string(), 0.25));
        }

        signals
    }

    // ─── Spec 025 — structured subgraph for LLM prompts ─────────────────
    //
    // Returns the same neighbourhood as `attack_narrative`, but as a
    // compact JSON payload the LLM can reason over directly instead of
    // re-deriving structure from prose. Measured delta on qwen2.5:3b:
    // action accuracy 53% → 73%, target hallucination 47% → 7%
    // (see `.specify/features/025-structured-ai-prompt/spec.md`).
    //
    // Output shape:
    //   { nodes: [ { id, type, label, ...selected_fields } ],
    //     edges: [ { from, to, rel, ts } ],
    //     truncated: bool }
    //
    // Design notes:
    // - The node projection drops bulky optional fields (datasets, tags,
    //   properties) — only the IDs + type + label + the few typed
    //   attributes that drive decisions (ip addr, pid, comm, severity).
    // - Cap at 40 nodes to keep the prompt manageable on small local
    //   models (qwen2.5:1.5b struggles above ~3k tokens). When the BFS
    //   returns more, we keep the centre + its most connected neighbours
    //   and emit `truncated: true` so the model knows context is partial.
    // - Edge timestamps are RFC3339 so the model can reason about ordering
    //   without having to parse weird formats.
    pub fn attack_subgraph_json(&self, center: NodeId, depth: usize) -> serde_json::Value {
        const MAX_NODES: usize = 40;

        let sub = self.neighborhood(center, depth);
        let full_node_count = sub.nodes.len();

        // Rank nodes by edge count so we keep the most connected ones when
        // truncating. Always keep the centre.
        let mut node_ids: Vec<NodeId> = sub.nodes.keys().copied().collect();
        if full_node_count > MAX_NODES {
            let mut degree: std::collections::HashMap<NodeId, usize> =
                std::collections::HashMap::new();
            for edge in &sub.edges {
                *degree.entry(edge.from).or_insert(0) += 1;
                *degree.entry(edge.to).or_insert(0) += 1;
            }
            node_ids.sort_by(|a, b| {
                // Centre always first, then by descending degree.
                if *a == center {
                    return std::cmp::Ordering::Less;
                }
                if *b == center {
                    return std::cmp::Ordering::Greater;
                }
                degree
                    .get(b)
                    .copied()
                    .unwrap_or(0)
                    .cmp(&degree.get(a).copied().unwrap_or(0))
            });
            node_ids.truncate(MAX_NODES);
        }

        let kept: std::collections::HashSet<NodeId> = node_ids.iter().copied().collect();

        let node_payload: Vec<serde_json::Value> = node_ids
            .iter()
            .filter_map(|id| sub.nodes.get(id).map(|n| project_node(*id, n)))
            .collect();

        // Only keep edges whose endpoints both survived truncation so the
        // LLM never references a dangling id.
        let edge_payload: Vec<serde_json::Value> = sub
            .edges
            .iter()
            .filter(|e| kept.contains(&e.from) && kept.contains(&e.to))
            .map(|e| {
                serde_json::json!({
                    "from": e.from,
                    "to": e.to,
                    "rel": format!("{:?}", e.relation),
                    "ts": e.ts.to_rfc3339(),
                })
            })
            .collect();

        serde_json::json!({
            "center": center,
            "nodes": node_payload,
            "edges": edge_payload,
            "truncated": full_node_count > MAX_NODES,
            "full_node_count": full_node_count,
        })
    }
}

/// Project a single `Node` into a compact `{id, type, label, ...}` JSON value
/// that the LLM can consume without re-deriving structure from prose.
fn project_node(id: NodeId, node: &Node) -> serde_json::Value {
    let mut out = serde_json::json!({
        "id": id,
        "type": format!("{:?}", node.node_type()),
        "label": node.label(),
    });
    let obj = out.as_object_mut().expect("json object");
    match node {
        Node::Ip {
            addr,
            is_tor,
            risk_score,
            datasets,
            ..
        } => {
            obj.insert("addr".into(), serde_json::Value::String(addr.clone()));
            if *is_tor {
                obj.insert("is_tor".into(), serde_json::Value::Bool(true));
            }
            if *risk_score > 0 {
                obj.insert("risk_score".into(), serde_json::json!(*risk_score));
            }
            if !datasets.is_empty() {
                obj.insert(
                    "threat_intel".into(),
                    serde_json::Value::Array(
                        datasets
                            .iter()
                            .cloned()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                );
            }
        }
        Node::Process { pid, comm, uid, .. } => {
            obj.insert("pid".into(), serde_json::json!(*pid));
            obj.insert("comm".into(), serde_json::Value::String(comm.clone()));
            obj.insert("uid".into(), serde_json::json!(*uid));
        }
        Node::File { path, .. } => {
            obj.insert("path".into(), serde_json::Value::String(path.clone()));
        }
        Node::User { name, uid, .. } => {
            obj.insert("name".into(), serde_json::Value::String(name.clone()));
            if let Some(uid) = uid {
                obj.insert("uid".into(), serde_json::json!(*uid));
            }
        }
        Node::Incident {
            incident_id,
            severity,
            detector,
            decision,
            auto_executed,
            ..
        } => {
            obj.insert(
                "incident_id".into(),
                serde_json::Value::String(incident_id.clone()),
            );
            obj.insert(
                "severity".into(),
                serde_json::Value::String(severity.clone()),
            );
            obj.insert(
                "detector".into(),
                serde_json::Value::String(detector.clone()),
            );
            if let Some(dec) = decision {
                obj.insert("decision".into(), serde_json::Value::String(dec.clone()));
                obj.insert(
                    "auto_executed".into(),
                    serde_json::Value::Bool(*auto_executed),
                );
            }
        }
        Node::Port {
            number, protocol, ..
        } => {
            obj.insert("port".into(), serde_json::json!(*number));
            obj.insert(
                "protocol".into(),
                serde_json::Value::String(protocol.clone()),
            );
        }
        Node::Domain { name, .. } => {
            obj.insert("name".into(), serde_json::Value::String(name.clone()));
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1700000000 + secs, 0).unwrap()
    }

    #[test]
    fn test_attack_narrative() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(1236, 1234, "payload", 0, ts(0));
        let ip = g.ensure_ip("93.1.1.1", ts(0));
        let file = g.ensure_file("/etc/cron.d/backdoor");

        g.add_edge(Edge::new(proc_id, ip, Relation::ConnectedTo, ts(1)));
        g.add_edge(Edge::new(proc_id, file, Relation::Wrote, ts(2)));

        let narrative = g.attack_narrative(proc_id, 2);
        assert!(narrative.contains("payload"));
        assert!(narrative.contains("93.1.1.1"));
        assert!(narrative.contains("/etc/cron.d/backdoor"));
        assert!(narrative.contains("Persistence mechanism"));
    }

    #[test]
    fn test_impact_analysis_block_ip() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(1236, 0, "payload", 0, ts(0));
        let ip_id = g.ensure_ip("93.1.1.1", ts(0));
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, ts(1)));

        let impact = g.impact_analysis("block_ip", "93.1.1.1");
        assert!(impact.contains("safe to block") || impact.contains("Safe to block"));
        assert!(impact.contains("payload"));
    }

    #[test]
    fn test_impact_analysis_production() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(100, 0, "nginx", 0, ts(0));
        let ip_id = g.ensure_ip("10.0.0.1", ts(0));
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, ts(1)));

        let impact = g.impact_analysis("block_ip", "10.0.0.1");
        assert!(impact.contains("WARNING") || impact.contains("production"));
    }

    #[test]
    fn test_confidence_signals() {
        let mut g = KnowledgeGraph::new();
        let sshd = g.ensure_process(800, 1, "sshd", 0, ts(0));
        let bash = g.ensure_process(1234, 800, "bash", 0, ts(1));
        let wget = g.ensure_process(1235, 1234, "wget", 0, ts(2));
        let payload = g.ensure_process(1236, 1234, "payload", 0, ts(3));

        g.add_edge(Edge::new(bash, sshd, Relation::SpawnedBy, ts(1)));
        g.add_edge(Edge::new(wget, bash, Relation::SpawnedBy, ts(2)));
        g.add_edge(Edge::new(payload, bash, Relation::SpawnedBy, ts(3)));

        let file = g.ensure_file("/etc/cron.d/backdoor");
        g.add_edge(Edge::new(payload, file, Relation::Wrote, ts(4)));

        let signals = g.confidence_signals(payload);
        assert!(!signals.is_empty());
        // Should detect deep chain and persistence
        let signal_names: Vec<&str> = signals.iter().map(|(n, _)| n.as_str()).collect();
        assert!(signal_names.contains(&"deep_process_chain"));
        assert!(signal_names.contains(&"persistence_detected"));
    }

    // ─── Spec 025 — attack_subgraph_json tests ─────────────────────────

    #[test]
    fn subgraph_empty_center_returns_stable_shape() {
        let g = KnowledgeGraph::new();
        // u64::MAX cannot exist — simulate a missing centre.
        let missing: NodeId = u64::MAX;
        let out = g.attack_subgraph_json(missing, 3);
        assert_eq!(out["center"].as_u64(), Some(u64::MAX));
        assert_eq!(out["nodes"].as_array().unwrap().len(), 0);
        assert_eq!(out["edges"].as_array().unwrap().len(), 0);
        assert_eq!(out["truncated"].as_bool(), Some(false));
        assert_eq!(out["full_node_count"].as_u64(), Some(0));
    }

    #[test]
    fn subgraph_depth_zero_returns_only_center() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(1234, 1, "payload", 0, ts(0));
        let ip = g.ensure_ip("93.1.1.1", ts(0));
        g.add_edge(Edge::new(proc_id, ip, Relation::ConnectedTo, ts(1)));

        let out = g.attack_subgraph_json(proc_id, 0);
        let nodes = out["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["id"].as_u64(), Some(proc_id));
        assert_eq!(nodes[0]["type"], "Process");
        // depth=0: no edges followed
        assert_eq!(out["edges"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn subgraph_projects_known_node_types_with_typed_fields() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(1234, 1, "payload", 100, ts(0));
        let ip = g.ensure_ip("93.1.1.1", ts(0));
        let file = g.ensure_file("/etc/cron.d/backdoor");

        g.add_edge(Edge::new(proc_id, ip, Relation::ConnectedTo, ts(1)));
        g.add_edge(Edge::new(proc_id, file, Relation::Wrote, ts(2)));

        let out = g.attack_subgraph_json(proc_id, 2);
        let nodes = out["nodes"].as_array().unwrap();

        let proc_node = nodes
            .iter()
            .find(|n| n["type"] == "Process")
            .expect("process node present");
        assert_eq!(proc_node["pid"].as_u64(), Some(1234));
        assert_eq!(proc_node["comm"], "payload");
        assert_eq!(proc_node["uid"].as_u64(), Some(100));

        let ip_node = nodes
            .iter()
            .find(|n| n["type"] == "Ip")
            .expect("ip node present");
        assert_eq!(ip_node["addr"], "93.1.1.1");

        let file_node = nodes
            .iter()
            .find(|n| n["type"] == "File")
            .expect("file node present");
        assert_eq!(file_node["path"], "/etc/cron.d/backdoor");
    }

    #[test]
    fn subgraph_edges_carry_relation_and_timestamp() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(1234, 1, "payload", 0, ts(0));
        let ip = g.ensure_ip("93.1.1.1", ts(0));
        g.add_edge(Edge::new(proc_id, ip, Relation::ConnectedTo, ts(10)));

        let out = g.attack_subgraph_json(proc_id, 2);
        let edges = out["edges"].as_array().unwrap();
        assert!(!edges.is_empty());
        let edge = &edges[0];
        assert_eq!(edge["rel"], "ConnectedTo");
        assert!(edge["ts"].as_str().unwrap().starts_with("2023-"));
    }

    #[test]
    fn subgraph_ip_threat_intel_fields_present_when_populated() {
        let mut g = KnowledgeGraph::new();
        let ip = g.ensure_ip("93.1.1.1", ts(0));
        // Mutate the node after insertion to set threat-intel state.
        if let Some(Node::Ip {
            datasets,
            is_tor,
            risk_score,
            ..
        }) = g.nodes.get_mut(&ip)
        {
            datasets.push("spamhaus_drop".to_string());
            *is_tor = true;
            *risk_score = 95;
        }

        let out = g.attack_subgraph_json(ip, 0);
        let ip_node = &out["nodes"][0];
        assert_eq!(ip_node["is_tor"], true);
        assert_eq!(ip_node["risk_score"], 95);
        assert_eq!(ip_node["threat_intel"][0], "spamhaus_drop");
    }

    #[test]
    fn subgraph_truncates_when_neighbourhood_exceeds_cap() {
        let mut g = KnowledgeGraph::new();
        let center = g.ensure_process(1000, 1, "hub", 0, ts(0));
        // 60 distinct IP nodes all connected to the centre -> triggers the cap.
        for i in 0..60 {
            let ip = g.ensure_ip(&format!("10.0.0.{}", i), ts(0));
            g.add_edge(Edge::new(center, ip, Relation::ConnectedTo, ts(i)));
        }
        let out = g.attack_subgraph_json(center, 3);
        let nodes = out["nodes"].as_array().unwrap();
        assert_eq!(out["truncated"].as_bool(), Some(true));
        assert_eq!(nodes.len(), 40);
        assert_eq!(
            nodes[0]["id"].as_u64(),
            Some(center),
            "centre must survive truncation"
        );
        // No dangling edges — every edge endpoint exists in the node list.
        let kept: std::collections::HashSet<u64> =
            nodes.iter().map(|n| n["id"].as_u64().unwrap()).collect();
        for edge in out["edges"].as_array().unwrap() {
            assert!(kept.contains(&edge["from"].as_u64().unwrap()));
            assert!(kept.contains(&edge["to"].as_u64().unwrap()));
        }
    }

    #[test]
    fn subgraph_incident_projects_decision_and_severity() {
        use innerwarden_core::{entities::EntityRef, event::Severity, incident::Incident};
        let mut g = KnowledgeGraph::new();
        let incident = Incident {
            ts: ts(0),
            host: "test".into(),
            incident_id: "ssh_bruteforce:93.1.1.1:test".into(),
            severity: Severity::High,
            title: "SSH brute force".into(),
            summary: "many failed logins".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("93.1.1.1")],
        };
        g.ingest_incident(&incident);
        let inc = g.find_by_incident(&incident.incident_id).unwrap();
        g.ingest_decision(
            &incident.incident_id,
            "block_ip",
            Some("93.1.1.1"),
            0.95,
            "auto-rule",
            true,
            ts(0),
        );

        let out = g.attack_subgraph_json(inc, 2);
        let inc_node = out["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["type"] == "Incident")
            .expect("incident node present");
        assert_eq!(inc_node["severity"], "High");
        assert_eq!(inc_node["detector"], "ssh_bruteforce");
        assert_eq!(inc_node["decision"], "block_ip");
        assert_eq!(inc_node["auto_executed"], true);
    }

    #[test]
    fn subgraph_full_node_count_reflects_pre_truncation_size() {
        let mut g = KnowledgeGraph::new();
        let center = g.ensure_process(1000, 1, "hub", 0, ts(0));
        for i in 0..5 {
            let ip = g.ensure_ip(&format!("10.0.0.{}", i), ts(0));
            g.add_edge(Edge::new(center, ip, Relation::ConnectedTo, ts(i)));
        }
        let out = g.attack_subgraph_json(center, 3);
        // 1 centre + 5 IPs = 6
        assert_eq!(out["full_node_count"].as_u64(), Some(6));
        assert_eq!(out["truncated"].as_bool(), Some(false));
    }
}
