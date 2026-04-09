use chrono::{DateTime, Utc};

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
                match key.as_str() {
                    "port" | "signal" | "method" | "command" | "module_name" => {
                        let val_str = match val {
                            serde_json::Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        detail.push_str(&format!(" ({}={})", key, val_str));
                    }
                    "success" => {
                        if val == &serde_json::Value::Bool(false) {
                            detail.push_str(" (FAILED)");
                        }
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
        for (_, node) in &sub.nodes {
            if let Node::Ip { datasets, is_tor, risk_score, addr, .. } = node {
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
        for (_, node) in &sub.nodes {
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
        for (_, node) in &sub.nodes {
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
                    target_id.map_or(false, |tid| {
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

        // Process tree depth
        if let Some(Node::Process { pid, .. }) = self.get_node(center) {
            let ancestors = self.ancestors(*pid);
            if ancestors.len() >= 3 {
                let chain: Vec<String> = std::iter::once(center)
                    .chain(ancestors.iter().copied())
                    .filter_map(|id| self.get_node(id))
                    .map(|n| n.label())
                    .collect();
                lines.push(String::new());
                lines.push(format!(
                    "  Process chain: {}",
                    chain.join(" → ")
                ));
            }
        }

        lines.join("\n")
    }

    /// Analyze the impact of blocking an IP or killing a process.
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

    fn impact_block_ip(&self, ip: &str) -> String {
        let ip_id = match self.find_by_ip(ip) {
            Some(id) => id,
            None => return format!("IP {} not in graph — safe to block", ip),
        };

        // Find all processes connected to this IP
        let mut affected_processes = Vec::new();
        let mut production_impact = false;

        let production_comms = [
            "nginx", "apache", "httpd", "postgresql", "postgres", "mysql",
            "mysqld", "redis-server", "redis", "haproxy", "sshd", "mongod",
            "node", "java", "python3", "gunicorn", "uwsgi",
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
            pid, comm, children.len()
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
                && sub
                    .nodes
                    .get(&e.to)
                    .map_or(false, |n| n.is_sensitive_file())
        });
        if sensitive_access {
            signals.push(("sensitive_file_access".to_string(), 0.15));
        }

        // Persistence indicators
        let has_persistence = sub.edges.iter().any(|e| {
            e.relation == Relation::Wrote
                && sub.nodes.get(&e.to).map_or(false, |n| {
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
