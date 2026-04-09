use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet, VecDeque};

use super::types::*;

/// In-memory knowledge graph with O(1) indexes for all critical queries.
pub struct KnowledgeGraph {
    // ── Storage ──
    pub(crate) nodes: HashMap<NodeId, Node>,
    pub(crate) edges: Vec<Edge>,

    // ── Dedup indexes (entity → NodeId) ──
    pub(crate) pid_index: HashMap<u32, NodeId>,
    pub(crate) ip_index: HashMap<String, NodeId>,
    pub(crate) file_index: HashMap<String, NodeId>,
    pub(crate) user_index: HashMap<String, NodeId>,
    pub(crate) domain_index: HashMap<String, NodeId>,
    pub(crate) port_index: HashMap<(u16, String), NodeId>,
    pub(crate) container_index: HashMap<String, NodeId>,
    pub(crate) device_index: HashMap<String, NodeId>, // "vendor:product:serial"
    pub(crate) incident_index: HashMap<String, NodeId>,
    pub(crate) campaign_index: HashMap<String, NodeId>,
    pub(crate) system_node: Option<NodeId>,

    // ── Adjacency lists (NodeId → edge indexes) ──
    pub(crate) outgoing: HashMap<NodeId, Vec<usize>>,
    pub(crate) incoming: HashMap<NodeId, Vec<usize>>,

    // ── Fast-access sets ──
    pub(crate) threat_intel_nodes: HashSet<NodeId>,

    // ── Counters ──
    pub(crate) next_id: NodeId,
    pub(crate) memory_estimate: usize,
    pub max_memory: usize,
    pub created_at: DateTime<Utc>,
}

impl KnowledgeGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            pid_index: HashMap::new(),
            ip_index: HashMap::new(),
            file_index: HashMap::new(),
            user_index: HashMap::new(),
            domain_index: HashMap::new(),
            port_index: HashMap::new(),
            container_index: HashMap::new(),
            device_index: HashMap::new(),
            incident_index: HashMap::new(),
            campaign_index: HashMap::new(),
            system_node: None,
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
            threat_intel_nodes: HashSet::new(),
            next_id: 1,
            memory_estimate: 0,
            max_memory: 50 * 1024 * 1024, // 50 MB
            created_at: Utc::now(),
        }
    }

    // ── Node CRUD ───────────────────────────────────────────────────────

    /// Add a node, returning its ID. If a node with the same dedup key exists,
    /// returns the existing ID without creating a duplicate.
    pub fn add_node(&mut self, node: Node) -> NodeId {
        // Check dedup
        if let Some(existing) = self.find_existing(&node) {
            return existing;
        }

        let id = self.next_id;
        self.next_id += 1;

        self.index_node(id, &node);
        self.memory_estimate += Self::estimate_node_size(&node);
        self.nodes.insert(id, node);

        id
    }

    /// Add or update: if the dedup key exists, update the node in-place and return its ID.
    /// Otherwise create a new node.
    pub fn upsert_node(&mut self, node: Node) -> NodeId {
        if let Some(existing_id) = self.find_existing(&node) {
            // Update the existing node with new data
            if let Some(existing) = self.nodes.get_mut(&existing_id) {
                Self::merge_node(existing, &node);
            }
            // Update threat intel index if needed
            if let Node::Ip { ref datasets, .. } = node {
                if !datasets.is_empty() {
                    self.threat_intel_nodes.insert(existing_id);
                }
            }
            existing_id
        } else {
            self.add_node(node)
        }
    }

    pub fn get_node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(&id)
    }

    pub fn get_node_mut(&mut self, id: NodeId) -> Option<&mut Node> {
        self.nodes.get_mut(&id)
    }

    pub fn remove_node(&mut self, id: NodeId) {
        if let Some(node) = self.nodes.remove(&id) {
            self.memory_estimate = self.memory_estimate.saturating_sub(Self::estimate_node_size(&node));
            self.deindex_node(id, &node);
            self.threat_intel_nodes.remove(&id);

            // Remove edges connected to this node (mark as tombstone by setting from=to=0)
            let edge_idxs: Vec<usize> = self
                .outgoing
                .remove(&id)
                .unwrap_or_default()
                .into_iter()
                .chain(self.incoming.remove(&id).unwrap_or_default())
                .collect();

            for idx in edge_idxs {
                if idx < self.edges.len() {
                    let edge = &self.edges[idx];
                    let other = if edge.from == id { edge.to } else { edge.from };
                    // Remove from the other node's adjacency
                    if let Some(adj) = self.outgoing.get_mut(&other) {
                        adj.retain(|&i| i != idx);
                    }
                    if let Some(adj) = self.incoming.get_mut(&other) {
                        adj.retain(|&i| i != idx);
                    }
                }
            }
        }
    }

    // ── Edge CRUD ───────────────────────────────────────────────────────

    /// Add an edge. Edges are never deduplicated — each represents a discrete event.
    pub fn add_edge(&mut self, edge: Edge) -> usize {
        let idx = self.edges.len();
        self.outgoing.entry(edge.from).or_default().push(idx);
        self.incoming.entry(edge.to).or_default().push(idx);
        self.memory_estimate += Self::estimate_edge_size(&edge);
        self.edges.push(edge);
        idx
    }

    pub fn get_edge(&self, idx: usize) -> Option<&Edge> {
        self.edges.get(idx)
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    // ── Lookup by dedup key ─────────────────────────────────────────────

    pub fn find_by_pid(&self, pid: u32) -> Option<NodeId> {
        self.pid_index.get(&pid).copied()
    }

    pub fn find_by_ip(&self, addr: &str) -> Option<NodeId> {
        self.ip_index.get(addr).copied()
    }

    pub fn find_by_path(&self, path: &str) -> Option<NodeId> {
        self.file_index.get(path).copied()
    }

    pub fn find_by_user(&self, name: &str) -> Option<NodeId> {
        self.user_index.get(name).copied()
    }

    pub fn find_by_domain(&self, name: &str) -> Option<NodeId> {
        self.domain_index.get(name).copied()
    }

    pub fn find_by_port(&self, number: u16, protocol: &str) -> Option<NodeId> {
        self.port_index.get(&(number, protocol.to_string())).copied()
    }

    pub fn find_by_container(&self, id: &str) -> Option<NodeId> {
        self.container_index.get(id).copied()
    }

    pub fn find_by_incident(&self, incident_id: &str) -> Option<NodeId> {
        self.incident_index.get(incident_id).copied()
    }

    pub fn find_by_campaign(&self, campaign_id: &str) -> Option<NodeId> {
        self.campaign_index.get(campaign_id).copied()
    }

    pub fn system_node(&self) -> Option<NodeId> {
        self.system_node
    }

    // ── Ensure helpers (find or create) ─────────────────────────────────

    pub fn ensure_process(
        &mut self,
        pid: u32,
        ppid: u32,
        comm: &str,
        uid: u32,
        ts: DateTime<Utc>,
    ) -> NodeId {
        if let Some(id) = self.find_by_pid(pid) {
            return id;
        }
        self.add_node(Node::Process {
            pid,
            ppid,
            comm: comm.to_string(),
            exe: None,
            uid,
            container_id: None,
            start_ts: ts,
            exit_ts: None,
        })
    }

    pub fn ensure_ip(&mut self, addr: &str, ts: DateTime<Utc>) -> NodeId {
        if let Some(id) = self.find_by_ip(addr) {
            // Update last_seen
            if let Some(Node::Ip { last_seen, .. }) = self.nodes.get_mut(&id) {
                *last_seen = ts;
            }
            return id;
        }
        self.add_node(Node::Ip {
            addr: addr.to_string(),
            is_internal: is_internal_ip(addr),
            datasets: Vec::new(),
            risk_score: 0,
            is_tor: false,
            first_seen: ts,
            last_seen: ts,
        })
    }

    pub fn ensure_file(&mut self, path: &str) -> NodeId {
        if let Some(id) = self.find_by_path(path) {
            return id;
        }
        self.add_node(Node::File {
            path: path.to_string(),
            sha256: None,
            size: None,
            entropy: None,
            is_sensitive: is_sensitive_path(path),
            yara_matches: Vec::new(),
        })
    }

    pub fn ensure_user(&mut self, name: &str) -> NodeId {
        if let Some(id) = self.find_by_user(name) {
            return id;
        }
        self.add_node(Node::User {
            name: name.to_string(),
            uid: None,
        })
    }

    pub fn ensure_domain(&mut self, name: &str) -> NodeId {
        if let Some(id) = self.find_by_domain(name) {
            return id;
        }
        self.add_node(Node::Domain {
            name: name.to_string(),
            datasets: Vec::new(),
            is_dga: None,
            entropy: None,
        })
    }

    pub fn ensure_port(&mut self, number: u16, protocol: &str) -> NodeId {
        if let Some(id) = self.find_by_port(number, protocol) {
            return id;
        }
        self.add_node(Node::Port {
            number,
            protocol: protocol.to_string(),
        })
    }

    pub fn ensure_container(&mut self, container_id: &str) -> NodeId {
        if let Some(id) = self.find_by_container(container_id) {
            return id;
        }
        self.add_node(Node::Container {
            container_id: container_id.to_string(),
            name: None,
            image: None,
            start_ts: None,
            exit_ts: None,
            oom_killed: false,
        })
    }

    pub fn ensure_system(&mut self, hostname: &str) -> NodeId {
        if let Some(id) = self.system_node {
            return id;
        }
        let id = self.add_node(Node::System {
            hostname: hostname.to_string(),
            sysctl_params: HashMap::new(),
        });
        self.system_node = Some(id);
        id
    }

    // ── Traversal primitives ────────────────────────────────────────────

    pub fn outgoing_edges(&self, node: NodeId) -> Vec<&Edge> {
        self.outgoing
            .get(&node)
            .map(|idxs| idxs.iter().filter_map(|&i| self.edges.get(i)).collect())
            .unwrap_or_default()
    }

    pub fn incoming_edges(&self, node: NodeId) -> Vec<&Edge> {
        self.incoming
            .get(&node)
            .map(|idxs| idxs.iter().filter_map(|&i| self.edges.get(i)).collect())
            .unwrap_or_default()
    }

    /// All edges (in + out) for a node, sorted by timestamp.
    pub fn all_edges(&self, node: NodeId) -> Vec<&Edge> {
        let mut edges: Vec<&Edge> = self
            .outgoing_edges(node)
            .into_iter()
            .chain(self.incoming_edges(node))
            .collect();
        edges.sort_by_key(|e| e.ts);
        edges.dedup_by(|a, b| std::ptr::eq(*a, *b));
        edges
    }

    /// Find all nodes of a given type.
    pub fn nodes_of_type(&self, nt: NodeType) -> Vec<NodeId> {
        self.nodes
            .iter()
            .filter(|(_, n)| n.node_type() == nt)
            .map(|(&id, _)| id)
            .collect()
    }

    /// BFS neighborhood: subgraph within `depth` hops of `start`.
    pub fn neighborhood(&self, start: NodeId, depth: usize) -> SubGraph {
        let mut sub = SubGraph::default();
        let mut visited: HashSet<NodeId> = HashSet::new();
        let mut queue: VecDeque<(NodeId, usize)> = VecDeque::new();

        if let Some(node) = self.nodes.get(&start) {
            visited.insert(start);
            sub.nodes.insert(start, node.clone());
            queue.push_back((start, 0));
        }

        while let Some((current, d)) = queue.pop_front() {
            if d >= depth {
                continue;
            }

            // Outgoing
            for edge in self.outgoing_edges(current) {
                sub.edges.push(edge.clone());
                if !visited.contains(&edge.to) {
                    visited.insert(edge.to);
                    if let Some(n) = self.nodes.get(&edge.to) {
                        sub.nodes.insert(edge.to, n.clone());
                    }
                    queue.push_back((edge.to, d + 1));
                }
            }

            // Incoming
            for edge in self.incoming_edges(current) {
                sub.edges.push(edge.clone());
                if !visited.contains(&edge.from) {
                    visited.insert(edge.from);
                    if let Some(n) = self.nodes.get(&edge.from) {
                        sub.nodes.insert(edge.from, n.clone());
                    }
                    queue.push_back((edge.from, d + 1));
                }
            }
        }

        sub
    }

    /// BFS shortest path between two nodes. Returns edge chain or None.
    pub fn path_between(
        &self,
        from: NodeId,
        to: NodeId,
        max_depth: usize,
    ) -> Option<Vec<Edge>> {
        if from == to {
            return Some(Vec::new());
        }

        let mut visited: HashSet<NodeId> = HashSet::new();
        // (current_node, path_of_edge_indexes)
        let mut queue: VecDeque<(NodeId, Vec<usize>)> = VecDeque::new();

        visited.insert(from);
        queue.push_back((from, Vec::new()));

        while let Some((current, path)) = queue.pop_front() {
            if path.len() >= max_depth {
                continue;
            }

            // Outgoing edges
            if let Some(idxs) = self.outgoing.get(&current) {
                for &idx in idxs {
                    if let Some(edge) = self.edges.get(idx) {
                        if edge.to == to {
                            let mut result: Vec<Edge> =
                                path.iter().filter_map(|&i| self.edges.get(i).cloned()).collect();
                            result.push(edge.clone());
                            return Some(result);
                        }
                        if !visited.contains(&edge.to) {
                            visited.insert(edge.to);
                            let mut new_path = path.clone();
                            new_path.push(idx);
                            queue.push_back((edge.to, new_path));
                        }
                    }
                }
            }

            // Incoming edges (bidirectional search)
            if let Some(idxs) = self.incoming.get(&current) {
                for &idx in idxs {
                    if let Some(edge) = self.edges.get(idx) {
                        if edge.from == to {
                            let mut result: Vec<Edge> =
                                path.iter().filter_map(|&i| self.edges.get(i).cloned()).collect();
                            result.push(edge.clone());
                            return Some(result);
                        }
                        if !visited.contains(&edge.from) {
                            visited.insert(edge.from);
                            let mut new_path = path.clone();
                            new_path.push(idx);
                            queue.push_back((edge.from, new_path));
                        }
                    }
                }
            }
        }

        None
    }

    /// Process tree: all descendants via SpawnedBy edges (reversed).
    pub fn descendants(&self, pid: u32) -> Vec<NodeId> {
        let start = match self.find_by_pid(pid) {
            Some(id) => id,
            None => return Vec::new(),
        };

        let mut result = Vec::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back(start);
        visited.insert(start);

        while let Some(current) = queue.pop_front() {
            // Children are nodes that have SpawnedBy edge pointing TO current
            if let Some(idxs) = self.incoming.get(&current) {
                for &idx in idxs {
                    if let Some(edge) = self.edges.get(idx) {
                        if edge.relation == Relation::SpawnedBy && !visited.contains(&edge.from) {
                            visited.insert(edge.from);
                            result.push(edge.from);
                            queue.push_back(edge.from);
                        }
                    }
                }
            }
        }

        result
    }

    /// Process tree: ancestors via SpawnedBy edges (forward).
    pub fn ancestors(&self, pid: u32) -> Vec<NodeId> {
        let start = match self.find_by_pid(pid) {
            Some(id) => id,
            None => return Vec::new(),
        };

        let mut result = Vec::new();
        let mut current = start;
        let mut visited = HashSet::new();
        visited.insert(current);

        loop {
            // Parent is the node this process has a SpawnedBy edge TO
            let parent = self.outgoing.get(&current).and_then(|idxs| {
                idxs.iter().find_map(|&idx| {
                    self.edges.get(idx).and_then(|e| {
                        if e.relation == Relation::SpawnedBy {
                            Some(e.to)
                        } else {
                            None
                        }
                    })
                })
            });

            match parent {
                Some(p) if !visited.contains(&p) => {
                    visited.insert(p);
                    result.push(p);
                    current = p;
                }
                _ => break,
            }
        }

        result
    }

    /// Timeline: all edges of a node sorted by timestamp, excluding snapshots.
    pub fn timeline(&self, node: NodeId) -> Vec<&Edge> {
        let mut edges = self.all_edges(node);
        edges.retain(|e| !e.is_snapshot());
        edges
    }

    /// Threat intel hits: processes connected to IPs with non-empty datasets.
    pub fn threat_intel_hits(&self) -> Vec<(NodeId, NodeId, String)> {
        let mut hits = Vec::new();
        for &ip_id in &self.threat_intel_nodes {
            let datasets = match self.nodes.get(&ip_id) {
                Some(Node::Ip { datasets, .. }) if !datasets.is_empty() => datasets.clone(),
                _ => continue,
            };

            // Find processes connected to this IP
            if let Some(idxs) = self.incoming.get(&ip_id) {
                for &idx in idxs {
                    if let Some(edge) = self.edges.get(idx) {
                        if edge.relation == Relation::ConnectedTo {
                            for ds in &datasets {
                                hits.push((edge.from, ip_id, ds.clone()));
                            }
                        }
                    }
                }
            }
        }
        hits
    }

    /// Nodes matching a type and predicate.
    pub fn find_nodes(&self, node_type: NodeType, predicate: impl Fn(&Node) -> bool) -> Vec<NodeId> {
        self.nodes
            .iter()
            .filter(|(_, n)| n.node_type() == node_type && predicate(n))
            .map(|(&id, _)| id)
            .collect()
    }

    // ── TTL + Memory management ─────────────────────────────────────────

    /// Remove expired nodes based on TTL rules.
    pub fn cleanup_expired(&mut self, now: DateTime<Utc>) {
        let expired: Vec<NodeId> = self
            .nodes
            .iter()
            .filter(|(id, node)| self.is_expired(node, **id, now))
            .map(|(&id, _)| id)
            .collect();

        for id in expired {
            self.remove_node(id);
        }
    }

    /// If memory exceeds max, prune oldest nodes by last edge timestamp (LRU).
    pub fn enforce_memory_limit(&mut self) {
        if self.memory_estimate <= self.max_memory {
            return;
        }

        // Collect (node_id, last_edge_ts) sorted oldest first
        let mut candidates: Vec<(NodeId, DateTime<Utc>)> = self
            .nodes
            .keys()
            .filter(|&&id| {
                // Never prune System or permanent nodes
                !matches!(self.nodes.get(&id), Some(Node::System { .. }))
            })
            .map(|&id| {
                let last_ts = self
                    .all_edges(id)
                    .last()
                    .map(|e| e.ts)
                    .unwrap_or(self.created_at);
                (id, last_ts)
            })
            .collect();

        candidates.sort_by_key(|(_, ts)| *ts);

        for (id, _) in candidates {
            if self.memory_estimate <= self.max_memory {
                break;
            }
            self.remove_node(id);
        }
    }

    /// Current estimated memory usage in bytes.
    pub fn memory_estimate(&self) -> usize {
        self.memory_estimate
    }

    // ── Metrics ─────────────────────────────────────────────────────────

    pub fn metrics(&self) -> GraphMetrics {
        let mut nodes_by_type: HashMap<String, usize> = HashMap::new();
        for node in self.nodes.values() {
            *nodes_by_type
                .entry(format!("{:?}", node.node_type()))
                .or_default() += 1;
        }

        let total_degree: usize = self.nodes.keys().map(|id| self.all_edges(*id).len()).sum();
        let avg_degree = if self.nodes.is_empty() {
            0.0
        } else {
            total_degree as f32 / self.nodes.len() as f32
        };

        GraphMetrics {
            node_count: self.nodes.len(),
            edge_count: self.edges.len(),
            memory_bytes: self.memory_estimate,
            nodes_by_type,
            avg_degree,
            threat_intel_nodes: self.threat_intel_nodes.len(),
            incident_nodes: self.incident_index.len(),
        }
    }

    // ── Serialization support ───────────────────────────────────────────

    pub fn nodes(&self) -> &HashMap<NodeId, Node> {
        &self.nodes
    }

    pub fn edges_slice(&self) -> &[Edge] {
        &self.edges
    }

    // ── Internal helpers ────────────────────────────────────────────────

    fn find_existing(&self, node: &Node) -> Option<NodeId> {
        match node {
            Node::Process { pid, .. } => self.pid_index.get(pid).copied(),
            Node::Ip { addr, .. } => self.ip_index.get(addr).copied(),
            Node::File { path, .. } => self.file_index.get(path).copied(),
            Node::User { name, .. } => self.user_index.get(name).copied(),
            Node::Domain { name, .. } => self.domain_index.get(name).copied(),
            Node::Port { number, protocol, .. } => {
                self.port_index.get(&(*number, protocol.clone())).copied()
            }
            Node::Container { container_id, .. } => self.container_index.get(container_id).copied(),
            Node::Device { vendor, product, serial, .. } => {
                let key = device_key(vendor, product, serial.as_deref());
                self.device_index.get(&key).copied()
            }
            Node::System { .. } => self.system_node,
            Node::Incident { incident_id, .. } => self.incident_index.get(incident_id).copied(),
            Node::Campaign { campaign_id, .. } => self.campaign_index.get(campaign_id).copied(),
        }
    }

    pub(crate) fn index_node(&mut self, id: NodeId, node: &Node) {
        match node {
            Node::Process { pid, .. } => {
                self.pid_index.insert(*pid, id);
            }
            Node::Ip { addr, datasets, .. } => {
                self.ip_index.insert(addr.clone(), id);
                if !datasets.is_empty() {
                    self.threat_intel_nodes.insert(id);
                }
            }
            Node::File { path, .. } => {
                self.file_index.insert(path.clone(), id);
            }
            Node::User { name, .. } => {
                self.user_index.insert(name.clone(), id);
            }
            Node::Domain { name, .. } => {
                self.domain_index.insert(name.clone(), id);
            }
            Node::Port { number, protocol, .. } => {
                self.port_index.insert((*number, protocol.clone()), id);
            }
            Node::Container { container_id, .. } => {
                self.container_index.insert(container_id.clone(), id);
            }
            Node::Device { vendor, product, serial, .. } => {
                let key = device_key(vendor, product, serial.as_deref());
                self.device_index.insert(key, id);
            }
            Node::System { .. } => {
                self.system_node = Some(id);
            }
            Node::Incident { incident_id, .. } => {
                self.incident_index.insert(incident_id.clone(), id);
            }
            Node::Campaign { campaign_id, .. } => {
                self.campaign_index.insert(campaign_id.clone(), id);
            }
        }
    }

    fn deindex_node(&mut self, id: NodeId, node: &Node) {
        match node {
            Node::Process { pid, .. } => {
                self.pid_index.remove(pid);
            }
            Node::Ip { addr, .. } => {
                self.ip_index.remove(addr);
            }
            Node::File { path, .. } => {
                self.file_index.remove(path);
            }
            Node::User { name, .. } => {
                self.user_index.remove(name);
            }
            Node::Domain { name, .. } => {
                self.domain_index.remove(name);
            }
            Node::Port { number, protocol, .. } => {
                self.port_index.remove(&(*number, protocol.clone()));
            }
            Node::Container { container_id, .. } => {
                self.container_index.remove(container_id);
            }
            Node::Device { vendor, product, serial, .. } => {
                let key = device_key(vendor, product, serial.as_deref());
                self.device_index.remove(&key);
            }
            Node::System { .. } => {
                if self.system_node == Some(id) {
                    self.system_node = None;
                }
            }
            Node::Incident { incident_id, .. } => {
                self.incident_index.remove(incident_id);
            }
            Node::Campaign { campaign_id, .. } => {
                self.campaign_index.remove(campaign_id);
            }
        }
    }

    fn merge_node(existing: &mut Node, incoming: &Node) {
        match (existing, incoming) {
            (
                Node::Process { exe, exit_ts, container_id, .. },
                Node::Process {
                    exe: new_exe,
                    exit_ts: new_exit,
                    container_id: new_cid,
                    ..
                },
            ) => {
                if exe.is_none() && new_exe.is_some() {
                    *exe = new_exe.clone();
                }
                if exit_ts.is_none() && new_exit.is_some() {
                    *exit_ts = *new_exit;
                }
                if container_id.is_none() && new_cid.is_some() {
                    *container_id = new_cid.clone();
                }
            }
            (
                Node::Ip { last_seen, datasets, risk_score, is_tor, .. },
                Node::Ip {
                    last_seen: new_last,
                    datasets: new_ds,
                    risk_score: new_rs,
                    is_tor: new_tor,
                    ..
                },
            ) => {
                if *new_last > *last_seen {
                    *last_seen = *new_last;
                }
                for ds in new_ds {
                    if !datasets.contains(ds) {
                        datasets.push(ds.clone());
                    }
                }
                if *new_rs > *risk_score {
                    *risk_score = *new_rs;
                }
                if *new_tor {
                    *is_tor = true;
                }
            }
            (
                Node::File { sha256, size, entropy, yara_matches, .. },
                Node::File {
                    sha256: new_sha,
                    size: new_size,
                    entropy: new_ent,
                    yara_matches: new_yara,
                    ..
                },
            ) => {
                if sha256.is_none() && new_sha.is_some() {
                    *sha256 = new_sha.clone();
                }
                if size.is_none() && new_size.is_some() {
                    *size = *new_size;
                }
                if entropy.is_none() && new_ent.is_some() {
                    *entropy = *new_ent;
                }
                for y in new_yara {
                    if !yara_matches.contains(y) {
                        yara_matches.push(y.clone());
                    }
                }
            }
            (
                Node::Container { name, image, start_ts, exit_ts, oom_killed, .. },
                Node::Container {
                    name: nn,
                    image: ni,
                    start_ts: ns,
                    exit_ts: ne,
                    oom_killed: no,
                    ..
                },
            ) => {
                if name.is_none() && nn.is_some() {
                    *name = nn.clone();
                }
                if image.is_none() && ni.is_some() {
                    *image = ni.clone();
                }
                if start_ts.is_none() && ns.is_some() {
                    *start_ts = *ns;
                }
                if exit_ts.is_none() && ne.is_some() {
                    *exit_ts = *ne;
                }
                if *no {
                    *oom_killed = true;
                }
            }
            (
                Node::Domain { datasets, is_dga, entropy, .. },
                Node::Domain {
                    datasets: nd,
                    is_dga: ndga,
                    entropy: ne,
                    ..
                },
            ) => {
                for d in nd {
                    if !datasets.contains(d) {
                        datasets.push(d.clone());
                    }
                }
                if is_dga.is_none() && ndga.is_some() {
                    *is_dga = *ndga;
                }
                if entropy.is_none() && ne.is_some() {
                    *entropy = *ne;
                }
            }
            _ => {}
        }
    }

    fn is_expired(&self, node: &Node, node_id: NodeId, now: DateTime<Utc>) -> bool {
        match node {
            Node::Process { exit_ts: Some(exit), .. } => {
                now - *exit > Duration::hours(1)
            }
            Node::Process { exit_ts: None, .. } => {
                // Check last edge
                let last = self.all_edges(node_id).last().map(|e| e.ts);
                match last {
                    Some(ts) => now - ts > Duration::hours(24),
                    None => now - self.created_at > Duration::hours(24),
                }
            }
            Node::Ip { datasets, risk_score, last_seen, .. } => {
                if !datasets.is_empty() || *risk_score > 0 {
                    return false; // Permanent if threat intel
                }
                now - *last_seen > Duration::hours(24)
            }
            Node::File { is_sensitive, .. } => {
                if *is_sensitive {
                    return false; // Permanent
                }
                let last = self.all_edges(node_id).last().map(|e| e.ts);
                match last {
                    Some(ts) => now - ts > Duration::hours(24),
                    None => false,
                }
            }
            Node::User { .. } | Node::Device { .. } | Node::System { .. } => false, // Permanent
            Node::Domain { datasets, .. } => {
                if !datasets.is_empty() {
                    return false;
                }
                let last = self.all_edges(node_id).last().map(|e| e.ts);
                match last {
                    Some(ts) => now - ts > Duration::hours(24),
                    None => false,
                }
            }
            Node::Port { .. } => {
                let last = self.all_edges(node_id).last().map(|e| e.ts);
                match last {
                    Some(ts) => now - ts > Duration::hours(24),
                    None => false,
                }
            }
            Node::Container { exit_ts: Some(exit), .. } => {
                now - *exit > Duration::hours(1)
            }
            Node::Container { .. } => false, // Running
            Node::Incident { decision, ts, .. } => {
                if decision.as_deref() == Some("block") {
                    return false; // Permanent
                }
                now - *ts > Duration::days(7)
            }
            Node::Campaign { last_seen, .. } => now - *last_seen > Duration::days(30),
        }
    }

    pub(crate) fn estimate_node_size(node: &Node) -> usize {
        match node {
            Node::Process { .. } => 250,
            Node::Ip { .. } => 200,
            Node::File { .. } => 200,
            Node::User { .. } => 100,
            Node::Domain { .. } => 150,
            Node::Port { .. } => 50,
            Node::Container { .. } => 200,
            Node::Device { .. } => 150,
            Node::System { .. } => 500,
            Node::Incident { .. } => 300,
            Node::Campaign { .. } => 200,
        }
    }

    pub(crate) fn estimate_edge_size(edge: &Edge) -> usize {
        120 + edge.properties.len() * 40
    }
}

// ── Utility functions ───────────────────────────────────────────────────

fn is_internal_ip(addr: &str) -> bool {
    addr.starts_with("10.")
        || addr.starts_with("172.16.")
        || addr.starts_with("172.17.")
        || addr.starts_with("172.18.")
        || addr.starts_with("172.19.")
        || addr.starts_with("172.2")
        || addr.starts_with("172.30.")
        || addr.starts_with("172.31.")
        || addr.starts_with("192.168.")
        || addr == "127.0.0.1"
        || addr == "::1"
}

fn is_sensitive_path(path: &str) -> bool {
    let sensitive = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/",
        "authorized_keys",
        "/etc/cron",
        "/etc/systemd/",
        "/usr/lib/systemd/",
        "/var/spool/cron",
        ".ssh/id_",
        ".ssh/config",
        ".bashrc",
        ".bash_profile",
        ".profile",
    ];
    sensitive.iter().any(|s| path.contains(s))
}

fn device_key(vendor: &str, product: &str, serial: Option<&str>) -> String {
    format!("{}:{}:{}", vendor, product, serial.unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1700000000 + secs, 0).unwrap()
    }

    #[test]
    fn test_add_node_dedup() {
        let mut g = KnowledgeGraph::new();
        let id1 = g.ensure_process(1234, 1, "bash", 0, ts(0));
        let id2 = g.ensure_process(1234, 1, "bash", 0, ts(1));
        assert_eq!(id1, id2);
        assert_eq!(g.node_count(), 1);
    }

    #[test]
    fn test_add_edge_no_dedup() {
        let mut g = KnowledgeGraph::new();
        let proc_id = g.ensure_process(1, 0, "bash", 0, ts(0));
        let ip_id = g.ensure_ip("1.2.3.4", ts(0));
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, ts(1)));
        g.add_edge(Edge::new(proc_id, ip_id, Relation::ConnectedTo, ts(2)));
        assert_eq!(g.edge_count(), 2);
    }

    #[test]
    fn test_find_by_index() {
        let mut g = KnowledgeGraph::new();
        g.ensure_process(42, 1, "wget", 0, ts(0));
        g.ensure_ip("10.0.0.1", ts(0));
        g.ensure_file("/etc/passwd");
        g.ensure_user("root");
        g.ensure_domain("evil.com");
        g.ensure_port(443, "tcp");

        assert!(g.find_by_pid(42).is_some());
        assert!(g.find_by_ip("10.0.0.1").is_some());
        assert!(g.find_by_path("/etc/passwd").is_some());
        assert!(g.find_by_user("root").is_some());
        assert!(g.find_by_domain("evil.com").is_some());
        assert!(g.find_by_port(443, "tcp").is_some());
        assert!(g.find_by_pid(999).is_none());
    }

    #[test]
    fn test_sensitive_file() {
        let mut g = KnowledgeGraph::new();
        let id = g.ensure_file("/etc/shadow");
        assert!(g.get_node(id).unwrap().is_sensitive_file());

        let id2 = g.ensure_file("/tmp/foo.txt");
        assert!(!g.get_node(id2).unwrap().is_sensitive_file());
    }

    #[test]
    fn test_internal_ip() {
        let mut g = KnowledgeGraph::new();
        let id = g.ensure_ip("192.168.1.1", ts(0));
        match g.get_node(id) {
            Some(Node::Ip { is_internal, .. }) => assert!(is_internal),
            _ => panic!("expected Ip node"),
        }
        let id2 = g.ensure_ip("8.8.8.8", ts(0));
        match g.get_node(id2) {
            Some(Node::Ip { is_internal, .. }) => assert!(!is_internal),
            _ => panic!("expected Ip node"),
        }
    }

    #[test]
    fn test_remove_node() {
        let mut g = KnowledgeGraph::new();
        let id = g.ensure_ip("1.2.3.4", ts(0));
        assert_eq!(g.node_count(), 1);
        g.remove_node(id);
        assert_eq!(g.node_count(), 0);
        assert!(g.find_by_ip("1.2.3.4").is_none());
    }

    #[test]
    fn test_descendants_and_ancestors() {
        let mut g = KnowledgeGraph::new();
        let sshd = g.ensure_process(800, 1, "sshd", 0, ts(0));
        let bash = g.ensure_process(1234, 800, "bash", 0, ts(1));
        let wget = g.ensure_process(1235, 1234, "wget", 0, ts(2));
        let payload = g.ensure_process(1236, 1234, "payload", 0, ts(3));

        g.add_edge(Edge::new(bash, sshd, Relation::SpawnedBy, ts(1)));
        g.add_edge(Edge::new(wget, bash, Relation::SpawnedBy, ts(2)));
        g.add_edge(Edge::new(payload, bash, Relation::SpawnedBy, ts(3)));

        let desc = g.descendants(800);
        assert_eq!(desc.len(), 3); // bash, wget, payload

        let anc = g.ancestors(1236);
        assert_eq!(anc.len(), 2); // bash, sshd
        assert_eq!(anc[0], bash);
        assert_eq!(anc[1], sshd);
    }

    #[test]
    fn test_path_between() {
        let mut g = KnowledgeGraph::new();
        let user = g.ensure_user("root");
        let ip1 = g.ensure_ip("185.1.1.1", ts(0));
        let proc1 = g.ensure_process(1234, 1, "bash", 0, ts(1));
        let ip2 = g.ensure_ip("93.1.1.1", ts(2));

        g.add_edge(Edge::new(user, ip1, Relation::LoggedInFrom, ts(0)));
        g.add_edge(Edge::new(proc1, user, Relation::RunAs, ts(1)));
        g.add_edge(Edge::new(proc1, ip2, Relation::ConnectedTo, ts(2)));

        let path = g.path_between(ip1, ip2, 5);
        assert!(path.is_some());
        assert!(path.unwrap().len() >= 2);
    }

    #[test]
    fn test_neighborhood() {
        let mut g = KnowledgeGraph::new();
        let proc1 = g.ensure_process(1, 0, "bash", 0, ts(0));
        let ip = g.ensure_ip("1.2.3.4", ts(0));
        let file = g.ensure_file("/tmp/x");
        g.add_edge(Edge::new(proc1, ip, Relation::ConnectedTo, ts(1)));
        g.add_edge(Edge::new(proc1, file, Relation::Wrote, ts(2)));

        let sub = g.neighborhood(proc1, 1);
        assert_eq!(sub.nodes.len(), 3);
        assert_eq!(sub.edges.len(), 2);
    }

    #[test]
    fn test_timeline() {
        let mut g = KnowledgeGraph::new();
        let proc1 = g.ensure_process(1, 0, "bash", 0, ts(0));
        let ip = g.ensure_ip("1.2.3.4", ts(0));
        let file = g.ensure_file("/tmp/x");

        g.add_edge(Edge::new(proc1, file, Relation::Wrote, ts(3)));
        g.add_edge(Edge::new(proc1, ip, Relation::ConnectedTo, ts(1)));
        g.add_edge(Edge::new(proc1, file, Relation::Read, ts(2)));

        let tl = g.timeline(proc1);
        assert_eq!(tl.len(), 3);
        assert!(tl[0].ts <= tl[1].ts);
        assert!(tl[1].ts <= tl[2].ts);
    }

    #[test]
    fn test_threat_intel_hits() {
        let mut g = KnowledgeGraph::new();
        let proc1 = g.ensure_process(1, 0, "wget", 0, ts(0));
        let ip = g.add_node(Node::Ip {
            addr: "93.1.1.1".into(),
            is_internal: false,
            datasets: vec!["sslbl".into()],
            risk_score: 80,
            is_tor: false,
            first_seen: ts(0),
            last_seen: ts(0),
        });
        g.add_edge(Edge::new(proc1, ip, Relation::ConnectedTo, ts(1)));

        let hits = g.threat_intel_hits();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].2, "sslbl");
    }

    #[test]
    fn test_system_singleton() {
        let mut g = KnowledgeGraph::new();
        let id1 = g.ensure_system("prod-01");
        let id2 = g.ensure_system("prod-01");
        assert_eq!(id1, id2);
        assert_eq!(g.node_count(), 1);
    }

    #[test]
    fn test_metrics() {
        let mut g = KnowledgeGraph::new();
        g.ensure_process(1, 0, "bash", 0, ts(0));
        g.ensure_ip("1.2.3.4", ts(0));
        let m = g.metrics();
        assert_eq!(m.node_count, 2);
        assert_eq!(m.edge_count, 0);
    }
}
