use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

pub type NodeId = u64;

/// Property key type used in `Edge.properties`. Backed by an `Arc<str>`
/// served by `crate::knowledge_graph::intern::intern`, so repeated keys
/// across edges (the common case — "event_source", "event_kind",
/// "summary", "severity" recur on every event-derived edge) share a
/// single heap allocation. `Arc<str>` implements `Borrow<str>` so map
/// lookups continue to accept `&str` without allocating a key.
pub type PropKey = Arc<str>;

// ── Node types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeType {
    Process,
    Ip,
    File,
    User,
    Domain,
    Port,
    Container,
    Device,
    System,
    Incident,
    Campaign,
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            NodeType::Process => "process",
            NodeType::Ip => "ip",
            NodeType::File => "file",
            NodeType::User => "user",
            NodeType::Domain => "domain",
            NodeType::Port => "port",
            NodeType::Container => "container",
            NodeType::Device => "device",
            NodeType::System => "system",
            NodeType::Incident => "incident",
            NodeType::Campaign => "campaign",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Node {
    Process {
        pid: u32,
        ppid: u32,
        comm: String,
        exe: Option<String>,
        uid: u32,
        container_id: Option<String>,
        start_ts: DateTime<Utc>,
        exit_ts: Option<DateTime<Utc>>,
    },
    Ip {
        addr: String,
        is_internal: bool,
        datasets: Vec<String>,
        risk_score: u8,
        is_tor: bool,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
        /// Spec 015: attacker-supplied usernames from failed SSH auth.
        /// Stored here (not as User nodes) so the User namespace only
        /// contains real local users. Dedup + LIFO cap of 50.
        #[serde(default)]
        attempted_usernames: Vec<String>,
    },
    File {
        path: String,
        sha256: Option<String>,
        size: Option<u64>,
        entropy: Option<f32>,
        is_sensitive: bool,
        yara_matches: Vec<String>,
    },
    User {
        name: String,
        uid: Option<u32>,
    },
    Domain {
        name: String,
        datasets: Vec<String>,
        is_dga: Option<bool>,
        entropy: Option<f32>,
    },
    Port {
        number: u16,
        protocol: String,
    },
    Container {
        container_id: String,
        name: Option<String>,
        image: Option<String>,
        start_ts: Option<DateTime<Utc>>,
        exit_ts: Option<DateTime<Utc>>,
        oom_killed: bool,
    },
    Device {
        vendor: String,
        product: String,
        serial: Option<String>,
        dev_class: Option<String>,
    },
    System {
        hostname: String,
        sysctl_params: HashMap<String, String>,
    },
    Incident {
        incident_id: String,
        detector: String,
        severity: String,
        title: String,
        summary: String,
        ts: DateTime<Utc>,
        mitre_ids: Vec<String>,
        decision: Option<String>,
        confidence: Option<f32>,
        decision_reason: Option<String>,
        decision_target: Option<String>,
        auto_executed: bool,
        /// True if the source entity (IP/user) is in the allowlist.
        is_allowlisted: bool,
        /// Phase 7 Gap 1: operator marked this incident as false positive.
        #[serde(default)]
        false_positive: bool,
        /// Who reported the FP (operator name / Telegram username).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fp_reporter: Option<String>,
        /// When the FP was reported.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fp_reported_at: Option<DateTime<Utc>>,
        /// Spec 015 follow-up: incident is useful for AI research/training
        /// but NOT for the operator (e.g. self-traffic to cloud providers,
        /// the agent's own Telegram/GeoIP/Cloudflare calls, near-miss LSM
        /// patterns). Dashboard operator views filter these out; neural
        /// training and investigation views still see them.
        #[serde(default)]
        research_only: bool,
    },
    Campaign {
        campaign_id: String,
        dna_hash: Option<String>,
        pattern_class: String,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
        ip_count: u32,
    },
}

impl Node {
    pub fn node_type(&self) -> NodeType {
        match self {
            Node::Process { .. } => NodeType::Process,
            Node::Ip { .. } => NodeType::Ip,
            Node::File { .. } => NodeType::File,
            Node::User { .. } => NodeType::User,
            Node::Domain { .. } => NodeType::Domain,
            Node::Port { .. } => NodeType::Port,
            Node::Container { .. } => NodeType::Container,
            Node::Device { .. } => NodeType::Device,
            Node::System { .. } => NodeType::System,
            Node::Incident { .. } => NodeType::Incident,
            Node::Campaign { .. } => NodeType::Campaign,
        }
    }

    pub fn label(&self) -> String {
        match self {
            Node::Process { comm, pid, .. } => format!("{}({})", comm, pid),
            Node::Ip { addr, .. } => addr.clone(),
            Node::File { path, .. } => path.clone(),
            Node::User { name, .. } => name.clone(),
            Node::Domain { name, .. } => name.clone(),
            Node::Port {
                number, protocol, ..
            } => format!("{}/{}", number, protocol),
            Node::Container {
                container_id, name, ..
            } => name
                .as_deref()
                .unwrap_or(&container_id[..12.min(container_id.len())])
                .to_string(),
            Node::Device {
                vendor, product, ..
            } => format!("{} {}", vendor, product),
            Node::System { hostname, .. } => hostname.clone(),
            Node::Incident { incident_id, .. } => incident_id.clone(),
            Node::Campaign { campaign_id, .. } => campaign_id.clone(),
        }
    }

    pub fn is_sensitive_file(&self) -> bool {
        matches!(
            self,
            Node::File {
                is_sensitive: true,
                ..
            }
        )
    }
}

// ── Edge / Relation types ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Relation {
    // Process → Process
    SpawnedBy,
    PtraceAttached,
    Signaled,
    // Process → Ip
    ConnectedTo,
    AcceptedFrom,
    // Process → Port
    ListensOn,
    // Process → File
    Wrote,
    Read,
    Executed,
    Deleted,
    Renamed,
    Truncated,
    Timestomped,
    Mounted,
    // Process → Domain
    Resolved,
    // Process → User
    RunAs,
    EscalatedTo,
    SudoAs,
    // Process → Container
    InContainer,
    // Process self-referential (memfd/fd/mprotect)
    CreatedMemfd,
    RedirectedFd,
    MprotectExec,
    // User → Ip
    LoggedInFrom,
    // Ip → Port
    ScannedPort,
    // Ip → Ip
    HttpRequestTo,
    // Ip → Domain
    HostedAt,
    // File → Ip
    DownloadedFrom,
    // File → File (integrity)
    IntegrityChanged,
    // Device → System
    InsertedOn,
    RemovedFrom,
    // * → System (kernel/firmware)
    LoadedModule,
    LoadedBpf,
    WroteMsr,
    CalledEfi,
    ChangedIoperm,
    ChangedIopl,
    EvalAcpi,
    TimingAnomaly,
    ChangedSysctl,
    SyscallTableModified,
    ExecBlocked,
    IoUringSubmit,
    IoUringCreate,
    // Container → System
    StartedOn,
    DiedOn,
    OomKilled,
    // Network snapshot (bulk)
    SnapshotConnectedTo,
    SnapshotListensOn,
    // Incident relations
    TriggeredBy,
    CorrelatedWith,
    EscalatedFrom,
    // Ip → Campaign
    MemberOf,
    // Ip → System
    BlockedBy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub relation: Relation,
    pub ts: DateTime<Utc>,
    /// Property bag keyed by interned `Arc<str>`. Edges that share a
    /// key (the common case) share a single key allocation. The
    /// derived `Serialize`/`Deserialize` emit/parse plain JSON
    /// strings for keys, so the wire format is unchanged from when
    /// keys were `String` — back-compat with snapshot v3.
    pub properties: HashMap<PropKey, serde_json::Value>,
}

impl Edge {
    pub fn new(from: NodeId, to: NodeId, relation: Relation, ts: DateTime<Utc>) -> Self {
        Self {
            from,
            to,
            relation,
            ts,
            properties: HashMap::new(),
        }
    }

    pub fn with_prop(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.properties
            .insert(crate::knowledge_graph::intern::intern(key), value.into());
        self
    }

    pub fn is_snapshot(&self) -> bool {
        matches!(
            self.relation,
            Relation::SnapshotConnectedTo | Relation::SnapshotListensOn
        )
    }
}

// ── SubGraph (query results) ────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize)]
pub struct SubGraph {
    pub nodes: HashMap<NodeId, Node>,
    pub edges: Vec<Edge>,
}

// ── GraphMetrics ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize)]
pub struct GraphMetrics {
    pub node_count: usize,
    pub edge_count: usize,
    pub memory_bytes: usize,
    pub nodes_by_type: HashMap<String, usize>,
    pub avg_degree: f32,
    pub threat_intel_nodes: usize,
    pub incident_nodes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-04-20T08:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn sample_ip(addr: &str, risk_score: u8) -> Node {
        Node::Ip {
            addr: addr.to_string(),
            is_internal: false,
            datasets: vec!["test-feed".into()],
            risk_score,
            is_tor: false,
            first_seen: ts(),
            last_seen: ts(),
            attempted_usernames: vec!["root".into()],
        }
    }

    fn sample_incident() -> Node {
        Node::Incident {
            incident_id: "inc-1".into(),
            detector: "ssh_bruteforce".into(),
            severity: "high".into(),
            title: "SSH brute force".into(),
            summary: "multiple failed logins".into(),
            ts: ts(),
            mitre_ids: vec!["T1110".into()],
            decision: Some("block_ip".into()),
            confidence: Some(0.91),
            decision_reason: Some("repeated attempts".into()),
            decision_target: Some("203.0.113.10".into()),
            auto_executed: true,
            is_allowlisted: false,
            false_positive: false,
            fp_reporter: None,
            fp_reported_at: None,
            research_only: false,
        }
    }

    #[test]
    fn ip_label_returns_address() {
        assert_eq!(sample_ip("1.2.3.4", 10).label(), "1.2.3.4");
    }

    #[test]
    fn process_label_has_pid_fallback_when_comm_empty() {
        let node = Node::Process {
            pid: 42,
            ppid: 1,
            comm: String::new(),
            exe: None,
            uid: 1000,
            container_id: None,
            start_ts: ts(),
            exit_ts: None,
        };

        assert_eq!(node.label(), "(42)");
    }

    #[test]
    fn incident_node_serde_round_trips() {
        let node = sample_incident();
        let json = serde_json::to_string(&node).expect("serialize incident node");
        let decoded: Node = serde_json::from_str(&json).expect("deserialize incident node");

        assert_eq!(decoded, node);
    }

    #[test]
    fn edge_serde_round_trips_all_relation_variants() {
        let relations = [
            Relation::SpawnedBy,
            Relation::PtraceAttached,
            Relation::Signaled,
            Relation::ConnectedTo,
            Relation::AcceptedFrom,
            Relation::ListensOn,
            Relation::Wrote,
            Relation::Read,
            Relation::Executed,
            Relation::Deleted,
            Relation::Renamed,
            Relation::Truncated,
            Relation::Timestomped,
            Relation::Mounted,
            Relation::Resolved,
            Relation::RunAs,
            Relation::EscalatedTo,
            Relation::SudoAs,
            Relation::InContainer,
            Relation::CreatedMemfd,
            Relation::RedirectedFd,
            Relation::MprotectExec,
            Relation::LoggedInFrom,
            Relation::ScannedPort,
            Relation::HttpRequestTo,
            Relation::HostedAt,
            Relation::DownloadedFrom,
            Relation::IntegrityChanged,
            Relation::InsertedOn,
            Relation::RemovedFrom,
            Relation::LoadedModule,
            Relation::LoadedBpf,
            Relation::WroteMsr,
            Relation::CalledEfi,
            Relation::ChangedIoperm,
            Relation::ChangedIopl,
            Relation::EvalAcpi,
            Relation::TimingAnomaly,
            Relation::ChangedSysctl,
            Relation::SyscallTableModified,
            Relation::ExecBlocked,
            Relation::IoUringSubmit,
            Relation::IoUringCreate,
            Relation::StartedOn,
            Relation::DiedOn,
            Relation::OomKilled,
            Relation::SnapshotConnectedTo,
            Relation::SnapshotListensOn,
            Relation::TriggeredBy,
            Relation::CorrelatedWith,
            Relation::EscalatedFrom,
            Relation::MemberOf,
            Relation::BlockedBy,
        ];

        for relation in relations {
            let edge = Edge::new(1, 2, relation, ts()).with_prop("source", "unit-test");
            let json = serde_json::to_string(&edge).expect("serialize edge");
            let decoded: Edge = serde_json::from_str(&json).expect("deserialize edge");

            assert_eq!(decoded, edge);
        }
    }

    #[test]
    fn node_type_display_uses_lowercase_strings() {
        assert_eq!(NodeType::Ip.to_string(), "ip");
        assert_eq!(NodeType::Process.to_string(), "process");
        assert_eq!(NodeType::Incident.to_string(), "incident");
    }

    #[test]
    fn ip_nodes_can_share_label_without_full_struct_equality() {
        let low_risk = sample_ip("203.0.113.10", 10);
        let high_risk = sample_ip("203.0.113.10", 90);

        assert_eq!(low_risk.label(), high_risk.label());
        assert_ne!(low_risk, high_risk);
    }

    #[test]
    fn edge_snapshot_classifier_matches_only_snapshot_relations() {
        assert!(Edge::new(1, 2, Relation::SnapshotConnectedTo, ts()).is_snapshot());
        assert!(Edge::new(1, 2, Relation::SnapshotListensOn, ts()).is_snapshot());
        assert!(!Edge::new(1, 2, Relation::ConnectedTo, ts()).is_snapshot());
    }
}
