use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type NodeId = u64;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
            Node::Port { number, protocol, .. } => format!("{}/{}", number, protocol),
            Node::Container { container_id, name, .. } => {
                name.as_deref().unwrap_or(&container_id[..12.min(container_id.len())]).to_string()
            }
            Node::Device { vendor, product, .. } => format!("{} {}", vendor, product),
            Node::System { hostname, .. } => hostname.clone(),
            Node::Incident { incident_id, .. } => incident_id.clone(),
            Node::Campaign { campaign_id, .. } => campaign_id.clone(),
        }
    }

    pub fn is_sensitive_file(&self) -> bool {
        matches!(self, Node::File { is_sensitive: true, .. })
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub relation: Relation,
    pub ts: DateTime<Utc>,
    pub properties: HashMap<String, serde_json::Value>,
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
        self.properties.insert(key.to_string(), value.into());
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
