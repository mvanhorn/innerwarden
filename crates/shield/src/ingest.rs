// ingest.rs — Event Ingestion
//
// Reads Inner Warden JSONL files (events-*.jsonl, incidents-*.jsonl)
// with byte-offset tracking for incremental reads. Polls every cycle
// and feeds parsed events to the rate limiter, SYN tracker, and
// attack classifier.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Raw event from JSONL
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct IngestEvent {
    pub source: Option<String>,
    pub kind: Option<String>,
    /// Legacy field — some events have source_ip at top level.
    pub source_ip: Option<String>,
    /// Inner Warden core events use `ts` as the timestamp field.
    pub ts: Option<String>,
    /// Legacy timestamp field.
    pub timestamp: Option<String>,
    #[serde(default)]
    pub details: HashMap<String, serde_json::Value>,
    /// Inner Warden core events store IPs in the entities array.
    #[serde(default)]
    pub entities: Vec<EntityRef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EntityRef {
    #[serde(rename = "type")]
    pub entity_type: String,
    pub value: String,
}

// ---------------------------------------------------------------------------
// Parsed network event
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NetworkEvent {
    pub ip: String,
    pub timestamp: DateTime<Utc>,
    pub packets: u64,
    pub bytes: u64,
    pub is_connection: bool,
    pub is_syn: bool,
    pub is_syn_ack: bool,
    pub kind: String,
    pub source: String,
}

/// Event kinds relevant to DDoS detection.
const NETWORK_KINDS: &[&str] = &[
    "ssh.login_failed",
    "network.connection",
    "network.connection_blocked",
    "network.syn",
    "network.syn_ack",
    "ssh.bruteforce",
    "port_scan",
    "credential_stuffing",
    "web_scan",
    "ddos.packet",
    "http.request",
    "dns.response",
    "udp.flood",
];

// ---------------------------------------------------------------------------
// Ingestor
// ---------------------------------------------------------------------------

pub struct EventIngestor {
    data_dir: PathBuf,
    offsets: HashMap<PathBuf, u64>,
}

impl EventIngestor {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            offsets: HashMap::new(),
        }
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn restore_offsets(&mut self, offsets: HashMap<PathBuf, u64>) {
        self.offsets = offsets;
    }

    pub fn get_offsets(&self) -> &HashMap<PathBuf, u64> {
        &self.offsets
    }

    /// Poll for new events from all JSONL files.
    pub fn poll(&mut self) -> Result<Vec<NetworkEvent>> {
        let mut events = Vec::new();

        if let Ok(entries) = std::fs::read_dir(&self.data_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let fname = path.file_name().unwrap_or_default().to_string_lossy();

                let matches = (fname.starts_with("events-") && fname.ends_with(".jsonl"))
                    || (fname.starts_with("incidents-") && fname.ends_with(".jsonl"));

                if matches {
                    match self.read_file(&path) {
                        Ok(mut file_events) => events.append(&mut file_events),
                        Err(e) => {
                            tracing::warn!(path = ?path, error = %e, "Failed to read JSONL file");
                        }
                    }
                }
            }
        }

        Ok(events)
    }

    fn read_file(&mut self, path: &Path) -> Result<Vec<NetworkEvent>> {
        let mut events = Vec::new();
        let offset = self.offsets.get(path).copied().unwrap_or(0);

        let file =
            std::fs::File::open(path).with_context(|| format!("Failed to open {:?}", path))?;
        let metadata = file.metadata()?;
        if metadata.len() <= offset {
            return Ok(events);
        }

        let reader = BufReader::new(file);
        let mut current_offset: u64 = 0;

        for line in reader.lines() {
            let line = line?;
            let line_len = line.len() as u64 + 1;
            current_offset += line_len;

            if current_offset <= offset {
                continue;
            }

            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<IngestEvent>(&line) {
                Ok(event) => {
                    if let Some(net_event) = parse_network_event(&event) {
                        events.push(net_event);
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "Skipping unparseable line");
                }
            }
        }

        self.offsets.insert(path.to_path_buf(), current_offset);
        Ok(events)
    }
}

/// Extract the source IP from an event, checking multiple locations.
fn extract_ip(event: &IngestEvent) -> Option<String> {
    // 1. Top-level source_ip field (legacy format)
    if let Some(ref ip) = event.source_ip {
        if ip.contains('.') || ip.contains(':') {
            return Some(ip.clone());
        }
    }
    // 2. details.src_ip (Inner Warden journald/firewall events)
    if let Some(ip) = event.details.get("src_ip").and_then(|v| v.as_str()) {
        return Some(ip.to_string());
    }
    // 3. details.ip (Inner Warden auth_log events)
    if let Some(ip) = event.details.get("ip").and_then(|v| v.as_str()) {
        return Some(ip.to_string());
    }
    // 4. First IP entity in entities array
    for entity in &event.entities {
        if entity.entity_type == "ip" {
            // Skip private/local IPs — we want the attacker IP
            if !entity.value.starts_with("10.")
                && !entity.value.starts_with("192.168.")
                && !entity.value.starts_with("127.")
            {
                return Some(entity.value.clone());
            }
        }
    }
    // 5. Fallback: any IP entity
    for entity in &event.entities {
        if entity.entity_type == "ip" {
            return Some(entity.value.clone());
        }
    }
    None
}

/// Parse an IngestEvent into a NetworkEvent if it represents network activity.
pub fn parse_network_event(event: &IngestEvent) -> Option<NetworkEvent> {
    let kind = event.kind.as_deref()?;

    let is_network = NETWORK_KINDS.iter().any(|k| kind.contains(k))
        || event
            .source
            .as_deref()
            .map(|s| {
                s.contains("network")
                    || s.contains("firewall")
                    || s.contains("nginx")
                    || s.contains("ssh")
                    || s.contains("journald")
                    || s.contains("auth_log")
            })
            .unwrap_or(false);

    if !is_network {
        return None;
    }

    let ip_str = extract_ip(event)?;

    let timestamp = event
        .ts
        .as_deref()
        .or(event.timestamp.as_deref())
        .and_then(|t| t.parse::<DateTime<Utc>>().ok())
        .unwrap_or_else(Utc::now);

    let packets = event
        .details
        .get("packets")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);

    let bytes = event
        .details
        .get("bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(100);

    let is_connection = kind.contains("connection") || kind.contains("login");
    let is_syn = kind.contains("syn") && !kind.contains("syn_ack");
    let is_syn_ack = kind.contains("syn_ack");

    Some(NetworkEvent {
        ip: ip_str.to_string(),
        timestamp,
        packets,
        bytes,
        is_connection,
        is_syn,
        is_syn_ack,
        kind: kind.to_string(),
        source: event.source.clone().unwrap_or_default(),
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_ssh_event() {
        let event = IngestEvent {
            source: Some("auth_log".to_string()),
            kind: Some("ssh.login_failed".to_string()),
            source_ip: Some("10.0.0.1".to_string()),
            ts: None,
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            details: HashMap::new(),
            entities: vec![],
        };
        let result = parse_network_event(&event);
        assert!(result.is_some());
        let net = result.unwrap();
        assert_eq!(net.ip, "10.0.0.1");
        assert!(net.is_connection);
        assert!(!net.is_syn);
    }

    #[test]
    fn parse_non_network_event() {
        let event = IngestEvent {
            source: Some("integrity".to_string()),
            kind: Some("file.modified".to_string()),
            source_ip: None,
            ts: None,
            timestamp: None,
            details: HashMap::new(),
            entities: vec![],
        };
        assert!(parse_network_event(&event).is_none());
    }

    #[test]
    fn parse_event_missing_ip() {
        let event = IngestEvent {
            source: Some("auth_log".to_string()),
            kind: Some("ssh.login_failed".to_string()),
            source_ip: None,
            ts: None,
            timestamp: None,
            details: HashMap::new(),
            entities: vec![],
        };
        assert!(parse_network_event(&event).is_none());
    }

    #[test]
    fn parse_syn_event() {
        let event = IngestEvent {
            source: Some("network".to_string()),
            kind: Some("network.syn".to_string()),
            source_ip: Some("10.0.0.5".to_string()),
            ts: None,
            timestamp: None,
            details: HashMap::new(),
            entities: vec![],
        };
        let result = parse_network_event(&event);
        assert!(result.is_some());
        let net = result.unwrap();
        assert!(net.is_syn);
        assert!(!net.is_syn_ack);
    }

    #[test]
    fn parse_syn_ack_event() {
        let event = IngestEvent {
            source: Some("network".to_string()),
            kind: Some("network.syn_ack".to_string()),
            source_ip: Some("10.0.0.6".to_string()),
            ts: None,
            timestamp: None,
            details: HashMap::new(),
            entities: vec![],
        };
        let result = parse_network_event(&event);
        assert!(result.is_some());
        let net = result.unwrap();
        assert!(net.is_syn_ack);
        assert!(!net.is_syn); // syn_ack should not flag is_syn
    }

    #[test]
    fn ingestor_reads_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("events-2024-01-01.jsonl");

        let event_json = serde_json::json!({
            "source": "auth_log",
            "kind": "ssh.login_failed",
            "source_ip": "192.168.1.100",
            "timestamp": "2024-01-01T00:00:00Z",
            "details": {}
        });

        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "{}", event_json).unwrap();

        let mut ingestor = EventIngestor::new(dir.path());
        let events = ingestor.poll().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].ip, "192.168.1.100");
    }

    #[test]
    fn ingestor_incremental_read() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("events-2024-01-01.jsonl");

        let event1 = serde_json::json!({
            "source": "auth_log",
            "kind": "ssh.login_failed",
            "source_ip": "10.0.0.1",
            "timestamp": "2024-01-01T00:00:00Z",
            "details": {}
        });

        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "{}", event1).unwrap();
        drop(file);

        let mut ingestor = EventIngestor::new(dir.path());
        let events = ingestor.poll().unwrap();
        assert_eq!(events.len(), 1);

        // Append second event.
        let event2 = serde_json::json!({
            "source": "auth_log",
            "kind": "ssh.login_failed",
            "source_ip": "10.0.0.2",
            "timestamp": "2024-01-01T00:01:00Z",
            "details": {}
        });

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&file_path)
            .unwrap();
        writeln!(file, "{}", event2).unwrap();
        drop(file);

        let events = ingestor.poll().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].ip, "10.0.0.2");
    }

    #[test]
    fn ingestor_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut ingestor = EventIngestor::new(dir.path());
        let events = ingestor.poll().unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_with_packets_and_bytes() {
        let mut details = HashMap::new();
        details.insert("packets".to_string(), serde_json::json!(10));
        details.insert("bytes".to_string(), serde_json::json!(5000));

        let event = IngestEvent {
            source: Some("network".to_string()),
            kind: Some("network.connection".to_string()),
            source_ip: Some("10.0.0.7".to_string()),
            ts: None,
            timestamp: Some("2024-06-01T12:00:00Z".to_string()),
            details,
            entities: vec![],
        };

        let net = parse_network_event(&event).unwrap();
        assert_eq!(net.packets, 10);
        assert_eq!(net.bytes, 5000);
    }
}
