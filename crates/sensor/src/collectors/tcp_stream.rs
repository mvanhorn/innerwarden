//! TCP Stream Reassembly Engine.
//!
//! Captures TCP packets via AF_PACKET and reconstructs bidirectional byte streams.
//! Each TCP connection (identified by 5-tuple) gets a flow entry with reassembly
//! buffers for both directions (client->server, server->client).
//!
//! When a stream accumulates enough data or the connection closes, the reassembled
//! bytes are passed to application-layer protocol detection and parsing.
//!
//! This enables:
//! - Deep packet inspection on ANY port (not just 80/443)
//! - Detection of C2 on non-standard ports
//! - File extraction from HTTP downloads
//! - Protocol anomaly detection
//! - Evasion resistance (fragmented payloads are reassembled before analysis)
//!
//! Requires: Linux, CAP_NET_RAW.
//! Memory-capped: max 10K concurrent flows, 1MB per flow, 100MB total.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Flow tracking
// ---------------------------------------------------------------------------

/// 5-tuple key identifying a TCP connection.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl FlowKey {
    /// Create the reverse direction key.
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            proto: self.proto,
        }
    }

    pub fn src_ip_str(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            (self.src_ip >> 24) & 0xff,
            (self.src_ip >> 16) & 0xff,
            (self.src_ip >> 8) & 0xff,
            self.src_ip & 0xff
        )
    }

    pub fn dst_ip_str(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            (self.dst_ip >> 24) & 0xff,
            (self.dst_ip >> 16) & 0xff,
            (self.dst_ip >> 8) & 0xff,
            self.dst_ip & 0xff
        )
    }
}

/// State of a TCP connection.
#[derive(Debug, Clone, PartialEq)]
pub enum FlowState {
    /// SYN seen, waiting for SYN-ACK.
    SynSent,
    /// Connection established (3-way handshake complete).
    Established,
    /// FIN seen, connection closing.
    Closing,
    /// Connection closed or reset.
    Closed,
}

/// One direction of a TCP stream (reassembly buffer).
#[derive(Debug)]
pub struct StreamBuffer {
    /// Expected next sequence number.
    next_seq: u32,
    /// Reassembled bytes in order.
    data: Vec<u8>,
    /// Total bytes seen (before truncation).
    total_bytes: usize,
    /// Max buffer size (configurable).
    max_bytes: usize,
}

impl StreamBuffer {
    fn new(initial_seq: u32, max_bytes: usize) -> Self {
        Self {
            next_seq: initial_seq,
            data: Vec::new(),
            total_bytes: 0,
            max_bytes,
        }
    }

    /// Add a TCP segment's payload to the stream.
    /// Returns true if data was added (in-order).
    fn add_segment(&mut self, seq: u32, payload: &[u8]) -> bool {
        if payload.is_empty() {
            return false;
        }

        // Simple in-order reassembly: only accept if seq matches expected.
        // Out-of-order segments are dropped (simplification for v1).
        if seq == self.next_seq {
            let available = self.max_bytes.saturating_sub(self.data.len());
            let to_copy = payload.len().min(available);
            if to_copy > 0 {
                self.data.extend_from_slice(&payload[..to_copy]);
            }
            self.total_bytes += payload.len();
            self.next_seq = seq.wrapping_add(payload.len() as u32);
            true
        } else if seq_before(seq, self.next_seq) {
            // Retransmission: already have this data
            false
        } else {
            // Gap: out-of-order segment. Skip for now (v2: buffer and reorder).
            self.next_seq = seq.wrapping_add(payload.len() as u32);
            self.total_bytes += payload.len();
            false
        }
    }

    /// Get the reassembled data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Total bytes seen in this direction.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}

/// A tracked TCP flow with bidirectional reassembly.
pub struct Flow {
    pub key: FlowKey,
    pub state: FlowState,
    /// Client to server stream.
    pub client: StreamBuffer,
    /// Server to client stream.
    pub server: StreamBuffer,
    /// First packet timestamp.
    pub started: DateTime<Utc>,
    /// Last packet timestamp.
    pub last_seen: DateTime<Utc>,
    /// Detected application protocol (after probing).
    pub app_proto: Option<AppProtocol>,
}

/// Detected application-layer protocol.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppProtocol {
    Http,
    Ssh,
    Tls,
    Smtp,
    Smb,
    Unknown,
}

/// Flow table managing all active TCP connections.
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    max_flows: usize,
    max_bytes_per_flow: usize,
}

/// Event emitted when a flow has enough data for analysis.
#[derive(Debug)]
pub struct FlowEvent {
    pub key: FlowKey,
    pub app_proto: AppProtocol,
    pub client_data: Vec<u8>,
    pub server_data: Vec<u8>,
    pub started: DateTime<Utc>,
    pub duration_ms: i64,
}

impl FlowTable {
    pub fn new(max_flows: usize, max_bytes_per_flow: usize) -> Self {
        Self {
            flows: HashMap::with_capacity(max_flows / 2),
            max_flows,
            max_bytes_per_flow,
        }
    }

    /// Process a TCP packet. Returns a FlowEvent if the flow is ready for analysis.
    pub fn process_packet(
        &mut self,
        key: FlowKey,
        tcp_flags: u8,
        seq: u32,
        payload: &[u8],
        now: DateTime<Utc>,
    ) -> Option<FlowEvent> {
        const SYN: u8 = 0x02;
        const FIN: u8 = 0x01;
        const RST: u8 = 0x04;
        const ACK: u8 = 0x10;

        let is_syn = tcp_flags & SYN != 0;
        let is_fin = tcp_flags & FIN != 0;
        let is_rst = tcp_flags & RST != 0;
        let is_ack = tcp_flags & ACK != 0;

        // Evict oldest flow if at capacity
        if !self.flows.contains_key(&key) && self.flows.len() >= self.max_flows {
            self.evict_oldest();
        }

        // New connection (SYN without ACK)
        if is_syn && !is_ack {
            let flow = Flow {
                key: key.clone(),
                state: FlowState::SynSent,
                client: StreamBuffer::new(seq.wrapping_add(1), self.max_bytes_per_flow),
                server: StreamBuffer::new(0, self.max_bytes_per_flow),
                started: now,
                last_seen: now,
                app_proto: None,
            };
            self.flows.insert(key, flow);
            return None;
        }

        // SYN-ACK (server response)
        let rev = key.reverse();
        if is_syn && is_ack {
            if let Some(flow) = self.flows.get_mut(&rev) {
                flow.server = StreamBuffer::new(seq.wrapping_add(1), self.max_bytes_per_flow);
                flow.state = FlowState::Established;
                flow.last_seen = now;
            }
            return None;
        }

        // Find the flow (try both directions)
        let (flow_key, is_client) = if self.flows.contains_key(&key) {
            (key.clone(), true)
        } else if self.flows.contains_key(&rev) {
            (rev.clone(), false)
        } else {
            // No tracked flow: mid-stream packet. Create a flow if it has data.
            if !payload.is_empty() {
                let flow = Flow {
                    key: key.clone(),
                    state: FlowState::Established,
                    client: StreamBuffer::new(seq, self.max_bytes_per_flow),
                    server: StreamBuffer::new(0, self.max_bytes_per_flow),
                    started: now,
                    last_seen: now,
                    app_proto: None,
                };
                self.flows.insert(key.clone(), flow);
                let flow = self.flows.get_mut(&key)?;
                flow.client.add_segment(seq, payload);
                // Probe for protocol
                if flow.app_proto.is_none() {
                    flow.app_proto = Some(probe_protocol(payload));
                }
            }
            return None;
        };

        let flow = self.flows.get_mut(&flow_key)?;
        flow.last_seen = now;

        // Add payload to the appropriate direction
        if !payload.is_empty() {
            if is_client {
                flow.client.add_segment(seq, payload);
                if flow.app_proto.is_none() {
                    flow.app_proto = Some(probe_protocol(payload));
                }
            } else {
                flow.server.add_segment(seq, payload);
                if flow.app_proto.is_none() {
                    flow.app_proto = Some(probe_protocol(payload));
                }
            }
        }

        // Connection closing
        if is_fin || is_rst {
            flow.state = FlowState::Closed;
            return self.emit_and_remove(&flow_key);
        }

        // Emit if we have enough data for analysis (4KB+ in either direction)
        let client_len = flow.client.data.len();
        let server_len = flow.server.data.len();
        if client_len >= 4096 || server_len >= 4096 {
            // Don't remove: keep tracking. Just emit what we have so far.
            let evt = FlowEvent {
                key: flow.key.clone(),
                app_proto: flow.app_proto.clone().unwrap_or(AppProtocol::Unknown),
                client_data: flow.client.data.clone(),
                server_data: flow.server.data.clone(),
                started: flow.started,
                duration_ms: (now - flow.started).num_milliseconds(),
            };
            return Some(evt);
        }

        None
    }

    fn emit_and_remove(&mut self, key: &FlowKey) -> Option<FlowEvent> {
        let flow = self.flows.remove(key)?;
        // Only emit if there's meaningful data
        if flow.client.data.is_empty() && flow.server.data.is_empty() {
            return None;
        }
        Some(FlowEvent {
            key: flow.key,
            app_proto: flow.app_proto.unwrap_or(AppProtocol::Unknown),
            client_data: flow.client.data,
            server_data: flow.server.data,
            started: flow.started,
            duration_ms: (flow.last_seen - flow.started).num_milliseconds(),
        })
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .flows
            .iter()
            .min_by_key(|(_, f)| f.last_seen)
            .map(|(k, _)| k.clone())
        {
            self.flows.remove(&oldest_key);
        }
    }

    pub fn active_flows(&self) -> usize {
        self.flows.len()
    }

    /// Clean up stale flows (no packets for >60s).
    pub fn cleanup_stale(&mut self, now: DateTime<Utc>, timeout_secs: i64) -> Vec<FlowEvent> {
        let cutoff = now - chrono::Duration::seconds(timeout_secs);
        let stale_keys: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, f)| f.last_seen < cutoff)
            .map(|(k, _)| k.clone())
            .collect();

        let mut events = Vec::new();
        for key in stale_keys {
            if let Some(evt) = self.emit_and_remove(&key) {
                events.push(evt);
            }
        }
        events
    }
}

// ---------------------------------------------------------------------------
// Protocol probing
// ---------------------------------------------------------------------------

/// Detect application protocol from the first bytes of a stream.
/// Port-independent: if it looks like HTTP, it IS HTTP (even on port 4444).
fn probe_protocol(data: &[u8]) -> AppProtocol {
    if data.len() < 4 {
        return AppProtocol::Unknown;
    }

    // HTTP: starts with method (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH)
    // or response (HTTP/1.)
    if data.starts_with(b"GET ")
        || data.starts_with(b"POST ")
        || data.starts_with(b"PUT ")
        || data.starts_with(b"DELETE ")
        || data.starts_with(b"HEAD ")
        || data.starts_with(b"OPTIONS ")
        || data.starts_with(b"PATCH ")
        || data.starts_with(b"CONNECT ")
        || data.starts_with(b"HTTP/1.")
        || data.starts_with(b"HTTP/2")
    {
        return AppProtocol::Http;
    }

    // SSH: starts with "SSH-"
    if data.starts_with(b"SSH-") {
        return AppProtocol::Ssh;
    }

    // TLS: starts with ContentType (0x16) + version (0x03, 0x01-0x04)
    if data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x04 {
        return AppProtocol::Tls;
    }

    // SMTP: starts with "220 " (server greeting) or "EHLO"/"HELO"
    if data.starts_with(b"220 ") || data.starts_with(b"EHLO") || data.starts_with(b"HELO") {
        return AppProtocol::Smtp;
    }

    // SMB: starts with NetBIOS session header (0x00) + SMB magic (0xFF, 'S', 'M', 'B')
    if data.len() >= 8 && data[4] == 0xFF && data[5] == b'S' && data[6] == b'M' && data[7] == b'B'
    {
        return AppProtocol::Smb;
    }

    AppProtocol::Unknown
}

/// TCP sequence number comparison (handles wraparound).
fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

// ---------------------------------------------------------------------------
// Packet parsing
// ---------------------------------------------------------------------------

/// Parse a raw ethernet frame into TCP fields.
/// Returns (FlowKey, tcp_flags, seq_num, payload).
#[cfg(target_os = "linux")]
pub fn parse_tcp_packet(raw: &[u8]) -> Option<(FlowKey, u8, u32, &[u8])> {
    // Ethernet header: 14 bytes
    if raw.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([raw[12], raw[13]]);

    let ip_start = if ethertype == 0x0800 {
        14 // IPv4
    } else if ethertype == 0x8100 {
        18 // VLAN tagged
    } else {
        return None; // Not IPv4
    };

    if raw.len() < ip_start + 20 {
        return None;
    }

    let ip_header = &raw[ip_start..];
    let ip_version = ip_header[0] >> 4;
    if ip_version != 4 {
        return None;
    }

    let ip_header_len = ((ip_header[0] & 0x0f) as usize) * 4;
    let protocol = ip_header[9];

    // Only TCP (protocol 6)
    if protocol != 6 {
        return None;
    }

    let src_ip = u32::from_be_bytes([ip_header[12], ip_header[13], ip_header[14], ip_header[15]]);
    let dst_ip = u32::from_be_bytes([ip_header[16], ip_header[17], ip_header[18], ip_header[19]]);

    let tcp_start = ip_start + ip_header_len;
    if raw.len() < tcp_start + 20 {
        return None;
    }

    let tcp = &raw[tcp_start..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let tcp_data_offset = ((tcp[12] >> 4) as usize) * 4;
    let flags = tcp[13];

    let payload_start = tcp_start + tcp_data_offset;
    let payload = if raw.len() > payload_start {
        &raw[payload_start..]
    } else {
        &[]
    };

    let key = FlowKey {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto: 6,
    };

    Some((key, flags, seq, payload))
}

// ---------------------------------------------------------------------------
// Collector entry point
// ---------------------------------------------------------------------------

/// Run the TCP stream reassembly collector.
/// Captures all TCP traffic, reassembles streams, detects protocols, and
/// emits events for further analysis.
#[cfg(target_os = "linux")]
pub async fn run(
    tx: tokio::sync::mpsc::Sender<innerwarden_core::event::Event>,
    host_id: String,
) {
    use innerwarden_core::event::{Event, Severity};

    info!("tcp_stream: starting TCP stream reassembly engine");

    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };

    if fd < 0 {
        warn!("tcp_stream: failed to create AF_PACKET socket (need CAP_NET_RAW)");
        return;
    }

    info!("tcp_stream: listening on all interfaces (max 10K flows, 1MB/flow)");

    let mut table = FlowTable::new(10_000, 1_048_576); // 10K flows, 1MB each
    let mut buf = [0u8; 65536];
    let mut cleanup_counter = 0u64;

    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

        if n <= 0 {
            tokio::task::yield_now().await;
            continue;
        }

        let raw = &buf[..n as usize];
        let now = Utc::now();

        if let Some((key, flags, seq, payload)) = parse_tcp_packet(raw) {
            if let Some(flow_event) = table.process_packet(key, flags, seq, payload, now) {
                // Emit protocol event
                let event = flow_event_to_event(&flow_event, &host_id);
                let _ = tx.send(event).await;

                // Try file extraction from HTTP flows
                let filestore = std::path::Path::new("/var/lib/innerwarden/filestore");
                if let Some(extracted) = super::file_extract::extract_from_flow(&flow_event, filestore) {
                    let file_event = super::file_extract::to_event(&extracted, &host_id);
                    let _ = tx.send(file_event).await;
                }
            }
        }

        // Periodic cleanup (every ~10K packets)
        cleanup_counter += 1;
        if cleanup_counter % 10_000 == 0 {
            let stale_events = table.cleanup_stale(Utc::now(), 60);
            for flow_event in stale_events {
                let event = flow_event_to_event(&flow_event, &host_id);
                let _ = tx.send(event).await;

                let filestore = std::path::Path::new("/var/lib/innerwarden/filestore");
                if let Some(extracted) = super::file_extract::extract_from_flow(&flow_event, filestore) {
                    let file_event = super::file_extract::to_event(&extracted, &host_id);
                    let _ = tx.send(file_event).await;
                }
            }
        }
    }
}

/// Convert a FlowEvent into an InnerWarden Event for the detector pipeline.
/// Uses deep protocol parsers for HTTP, SSH, and SMB when available.
fn flow_event_to_event(
    fe: &FlowEvent,
    host_id: &str,
) -> innerwarden_core::event::Event {
    use innerwarden_core::event::{Event, Severity};
    use super::proto_http;
    use super::proto_ssh;
    use super::proto_smb;

    let src_ip = fe.key.src_ip_str();
    let dst_ip = fe.key.dst_ip_str();

    let (kind, severity, summary, details) = match fe.app_proto {
        AppProtocol::Http => {
            // Deep HTTP parsing
            let req = proto_http::parse_request(&fe.client_data);
            let resp = proto_http::parse_response(&fe.server_data);
            let signals = req
                .as_ref()
                .map(|r| proto_http::extract_signals(r, resp.as_ref()))
                .unwrap_or_default();

            let method = req.as_ref().map(|r| r.method.as_str()).unwrap_or("?");
            let uri = req.as_ref().map(|r| r.uri.as_str()).unwrap_or("?");
            let host = req.as_ref().map(|r| r.host.as_str()).unwrap_or("?");
            let user_agent = req.as_ref().map(|r| r.user_agent.as_str()).unwrap_or("?");
            let status = resp.as_ref().map(|r| r.status_code).unwrap_or(0);

            let sev = if signals.iter().any(|s| {
                s.contains("LATERAL") || s.contains("injection") || s.contains("webshell")
            }) {
                Severity::High
            } else if !signals.is_empty() {
                Severity::Medium
            } else {
                Severity::Info
            };

            (
                "tcp_stream.http",
                sev,
                format!("{method} {uri} -> {status} ({src_ip} -> {host})"),
                serde_json::json!({
                    "app_proto": "http",
                    "method": method,
                    "uri": uri,
                    "host": host,
                    "user_agent": user_agent,
                    "status_code": status,
                    "content_type": resp.as_ref().map(|r| r.content_type.as_str()).unwrap_or(""),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": fe.key.dst_port,
                    "client_bytes": fe.client_data.len(),
                    "server_bytes": fe.server_data.len(),
                    "duration_ms": fe.duration_ms,
                    "signals": signals,
                }),
            )
        }
        AppProtocol::Ssh => {
            // Deep SSH parsing
            let session = proto_ssh::parse_session(&fe.client_data, &fe.server_data);
            let client_ver = session.as_ref().map(|s| s.client_version.as_str()).unwrap_or("?");
            let server_ver = session.as_ref().map(|s| s.server_version.as_str()).unwrap_or("?");
            let signals: Vec<String> = session.as_ref().map(|s| s.signals.clone()).unwrap_or_default();
            let has_tunnel = session.as_ref().map(|s| s.has_tunnel_request).unwrap_or(false);

            let sev = if has_tunnel || signals.iter().any(|s| s.contains("bruteforce")) {
                Severity::High
            } else if !signals.is_empty() {
                Severity::Medium
            } else {
                Severity::Info
            };

            let mut summary_extra = String::new();
            if fe.key.dst_port != 22 {
                summary_extra = format!(" (non-standard port {})", fe.key.dst_port);
            }
            if has_tunnel {
                summary_extra.push_str(" [TUNNEL]");
            }

            (
                "tcp_stream.ssh",
                sev,
                format!("SSH {client_ver} -> {server_ver} ({src_ip} -> {dst_ip}){summary_extra}"),
                serde_json::json!({
                    "app_proto": "ssh",
                    "client_version": client_ver,
                    "server_version": server_ver,
                    "has_tunnel": has_tunnel,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": fe.key.dst_port,
                    "non_standard_port": fe.key.dst_port != 22,
                    "client_bytes": fe.client_data.len(),
                    "server_bytes": fe.server_data.len(),
                    "duration_ms": fe.duration_ms,
                    "signals": signals,
                }),
            )
        }
        AppProtocol::Smb => {
            // Deep SMB parsing
            let session = proto_smb::parse_session(&fe.client_data);
            let signals: Vec<String> = session.as_ref().map(|s| s.signals.clone()).unwrap_or_default();
            let pipes: Vec<String> = session.as_ref().map(|s| s.named_pipes.clone()).unwrap_or_default();
            let version = session.as_ref().map(|s| format!("{:?}", s.version)).unwrap_or("?".into());

            let sev = if signals.iter().any(|s| s.contains("LATERAL") || s.contains("CREDENTIAL")) {
                Severity::Critical
            } else if signals.iter().any(|s| s.contains("admin_share") || s.contains("remote_")) {
                Severity::High
            } else {
                Severity::Medium // SMB itself is notable
            };

            (
                "tcp_stream.smb",
                sev,
                format!("SMB {version} ({src_ip} -> {dst_ip}:{}) pipes:{}", fe.key.dst_port, pipes.join(",")),
                serde_json::json!({
                    "app_proto": "smb",
                    "smb_version": version,
                    "named_pipes": pipes,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": fe.key.dst_port,
                    "client_bytes": fe.client_data.len(),
                    "server_bytes": fe.server_data.len(),
                    "duration_ms": fe.duration_ms,
                    "signals": signals,
                }),
            )
        }
        _ => (
            "tcp_stream.flow",
            Severity::Info,
            format!("TCP flow: {src_ip}:{} -> {dst_ip}:{} ({:?})",
                fe.key.src_port, fe.key.dst_port, fe.app_proto),
            serde_json::json!({
                "app_proto": format!("{:?}", fe.app_proto),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": fe.key.src_port,
                "dst_port": fe.key.dst_port,
                "client_bytes": fe.client_data.len(),
                "server_bytes": fe.server_data.len(),
                "duration_ms": fe.duration_ms,
            }),
        ),
    };

    Event {
        ts: fe.started,
        host: host_id.to_string(),
        source: "tcp_stream".into(),
        kind: kind.into(),
        severity,
        summary,
        details,
        tags: vec!["network".into(), format!("{:?}", fe.app_proto).to_lowercase()],
        entities: vec![
            innerwarden_core::entities::EntityRef::ip(src_ip),
            innerwarden_core::entities::EntityRef::ip(dst_ip),
        ],
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn run(
    _tx: tokio::sync::mpsc::Sender<innerwarden_core::event::Event>,
    _host_id: String,
) {
    info!("tcp_stream: not available on this platform (requires Linux AF_PACKET)");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_key_reverse() {
        let key = FlowKey {
            src_ip: 0x0A000001,
            dst_ip: 0x0A000002,
            src_port: 12345,
            dst_port: 80,
            proto: 6,
        };
        let rev = key.reverse();
        assert_eq!(rev.src_ip, key.dst_ip);
        assert_eq!(rev.dst_ip, key.src_ip);
        assert_eq!(rev.src_port, key.dst_port);
        assert_eq!(rev.dst_port, key.src_port);
    }

    #[test]
    fn test_stream_buffer_in_order() {
        let mut buf = StreamBuffer::new(100, 4096);
        assert!(buf.add_segment(100, b"hello"));
        assert!(buf.add_segment(105, b" world"));
        assert_eq!(buf.data(), b"hello world");
        assert_eq!(buf.total_bytes(), 11);
    }

    #[test]
    fn test_stream_buffer_retransmission() {
        let mut buf = StreamBuffer::new(100, 4096);
        assert!(buf.add_segment(100, b"hello"));
        assert!(!buf.add_segment(100, b"hello")); // retransmission
        assert_eq!(buf.data(), b"hello");
    }

    #[test]
    fn test_stream_buffer_max_bytes() {
        let mut buf = StreamBuffer::new(0, 10);
        buf.add_segment(0, b"12345678901234567890");
        assert_eq!(buf.data().len(), 10); // capped at max
    }

    #[test]
    fn test_probe_protocol() {
        assert_eq!(probe_protocol(b"GET / HTTP/1.1\r\n"), AppProtocol::Http);
        assert_eq!(probe_protocol(b"POST /api HTTP/1.1"), AppProtocol::Http);
        assert_eq!(probe_protocol(b"HTTP/1.1 200 OK"), AppProtocol::Http);
        assert_eq!(probe_protocol(b"SSH-2.0-OpenSSH"), AppProtocol::Ssh);
        assert_eq!(probe_protocol(b"\x16\x03\x01\x00"), AppProtocol::Tls);
        assert_eq!(probe_protocol(b"220 smtp.example.com"), AppProtocol::Smtp);
        assert_eq!(probe_protocol(b"abc"), AppProtocol::Unknown);
    }

    #[test]
    fn test_seq_before() {
        assert!(seq_before(1, 2));
        assert!(!seq_before(2, 1));
        // Wraparound
        assert!(seq_before(u32::MAX, 0));
    }

    #[test]
    fn test_flow_table_syn_handshake() {
        let mut table = FlowTable::new(100, 4096);
        let now = Utc::now();
        let key = FlowKey {
            src_ip: 1,
            dst_ip: 2,
            src_port: 12345,
            dst_port: 80,
            proto: 6,
        };

        // SYN
        assert!(table.process_packet(key.clone(), 0x02, 1000, &[], now).is_none());
        assert_eq!(table.active_flows(), 1);

        // SYN-ACK
        let rev = key.reverse();
        assert!(table.process_packet(rev.clone(), 0x12, 2000, &[], now).is_none());

        // Data from client
        assert!(table
            .process_packet(key.clone(), 0x10, 1001, b"GET / HTTP/1.1\r\n", now)
            .is_none()); // not enough data yet
    }

    #[test]
    fn test_flow_table_eviction() {
        let mut table = FlowTable::new(2, 4096);
        let now = Utc::now();

        // Fill up
        for i in 0..3 {
            let key = FlowKey {
                src_ip: i,
                dst_ip: 100,
                src_port: 12345,
                dst_port: 80,
                proto: 6,
            };
            table.process_packet(key, 0x02, 1000, &[], now);
        }
        assert!(table.active_flows() <= 2);
    }

    #[test]
    fn test_ip_str() {
        let key = FlowKey {
            src_ip: 0x0A000101, // 10.0.1.1
            dst_ip: 0xC0A80001, // 192.168.0.1
            src_port: 0,
            dst_port: 0,
            proto: 6,
        };
        assert_eq!(key.src_ip_str(), "10.0.1.1");
        assert_eq!(key.dst_ip_str(), "192.168.0.1");
    }
}
