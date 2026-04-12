//! Protocol anomaly detector.
//!
//! Detects violations of protocol specifications that indicate:
//! - Zero-day exploit attempts (malformed packets crafted to trigger bugs)
//! - Evasion techniques (HTTP request smuggling, double encoding)
//! - Reconnaissance (protocol probing, banner grabbing on wrong ports)
//!
//! Works on events from the tcp_stream reassembly engine.
//! Checks HTTP, SSH, TLS, and generic TCP anomalies.
//!
//! Inspired by protocol mismatch and anomaly detection patterns used in mature IDS engines.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
    incident::Incident,
};

/// Anomaly types detected.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // many variants are constructed only by the Linux-gated tcp_stream run loop; kept as a closed set
pub enum AnomalyType {
    /// Protocol detected doesn't match the expected port service.
    ProtocolMismatch,
    /// HTTP request smuggling indicators.
    HttpRequestSmuggling,
    /// HTTP double encoding in URI (evasion).
    HttpDoubleEncoding,
    /// HTTP oversized headers (potential buffer overflow).
    HttpOversizedHeaders,
    /// HTTP invalid method.
    HttpInvalidMethod,
    /// HTTP invalid version.
    HttpInvalidVersion,
    /// HTTP response before request (protocol confusion).
    HttpResponseBeforeRequest,
    /// SSH on non-standard port (C2 indicator).
    SshNonStandardPort,
    /// SSH version string anomaly.
    SshVersionAnomaly,
    /// TLS on unexpected port.
    TlsUnexpectedPort,
    /// TLS invalid version (downgrade attack).
    TlsInvalidVersion,
    /// SMB on non-standard port (lateral movement).
    SmbNonStandardPort,
    /// TCP: data sent before handshake complete.
    TcpDataBeforeHandshake,
    /// Multiple protocols detected on same flow (protocol confusion).
    ProtocolConfusion,
    /// Extremely long flow with minimal data (slow loris style).
    SlowConnection,
}

pub struct ProtoAnomalyDetector {
    host: String,
    cooldown: Duration,
    alerted: HashMap<String, DateTime<Utc>>,
}

impl ProtoAnomalyDetector {
    pub fn new(host: impl Into<String>, cooldown_secs: i64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_secs),
            alerted: HashMap::new(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Vec<Incident> {
        let mut incidents = Vec::new();

        // Only process tcp_stream events
        if !event.kind.starts_with("tcp_stream.") {
            return incidents;
        }

        let src_ip = event
            .details
            .get("src_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let dst_ip = event
            .details
            .get("dst_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let dst_port = event
            .details
            .get("dst_port")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;
        let app_proto = event
            .details
            .get("app_proto")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let signals: Vec<String> = event
            .details
            .get("signals")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let now = event.ts;

        // ── Protocol mismatch detection ──
        // HTTP on non-HTTP port (C2 indicator)
        if app_proto == "http" && !is_http_port(dst_port) {
            if let Some(inc) = self.emit(
                AnomalyType::ProtocolMismatch,
                &format!("HTTP on port {dst_port}"),
                &format!("HTTP traffic detected on non-standard port {dst_port} ({src_ip} -> {dst_ip}). This is a common C2 indicator: attackers run HTTP C2 on random ports to avoid firewall rules."),
                src_ip, dst_ip, dst_port, now,
                Severity::High,
            ) {
                incidents.push(inc);
            }
        }

        // SSH on non-standard port
        if app_proto == "ssh" && dst_port != 22 {
            if let Some(inc) = self.emit(
                AnomalyType::SshNonStandardPort,
                &format!("SSH on port {dst_port}"),
                &format!("SSH protocol detected on non-standard port {dst_port} ({src_ip} -> {dst_ip}). Could be legitimate (custom SSH port) or C2/tunneling."),
                src_ip, dst_ip, dst_port, now,
                Severity::Medium,
            ) {
                incidents.push(inc);
            }
        }

        // SMB on non-standard port (lateral movement on non-445)
        if app_proto == "smb" && dst_port != 445 && dst_port != 139 {
            if let Some(inc) = self.emit(
                AnomalyType::SmbNonStandardPort,
                &format!("SMB on port {dst_port}"),
                &format!("SMB protocol detected on non-standard port {dst_port} ({src_ip} -> {dst_ip}). Possible lateral movement attempt on a non-default port to evade firewall rules."),
                src_ip, dst_ip, dst_port, now,
                Severity::High,
            ) {
                incidents.push(inc);
            }
        }

        // ── HTTP-specific anomalies ──
        if event.kind == "tcp_stream.http" {
            let uri = event
                .details
                .get("uri")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let _method = event
                .details
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let _user_agent = event
                .details
                .get("user_agent")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let client_bytes = event
                .details
                .get("client_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let _server_bytes = event
                .details
                .get("server_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            // Double encoding: %25xx patterns (evasion technique)
            if uri.contains("%25") || uri.contains("%252f") || uri.contains("%252e") {
                if let Some(inc) = self.emit(
                    AnomalyType::HttpDoubleEncoding,
                    "HTTP double encoding in URI",
                    &format!("URI contains double-encoded characters (%25xx): {uri}. This is a common WAF evasion technique used to hide path traversal or injection payloads."),
                    src_ip, dst_ip, dst_port, now,
                    Severity::High,
                ) {
                    incidents.push(inc);
                }
            }

            // Request smuggling indicators: conflicting Content-Length and Transfer-Encoding
            for signal in &signals {
                if signal.contains("smuggling") {
                    if let Some(inc) = self.emit(
                        AnomalyType::HttpRequestSmuggling,
                        "HTTP request smuggling indicator",
                        &format!("Request from {src_ip} shows request smuggling indicators: {signal}. This can allow bypassing security controls."),
                        src_ip, dst_ip, dst_port, now,
                        Severity::Critical,
                    ) {
                        incidents.push(inc);
                    }
                }
            }

            // Oversized URI (potential buffer overflow attempt)
            if uri.len() > 8192 {
                if let Some(inc) = self.emit(
                    AnomalyType::HttpOversizedHeaders,
                    &format!("HTTP oversized URI ({} bytes)", uri.len()),
                    &format!("HTTP request from {src_ip} has an unusually large URI ({} bytes). This may be a buffer overflow attempt or fuzzing probe.", uri.len()),
                    src_ip, dst_ip, dst_port, now,
                    Severity::High,
                ) {
                    incidents.push(inc);
                }
            }

            // Slow connection (slow loris detection)
            let duration_ms = event
                .details
                .get("duration_ms")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            if duration_ms > 30_000 && client_bytes < 500 {
                if let Some(inc) = self.emit(
                    AnomalyType::SlowConnection,
                    "Slow HTTP connection (possible slowloris)",
                    &format!("HTTP connection from {src_ip} lasted {:.0}s but sent only {client_bytes} bytes. This pattern matches slowloris-style DoS attacks.", duration_ms as f64 / 1000.0),
                    src_ip, dst_ip, dst_port, now,
                    Severity::Medium,
                ) {
                    incidents.push(inc);
                }
            }
        }

        // ── SSH anomalies ──
        if event.kind == "tcp_stream.ssh" {
            let client_version = event
                .details
                .get("client_version")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // Malformed SSH version — remote client sent an invalid protocol
            // handshake. sshd rejects at TCP level before any auth attempt.
            // Severity Low: the "attack" failed before it started — no
            // credentials tested, no shell obtained, no data read.
            // High/Critical is reserved for threats that got past the
            // protocol handshake. Observed 2026-04-12: 15/day from random
            // bots, all showing as "High — needs attention" for a non-event.
            if !client_version.is_empty()
                && !client_version.starts_with("SSH-2.0-")
                && !client_version.starts_with("SSH-1.")
            {
                if let Some(inc) = self.emit(
                    AnomalyType::SshVersionAnomaly,
                    "Malformed SSH version string",
                    &format!("SSH client from {src_ip} sent malformed version: '{client_version}'. Scanner or exploit tool that failed at protocol level — no authentication attempted."),
                    src_ip, dst_ip, dst_port, now,
                    Severity::Low,
                ) {
                    incidents.push(inc);
                }
            }
        }

        incidents
    }

    #[allow(clippy::too_many_arguments)]
    fn emit(
        &mut self,
        anomaly_type: AnomalyType,
        title: &str,
        summary: &str,
        src_ip: &str,
        dst_ip: &str,
        dst_port: u16,
        now: DateTime<Utc>,
        severity: Severity,
    ) -> Option<Incident> {
        let key = format!("{:?}:{}:{}", anomaly_type, src_ip, dst_port);

        if let Some(&last) = self.alerted.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.alerted.insert(key, now);

        if self.alerted.len() > 1000 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, t| *t > cutoff);
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "proto_anomaly:{:?}:{}:{}",
                anomaly_type,
                src_ip,
                now.format("%Y-%m-%dT%H:%MZ")
            ),
            severity,
            title: title.to_string(),
            summary: summary.to_string(),
            evidence: serde_json::json!({
                "anomaly_type": format!("{:?}", anomaly_type),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
            }),
            recommended_checks: vec![
                format!("Investigate traffic from {src_ip} to port {dst_port}"),
                "Check if this is a known service on a non-standard port".into(),
                "Correlate with other anomalies from the same source".into(),
            ],
            tags: vec![
                "protocol_anomaly".into(),
                format!("{:?}", anomaly_type).to_lowercase(),
            ],
            entities: vec![EntityRef::ip(src_ip.to_string())],
        })
    }
}

fn is_http_port(port: u16) -> bool {
    matches!(
        port,
        80 | 443 | 8080 | 8443 | 8000 | 8888 | 3000 | 5000 | 8787 | 9090 | 3128
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stream_event(kind: &str, details: serde_json::Value) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "tcp_stream".into(),
            kind: kind.into(),
            severity: Severity::Info,
            summary: String::new(),
            details,
            tags: Vec::new(),
            entities: Vec::new(),
        }
    }

    #[test]
    fn test_http_on_non_standard_port() {
        let mut det = ProtoAnomalyDetector::new("host1", 300);
        let ev = make_stream_event(
            "tcp_stream.http",
            serde_json::json!({
                "app_proto": "http",
                "src_ip": "1.2.3.4",
                "dst_ip": "10.0.0.1",
                "dst_port": 4444,
                "signals": [],
            }),
        );
        let incidents = det.process(&ev);
        assert_eq!(incidents.len(), 1);
        assert!(incidents[0].title.contains("HTTP on port 4444"));
        assert_eq!(incidents[0].severity, Severity::High);
    }

    #[test]
    fn test_http_on_standard_port_no_alert() {
        let mut det = ProtoAnomalyDetector::new("host1", 300);
        let ev = make_stream_event(
            "tcp_stream.http",
            serde_json::json!({
                "app_proto": "http",
                "src_ip": "1.2.3.4",
                "dst_ip": "10.0.0.1",
                "dst_port": 80,
                "signals": [],
            }),
        );
        let incidents = det.process(&ev);
        assert!(incidents.is_empty());
    }

    #[test]
    fn test_double_encoding() {
        let mut det = ProtoAnomalyDetector::new("host1", 300);
        let ev = make_stream_event(
            "tcp_stream.http",
            serde_json::json!({
                "app_proto": "http",
                "src_ip": "1.2.3.4",
                "dst_ip": "10.0.0.1",
                "dst_port": 80,
                "uri": "/admin%252f..%252f..%252fetc/passwd",
                "method": "GET",
                "user_agent": "curl",
                "client_bytes": 200,
                "server_bytes": 500,
                "signals": [],
            }),
        );
        let incidents = det.process(&ev);
        assert!(incidents
            .iter()
            .any(|i| i.title.contains("double encoding")));
    }

    #[test]
    fn test_smb_non_standard_port() {
        let mut det = ProtoAnomalyDetector::new("host1", 300);
        let ev = make_stream_event(
            "tcp_stream.smb",
            serde_json::json!({
                "app_proto": "smb",
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.10",
                "dst_port": 8445,
                "signals": [],
            }),
        );
        let incidents = det.process(&ev);
        assert!(incidents.iter().any(|i| i.title.contains("SMB on port")));
    }

    #[test]
    fn test_ssh_malformed_version() {
        let mut det = ProtoAnomalyDetector::new("host1", 300);
        let ev = make_stream_event(
            "tcp_stream.ssh",
            serde_json::json!({
                "app_proto": "ssh",
                "src_ip": "1.2.3.4",
                "dst_ip": "10.0.0.1",
                "dst_port": 22,
                "client_version": "EXPLOIT-TOOL-v1",
                "signals": [],
            }),
        );
        let incidents = det.process(&ev);
        assert!(incidents.iter().any(|i| i.title.contains("Malformed SSH")));
    }

    #[test]
    fn test_cooldown() {
        let mut det = ProtoAnomalyDetector::new("host1", 300);
        let ev = make_stream_event(
            "tcp_stream.http",
            serde_json::json!({
                "app_proto": "http",
                "src_ip": "1.2.3.4",
                "dst_ip": "10.0.0.1",
                "dst_port": 4444,
                "signals": [],
            }),
        );
        assert_eq!(det.process(&ev).len(), 1);
        assert_eq!(det.process(&ev).len(), 0); // cooldown
    }

    #[test]
    fn test_ignores_non_stream_events() {
        let mut det = ProtoAnomalyDetector::new("host1", 300);
        let ev = Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "auth_log".into(),
            kind: "ssh.login_failed".into(),
            severity: Severity::Info,
            summary: String::new(),
            details: serde_json::json!({}),
            tags: Vec::new(),
            entities: Vec::new(),
        };
        assert!(det.process(&ev).is_empty());
    }
}
