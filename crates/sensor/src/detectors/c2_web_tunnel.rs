//! Web-tunnel C2 detection (spec 050-PR3).
//!
//! Catches the operator-friendly tunneling tools attackers love
//! because they punch through NAT/firewalls without infrastructure:
//! `ngrok`, `cloudflared` (tunnel mode), `localtunnel`, `pinggy`,
//! `bore`, `serveo`, `frpc`.
//!
//! Two detection paths:
//!   1. `shell.command_exec` of one of the tunneling binaries.
//!   2. `dns.query` for a known tunnel-service domain — catches
//!      the tunneled session even when the binary was renamed.
//!
//! Anti-FP gates:
//!   - `cloudflared` running as the `cloudflared.service` systemd
//!     unit silenced via operator allowlist `[detectors.c2_web_tunnel]`
//!     (operators who legitimately deploy Cloudflare tunnels must
//!     add `cloudflared` there).
//!
//! MITRE: T1572 (Protocol Tunneling) / T1090.003 (Multi-hop Proxy).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

const TUNNEL_BINARIES: &[&str] = &[
    "ngrok",
    "cloudflared",
    "localtunnel",
    "lt", // localtunnel CLI shorthand
    "pinggy",
    "bore",
    "serveo",
    "frpc",
    "frps",
    "chisel",
    "gost",
];

/// Suffix-match against the FQDN in the DNS query. Order matters —
/// longer / more-specific suffixes are checked first by virtue of
/// being checked via `ends_with` per entry.
const TUNNEL_DOMAIN_SUFFIXES: &[&str] = &[
    ".devtunnels.ms",
    ".trycloudflare.com",
    ".ngrok-free.app",
    ".ngrok.io",
    ".ngrok.app",
    ".serveo.net",
    ".localtunnel.me",
    ".loca.lt",
    ".pinggy.io",
    ".pinggy.link",
    ".bore.pub",
    ".lhr.life",
];

pub struct C2WebTunnelDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl C2WebTunnelDetector {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            last_fired: HashMap::new(),
            cooldown: Duration::seconds(600),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        match event.kind.as_str() {
            "shell.command_exec" | "process.exec" => self.process_exec(event),
            "dns.query" => self.process_dns(event),
            _ => None,
        }
    }

    fn process_exec(&mut self, event: &Event) -> Option<Incident> {
        let argv0 = event
            .details
            .get("argv")
            .and_then(|v| v.get(0))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let argv0_base = argv0.split('/').next_back().unwrap_or(argv0);
        if !is_tunnel_binary(argv0_base) {
            return None;
        }
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let command = event
            .details
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        self.emit(
            event,
            "exec",
            argv0_base,
            comm,
            parent_comm,
            command,
            pid,
            uid,
        )
    }

    fn process_dns(&mut self, event: &Event) -> Option<Incident> {
        let qname = event
            .details
            .get("query")
            .or_else(|| event.details.get("name"))
            .or_else(|| event.details.get("domain"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let qname = qname.trim_end_matches('.').to_lowercase();
        if qname.is_empty() {
            return None;
        }
        if !TUNNEL_DOMAIN_SUFFIXES.iter().any(|s| qname.ends_with(*s)) {
            return None;
        }
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        self.emit(event, "dns", &qname, comm, "", &qname, pid, uid)
    }

    #[allow(clippy::too_many_arguments)]
    fn emit(
        &mut self,
        event: &Event,
        sub_kind: &str,
        target: &str,
        comm: &str,
        parent_comm: &str,
        command: &str,
        pid: u64,
        uid: u64,
    ) -> Option<Incident> {
        let now = event.ts;
        let key = format!("{sub_kind}:{target}");
        if let Some(&last) = self.last_fired.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.last_fired.insert(key.clone(), now);
        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "c2_web_tunnel:{sub_kind}:{}:{}",
                target,
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity: Severity::Critical,
            title: format!("Web-tunnel C2 indicator ({sub_kind}): {target}"),
            summary: format!(
                "Sub-detector `{sub_kind}` matched target `{target}` (comm=`{comm}`, \
                 parent_comm=`{parent_comm}`, pid={pid}, uid={uid}, command=`{command}`). \
                 Operator-friendly tunneling tools are a common C2 channel; the same \
                 binary that lets a developer expose a local port to the internet lets \
                 an attacker exfiltrate over an attacker-controlled relay (T1572)."
            ),
            evidence: serde_json::json!([{
                "kind": "c2_web_tunnel",
                "sub_kind": sub_kind,
                "target": target,
                "comm": comm,
                "parent_comm": parent_comm,
                "command": command,
                "pid": pid,
                "uid": uid,
                "mitre": ["T1572", "T1090.003"],
            }]),
            recommended_checks: vec![
                format!("Inspect process tree: pstree -p {pid}"),
                "If the operator legitimately runs Cloudflare tunnels / ngrok, allowlist via [detectors.c2_web_tunnel]".to_string(),
                "Correlate with the host's outbound connections in the last 5 minutes".to_string(),
            ],
            tags: vec!["c2".to_string(), "tunnel".to_string()],
            entities: vec![],
        })
    }
}

fn is_tunnel_binary(base: &str) -> bool {
    TUNNEL_BINARIES.contains(&base)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_event(argv0_path: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: format!("exec {argv0_path}"),
            details: serde_json::json!({
                "pid": 4242,
                "uid": 1000,
                "ppid": 4241,
                "comm": "bash",
                "parent_comm": "bash",
                "command": argv0_path,
                "argv": [argv0_path],
                "argc": 1,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    fn dns_event(qname: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "dns_capture".into(),
            kind: "dns.query".into(),
            severity: Severity::Info,
            summary: format!("dns query {qname}"),
            details: serde_json::json!({
                "query": qname,
                "pid": 4242,
                "uid": 1000,
                "comm": "curl",
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_known_tunnel_binaries() {
        for bin in [
            "/usr/local/bin/ngrok",
            "cloudflared",
            "/usr/bin/bore",
            "frpc",
            "chisel",
        ] {
            let mut det = C2WebTunnelDetector::new("test");
            assert!(det.process(&exec_event(bin)).is_some(), "{bin} should fire");
        }
    }

    #[test]
    fn fires_on_dns_query_to_tunnel_suffix() {
        for q in [
            "abcd1234.ngrok-free.app",
            "deadbeef.trycloudflare.com",
            "user42.serveo.net",
            "x.loca.lt",
            "y.pinggy.io",
        ] {
            let mut det = C2WebTunnelDetector::new("test");
            assert!(det.process(&dns_event(q)).is_some(), "{q} should fire");
        }
    }

    #[test]
    fn ignores_unrelated_binaries() {
        let mut det = C2WebTunnelDetector::new("test");
        for bin in ["ssh", "scp", "curl", "wget"] {
            assert!(
                det.process(&exec_event(bin)).is_none(),
                "{bin} should not fire"
            );
        }
    }

    #[test]
    fn ignores_unrelated_dns() {
        let mut det = C2WebTunnelDetector::new("test");
        for q in [
            "google.com",
            "github.com",
            "innerwarden.com",
            "cdn.example.org",
        ] {
            assert!(det.process(&dns_event(q)).is_none());
        }
    }

    #[test]
    fn dns_suffix_match_is_anchored() {
        // Attacker-controlled domain that ENDs with "ngrok-free.app"
        // legitimately is what we want to catch. But a string that just
        // CONTAINS "ngrok" without the full suffix must NOT fire.
        let mut det = C2WebTunnelDetector::new("test");
        assert!(det
            .process(&dns_event("ngrok-impostor-domain.com"))
            .is_none());
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = C2WebTunnelDetector::new("test");
        let ev = exec_event("ngrok");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(30);
        assert!(det.process(&ev2).is_none());
    }
}
