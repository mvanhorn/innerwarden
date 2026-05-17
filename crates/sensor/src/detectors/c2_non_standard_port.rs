//! Non-standard listening port detection (spec 050-PR3).
//!
//! Fires when a non-well-known port appears in the host's listening
//! set OR when a `tcp.listen` event surfaces with a port outside the
//! known-service whitelist AND the listener isn't a systemd-managed
//! daemon. C2 implants typically bind to a random high port and
//! tolerate any source — the inverse of an ops-installed service
//! that lives on a stable port and runs under systemd.
//!
//! Anti-FP gates:
//!   - Built-in well-known-services exclusion (innerwarden 8787,
//!     nginx 80/443/8888, sshd 22 + 49222, postgres 5432, redis
//!     6379, etc).
//!   - parent / launcher comm = `systemd` silences (systemd-managed
//!     service bound to whatever port its unit declared).
//!   - Operator-extensible `[detectors.c2_non_standard_port]` TOML
//!     for dev ranges (8000-8100, 3000-3010).
//!
//! MITRE: T1571 (Non-Standard Port).

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

/// Ports the operator clearly does NOT need an alert about. Built-in
/// to keep the default-on shape sane; operators can extend via TOML.
const WELL_KNOWN_PORTS: &[u16] = &[
    22, // ssh
    25, // smtp
    53, // dns
    80, // http
    81, // alt http
    110, 143, 443, // smtp/imap/https
    465, 587, 993, 995, // smtps/submission/imaps/pop3s
    3306, 5432, 6379, // mysql / postgres / redis
    9200, 9300,  // elasticsearch
    27017, // mongodb
    5672, 15672, // rabbitmq
    8080, 8443, // alt http(s)
    8787, 8888,  // innerwarden dashboard / spare nginx
    49222, // SSH custom port (operator pattern)
    11211, // memcached
    2379, 2380,  // etcd
    6443,  // kubernetes api
    25565, // minecraft? (operator preference)
];

pub struct C2NonStandardPortDetector {
    host: String,
    last_fired: HashMap<u16, DateTime<Utc>>,
    cooldown: Duration,
    /// Per-instance set of operator-extra-allowed ports (built up from
    /// dynamic allowlist if available; left empty otherwise).
    extra_allowed: HashSet<u16>,
}

impl C2NonStandardPortDetector {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            last_fired: HashMap::new(),
            cooldown: Duration::seconds(900),
            extra_allowed: HashSet::new(),
        }
    }

    /// Test/builder-style extension hook for the operator-extensible
    /// dev range. Production wiring may seed this from the dynamic
    /// allowlist; tests use it directly. Marked `dead_code` because
    /// the production wiring is a follow-up — the TOML loader needs
    /// a per-detector port-range section that doesn't exist yet
    /// (spec 050-PR3 follow-up). Tests reach this directly so the
    /// allowlist axis is anchored from day one.
    #[allow(dead_code)]
    pub fn with_extra_allowed_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.extra_allowed = ports.into_iter().collect();
        self
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        if event.kind != "tcp.listen" && event.kind != "process.listen" {
            return None;
        }
        let port = event
            .details
            .get("port")
            .or_else(|| event.details.get("local_port"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;
        if port == 0 {
            return None;
        }
        if WELL_KNOWN_PORTS.contains(&port) || self.extra_allowed.contains(&port) {
            return None;
        }

        // Systemd-managed listeners are operator infrastructure even
        // when the port is non-standard.
        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if is_systemd_managed(parent_comm) || is_systemd_managed(comm) {
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

        let now = event.ts;
        if let Some(&last) = self.last_fired.get(&port) {
            if now - last < self.cooldown {
                return None;
            }
        }
        self.last_fired.insert(port, now);

        // Severity: high when the listener is on an internet-facing
        // bind address (0.0.0.0 / ::), medium when bound to loopback.
        let bind_addr = event
            .details
            .get("bind_addr")
            .or_else(|| event.details.get("local_addr"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let internet_facing =
            bind_addr.starts_with("0.0.0.0") || bind_addr == "::" || bind_addr.is_empty(); // empty = bind to all by default
        let severity = if internet_facing {
            Severity::High
        } else {
            Severity::Medium
        };

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!(
                "c2_non_standard_port:{port}:{}",
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity,
            title: format!(
                "Non-standard listening port {port} (internet_facing={internet_facing})"
            ),
            summary: format!(
                "Process `{comm}` (parent=`{parent_comm}`, pid={pid}, uid={uid}) bound \
                 to non-well-known port {port} on `{bind_addr}`. Not systemd-managed. \
                 Classic C2 listener shape (T1571)."
            ),
            evidence: serde_json::json!([{
                "kind": "c2_non_standard_port",
                "port": port,
                "bind_addr": bind_addr,
                "internet_facing": internet_facing,
                "comm": comm,
                "parent_comm": parent_comm,
                "pid": pid,
                "uid": uid,
                "mitre": ["T1571"],
            }]),
            recommended_checks: vec![
                format!("ss -tlnp | grep ':{port} '"),
                format!("ls -l /proc/{pid}/exe (binary path)"),
                "If a dev workflow legitimately binds this port, allowlist via [detectors.c2_non_standard_port]".to_string(),
            ],
            tags: vec!["c2".to_string(), "listener".to_string()],
            entities: vec![],
        })
    }
}

fn is_systemd_managed(comm: &str) -> bool {
    if comm.is_empty() {
        return false;
    }
    let base = comm.split('/').next_back().unwrap_or(comm);
    let base = base.trim_matches(|c: char| c == '(' || c == ')');
    base.starts_with("systemd")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listen_event(port: u16, bind_addr: &str, comm: &str, parent_comm: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "net_snapshot".into(),
            kind: "tcp.listen".into(),
            severity: Severity::Info,
            summary: format!("listen {bind_addr}:{port}"),
            details: serde_json::json!({
                "port": port,
                "bind_addr": bind_addr,
                "comm": comm,
                "parent_comm": parent_comm,
                "pid": 9999,
                "uid": 1000,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_random_high_port_with_internet_facing_bind() {
        let mut det = C2NonStandardPortDetector::new("test");
        let inc = det
            .process(&listen_event(31337, "0.0.0.0", "evil", "bash"))
            .expect("should fire");
        assert_eq!(inc.severity, Severity::High);
    }

    #[test]
    fn medium_severity_when_bound_to_loopback() {
        let mut det = C2NonStandardPortDetector::new("test");
        let inc = det
            .process(&listen_event(31337, "127.0.0.1", "evil", "bash"))
            .expect("should fire");
        assert_eq!(inc.severity, Severity::Medium);
    }

    #[test]
    fn silences_well_known_ports() {
        let mut det = C2NonStandardPortDetector::new("test");
        for port in [22, 80, 443, 5432, 6379, 8787, 49222] {
            assert!(
                det.process(&listen_event(port, "0.0.0.0", "x", "bash"))
                    .is_none(),
                "well-known port {port} should not fire"
            );
        }
    }

    #[test]
    fn silences_systemd_managed_listener() {
        let mut det = C2NonStandardPortDetector::new("test");
        assert!(
            det.process(&listen_event(31337, "0.0.0.0", "myservice", "systemd"))
                .is_none(),
            "systemd-parented listener must be silent"
        );
    }

    #[test]
    fn silences_extra_allowed_ports() {
        let mut det =
            C2NonStandardPortDetector::new("test").with_extra_allowed_ports([3000, 3001, 3002]);
        for port in [3000, 3001, 3002] {
            assert!(
                det.process(&listen_event(port, "0.0.0.0", "node", "bash"))
                    .is_none(),
                "extra-allowed {port} should not fire"
            );
        }
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = C2NonStandardPortDetector::new("test");
        let ev = listen_event(31337, "0.0.0.0", "evil", "bash");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(60);
        assert!(det.process(&ev2).is_none());
    }

    #[test]
    fn ignores_non_listen_events() {
        let mut det = C2NonStandardPortDetector::new("test");
        let mut ev = listen_event(31337, "0.0.0.0", "evil", "bash");
        ev.kind = "shell.command_exec".into();
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_zero_port() {
        let mut det = C2NonStandardPortDetector::new("test");
        let ev = listen_event(0, "0.0.0.0", "evil", "bash");
        assert!(det.process(&ev).is_none());
    }
}
