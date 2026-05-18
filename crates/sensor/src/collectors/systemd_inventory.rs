//! Systemd unit inventory collector.
//!
//! Baselines all enabled/running systemd units at startup and polls
//! for new units. Detects persistence mechanisms that existed before
//! InnerWarden was installed, or units loaded from suspicious paths.

use std::collections::HashSet;

use chrono::Utc;
use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};
use tokio::sync::mpsc;
use tracing::info;

/// Suspicious paths for systemd unit files.
const SUSPICIOUS_UNIT_PATHS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/"];

#[derive(Debug, Clone)]
struct SystemdUnit {
    name: String,
    load_state: String,
    active_state: String,
    sub_state: String,
    fragment_path: String,
}

pub async fn run(tx: mpsc::Sender<Event>, host_id: String, interval_secs: u64) {
    info!("systemd_inventory: starting (interval: {interval_secs}s)");

    // Build baseline
    let mut baseline: HashSet<String> = HashSet::new();
    let initial = list_systemd_units();
    for unit in &initial {
        baseline.insert(unit.name.clone());
    }
    info!("systemd_inventory: baseline {} units", baseline.len());

    // Check existing units for suspicious paths on first run
    for unit in &initial {
        if is_suspicious_path(&unit.fragment_path) {
            let event = build_event(
                unit,
                "suspicious_existing_unit",
                Severity::High,
                &host_id,
                &format!(
                    "Existing systemd unit '{}' loaded from suspicious path: {}",
                    unit.name, unit.fragment_path
                ),
            );
            let _ = tx.send(event).await;
        }
    }

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

        let current = list_systemd_units();

        for unit in &current {
            if baseline.contains(&unit.name) {
                continue;
            }

            baseline.insert(unit.name.clone());

            let in_suspicious = is_suspicious_path(&unit.fragment_path);

            let severity = if in_suspicious {
                Severity::Critical
            } else {
                Severity::High
            };

            let event = build_event(
                unit,
                "new_systemd_unit",
                severity,
                &host_id,
                &format!(
                    "New systemd unit detected: {} (state: {}/{}, path: {})",
                    unit.name, unit.active_state, unit.sub_state, unit.fragment_path
                ),
            );

            let _ = tx.send(event).await;
        }
    }
}

fn build_event(
    unit: &SystemdUnit,
    action: &str,
    severity: Severity,
    host_id: &str,
    summary: &str,
) -> Event {
    Event {
        ts: Utc::now(),
        host: host_id.to_string(),
        source: "systemd_inventory".into(),
        kind: format!("system.{action}"),
        severity,
        summary: summary.to_string(),
        details: serde_json::json!({
            "action": action,
            "unit_name": unit.name,
            "load_state": unit.load_state,
            "active_state": unit.active_state,
            "sub_state": unit.sub_state,
            "fragment_path": unit.fragment_path,
            "suspicious_path": is_suspicious_path(&unit.fragment_path),
        }),
        tags: vec!["systemd".into(), "inventory".into(), "persistence".into()],
        entities: vec![EntityRef::service(unit.name.clone())],
    }
}

fn is_suspicious_path(path: &str) -> bool {
    SUSPICIOUS_UNIT_PATHS.iter().any(|p| path.starts_with(p))
}

fn list_systemd_units() -> Vec<SystemdUnit> {
    let output = match std::process::Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--all",
            "--no-pager",
            "--plain",
            "--no-legend",
        ])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    parse_systemd_units(&text, get_unit_path)
}

fn parse_systemd_units(text: &str, fragment_path_for: impl Fn(&str) -> String) -> Vec<SystemdUnit> {
    let mut units = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("UNIT ") || line.contains(" loaded units listed") {
            continue;
        }

        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        let name = fields[0].to_string();
        let load_state = fields[1].to_string();
        let active_state = fields[2].to_string();
        let sub_state = fields[3].to_string();

        let fragment_path = fragment_path_for(&name);

        units.push(SystemdUnit {
            name,
            load_state,
            active_state,
            sub_state,
            fragment_path,
        });
    }

    units
}

fn get_unit_path(unit_name: &str) -> String {
    let output = std::process::Command::new("systemctl")
        .args(["show", "-p", "FragmentPath", "--value", unit_name])
        .output();

    match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicious_paths() {
        assert!(is_suspicious_path("/tmp/evil.service"));
        assert!(is_suspicious_path("/var/tmp/payload.service"));
        assert!(is_suspicious_path("/dev/shm/backdoor.service"));
        assert!(is_suspicious_path(
            "/home/user/.config/systemd/user/mal.service"
        ));
        assert!(is_suspicious_path(
            "/root/.config/systemd/user/rootkit.service"
        ));
        assert!(!is_suspicious_path("/tmpdir/legit.service"));
        assert!(!is_suspicious_path("/etc/systemd/system/nginx.service"));
        assert!(!is_suspicious_path("/usr/lib/systemd/system/sshd.service"));
    }

    fn parse_fixture(text: &str) -> Vec<SystemdUnit> {
        parse_systemd_units(text, |name| format!("/usr/lib/systemd/system/{name}"))
    }

    #[test]
    fn parse_systemd_units_empty_input_returns_empty() {
        assert!(parse_fixture("").is_empty());
    }

    #[test]
    fn parse_systemd_units_single_line() {
        let units = parse_fixture("ssh.service loaded active running OpenSSH server daemon\n");

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "ssh.service");
        assert_eq!(units[0].load_state, "loaded");
        assert_eq!(units[0].active_state, "active");
        assert_eq!(units[0].sub_state, "running");
        assert_eq!(
            units[0].fragment_path,
            "/usr/lib/systemd/system/ssh.service"
        );
    }

    #[test]
    fn parse_systemd_units_realistic_multiline_fixture() {
        let units = parse_fixture(
            "\
UNIT                         LOAD   ACTIVE SUB     DESCRIPTION
ssh.service                  loaded active running OpenSSH server daemon
docker.service               loaded active running Docker Application Container Engine
fail2ban.service             loaded active exited  Fail2Ban Service
3 loaded units listed.
",
        );

        let names: Vec<&str> = units.iter().map(|unit| unit.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["ssh.service", "docker.service", "fail2ban.service"]
        );
    }

    #[test]
    fn parse_systemd_units_accepts_unit_without_description() {
        let units = parse_fixture("minimal.service loaded inactive dead\n");

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "minimal.service");
        assert_eq!(units[0].sub_state, "dead");
    }

    #[test]
    fn parse_systemd_units_unicode_description_survives_parsing() {
        let units = parse_fixture("backup.service loaded active running Cópia diária\n");

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "backup.service");
        assert_eq!(units[0].active_state, "active");
    }

    #[test]
    fn parse_systemd_units_skips_malformed_rows() {
        let units = parse_fixture(
            "\
not-enough columns
network.service loaded active running Network Manager
",
        );

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "network.service");
    }

    #[test]
    fn test_build_event() {
        let unit = SystemdUnit {
            name: "malicious.service".to_string(),
            load_state: "loaded".to_string(),
            active_state: "active".to_string(),
            sub_state: "running".to_string(),
            fragment_path: "/tmp/malicious.service".to_string(),
        };

        let event = build_event(
            &unit,
            "suspicious_existing_unit",
            Severity::Critical,
            "host123",
            "Found malicious service",
        );

        assert_eq!(event.host, "host123");
        assert_eq!(event.source, "systemd_inventory");
        assert_eq!(event.kind, "system.suspicious_existing_unit");
        assert_eq!(event.severity, Severity::Critical);
        assert_eq!(event.summary, "Found malicious service");
        assert_eq!(event.tags, vec!["systemd", "inventory", "persistence"]);

        let entities = event.entities;
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].value, "malicious.service");

        let details = event.details;
        assert_eq!(details["action"], "suspicious_existing_unit");
        assert_eq!(details["unit_name"], "malicious.service");
        assert_eq!(details["load_state"], "loaded");
        assert_eq!(details["active_state"], "active");
        assert_eq!(details["sub_state"], "running");
        assert_eq!(details["fragment_path"], "/tmp/malicious.service");
        assert_eq!(details["suspicious_path"], true);
    }

    #[test]
    fn build_event_marks_non_suspicious_unit_details() {
        let unit = SystemdUnit {
            name: "nginx.service".to_string(),
            load_state: "loaded".to_string(),
            active_state: "inactive".to_string(),
            sub_state: "dead".to_string(),
            fragment_path: "/etc/systemd/system/nginx.service".to_string(),
        };

        let event = build_event(
            &unit,
            "new_systemd_unit",
            Severity::High,
            "host456",
            "New unit",
        );

        assert_eq!(event.kind, "system.new_systemd_unit");
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.details["unit_name"], "nginx.service");
        assert_eq!(event.details["active_state"], "inactive");
        assert_eq!(event.details["sub_state"], "dead");
        assert_eq!(event.details["suspicious_path"], false);
        assert_eq!(event.entities[0].value, "nginx.service");
    }
}
