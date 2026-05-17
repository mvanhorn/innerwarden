//! Screen capture detection (spec 050-PR2).
//!
//! Fires on exec of common screenshot/screen-grab tools on a
//! production server. Like clipboard reading, a headless box should
//! never need to capture its own screen — when it happens, it's a
//! collection-stage signal.
//!
//! Anti-FP gates:
//!   - Parent comm in `{Xorg, Xwayland, gnome-shell, kwin, sway}` →
//!     silenced (the compositor itself reading framebuffer for
//!     normal display is expected).
//!   - Operator-extensible `[detectors.screen_capture]` TOML.
//!
//! MITRE: T1113 (Screen Capture).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

const SCREENSHOT_COMMS: &[&str] = &[
    "scrot",
    "gnome-screenshot",
    "import",
    "xwd",
    "grim",
    "flameshot",
    "spectacle",
    "shutter",
    "ksnip",
    "maim",
];

const DISPLAY_SERVER_PARENTS: &[&str] = &[
    "Xorg",
    "Xwayland",
    "gnome-shell",
    "kwin",
    "kwin_x11",
    "kwin_wayland",
    "sway",
    "mutter",
    "weston",
];

pub struct ScreenCaptureDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl ScreenCaptureDetector {
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
        let argv0 = event
            .details
            .get("argv")
            .and_then(|v| v.get(0))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let argv0_base = argv0.split('/').next_back().unwrap_or(argv0);
        if !is_screenshot_comm(argv0_base) {
            return None;
        }
        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if is_display_server_parent(parent_comm) {
            return None;
        }
        let uid = event
            .details
            .get("uid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let command = event
            .details
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let key = format!("{uid}:{argv0_base}");
        let now = event.ts;
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
                "screen_capture:{}:{}",
                argv0_base,
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity: Severity::High,
            title: format!("Screen capture tool exec on host: {}", argv0_base),
            summary: format!(
                "Process `{argv0_base}` (launched by `{comm}`, pid={pid}, uid={uid}) — `{command}`. \
                 Headless / production servers should not be capturing their own screen."
            ),
            evidence: serde_json::json!([{
                "kind": "screen_capture",
                "screenshot_tool": argv0_base,
                "launcher_comm": comm,
                "parent_comm": parent_comm,
                "uid": uid,
                "pid": pid,
                "command": command,
                "mitre": ["T1113"],
            }]),
            recommended_checks: vec![
                format!("Inspect process tree of pid {pid}: pstree -p {pid}"),
                "If a graphical session legitimately runs on this host, allowlist via [detectors.screen_capture]".to_string(),
            ],
            tags: vec!["collection".to_string(), "screen_capture".to_string()],
            entities: vec![],
        })
    }
}

fn is_screenshot_comm(base: &str) -> bool {
    SCREENSHOT_COMMS.contains(&base)
}

fn is_display_server_parent(parent_comm: &str) -> bool {
    if parent_comm.is_empty() {
        return false;
    }
    let base = parent_comm.split('/').next_back().unwrap_or(parent_comm);
    let base = base.trim_matches(|c: char| c == '(' || c == ')');
    DISPLAY_SERVER_PARENTS.iter().any(|p| base.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(argv0_path: &str, parent_comm: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: format!("Shell command executed: {argv0_path}"),
            details: serde_json::json!({
                "pid": 4242,
                "uid": 1000,
                "ppid": 4241,
                "comm": "sudo",
                "parent_comm": parent_comm,
                "command": argv0_path,
                "argv": [argv0_path],
                "argc": 1,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_known_screenshot_tools() {
        for tool in [
            "scrot",
            "gnome-screenshot",
            "grim",
            "flameshot",
            "maim",
            "/usr/bin/scrot",
        ] {
            let mut det = ScreenCaptureDetector::new("test");
            assert!(
                det.process(&make_event(tool, "bash")).is_some(),
                "{tool} should fire"
            );
        }
    }

    #[test]
    fn silences_when_parent_is_compositor() {
        for parent in ["Xorg", "Xwayland", "gnome-shell", "kwin", "sway", "mutter"] {
            let mut det = ScreenCaptureDetector::new("test");
            assert!(
                det.process(&make_event("scrot", parent)).is_none(),
                "parent={parent} should silence"
            );
        }
    }

    #[test]
    fn ignores_unrelated_binaries() {
        let mut det = ScreenCaptureDetector::new("test");
        for tool in ["bash", "vim", "cat", "ls", "nmap"] {
            assert!(det.process(&make_event(tool, "bash")).is_none());
        }
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = ScreenCaptureDetector::new("test");
        let ev = make_event("/usr/bin/scrot", "bash");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(30);
        assert!(det.process(&ev2).is_none());
    }

    #[test]
    fn ignores_non_exec_events() {
        let mut det = ScreenCaptureDetector::new("test");
        let mut ev = make_event("scrot", "bash");
        ev.kind = "network.outbound_connect".into();
        assert!(det.process(&ev).is_none());
    }
}
