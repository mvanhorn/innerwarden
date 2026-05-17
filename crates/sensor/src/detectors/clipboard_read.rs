//! Clipboard read detection (spec 050-PR2).
//!
//! Fires when a process execs `xclip`, `xsel`, `wl-paste`, or
//! `pbpaste` on a host that has no business reading the clipboard
//! (production server, container, headless box). Clipboard exfiltration
//! is a low-noise data theft vector — attackers grab credentials and
//! tokens that were pasted by the operator.
//!
//! Anti-FP gates:
//!   - Parent comm is a known editor (vim/nvim/vscode-server/code/zed)
//!     → silenced. Editors legitimately read clipboard for paste.
//!   - Operator-extensible `[detectors.clipboard_read]` TOML.
//!
//! MITRE: T1115 (Clipboard Data).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

const CLIPBOARD_COMMS: &[&str] = &["xclip", "xsel", "wl-paste", "pbpaste", "wl-copy"];
const EDITOR_PARENTS: &[&str] = &[
    "vim",
    "nvim",
    "neovim",
    "vscode-server",
    "code",
    "code-server",
    "zed",
    "helix",
    "emacs",
    "kakoune",
    "kitty",
    "alacritty",
];

pub struct ClipboardReadDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl ClipboardReadDetector {
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

        // Spec 050-PR1 lesson (#662): eBPF execve fires pre-rename so
        // `comm` holds the launcher, not the binary. Read identity from
        // argv[0] basename.
        let argv0 = event
            .details
            .get("argv")
            .and_then(|v| v.get(0))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let argv0_base = argv0.split('/').next_back().unwrap_or(argv0);
        if !is_clipboard_comm(argv0_base) {
            return None;
        }

        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if is_editor_parent(parent_comm) {
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
                "clipboard_read:{}:{}",
                argv0_base,
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity: Severity::High,
            title: format!("Clipboard read tool exec on host: {}", argv0_base),
            summary: format!(
                "Process `{comm}` (pid={pid}, uid={uid}) ran `{command}`. \
                 Headless / production hosts should not be reading the clipboard \
                 — possible exfiltration of operator-pasted credentials."
            ),
            evidence: serde_json::json!([{
                "kind": "clipboard_read",
                "comm": comm,
                "parent_comm": parent_comm,
                "uid": uid,
                "pid": pid,
                "command": command,
                "mitre": ["T1115"],
            }]),
            recommended_checks: vec![
                format!("Inspect process tree: pstree -p {pid}"),
                "If a desktop session legitimately runs on this host, allowlist via [detectors.clipboard_read]".to_string(),
            ],
            tags: vec!["collection".to_string(), "clipboard".to_string()],
            entities: vec![],
        })
    }
}

fn comm_base(comm: &str) -> &str {
    let base = comm.split('/').next_back().unwrap_or(comm);
    base.trim_matches(|c: char| c == '(' || c == ')')
}

fn is_clipboard_comm(base: &str) -> bool {
    CLIPBOARD_COMMS.contains(&base)
}

fn is_editor_parent(parent_comm: &str) -> bool {
    if parent_comm.is_empty() {
        return false;
    }
    let base = comm_base(parent_comm);
    EDITOR_PARENTS.iter().any(|p| base.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(comm: &str, parent_comm: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: format!("Shell command executed: {comm}"),
            details: serde_json::json!({
                "pid": 4242,
                "uid": 1000,
                "ppid": 999,
                "comm": comm,
                "parent_comm": parent_comm,
                "command": format!("{comm} -o"),
                "argv": [comm, "-o"],
                "argc": 2,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_xclip_xsel_wlpaste_pbpaste() {
        for c in ["xclip", "xsel", "wl-paste", "pbpaste", "wl-copy"] {
            let mut det = ClipboardReadDetector::new("test");
            assert!(
                det.process(&make_event(c, "bash")).is_some(),
                "{c} should fire"
            );
        }
    }

    #[test]
    fn silences_when_parent_is_editor() {
        for parent in ["vim", "nvim", "vscode-server", "code", "zed", "emacs"] {
            let mut det = ClipboardReadDetector::new("test");
            assert!(
                det.process(&make_event("xclip", parent)).is_none(),
                "parent={parent} should silence"
            );
        }
    }

    #[test]
    fn ignores_unrelated_comms() {
        let mut det = ClipboardReadDetector::new("test");
        for c in ["bash", "vim", "cat", "ls"] {
            assert!(det.process(&make_event(c, "bash")).is_none());
        }
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = ClipboardReadDetector::new("test");
        let ev = make_event("xclip", "bash");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(30);
        assert!(det.process(&ev2).is_none());
    }

    /// Smoke-shape regression: eBPF emits comm=launcher (pre-rename)
    /// and argv=[/usr/bin/binary]. Detector identifies the clipboard
    /// tool via argv[0] basename, not comm. Without this, a
    /// `sudo xclip -o` exec would land with `comm="sudo"` and never
    /// match the clipboard list (same class as the spec 050 PR1
    /// nmap_scan bug, #662).
    #[test]
    fn fires_when_comm_is_launcher_and_argv_holds_clipboard_path() {
        let mut det = ClipboardReadDetector::new("test");
        let ev = Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: "Shell command executed: /usr/bin/xclip -o".into(),
            details: serde_json::json!({
                "pid": 4242,
                "uid": 1000,
                "ppid": 4241,
                "comm": "sudo",
                "parent_comm": "sudo",
                "command": "/usr/bin/xclip -o",
                "argv": ["/usr/bin/xclip", "-o"],
                "argc": 2,
            }),
            tags: vec![],
            entities: vec![],
        };
        let inc = det
            .process(&ev)
            .expect("argv[0] = /usr/bin/xclip must fire");
        assert!(inc.incident_id.starts_with("clipboard_read:xclip"));
    }

    #[test]
    fn ignores_non_exec_events() {
        let mut det = ClipboardReadDetector::new("test");
        let mut ev = make_event("xclip", "bash");
        ev.kind = "network.outbound_connect".into();
        assert!(det.process(&ev).is_none());
    }
}
