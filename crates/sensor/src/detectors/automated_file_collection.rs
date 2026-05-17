//! Automated file collection detection (spec 050-PR2).
//!
//! Catches `find` invocations that scan user-data directories with
//! `-newer` (incremental collection by mtime) or pipe directly into
//! `-exec cat` / `-print`. The signature of an adversary collecting
//! a curated batch of files for staging or exfiltration.
//!
//! Anti-FP gates:
//!   - Parent comm in `{cron, crond, logrotate, aide, tripwire,
//!     borgmatic, restic, duplicity, rkhunter}` → silenced (legit
//!     scheduled scanners).
//!   - Operator-extensible `[detectors.automated_file_collection]`
//!     TOML.
//!
//! MITRE: T1119 (Automated Collection).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

const COLLECTION_LAUNCHER_BASENAMES: &[&str] = &["find"];

const LEGIT_PARENTS: &[&str] = &[
    "cron",
    "crond",
    "anacron",
    "logrotate",
    "aide",
    "aide.wrapper",
    "tripwire",
    "borgmatic",
    "restic",
    "duplicity",
    "rkhunter",
    "lynis",
    "rsync",    // rsync uses find-like traversal in some modes
    "updatedb", // mlocate baseline
];

const USER_DATA_PATH_PREFIXES: &[&str] = &[
    "/home/",
    "/var/lib/",
    "/var/www/",
    "/etc/",
    "/root/",
    "/srv/",
];

pub struct AutomatedFileCollectionDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl AutomatedFileCollectionDetector {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            last_fired: HashMap::new(),
            cooldown: Duration::seconds(900),
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
        if !COLLECTION_LAUNCHER_BASENAMES.contains(&argv0_base) {
            return None;
        }

        let parent_comm = event
            .details
            .get("parent_comm")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if is_legit_parent(parent_comm) {
            return None;
        }

        // Three indicators of "collection-shape" find usage:
        //   1. -newer <ref> — incremental mtime sweep
        //   2. -exec cat / -exec base64 / -exec gzip — read+stage
        //   3. -print / -print0 scanning a user-data path
        let has_newer = argv.iter().any(|a| a == "-newer");
        let has_exec_read = has_exec_read_pattern(&argv);
        let scans_user_data = argv
            .iter()
            .any(|a| USER_DATA_PATH_PREFIXES.iter().any(|p| a.starts_with(p)));

        // Need at least one strong signal (newer OR exec-read) AND
        // we must be scanning user data — bare `find . -name foo` from
        // an interactive session is noise, not signal.
        if !(has_newer || has_exec_read) || !scans_user_data {
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

        // Severity: high when -exec read pattern is present (stages
        // file content); medium for -newer-only (just enumeration).
        let severity = if has_exec_read {
            Severity::High
        } else {
            Severity::Medium
        };

        let now = event.ts;
        let key = format!("{uid}:find");
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
                "automated_file_collection:{}:{}",
                argv0_base,
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity,
            title: format!(
                "Automated file collection: find sweep of user-data dirs (exec_read={})",
                has_exec_read
            ),
            summary: format!(
                "Process `find` (launcher comm=`{comm}`, parent=`{parent_comm}`, pid={pid}, uid={uid}) \
                 ran `{command}`. The argv pattern matches automated collection (T1119): \
                 has_newer={has_newer}, has_exec_read={has_exec_read}, scans_user_data=true."
            ),
            evidence: serde_json::json!([{
                "kind": "automated_file_collection",
                "argv0": argv[0],
                "has_newer": has_newer,
                "has_exec_read": has_exec_read,
                "scans_user_data": scans_user_data,
                "launcher_comm": comm,
                "parent_comm": parent_comm,
                "uid": uid,
                "pid": pid,
                "command": command,
                "mitre": ["T1119"],
            }]),
            recommended_checks: vec![
                format!("Trace process tree: pstree -p {pid}"),
                "If this is a known scheduler (aide/borgmatic/restic), allowlist via [detectors.automated_file_collection]".to_string(),
                "Inspect what files were touched after this exec — correlate with file.read_access events".to_string(),
            ],
            tags: vec!["collection".to_string()],
            entities: vec![],
        })
    }
}

fn is_legit_parent(parent_comm: &str) -> bool {
    if parent_comm.is_empty() {
        return false;
    }
    let base = parent_comm.split('/').next_back().unwrap_or(parent_comm);
    let base = base.trim_matches(|c: char| c == '(' || c == ')');
    LEGIT_PARENTS.iter().any(|p| base.starts_with(p))
}

fn has_exec_read_pattern(argv: &[String]) -> bool {
    // Look for `-exec`/`-execdir`/`-okdir` followed by a content-read
    // tool. Conservative: require explicit pairing so a benign
    // `-exec rm {} \;` doesn't trip the read-pattern signal.
    for (i, a) in argv.iter().enumerate() {
        if (a == "-exec" || a == "-execdir") && i + 1 < argv.len() {
            let next = argv[i + 1]
                .split('/')
                .next_back()
                .unwrap_or(&argv[i + 1])
                .to_string();
            if matches!(
                next.as_str(),
                "cat" | "base64" | "gzip" | "bzip2" | "xz" | "tar" | "tee" | "head" | "tail"
            ) {
                return true;
            }
        }
    }
    false
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
            summary: format!("exec {}", argv.join(" ")),
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
    fn fires_on_find_newer_in_home() {
        let mut det = AutomatedFileCollectionDetector::new("test");
        let ev = exec_event(
            &["find", "/home/ubuntu/", "-newer", "/tmp/marker", "-print"],
            "bash",
        );
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::Medium);
    }

    #[test]
    fn fires_on_find_exec_cat_with_high_severity() {
        let mut det = AutomatedFileCollectionDetector::new("test");
        let ev = exec_event(
            &["find", "/etc/", "-type", "f", "-exec", "cat", "{}", ";"],
            "bash",
        );
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::High);
    }

    #[test]
    fn silences_when_parent_is_cron() {
        let mut det = AutomatedFileCollectionDetector::new("test");
        let ev = exec_event(&["find", "/var/lib/", "-newer", "/tmp/cron-marker"], "cron");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn silences_when_parent_is_aide() {
        let mut det = AutomatedFileCollectionDetector::new("test");
        let ev = exec_event(&["find", "/etc/", "-newer", "/var/lib/aide/db.gz"], "aide");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_find_outside_user_data_dirs() {
        let mut det = AutomatedFileCollectionDetector::new("test");
        let ev = exec_event(&["find", "/tmp/", "-newer", "/tmp/x", "-print"], "bash");
        assert!(det.process(&ev).is_none(), "find on /tmp should not fire");
    }

    #[test]
    fn ignores_find_without_strong_signal() {
        let mut det = AutomatedFileCollectionDetector::new("test");
        // -name match on a user-data dir without -newer / -exec-read
        // is interactive admin work, not collection.
        let ev = exec_event(&["find", "/home/ubuntu/", "-name", "foo.txt"], "bash");
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_non_find_invocations() {
        let mut det = AutomatedFileCollectionDetector::new("test");
        for bin in ["cat", "grep", "ls", "rsync"] {
            let ev = exec_event(&[bin, "/home/ubuntu/", "-newer", "/tmp/x"], "bash");
            assert!(det.process(&ev).is_none(), "{bin} should not fire");
        }
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = AutomatedFileCollectionDetector::new("test");
        let ev = exec_event(&["find", "/home/", "-newer", "/tmp/x"], "bash");
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(60);
        assert!(det.process(&ev2).is_none());
    }
}
