//! Password-protected archive creation detection (spec 050-PR2).
//!
//! Adversaries password-protect archives during staging to defeat both
//! YARA/AV scanning and outbound DLP. Detects exec of `tar`, `zip`,
//! `7z`/`7za`, `rar` with a password flag (`--password=`, `-p`,
//! `-pPASSWORD`).
//!
//! Anti-FP gates:
//!   - Operator allowlisting via `[detectors.archive_pwd_protected]`
//!     TOML for backup tools / personal archive workflows.
//!
//! Severity is elevated when the archive output path looks like a
//! staging directory (`/tmp/`, `/var/tmp/`, `/dev/shm/`).
//!
//! MITRE: T1560.001 (Archive Collected Data: Archive via Utility).

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{event::Event, event::Severity, incident::Incident};

const ARCHIVE_COMMS: &[&str] = &["tar", "zip", "7z", "7za", "7zr", "rar", "unrar"];

const STAGING_DIRS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];

pub struct ArchivePwdProtectedDetector {
    host: String,
    last_fired: HashMap<String, DateTime<Utc>>,
    cooldown: Duration,
}

impl ArchivePwdProtectedDetector {
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
        if !is_archive_comm(argv0_base) {
            return None;
        }
        // Sniff argv tail for password flag.
        if !argv_has_password_flag(&argv[1..]) {
            return None;
        }
        // Sniff for staging-dir output path → elevated severity.
        let touches_staging = argv.iter().any(|a| {
            STAGING_DIRS
                .iter()
                .any(|d| a.contains(d) || a.starts_with(d.trim_end_matches('/')))
        });
        let severity = if touches_staging {
            Severity::Critical
        } else {
            Severity::High
        };

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
        let now = event.ts;
        let key = format!("{uid}:{argv0_base}");
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
                "archive_pwd_protected:{}:{}",
                argv0_base,
                now.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            severity,
            title: format!(
                "Password-protected archive: {} (staging={})",
                argv0_base, touches_staging
            ),
            summary: format!(
                "Process `{argv0_base}` (launched by `{comm}`, pid={pid}, uid={uid}) ran \
                 `{command}` with a password flag. {staging_note} (T1560.001).",
                staging_note = if touches_staging {
                    "Output path matches a staging directory (/tmp, /var/tmp, /dev/shm) — \
                     classic exfil pre-stage pattern"
                } else {
                    "Possible exfiltration staging"
                }
            ),
            evidence: serde_json::json!([{
                "kind": "archive_pwd_protected",
                "archiver": argv0_base,
                "launcher_comm": comm,
                "uid": uid,
                "pid": pid,
                "command": command,
                "staging_path": touches_staging,
                "mitre": ["T1560.001"],
            }]),
            recommended_checks: vec![
                format!("Inspect process tree: pstree -p {pid}"),
                "Search for the archive file produced and inspect its source content".to_string(),
                "If operator backup tools legitimately password-protect archives, allowlist via [detectors.archive_pwd_protected]".to_string(),
            ],
            tags: vec!["collection".to_string(), "archive".to_string()],
            entities: vec![],
        })
    }
}

fn is_archive_comm(base: &str) -> bool {
    ARCHIVE_COMMS.contains(&base)
}

/// Inspect argv (after argv[0]) for a password flag. Recognises:
///   - `--password=...`
///   - `-p` (followed by a value OR `-pPASS` glued)
///   - `-P` (some tools)
fn argv_has_password_flag(args: &[String]) -> bool {
    for a in args {
        if a.starts_with("--password=") || a == "--password" {
            return true;
        }
        // -p (zip), -p<pass> (7z `-p<pass>` glued), -P (tar's --new-volume-script alt)
        // Be conservative: a bare "-p" is the trigger; "-pSOMETHING" too.
        if a == "-p" || a == "-P" {
            return true;
        }
        if a.starts_with("-p") && a.len() > 2 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_event(argv: &[&str]) -> Event {
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
                "parent_comm": "bash",
                "command": argv.join(" "),
                "argv": argv_owned,
                "argc": argv.len() as u32,
            }),
            tags: vec![],
            entities: vec![],
        }
    }

    #[test]
    fn fires_on_7z_with_password_glued() {
        let mut det = ArchivePwdProtectedDetector::new("test");
        let ev = exec_event(&["/usr/bin/7z", "a", "-pSecret123", "/tmp/loot.7z", "/etc/"]);
        let inc = det.process(&ev).expect("should fire");
        // /tmp staging → critical
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn fires_on_zip_with_dash_p() {
        let mut det = ArchivePwdProtectedDetector::new("test");
        let ev = exec_event(&[
            "/usr/bin/zip",
            "-r",
            "-P",
            "Hunter2",
            "/home/backup.zip",
            "/data/",
        ]);
        let inc = det.process(&ev).expect("should fire");
        assert_eq!(inc.severity, Severity::High);
    }

    #[test]
    fn fires_on_tar_with_password_long_flag() {
        let mut det = ArchivePwdProtectedDetector::new("test");
        let ev = exec_event(&[
            "tar",
            "--password=secret",
            "-czf",
            "/var/tmp/loot.tar.gz",
            "/etc/",
        ]);
        let inc = det.process(&ev).expect("should fire");
        // /var/tmp staging → critical
        assert_eq!(inc.severity, Severity::Critical);
    }

    #[test]
    fn ignores_tar_without_password_flag() {
        let mut det = ArchivePwdProtectedDetector::new("test");
        let ev = exec_event(&["tar", "-czf", "/home/backup.tar.gz", "/data/"]);
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ignores_unrelated_binaries() {
        let mut det = ArchivePwdProtectedDetector::new("test");
        for bin in ["cp", "rsync", "scp", "dd"] {
            let ev = exec_event(&[bin, "-p", "/tmp/x"]);
            assert!(det.process(&ev).is_none(), "{bin} should not fire");
        }
    }

    #[test]
    fn dedupes_within_cooldown() {
        let mut det = ArchivePwdProtectedDetector::new("test");
        let ev = exec_event(&["7z", "a", "-pX", "/tmp/a.7z"]);
        assert!(det.process(&ev).is_some());
        let mut ev2 = ev.clone();
        ev2.ts = ev.ts + Duration::seconds(30);
        assert!(det.process(&ev2).is_none());
    }
}
