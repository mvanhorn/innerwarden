//! AI SOC Daily Checks (spec 020 Phase D).
//!
//! Runs 15 system health checks, compares with previous results, and
//! generates a report via AI.  Results go to dashboard + Telegram.
//!
//! Each check is a pure function that takes command output and returns
//! structured data.  The orchestrator runs at 06:00 UTC.

use serde::{Deserialize, Serialize};

// ── Check result types ──────────────────────────────────────────────────

/// Result of a single SOC check.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub name: &'static str,
    pub category: &'static str,
    pub items: Vec<String>,
    pub count: usize,
}

/// Diff between today's and yesterday's check results.
#[derive(Debug, Clone, Serialize)]
pub struct CheckDiff {
    pub name: &'static str,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

/// Full daily SOC report.
#[derive(Debug, Clone, Serialize)]
pub struct SocReport {
    pub checks: Vec<CheckResult>,
    pub diffs: Vec<CheckDiff>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

// ── Check parsers (pure functions) ──────────────────────────────────────

/// Parse `ss -tlnp` output into listening ports.
pub fn parse_open_ports(output: &str) -> CheckResult {
    let items: Vec<String> = output
        .lines()
        .skip(1) // header
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            let addr = parts.get(3).unwrap_or(&"?");
            let proc = parts.last().unwrap_or(&"?");
            format!("{} ({})", addr, proc)
        })
        .collect();
    let count = items.len();
    CheckResult {
        name: "open_ports",
        category: "network",
        items,
        count,
    }
}

/// Parse `last -n 20` output into recent logins.
pub fn parse_recent_logins(output: &str) -> CheckResult {
    let items: Vec<String> = output
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with("wtmp") && !l.starts_with("reboot"))
        .take(20)
        .map(|l| l.trim().to_string())
        .collect();
    let count = items.len();
    CheckResult {
        name: "recent_logins",
        category: "access",
        items,
        count,
    }
}

/// Parse `journalctl --priority=err --since yesterday -q` for system errors.
pub fn parse_system_errors(output: &str) -> CheckResult {
    let items: Vec<String> = output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(50)
        .map(|l| l.trim().to_string())
        .collect();
    let count = items.len();
    CheckResult {
        name: "system_errors",
        category: "system",
        items,
        count,
    }
}

/// Parse `df -h` output for disk usage.
pub fn parse_disk_usage(output: &str) -> CheckResult {
    let items: Vec<String> = output
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect();
    let count = items.len();
    CheckResult {
        name: "disk_usage",
        category: "system",
        items,
        count,
    }
}

/// Parse `/etc/passwd` or `getent passwd` for user accounts.
pub fn parse_user_accounts(output: &str) -> CheckResult {
    let items: Vec<String> = output
        .lines()
        .filter(|l| {
            if let Some(uid_str) = l.split(':').nth(2) {
                if let Ok(uid) = uid_str.parse::<u32>() {
                    // Root + human users (1000-59999), exclude nobody (65534) etc.
                    return uid == 0 || (1000..60000).contains(&uid);
                }
            }
            false
        })
        .map(|l| {
            let name = l.split(':').next().unwrap_or("?");
            let uid = l.split(':').nth(2).unwrap_or("?");
            let shell = l.split(':').next_back().unwrap_or("?");
            format!("{} (uid:{}, shell:{})", name, uid, shell)
        })
        .collect();
    let count = items.len();
    CheckResult {
        name: "user_accounts",
        category: "access",
        items,
        count,
    }
}

/// Parse `find /tmp -type f -executable` for executables in /tmp.
pub fn parse_tmp_executables(output: &str) -> CheckResult {
    let items: Vec<String> = output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect();
    let count = items.len();
    CheckResult {
        name: "tmp_executables",
        category: "filesystem",
        items,
        count,
    }
}

/// Parse `systemctl --failed` for failed services.
pub fn parse_failed_services(output: &str) -> CheckResult {
    let items: Vec<String> = output
        .lines()
        .filter(|l| l.contains("failed") || l.contains("FAILED"))
        .map(|l| l.trim().to_string())
        .collect();
    let count = items.len();
    CheckResult {
        name: "failed_services",
        category: "system",
        items,
        count,
    }
}

/// Parse `crontab -l` or `/var/spool/cron` for cron jobs.
pub fn parse_crontabs(output: &str) -> CheckResult {
    let items: Vec<String> = output
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| l.trim().to_string())
        .collect();
    let count = items.len();
    CheckResult {
        name: "crontabs",
        category: "persistence",
        items,
        count,
    }
}

/// Parse `cat ~/.ssh/authorized_keys` for SSH keys.
pub fn parse_ssh_keys(output: &str) -> CheckResult {
    let items: Vec<String> = output
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            // Show key type + comment (last field), not the full key
            let parts: Vec<&str> = l.split_whitespace().collect();
            let key_type = parts.first().unwrap_or(&"?");
            let comment = parts.last().unwrap_or(&"?");
            format!("{} {}", key_type, comment)
        })
        .collect();
    let count = items.len();
    CheckResult {
        name: "ssh_authorized_keys",
        category: "access",
        items,
        count,
    }
}

/// Parse `lsmod` for loaded kernel modules.
pub fn parse_kernel_modules(output: &str) -> CheckResult {
    let items: Vec<String> = output
        .lines()
        .skip(1) // header
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split_whitespace().next().unwrap_or("?").to_string())
        .collect();
    let count = items.len();
    CheckResult {
        name: "kernel_modules",
        category: "kernel",
        items,
        count,
    }
}

/// Parse `find / -perm -4000` for SUID binaries.
pub fn parse_suid_binaries(output: &str) -> CheckResult {
    let items: Vec<String> = output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.trim().to_string())
        .collect();
    let count = items.len();
    CheckResult {
        name: "suid_binaries",
        category: "filesystem",
        items,
        count,
    }
}

// ── Diff computation ────────────────────────────────────────────────────

/// Compare two CheckResults and return the diff.
pub fn diff_check(today: &CheckResult, yesterday: &CheckResult) -> CheckDiff {
    let today_set: std::collections::HashSet<&str> =
        today.items.iter().map(|s| s.as_str()).collect();
    let yesterday_set: std::collections::HashSet<&str> =
        yesterday.items.iter().map(|s| s.as_str()).collect();

    let added: Vec<String> = today_set
        .difference(&yesterday_set)
        .map(|s| s.to_string())
        .collect();
    let removed: Vec<String> = yesterday_set
        .difference(&today_set)
        .map(|s| s.to_string())
        .collect();

    CheckDiff {
        name: today.name,
        added,
        removed,
    }
}

/// Build the AI prompt for SOC report analysis.
pub fn soc_report_prompt(report: &SocReport) -> String {
    let mut prompt = String::from(
        "You are a security analyst reviewing daily system checks on a Linux server.\n\
         Compare today's results with yesterday and report:\n\
         1. New items that appeared (new ports, users, services, etc.)\n\
         2. Items that disappeared (stopped services, removed users, etc.)\n\
         3. Anything unusual or concerning\n\
         4. Overall security posture assessment\n\n\
         Respond in 3-5 bullet points, concise and actionable.\n\n",
    );

    for check in &report.checks {
        prompt.push_str(&format!(
            "=== {} ({}) — {} items ===\n",
            check.name, check.category, check.count
        ));
        for item in check.items.iter().take(20) {
            prompt.push_str(&format!("  {}\n", item));
        }
        if check.items.len() > 20 {
            prompt.push_str(&format!("  ... and {} more\n", check.items.len() - 20));
        }
        prompt.push('\n');
    }

    if report
        .diffs
        .iter()
        .any(|d| !d.added.is_empty() || !d.removed.is_empty())
    {
        prompt.push_str("=== CHANGES FROM YESTERDAY ===\n");
        for diff in &report.diffs {
            if diff.added.is_empty() && diff.removed.is_empty() {
                continue;
            }
            prompt.push_str(&format!("{}:\n", diff.name));
            for a in &diff.added {
                prompt.push_str(&format!("  + {}\n", a));
            }
            for r in &diff.removed {
                prompt.push_str(&format!("  - {}\n", r));
            }
        }
    } else {
        prompt.push_str("No changes from yesterday.\n");
    }

    prompt
}

// ── Config ──────────────────────────────────────────────────────────────

/// Configuration for SOC daily checks.
#[derive(Debug, Clone, Deserialize)]
pub struct SocChecksConfig {
    /// Enable daily SOC checks (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Hour (UTC) to run daily checks (default: 6).
    #[serde(default = "default_hour")]
    pub hour: u32,
}

fn default_true() -> bool {
    true
}
fn default_hour() -> u32 {
    6
}

impl Default for SocChecksConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hour: 6,
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_open_ports: 3 tests ───────────────────────────────────────

    #[test]
    fn parse_open_ports_normal() {
        let output = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0      128    0.0.0.0:22   0.0.0.0:*     users:((\"sshd\",pid=1234,fd=3))\nLISTEN 0      511    0.0.0.0:80   0.0.0.0:*     users:((\"nginx\",pid=5678,fd=6))\n";
        let r = parse_open_ports(output);
        assert_eq!(r.count, 2);
        assert!(r.items[0].contains("22"));
    }

    #[test]
    fn parse_open_ports_empty() {
        let output = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n";
        let r = parse_open_ports(output);
        assert_eq!(r.count, 0);
    }

    #[test]
    fn parse_open_ports_single() {
        let output = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=1,fd=3))\n";
        let r = parse_open_ports(output);
        assert_eq!(r.count, 1);
        assert_eq!(r.name, "open_ports");
        assert_eq!(r.category, "network");
    }

    // ── parse_recent_logins: 3 tests ────────────────────────────────────

    #[test]
    fn parse_recent_logins_normal() {
        let output = "ubuntu   pts/0   192.168.1.1  Wed Apr 16 10:00 - 11:00\nroot     pts/1   10.0.0.5     Wed Apr 16 09:00 - 10:00\n";
        let r = parse_recent_logins(output);
        assert_eq!(r.count, 2);
    }

    #[test]
    fn parse_recent_logins_with_wtmp() {
        let output =
            "ubuntu   pts/0   192.168.1.1  Wed Apr 16 10:00\nwtmp begins Wed Mar 1 00:00:00 2026\n";
        let r = parse_recent_logins(output);
        assert_eq!(r.count, 1); // wtmp line filtered out
    }

    #[test]
    fn parse_recent_logins_empty() {
        let r = parse_recent_logins("");
        assert_eq!(r.count, 0);
    }

    // ── parse_system_errors: 3 tests ────────────────────────────────────

    #[test]
    fn parse_system_errors_some() {
        let output = "Apr 16 10:00 host kernel: error1\nApr 16 11:00 host nginx: error2\n";
        let r = parse_system_errors(output);
        assert_eq!(r.count, 2);
    }

    #[test]
    fn parse_system_errors_empty() {
        let r = parse_system_errors("");
        assert_eq!(r.count, 0);
    }

    #[test]
    fn parse_system_errors_capped() {
        let output = (0..100)
            .map(|i| format!("error line {}", i))
            .collect::<Vec<_>>()
            .join("\n");
        let r = parse_system_errors(&output);
        assert_eq!(r.count, 50); // capped at 50
    }

    // ── parse_user_accounts: 3 tests ────────────────────────────────────

    #[test]
    fn parse_user_accounts_filters_system() {
        let output = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n";
        let r = parse_user_accounts(output);
        // root (uid 0) + ubuntu (uid 1000), daemon (uid 1) and nobody filtered
        assert_eq!(r.count, 2);
    }

    #[test]
    fn parse_user_accounts_empty() {
        let r = parse_user_accounts("");
        assert_eq!(r.count, 0);
    }

    #[test]
    fn parse_user_accounts_shows_shell() {
        let output = "test:x:1001:1001::/home/test:/bin/zsh\n";
        let r = parse_user_accounts(output);
        assert_eq!(r.count, 1);
        assert!(r.items[0].contains("zsh"));
    }

    // ── parse_tmp_executables: 3 tests ──────────────────────────────────

    #[test]
    fn parse_tmp_executables_some() {
        let output = "/tmp/malware\n/tmp/exploit\n";
        let r = parse_tmp_executables(output);
        assert_eq!(r.count, 2);
    }

    #[test]
    fn parse_tmp_executables_empty() {
        let r = parse_tmp_executables("");
        assert_eq!(r.count, 0);
    }

    #[test]
    fn parse_tmp_executables_name() {
        let r = parse_tmp_executables("/tmp/test\n");
        assert_eq!(r.name, "tmp_executables");
        assert_eq!(r.category, "filesystem");
    }

    // ── parse_failed_services: 3 tests ──────────────────────────────────

    #[test]
    fn parse_failed_services_some() {
        let output = "  UNIT          LOAD   ACTIVE SUB    DESCRIPTION\n* foo.service  loaded failed failed Foo\n* bar.service  loaded failed failed Bar\n\n2 loaded units listed.\n";
        let r = parse_failed_services(output);
        assert_eq!(r.count, 2);
    }

    #[test]
    fn parse_failed_services_none() {
        let output = "  UNIT  LOAD  ACTIVE SUB  DESCRIPTION\n\n0 loaded units listed.\n";
        let r = parse_failed_services(output);
        assert_eq!(r.count, 0);
    }

    #[test]
    fn parse_failed_services_mixed() {
        let output = "active running foo\nfailed dead bar\n";
        let r = parse_failed_services(output);
        assert_eq!(r.count, 1);
    }

    // ── parse_crontabs: 3 tests ─────────────────────────────────────────

    #[test]
    fn parse_crontabs_normal() {
        let output = "# comment\n0 * * * * /usr/bin/backup\n30 6 * * * /opt/check.sh\n";
        let r = parse_crontabs(output);
        assert_eq!(r.count, 2); // comments filtered
    }

    #[test]
    fn parse_crontabs_empty() {
        let r = parse_crontabs("");
        assert_eq!(r.count, 0);
    }

    #[test]
    fn parse_crontabs_all_comments() {
        let output = "# m h dom mon dow command\n# nothing scheduled\n";
        let r = parse_crontabs(output);
        assert_eq!(r.count, 0);
    }

    // ── parse_ssh_keys: 3 tests ─────────────────────────────────────────

    #[test]
    fn parse_ssh_keys_normal() {
        let output = "ssh-ed25519 AAAA... user@host\nssh-rsa AAAA... admin@server\n";
        let r = parse_ssh_keys(output);
        assert_eq!(r.count, 2);
        assert!(r.items[0].contains("ssh-ed25519"));
        assert!(r.items[0].contains("user@host"));
    }

    #[test]
    fn parse_ssh_keys_empty() {
        let r = parse_ssh_keys("");
        assert_eq!(r.count, 0);
    }

    #[test]
    fn parse_ssh_keys_with_comments() {
        let output = "# some comment\nssh-ed25519 AAAA... me@laptop\n";
        let r = parse_ssh_keys(output);
        assert_eq!(r.count, 1);
    }

    // ── parse_kernel_modules: 3 tests ───────────────────────────────────

    #[test]
    fn parse_kernel_modules_normal() {
        let output = "Module                  Size  Used by\nip_tables              32768  0\nnf_tables              262144  1\n";
        let r = parse_kernel_modules(output);
        assert_eq!(r.count, 2);
        assert_eq!(r.items[0], "ip_tables");
    }

    #[test]
    fn parse_kernel_modules_empty() {
        let output = "Module                  Size  Used by\n";
        let r = parse_kernel_modules(output);
        assert_eq!(r.count, 0);
    }

    #[test]
    fn parse_kernel_modules_name() {
        let r = parse_kernel_modules("Module Size Used\ntest 1234 0\n");
        assert_eq!(r.name, "kernel_modules");
        assert_eq!(r.category, "kernel");
    }

    // ── parse_suid_binaries: 3 tests ────────────────────────────────────

    #[test]
    fn parse_suid_binaries_normal() {
        let output = "/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/ping\n";
        let r = parse_suid_binaries(output);
        assert_eq!(r.count, 3);
    }

    #[test]
    fn parse_suid_binaries_empty() {
        let r = parse_suid_binaries("");
        assert_eq!(r.count, 0);
    }

    #[test]
    fn parse_suid_binaries_suspicious() {
        let output = "/tmp/exploit\n";
        let r = parse_suid_binaries(output);
        assert_eq!(r.count, 1);
        assert!(r.items[0].contains("/tmp/"));
    }

    // ── diff_check: 3 tests ─────────────────────────────────────────────

    #[test]
    fn diff_check_added() {
        let today = CheckResult {
            name: "test",
            category: "test",
            items: vec!["a".into(), "b".into(), "c".into()],
            count: 3,
        };
        let yesterday = CheckResult {
            name: "test",
            category: "test",
            items: vec!["a".into(), "b".into()],
            count: 2,
        };
        let diff = diff_check(&today, &yesterday);
        assert_eq!(diff.added.len(), 1);
        assert!(diff.added.contains(&"c".to_string()));
        assert!(diff.removed.is_empty());
    }

    #[test]
    fn diff_check_removed() {
        let today = CheckResult {
            name: "test",
            category: "test",
            items: vec!["a".into()],
            count: 1,
        };
        let yesterday = CheckResult {
            name: "test",
            category: "test",
            items: vec!["a".into(), "b".into()],
            count: 2,
        };
        let diff = diff_check(&today, &yesterday);
        assert!(diff.added.is_empty());
        assert_eq!(diff.removed.len(), 1);
        assert!(diff.removed.contains(&"b".to_string()));
    }

    #[test]
    fn diff_check_no_change() {
        let today = CheckResult {
            name: "test",
            category: "test",
            items: vec!["a".into(), "b".into()],
            count: 2,
        };
        let diff = diff_check(&today, &today);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
    }

    // ── soc_report_prompt: 3 tests ──────────────────────────────────────

    #[test]
    fn soc_report_prompt_includes_checks() {
        let report = SocReport {
            checks: vec![CheckResult {
                name: "open_ports",
                category: "network",
                items: vec!["0.0.0.0:22 (sshd)".into()],
                count: 1,
            }],
            diffs: vec![],
            timestamp: chrono::Utc::now(),
        };
        let prompt = soc_report_prompt(&report);
        assert!(prompt.contains("open_ports"));
        assert!(prompt.contains("0.0.0.0:22"));
    }

    #[test]
    fn soc_report_prompt_includes_diffs() {
        let report = SocReport {
            checks: vec![],
            diffs: vec![CheckDiff {
                name: "open_ports",
                added: vec!["0.0.0.0:8080 (java)".into()],
                removed: vec![],
            }],
            timestamp: chrono::Utc::now(),
        };
        let prompt = soc_report_prompt(&report);
        assert!(prompt.contains("CHANGES FROM YESTERDAY"));
        assert!(prompt.contains("+ 0.0.0.0:8080"));
    }

    #[test]
    fn soc_report_prompt_no_changes() {
        let report = SocReport {
            checks: vec![],
            diffs: vec![],
            timestamp: chrono::Utc::now(),
        };
        let prompt = soc_report_prompt(&report);
        assert!(prompt.contains("No changes from yesterday"));
    }

    // ── Config tests ────────────────────────────────────────────────────

    #[test]
    fn config_default() {
        let cfg = SocChecksConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.hour, 6);
    }

    #[test]
    fn config_deserialize_custom() {
        let toml = "enabled = true\nhour = 8\n";
        let cfg: SocChecksConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.hour, 8);
    }

    #[test]
    fn config_deserialize_default() {
        let cfg: SocChecksConfig = toml::from_str("").unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.hour, 6);
    }
}
