use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

pub(super) fn check_auditd(env: &impl HardenEnv) -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Auditd";

    // Check if auditd is installed
    let auditd_installed = env.path_exists("/sbin/auditd") || env.path_exists("/usr/sbin/auditd");

    if !auditd_installed {
        findings.push(Finding {
            category: cat,
            severity: Severity::High,
            title: "auditd not installed".into(),
            fix: "Install auditd: apt-get install auditd (Debian/Ubuntu) or yum install audit (RHEL/Rocky)".into(),
        });
        return CheckResult {
            category: cat,
            passed,
            findings,
        };
    }
    passed.push("auditd installed".into());

    // Check if auditd service is active
    let active = env
        .command_stdout("systemctl", &["is-active", "auditd"])
        .map(|stdout| stdout.trim().to_string())
        .unwrap_or_default();

    if active != "active" {
        findings.push(Finding {
            category: cat,
            severity: Severity::High,
            title: "auditd service not running".into(),
            fix: "Enable and start auditd: systemctl enable --now auditd".into(),
        });
    } else {
        passed.push("auditd service active".into());
    }

    // Read all audit rules
    let mut rules = String::new();
    if let Some(content) = env.read_to_string("/etc/audit/audit.rules") {
        rules.push_str(&content);
    }
    // Also read rules.d/ directory
    for entry in env.read_dir("/etc/audit/rules.d") {
        if entry.path.ends_with(".rules") {
            if let Some(content) = env.read_to_string(&entry.path) {
                rules.push_str(&content);
            }
        }
    }

    // Critical ATT&CK rules that enable Sigma detection
    let critical_rules: &[(&str, &str, &str)] = &[
        (
            "-S execve",
            "Execution monitoring (T1059)",
            "Tracks all process execution — enables 120+ Sigma process_creation rules",
        ),
        (
            "-w /etc/passwd",
            "Identity file monitoring (T1003)",
            "Detects credential harvesting and user enumeration",
        ),
        (
            "-w /etc/shadow",
            "Credential file monitoring (T1003)",
            "Detects password hash access",
        ),
        (
            "-w /etc/sudoers",
            "Privilege config monitoring (T1548)",
            "Detects sudo policy tampering",
        ),
        (
            "-w /etc/cron",
            "Persistence monitoring (T1053)",
            "Detects crontab-based persistence",
        ),
        (
            "-w /etc/ssh",
            "SSH config monitoring (T1098.004)",
            "Detects SSH key injection and config tampering",
        ),
        (
            "-S connect",
            "Network connection monitoring (T1071)",
            "Tracks outbound connections for C2 detection",
        ),
        (
            "-S ptrace",
            "Process injection monitoring (T1055)",
            "Detects ptrace-based injection and debugging",
        ),
        (
            "-w /tmp -p x",
            "Temp execution monitoring (T1059)",
            "Detects execution from /tmp (common malware staging)",
        ),
        (
            "-S init_module",
            "Kernel module monitoring (T1547.006)",
            "Detects rootkit and kernel module loading",
        ),
    ];

    let mut missing_rules: Vec<(&str, &str, &str)> = Vec::new();
    for (rule_fragment, title, description) in critical_rules {
        if rules.contains(rule_fragment) {
            passed.push(format!("{title} enabled"));
        } else {
            missing_rules.push((rule_fragment, title, description));
        }
    }

    let total = critical_rules.len();
    let missing_count = missing_rules.len();
    if missing_count == 0 {
        passed.push("All critical audit rules configured".into());
    } else {
        // Bug 7 fix (2026-05-06): pre-fix this loop emitted ONE Medium
        // finding per missing rule, which produced 9 × 5pp = 45 score
        // penalty for an auditd-only gap (plus 10pp on the summary).
        // The operator's prod harden output was 16/100 "Critical" with
        // SSH/firewall/kernel/permissions/docker/TLS all green —
        // disproportionate. Fix: emit ONE finding for the auditd
        // category, with severity scaling by missing-count, and embed
        // every missing rule's hint inside the fix text. Score impact
        // is now bounded (Low/Medium/High based on count) regardless
        // of whether 1 rule or 10 are missing.
        //
        // Bug 9 fix (2026-05-06): the inline hints used to write
        // `auditctl ...` directly after the prose with no visual
        // separation — the operator could not tell where the prose
        // ended and the command began. The new format uses an
        // indented bullet line per rule so copy-paste works.
        //
        // Bug 10 fix (2026-05-06): the prior summary mentioned
        // `innerwarden harden --install-audit-rules` but that flag
        // was never implemented. Dropped the false promise; the fix
        // text now describes the canonical manual path (write
        // `/etc/audit/rules.d/innerwarden.rules` directly) plus the
        // wiki link operators can use as a recipe.
        let severity = if missing_count >= 7 {
            Severity::High
        } else if missing_count >= 3 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let mut fix = String::new();
        fix.push_str(&format!(
            "Add the {missing_count} missing rule(s) to /etc/audit/rules.d/innerwarden.rules \
             (then reload with `sudo augenrules --load`).\n\
             Recipe + full ruleset: https://github.com/InnerWarden/innerwarden/wiki/Operations#auditd\n\
             Missing rules:"
        ));
        // 2026-05-09 prod fix: the suggestion line used to prefix every
        // fragment with `-a always,exit -F arch=b64 …`, which is correct
        // for syscall rules (`-S execve`) but auditctl rejects when
        // mixed with watch rules (`-w /etc/passwd`) because watch and
        // syscall are different rule families ("watch option can't be
        // given with a syscall"). Operator copy-pasted the suggestions
        // from `harden --verbose` and got 9/10 rules silently rejected.
        // The fix: detect the rule family per fragment and emit the
        // canonical install line for each.
        for (rule_fragment, title, _description) in &missing_rules {
            let install_line = if rule_fragment.starts_with("-w ") {
                // Watch rule. If the fragment already specifies `-p` (e.g.
                // `-w /tmp -p x`), keep it; otherwise default to `wa`
                // (write+attribute) which is the canonical permission
                // set for /etc/passwd-style files.
                if rule_fragment.contains(" -p ") {
                    format!("{rule_fragment} -k innerwarden")
                } else {
                    format!("{rule_fragment} -p wa -k innerwarden")
                }
            } else {
                // Syscall rule.
                format!("-a always,exit -F arch=b64 {rule_fragment} -k innerwarden")
            };
            fix.push_str(&format!("\n   • {title}:  {install_line}"));
        }

        findings.push(Finding {
            category: cat,
            severity,
            title: format!("{missing_count}/{total} critical audit rules missing"),
            fix,
        });
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harden::env::{DirEntry, HardenEnv};

    struct MockEnv {
        auditd_installed: bool,
        auditd_active: bool,
        rules_content: String,
    }

    impl HardenEnv for MockEnv {
        fn read_to_string(&self, path: &str) -> Option<String> {
            if path == "/etc/audit/audit.rules" {
                Some(self.rules_content.clone())
            } else {
                None
            }
        }
        fn read_bytes(&self, _path: &str) -> Option<Vec<u8>> {
            None
        }
        fn read_dir(&self, _path: &str) -> Vec<DirEntry> {
            vec![]
        }
        fn metadata_mode(&self, _path: &str) -> Option<u32> {
            None
        }
        fn path_exists(&self, path: &str) -> bool {
            if path.contains("auditd") {
                self.auditd_installed
            } else {
                false
            }
        }
        fn command_stdout(&self, _program: &str, _args: &[&str]) -> Option<String> {
            if self.auditd_active {
                Some("active\n".to_string())
            } else {
                Some("inactive\n".to_string())
            }
        }
    }

    #[test]
    fn test_check_auditd_not_installed() {
        let env = MockEnv {
            auditd_installed: false,
            auditd_active: false,
            rules_content: "".to_string(),
        };
        let res = check_auditd(&env);
        assert!(res
            .findings
            .iter()
            .any(|f| f.title.contains("not installed")));
    }

    #[test]
    fn test_check_auditd_installed_not_active() {
        let env = MockEnv {
            auditd_installed: true,
            auditd_active: false,
            rules_content: "".to_string(),
        };
        let res = check_auditd(&env);
        assert!(res.findings.iter().any(|f| f.title.contains("not running")));
    }

    #[test]
    fn test_check_auditd_missing_rules() {
        let env = MockEnv {
            auditd_installed: true,
            auditd_active: true,
            rules_content: "-w /etc/passwd\n".to_string(),
        };
        let res = check_auditd(&env);
        assert!(res.findings.iter().any(|f| f.title.contains("missing")));
    }

    /// Bug 7 anchor (2026-05-06): with 9 missing rules, harden MUST
    /// produce exactly ONE finding for the auditd category — not 9
    /// (one per rule) plus a summary. The operator's prod output had
    /// 9 × Medium (5pp each) + 1 × High (10pp) = 55pp from auditd
    /// alone; the score read 16/100 "Critical" while every other
    /// category was clean. Pin the new contract: one finding total.
    #[test]
    fn check_auditd_missing_9_of_10_emits_single_finding() {
        let env = MockEnv {
            auditd_installed: true,
            auditd_active: true,
            // Only one rule present → 9 missing.
            rules_content: "-w /etc/passwd\n".to_string(),
        };
        let res = check_auditd(&env);
        let auditd_findings: Vec<_> = res
            .findings
            .iter()
            .filter(|f| f.category == "Auditd" && f.title.contains("rules missing"))
            .collect();
        assert_eq!(
            auditd_findings.len(),
            1,
            "expected exactly one auditd-rules-missing finding, got {}",
            auditd_findings.len()
        );
        let f = auditd_findings[0];
        assert!(f.title.starts_with("9/10 "));
    }

    /// Bug 7 anchor: severity scales with the missing count. 9 missing
    /// is High (most rules absent); 4 missing is Medium; 1 missing is
    /// Low. This caps the auditd category's contribution to the score
    /// at one severity-bounded penalty regardless of how many rules
    /// are missing.
    #[test]
    fn check_auditd_severity_scales_with_missing_count() {
        // 9 missing → High
        let env = MockEnv {
            auditd_installed: true,
            auditd_active: true,
            rules_content: "-w /etc/passwd\n".to_string(),
        };
        let res = check_auditd(&env);
        let f = res
            .findings
            .iter()
            .find(|f| f.title.contains("rules missing"))
            .expect("missing-rules finding");
        assert_eq!(f.severity, Severity::High);

        // 4 missing → Medium (6 of 10 present).
        let env = MockEnv {
            auditd_installed: true,
            auditd_active: true,
            rules_content: "\
-S execve
-w /etc/passwd
-w /etc/shadow
-w /etc/sudoers
-w /etc/cron
-w /etc/ssh
"
            .to_string(),
        };
        let res = check_auditd(&env);
        let f = res
            .findings
            .iter()
            .find(|f| f.title.contains("rules missing"))
            .expect("missing-rules finding");
        assert_eq!(f.severity, Severity::Medium);

        // 1 missing → Low (only init_module absent).
        let env = MockEnv {
            auditd_installed: true,
            auditd_active: true,
            rules_content: "\
-S execve
-w /etc/passwd
-w /etc/shadow
-w /etc/sudoers
-w /etc/cron
-w /etc/ssh
-S connect
-S ptrace
-w /tmp -p x
"
            .to_string(),
        };
        let res = check_auditd(&env);
        let f = res
            .findings
            .iter()
            .find(|f| f.title.contains("rules missing"))
            .expect("missing-rules finding");
        assert_eq!(f.severity, Severity::Low);
    }

    /// Bug 9 anchor (2026-05-06): the fix text MUST present each
    /// missing rule on its own indented bullet line so the operator
    /// can read the prose and copy the auditctl/rule fragment without
    /// the two colliding. Pre-fix prose ran straight into the
    /// `auditctl ...` command with no visual break.
    #[test]
    fn check_auditd_missing_rules_fix_is_bullet_formatted() {
        let env = MockEnv {
            auditd_installed: true,
            auditd_active: true,
            rules_content: "".to_string(),
        };
        let res = check_auditd(&env);
        let f = res
            .findings
            .iter()
            .find(|f| f.title.contains("rules missing"))
            .expect("missing-rules finding");
        // Each missing rule appears on its own bullet (indented "•").
        assert!(
            f.fix.contains("\n   • "),
            "fix must use bullet-per-rule format, got: {}",
            f.fix
        );
        // The helpful augenrules reload command is present.
        assert!(
            f.fix.contains("augenrules --load"),
            "fix must mention augenrules reload, got: {}",
            f.fix
        );
    }

    /// 2026-05-09 prod anchor: the previous suggestion line mixed
    /// `-w` (watch) and `-a … -F arch=b64 -S` (syscall) prefixes,
    /// which auditctl rejects with "watch option can't be given with
    /// a syscall". Operator copy-pasted the suggestions from
    /// `harden --verbose` → 9/10 rules silently rejected on load.
    /// Anchor that watch fragments emit watch-form lines (with `-p`
    /// permission) and syscall fragments emit `-a always,exit -F
    /// arch=b64 …` lines. Auditctl must accept every emitted line.
    #[test]
    fn check_auditd_missing_rules_emits_valid_auditctl_syntax() {
        let env = MockEnv {
            auditd_installed: true,
            auditd_active: true,
            rules_content: "".to_string(),
        };
        let res = check_auditd(&env);
        let f = res
            .findings
            .iter()
            .find(|f| f.title.contains("rules missing"))
            .expect("missing-rules finding");

        // Watch fragments (path-based) must NOT carry `-a always,exit`
        // — that prefix is the syscall family and auditctl rejects
        // mixing them with `-w`.
        for path in [
            "-w /etc/passwd",
            "-w /etc/shadow",
            "-w /etc/sudoers",
            "-w /etc/cron",
            "-w /etc/ssh",
        ] {
            // Locate the bullet line for this path and check it does
            // not contain the syscall prefix.
            let line =
                f.fix.lines().find(|l| l.contains(path)).unwrap_or_else(|| {
                    panic!("expected {path} to appear in fix text, got: {}", f.fix)
                });
            assert!(
                !line.contains("-a always,exit"),
                "watch rule for {path} must NOT carry the syscall prefix \
                 (auditctl rejects `-a … -w`). got line: {line}"
            );
            assert!(
                line.contains("-p "),
                "watch rule for {path} must include a `-p` permission \
                 set (default to `-p wa`). got line: {line}"
            );
        }

        // Syscall fragments must keep the canonical syscall prefix.
        for sc in ["-S connect", "-S ptrace", "-S init_module", "-S execve"] {
            let line =
                f.fix.lines().find(|l| l.contains(sc)).unwrap_or_else(|| {
                    panic!("expected {sc} to appear in fix text, got: {}", f.fix)
                });
            assert!(
                line.contains("-a always,exit -F arch=b64"),
                "syscall rule for {sc} must include `-a always,exit -F arch=b64`. \
                 got line: {line}"
            );
        }
    }

    /// Bug 10 anchor (2026-05-06): the previous fix text mentioned
    /// `innerwarden harden --install-audit-rules` but that flag does
    /// not exist anywhere in the CLI. Pin that the fix text NEVER
    /// re-introduces a reference to a non-existent flag.
    #[test]
    fn check_auditd_missing_rules_fix_does_not_promise_unimplemented_flag() {
        let env = MockEnv {
            auditd_installed: true,
            auditd_active: true,
            rules_content: "".to_string(),
        };
        let res = check_auditd(&env);
        let f = res
            .findings
            .iter()
            .find(|f| f.title.contains("rules missing"))
            .expect("missing-rules finding");
        assert!(
            !f.fix.contains("--install-audit-rules"),
            "Bug 10 regression: fix text promised the unimplemented `--install-audit-rules` flag. \
             Either implement the flag in a separate PR before re-adding the mention, or keep \
             the manual instructions. got: {}",
            f.fix
        );
    }

    #[test]
    fn test_check_auditd_all_rules_present() {
        let env = MockEnv {
            auditd_installed: true,
            auditd_active: true,
            rules_content: "\
-S execve
-w /etc/passwd
-w /etc/shadow
-w /etc/sudoers
-w /etc/cron
-w /etc/ssh
-S connect
-S ptrace
-w /tmp -p x
-S init_module
"
            .to_string(),
        };
        let res = check_auditd(&env);
        assert!(res
            .passed
            .iter()
            .any(|p| p.contains("All critical audit rules configured")));
    }
}
