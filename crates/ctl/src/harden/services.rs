use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

/// Bug 8 (2026-05-06 prod observation): the prior code did
/// `command_stdout("systemctl", ["is-active", ...]) == "active"` and
/// any other shape (including `unknown` from `Failed to connect to
/// bus`) became "agent is not running". Harden then created a real
/// finding that lowered the score even though the agent was alive.
///
/// This helper distinguishes the three cases. On `Unknown` we do not
/// produce a finding — `harden` is an advisor and would rather be
/// silent than wrong. The companion fix in `crates/ctl/src/systemd.rs`
/// gives the same tri-state to `cmd_doctor`'s Services section.
pub(super) fn classify_service_active(stdout: Option<&str>) -> ServicePresence {
    match stdout {
        None => ServicePresence::Unknown,
        Some(line) => match line.trim() {
            "active" => ServicePresence::Active,
            "" | "unknown" => ServicePresence::Unknown,
            _ => ServicePresence::Inactive,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ServicePresence {
    Active,
    Inactive,
    Unknown,
}

pub(super) fn is_service_exposure_line_safe(line: &str) -> bool {
    line.contains(":22 ")
        || line.contains(":80 ")
        || line.contains(":443 ")
        || line.contains(":53 ")
        || line.contains(":8787 ")
        || line.contains(":8790 ")
        || line.contains(":2222 ")
        || line.contains("innerwarden")
        || line.contains("docker-proxy")
        || line.contains("containerd")
}

pub(super) fn exposed_service_lines(ss_output: &str) -> Vec<String> {
    ss_output
        .lines()
        .filter(|line| line.contains("0.0.0.0:") || line.contains(":::"))
        .filter(|line| !is_service_exposure_line_safe(line))
        .map(|line| line.to_string())
        .collect()
}

pub(super) fn check_services(env: &impl HardenEnv) -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Services";

    // Check for commonly exploited services exposed on all interfaces
    if let Some(lines) = env.command_stdout("ss", &["-tlnp"]) {
        let listening_all = exposed_service_lines(&lines);

        if listening_all.len() > 5 {
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: format!("{} services exposed on all interfaces", listening_all.len()),
                fix: "Review services binding to 0.0.0.0 - bind to 127.0.0.1 where possible".into(),
            });
        } else {
            passed.push("Service exposure looks reasonable".into());
        }
    }

    // Bug 8 fix (2026-05-06): tri-state instead of bool. `Active`
    // adds a passed line, `Inactive` produces the finding, `Unknown`
    // is silent — we cannot reliably tell from this session whether
    // the agent is up, and the operator's `innerwarden doctor` Agent
    // health section uses telemetry-freshness to answer the question
    // honestly. Producing a false "is not running" finding here
    // double-tanks the score in that case.
    //
    // 2026-05-09 prod fix: the proprietary `innerwarden-watchdog`
    // setup runs the agent as a child process (not via the
    // `innerwarden-agent.service` unit, which is intentionally
    // disabled in that mode). On those hosts `systemctl is-active
    // innerwarden-agent` returns `inactive`, the harden classifier
    // calls it Inactive, and the score gets penalised even though
    // the agent is alive. Pre-fix: operator's prod harden output
    // emitted "Inner Warden agent is not running [medium]" while
    // pid 868514 was processing events under the watchdog wrap.
    //
    // The fix probes a second source of truth: if the watchdog
    // service is active AND a process named `innerwarden-agent` is
    // visible in `pgrep`, treat that as Active. Only when systemd
    // says inactive AND watchdog is missing AND no agent process is
    // running do we emit the finding.
    let stdout_owned = env.command_stdout("systemctl", &["is-active", "innerwarden-agent"]);
    let presence = classify_service_active(stdout_owned.as_deref());
    let presence = if presence == ServicePresence::Inactive {
        // Promote to Active if the watchdog model is in use.
        let watchdog_stdout =
            env.command_stdout("systemctl", &["is-active", "innerwarden-watchdog"]);
        let watchdog_active =
            classify_service_active(watchdog_stdout.as_deref()) == ServicePresence::Active;
        let agent_process_alive = env
            .command_stdout("pgrep", &["-x", "innerwarden-age"])
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if watchdog_active && agent_process_alive {
            ServicePresence::Active
        } else {
            presence
        }
    } else {
        presence
    };
    match presence {
        ServicePresence::Active => {
            passed.push("Inner Warden agent is active".into());
        }
        ServicePresence::Inactive => {
            findings.push(Finding {
                category: cat,
                severity: Severity::Medium,
                title: "Inner Warden agent is not running".into(),
                fix: "Run: sudo systemctl start innerwarden-agent".into(),
            });
        }
        ServicePresence::Unknown => {
            // Silent — we do not know. Doctor's Agent health section
            // is the source of truth via telemetry-freshness.
        }
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

    /// Bug 8 anchor (2026-05-06): "active" stdout means active.
    #[test]
    fn classify_service_active_active_string_maps_to_active() {
        assert_eq!(
            classify_service_active(Some("active\n")),
            ServicePresence::Active
        );
    }

    /// Bug 8 anchor: "inactive" / "failed" / arbitrary other strings
    /// (that are NOT the bus-failure shape) classify as Inactive so
    /// harden DOES produce the finding when the agent is genuinely
    /// down.
    #[test]
    fn classify_service_active_inactive_strings_map_to_inactive() {
        assert_eq!(
            classify_service_active(Some("inactive\n")),
            ServicePresence::Inactive
        );
        assert_eq!(
            classify_service_active(Some("failed\n")),
            ServicePresence::Inactive
        );
    }

    /// Bug 8 headline anchor: "unknown" stdout (the `Failed to
    /// connect to bus` shape) maps to Unknown — NOT Inactive — so
    /// harden does not create a false finding when the operator's
    /// session lacks `DBUS_SESSION_BUS_ADDRESS`.
    #[test]
    fn classify_service_active_unknown_stdout_maps_to_unknown() {
        assert_eq!(
            classify_service_active(Some("unknown\n")),
            ServicePresence::Unknown
        );
    }

    /// Bug 8 anchor: empty stdout (the bus-failure shape on some
    /// distros) also maps to Unknown.
    #[test]
    fn classify_service_active_empty_stdout_maps_to_unknown() {
        assert_eq!(classify_service_active(Some("")), ServicePresence::Unknown);
        assert_eq!(
            classify_service_active(Some("   \n")),
            ServicePresence::Unknown
        );
    }

    /// Bug 8 anchor: when the command did not even run (None from
    /// `command_stdout`), classification is Unknown.
    #[test]
    fn classify_service_active_none_maps_to_unknown() {
        assert_eq!(classify_service_active(None), ServicePresence::Unknown);
    }
}
