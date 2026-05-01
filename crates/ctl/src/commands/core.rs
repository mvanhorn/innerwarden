use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;

use crate::{commands, make_opts, welcome, CapabilityRegistry, Cli, DailyCommand};

fn capability_status_label(enabled: bool) -> &'static str {
    if enabled {
        "enabled"
    } else {
        "disabled"
    }
}

fn daily_help_lines() -> &'static [&'static str] {
    &[
        "InnerWarden Daily Commands",
        "Use these for day-to-day operations:",
        "  innerwarden daily status",
        "  innerwarden daily threats",
        "  innerwarden daily actions",
        "  innerwarden daily report",
        "  innerwarden daily doctor",
        "  innerwarden daily test",
        "  innerwarden daily agent",
        "",
        "Short aliases:",
        "  innerwarden quick status",
        "  innerwarden day threats --live",
        "  innerwarden quick agent scan",
        "",
        "Need advanced operations?",
        "  innerwarden --help",
        "  innerwarden <command> --help",
    ]
}

fn count_innerwarden_programs(output: &[u8]) -> u32 {
    String::from_utf8_lossy(output)
        .matches("innerwarden")
        .count() as u32
}

pub(crate) fn cmd_list(cli: &Cli, registry: &CapabilityRegistry) -> Result<()> {
    println!("{:<20} {:<10} Description", "Capability", "Status");
    println!("{}", "─".repeat(72));
    for cap in registry.all() {
        let opts = make_opts(cli, HashMap::new(), false);
        let status = capability_status_label(cap.is_enabled(&opts));
        println!("{:<20} {:<10} {}", cap.id(), status, cap.description());
    }

    println!();
    println!("System coverage:");
    println!("  22 eBPF kernel hooks (execve, connect, ptrace, setuid, bind, mount, ...)");
    println!("  36 stateful detectors (SSH brute-force, rootkit, reverse shell, ransomware, ...)");
    println!("  13 log collectors (auth_log, journald, docker, nginx, cloudtrail, ...)");
    println!("  7 kill chain patterns blocked at kernel level");
    println!();
    println!("These run automatically. Capabilities above are optional add-ons.");
    println!("Run 'innerwarden scan' to see what's recommended for this machine.");

    Ok(())
}

pub(crate) fn cmd_daily(
    cli: &Cli,
    registry: &CapabilityRegistry,
    command: Option<&DailyCommand>,
) -> Result<()> {
    match command {
        Some(DailyCommand::Status) => {
            let modules_dir = Path::new("/etc/innerwarden/modules");
            commands::status::cmd_status_global(cli, registry, modules_dir)
        }
        Some(DailyCommand::Threats {
            days,
            severity,
            live,
        }) => {
            if *live {
                commands::history::cmd_incidents_live(cli, severity, &cli.data_dir.clone())
            } else {
                commands::history::cmd_incidents(cli, *days, severity, &cli.data_dir.clone())
            }
        }
        Some(DailyCommand::Actions { days }) => {
            commands::history::cmd_decisions(cli, *days, None, &cli.data_dir.clone())
        }
        Some(DailyCommand::Report { date }) => {
            commands::status::cmd_report(cli, date, &cli.data_dir.clone())
        }
        Some(DailyCommand::Doctor) => commands::ops::cmd_doctor(cli, registry),
        Some(DailyCommand::Test { wait }) => {
            commands::ops::cmd_pipeline_test(cli, *wait, &cli.data_dir.clone())
        }
        Some(DailyCommand::Agent { command }) => commands::agent::cmd_agent(cli, command.as_ref()),
        None => {
            let lines = daily_help_lines();
            println!("{}", lines[0]);
            println!("{}", "═".repeat(52));
            for line in lines.iter().skip(1) {
                println!("{line}");
            }
            Ok(())
        }
    }
}

pub(crate) fn cmd_welcome() -> Result<()> {
    let ebpf = std::process::Command::new("bpftool")
        .args(["prog", "list"])
        .output()
        .ok()
        .map(|o| count_innerwarden_programs(&o.stdout))
        .unwrap_or(0);
    welcome::run_welcome(ebpf);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_cli(dir: &TempDir) -> Cli {
        Cli {
            sensor_config: dir.path().join("config.toml"),
            agent_config: dir.path().join("agent.toml"),
            data_dir: dir.path().to_path_buf(),
            dry_run: true,
            command: None,
        }
    }

    #[test]
    fn capability_status_label_enabled_branch() {
        // Exercises the enabled branch so status output stays consistent in capability listings.
        assert_eq!(capability_status_label(true), "enabled");
    }

    #[test]
    fn capability_status_label_disabled_branch() {
        // Exercises the disabled branch so status output doesn't regress for inactive capabilities.
        assert_eq!(capability_status_label(false), "disabled");
    }

    #[test]
    fn daily_help_lines_contains_expected_commands() {
        // Verifies the daily command help text includes critical operator paths and aliases.
        let lines = daily_help_lines();
        assert!(lines.contains(&"  innerwarden daily status"));
        assert!(lines.contains(&"  innerwarden daily test"));
        assert!(lines.contains(&"  innerwarden quick status"));
    }

    #[test]
    fn count_innerwarden_programs_counts_every_match() {
        // Ensures welcome-mode eBPF count reflects multiple innerwarden program occurrences.
        let output = b"prog_a innerwarden\nprog_b innerwarden\nprog_c";
        assert_eq!(count_innerwarden_programs(output), 2);
    }

    #[test]
    fn count_innerwarden_programs_returns_zero_without_matches() {
        // Guards the no-match path so welcome output remains deterministic when bpftool output is unrelated.
        assert_eq!(count_innerwarden_programs(b"prog_a\nprog_b"), 0);
    }

    #[test]
    fn cmd_daily_without_command_prints_help() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir);
        let registry = CapabilityRegistry::default_all();

        cmd_daily(&cli, &registry, None).unwrap();
    }

    #[test]
    fn cmd_daily_dispatches_empty_threat_and_action_views() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir);
        let registry = CapabilityRegistry::default_all();

        cmd_daily(
            &cli,
            &registry,
            Some(&DailyCommand::Threats {
                days: 1,
                severity: "low".to_string(),
                live: false,
            }),
        )
        .unwrap();
        cmd_daily(&cli, &registry, Some(&DailyCommand::Actions { days: 1 })).unwrap();
    }

    #[test]
    fn cmd_daily_dispatches_missing_report_without_error() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir);
        let registry = CapabilityRegistry::default_all();

        cmd_daily(
            &cli,
            &registry,
            Some(&DailyCommand::Report {
                date: "today".to_string(),
            }),
        )
        .unwrap();
    }

    #[test]
    fn cmd_daily_dispatches_agent_menu() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir);
        let registry = CapabilityRegistry::default_all();

        cmd_daily(
            &cli,
            &registry,
            Some(&DailyCommand::Agent { command: None }),
        )
        .unwrap();
    }

    #[test]
    fn cmd_daily_dispatches_pipeline_test_to_temp_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir);
        let registry = CapabilityRegistry::default_all();

        cmd_daily(&cli, &registry, Some(&DailyCommand::Test { wait: 0 })).unwrap();

        let today = crate::today_date_string();
        assert!(dir.path().join(format!("incidents-{today}.jsonl")).exists());
    }

    #[test]
    fn cmd_list_smoke_uses_registry_capabilities() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir);
        let registry = CapabilityRegistry::default_all();

        cmd_list(&cli, &registry).unwrap();
    }
}
