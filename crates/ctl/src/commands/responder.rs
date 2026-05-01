use std::io::Write;

use anyhow::Result;
use innerwarden_core::audit::{append_admin_action, current_operator, AdminActionEntry};

use crate::{config_editor, prompt, require_sudo, restart_agent, Cli};

fn requires_live_confirmation(enable: bool, dry_run_flag: Option<bool>, cli_dry_run: bool) -> bool {
    enable && dry_run_flag == Some(false) && !cli_dry_run
}

fn responder_outcome_message(
    enable: bool,
    disable: bool,
    dry_run_flag: Option<bool>,
) -> &'static str {
    if enable && dry_run_flag == Some(false) {
        "Responder is LIVE. Decisions will execute automatically."
    } else if disable {
        "Responder disabled. System observes only."
    } else {
        "Responder updated. Run 'innerwarden status' to confirm."
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponderMode {
    ObserveOnly,
    DryRun,
    Live,
}

fn parse_responder_interactive_choice(choice: &str) -> Option<ResponderMode> {
    match choice.trim() {
        "1" => Some(ResponderMode::ObserveOnly),
        "2" => Some(ResponderMode::DryRun),
        "3" => Some(ResponderMode::Live),
        _ => None,
    }
}

pub(crate) fn cmd_configure_responder(
    cli: &Cli,
    enable: bool,
    disable: bool,
    dry_run_flag: Option<bool>,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    if !enable && !disable && dry_run_flag.is_none() {
        return cmd_configure_responder_interactive(cli);
    }

    if enable || disable {
        let value = enable;

        if requires_live_confirmation(enable, dry_run_flag, cli.dry_run) {
            println!("  WARNING: This will enable LIVE execution of security responses.");
            println!("  InnerWarden will run commands like 'ufw deny from <IP>' automatically.");
            println!();
            print!("  Type 'yes' to confirm: ");
            std::io::stdout().flush()?;
            let mut ans = String::new();
            std::io::stdin().read_line(&mut ans)?;
            if ans.trim() != "yes" {
                println!("Aborted.");
                return Ok(());
            }
        }

        if cli.dry_run {
            println!(
                "  [dry-run] would set [responder] enabled={value} in {}",
                cli.agent_config.display()
            );
        } else {
            config_editor::write_bool(&cli.agent_config, "responder", "enabled", value)?;
            println!("  [ok] responder.enabled = {value}");
        }
    }

    if let Some(dr) = dry_run_flag {
        if cli.dry_run {
            println!(
                "  [dry-run] would set [responder] dry_run={dr} in {}",
                cli.agent_config.display()
            );
        } else {
            config_editor::write_bool(&cli.agent_config, "responder", "dry_run", dr)?;
            println!("  [ok] responder.dry_run = {dr}");
        }
    }

    restart_agent(cli);
    println!();
    println!(
        "{}",
        responder_outcome_message(enable, disable, dry_run_flag)
    );

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "configure".to_string(),
        target: "responder".to_string(),
        parameters: serde_json::json!({
            "enable": enable,
            "disable": disable,
            "dry_run": dry_run_flag,
        }),
        result: if cli.dry_run {
            "dry_run".to_string()
        } else {
            "success".to_string()
        },
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
}

fn cmd_configure_responder_interactive(cli: &Cli) -> Result<()> {
    println!("InnerWarden - Responder setup\n");
    println!("The responder controls what InnerWarden does when it detects an attack.\n");
    println!("  1. Observe only (safe)   - logs everything, takes no action");
    println!("  2. Dry-run mode          - shows what it WOULD do, but doesn't execute");
    println!("  3. Live (auto-block)     - automatically blocks IPs and suspends users\n");

    let choice = prompt("Choose [1/2/3]")?;

    let Some(mode) = parse_responder_interactive_choice(&choice) else {
        anyhow::bail!("invalid choice - enter 1, 2, or 3");
    };

    let live_confirmed = if mode == ResponderMode::Live {
        println!();
        println!("  WARNING: In live mode, InnerWarden will automatically:");
        println!("    - Block IPs with: sudo ufw deny from <IP>  (or iptables/nftables)");
        println!("    - Suspend users:  drop-in in /etc/sudoers.d/");
        println!();
        println!("  Make sure block-ip is enabled: innerwarden enable block-ip");
        println!();
        print!("  Type 'yes' to enable live execution: ");
        std::io::stdout().flush()?;
        let mut ans = String::new();
        std::io::stdin().read_line(&mut ans)?;
        if ans.trim() != "yes" {
            println!("Aborted.");
            return Ok(());
        }
        true
    } else {
        false
    };

    apply_responder_mode(cli, mode, live_confirmed)
}

fn apply_responder_mode(cli: &Cli, mode: ResponderMode, live_confirmed: bool) -> Result<()> {
    match mode {
        ResponderMode::ObserveOnly => {
            if !cli.dry_run {
                config_editor::write_bool(&cli.agent_config, "responder", "enabled", false)?;
                println!("  [ok] responder disabled - observe only");
            } else {
                println!("  [dry-run] would disable responder");
            }
            restart_agent(cli);
            println!("\nSystem is in observe mode. No automatic actions will be taken.");
        }
        ResponderMode::DryRun => {
            if !cli.dry_run {
                config_editor::write_bool(&cli.agent_config, "responder", "enabled", true)?;
                config_editor::write_bool(&cli.agent_config, "responder", "dry_run", true)?;
                println!("  [ok] responder.enabled = true, dry_run = true");
            } else {
                println!("  [dry-run] would set responder.enabled=true, dry_run=true");
            }
            restart_agent(cli);
            println!(
                "\nDry-run mode enabled. InnerWarden will log what it would do but take no action."
            );
            println!("Check decisions-*.jsonl to review. When ready, run:");
            println!("  innerwarden configure responder --enable --dry-run false");
        }
        ResponderMode::Live => {
            if !live_confirmed {
                println!("Aborted.");
                return Ok(());
            }
            if !cli.dry_run {
                config_editor::write_bool(&cli.agent_config, "responder", "enabled", true)?;
                config_editor::write_bool(&cli.agent_config, "responder", "dry_run", false)?;
                println!("  [ok] responder is LIVE");
            } else {
                println!("  [dry-run] would set responder.enabled=true, dry_run=false");
            }
            restart_agent(cli);
            println!(
                "\nResponder is LIVE. InnerWarden will act automatically on high-confidence threats."
            );
            println!(
                "Monitor decisions: tail -f /var/lib/innerwarden/decisions-$(date +%Y-%m-%d).jsonl"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_cli(dir: &TempDir, dry_run: bool) -> Cli {
        let agent_path = dir.path().join("agent.toml");
        std::fs::write(&agent_path, "").unwrap();
        Cli {
            sensor_config: dir.path().join("config.toml"),
            agent_config: agent_path,
            data_dir: dir.path().to_path_buf(),
            dry_run,
            command: None,
        }
    }

    fn read_agent_doc(cli: &Cli) -> toml_edit::DocumentMut {
        std::fs::read_to_string(&cli.agent_config)
            .unwrap()
            .parse()
            .unwrap()
    }

    fn responder_bool(doc: &toml_edit::DocumentMut, key: &str) -> Option<bool> {
        doc.get("responder")
            .and_then(|section| section.get(key))
            .and_then(|value| value.as_bool())
    }

    #[test]
    fn requires_live_confirmation_only_for_real_live_mode() {
        // Covers the dangerous-mode guard so explicit confirmation is required only when it should be.
        assert!(requires_live_confirmation(true, Some(false), false));
        assert!(!requires_live_confirmation(true, Some(true), false));
        assert!(!requires_live_confirmation(false, Some(false), false));
        assert!(!requires_live_confirmation(true, Some(false), true));
    }

    #[test]
    fn responder_outcome_message_live_path() {
        // Ensures operator-facing messaging matches live execution mode.
        assert_eq!(
            responder_outcome_message(true, false, Some(false)),
            "Responder is LIVE. Decisions will execute automatically."
        );
    }

    #[test]
    fn responder_outcome_message_disabled_path() {
        // Ensures disabled mode reports observe-only behavior instead of generic text.
        assert_eq!(
            responder_outcome_message(false, true, None),
            "Responder disabled. System observes only."
        );
    }

    #[test]
    fn responder_outcome_message_default_path() {
        // Covers the default informational branch for non-live/non-disable updates.
        assert_eq!(
            responder_outcome_message(true, false, Some(true)),
            "Responder updated. Run 'innerwarden status' to confirm."
        );
    }

    #[test]
    fn parse_responder_interactive_choice_accepts_supported_values() {
        // Verifies canonical interactive options resolve to stable branch identifiers.
        assert_eq!(
            parse_responder_interactive_choice("1"),
            Some(ResponderMode::ObserveOnly)
        );
        assert_eq!(
            parse_responder_interactive_choice("2"),
            Some(ResponderMode::DryRun)
        );
        assert_eq!(
            parse_responder_interactive_choice("3"),
            Some(ResponderMode::Live)
        );
    }

    #[test]
    fn parse_responder_interactive_choice_rejects_invalid_input() {
        // Guards invalid-choice branch to preserve explicit error behavior in interactive flow.
        assert_eq!(parse_responder_interactive_choice("0"), None);
        assert_eq!(parse_responder_interactive_choice("4"), None);
        assert_eq!(parse_responder_interactive_choice("abc"), None);
    }

    #[test]
    fn cmd_configure_responder_dry_run_enable_does_not_write_config() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);

        cmd_configure_responder(&cli, true, false, Some(true)).unwrap();

        assert_eq!(std::fs::read_to_string(&cli.agent_config).unwrap(), "");
    }

    #[test]
    fn cmd_configure_responder_dry_run_live_path_skips_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, true);

        cmd_configure_responder(&cli, true, false, Some(false)).unwrap();

        assert_eq!(std::fs::read_to_string(&cli.agent_config).unwrap(), "");
    }

    #[test]
    fn cmd_configure_responder_writes_enable_and_dry_run_true() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, false);

        cmd_configure_responder(&cli, true, false, Some(true)).unwrap();

        let doc = read_agent_doc(&cli);
        assert_eq!(responder_bool(&doc, "enabled"), Some(true));
        assert_eq!(responder_bool(&doc, "dry_run"), Some(true));
    }

    #[test]
    fn cmd_configure_responder_writes_disable_without_dry_run_flag() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, false);

        cmd_configure_responder(&cli, false, true, None).unwrap();

        let doc = read_agent_doc(&cli);
        assert_eq!(responder_bool(&doc, "enabled"), Some(false));
        assert_eq!(responder_bool(&doc, "dry_run"), None);
    }

    #[test]
    fn cmd_configure_responder_can_update_dry_run_flag_only() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, false);

        cmd_configure_responder(&cli, false, false, Some(false)).unwrap();

        let doc = read_agent_doc(&cli);
        assert_eq!(responder_bool(&doc, "enabled"), None);
        assert_eq!(responder_bool(&doc, "dry_run"), Some(false));
    }

    #[test]
    fn apply_responder_mode_observe_only_writes_disabled_state() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, false);

        apply_responder_mode(&cli, ResponderMode::ObserveOnly, false).unwrap();

        let doc = read_agent_doc(&cli);
        assert_eq!(responder_bool(&doc, "enabled"), Some(false));
        assert_eq!(responder_bool(&doc, "dry_run"), None);
    }

    #[test]
    fn apply_responder_mode_dry_run_writes_enabled_safe_state() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, false);

        apply_responder_mode(&cli, ResponderMode::DryRun, false).unwrap();

        let doc = read_agent_doc(&cli);
        assert_eq!(responder_bool(&doc, "enabled"), Some(true));
        assert_eq!(responder_bool(&doc, "dry_run"), Some(true));
    }

    #[test]
    fn apply_responder_mode_live_requires_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, false);

        apply_responder_mode(&cli, ResponderMode::Live, false).unwrap();

        assert_eq!(std::fs::read_to_string(&cli.agent_config).unwrap(), "");
    }

    #[test]
    fn apply_responder_mode_live_writes_confirmed_live_state() {
        let dir = tempfile::tempdir().unwrap();
        let cli = test_cli(&dir, false);

        apply_responder_mode(&cli, ResponderMode::Live, true).unwrap();

        let doc = read_agent_doc(&cli);
        assert_eq!(responder_bool(&doc, "enabled"), Some(true));
        assert_eq!(responder_bool(&doc, "dry_run"), Some(false));
    }
}
