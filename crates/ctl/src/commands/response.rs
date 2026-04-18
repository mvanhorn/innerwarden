use std::path::Path;

use anyhow::Result;

use crate::{
    append_admin_action, current_operator, looks_like_ip, resolve_data_dir, write_manual_decision,
    AdminActionEntry, Cli,
};

fn configured_block_backend(agent_config: &Path) -> String {
    std::fs::read_to_string(agent_config)
        .ok()
        .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
        .and_then(|v| {
            v.get("responder")
                .and_then(|r| r.get("block_backend"))
                .and_then(|b| b.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "ufw".to_string())
}

fn block_command_args(backend: &str, ip: &str) -> Vec<String> {
    match backend {
        "iptables" => ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        "nftables" => [
            "nft",
            "add",
            "element",
            "ip",
            "filter",
            "innerwarden-blocked",
            &format!("{{ {ip} }}"),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        "pf" => ["pfctl", "-t", "innerwarden-blocked", "-T", "add", ip]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        _ => ["ufw", "deny", "from", ip]
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}

fn unblock_command_args(backend: &str, ip: &str) -> Vec<String> {
    match backend {
        "iptables" => ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        "nftables" => [
            "nft",
            "delete",
            "element",
            "ip",
            "filter",
            "innerwarden-blocked",
            &format!("{{ {ip} }}"),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        "pf" => ["pfctl", "-t", "innerwarden-blocked", "-T", "delete", ip]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        _ => ["ufw", "delete", "deny", "from", ip]
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}

fn parse_suppressed_patterns(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|s| s.to_string())
        .collect()
}

pub(crate) fn cmd_block(cli: &Cli, ip: &str, reason: &str, data_dir: &Path) -> Result<()> {
    cmd_block_with_sudo(cli, ip, reason, data_dir, "sudo")
}

fn cmd_block_with_sudo(
    cli: &Cli,
    ip: &str,
    reason: &str,
    data_dir: &Path,
    sudo_bin: &str,
) -> Result<()> {
    // Basic IP validation
    if !looks_like_ip(ip) {
        anyhow::bail!("'{ip}' doesn't look like a valid IP address");
    }

    let effective_dir = resolve_data_dir(cli, data_dir);

    // Read configured block backend from agent.toml
    let backend = configured_block_backend(&cli.agent_config);

    println!("Blocking {ip} via {backend}...");

    if cli.dry_run {
        println!("  [dry-run] would run block command for {ip}");
        println!(
            "  [dry-run] would record in {}/decisions-*.jsonl",
            effective_dir.display()
        );
        return Ok(());
    }

    // Execute the block
    let blocked = std::process::Command::new(sudo_bin)
        .args(block_command_args(backend.as_str(), ip))
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !blocked {
        anyhow::bail!("block command failed - check sudo permissions (run: innerwarden doctor)");
    }
    println!("  [ok] {ip} blocked via {backend}");

    // Write audit trail
    write_manual_decision(&effective_dir, ip, "block_ip", reason, "operator:cli")?;
    println!("  [ok] recorded in decisions log");

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "block_ip".to_string(),
        target: ip.to_string(),
        parameters: serde_json::json!({ "reason": reason, "backend": backend }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&effective_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("{ip} is now blocked. To reverse: innerwarden unblock {ip} --reason \"...\"");
    Ok(())
}

pub(crate) fn cmd_unblock(cli: &Cli, ip: &str, reason: &str, data_dir: &Path) -> Result<()> {
    cmd_unblock_with_sudo(cli, ip, reason, data_dir, "sudo")
}

fn cmd_unblock_with_sudo(
    cli: &Cli,
    ip: &str,
    reason: &str,
    data_dir: &Path,
    sudo_bin: &str,
) -> Result<()> {
    if !looks_like_ip(ip) {
        anyhow::bail!("'{ip}' doesn't look like a valid IP address");
    }

    let effective_dir = resolve_data_dir(cli, data_dir);

    let backend = configured_block_backend(&cli.agent_config);

    println!("Unblocking {ip} via {backend}...");

    if cli.dry_run {
        println!("  [dry-run] would remove block for {ip}");
        println!(
            "  [dry-run] would record in {}/decisions-*.jsonl",
            effective_dir.display()
        );
        return Ok(());
    }

    let unblocked = std::process::Command::new(sudo_bin)
        .args(unblock_command_args(backend.as_str(), ip))
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !unblocked {
        println!("  Warning: unblock command may have failed (rule may not exist).");
        println!("  Check manually: sudo ufw status | grep {ip}");
    } else {
        println!("  [ok] {ip} unblocked via {backend}");
    }

    write_manual_decision(&effective_dir, ip, "unblock_ip", reason, "operator:cli")?;
    println!("  [ok] recorded in decisions log");

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "unblock_ip".to_string(),
        target: ip.to_string(),
        parameters: serde_json::json!({ "reason": reason, "backend": backend }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&effective_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!();
    println!("{ip} is now unblocked.");
    Ok(())
}

pub(crate) fn cmd_allowlist_add(cli: &Cli, ip: Option<&str>, user: Option<&str>) -> Result<()> {
    use crate::config_editor::write_array_push;
    let mut changed = false;
    if let Some(ip_val) = ip {
        let added = write_array_push(&cli.agent_config, "allowlist", "trusted_ips", ip_val)?;
        if added {
            println!("Added to trusted IPs: {ip_val}");
            changed = true;
        } else {
            println!("{ip_val} is already in trusted_ips.");
        }
    }
    if let Some(user_val) = user {
        let added = write_array_push(&cli.agent_config, "allowlist", "trusted_users", user_val)?;
        if added {
            println!("Added to trusted users: {user_val}");
            changed = true;
        } else {
            println!("{user_val} is already in trusted_users.");
        }
    }
    if !changed && ip.is_none() && user.is_none() {
        anyhow::bail!("specify --ip <cidr> or --user <username>");
    }
    if changed {
        // Audit log
        let target = ip
            .map(|v| v.to_string())
            .or_else(|| user.map(|v| v.to_string()))
            .unwrap_or_default();
        let mut audit = AdminActionEntry {
            ts: chrono::Utc::now(),
            operator: current_operator(),
            source: "cli".to_string(),
            action: "allowlist_add".to_string(),
            target,
            parameters: serde_json::json!({ "ip": ip, "user": user }),
            result: "success".to_string(),
            prev_hash: None,
        };
        if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
            eprintln!("  [warn] failed to write admin audit: {e:#}");
        }

        println!(
            "Allowlist updated. Restart the agent to apply:\n  sudo systemctl restart innerwarden-agent"
        );
    }
    Ok(())
}

pub(crate) fn cmd_allowlist_remove(cli: &Cli, ip: Option<&str>, user: Option<&str>) -> Result<()> {
    use crate::config_editor::write_array_remove;
    let mut changed = false;
    if let Some(ip_val) = ip {
        let removed = write_array_remove(&cli.agent_config, "allowlist", "trusted_ips", ip_val)?;
        if removed {
            println!("Removed from trusted IPs: {ip_val}");
            changed = true;
        } else {
            println!("{ip_val} was not in trusted_ips.");
        }
    }
    if let Some(user_val) = user {
        let removed =
            write_array_remove(&cli.agent_config, "allowlist", "trusted_users", user_val)?;
        if removed {
            println!("Removed from trusted users: {user_val}");
            changed = true;
        } else {
            println!("{user_val} was not in trusted_users.");
        }
    }
    if !changed && ip.is_none() && user.is_none() {
        anyhow::bail!("specify --ip <cidr> or --user <username>");
    }
    if changed {
        // Audit log
        let target = ip
            .map(|v| v.to_string())
            .or_else(|| user.map(|v| v.to_string()))
            .unwrap_or_default();
        let mut audit = AdminActionEntry {
            ts: chrono::Utc::now(),
            operator: current_operator(),
            source: "cli".to_string(),
            action: "allowlist_remove".to_string(),
            target,
            parameters: serde_json::json!({ "ip": ip, "user": user }),
            result: "success".to_string(),
            prev_hash: None,
        };
        if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
            eprintln!("  [warn] failed to write admin audit: {e:#}");
        }

        println!(
            "Allowlist updated. Restart the agent to apply:\n  sudo systemctl restart innerwarden-agent"
        );
    }
    Ok(())
}

pub(crate) fn cmd_allowlist_list(cli: &Cli) -> Result<()> {
    use crate::config_editor::read_str_array;
    let ips = read_str_array(&cli.agent_config, "allowlist", "trusted_ips");
    let users = read_str_array(&cli.agent_config, "allowlist", "trusted_users");

    if ips.is_empty() && users.is_empty() {
        println!("Allowlist is empty - no trusted IPs or users configured.");
        println!("Add entries with: innerwarden allowlist add --ip <cidr>");
        return Ok(());
    }

    if !ips.is_empty() {
        println!("Trusted IPs / CIDRs:");
        for ip in &ips {
            println!("  {ip}");
        }
    }
    if !users.is_empty() {
        println!("Trusted users:");
        for user in &users {
            println!("  {user}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// innerwarden suppress
// ---------------------------------------------------------------------------

fn suppressed_file(cli: &Cli) -> std::path::PathBuf {
    cli.data_dir.join("suppressed-incidents.txt")
}

pub(crate) fn cmd_suppress_add(cli: &Cli, pattern: &str) -> Result<()> {
    let path = suppressed_file(cli);
    let existing = std::fs::read_to_string(&path).unwrap_or_default();

    // Check if already exists
    if existing.lines().any(|l| l.trim() == pattern) {
        println!("Pattern already suppressed: {pattern}");
        return Ok(());
    }

    // Append
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    writeln!(f, "{pattern}")?;

    println!("Suppressed: {pattern}");
    println!("Matching incidents will be silently logged but not alerted.");
    println!();
    println!("  The agent will pick this up on next restart, or you can restart now:");
    println!("  sudo systemctl restart innerwarden-agent");

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "suppress_add".to_string(),
        target: pattern.to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }
    Ok(())
}

pub(crate) fn cmd_suppress_remove(cli: &Cli, pattern: &str) -> Result<()> {
    let path = suppressed_file(cli);
    let content = std::fs::read_to_string(&path).unwrap_or_default();

    let new_content: String = content
        .lines()
        .filter(|l| l.trim() != pattern)
        .collect::<Vec<_>>()
        .join("\n");

    if content == new_content {
        println!("Pattern not found: {pattern}");
        return Ok(());
    }

    std::fs::write(
        &path,
        if new_content.is_empty() {
            String::new()
        } else {
            format!("{new_content}\n")
        },
    )?;
    println!("Removed suppression: {pattern}");
    println!("Matching incidents will alert again after agent restart.");

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "suppress_remove".to_string(),
        target: pattern.to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }
    Ok(())
}

pub(crate) fn cmd_suppress_list(cli: &Cli) -> Result<()> {
    let path = suppressed_file(cli);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let patterns = parse_suppressed_patterns(&content);

    if patterns.is_empty() {
        println!("No suppressed patterns.");
        println!("Add with: innerwarden suppress add <pattern>");
        return Ok(());
    }

    println!("Suppressed incident patterns:");
    for p in &patterns {
        println!("  {p}");
    }
    println!();
    println!(
        "{} pattern(s) active. Matching incidents are silently logged.",
        patterns.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tempfile::TempDir;

    #[cfg(unix)]
    fn fake_sudo_script(temp: &TempDir, exit_code: u8) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let script = temp.path().join(format!("fake-sudo-{exit_code}.sh"));
        std::fs::write(&script, format!("#!/bin/sh\nexit {exit_code}\n"))
            .expect("test should write fake sudo script");
        let mut perms = std::fs::metadata(&script)
            .expect("fake sudo metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("fake sudo chmod");
        script
    }

    fn write_agent_config(path: &Path, content: &str) {
        std::fs::write(path, content).expect("test should write agent config");
    }

    fn test_cli(temp: &TempDir) -> Cli {
        let mut cli = Cli::parse_from(["innerwarden", "replay"]);
        cli.sensor_config = temp.path().join("sensor.toml");
        cli.agent_config = temp.path().join("agent.toml");
        cli.data_dir = temp.path().join("data");
        cli.dry_run = true;
        std::fs::create_dir_all(&cli.data_dir).expect("test should create data dir");
        write_agent_config(
            &cli.agent_config,
            "[allowlist]\ntrusted_ips=[]\ntrusted_users=[]\n",
        );
        cli
    }

    #[test]
    fn configured_block_backend_defaults_to_ufw_when_missing() {
        // Covers fallback branch so block/unblock keep working with absent or invalid config.
        let temp = TempDir::new().expect("test should create temp dir");
        let backend = configured_block_backend(&temp.path().join("missing-agent.toml"));
        assert_eq!(backend, "ufw");
    }

    #[test]
    fn configured_block_backend_reads_responder_backend() {
        // Verifies config parsing path so backend selection follows agent.toml responder settings.
        let temp = TempDir::new().expect("test should create temp dir");
        let config = temp.path().join("agent.toml");
        write_agent_config(&config, "[responder]\nblock_backend = \"pf\"\n");
        let backend = configured_block_backend(&config);
        assert_eq!(backend, "pf");
    }

    #[test]
    fn block_command_args_maps_supported_backends() {
        // Exercises each block backend arm to guard command construction before subprocess execution.
        assert_eq!(
            block_command_args("iptables", "1.2.3.4"),
            vec!["iptables", "-A", "INPUT", "-s", "1.2.3.4", "-j", "DROP"]
        );
        assert_eq!(
            block_command_args("nftables", "1.2.3.4"),
            vec![
                "nft",
                "add",
                "element",
                "ip",
                "filter",
                "innerwarden-blocked",
                "{ 1.2.3.4 }"
            ]
        );
        assert_eq!(
            block_command_args("pf", "1.2.3.4"),
            vec!["pfctl", "-t", "innerwarden-blocked", "-T", "add", "1.2.3.4"]
        );
    }

    #[test]
    fn block_command_args_falls_back_to_ufw_for_unknown_backend() {
        // Protects default branch so unknown backend values still produce a safe ufw command.
        assert_eq!(
            block_command_args("unknown", "1.2.3.4"),
            vec!["ufw", "deny", "from", "1.2.3.4"]
        );
    }

    #[test]
    fn unblock_command_args_maps_supported_and_default_backends() {
        // Covers all unblock command variants to prevent regressions in response rollback paths.
        assert_eq!(
            unblock_command_args("iptables", "1.2.3.4"),
            vec!["iptables", "-D", "INPUT", "-s", "1.2.3.4", "-j", "DROP"]
        );
        assert_eq!(
            unblock_command_args("nftables", "1.2.3.4"),
            vec![
                "nft",
                "delete",
                "element",
                "ip",
                "filter",
                "innerwarden-blocked",
                "{ 1.2.3.4 }"
            ]
        );
        assert_eq!(
            unblock_command_args("pf", "1.2.3.4"),
            vec![
                "pfctl",
                "-t",
                "innerwarden-blocked",
                "-T",
                "delete",
                "1.2.3.4"
            ]
        );
        assert_eq!(
            unblock_command_args("unknown", "1.2.3.4"),
            vec!["ufw", "delete", "deny", "from", "1.2.3.4"]
        );
    }

    #[test]
    fn cmd_block_rejects_invalid_ip() {
        // Ensures malformed targets fail before any command execution or state write.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        let err =
            cmd_block(&cli, "not-an-ip", "test", temp.path()).expect_err("invalid ip must fail");
        assert!(err
            .to_string()
            .contains("doesn't look like a valid IP address"));
    }

    #[test]
    fn cmd_block_dry_run_succeeds_with_valid_ip() {
        // Covers dry-run branch that bypasses subprocess execution while still validating inputs and config.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        cmd_block(&cli, "1.2.3.4", "investigation", temp.path())
            .expect("dry-run block should succeed");
    }

    #[cfg(unix)]
    #[test]
    fn cmd_block_with_sudo_non_dry_run_surfaces_command_failure() {
        // Covers the non-dry-run command execution branch safely via a fake sudo binary.
        let temp = TempDir::new().expect("test should create temp dir");
        let mut cli = test_cli(&temp);
        cli.dry_run = false;
        write_agent_config(&cli.agent_config, "[responder]\nblock_backend = \"pf\"\n");
        let fake_sudo = fake_sudo_script(&temp, 1);

        let err = cmd_block_with_sudo(
            &cli,
            "1.2.3.4",
            "investigation",
            temp.path(),
            fake_sudo.to_str().expect("utf-8 fake sudo path"),
        )
        .expect_err("fake sudo failure must propagate");
        assert!(err.to_string().contains("block command failed"));
    }

    #[test]
    fn cmd_unblock_dry_run_succeeds_with_valid_ip() {
        // Covers unblock dry-run path to keep manual rollback CLI available in non-root test contexts.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        cmd_unblock(&cli, "1.2.3.4", "false-positive", temp.path())
            .expect("dry-run unblock should succeed");
    }

    #[cfg(unix)]
    #[test]
    fn cmd_unblock_with_sudo_non_dry_run_handles_command_failure_and_continues() {
        // Executes non-dry-run unblock path without invoking real sudo/firewall commands.
        let temp = TempDir::new().expect("test should create temp dir");
        let mut cli = test_cli(&temp);
        cli.dry_run = false;
        write_agent_config(&cli.agent_config, "[responder]\nblock_backend = \"pf\"\n");
        let fake_sudo = fake_sudo_script(&temp, 1);

        cmd_unblock_with_sudo(
            &cli,
            "1.2.3.4",
            "false-positive",
            temp.path(),
            fake_sudo.to_str().expect("utf-8 fake sudo path"),
        )
        .expect("unblock should continue even when command fails");
    }

    #[test]
    fn cmd_allowlist_add_requires_ip_or_user() {
        // Validates guard clause that prevents no-op allowlist updates.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        let err = cmd_allowlist_add(&cli, None, None).expect_err("empty add must fail");
        assert!(err
            .to_string()
            .contains("specify --ip <cidr> or --user <username>"));
    }

    #[test]
    fn cmd_allowlist_add_and_remove_updates_arrays() {
        // Exercises add/remove state transitions so trusted IP persistence behaves deterministically.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        cmd_allowlist_add(&cli, Some("10.0.0.1"), None).expect("add ip should succeed");
        let ips =
            crate::config_editor::read_str_array(&cli.agent_config, "allowlist", "trusted_ips");
        assert_eq!(ips, vec!["10.0.0.1".to_string()]);

        cmd_allowlist_remove(&cli, Some("10.0.0.1"), None).expect("remove ip should succeed");
        let ips =
            crate::config_editor::read_str_array(&cli.agent_config, "allowlist", "trusted_ips");
        assert!(ips.is_empty());
    }

    #[test]
    fn parse_suppressed_patterns_filters_comments_and_blanks() {
        // Verifies suppress listing parser ignores comments/blank lines while preserving active patterns.
        let parsed = parse_suppressed_patterns("\n# note\nfoo\n  \n bar  \n");
        assert_eq!(parsed, vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn cmd_suppress_add_and_remove_manages_file_state() {
        // Covers suppression add/remove transitions, including dedup add and missing-pattern removal.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);

        cmd_suppress_add(&cli, "firmware:trust_degraded").expect("first add should succeed");
        cmd_suppress_add(&cli, "firmware:trust_degraded").expect("duplicate add should be no-op");

        let suppress_path = suppressed_file(&cli);
        let content = std::fs::read_to_string(&suppress_path).expect("suppress file should exist");
        assert_eq!(content.lines().count(), 1);
        assert_eq!(content.trim(), "firmware:trust_degraded");

        cmd_suppress_remove(&cli, "not-present").expect("removing missing pattern should be no-op");
        cmd_suppress_remove(&cli, "firmware:trust_degraded").expect("remove should succeed");
        let content =
            std::fs::read_to_string(&suppress_path).expect("suppress file should still exist");
        assert!(content.trim().is_empty());
    }

    #[test]
    fn cmd_suppress_list_reads_and_parses_saved_patterns() {
        // Covers suppress-list parser path used by the CLI command itself.
        let temp = TempDir::new().expect("test should create temp dir");
        let cli = test_cli(&temp);
        cmd_suppress_add(&cli, "detector:example").expect("add should succeed");
        cmd_suppress_list(&cli).expect("list should parse and print active suppressions");
    }
}
