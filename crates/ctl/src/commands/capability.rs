use std::collections::HashMap;
use std::io::Write;

use anyhow::Result;
use innerwarden_core::audit::{append_admin_action, current_operator, AdminActionEntry};

use crate::{make_opts, require_sudo, unknown_cap_error, CapabilityRegistry, Cli};

fn confirmation_accepted(answer: &str) -> bool {
    let normalized = answer.trim().to_lowercase();
    normalized.is_empty() || normalized == "y" || normalized == "yes"
}

pub(crate) fn parse_params(raw: &[String]) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for item in raw {
        let (k, v) = item.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("invalid param '{}' - expected KEY=VALUE format", item)
        })?;
        map.insert(k.to_string(), v.to_string());
    }
    Ok(map)
}

pub(crate) fn cmd_enable(
    cli: &Cli,
    registry: &CapabilityRegistry,
    id: &str,
    params: HashMap<String, String>,
    yes: bool,
) -> Result<()> {
    cmd_enable_with_deferred_restart(cli, registry, id, params, yes, false)
}

pub(crate) fn cmd_enable_with_deferred_restart(
    cli: &Cli,
    registry: &CapabilityRegistry,
    id: &str,
    params: HashMap<String, String>,
    yes: bool,
    defer_restarts: bool,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let cap = registry.get(id).ok_or_else(|| unknown_cap_error(id))?;
    let mut opts = make_opts(cli, params, yes);
    opts.defer_restarts = defer_restarts;

    if cap.is_enabled(&opts) {
        println!(
            "Capability '{}' is already enabled. Nothing to do.",
            cap.id()
        );
        return Ok(());
    }

    println!("Enabling capability: {}\n", cap.name());

    // --- Preflight checks ---
    println!("Preflight checks:");
    let preflights = cap.preflights(&opts);
    let mut any_failed = false;
    for pf in &preflights {
        match pf.check() {
            Ok(()) => println!("  [ok] {}", pf.name()),
            Err(e) => {
                println!("  [fail] {}", e.message);
                if let Some(hint) = &e.fix_hint {
                    println!("         → {hint}");
                }
                any_failed = true;
            }
        }
    }
    if any_failed {
        anyhow::bail!("preflight checks failed - no changes applied");
    }

    // --- Planned effects ---
    println!("\nPlanned changes:");
    let effects = cap.planned_effects(&opts);
    for (i, effect) in effects.iter().enumerate() {
        println!("  {}. {}", i + 1, effect.description);
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    // --- Confirmation ---
    if !yes {
        print!("\nApply? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !confirmation_accepted(&input) {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    // --- Activate ---
    let report = cap.activate(&opts)?;
    for effect in &report.effects_applied {
        println!("  [done] {}", effect.description);
    }
    for warn in &report.warnings {
        println!("  [warn] {warn}");
    }

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "enable".to_string(),
        target: id.to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!("\nCapability '{}' is now enabled.", cap.id());
    Ok(())
}

pub(crate) fn cmd_disable(
    cli: &Cli,
    registry: &CapabilityRegistry,
    id: &str,
    yes: bool,
) -> Result<()> {
    if !cli.dry_run {
        require_sudo(cli);
    }
    let cap = registry.get(id).ok_or_else(|| unknown_cap_error(id))?;
    let opts = make_opts(cli, HashMap::new(), yes);

    if !cap.is_enabled(&opts) {
        println!("Capability '{}' is not enabled. Nothing to do.", cap.id());
        return Ok(());
    }

    println!("Disabling capability: {}\n", cap.name());

    println!("Changes to apply:");
    let effects = cap.planned_disable_effects(&opts);
    for (i, effect) in effects.iter().enumerate() {
        println!("  {}. {}", i + 1, effect.description);
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nApply? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !confirmation_accepted(&input) {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    let report = cap.deactivate(&opts)?;
    for effect in &report.effects_applied {
        println!("  [done] {}", effect.description);
    }
    for warn in &report.warnings {
        println!("  [warn] {warn}");
    }

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "disable".to_string(),
        target: id.to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!("\nCapability '{}' is now disabled.", cap.id());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_accepted_allows_empty_response() {
        // Confirms default-enter behavior still applies the action when operator just presses Enter.
        assert!(confirmation_accepted(""));
        assert!(confirmation_accepted("   "));
    }

    #[test]
    fn confirmation_accepted_allows_yes_variants() {
        // Covers positive confirmations so both short and full forms remain accepted.
        assert!(confirmation_accepted("y"));
        assert!(confirmation_accepted("yes"));
        assert!(confirmation_accepted(" YES "));
    }

    #[test]
    fn confirmation_accepted_rejects_non_yes_values() {
        // Ensures abort path is triggered for explicit negative or unrelated responses.
        assert!(!confirmation_accepted("n"));
        assert!(!confirmation_accepted("no"));
        assert!(!confirmation_accepted("later"));
    }

    #[test]
    fn parse_params_parses_multiple_entries() {
        // Exercises standard KEY=VALUE parsing for capability parameter forwarding.
        let raw = vec![
            "mode=strict".to_string(),
            "timeout=30".to_string(),
            "region=eu".to_string(),
        ];
        let parsed = parse_params(&raw).expect("valid params should parse");

        assert_eq!(parsed.get("mode").expect("mode key"), "strict");
        assert_eq!(parsed.get("timeout").expect("timeout key"), "30");
        assert_eq!(parsed.get("region").expect("region key"), "eu");
    }

    #[test]
    fn parse_params_rejects_missing_separator() {
        // Guards validation branch so malformed CLI params fail fast with a clear error.
        let raw = vec!["mode".to_string()];
        let err = parse_params(&raw).expect_err("missing '=' must error");
        assert!(err.to_string().contains("expected KEY=VALUE format"));
    }

    #[test]
    fn parse_params_allows_empty_value_after_separator() {
        // Documents accepted behavior for explicitly clearing a value via KEY= syntax.
        let raw = vec!["token=".to_string()];
        let parsed = parse_params(&raw).expect("empty values are currently allowed");
        assert_eq!(parsed.get("token").expect("token key"), "");
    }

    #[test]
    fn parse_params_last_duplicate_wins() {
        // Verifies deterministic overwrite behavior when user provides same key multiple times.
        let raw = vec![
            "level=low".to_string(),
            "level=high".to_string(),
            "level=critical".to_string(),
        ];
        let parsed = parse_params(&raw).expect("duplicate keys should still parse");
        assert_eq!(parsed.get("level").expect("level key"), "critical");
    }
}
