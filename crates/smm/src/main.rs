use innerwarden_smm::{baseline, full_audit, CheckStatus};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Subcommands.
    match args.get(1).map(|s| s.as_str()) {
        Some("baseline") => cmd_baseline(),
        Some("drift") => cmd_drift(),
        _ => cmd_audit(&args),
    }
}

/// `innerwarden-smm baseline` — capture firmware baseline.
fn cmd_baseline() {
    let path = baseline::FirmwareBaseline::default_path();
    eprintln!("Capturing firmware baseline...");
    let b = baseline::FirmwareBaseline::capture();
    if let Err(e) = b.save(&path) {
        eprintln!("  Failed to save: {e}");
        std::process::exit(1);
    }
    eprintln!("  Saved to {}", path.display());
    eprintln!("  BIOS: {} {}", b.bios.vendor, b.bios.version);
    eprintln!("  ACPI tables: {}", b.acpi_tables.len());
    eprintln!("  PCR values: {}", b.pcrs.len());
    if let Some(smi) = b.smi_count {
        eprintln!("  SMI count: {smi}");
    }
    eprintln!("\n  Re-run `innerwarden-smm` to audit against this baseline.");
}

/// `innerwarden-smm drift` — show what changed since baseline.
fn cmd_drift() {
    let path = baseline::FirmwareBaseline::default_path();
    let Ok(b) = baseline::FirmwareBaseline::load(&path) else {
        eprintln!("No baseline found. Run `innerwarden-smm baseline` first.");
        std::process::exit(1);
    };

    let drift = baseline::detect_drift(&b);
    println!("Drift report (baseline from {})", drift.baseline_date);
    println!();

    if drift.drifts.is_empty() {
        println!("  No changes detected since baseline.");
        return;
    }

    for d in &drift.drifts {
        let (icon, color) = match d.severity {
            baseline::DriftSeverity::Info => ("~", "\x1b[36m"),
            baseline::DriftSeverity::Suspicious => ("?", "\x1b[33m"),
            baseline::DriftSeverity::Critical => ("!", "\x1b[31m"),
        };
        println!(
            "  {color}{icon}\x1b[0m {}: {color}{}\x1b[0m",
            d.component, d.detail
        );
    }
}

/// Default: run full audit with correlation.
fn cmd_audit(args: &[String]) {
    let report = full_audit();

    println!("╔══════════════════════════════════════════════╗");
    println!("║  InnerWarden SMM — Firmware Security Audit   ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();
    println!("  Architecture: {:?}", report.arch);
    println!("  Timestamp:    {}", report.ts);
    println!("  Trust Score:  {}", format_trust(report.trust_score));
    println!();

    // Individual checks.
    for check in &report.checks {
        let (icon, color_code) = match check.status {
            CheckStatus::Secure => ("✓", "\x1b[32m"),
            CheckStatus::Warning => ("⚠", "\x1b[33m"),
            CheckStatus::Critical => ("✗", "\x1b[31m"),
            CheckStatus::Unavailable => ("–", "\x1b[90m"),
        };
        let reset = "\x1b[0m";
        let conf = if check.confidence > 0.0 {
            format!(" \x1b[90m({:.0}%)\x1b[0m", check.confidence * 100.0)
        } else {
            String::new()
        };

        println!(
            "  {color_code}{icon}{reset} [{id}] {name}{conf}",
            id = check.id,
            name = check.name,
        );
        println!("    {color_code}{detail}{reset}", detail = check.detail);
        println!();
    }

    // Correlated threats.
    if !report.correlated_threats.is_empty() {
        println!("  \x1b[35;1m══ Correlated Threats ══\x1b[0m");
        println!();
        for threat in &report.correlated_threats {
            let color = if threat.confidence >= 0.9 {
                "\x1b[31;1m"
            } else if threat.confidence >= 0.7 {
                "\x1b[31m"
            } else {
                "\x1b[33m"
            };
            println!(
                "  {color}⚡ [{id}] {name} ({conf:.0}% confidence)\x1b[0m",
                id = threat.id,
                name = threat.name,
                conf = threat.confidence * 100.0,
            );
            println!("    {color}{detail}\x1b[0m", detail = threat.detail);
            println!("    Evidence:");
            for e in &threat.evidence {
                println!("      → {e}");
            }
            println!();
        }
    }

    // Summary.
    let secure = report
        .checks
        .iter()
        .filter(|c| c.status == CheckStatus::Secure)
        .count();
    let warnings = report
        .checks
        .iter()
        .filter(|c| c.status == CheckStatus::Warning)
        .count();
    let critical = report
        .checks
        .iter()
        .filter(|c| c.status == CheckStatus::Critical)
        .count();
    let unavailable = report
        .checks
        .iter()
        .filter(|c| c.status == CheckStatus::Unavailable)
        .count();

    println!("  ──────────────────────────────────────────");
    println!(
        "  \x1b[32m{secure} secure\x1b[0m  \
         \x1b[33m{warnings} warnings\x1b[0m  \
         \x1b[31m{critical} critical\x1b[0m  \
         \x1b[90m{unavailable} unavailable\x1b[0m  \
         \x1b[35m{corr} correlated\x1b[0m",
        corr = report.correlated_threats.len(),
    );

    if critical > 0 || !report.correlated_threats.is_empty() {
        println!();
        if report.trust_score < 0.1 {
            println!(
                "  \x1b[31;1m⚠ FIRMWARE INTEGRITY COMPROMISED — investigate immediately.\x1b[0m"
            );
        } else if report.trust_score < 0.5 {
            println!(
                "  \x1b[31m⚠ Firmware trust degraded — review correlated threats above.\x1b[0m"
            );
        }
    }

    // Baseline hint.
    let baseline_path = baseline::FirmwareBaseline::default_path();
    if !baseline_path.exists() {
        println!();
        println!("  \x1b[36mTip: run `innerwarden-smm baseline` to enable drift detection.\x1b[0m");
    }

    // JSON output.
    if args.iter().any(|a| a == "--json") {
        println!();
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    }
}

fn format_trust(score: f64) -> String {
    let pct = (score * 100.0) as u32;
    let (color, label) = if pct >= 90 {
        ("\x1b[32m", "TRUSTED")
    } else if pct >= 60 {
        ("\x1b[33m", "DEGRADED")
    } else if pct >= 30 {
        ("\x1b[31m", "AT RISK")
    } else {
        ("\x1b[31;1m", "COMPROMISED")
    };
    format!("{color}{pct}% — {label}\x1b[0m")
}
