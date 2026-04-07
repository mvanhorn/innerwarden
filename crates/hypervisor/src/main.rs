use innerwarden_hypervisor::{full_audit, CheckStatus, Environment};

fn main() {
    let report = full_audit();

    println!("╔══════════════════════════════════════════════╗");
    println!("║  InnerWarden Hypervisor — Ring -1 Audit      ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    let env_str = match &report.environment {
        Environment::BareMetal => "\x1b[32mBare Metal\x1b[0m".to_string(),
        Environment::VirtualMachine { hypervisor } => {
            format!("\x1b[36mVirtual Machine ({hypervisor})\x1b[0m")
        }
        Environment::HypervisorHost { vm_count } => {
            format!("\x1b[35mKVM Host ({vm_count} VMs)\x1b[0m")
        }
        Environment::UnknownHypervisor => "\x1b[31;1mUNKNOWN HYPERVISOR\x1b[0m".to_string(),
    };
    println!("  Environment: {env_str}");
    println!(
        "  VM Score:    {}/100 ({} evidence signals)",
        report.vm_verdict.score, report.vm_verdict.evidence_count
    );
    if let Some(ref brand) = report.vm_verdict.brand {
        println!("  VM Brand:    \x1b[36m{brand}\x1b[0m");
    }
    println!("  Trust Score: {}", format_trust(report.trust_score));
    println!();

    // Deep checks.
    println!("  \x1b[1m── Deep Checks ──\x1b[0m");
    println!();
    for check in &report.checks {
        let (icon, color) = match check.status {
            CheckStatus::Secure => ("✓", "\x1b[32m"),
            CheckStatus::Warning => ("⚠", "\x1b[33m"),
            CheckStatus::Critical => ("✗", "\x1b[31m"),
            CheckStatus::Unavailable => ("–", "\x1b[90m"),
        };
        let conf = if check.confidence > 0.0 {
            format!(" \x1b[90m({:.0}%)\x1b[0m", check.confidence * 100.0)
        } else {
            String::new()
        };
        println!(
            "  {color}{icon}\x1b[0m [{id}] {name}{conf}",
            id = check.id,
            name = check.name
        );
        println!("    {color}{detail}\x1b[0m", detail = check.detail);
        println!();
    }

    // Probe evidence.
    let positive_probes: Vec<_> = report
        .probe_results
        .iter()
        .filter(|p| p.score > 0)
        .collect();
    if !positive_probes.is_empty() {
        println!(
            "  \x1b[1m── VM Evidence ({} signals) ──\x1b[0m",
            positive_probes.len()
        );
        println!();
        for p in &positive_probes {
            let color = if p.score >= 80 {
                "\x1b[36m"
            } else if p.score >= 50 {
                "\x1b[33m"
            } else {
                "\x1b[90m"
            };
            println!(
                "  {color}[{score:>3}] {id}: {detail}\x1b[0m",
                score = p.score,
                id = p.id,
                detail = p.detail,
            );
        }
        println!();
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
    let unavail = report
        .checks
        .iter()
        .filter(|c| c.status == CheckStatus::Unavailable)
        .count();

    println!("  ──────────────────────────────────────────");
    println!(
        "  \x1b[32m{secure} secure\x1b[0m  \x1b[33m{warnings} warnings\x1b[0m  \
         \x1b[31m{critical} critical\x1b[0m  \x1b[90m{unavail} unavailable\x1b[0m  \
         \x1b[36m{probes} probes ({evidence} positive)\x1b[0m",
        probes = report.probe_results.len(),
        evidence = report.vm_verdict.evidence_count,
    );

    if std::env::args().any(|a| a == "--json") {
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
    } else {
        ("\x1b[31;1m", "COMPROMISED")
    };
    format!("{color}{pct}% — {label}\x1b[0m")
}
