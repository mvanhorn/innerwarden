use innerwarden_hypervisor::{full_audit, CheckStatus, Environment};

fn render_environment_label(environment: &Environment) -> String {
    match environment {
        Environment::BareMetal => "\x1b[32mBare Metal\x1b[0m".to_string(),
        Environment::VirtualMachine { hypervisor } => {
            format!("\x1b[36mVirtual Machine ({hypervisor})\x1b[0m")
        }
        Environment::HypervisorHost { vm_count } => {
            format!("\x1b[35mKVM Host ({vm_count} VMs)\x1b[0m")
        }
        Environment::UnknownHypervisor => "\x1b[31;1mUNKNOWN HYPERVISOR\x1b[0m".to_string(),
    }
}

fn status_style(status: &CheckStatus) -> (&'static str, &'static str) {
    match status {
        CheckStatus::Secure => ("✓", "\x1b[32m"),
        CheckStatus::Warning => ("⚠", "\x1b[33m"),
        CheckStatus::Critical => ("✗", "\x1b[31m"),
        CheckStatus::Unavailable => ("–", "\x1b[90m"),
    }
}

fn main() {
    let report = full_audit();

    println!("╔══════════════════════════════════════════════╗");
    println!("║  InnerWarden Hypervisor — Ring -1 Audit      ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    let env_str = render_environment_label(&report.environment);
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
        let (icon, color) = status_style(&check.status);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_trust_marks_trusted_at_ninety_plus() {
        // Covers the highest trust band so strong scores render as TRUSTED
        // with the expected percentage in the summary footer.
        let trust = format_trust(0.91);
        assert!(trust.contains("TRUSTED"));
        assert!(trust.contains("91%"));
    }

    #[test]
    fn format_trust_marks_degraded_between_sixty_and_ninety() {
        // Covers the middle trust band that should communicate DEGRADED status
        // without jumping directly to compromise wording.
        let trust = format_trust(0.75);
        assert!(trust.contains("DEGRADED"));
        assert!(trust.contains("75%"));
    }

    #[test]
    fn format_trust_marks_compromised_below_sixty() {
        // Covers the low-trust path to ensure risky hosts are labeled
        // COMPROMISED in the CLI output.
        let trust = format_trust(0.40);
        assert!(trust.contains("COMPROMISED"));
        assert!(trust.contains("40%"));
    }

    #[test]
    fn render_environment_label_formats_vm_and_host_variants() {
        // Verifies environment rendering for VM and hypervisor-host contexts
        // so operators see role-specific labels at a glance.
        let vm = render_environment_label(&Environment::VirtualMachine {
            hypervisor: "KVM".to_string(),
        });
        let host = render_environment_label(&Environment::HypervisorHost { vm_count: 3 });
        assert!(vm.contains("Virtual Machine (KVM)"));
        assert!(host.contains("KVM Host (3 VMs)"));
    }

    #[test]
    fn status_style_maps_every_check_state() {
        // Guards icon/color mapping used by deep-check rendering for all
        // status variants emitted by the audit pipeline.
        assert_eq!(status_style(&CheckStatus::Secure), ("✓", "\x1b[32m"));
        assert_eq!(status_style(&CheckStatus::Warning), ("⚠", "\x1b[33m"));
        assert_eq!(status_style(&CheckStatus::Critical), ("✗", "\x1b[31m"));
        assert_eq!(status_style(&CheckStatus::Unavailable), ("–", "\x1b[90m"));
    }
}
