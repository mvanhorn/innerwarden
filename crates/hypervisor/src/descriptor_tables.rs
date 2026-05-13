//! Descriptor table analysis — IDTR/GDTR position check (Red Pill technique).
//!
//! The original "Red Pill" (2004) detected VMs by reading the IDTR (Interrupt
//! Descriptor Table Register) — on bare metal, IDTR base is at a predictable
//! high address, while inside a VM it's relocated.
//!
//! Modern hypervisors have mitigated this by virtualizing SIDT/SGDT properly,
//! but we can still detect:
//! - Multiple descriptor tables (one per CPU on SMP)
//! - Descriptor table address range anomalies
//! - Interrupt delivery overhead via /proc/interrupts analysis
//!
//! On ARM: equivalent is VBAR_EL1 (Vector Base Address Register),
//! but it's not readable from EL0. We use /proc/interrupts instead.

use crate::{confidence, CheckResult, CheckStatus};
use std::collections::BTreeMap;
use std::fs;

/// Interrupt statistics from /proc/interrupts.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InterruptStats {
    /// Total interrupts across all CPUs.
    pub total: u64,
    /// Interrupts per CPU (cpu_id → count).
    pub per_cpu: BTreeMap<u32, u64>,
    /// Number of interrupt sources.
    pub source_count: usize,
    /// Interesting sources (timer, IPI, NMI, etc.).
    pub notable_sources: Vec<(String, u64)>,
}

impl InterruptStats {
    pub fn read() -> Option<Self> {
        let content = fs::read_to_string("/proc/interrupts").ok()?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Option<Self> {
        let mut lines = content.lines();

        // First line: CPU headers.
        let header = lines.next()?;
        let cpu_count = header.split_whitespace().count();

        let mut total = 0u64;
        let mut per_cpu: BTreeMap<u32, u64> = BTreeMap::new();
        let mut source_count = 0;
        let mut notable = Vec::new();

        for line in lines {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            // First field: IRQ number or name (e.g., "0:", "NMI:", "LOC:").
            let irq_name = parts[0].trim_end_matches(':');
            source_count += 1;

            // Sum counts across CPUs.
            let mut line_total = 0u64;
            for (i, &count_str) in parts[1..].iter().enumerate() {
                if i >= cpu_count {
                    break;
                }
                if let Ok(count) = count_str.parse::<u64>() {
                    line_total += count;
                    *per_cpu.entry(i as u32).or_insert(0) += count;
                }
            }
            total += line_total;

            // Track notable interrupt sources.
            let notable_names = [
                "NMI", "LOC", "PMI", "IWI", "RES", "TLB", "MCP", "HYP", "HRTimer",
            ];
            if notable_names.iter().any(|n| irq_name.contains(n)) && line_total > 0 {
                notable.push((irq_name.to_string(), line_total));
            }
        }

        Some(Self {
            total,
            per_cpu,
            source_count,
            notable_sources: notable,
        })
    }
}

fn interrupt_analysis_unavailable() -> CheckResult {
    CheckResult {
        id: "HV-005",
        name: "Interrupt Analysis",
        status: CheckStatus::Unavailable,
        confidence: 0.0,
        detail: "cannot read /proc/interrupts".into(),
    }
}

fn has_hypervisor_interrupt_source(notable_sources: &[(String, u64)]) -> bool {
    notable_sources
        .iter()
        .any(|(name, _)| name.contains("HYP") || name.contains("virt"))
}

fn interrupt_imbalance_detail(per_cpu: &BTreeMap<u32, u64>) -> (f64, String) {
    let cpu_counts: Vec<u64> = per_cpu.values().copied().collect();
    if cpu_counts.len() <= 1 {
        return (1.0, "single CPU".into());
    }

    let max = cpu_counts.iter().max().copied().unwrap_or(1);
    let min = cpu_counts.iter().min().copied().unwrap_or(1);
    let ratio = if min > 0 {
        max as f64 / min as f64
    } else {
        0.0
    };

    (
        ratio,
        format!("CPU interrupt balance: {ratio:.1}x (max={max}, min={min})"),
    )
}

fn notable_interrupt_summary(notable_sources: &[(String, u64)]) -> String {
    let notable: Vec<String> = notable_sources
        .iter()
        .take(5)
        .map(|(name, count)| format!("{name}={count}"))
        .collect();

    if notable.is_empty() {
        "none".into()
    } else {
        notable.join(", ")
    }
}

fn check_interrupt_analysis_from_stats(stats: Option<InterruptStats>) -> CheckResult {
    let Some(stats) = stats else {
        return interrupt_analysis_unavailable();
    };

    let has_hyp_irq = has_hypervisor_interrupt_source(&stats.notable_sources);
    let (imbalance, detail_imbalance) = interrupt_imbalance_detail(&stats.per_cpu);
    let notable_str = notable_interrupt_summary(&stats.notable_sources);

    let detail = format!(
        "{} total interrupts, {} sources, {} CPUs. {detail_imbalance}. \
         Notable: {}.",
        stats.total,
        stats.source_count,
        stats.per_cpu.len(),
        notable_str,
    );

    if has_hyp_irq {
        return CheckResult {
            id: "HV-005",
            name: "Interrupt Analysis",
            status: CheckStatus::Secure,
            confidence: confidence(0.5, 0.9),
            detail: format!("VIRTUALIZED — hypervisor interrupt source found. {detail}"),
        };
    }

    if imbalance > 10.0 {
        return CheckResult {
            id: "HV-005",
            name: "Interrupt Analysis",
            status: CheckStatus::Warning,
            confidence: confidence(0.4, 0.6),
            detail: format!(
                "CPU interrupt imbalance {imbalance:.1}x — may indicate vCPU pinning. {detail}"
            ),
        };
    }

    CheckResult {
        id: "HV-005",
        name: "Interrupt Analysis",
        status: CheckStatus::Secure,
        confidence: confidence(0.3, 0.7),
        detail: format!("interrupt patterns normal. {detail}"),
    }
}

// ── x86 Descriptor Table Reading ────────────────────────────────────────

/// IDTR value (base + limit) — x86 only.
#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
struct DescriptorTableRegister {
    limit: u16,
    base: u64,
}

/// Read IDTR via SIDT instruction (x86_64 only).
/// Returns (base, limit). SIDT is unprivileged on x86.
#[cfg(target_arch = "x86_64")]
fn read_idtr() -> (u64, u16) {
    let mut dtr = DescriptorTableRegister { limit: 0, base: 0 };
    unsafe {
        std::arch::asm!("sidt [{}]", in(reg) &mut dtr, options(nostack));
    }
    (dtr.base, dtr.limit)
}

/// Read GDTR via SGDT instruction (x86_64 only).
#[cfg(target_arch = "x86_64")]
fn read_gdtr() -> (u64, u16) {
    let mut dtr = DescriptorTableRegister { limit: 0, base: 0 };
    unsafe {
        std::arch::asm!("sgdt [{}]", in(reg) &mut dtr, options(nostack));
    }
    (dtr.base, dtr.limit)
}

// ── Check functions ─────────────────────────────────────────────────────

/// Analyze interrupt delivery patterns for VM indicators.
pub fn check_interrupt_analysis() -> CheckResult {
    check_interrupt_analysis_from_stats(InterruptStats::read())
}

/// Descriptor table check (x86 only — SIDT/SGDT Red Pill variant).
pub fn check_descriptor_tables() -> CheckResult {
    #[cfg(target_arch = "x86_64")]
    {
        let (idt_base, idt_limit) = read_idtr();
        let (gdt_base, gdt_limit) = read_gdtr();

        // On bare-metal Linux, IDT/GDT base is in kernel space (0xFFFF...).
        // In a VM, the hypervisor may relocate these.
        let kernel_space = idt_base > 0xFFFF_0000_0000_0000;

        let detail = format!(
            "IDTR: base=0x{idt_base:016X} limit={idt_limit}. \
             GDTR: base=0x{gdt_base:016X} limit={gdt_limit}. \
             Kernel space: {kernel_space}.",
        );

        if !kernel_space && idt_base != 0 {
            return CheckResult {
                id: "HV-006",
                name: "Descriptor Tables (SIDT/SGDT)",
                status: CheckStatus::Warning,
                confidence: confidence(0.6, 0.7),
                detail: format!("IDT base NOT in kernel space — possible VM relocation. {detail}"),
            };
        }

        return CheckResult {
            id: "HV-006",
            name: "Descriptor Tables (SIDT/SGDT)",
            status: CheckStatus::Secure,
            confidence: confidence(0.4, 0.8),
            detail: format!("descriptor tables in expected kernel range. {detail}"),
        };
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        CheckResult {
            id: "HV-006",
            name: "Descriptor Tables (SIDT/SGDT)",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "SIDT/SGDT only available on x86_64".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(per_cpu: &[(u32, u64)], notable_sources: &[(&str, u64)]) -> InterruptStats {
        InterruptStats {
            total: per_cpu.iter().map(|(_, count)| count).sum::<u64>(),
            per_cpu: per_cpu.iter().copied().collect(),
            source_count: notable_sources.len(),
            notable_sources: notable_sources
                .iter()
                .map(|(name, count)| ((*name).to_string(), *count))
                .collect(),
        }
    }

    #[test]
    fn interrupt_stats_runs() {
        let stats = InterruptStats::read();
        // On macOS this returns None (no /proc), on Linux should succeed.
        let _ = stats;
    }

    #[test]
    fn check_interrupts_runs() {
        let r = check_interrupt_analysis();
        assert_eq!(r.id, "HV-005");
    }

    #[test]
    fn interrupt_analysis_reports_unavailable_when_stats_are_missing() {
        let result = check_interrupt_analysis_from_stats(None);

        assert_eq!(result.status, CheckStatus::Unavailable);
        assert_eq!(result.confidence, 0.0);
        assert_eq!(result.detail, "cannot read /proc/interrupts");
    }

    #[test]
    fn interrupt_analysis_reports_virtualized_for_hypervisor_source() {
        let result =
            check_interrupt_analysis_from_stats(Some(stats(&[(0, 50), (1, 50)], &[("HYP", 7)])));

        assert_eq!(result.status, CheckStatus::Secure);
        assert_eq!(result.confidence, confidence(0.5, 0.9));
        assert!(result.detail.contains("VIRTUALIZED"));
        assert!(result.detail.contains("HYP=7"));
    }

    #[test]
    fn interrupt_analysis_warns_on_large_cpu_imbalance() {
        let result = check_interrupt_analysis_from_stats(Some(stats(&[(0, 1), (1, 20)], &[])));

        assert_eq!(result.status, CheckStatus::Warning);
        assert_eq!(result.confidence, confidence(0.4, 0.6));
        assert!(result.detail.contains("imbalance 20.0x"));
    }

    #[test]
    fn interrupt_analysis_reports_normal_balanced_interrupts() {
        let result = check_interrupt_analysis_from_stats(Some(stats(&[(0, 10), (1, 20)], &[])));

        assert_eq!(result.status, CheckStatus::Secure);
        assert_eq!(result.confidence, confidence(0.3, 0.7));
        assert!(result.detail.contains("interrupt patterns normal"));
        assert!(result.detail.contains("Notable: none"));
    }

    #[test]
    fn interrupt_imbalance_treats_single_cpu_as_balanced() {
        let (ratio, detail) = interrupt_imbalance_detail(&[(0, 42)].into_iter().collect());

        assert_eq!(ratio, 1.0);
        assert_eq!(detail, "single CPU");
    }

    #[test]
    fn interrupt_imbalance_handles_zero_minimum_without_dividing() {
        let (ratio, detail) = interrupt_imbalance_detail(&[(0, 0), (1, 10)].into_iter().collect());

        assert_eq!(ratio, 0.0);
        assert!(detail.contains("max=10"));
        assert!(detail.contains("min=0"));
    }

    #[test]
    fn notable_interrupt_summary_limits_to_first_five_sources() {
        let notable = [
            ("NMI".to_string(), 1),
            ("LOC".to_string(), 2),
            ("PMI".to_string(), 3),
            ("IWI".to_string(), 4),
            ("RES".to_string(), 5),
            ("TLB".to_string(), 6),
        ];

        let summary = notable_interrupt_summary(&notable);

        assert_eq!(summary, "NMI=1, LOC=2, PMI=3, IWI=4, RES=5");
    }

    #[test]
    fn check_descriptors_runs() {
        let r = check_descriptor_tables();
        assert_eq!(r.id, "HV-006");
    }

    #[test]
    fn parse_interrupt_stats_basic() {
        let content = "            CPU0       CPU1
   0:        100        200   PCI-MSI edge      eth0
 NMI:       1000       2000   Non-maskable interrupts
 LOC:       5000       6000   Local timer interrupts
";
        let stats = InterruptStats::parse(content).expect("should parse");
        assert_eq!(stats.source_count, 3);
        assert_eq!(stats.total, 100 + 200 + 1000 + 2000 + 5000 + 6000);
        assert_eq!(stats.per_cpu[&0], 100 + 1000 + 5000);
        assert_eq!(stats.per_cpu[&1], 200 + 2000 + 6000);
        // NMI and LOC are notable.
        assert!(stats.notable_sources.iter().any(|(n, _)| n == "NMI"));
        assert!(stats.notable_sources.iter().any(|(n, _)| n == "LOC"));
    }

    #[test]
    fn parse_interrupt_stats_skips_short_lines() {
        let content = "CPU0\n\n  short";
        // Should not crash on short/blank lines.
        let _ = InterruptStats::parse(content);
    }

    #[test]
    fn parse_interrupt_stats_single_cpu() {
        let content = "            CPU0
   0:        500
";
        let stats = InterruptStats::parse(content).expect("single cpu should parse");
        assert_eq!(stats.total, 500);
        assert_eq!(stats.per_cpu.len(), 1);
    }

    #[test]
    fn parse_interrupt_stats_no_notable_when_zero() {
        let content = "            CPU0
 NMI:           0
";
        let stats = InterruptStats::parse(content).expect("should parse");
        // NMI count is zero — should NOT appear in notable.
        assert!(stats.notable_sources.is_empty());
    }

    #[test]
    fn parse_interrupt_stats_ignores_non_cpu_fields_after_header_count() {
        let content = "            CPU0       CPU1
   0:        100        200   PCI-MSI edge      eth0
";
        let stats = InterruptStats::parse(content).expect("should parse");

        assert_eq!(stats.total, 300);
        assert_eq!(stats.per_cpu[&0], 100);
        assert_eq!(stats.per_cpu[&1], 200);
    }

    #[test]
    fn parse_interrupt_stats_returns_none_for_empty_content() {
        assert!(InterruptStats::parse("").is_none());
    }
}
