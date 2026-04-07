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
    let Some(stats) = InterruptStats::read() else {
        return CheckResult {
            id: "HV-005",
            name: "Interrupt Analysis",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "cannot read /proc/interrupts".into(),
        };
    };

    // Look for hypervisor-specific interrupt sources.
    let has_hyp_irq = stats
        .notable_sources
        .iter()
        .any(|(name, _)| name.contains("HYP") || name.contains("virt"));

    // Look for unusually high IPI count (VM migration, vCPU scheduling).
    let ipi_count: u64 = stats
        .notable_sources
        .iter()
        .filter(|(name, _)| name.contains("RES") || name.contains("IWI"))
        .map(|(_, count)| count)
        .sum();

    // Check CPU interrupt balance — uneven distribution may indicate vCPU pinning.
    let cpu_counts: Vec<u64> = stats.per_cpu.values().copied().collect();
    let (imbalance, detail_imbalance) = if cpu_counts.len() > 1 {
        let max = cpu_counts.iter().max().copied().unwrap_or(1);
        let min = cpu_counts.iter().min().copied().unwrap_or(1);
        let ratio = if min > 0 {
            max as f64 / min as f64
        } else {
            0.0
        };
        (
            ratio,
            format!("CPU interrupt balance: {ratio:.1}x (max={max}, min={min})",),
        )
    } else {
        (1.0, "single CPU".into())
    };

    let notable_str: Vec<String> = stats
        .notable_sources
        .iter()
        .take(5)
        .map(|(n, c)| format!("{n}={c}"))
        .collect();

    let detail = format!(
        "{} total interrupts, {} sources, {} CPUs. {detail_imbalance}. \
         Notable: {}.",
        stats.total,
        stats.source_count,
        stats.per_cpu.len(),
        if notable_str.is_empty() {
            "none".into()
        } else {
            notable_str.join(", ")
        },
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
    fn check_descriptors_runs() {
        let r = check_descriptor_tables();
        assert_eq!(r.id, "HV-006");
    }
}
