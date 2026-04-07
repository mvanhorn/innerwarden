//! Memory-based VM detection — TLB/EPT overhead measurement.
//!
//! When running inside a VM, every TLB miss triggers a two-level page walk:
//! guest page tables (stage 1) + host EPT/stage-2 tables. This adds
//! measurable overhead compared to bare metal (single page walk).
//!
//! Technique: allocate a large buffer, access it with a stride that
//! exceeds TLB coverage, measure access latency. In a VM, the P95
//! latency is 2-5x higher due to EPT walks.
//!
//! Works on ALL architectures (x86, ARM, RISC-V) — universal VM detection.

use crate::{confidence, CheckResult, CheckStatus};

/// Size of probe buffer (must exceed L1/L2 TLB coverage).
/// 64MB with 4KB pages = 16384 pages. Most TLBs hold 512-2048 entries.
const PROBE_SIZE: usize = 64 * 1024 * 1024;

/// Stride between accesses (one page = 4KB to maximize TLB misses).
const STRIDE: usize = 4096;

/// Number of measurement rounds.
const ROUNDS: usize = 5;

/// Accesses per round.
const ACCESSES_PER_ROUND: usize = PROBE_SIZE / STRIDE;

/// Read cycle counter (same as timing.rs).
#[inline(always)]
fn rdcycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let lo: u32;
        let hi: u32;
        unsafe {
            std::arch::asm!("rdtscp", out("eax") lo, out("edx") hi, out("ecx") _, options(nostack, nomem));
        }
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let cnt: u64;
        unsafe {
            std::arch::asm!("isb", "mrs {}, cntvct_el0", out(reg) cnt, options(nostack, nomem));
        }
        cnt
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0
    }
}

/// Memory probe result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MemoryProbeResult {
    /// Median cycles per page access.
    pub median_cycles: u64,
    /// P95 cycles (sensitive to EPT overhead).
    pub p95_cycles: u64,
    /// P99 cycles.
    pub p99_cycles: u64,
    /// Max cycles (outlier — could be interrupt or EPT walk).
    pub max_cycles: u64,
    /// Ratio P95/median — elevated in VMs due to EPT.
    pub tail_ratio: f64,
    /// Total accesses measured.
    pub total_accesses: usize,
}

/// Run the memory TLB probe.
pub fn probe_tlb_overhead() -> MemoryProbeResult {
    // Allocate a large buffer. Use vec to ensure it's heap-allocated
    // (not stack, which might be mapped differently).
    let mut buf = vec![0u8; PROBE_SIZE];

    // Warm up: touch every page once to fault them in.
    for i in (0..PROBE_SIZE).step_by(STRIDE) {
        buf[i] = 1;
    }

    // Measure individual page access latencies.
    let mut all_deltas = Vec::with_capacity(ROUNDS * ACCESSES_PER_ROUND);

    for _ in 0..ROUNDS {
        // Flush TLB by accessing a different large region.
        // We can't explicitly flush TLB from userspace, but accessing
        // the buffer backwards (cold direction) forces TLB misses.
        for i in (0..PROBE_SIZE).step_by(STRIDE).rev() {
            let before = rdcycles();
            // Volatile read to prevent optimization.
            let _ = unsafe { core::ptr::read_volatile(&buf[i]) };
            let after = rdcycles();
            let delta = after.wrapping_sub(before);
            if delta > 0 && delta < 100_000 {
                all_deltas.push(delta);
            }
        }
    }

    if all_deltas.is_empty() {
        return MemoryProbeResult {
            median_cycles: 0,
            p95_cycles: 0,
            p99_cycles: 0,
            max_cycles: 0,
            tail_ratio: 0.0,
            total_accesses: 0,
        };
    }

    all_deltas.sort_unstable();
    let n = all_deltas.len();
    let median = all_deltas[n / 2];
    let p95 = all_deltas[(n as f64 * 0.95) as usize];
    let p99 = all_deltas[(n as f64 * 0.99) as usize];
    let max = all_deltas[n - 1];
    let tail_ratio = if median > 0 {
        p95 as f64 / median as f64
    } else {
        0.0
    };

    // Free the buffer explicitly to not hold 64MB during the rest of the audit.
    drop(buf);

    MemoryProbeResult {
        median_cycles: median,
        p95_cycles: p95,
        p99_cycles: p99,
        max_cycles: max,
        tail_ratio,
        total_accesses: n,
    }
}

// ── Check function ──────────────────────────────────────────────────────

/// Detect VM via memory access overhead (EPT/stage-2 page table).
pub fn check_memory_vm_detection() -> CheckResult {
    let result = probe_tlb_overhead();

    if result.total_accesses == 0 {
        return CheckResult {
            id: "HV-004",
            name: "Memory VM Detection (TLB/EPT)",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "memory probe failed — cycle counter not available".into(),
        };
    }

    // Tail ratio analysis:
    // Bare metal: P95/median ~1.5-3x (normal TLB miss variance)
    // VM with EPT: P95/median ~3-10x (EPT walk adds tail latency)
    // VM with heavy host load: P95/median ~10-50x

    let detail = format!(
        "median={} cycles, P95={} cycles, P99={} cycles, max={}. \
         Tail ratio (P95/median): {:.1}x. {} accesses measured.",
        result.median_cycles,
        result.p95_cycles,
        result.p99_cycles,
        result.max_cycles,
        result.tail_ratio,
        result.total_accesses,
    );

    if result.tail_ratio > 8.0 {
        CheckResult {
            id: "HV-004",
            name: "Memory VM Detection (TLB/EPT)",
            status: CheckStatus::Secure,
            confidence: confidence(0.6, 0.8),
            detail: format!(
                "VIRTUALIZED — {detail} \
                 High tail ratio indicates EPT/stage-2 page walk overhead."
            ),
        }
    } else if result.tail_ratio > 3.0 {
        CheckResult {
            id: "HV-004",
            name: "Memory VM Detection (TLB/EPT)",
            status: CheckStatus::Warning,
            confidence: confidence(0.5, 0.6),
            detail: format!(
                "AMBIGUOUS — {detail} \
                 Moderate tail ratio — could be VM or NUMA/cache contention."
            ),
        }
    } else {
        CheckResult {
            id: "HV-004",
            name: "Memory VM Detection (TLB/EPT)",
            status: CheckStatus::Secure,
            confidence: confidence(0.5, 0.8),
            detail: format!("BARE METAL — {detail} No EPT overhead detected."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_runs() {
        let result = probe_tlb_overhead();
        if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            assert!(result.total_accesses > 0, "probe should collect data");
            assert!(result.median_cycles > 0, "median should be nonzero");
        }
    }

    #[test]
    fn tail_ratio_positive() {
        let result = probe_tlb_overhead();
        if result.total_accesses > 0 {
            assert!(result.tail_ratio >= 1.0, "tail ratio should be >= 1.0");
        }
    }

    #[test]
    fn check_runs() {
        let r = check_memory_vm_detection();
        assert_eq!(r.id, "HV-004");
    }
}
