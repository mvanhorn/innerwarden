//! Chronomancy — timing-based firmware attestation.
//!
//! Inspired by MITRE's BIOS Chronomancy (2013): detect firmware modifications
//! by measuring execution timing. A rootkit adds code → code takes time →
//! timing profile changes detectably.
//!
//! **Universal**: works on any CPU with a cycle counter.
//! - x86_64: RDTSC (Time Stamp Counter)
//! - aarch64: CNTVCT_EL0 (Counter-timer Virtual Count)
//!
//! **No hardware dependency**: no TPM, no MSR, no kernel module.
//! **Read-only**: only reads cycle counters, never writes anything.
//!
//! # How it works
//!
//! 1. Execute a deterministic workload (e.g., read a sysfs path N times)
//! 2. Measure CPU cycles before and after
//! 3. If firmware intercepts (SMI), cycles spike
//! 4. Compare against baseline timing profile
//! 5. Statistical deviation beyond threshold = anomaly
//!
//! The key insight: you don't need to READ firmware to know if it changed.
//! You measure how long known operations take. A firmware rootkit that hooks
//! SMIs adds latency. Even 51 bytes of injected code is detectable through
//! timing jitter (MITRE proved this with "Tick" malware).

use crate::{confidence, CheckResult, CheckStatus};
use std::time::Instant;

// ── Cycle counter primitives ────────────────────────────────────────────

/// Read the CPU cycle counter.
///
/// - x86_64: `RDTSC` instruction (reads Time Stamp Counter)
/// - aarch64: `MRS CNTVCT_EL0` (reads virtual count register)
/// - fallback: `std::time::Instant` (nanosecond resolution, less precise)
#[inline(always)]
pub fn read_cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // RDTSC: returns 64-bit cycle count in EDX:EAX.
        // Safe, unprivileged instruction available in Ring 3.
        let lo: u32;
        let hi: u32;
        unsafe {
            std::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nostack, nomem),
            );
        }
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(target_arch = "aarch64")]
    {
        // CNTVCT_EL0: virtual counter, accessible from EL0 (userspace).
        // Counts at a fixed frequency (typically CPU reference clock).
        let cnt: u64;
        unsafe {
            std::arch::asm!(
                "mrs {}, cntvct_el0",
                out(reg) cnt,
                options(nostack, nomem),
            );
        }
        cnt
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        // Fallback: use Instant (lower precision but still useful).
        Instant::now().elapsed().as_nanos() as u64
    }
}

/// Serialize execution to prevent out-of-order measurement (x86 only).
/// On ARM, the ISB instruction serves a similar purpose.
#[inline(always)]
fn serialize() {
    #[cfg(target_arch = "x86_64")]
    {
        // CPUID serializes the instruction stream — ensures RDTSC
        // measures what we intend, not speculated future instructions.
        unsafe {
            std::arch::asm!(
                "push rbx",
                "cpuid",
                "pop rbx",
                inout("eax") 0 => _,
                out("ecx") _,
                out("edx") _,
                options(nostack),
            );
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // ISB: instruction synchronization barrier.
        unsafe {
            std::arch::asm!("isb", options(nostack, nomem));
        }
    }
}

// ── Timing workloads ────────────────────────────────────────────────────

/// A deterministic workload that exercises a known code path.
/// The goal is to produce a stable timing signature that changes
/// if firmware hooks intercept execution.
#[derive(Debug, Clone, Copy)]
pub enum Workload {
    /// Pure CPU: tight loop of arithmetic operations.
    /// Detects SMI interception (SMI adds ~100μs latency).
    CpuBound,
    /// Memory-bound: sequential reads from a buffer.
    /// Detects memory remapping by firmware.
    MemoryBound,
    /// Sysfs read: reads a small sysfs file N times.
    /// Detects I/O interception.
    SysfsRead,
}

/// Result of a single timing measurement.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimingSample {
    /// CPU cycles for this iteration.
    pub cycles: u64,
    /// Wall-clock nanoseconds for this iteration.
    pub nanos: u64,
}

/// Result of a complete timing profile.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimingProfile {
    pub workload: String,
    pub iterations: usize,
    pub samples: Vec<TimingSample>,
    /// Median cycles across all samples.
    pub median_cycles: u64,
    /// Mean cycles.
    pub mean_cycles: f64,
    /// Standard deviation of cycles.
    pub stddev_cycles: f64,
    /// Maximum cycles (potential SMI interception).
    pub max_cycles: u64,
    /// Minimum cycles (baseline for clean execution).
    pub min_cycles: u64,
    /// Number of outliers (> 3 stddev from mean).
    pub outlier_count: usize,
    /// Jitter ratio: max/median (1.0 = perfect, >2.0 = suspicious).
    pub jitter_ratio: f64,
}

/// Run a workload N times and collect cycle-accurate timing samples.
pub fn measure(workload: Workload, iterations: usize) -> TimingProfile {
    let mut samples = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        serialize();
        let t0 = Instant::now();
        let c0 = read_cycles();

        run_workload(workload);

        serialize();
        let c1 = read_cycles();
        let elapsed = t0.elapsed();

        samples.push(TimingSample {
            cycles: c1.wrapping_sub(c0),
            nanos: elapsed.as_nanos() as u64,
        });
    }

    let name = match workload {
        Workload::CpuBound => "cpu_bound",
        Workload::MemoryBound => "memory_bound",
        Workload::SysfsRead => "sysfs_read",
    };

    compute_profile(name, samples)
}

fn run_workload(workload: Workload) {
    match workload {
        Workload::CpuBound => workload_cpu(),
        Workload::MemoryBound => workload_memory(),
        Workload::SysfsRead => workload_sysfs(),
    }
}

/// Pure arithmetic loop — stable timing, any spike = interception.
#[inline(never)]
fn workload_cpu() {
    let mut x: u64 = 0xDEAD_BEEF;
    for _ in 0..10_000 {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
    }
    // Prevent optimization.
    std::hint::black_box(x);
}

/// Sequential memory reads — detects memory remapping.
#[inline(never)]
fn workload_memory() {
    let buf = vec![0u8; 64 * 1024]; // 64KB
    let mut sum: u64 = 0;
    for chunk in buf.chunks(64) {
        sum = sum.wrapping_add(chunk[0] as u64);
    }
    std::hint::black_box(sum);
}

/// Read a small sysfs file — detects I/O interception.
#[inline(never)]
fn workload_sysfs() {
    // /proc/uptime is universally available and tiny.
    let _ = std::fs::read_to_string("/proc/uptime");
}

// ── Statistical analysis ────────────────────────────────────────────────

fn compute_profile(name: &str, samples: Vec<TimingSample>) -> TimingProfile {
    let cycles: Vec<u64> = samples.iter().map(|s| s.cycles).collect();
    let n = cycles.len() as f64;

    let mean = cycles.iter().sum::<u64>() as f64 / n;
    let variance = cycles
        .iter()
        .map(|&c| (c as f64 - mean).powi(2))
        .sum::<f64>()
        / n;
    let stddev = variance.sqrt();
    let max = cycles.iter().copied().max().unwrap_or(0);
    let min = cycles.iter().copied().min().unwrap_or(0);

    let mut sorted = cycles.clone();
    sorted.sort_unstable();
    let median = sorted[sorted.len() / 2];

    let outlier_count = cycles
        .iter()
        .filter(|&&c| (c as f64 - mean).abs() > 3.0 * stddev)
        .count();

    let jitter_ratio = if median > 0 {
        max as f64 / median as f64
    } else {
        1.0
    };

    TimingProfile {
        workload: name.to_string(),
        iterations: samples.len(),
        samples,
        median_cycles: median,
        mean_cycles: mean,
        stddev_cycles: stddev,
        max_cycles: max,
        min_cycles: min,
        outlier_count,
        jitter_ratio,
    }
}

// ── Baseline comparison ─────────────────────────────────────────────────

/// Stored timing baseline for comparison.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimingBaseline {
    pub workload: String,
    pub median_cycles: u64,
    pub mean_cycles: f64,
    pub stddev_cycles: f64,
    pub captured_at: String,
}

impl From<&TimingProfile> for TimingBaseline {
    fn from(p: &TimingProfile) -> Self {
        Self {
            workload: p.workload.clone(),
            median_cycles: p.median_cycles,
            mean_cycles: p.mean_cycles,
            stddev_cycles: p.stddev_cycles,
            captured_at: ::chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Compare a current profile against a stored baseline.
/// Returns the number of standard deviations the current median
/// is from the baseline mean (z-score).
pub fn compare_timing(current: &TimingProfile, baseline: &TimingBaseline) -> TimingDrift {
    let z_score = if baseline.stddev_cycles > 0.0 {
        (current.median_cycles as f64 - baseline.mean_cycles) / baseline.stddev_cycles
    } else {
        0.0
    };

    let pct_change = if baseline.median_cycles > 0 {
        ((current.median_cycles as f64 - baseline.median_cycles as f64)
            / baseline.median_cycles as f64)
            * 100.0
    } else {
        0.0
    };

    TimingDrift {
        workload: current.workload.clone(),
        z_score,
        pct_change,
        baseline_median: baseline.median_cycles,
        current_median: current.median_cycles,
    }
}

/// Timing drift between current measurement and baseline.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimingDrift {
    pub workload: String,
    /// Z-score: how many standard deviations from baseline mean.
    /// > 3.0 = statistical anomaly, > 6.0 = almost certainly tampered.
    pub z_score: f64,
    /// Percentage change from baseline median.
    pub pct_change: f64,
    pub baseline_median: u64,
    pub current_median: u64,
}

// ── Check function ──────────────────────────────────────────────────────

/// Run timing attestation and check for anomalies.
///
/// This is the main entry point. Runs CPU-bound workload 100 times,
/// checks jitter ratio and outlier count.
pub fn check_timing_attestation() -> CheckResult {
    let profile = measure(Workload::CpuBound, 100);

    // Jitter ratio: max/median. Normal is 1.0-1.5.
    // SMI interception causes spikes to 10x-100x.
    if profile.jitter_ratio > 10.0 {
        CheckResult {
            id: "CHRONO-001",
            name: "Timing Attestation",
            status: CheckStatus::Critical,
            // High jitter + deterministic workload = very suspicious.
            confidence: confidence(0.85, 0.75),
            detail: format!(
                "TIMING ANOMALY: jitter ratio {:.1}x (max={} vs median={}). \
                 {} outliers in {} samples. Possible SMI interception or firmware hooking.",
                profile.jitter_ratio,
                profile.max_cycles,
                profile.median_cycles,
                profile.outlier_count,
                profile.iterations,
            ),
        }
    } else if profile.jitter_ratio > 3.0 || profile.outlier_count > 5 {
        CheckResult {
            id: "CHRONO-001",
            name: "Timing Attestation",
            status: CheckStatus::Warning,
            confidence: confidence(0.6, 0.6),
            detail: format!(
                "elevated jitter: ratio {:.1}x, {} outliers in {} samples. \
                 Could be power management, thermal throttling, or early-stage \
                 firmware activity. Median: {} cycles.",
                profile.jitter_ratio,
                profile.outlier_count,
                profile.iterations,
                profile.median_cycles,
            ),
        }
    } else {
        CheckResult {
            id: "CHRONO-001",
            name: "Timing Attestation",
            status: CheckStatus::Secure,
            confidence: confidence(0.7, 0.8),
            detail: format!(
                "timing stable: jitter {:.2}x, {} outliers, median {} cycles, \
                 stddev {:.0} cycles",
                profile.jitter_ratio,
                profile.outlier_count,
                profile.median_cycles,
                profile.stddev_cycles,
            ),
        }
    }
}

// ── hwlat_detector integration ──────────────────────────────────────────

/// Check the kernel's hardware latency detector for SMI evidence.
/// This reads from `/sys/kernel/debug/tracing/hwlat_detector/` if available.
/// No kernel module needed — uses the kernel's built-in tracer.
pub fn check_hwlat() -> CheckResult {
    let max_path = "/sys/kernel/debug/tracing/hwlat_detector/max";
    match std::fs::read_to_string(max_path) {
        Ok(val) => {
            let max_us: u64 = val.trim().parse().unwrap_or(0);
            if max_us > 500 {
                // > 500μs latency spike = SMI activity
                CheckResult {
                    id: "CHRONO-002",
                    name: "Hardware Latency (hwlat)",
                    status: CheckStatus::Warning,
                    confidence: confidence(0.7, 0.9),
                    detail: format!(
                        "hwlat detected {max_us}μs max latency spike. \
                         Normal is <100μs. High values indicate SMI activity."
                    ),
                }
            } else {
                CheckResult {
                    id: "CHRONO-002",
                    name: "Hardware Latency (hwlat)",
                    status: CheckStatus::Secure,
                    confidence: confidence(0.7, 0.9),
                    detail: format!("hwlat max latency: {max_us}μs (normal)"),
                }
            }
        }
        Err(_) => CheckResult {
            id: "CHRONO-002",
            name: "Hardware Latency (hwlat)",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "hwlat_detector not available (need debugfs + root)".into(),
        },
    }
}

// ── IMA log reader ──────────────────────────────────────────────────────

/// Check Linux IMA (Integrity Measurement Architecture) runtime log.
/// Reads `/sys/kernel/security/ima/ascii_runtime_measurements`.
/// No kernel module needed — IMA is built into most distro kernels.
pub fn check_ima_log() -> CheckResult {
    let ima_path = "/sys/kernel/security/ima/ascii_runtime_measurements";
    match std::fs::read_to_string(ima_path) {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            let total = lines.len();

            // Count measurements with SHA-256 vs SHA-1
            let sha256_count = lines.iter().filter(|l| l.contains("sha256:")).count();

            // Look for violations (IMA marks them)
            let violations = lines
                .iter()
                .filter(|l| {
                    l.contains("violated") || l.contains("invalid") || l.contains("INVALID")
                })
                .count();

            if violations > 0 {
                CheckResult {
                    id: "CHRONO-003",
                    name: "IMA Runtime Log",
                    status: CheckStatus::Warning,
                    confidence: confidence(0.7, 0.9),
                    detail: format!(
                        "{violations} IMA violation(s) in {total} measurements. \
                         Files may have been modified after boot."
                    ),
                }
            } else {
                CheckResult {
                    id: "CHRONO-003",
                    name: "IMA Runtime Log",
                    status: CheckStatus::Secure,
                    confidence: confidence(0.5, 0.9),
                    detail: format!(
                        "{total} IMA measurements ({sha256_count} SHA-256). \
                         No violations detected."
                    ),
                }
            }
        }
        Err(_) => CheckResult {
            id: "CHRONO-003",
            name: "IMA Runtime Log",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "IMA not available (need securityfs mounted + IMA enabled in kernel)".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_cycles_returns_nonzero() {
        let c = read_cycles();
        assert!(c > 0, "cycle counter should return nonzero");
    }

    #[test]
    fn read_cycles_monotonic() {
        let a = read_cycles();
        let b = read_cycles();
        // b should be >= a (wrapping handled by the workload, not here)
        assert!(b >= a || b < 1000, "cycle counter should be monotonic");
    }

    #[test]
    fn cpu_workload_timing() {
        let profile = measure(Workload::CpuBound, 10);
        assert_eq!(profile.iterations, 10);
        assert!(profile.median_cycles > 0);
        assert!(profile.mean_cycles > 0.0);
        // Jitter should be low for pure CPU work in a test environment.
        assert!(
            profile.jitter_ratio < 50.0,
            "jitter ratio {} too high for CPU workload",
            profile.jitter_ratio
        );
    }

    #[test]
    fn memory_workload_timing() {
        let profile = measure(Workload::MemoryBound, 10);
        assert_eq!(profile.iterations, 10);
        assert!(profile.median_cycles > 0);
    }

    #[test]
    fn sysfs_workload_timing() {
        let profile = measure(Workload::SysfsRead, 10);
        assert_eq!(profile.iterations, 10);
        assert!(profile.median_cycles > 0);
    }

    #[test]
    fn timing_baseline_roundtrip() {
        let profile = measure(Workload::CpuBound, 10);
        let baseline = TimingBaseline::from(&profile);
        assert_eq!(baseline.workload, "cpu_bound");
        assert_eq!(baseline.median_cycles, profile.median_cycles);

        let json = serde_json::to_string(&baseline).unwrap();
        let loaded: TimingBaseline = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.median_cycles, baseline.median_cycles);
    }

    #[test]
    fn drift_detection_stable() {
        let profile = measure(Workload::CpuBound, 50);
        let baseline = TimingBaseline::from(&profile);

        // Compare against itself — should show ~0 drift.
        let drift = compare_timing(&profile, &baseline);
        assert!(
            drift.z_score.abs() < 1.0,
            "self-comparison z-score {} should be near 0",
            drift.z_score
        );
        assert!(
            drift.pct_change.abs() < 5.0,
            "self-comparison pct change {} should be near 0",
            drift.pct_change
        );
    }

    #[test]
    fn check_timing_runs() {
        let result = check_timing_attestation();
        assert_eq!(result.id, "CHRONO-001");
        // On a normal dev machine, should be Secure or Warning (not Critical).
        assert_ne!(result.status, CheckStatus::Critical);
    }

    #[test]
    fn outlier_detection() {
        // Simulate a profile with one massive spike (SMI interception).
        let mut samples = Vec::new();
        for _ in 0..99 {
            samples.push(TimingSample {
                cycles: 10_000,
                nanos: 1_000,
            });
        }
        // One spike: 10x the normal
        samples.push(TimingSample {
            cycles: 100_000,
            nanos: 10_000,
        });

        let profile = compute_profile("test", samples);
        assert!(
            profile.jitter_ratio > 5.0,
            "jitter ratio {} should reflect the spike",
            profile.jitter_ratio
        );
        assert!(
            profile.outlier_count >= 1,
            "should detect at least 1 outlier"
        );
    }
}
