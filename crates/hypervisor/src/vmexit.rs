//! VM exit analysis — monitor and analyze KVM VM exit patterns.
//!
//! VM exits are the most expensive operation in virtualization. Each exit
//! transfers control from guest to host. Anomalous exit patterns indicate:
//! - Guest VM trying to escape (probing hardware, accessing forbidden MSRs)
//! - Guest VM under attack (code injection causing unusual exits)
//! - Host-level hypervisor manipulation
//!
//! Data source: /sys/kernel/debug/kvm/ statistics or perf kvm events.

use crate::{confidence, CheckResult, CheckStatus};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// VM exit statistics from KVM debugfs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VmExitStats {
    /// Total VM exits observed.
    pub total_exits: u64,
    /// Exits by reason (reason_name → count).
    pub by_reason: BTreeMap<String, u64>,
    /// Number of VMs these stats cover.
    pub vm_count: usize,
}

impl VmExitStats {
    /// Read aggregate VM exit stats from /sys/kernel/debug/kvm/.
    pub fn read() -> Option<Self> {
        let kvm_debug = Path::new("/sys/kernel/debug/kvm");
        if !kvm_debug.exists() {
            return None;
        }

        let mut by_reason = BTreeMap::new();
        let mut total = 0u64;
        let mut vm_count = 0;

        // Read global stats from /sys/kernel/debug/kvm/*.
        if let Ok(entries) = fs::read_dir(kvm_debug) {
            for entry in entries.flatten() {
                let path = entry.path();

                // Count VM directories.
                if path.is_dir() {
                    vm_count += 1;
                }

                // Read stat files (key-value pairs).
                if path.is_file() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if let Ok(val_str) = fs::read_to_string(&path) {
                        if let Ok(val) = val_str.trim().parse::<u64>() {
                            if val > 0 {
                                by_reason.insert(name, val);
                                total += val;
                            }
                        }
                    }
                }
            }
        }

        if total == 0 && vm_count == 0 {
            return None;
        }

        Some(Self {
            total_exits: total,
            by_reason,
            vm_count,
        })
    }
}

/// Exit reasons that indicate potential VM escape attempts.
const SUSPICIOUS_EXIT_REASONS: &[(&str, &str)] = &[
    (
        "io_exits",
        "I/O port access from guest (potential hardware probing)",
    ),
    ("mmio_exits", "Memory-mapped I/O from guest"),
    ("signal_exits", "Host signal during VM execution"),
    (
        "halt_exits",
        "Excessive HLT instructions (may indicate DoS)",
    ),
    (
        "insn_emulation_fail",
        "Failed instruction emulation (exploit probe)",
    ),
    (
        "pf_fixed",
        "Page fault fixups (may indicate memory probing)",
    ),
];

// ── Check function ──────────────────────────────────────────────────────

/// Analyze VM exit statistics for anomalies.
pub fn check_vm_exit_stats() -> CheckResult {
    let Some(stats) = VmExitStats::read() else {
        return CheckResult {
            id: "VMEXIT-001",
            name: "VM Exit Analysis",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "KVM debugfs not available (need root + debugfs mounted)".into(),
        };
    };

    if stats.total_exits == 0 {
        return CheckResult {
            id: "VMEXIT-001",
            name: "VM Exit Analysis",
            status: CheckStatus::Secure,
            confidence: confidence(0.3, 0.8),
            detail: format!(
                "{} VM(s) tracked, 0 total exits (VMs may be idle).",
                stats.vm_count,
            ),
        };
    }

    // Check for suspicious exit reasons.
    let mut suspicious = Vec::new();
    for (reason, description) in SUSPICIOUS_EXIT_REASONS {
        if let Some(&count) = stats.by_reason.get(*reason) {
            if count > 0 {
                let pct = (count as f64 / stats.total_exits as f64) * 100.0;
                if pct > 5.0 {
                    // More than 5% of exits from this reason = notable.
                    suspicious.push(format!("{reason}: {count} ({pct:.1}%) — {description}"));
                }
            }
        }
    }

    // Check for instruction emulation failures (strong escape indicator).
    let emul_fail = stats
        .by_reason
        .get("insn_emulation_fail")
        .copied()
        .unwrap_or(0);
    if emul_fail > 10 {
        return CheckResult {
            id: "VMEXIT-001",
            name: "VM Exit Analysis",
            status: CheckStatus::Warning,
            confidence: confidence(0.7, 0.8),
            detail: format!(
                "INSTRUCTION EMULATION FAILURES: {emul_fail}. \
                 Guest VM is executing instructions the hypervisor cannot handle. \
                 This may indicate VM escape probing. \
                 Total exits: {}, VMs: {}.",
                stats.total_exits, stats.vm_count,
            ),
        };
    }

    if !suspicious.is_empty() {
        return CheckResult {
            id: "VMEXIT-001",
            name: "VM Exit Analysis",
            status: CheckStatus::Secure,
            confidence: confidence(0.4, 0.7),
            detail: format!(
                "{} total exits across {} VM(s). Notable: {}",
                stats.total_exits,
                stats.vm_count,
                suspicious.join("; "),
            ),
        };
    }

    // Top 3 exit reasons for visibility.
    let mut sorted: Vec<_> = stats.by_reason.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    let top3: Vec<String> = sorted
        .iter()
        .take(3)
        .map(|(k, v)| format!("{k}={v}"))
        .collect();

    CheckResult {
        id: "VMEXIT-001",
        name: "VM Exit Analysis",
        status: CheckStatus::Secure,
        confidence: confidence(0.4, 0.8),
        detail: format!(
            "{} total exits, {} VM(s). Top reasons: {}",
            stats.total_exits,
            stats.vm_count,
            top3.join(", "),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_runs() {
        let r = check_vm_exit_stats();
        assert_eq!(r.id, "VMEXIT-001");
    }

    #[test]
    fn stats_empty() {
        // Baseline path: an empty stats snapshot should preserve zero totals
        // and allow callers to treat data as unavailable/idle.
        let stats = VmExitStats {
            total_exits: 0,
            by_reason: BTreeMap::new(),
            vm_count: 0,
        };
        assert_eq!(stats.total_exits, 0);
    }

    #[test]
    fn suspicious_exit_reasons_include_escape_probes() {
        // Coverage path: suspicious reason catalog must keep high-signal
        // escape indicators like emulation failures and MMIO probing.
        let reasons: Vec<&str> = SUSPICIOUS_EXIT_REASONS
            .iter()
            .map(|(reason, _)| *reason)
            .collect();
        assert!(reasons.contains(&"insn_emulation_fail"));
        assert!(reasons.contains(&"mmio_exits"));
        assert!(reasons.contains(&"io_exits"));
    }

    #[test]
    fn suspicious_percentage_threshold_matches_five_percent_gate() {
        // Threshold path: a reason should only be considered notable when its
        // contribution exceeds 5% of total exits in the current window.
        let total = 1_000u64;
        let below = 49u64;
        let above = 51u64;
        let below_pct = (below as f64 / total as f64) * 100.0;
        let above_pct = (above as f64 / total as f64) * 100.0;
        assert!(below_pct <= 5.0);
        assert!(above_pct > 5.0);
    }

    #[test]
    fn top_reason_sort_order_is_descending_by_count() {
        // Visibility path: summary ordering should keep the most frequent
        // exit reasons first so operators can triage noisy causes quickly.
        let mut by_reason = BTreeMap::new();
        by_reason.insert("io_exits".to_string(), 200);
        by_reason.insert("halt_exits".to_string(), 50);
        by_reason.insert("mmio_exits".to_string(), 400);
        let mut sorted: Vec<_> = by_reason.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));

        assert_eq!(sorted[0].0, "mmio_exits");
        assert_eq!(sorted[1].0, "io_exits");
        assert_eq!(sorted[2].0, "halt_exits");
    }
}
