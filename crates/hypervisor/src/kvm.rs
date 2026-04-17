//! KVM host monitoring — detect and inspect KVM hypervisor from the host side.
//!
//! When running as a KVM host, monitors:
//! - /dev/kvm presence and capabilities
//! - Loaded KVM kernel modules (kvm, kvm_intel, kvm_amd)
//! - Running virtual machines (via /sys/kernel/debug/kvm/)
//! - KVM configuration and security settings

use crate::{confidence, CheckResult, CheckStatus};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// KVM host state.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KvmState {
    /// /dev/kvm exists and is accessible.
    pub kvm_available: bool,
    /// KVM kernel modules loaded.
    pub modules: Vec<String>,
    /// Number of running VMs (from /sys/kernel/debug/kvm/).
    pub vm_count: usize,
    /// VM PIDs (from debugfs).
    pub vm_pids: Vec<u32>,
    /// Hardware virtualization type (Intel VT-x or AMD-V).
    pub virt_type: Option<String>,
}

impl KvmState {
    pub fn detect() -> Self {
        let kvm_available = Path::new("/dev/kvm").exists();

        let modules = detect_kvm_modules();

        let virt_type = if modules.iter().any(|m| m == "kvm_intel") {
            Some("Intel VT-x".into())
        } else if modules.iter().any(|m| m == "kvm_amd") {
            Some("AMD-V".into())
        } else {
            None
        };

        let (vm_count, vm_pids) = count_running_vms();

        Self {
            kvm_available,
            modules,
            vm_count,
            vm_pids,
            virt_type,
        }
    }
}

/// Detect loaded KVM kernel modules.
fn detect_kvm_modules() -> Vec<String> {
    let mut kvm_mods = Vec::new();
    if let Ok(content) = fs::read_to_string("/proc/modules") {
        for line in content.lines() {
            if let Some(name) = line.split_whitespace().next() {
                if name.starts_with("kvm") {
                    kvm_mods.push(name.to_string());
                }
            }
        }
    }
    kvm_mods
}

/// Count running VMs from /sys/kernel/debug/kvm/.
fn count_running_vms() -> (usize, Vec<u32>) {
    let kvm_debug = Path::new("/sys/kernel/debug/kvm");
    if !kvm_debug.exists() {
        return (0, Vec::new());
    }

    let mut pids = Vec::new();
    if let Ok(entries) = fs::read_dir(kvm_debug) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // KVM debugfs entries are named by PID-FD format.
            if let Some(pid_str) = name.split('-').next() {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    if !pids.contains(&pid) {
                        pids.push(pid);
                    }
                }
            }
        }
    }

    let count = pids.len();
    (count, pids)
}

// ── Check functions ─────────────────────────────────────────────────────

/// Check KVM host capabilities.
pub fn check_kvm_host() -> CheckResult {
    let state = KvmState::detect();

    if !state.kvm_available && state.modules.is_empty() {
        return CheckResult {
            id: "KVM-001",
            name: "KVM Host",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "KVM not available (no /dev/kvm, no kvm modules loaded). \
                     Not a hypervisor host."
                .into(),
        };
    }

    let virt = state.virt_type.as_deref().unwrap_or("unknown");

    if state.vm_count > 0 {
        CheckResult {
            id: "KVM-001",
            name: "KVM Host",
            status: CheckStatus::Secure,
            confidence: confidence(0.5, 0.9),
            detail: format!(
                "KVM host active ({virt}). {} module(s): {}. \
                 Running {} VM(s) (PIDs: {:?}).",
                state.modules.len(),
                state.modules.join(", "),
                state.vm_count,
                state.vm_pids,
            ),
        }
    } else {
        CheckResult {
            id: "KVM-001",
            name: "KVM Host",
            status: CheckStatus::Secure,
            confidence: confidence(0.3, 0.9),
            detail: format!(
                "KVM available ({virt}) but no VMs running. \
                 Modules: {}.",
                state.modules.join(", "),
            ),
        }
    }
}

/// Verify KVM kernel module integrity.
pub fn check_kvm_modules() -> CheckResult {
    let modules = detect_kvm_modules();

    if modules.is_empty() {
        return CheckResult {
            id: "KVM-002",
            name: "KVM Module Integrity",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "no KVM modules loaded".into(),
        };
    }

    // Check that module set is expected (kvm + kvm_intel or kvm_amd).
    let expected: BTreeSet<&str> = ["kvm", "kvm_intel", "kvm_amd"].iter().copied().collect();
    let unexpected: Vec<&String> = modules
        .iter()
        .filter(|m| !expected.contains(m.as_str()))
        .collect();

    if !unexpected.is_empty() {
        return CheckResult {
            id: "KVM-002",
            name: "KVM Module Integrity",
            status: CheckStatus::Warning,
            confidence: confidence(0.5, 0.7),
            detail: format!(
                "unexpected KVM-related modules: {}. \
                 Expected: kvm + kvm_intel/kvm_amd only.",
                unexpected
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        };
    }

    // Read module reference counts from /proc/modules to detect tampering.
    let refcounts: Vec<String> = if let Ok(content) = fs::read_to_string("/proc/modules") {
        content
            .lines()
            .filter(|l| l.starts_with("kvm"))
            .map(|l| {
                let parts: Vec<&str> = l.split_whitespace().collect();
                format!(
                    "{}(refs={},state={})",
                    parts.first().unwrap_or(&"?"),
                    parts.get(2).unwrap_or(&"?"),
                    parts.get(4).unwrap_or(&"?"),
                )
            })
            .collect()
    } else {
        vec![]
    };

    CheckResult {
        id: "KVM-002",
        name: "KVM Module Integrity",
        status: CheckStatus::Secure,
        confidence: confidence(0.4, 0.8),
        detail: format!("KVM modules nominal: {}", refcounts.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_runs() {
        // Smoke path: host-state detection should never panic, even when KVM
        // debugfs or modules are unavailable on the current machine.
        let state = KvmState::detect();
        // Should not panic on any system.
        let _ = state;
    }

    #[test]
    fn check_kvm_host_runs() {
        // Contract path: KVM host check must always return its stable check id.
        let r = check_kvm_host();
        assert_eq!(r.id, "KVM-001");
    }

    #[test]
    fn check_modules_runs() {
        // Contract path: KVM module integrity check must always return its
        // stable check id.
        let r = check_kvm_modules();
        assert_eq!(r.id, "KVM-002");
    }

    #[test]
    fn detect_kvm_modules_only_returns_kvm_prefixed_entries() {
        // Filter path: module detection should keep only KVM-related entries
        // from `/proc/modules` parsing.
        let modules = detect_kvm_modules();
        assert!(modules.iter().all(|module| module.starts_with("kvm")));
    }

    #[test]
    fn count_running_vms_reports_unique_pid_list() {
        // Parsing path: VM debugfs enumeration should return a pid list whose
        // length matches the reported VM count without duplicates.
        let (count, pids) = count_running_vms();
        let unique: BTreeSet<u32> = pids.iter().copied().collect();
        assert_eq!(count, pids.len());
        assert_eq!(unique.len(), pids.len());
    }
}
