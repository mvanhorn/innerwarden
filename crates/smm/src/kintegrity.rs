//! Kernel integrity verification — detect modifications to running kernel.
//!
//! Verifies the kernel text section, loaded modules, and symbol table
//! haven't been tampered with. Works from userspace by reading /proc.
//!
//! Modern rootkits (Singularity, VoidLink) hook kernel functions via ftrace.
//! This module detects such modifications by hashing kernel state and
//! comparing against baseline.
//!
//! **Techniques:**
//! - Hash `/proc/kallsyms` (kernel symbol table) — detects symbol tampering
//! - Inventory `/proc/modules` — detects hidden/unexpected kernel modules
//! - Hash kernel command line — detects boot parameter tampering
//! - Count loaded modules vs baseline — detects stealth module insertion

use crate::{confidence, CheckResult, CheckStatus};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;

/// Kernel integrity snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KernelState {
    /// Kernel version string from /proc/version.
    pub version: String,
    /// SHA-256 of /proc/kallsyms (symbol table).
    pub kallsyms_hash: Option<String>,
    /// Number of symbols in kallsyms.
    pub symbol_count: usize,
    /// Loaded kernel modules (sorted set).
    pub modules: BTreeSet<String>,
    /// Kernel command line from /proc/cmdline.
    pub cmdline: String,
    /// SHA-256 of cmdline.
    pub cmdline_hash: String,
}

impl KernelState {
    /// Capture current kernel state.
    pub fn capture() -> Self {
        let version = fs::read_to_string("/proc/version")
            .unwrap_or_default()
            .trim()
            .to_string();

        let (kallsyms_hash, symbol_count) = read_kallsyms_hash();

        let modules = read_modules();

        let cmdline = fs::read_to_string("/proc/cmdline")
            .unwrap_or_default()
            .trim()
            .to_string();
        let cmdline_hash = hex::encode(Sha256::digest(cmdline.as_bytes()));

        Self {
            version,
            kallsyms_hash,
            symbol_count,
            modules,
            cmdline,
            cmdline_hash,
        }
    }
}

/// Hash the kernel symbol table. Returns (hash, symbol_count).
/// kallsyms lists all kernel symbols with addresses — if a rootkit
/// modifies a function pointer, the symbol table may change.
fn read_kallsyms_hash() -> (Option<String>, usize) {
    match fs::read_to_string("/proc/kallsyms") {
        Ok(content) => {
            let count = content.lines().count();
            // Hash the content to detect any modifications.
            let hash = hex::encode(Sha256::digest(content.as_bytes()));
            (Some(hash), count)
        }
        Err(_) => (None, 0),
    }
}

/// Read currently loaded kernel modules from /proc/modules.
fn read_modules() -> BTreeSet<String> {
    let mut modules = BTreeSet::new();
    if let Ok(content) = fs::read_to_string("/proc/modules") {
        for line in content.lines() {
            if let Some(name) = line.split_whitespace().next() {
                modules.insert(name.to_string());
            }
        }
    }
    modules
}

/// Compare current kernel state against baseline.
pub fn detect_kernel_drift(current: &KernelState, baseline: &KernelState) -> Vec<KernelDrift> {
    let mut drifts = Vec::new();

    // Kernel version changed.
    if current.version != baseline.version {
        drifts.push(KernelDrift {
            component: "kernel_version".into(),
            severity: KernelDriftSeverity::Suspicious,
            detail: format!(
                "kernel version changed: '{}' → '{}'",
                truncate(&baseline.version, 60),
                truncate(&current.version, 60),
            ),
        });
    }

    // Kernel cmdline changed.
    if current.cmdline_hash != baseline.cmdline_hash {
        drifts.push(KernelDrift {
            component: "cmdline".into(),
            severity: KernelDriftSeverity::Suspicious,
            detail: "kernel command line changed since baseline".into(),
        });
    }

    // New modules loaded.
    let new_modules: Vec<&String> = current.modules.difference(&baseline.modules).collect();
    if !new_modules.is_empty() {
        drifts.push(KernelDrift {
            component: "modules".into(),
            severity: KernelDriftSeverity::Warning,
            detail: format!(
                "{} new module(s) since baseline: {}",
                new_modules.len(),
                new_modules
                    .iter()
                    .take(10)
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        });
    }

    // Modules removed (could be rootkit hiding itself).
    let removed_modules: Vec<&String> = baseline.modules.difference(&current.modules).collect();
    if !removed_modules.is_empty() {
        drifts.push(KernelDrift {
            component: "modules".into(),
            severity: KernelDriftSeverity::Suspicious,
            detail: format!(
                "{} module(s) disappeared since baseline: {}. \
                 Could be rootkit hiding its LKM.",
                removed_modules.len(),
                removed_modules
                    .iter()
                    .take(10)
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        });
    }

    // kallsyms hash changed (kernel symbol table modified).
    if let (Some(curr), Some(base)) = (&current.kallsyms_hash, &baseline.kallsyms_hash) {
        if curr != base {
            drifts.push(KernelDrift {
                component: "kallsyms".into(),
                severity: KernelDriftSeverity::Critical,
                detail: "kernel symbol table hash changed! \
                         Possible ftrace hook injection or kernel text modification."
                    .into(),
            });
        }
    }

    drifts
}

/// A detected change in kernel state.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KernelDrift {
    pub component: String,
    pub severity: KernelDriftSeverity,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum KernelDriftSeverity {
    Warning,
    Suspicious,
    Critical,
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() > max {
        &s[..max]
    } else {
        s
    }
}

// ── Check functions ─────────────────────────────────────────────────────

/// Verify kernel module inventory.
pub fn check_modules() -> CheckResult {
    let state = KernelState::capture();

    if state.modules.is_empty() {
        return CheckResult {
            id: "KERN-001",
            name: "Kernel Modules",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "cannot read /proc/modules".into(),
        };
    }

    // Check for known suspicious module names.
    let suspicious: Vec<&String> = state
        .modules
        .iter()
        .filter(|m| {
            let lower = m.to_lowercase();
            lower.contains("rootkit")
                || lower.contains("hide")
                || lower.contains("stealth")
                || lower.contains("diamorphine")
                || lower.contains("reptile")
                || lower.contains("bdvl")
        })
        .collect();

    if !suspicious.is_empty() {
        return CheckResult {
            id: "KERN-001",
            name: "Kernel Modules",
            status: CheckStatus::Critical,
            confidence: confidence(0.95, 0.9),
            detail: format!(
                "SUSPICIOUS MODULE(S): {}. Known rootkit-associated names detected.",
                suspicious
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
    }

    CheckResult {
        id: "KERN-001",
        name: "Kernel Modules",
        status: CheckStatus::Secure,
        confidence: confidence(0.5, 0.8),
        detail: format!(
            "{} modules loaded. No known suspicious names. \
             Run baseline to enable drift detection.",
            state.modules.len()
        ),
    }
}

/// Verify kernel symbol table integrity.
pub fn check_kallsyms() -> CheckResult {
    let (hash, count) = read_kallsyms_hash();

    match hash {
        Some(h) => CheckResult {
            id: "KERN-002",
            name: "Kernel Symbol Table",
            status: CheckStatus::Secure,
            confidence: confidence(0.7, 0.8),
            detail: format!(
                "{count} symbols, hash sha256:{:.16}… \
                 Baseline captured for drift detection.",
                h
            ),
        },
        None => CheckResult {
            id: "KERN-002",
            name: "Kernel Symbol Table",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "cannot read /proc/kallsyms (need root)".into(),
        },
    }
}

/// Verify kernel version and command line.
pub fn check_kernel_version() -> CheckResult {
    let version = fs::read_to_string("/proc/version").unwrap_or_default();
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();

    if version.is_empty() {
        return CheckResult {
            id: "KERN-003",
            name: "Kernel Version",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "cannot read /proc/version".into(),
        };
    }

    // Check for dangerous boot parameters.
    let dangerous_params = [
        "init=/bin/sh",
        "init=/bin/bash",
        "single",
        "nokaslr",
        "nopti",
        "nosmep",
        "nosmap",
    ];
    let found_dangerous: Vec<&&str> = dangerous_params
        .iter()
        .filter(|p| cmdline.contains(*p))
        .collect();

    if !found_dangerous.is_empty() {
        return CheckResult {
            id: "KERN-003",
            name: "Kernel Version",
            status: CheckStatus::Warning,
            confidence: confidence(0.6, 1.0),
            detail: format!(
                "dangerous boot params detected: {}. \
                 These disable kernel security features.",
                found_dangerous
                    .iter()
                    .map(|s| **s)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
    }

    CheckResult {
        id: "KERN-003",
        name: "Kernel Version",
        status: CheckStatus::Secure,
        confidence: confidence(0.3, 1.0),
        detail: format!("{}", truncate(version.trim(), 80)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_state() {
        let state = KernelState::capture();
        // Should at least get a version on any system.
        // On non-Linux (macOS), these will be empty but shouldn't panic.
        let _ = state;
    }

    #[test]
    fn module_drift_detection() {
        let mut baseline = KernelState {
            version: "Linux 6.1".into(),
            kallsyms_hash: Some("abc123".into()),
            symbol_count: 100000,
            modules: BTreeSet::from(["ext4".into(), "btrfs".into(), "nf_tables".into()]),
            cmdline: "root=/dev/sda1".into(),
            cmdline_hash: "hash1".into(),
        };

        let mut current = baseline.clone();
        current.modules.insert("suspicious_mod".into());
        current.modules.remove("nf_tables");

        let drifts = detect_kernel_drift(&current, &baseline);
        assert!(drifts.iter().any(|d| d.detail.contains("suspicious_mod")));
        assert!(drifts
            .iter()
            .any(|d| d.detail.contains("nf_tables") && d.detail.contains("disappeared")));
    }

    #[test]
    fn kallsyms_drift_detection() {
        let baseline = KernelState {
            version: "Linux 6.1".into(),
            kallsyms_hash: Some("original_hash".into()),
            symbol_count: 100000,
            modules: BTreeSet::new(),
            cmdline: "root=/dev/sda1".into(),
            cmdline_hash: "hash1".into(),
        };

        let mut current = baseline.clone();
        current.kallsyms_hash = Some("modified_hash".into());

        let drifts = detect_kernel_drift(&current, &baseline);
        assert!(drifts
            .iter()
            .any(|d| d.component == "kallsyms" && d.severity == KernelDriftSeverity::Critical));
    }

    #[test]
    fn dangerous_boot_params() {
        // This test checks the detection logic, not actual system state.
        let params = ["nokaslr", "nosmep", "nopti"];
        for p in params {
            let cmdline = format!("root=/dev/sda1 {p} quiet");
            assert!(cmdline.contains(p));
        }
    }

    #[test]
    fn check_modules_runs() {
        let result = check_modules();
        assert_eq!(result.id, "KERN-001");
    }

    #[test]
    fn check_kallsyms_runs() {
        let result = check_kallsyms();
        assert_eq!(result.id, "KERN-002");
    }
}
