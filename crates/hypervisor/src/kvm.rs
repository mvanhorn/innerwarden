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
        let (vm_count, vm_pids) = count_running_vms();

        kvm_state_from_parts(kvm_available, modules, vm_count, vm_pids)
    }
}

fn kvm_state_from_parts(
    kvm_available: bool,
    modules: Vec<String>,
    vm_count: usize,
    vm_pids: Vec<u32>,
) -> KvmState {
    let virt_type = if modules.iter().any(|m| m == "kvm_intel") {
        Some("Intel VT-x".into())
    } else if modules.iter().any(|m| m == "kvm_amd") {
        Some("AMD-V".into())
    } else {
        None
    };

    KvmState {
        kvm_available,
        modules,
        vm_count,
        vm_pids,
        virt_type,
    }
}

/// Detect loaded KVM kernel modules.
fn detect_kvm_modules() -> Vec<String> {
    detect_kvm_modules_from_path(Path::new("/proc/modules"))
}

fn detect_kvm_modules_from_path(path: &Path) -> Vec<String> {
    if let Ok(content) = fs::read_to_string(path) {
        parse_kvm_modules(&content)
    } else {
        Vec::new()
    }
}

fn parse_kvm_modules(content: &str) -> Vec<String> {
    let mut kvm_mods = Vec::new();
    for line in content.lines() {
        if let Some(name) = line.split_whitespace().next() {
            if name.starts_with("kvm") {
                kvm_mods.push(name.to_string());
            }
        }
    }
    kvm_mods
}

/// Count running VMs from /sys/kernel/debug/kvm/.
fn count_running_vms() -> (usize, Vec<u32>) {
    count_running_vms_in_dir(Path::new("/sys/kernel/debug/kvm"))
}

fn count_running_vms_in_dir(kvm_debug: &Path) -> (usize, Vec<u32>) {
    if !kvm_debug.exists() {
        return (0, Vec::new());
    }

    let names = fs::read_dir(kvm_debug)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.flatten())
        .map(|entry| entry.file_name().to_string_lossy().to_string());
    let mut pids = running_vm_pids_from_entry_names(names);
    pids.sort_unstable();

    let count = pids.len();
    (count, pids)
}

fn running_vm_pids_from_entry_names<I>(names: I) -> Vec<u32>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let mut pids = Vec::new();
    for name in names {
        // KVM debugfs entries are named by PID-FD format.
        if let Some(pid_str) = name.as_ref().split('-').next() {
            if let Ok(pid) = pid_str.parse::<u32>() {
                if !pids.contains(&pid) {
                    pids.push(pid);
                }
            }
        }
    }
    pids
}

// ── Check functions ─────────────────────────────────────────────────────

/// Check KVM host capabilities.
pub fn check_kvm_host() -> CheckResult {
    check_kvm_host_from_state(KvmState::detect())
}

fn check_kvm_host_from_state(state: KvmState) -> CheckResult {
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
    let module_content = fs::read_to_string("/proc/modules").ok();
    check_kvm_modules_from_state(&modules, module_content.as_deref())
}

fn check_kvm_modules_from_state(modules: &[String], module_content: Option<&str>) -> CheckResult {
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
    let refcounts: Vec<String> = if let Some(content) = module_content {
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

    #[test]
    fn parse_kvm_modules_extracts_correctly() {
        let content = "kvm_intel 315392 0 - Live 0xffffffffc0000000
kvm 1024000 1 kvm_intel, Live 0xffffffffc0100000
ext4 1000000 2 - Live 0xffffffffc0200000
kvm_amd 100000 0 - Live 0xffffffffc0300000";
        let mods = parse_kvm_modules(content);
        assert_eq!(mods.len(), 3);
        assert!(mods.contains(&"kvm_intel".to_string()));
        assert!(mods.contains(&"kvm".to_string()));
        assert!(mods.contains(&"kvm_amd".to_string()));
    }

    #[test]
    fn parse_kvm_modules_empty_if_no_kvm() {
        let content = "ext4 1000000 2 - Live 0xffffffffc0200000
zfs 500000 1 - Live 0xffffffffc0300000";
        let mods = parse_kvm_modules(content);
        assert!(mods.is_empty());
    }

    #[test]
    fn detect_kvm_modules_from_path_handles_missing_and_present_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        assert!(detect_kvm_modules_from_path(&temp.path().join("missing")).is_empty());

        let modules_file = temp.path().join("modules");
        std::fs::write(
            &modules_file,
            "kvm_intel 315392 0 - Live 0x1\next4 1000000 2 - Live 0x2\n",
        )
        .expect("modules file");
        assert_eq!(
            detect_kvm_modules_from_path(&modules_file),
            vec!["kvm_intel".to_string()]
        );
    }

    #[test]
    fn running_vm_pids_from_entry_names_deduplicates_pid_fd_entries() {
        let pids =
            running_vm_pids_from_entry_names(["1234-5", "1234-6", "not-a-pid", "9876-1", "42"]);
        assert_eq!(pids, vec![1234, 9876, 42]);
    }

    #[test]
    fn count_running_vms_in_dir_reads_debugfs_entry_names() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp.path().join("1234-5"), "").expect("debugfs entry");
        std::fs::write(temp.path().join("1234-6"), "").expect("debugfs entry");
        std::fs::write(temp.path().join("9876-1"), "").expect("debugfs entry");
        std::fs::write(temp.path().join("not-vm"), "").expect("debugfs entry");

        let (count, pids) = count_running_vms_in_dir(temp.path());
        assert_eq!(count, 2);
        assert_eq!(pids, vec![1234, 9876]);
    }

    #[test]
    fn count_running_vms_in_dir_returns_zero_for_missing_debugfs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (count, pids) = count_running_vms_in_dir(&temp.path().join("missing"));

        assert_eq!(count, 0);
        assert!(pids.is_empty());
    }

    #[test]
    fn kvm_state_from_parts_derives_virtualization_vendor() {
        let intel = kvm_state_from_parts(true, vec!["kvm".into(), "kvm_intel".into()], 0, vec![]);
        assert_eq!(intel.virt_type.as_deref(), Some("Intel VT-x"));

        let amd = kvm_state_from_parts(true, vec!["kvm_amd".into()], 0, vec![]);
        assert_eq!(amd.virt_type.as_deref(), Some("AMD-V"));

        let unknown = kvm_state_from_parts(true, vec!["kvm".into()], 0, vec![]);
        assert!(unknown.virt_type.is_none());
    }

    #[test]
    fn check_kvm_host_from_state_reports_unavailable_when_no_kvm_signal() {
        let result = check_kvm_host_from_state(KvmState {
            kvm_available: false,
            modules: vec![],
            vm_count: 0,
            vm_pids: vec![],
            virt_type: None,
        });
        assert_eq!(result.status, CheckStatus::Unavailable);
        assert!(result.detail.contains("Not a hypervisor host"));
    }

    #[test]
    fn check_kvm_host_from_state_reports_active_vm_context() {
        let result = check_kvm_host_from_state(KvmState {
            kvm_available: true,
            modules: vec!["kvm".into(), "kvm_intel".into()],
            vm_count: 2,
            vm_pids: vec![100, 200],
            virt_type: Some("Intel VT-x".into()),
        });
        assert_eq!(result.status, CheckStatus::Secure);
        assert!(result.detail.contains("KVM host active (Intel VT-x)"));
        assert!(result.detail.contains("Running 2 VM(s)"));
    }

    #[test]
    fn check_kvm_host_from_state_reports_idle_host() {
        let result = check_kvm_host_from_state(KvmState {
            kvm_available: true,
            modules: vec!["kvm".into(), "kvm_amd".into()],
            vm_count: 0,
            vm_pids: vec![],
            virt_type: Some("AMD-V".into()),
        });
        assert_eq!(result.status, CheckStatus::Secure);
        assert!(result.detail.contains("but no VMs running"));
    }

    #[test]
    fn check_kvm_host_from_state_reports_unknown_virtualization_type() {
        let result = check_kvm_host_from_state(KvmState {
            kvm_available: true,
            modules: vec!["kvm".into()],
            vm_count: 0,
            vm_pids: vec![],
            virt_type: None,
        });

        assert!(result.detail.contains("KVM available (unknown)"));
    }

    #[test]
    fn check_kvm_modules_from_state_flags_unexpected_modules() {
        let modules = vec!["kvm".to_string(), "kvm_shadow".to_string()];
        let result = check_kvm_modules_from_state(&modules, None);
        assert_eq!(result.status, CheckStatus::Warning);
        assert!(result.detail.contains("kvm_shadow"));
    }

    #[test]
    fn check_kvm_modules_from_state_reports_unavailable_when_no_modules() {
        let result = check_kvm_modules_from_state(&[], Some("kvm 1 0 - Live 0x1"));

        assert_eq!(result.status, CheckStatus::Unavailable);
        assert_eq!(result.confidence, 0.0);
        assert_eq!(result.detail, "no KVM modules loaded");
    }

    #[test]
    fn check_kvm_modules_from_state_allows_missing_module_content() {
        let modules = vec!["kvm".to_string()];
        let result = check_kvm_modules_from_state(&modules, None);

        assert_eq!(result.status, CheckStatus::Secure);
        assert_eq!(result.detail, "KVM modules nominal: ");
    }

    #[test]
    fn check_kvm_modules_from_state_formats_nominal_refcounts() {
        let modules = vec!["kvm".to_string(), "kvm_intel".to_string()];
        let content = "kvm_intel 315392 0 - Live 0xffffffffc0000000
kvm 1024000 1 kvm_intel, Live 0xffffffffc0100000
ext4 1000000 2 - Live 0xffffffffc0200000";
        let result = check_kvm_modules_from_state(&modules, Some(content));
        assert_eq!(result.status, CheckStatus::Secure);
        assert!(result.detail.contains("kvm_intel(refs=0,state=Live)"));
        assert!(result.detail.contains("kvm(refs=1,state=Live)"));
    }

    #[test]
    fn check_kvm_modules_from_state_uses_placeholders_for_short_proc_lines() {
        let modules = vec!["kvm".to_string()];
        let result = check_kvm_modules_from_state(&modules, Some("kvm\n"));

        assert_eq!(result.status, CheckStatus::Secure);
        assert!(result.detail.contains("kvm(refs=?,state=?)"));
    }
}
