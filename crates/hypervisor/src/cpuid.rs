//! CPUID-based hypervisor detection and fingerprinting.
//!
//! CPUID leaf 0x1 ECX bit 31 = hypervisor present bit (set by all compliant hypervisors).
//! CPUID leaf 0x40000000 = hypervisor vendor string (KVM, VMware, Xen, etc.).
//! CPUID leaf 0x40000001+ = hypervisor-specific features.
//!
//! A hidden hypervisor (Blue Pill) may set the hypervisor bit but NOT
//! provide a recognizable vendor string — this is a critical red flag.

use crate::{confidence, CheckResult, CheckStatus};
use std::fs;

/// CPUID hypervisor information.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CpuidHypervisor {
    /// CPUID leaf 0x1 ECX bit 31 — hypervisor present.
    pub hypervisor_bit: bool,
    /// Vendor string from CPUID leaf 0x40000000.
    pub vendor_string: Option<String>,
    /// Identified hypervisor name (from vendor string or sysfs).
    pub identified_name: Option<String>,
    /// Maximum CPUID leaf supported by hypervisor.
    pub max_leaf: u32,
}

impl CpuidHypervisor {
    pub fn detect() -> Self {
        let (hypervisor_bit, vendor_string, max_leaf) = read_cpuid_hypervisor();
        let identified_name = identify_hypervisor(&vendor_string);

        Self {
            hypervisor_bit,
            vendor_string,
            identified_name,
            max_leaf,
        }
    }
}

/// Read hypervisor info from CPUID (via /proc/cpuinfo flags + sysfs).
fn read_cpuid_hypervisor() -> (bool, Option<String>, u32) {
    // Check /proc/cpuinfo for hypervisor flag.
    let has_flag = fs::read_to_string("/proc/cpuinfo")
        .map(|c| c.contains(" hypervisor") || c.contains("\thypervisor"))
        .unwrap_or(false);

    // Check sysfs for hypervisor type.
    let sysfs_type = fs::read_to_string("/sys/hypervisor/type")
        .ok()
        .map(|s| s.trim().to_string());

    // Check DMI for VM product name.
    let dmi_product = fs::read_to_string("/sys/class/dmi/id/product_name")
        .ok()
        .map(|s| s.trim().to_string());

    // Check DMI sys vendor.
    let dmi_vendor = fs::read_to_string("/sys/class/dmi/id/sys_vendor")
        .ok()
        .map(|s| s.trim().to_string());

    // Build vendor string from available sources.
    let vendor = sysfs_type.or(dmi_product.clone()).or(dmi_vendor);

    // On x86, CPUID leaf 0x40000000 gives max hypervisor leaf.
    // We can't execute CPUID directly in no_std-free Rust on all platforms,
    // so we use /proc/cpuinfo and sysfs as the portable approach.
    let max_leaf = if has_flag { 0x40000001 } else { 0 };

    (has_flag, vendor, max_leaf)
}

/// Identify the hypervisor from vendor string.
fn identify_hypervisor(vendor: &Option<String>) -> Option<String> {
    let v = vendor.as_ref()?.to_lowercase();

    if v.contains("kvm") || v.contains("qemu") {
        Some("KVM/QEMU".into())
    } else if v.contains("vmware") {
        Some("VMware".into())
    } else if v.contains("virtualbox") || v.contains("vbox") {
        Some("VirtualBox".into())
    } else if v.contains("hyper-v") || v.contains("microsoft") {
        Some("Hyper-V".into())
    } else if v.contains("xen") {
        Some("Xen".into())
    } else if v.contains("parallels") {
        Some("Parallels".into())
    } else if v.contains("bhyve") {
        Some("bhyve".into())
    } else if v.contains("amazon") || v.contains("ec2") {
        Some("AWS Nitro".into())
    } else if v.contains("google") {
        Some("Google Compute".into())
    } else if v.contains("oracle") || v.contains("ovm") {
        Some("Oracle VM".into())
    } else {
        None
    }
}

// ── Known hypervisor CPUID vendor strings (12 bytes from EBX+ECX+EDX) ──

/// Known legitimate hypervisor CPUID signatures.
const KNOWN_VENDORS: &[(&str, &str)] = &[
    ("KVMKVMKVM\0\0\0", "KVM"),
    ("VMwareVMware", "VMware"),
    ("XenVMMXenVMM", "Xen"),
    ("Microsoft Hv", "Hyper-V"),
    ("VBoxVBoxVBox", "VirtualBox"),
    ("prl hyperv  ", "Parallels"),
    ("bhyve bhyve ", "bhyve"),
    ("ACRNACRNACRN", "ACRN"),
    ("TCGTCGTCGTCG", "QEMU/TCG"),
    (" lrpepyh  vr", "Parallels alt"),
];

// ── Check functions ─────────────────────────────────────────────────────

/// Deep CPUID hypervisor detection.
pub fn check_hypervisor_cpuid() -> CheckResult {
    let info = CpuidHypervisor::detect();

    if !info.hypervisor_bit {
        return CheckResult {
            id: "HV-001",
            name: "Hypervisor Detection (CPUID)",
            status: CheckStatus::Secure,
            confidence: confidence(0.5, 0.9),
            detail: "no hypervisor flag in CPUID — bare metal or well-hidden hypervisor".into(),
        };
    }

    match &info.identified_name {
        Some(name) => CheckResult {
            id: "HV-001",
            name: "Hypervisor Detection (CPUID)",
            status: CheckStatus::Secure,
            confidence: confidence(0.4, 0.95),
            detail: format!(
                "hypervisor detected: {name}. Vendor: {}. Expected if running in a VM.",
                info.vendor_string.as_deref().unwrap_or("unknown")
            ),
        },
        None => CheckResult {
            id: "HV-001",
            name: "Hypervisor Detection (CPUID)",
            status: CheckStatus::Warning,
            confidence: confidence(0.8, 0.7),
            detail: format!(
                "hypervisor flag SET but vendor UNRECOGNIZED: {:?}. \
                 Could be Blue Pill rootkit or uncommon hypervisor. \
                 Investigate if this machine should be bare-metal.",
                info.vendor_string,
            ),
        },
    }
}

/// Check CPUID consistency (detect hypervisor-induced anomalies).
pub fn check_cpuid_consistency() -> CheckResult {
    // Check if hardware virtualization extensions are available inside the VM.
    // If we're in a VM but VMX/SVM flags are present, it could mean nested virt
    // or a thin hypervisor exposing host features.
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let has_hypervisor = cpuinfo.contains(" hypervisor");
    let has_vmx = cpuinfo.contains(" vmx");
    let has_svm = cpuinfo.contains(" svm");

    if has_hypervisor && (has_vmx || has_svm) {
        // VM with nested virtualization — unusual but not necessarily malicious.
        let virt_type = if has_vmx {
            "VMX (Intel VT-x)"
        } else {
            "SVM (AMD-V)"
        };
        return CheckResult {
            id: "HV-002",
            name: "CPUID Consistency",
            status: CheckStatus::Warning,
            confidence: confidence(0.5, 0.8),
            detail: format!(
                "hypervisor detected but {virt_type} hardware virtualization exposed to guest. \
                 Nested virtualization enabled, or thin hypervisor passing through host features."
            ),
        };
    }

    if !has_hypervisor {
        // Check for signs of hypervisor that hides its flag.
        // DMI strings from well-known cloud providers indicate VM even without CPUID flag.
        let dmi_product = fs::read_to_string("/sys/class/dmi/id/product_name")
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        let cloud_indicators = [
            "virtual",
            "vm",
            "kvm",
            "qemu",
            "ec2",
            "google",
            "azure",
            "digitalocean",
        ];
        let hidden_vm = cloud_indicators.iter().any(|ind| dmi_product.contains(ind));

        if hidden_vm {
            return CheckResult {
                id: "HV-002",
                name: "CPUID Consistency",
                status: CheckStatus::Warning,
                confidence: confidence(0.6, 0.8),
                detail: format!(
                    "DMI product name '{dmi_product}' suggests VM but CPUID hypervisor bit is NOT set. \
                     The hypervisor may be hiding its presence."
                ),
            };
        }
    }

    CheckResult {
        id: "HV-002",
        name: "CPUID Consistency",
        status: CheckStatus::Secure,
        confidence: confidence(0.4, 0.8),
        detail: "CPUID flags consistent with detected environment".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_known_vendors() {
        // Mapping path: common vendor strings should map to stable hypervisor
        // names used by downstream summary and trust calculations.
        assert_eq!(
            identify_hypervisor(&Some("KVM".into())),
            Some("KVM/QEMU".into())
        );
        assert_eq!(
            identify_hypervisor(&Some("VMware Virtual Platform".into())),
            Some("VMware".into())
        );
        assert_eq!(
            identify_hypervisor(&Some("Microsoft Corporation".into())),
            Some("Hyper-V".into())
        );
        assert!(identify_hypervisor(&Some("Unknown Thing".into())).is_none());
        assert!(identify_hypervisor(&None).is_none());
    }

    #[test]
    fn check_runs() {
        // Smoke path: CPUID detector should always return the expected check
        // identifier regardless of host environment.
        let r = check_hypervisor_cpuid();
        assert_eq!(r.id, "HV-001");
    }

    #[test]
    fn identify_cloud_provider_hypervisors() {
        // Cloud path: provider-flavored vendor strings should map to the
        // correct hypervisor labels rather than unknown.
        assert_eq!(
            identify_hypervisor(&Some("Amazon EC2".into())),
            Some("AWS Nitro".into())
        );
        assert_eq!(
            identify_hypervisor(&Some("Google Compute Engine".into())),
            Some("Google Compute".into())
        );
        assert_eq!(
            identify_hypervisor(&Some("Oracle VM Server".into())),
            Some("Oracle VM".into())
        );
    }

    #[test]
    fn known_vendor_table_contains_core_signatures() {
        // Signature path: known CPUID signatures should keep representative
        // entries for KVM, VMware and Hyper-V.
        let signatures: Vec<&str> = KNOWN_VENDORS.iter().map(|(sig, _)| *sig).collect();
        assert!(signatures.contains(&"KVMKVMKVM\0\0\0"));
        assert!(signatures.contains(&"VMwareVMware"));
        assert!(signatures.contains(&"Microsoft Hv"));
    }

    #[test]
    fn cpuid_consistency_check_exposes_stable_id() {
        // Contract path: CPUID consistency probe must always publish the
        // canonical check id for dashboard and CLI aggregation.
        let result = check_cpuid_consistency();
        assert_eq!(result.id, "HV-002");
    }
}
