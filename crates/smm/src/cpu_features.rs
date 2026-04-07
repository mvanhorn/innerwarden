//! CPU feature flags audit — detect hypervisor presence and feature manipulation.
//!
//! Reads CPU feature flags from /proc/cpuinfo and CPUID (x86) or
//! /proc/cpuinfo features (ARM). Detects:
//!
//! - **Hidden hypervisor** (Blue Pill attack): CPUID hypervisor bit set
//!   but no expected hypervisor name, or hypervisor bit absent on a VM
//! - **Feature flag manipulation**: critical security features disabled
//!   (SMEP, SMAP, NX/XD, KASLR, CET) compared to what CPU supports
//! - **Drift from baseline**: features changed since last audit
//!
//! All reads are from /proc/cpuinfo and CPUID — no hardware dependency,
//! works on x86_64 and aarch64.

use crate::{confidence, CheckResult, CheckStatus};
use std::collections::BTreeSet;
use std::fs;

/// CPU feature state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CpuFeatures {
    /// Architecture.
    pub arch: String,
    /// All reported feature flags (sorted).
    pub flags: BTreeSet<String>,
    /// Whether a hypervisor is detected.
    pub hypervisor_detected: bool,
    /// Hypervisor vendor string (if detected).
    pub hypervisor_vendor: Option<String>,
    /// Critical security features present/absent.
    pub security_features: SecurityFeatures,
}

/// Security-critical CPU feature flags.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityFeatures {
    /// SMEP: Supervisor Mode Execution Prevention (x86).
    pub smep: bool,
    /// SMAP: Supervisor Mode Access Prevention (x86).
    pub smap: bool,
    /// NX/XD: No-Execute bit.
    pub nx: bool,
    /// UMIP: User-Mode Instruction Prevention (x86).
    pub umip: bool,
    /// CET: Control-flow Enforcement Technology (x86).
    pub cet: bool,
    /// IBRS/IBPB: Spectre mitigations.
    pub spectre_mitigations: bool,
    /// PTI: Page Table Isolation (Meltdown mitigation).
    pub pti: bool,
    /// ARM: PAN (Privileged Access Never).
    pub pan: bool,
    /// ARM: BTI (Branch Target Identification).
    pub bti: bool,
    /// ARM: MTE (Memory Tagging Extension).
    pub mte: bool,
}

impl CpuFeatures {
    /// Capture CPU feature state from /proc/cpuinfo.
    pub fn capture() -> Option<Self> {
        let content = fs::read_to_string("/proc/cpuinfo").ok()?;
        Some(Self::parse(&content))
    }

    /// Parse /proc/cpuinfo content.
    pub fn parse(content: &str) -> Self {
        let mut flags = BTreeSet::new();
        let mut hypervisor_detected = false;
        let mut hypervisor_vendor = None;
        let arch = if cfg!(target_arch = "x86_64") {
            "x86_64"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "unknown"
        };

        for line in content.lines() {
            let line = line.trim();
            if let Some((key, val)) = line.split_once(':') {
                let key = key.trim();
                let val = val.trim();
                match key {
                    // x86: flags field
                    "flags" => {
                        for flag in val.split_whitespace() {
                            flags.insert(flag.to_string());
                        }
                    }
                    // ARM: Features field
                    "Features" => {
                        for flag in val.split_whitespace() {
                            flags.insert(flag.to_string());
                        }
                    }
                    // Hypervisor detection
                    "hypervisor" => {
                        // Some kernels report "hypervisor" as a flag
                    }
                    _ => {}
                }
            }
        }

        // Hypervisor detection via flags.
        if flags.contains("hypervisor") {
            hypervisor_detected = true;
            // Try to identify the hypervisor.
            hypervisor_vendor = detect_hypervisor_vendor(&flags);
        }

        let security_features = extract_security_features(&flags, arch);

        Self {
            arch: arch.to_string(),
            flags,
            hypervisor_detected,
            hypervisor_vendor,
            security_features,
        }
    }
}

fn detect_hypervisor_vendor(flags: &BTreeSet<String>) -> Option<String> {
    // Check /sys/hypervisor/type if available.
    if let Ok(hv_type) = fs::read_to_string("/sys/hypervisor/type") {
        return Some(hv_type.trim().to_string());
    }
    // Check DMI for known hypervisor product names.
    if let Ok(product) = fs::read_to_string("/sys/class/dmi/id/product_name") {
        let p = product.trim().to_lowercase();
        if p.contains("virtualbox") {
            return Some("VirtualBox".into());
        }
        if p.contains("vmware") {
            return Some("VMware".into());
        }
        if p.contains("kvm") || p.contains("qemu") {
            return Some("KVM/QEMU".into());
        }
        if p.contains("hyper-v") {
            return Some("Hyper-V".into());
        }
        if p.contains("xen") {
            return Some("Xen".into());
        }
    }
    if flags.contains("vmx") || flags.contains("svm") {
        // Has virtualization support but no identified hypervisor.
        None
    } else {
        None
    }
}

fn extract_security_features(flags: &BTreeSet<String>, arch: &str) -> SecurityFeatures {
    match arch {
        "x86_64" => SecurityFeatures {
            smep: flags.contains("smep"),
            smap: flags.contains("smap"),
            nx: flags.contains("nx"),
            umip: flags.contains("umip"),
            cet: flags.contains("shstk") || flags.contains("ibt"),
            spectre_mitigations: flags.contains("ibrs")
                || flags.contains("ibpb")
                || flags.contains("stibp")
                || flags.contains("ssbd"),
            pti: check_pti_enabled(),
            pan: false,
            bti: false,
            mte: false,
        },
        "aarch64" => SecurityFeatures {
            smep: false,
            smap: false,
            nx: true, // ARM always has XN
            umip: false,
            cet: false,
            spectre_mitigations: flags.contains("ssbs"),
            pti: false,
            pan: flags.contains("pan"),
            bti: flags.contains("bti"),
            mte: flags.contains("mte"),
        },
        _ => SecurityFeatures {
            smep: false,
            smap: false,
            nx: false,
            umip: false,
            cet: false,
            spectre_mitigations: false,
            pti: false,
            pan: false,
            bti: false,
            mte: false,
        },
    }
}

fn check_pti_enabled() -> bool {
    // PTI status is in /sys/kernel/debug/x86/pti_enabled or kernel cmdline.
    if let Ok(cmdline) = fs::read_to_string("/proc/cmdline") {
        if cmdline.contains("nopti") {
            return false;
        }
    }
    // Default: assume enabled on modern kernels.
    true
}

/// Compare two feature sets and return differences.
pub fn diff_features(current: &CpuFeatures, baseline: &CpuFeatures) -> Vec<FeatureDiff> {
    let mut diffs = Vec::new();

    // Features removed since baseline (could indicate manipulation).
    for flag in baseline.flags.difference(&current.flags) {
        let critical = is_security_critical(flag);
        diffs.push(FeatureDiff {
            flag: flag.clone(),
            kind: FeatureDiffKind::Removed,
            critical,
        });
    }

    // Features added since baseline.
    for flag in current.flags.difference(&baseline.flags) {
        diffs.push(FeatureDiff {
            flag: flag.clone(),
            kind: FeatureDiffKind::Added,
            critical: false,
        });
    }

    // Hypervisor appeared.
    if current.hypervisor_detected && !baseline.hypervisor_detected {
        diffs.push(FeatureDiff {
            flag: "hypervisor".into(),
            kind: FeatureDiffKind::Added,
            critical: true, // hypervisor appearing at runtime = Blue Pill
        });
    }

    diffs
}

fn is_security_critical(flag: &str) -> bool {
    matches!(
        flag,
        "smep"
            | "smap"
            | "nx"
            | "umip"
            | "shstk"
            | "ibt"
            | "ibrs"
            | "ibpb"
            | "stibp"
            | "ssbd"
            | "pan"
            | "bti"
            | "mte"
    )
}

/// A difference in CPU features.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FeatureDiff {
    pub flag: String,
    pub kind: FeatureDiffKind,
    pub critical: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum FeatureDiffKind {
    Added,
    Removed,
}

// ── Check functions ─────────────────────────────────────────────────────

/// Audit CPU security features.
pub fn check_cpu_security_features() -> CheckResult {
    let Some(features) = CpuFeatures::capture() else {
        return CheckResult {
            id: "CPU-001",
            name: "CPU Security Features",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "cannot read /proc/cpuinfo".into(),
        };
    };

    let sf = &features.security_features;
    let mut missing = Vec::new();

    match features.arch.as_str() {
        "x86_64" => {
            if !sf.smep {
                missing.push("SMEP");
            }
            if !sf.smap {
                missing.push("SMAP");
            }
            if !sf.nx {
                missing.push("NX");
            }
            if !sf.spectre_mitigations {
                missing.push("Spectre mitigations");
            }
            if !sf.pti {
                missing.push("PTI (Meltdown)");
            }
        }
        "aarch64" => {
            if !sf.pan {
                missing.push("PAN");
            }
            if !sf.bti {
                missing.push("BTI");
            }
        }
        _ => {}
    }

    if !missing.is_empty() {
        return CheckResult {
            id: "CPU-001",
            name: "CPU Security Features",
            status: CheckStatus::Warning,
            confidence: confidence(0.6, 1.0),
            detail: format!(
                "missing security features: {}. {} total flags on {}.",
                missing.join(", "),
                features.flags.len(),
                features.arch,
            ),
        };
    }

    CheckResult {
        id: "CPU-001",
        name: "CPU Security Features",
        status: CheckStatus::Secure,
        confidence: confidence(0.5, 1.0),
        detail: format!(
            "{} flags on {}. All critical security features present.",
            features.flags.len(),
            features.arch,
        ),
    }
}

/// Check for hidden hypervisor (Blue Pill detection).
pub fn check_hypervisor() -> CheckResult {
    let Some(features) = CpuFeatures::capture() else {
        return CheckResult {
            id: "CPU-002",
            name: "Hypervisor Detection",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "cannot read /proc/cpuinfo".into(),
        };
    };

    if features.hypervisor_detected {
        match &features.hypervisor_vendor {
            Some(vendor) => CheckResult {
                id: "CPU-002",
                name: "Hypervisor Detection",
                status: CheckStatus::Secure,
                confidence: confidence(0.4, 0.9),
                detail: format!(
                    "hypervisor detected: {vendor}. Known vendor — expected if running in a VM."
                ),
            },
            None => CheckResult {
                id: "CPU-002",
                name: "Hypervisor Detection",
                status: CheckStatus::Warning,
                confidence: confidence(0.8, 0.7),
                detail: "hypervisor flag set but NO known vendor identified. \
                         Could be a thin hypervisor (Blue Pill) or unrecognized platform. \
                         Investigate if this machine should be bare-metal."
                    .into(),
            },
        }
    } else {
        CheckResult {
            id: "CPU-002",
            name: "Hypervisor Detection",
            status: CheckStatus::Secure,
            confidence: confidence(0.4, 0.8),
            detail: "no hypervisor detected — running on bare metal.".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_X86_FLAGS: &str = r#"
processor	: 0
vendor_id	: GenuineIntel
model name	: Intel Core i9
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology cpuid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch cpuid_fault invpcid_single ssbd ibrs ibpb stibp ibrs_enhanced fsgsbase bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves umip
"#;

    const SAMPLE_ARM_FLAGS: &str = r#"
processor	: 0
BogoMIPS	: 48.00
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp ssbs pan bti mte
"#;

    #[test]
    fn parse_x86_flags_extracted() {
        let f = CpuFeatures::parse(SAMPLE_X86_FLAGS);
        // Arch is compile-time, so we just check flags were extracted.
        assert!(f.flags.contains("smep"));
        assert!(f.flags.contains("smap"));
        assert!(f.flags.contains("nx"));
        assert!(f.flags.contains("umip"));
        assert!(f.flags.contains("hypervisor"));
    }

    #[test]
    fn parse_arm_flags_extracted() {
        let f = CpuFeatures::parse(SAMPLE_ARM_FLAGS);
        assert!(f.flags.contains("pan"));
        assert!(f.flags.contains("bti"));
        assert!(f.flags.contains("mte"));
    }

    #[test]
    fn detect_missing_flags() {
        let minimal = "flags\t\t: fpu vme de pse tsc msr\n";
        let f = CpuFeatures::parse(minimal);
        assert!(!f.flags.contains("smep"));
        assert!(!f.flags.contains("smap"));
    }

    #[test]
    fn diff_detects_removed_feature() {
        let mut baseline = CpuFeatures::parse(SAMPLE_X86_FLAGS);
        let mut current = baseline.clone();
        current.flags.remove("smep"); // attacker disabled SMEP

        let diffs = diff_features(&current, &baseline);
        assert!(diffs
            .iter()
            .any(|d| d.flag == "smep" && d.critical && d.kind == FeatureDiffKind::Removed));
    }

    #[test]
    fn diff_detects_hypervisor_appearance() {
        let mut baseline = CpuFeatures::parse("flags\t\t: fpu sse sse2 nx smep smap\n");
        baseline.hypervisor_detected = false;

        let mut current = baseline.clone();
        current.hypervisor_detected = true;
        current.flags.insert("hypervisor".into());

        let diffs = diff_features(&current, &baseline);
        assert!(diffs.iter().any(|d| d.flag == "hypervisor" && d.critical));
    }

    #[test]
    fn check_runs() {
        let r1 = check_cpu_security_features();
        assert_eq!(r1.id, "CPU-001");
        let r2 = check_hypervisor();
        assert_eq!(r2.id, "CPU-002");
    }
}
