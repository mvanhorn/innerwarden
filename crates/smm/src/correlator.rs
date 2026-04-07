//! Firmware threat correlation — combines weak signals into strong detections.
//!
//! Individual checks are useful but the real power is in correlation:
//! multiple weak signals that individually might be noise, together
//! become a high-confidence detection.
//!
//! Example: SMI rate elevated + ACPI table changed + no BIOS update
//! = highly suspicious firmware activity, even though each signal alone
//! might have an innocent explanation.

use crate::baseline::{DriftReport, DriftSeverity};
use crate::{CheckStatus, FirmwareReport};

/// Correlated threat — multiple signals combined into a single finding.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CorrelatedThreat {
    pub id: String,
    pub name: String,
    /// Combined confidence (boosted above individual signals).
    pub confidence: f64,
    /// Evidence chain: which signals contributed.
    pub evidence: Vec<String>,
    pub detail: String,
}

/// Run correlation rules against an audit report + optional drift report.
pub fn correlate(report: &FirmwareReport, drift: Option<&DriftReport>) -> Vec<CorrelatedThreat> {
    let mut threats = Vec::new();

    // Rule 1: SMM Rootkit Pattern
    // SMI rate elevated + SMRAM unlocked = near-certain rootkit
    threats.extend(rule_smm_rootkit(report));

    // Rule 2: Firmware Tamper Pattern
    // ACPI changed + no BIOS update + SMI count jump
    if let Some(drift) = drift {
        threats.extend(rule_firmware_tamper(report, drift));
    }

    // Rule 3: Boot Chain Degradation
    // Secure Boot disabled + PCR drift
    if let Some(drift) = drift {
        threats.extend(rule_boot_chain_degradation(report, drift));
    }

    // Rule 4: Stealth Persistence
    // SPI hash changed + ACPI modified + BIOS version same
    if let Some(drift) = drift {
        threats.extend(rule_stealth_persistence(drift));
    }

    // Rule 5: LKM Rootkit Installation Pattern
    // kallsyms changed + new module + new eBPF program
    threats.extend(rule_lkm_rootkit(report));

    // Rule 6: Hardware-Level Attack
    // Microcode mismatch + CPU feature drift
    threats.extend(rule_hardware_attack(report));

    // Rule 7: Kernel Inline Hooking
    // Kernel text hash changed + timing anomaly
    threats.extend(rule_inline_hooking(report));

    // Rule 8: eBPF Weaponization (VoidLink Pattern)
    // Unknown eBPF on sensitive hook + kernel integrity change
    threats.extend(rule_ebpf_weaponization(report));

    threats
}

/// SMM rootkit: SMRAM unlocked + SMI anomaly = near-certain compromise.
fn rule_smm_rootkit(report: &FirmwareReport) -> Option<CorrelatedThreat> {
    let smram_unlocked = report
        .checks
        .iter()
        .find(|c| c.id == "SMM-001" && c.status == CheckStatus::Critical);
    let smi_anomaly = report.checks.iter().find(|c| {
        c.id == "SMI-001" && matches!(c.status, CheckStatus::Critical | CheckStatus::Warning)
    });

    match (smram_unlocked, smi_anomaly) {
        (Some(smram), Some(smi)) => {
            // Both signals → confidence boost to 0.99
            Some(CorrelatedThreat {
                id: "CORR-001".into(),
                name: "SMM Rootkit".into(),
                confidence: 0.99,
                evidence: vec![
                    format!("[{}] {}", smram.id, smram.detail),
                    format!("[{}] {}", smi.id, smi.detail),
                ],
                detail: "SMRAM unprotected AND abnormal SMI activity. \
                         This combination is the signature of an active SMM rootkit. \
                         Neither signal alone is definitive, but together they are."
                    .into(),
            })
        }
        (Some(smram), None) => {
            // SMRAM unlocked alone is still critical but lower confidence
            Some(CorrelatedThreat {
                id: "CORR-001".into(),
                name: "SMM Rootkit (potential)".into(),
                confidence: 0.85,
                evidence: vec![format!("[{}] {}", smram.id, smram.detail)],
                detail: "SMRAM unprotected. No SMI anomaly yet, but the door is open. \
                         A kernel-level attacker could install an SMM rootkit at any time."
                    .into(),
            })
        }
        _ => None,
    }
}

/// Firmware tamper: ACPI drift + SMI count jump + no BIOS update.
fn rule_firmware_tamper(report: &FirmwareReport, drift: &DriftReport) -> Option<CorrelatedThreat> {
    let acpi_drifts: Vec<&str> = drift
        .drifts
        .iter()
        .filter(|d| d.component.starts_with("ACPI:") && d.severity == DriftSeverity::Suspicious)
        .map(|d| d.component.as_str())
        .collect();

    let smi_drift = drift.drifts.iter().any(|d| d.component == "SMI");

    let bios_changed = drift.drifts.iter().any(|d| d.component == "BIOS");

    // ACPI changed + SMI jumped + BIOS NOT updated = suspicious
    if !acpi_drifts.is_empty() && smi_drift && !bios_changed {
        let mut evidence = Vec::new();
        for table in &acpi_drifts {
            evidence.push(format!("{table} hash changed since baseline"));
        }
        evidence.push("SMI count anomaly since baseline".into());
        evidence.push("BIOS version unchanged (not a legitimate update)".into());

        // Boost: 3 correlated signals
        let base_confidence: f64 = 0.5;
        let boost = 1.0 - (1.0 - base_confidence).powi(evidence.len() as i32);

        return Some(CorrelatedThreat {
            id: "CORR-002".into(),
            name: "Firmware Tamper".into(),
            confidence: boost.min(0.95),
            evidence,
            detail: "ACPI tables modified and SMI count jumped, but BIOS version is unchanged. \
                     Legitimate firmware updates change both BIOS version and ACPI tables. \
                     This pattern suggests runtime firmware modification."
                .into(),
        });
    }

    // ACPI changed alone without BIOS update = low-medium suspicion
    if !acpi_drifts.is_empty() && !bios_changed {
        let check = report.checks.iter().find(|c| c.id == "ACPI-001");
        let evidence = vec![
            format!(
                "{} ACPI table(s) changed: {}",
                acpi_drifts.len(),
                acpi_drifts.join(", ")
            ),
            "BIOS version unchanged".into(),
        ];
        let _ = check; // reference for future enrichment

        return Some(CorrelatedThreat {
            id: "CORR-002".into(),
            name: "ACPI Drift".into(),
            confidence: 0.55,
            evidence,
            detail: "ACPI tables changed without a BIOS update. Could be kernel \
                     module loading new SSDTs, or could be firmware-level modification."
                .into(),
        });
    }

    None
}

/// Boot chain degradation: Secure Boot disabled + PCR drift.
fn rule_boot_chain_degradation(
    _report: &FirmwareReport,
    drift: &DriftReport,
) -> Option<CorrelatedThreat> {
    let sb_disabled = drift
        .drifts
        .iter()
        .find(|d| d.component == "SecureBoot" && d.severity == DriftSeverity::Critical);

    let pcr_drifts: Vec<&str> = drift
        .drifts
        .iter()
        .filter(|d| d.component.starts_with("TPM:PCR") && d.severity == DriftSeverity::Critical)
        .map(|d| d.component.as_str())
        .collect();

    if sb_disabled.is_some() && !pcr_drifts.is_empty() {
        let mut evidence = vec!["Secure Boot was disabled since baseline".into()];
        for pcr in &pcr_drifts {
            evidence.push(format!("{pcr} value changed"));
        }

        return Some(CorrelatedThreat {
            id: "CORR-003".into(),
            name: "Boot Chain Compromise".into(),
            confidence: 0.92,
            evidence,
            detail: "Secure Boot disabled AND TPM PCR values changed. \
                     The boot chain of trust has been broken. An attacker may have \
                     inserted unsigned code into the boot process."
                .into(),
        });
    }

    None
}

/// Stealth persistence: SPI + ACPI changed but BIOS version unchanged.
fn rule_stealth_persistence(drift: &DriftReport) -> Option<CorrelatedThreat> {
    let spi_changed = drift
        .drifts
        .iter()
        .any(|d| d.component == "SPI" && d.severity == DriftSeverity::Critical);

    let acpi_changed = drift
        .drifts
        .iter()
        .any(|d| d.component.starts_with("ACPI:") && d.severity == DriftSeverity::Suspicious);

    let bios_same = !drift.drifts.iter().any(|d| d.component == "BIOS");

    if spi_changed && acpi_changed && bios_same {
        Some(CorrelatedThreat {
            id: "CORR-004".into(),
            name: "Stealth Firmware Implant".into(),
            confidence: 0.97,
            evidence: vec![
                "SPI flash hash changed".into(),
                "ACPI tables modified".into(),
                "BIOS version unchanged (no legitimate update)".into(),
            ],
            detail: "SPI flash AND ACPI tables were modified without a BIOS update. \
                     This is the signature of a firmware implant (LoJax, CosmicStrand). \
                     The attacker modified firmware directly while keeping version strings \
                     unchanged to avoid detection."
                .into(),
        })
    } else {
        None
    }
}

/// LKM rootkit installation: kallsyms changed + suspicious module or eBPF spike.
fn rule_lkm_rootkit(report: &FirmwareReport) -> Option<CorrelatedThreat> {
    let kallsyms_issue = report
        .checks
        .iter()
        .find(|c| c.id == "KERN-002" && c.status == CheckStatus::Warning);
    let module_issue = report
        .checks
        .iter()
        .find(|c| c.id == "KERN-001" && c.status == CheckStatus::Critical);
    let ebpf_issue = report
        .checks
        .iter()
        .find(|c| c.id == "EBPF-001" && c.status == CheckStatus::Warning);

    let mut evidence = Vec::new();
    if let Some(k) = kallsyms_issue {
        evidence.push(format!("[{}] {}", k.id, k.detail));
    }
    if let Some(m) = module_issue {
        evidence.push(format!("[{}] {}", m.id, m.detail));
    }
    if let Some(e) = ebpf_issue {
        evidence.push(format!("[{}] {}", e.id, e.detail));
    }

    if evidence.len() >= 2 {
        let base: f64 = 0.5;
        let boost = 1.0 - (1.0 - base).powi(evidence.len() as i32);
        Some(CorrelatedThreat {
            id: "CORR-005".into(),
            name: "LKM Rootkit Installation".into(),
            confidence: boost.min(0.95),
            evidence,
            detail: "Multiple kernel integrity signals: symbol table modified, \
                     suspicious modules or unusual eBPF activity. \
                     This pattern matches rootkit installation via loadable kernel module."
                .into(),
        })
    } else {
        None
    }
}

/// Hardware-level attack: microcode mismatch + CPU feature anomaly.
fn rule_hardware_attack(report: &FirmwareReport) -> Option<CorrelatedThreat> {
    let ucode_critical = report
        .checks
        .iter()
        .find(|c| c.id == "UCODE-001" && c.status == CheckStatus::Critical);
    let cpu_warning = report
        .checks
        .iter()
        .find(|c| c.id == "CPU-001" && c.status == CheckStatus::Warning);
    let hv_unknown = report
        .checks
        .iter()
        .find(|c| c.id == "CPU-002" && c.status == CheckStatus::Warning);

    let mut evidence = Vec::new();
    if let Some(u) = ucode_critical {
        evidence.push(format!("[{}] {}", u.id, u.detail));
    }
    if let Some(c) = cpu_warning {
        evidence.push(format!("[{}] {}", c.id, c.detail));
    }
    if let Some(h) = hv_unknown {
        evidence.push(format!("[{}] {}", h.id, h.detail));
    }

    if evidence.len() >= 2 {
        let base: f64 = 0.55;
        let boost = 1.0 - (1.0 - base).powi(evidence.len() as i32);
        Some(CorrelatedThreat {
            id: "CORR-006".into(),
            name: "Hardware-Level Attack".into(),
            confidence: boost.min(0.96),
            evidence,
            detail: "Microcode anomaly combined with CPU feature or hypervisor anomaly. \
                     This may indicate malicious microcode injection (AMD CVE-2024-56161), \
                     hidden hypervisor (Blue Pill), or CPU feature manipulation."
                .into(),
        })
    } else {
        None
    }
}

/// Kernel inline hooking: kernel text changed + timing anomaly.
fn rule_inline_hooking(report: &FirmwareReport) -> Option<CorrelatedThreat> {
    let ktext_changed = report.checks.iter().find(|c| {
        c.id == "KTEXT-001" && matches!(c.status, CheckStatus::Critical | CheckStatus::Warning)
    });
    let timing_anomaly = report.checks.iter().find(|c| {
        c.id == "CHRONO-001" && matches!(c.status, CheckStatus::Critical | CheckStatus::Warning)
    });
    let kallsyms_changed = report
        .checks
        .iter()
        .find(|c| c.id == "KERN-002" && c.status == CheckStatus::Warning);

    let mut evidence = Vec::new();
    if let Some(k) = ktext_changed {
        evidence.push(format!("[{}] {}", k.id, k.detail));
    }
    if let Some(t) = timing_anomaly {
        evidence.push(format!("[{}] {}", t.id, t.detail));
    }
    if let Some(s) = kallsyms_changed {
        evidence.push(format!("[{}] {}", s.id, s.detail));
    }

    if evidence.len() >= 2 {
        Some(CorrelatedThreat {
            id: "CORR-007".into(),
            name: "Kernel Inline Hooking".into(),
            confidence: 0.93,
            evidence,
            detail: "Kernel code integrity change combined with execution timing anomaly. \
                     Inline hooking modifies function prologues — this changes both the \
                     text hash AND the timing profile. Signature of active kernel rootkit \
                     (Singularity, Diamorphine ftrace hooks)."
                .into(),
        })
    } else {
        None
    }
}

/// eBPF weaponization (VoidLink pattern): unknown eBPF + kernel change.
fn rule_ebpf_weaponization(report: &FirmwareReport) -> Option<CorrelatedThreat> {
    let ebpf_suspicious = report.checks.iter().find(|c| {
        c.id == "EBPF-001" && matches!(c.status, CheckStatus::Warning | CheckStatus::Critical)
    });
    let kernel_change = report.checks.iter().find(|c| {
        (c.id == "KTEXT-001" || c.id == "KERN-001" || c.id == "KERN-002")
            && matches!(c.status, CheckStatus::Warning | CheckStatus::Critical)
    });

    match (ebpf_suspicious, kernel_change) {
        (Some(e), Some(k)) => Some(CorrelatedThreat {
            id: "CORR-008".into(),
            name: "eBPF Weaponization (VoidLink Pattern)".into(),
            confidence: 0.88,
            evidence: vec![
                format!("[{}] {}", e.id, e.detail),
                format!("[{}] {}", k.id, k.detail),
            ],
            detail: "Suspicious eBPF programs on sensitive hooks combined with kernel \
                     integrity changes. VoidLink rootkit uses eBPF programs attached to \
                     kprobes/tracepoints to hide processes and files. The eBPF programs \
                     themselves are legitimate kernel features being abused."
                .into(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::{Drift, DriftReport};
    use crate::CheckResult;

    fn empty_report() -> FirmwareReport {
        FirmwareReport {
            ts: chrono::Utc::now(),
            arch: crate::Arch::X86_64,
            trust_score: 1.0,
            checks: vec![],
            correlated_threats: vec![],
        }
    }

    #[test]
    fn smm_rootkit_both_signals() {
        let report = FirmwareReport {
            checks: vec![
                CheckResult {
                    id: "SMM-001",
                    name: "SMRAM Lock",
                    status: CheckStatus::Critical,
                    confidence: 1.0,
                    detail: "SMRR unlocked".into(),
                },
                CheckResult {
                    id: "SMI-001",
                    name: "SMI Rate",
                    status: CheckStatus::Critical,
                    confidence: 0.63,
                    detail: "SMI storm: 500 SMIs/min".into(),
                },
            ],
            ..empty_report()
        };

        let threats = correlate(&report, None);
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].id, "CORR-001");
        assert!(threats[0].confidence >= 0.99);
        assert_eq!(threats[0].evidence.len(), 2);
    }

    #[test]
    fn smm_rootkit_smram_only() {
        let report = FirmwareReport {
            checks: vec![CheckResult {
                id: "SMM-001",
                name: "SMRAM Lock",
                status: CheckStatus::Critical,
                confidence: 1.0,
                detail: "SMRR unlocked".into(),
            }],
            ..empty_report()
        };

        let threats = correlate(&report, None);
        assert_eq!(threats.len(), 1);
        assert!(threats[0].confidence < 0.99); // lower without SMI confirmation
    }

    #[test]
    fn no_threats_when_secure() {
        let report = FirmwareReport {
            checks: vec![
                CheckResult {
                    id: "SMM-001",
                    name: "SMRAM Lock",
                    status: CheckStatus::Secure,
                    confidence: 1.0,
                    detail: "locked".into(),
                },
                CheckResult {
                    id: "SMI-001",
                    name: "SMI Rate",
                    status: CheckStatus::Secure,
                    confidence: 0.56,
                    detail: "normal".into(),
                },
            ],
            ..empty_report()
        };

        let threats = correlate(&report, None);
        assert!(threats.is_empty());
    }

    #[test]
    fn boot_chain_degradation() {
        let drift = DriftReport {
            baseline_date: "2026-01-01".into(),
            drifts: vec![
                Drift {
                    component: "SecureBoot".into(),
                    severity: DriftSeverity::Critical,
                    detail: "disabled".into(),
                },
                Drift {
                    component: "TPM:PCR0".into(),
                    severity: DriftSeverity::Critical,
                    detail: "changed".into(),
                },
            ],
        };

        let report = empty_report();
        let threats = correlate(&report, Some(&drift));
        assert!(threats.iter().any(|t| t.id == "CORR-003"));
    }

    #[test]
    fn stealth_persistence_pattern() {
        let drift = DriftReport {
            baseline_date: "2026-01-01".into(),
            drifts: vec![
                Drift {
                    component: "SPI".into(),
                    severity: DriftSeverity::Critical,
                    detail: "hash changed".into(),
                },
                Drift {
                    component: "ACPI:DSDT".into(),
                    severity: DriftSeverity::Suspicious,
                    detail: "hash changed".into(),
                },
                // NOTE: no BIOS drift = attacker kept version unchanged
            ],
        };

        let threats = correlate(&empty_report(), Some(&drift));
        let implant = threats.iter().find(|t| t.id == "CORR-004");
        assert!(implant.is_some());
        assert!(implant.unwrap().confidence >= 0.95);
    }

    #[test]
    fn lkm_rootkit_pattern() {
        let report = FirmwareReport {
            checks: vec![
                CheckResult {
                    id: "KERN-001",
                    name: "Kernel Modules",
                    status: CheckStatus::Critical,
                    confidence: 0.9,
                    detail: "suspicious module: diamorphine".into(),
                },
                CheckResult {
                    id: "KERN-002",
                    name: "Kernel Symbol Table",
                    status: CheckStatus::Warning,
                    confidence: 0.56,
                    detail: "symbol table changed".into(),
                },
            ],
            ..empty_report()
        };

        let threats = correlate(&report, None);
        assert!(threats.iter().any(|t| t.id == "CORR-005"));
    }

    #[test]
    fn inline_hooking_pattern() {
        let report = FirmwareReport {
            checks: vec![
                CheckResult {
                    id: "KTEXT-001",
                    name: "Kernel Text",
                    status: CheckStatus::Critical,
                    confidence: 0.76,
                    detail: "text hash changed".into(),
                },
                CheckResult {
                    id: "CHRONO-001",
                    name: "Timing",
                    status: CheckStatus::Warning,
                    confidence: 0.36,
                    detail: "jitter elevated".into(),
                },
            ],
            ..empty_report()
        };

        let threats = correlate(&report, None);
        let hook = threats.iter().find(|t| t.id == "CORR-007");
        assert!(hook.is_some());
        assert!(hook.unwrap().confidence >= 0.9);
    }

    #[test]
    fn ebpf_weaponization_pattern() {
        let report = FirmwareReport {
            checks: vec![
                CheckResult {
                    id: "EBPF-001",
                    name: "eBPF Audit",
                    status: CheckStatus::Warning,
                    confidence: 0.35,
                    detail: "30 programs, 28 sensitive".into(),
                },
                CheckResult {
                    id: "KERN-002",
                    name: "Kernel Symbol Table",
                    status: CheckStatus::Warning,
                    confidence: 0.56,
                    detail: "changed".into(),
                },
            ],
            ..empty_report()
        };

        let threats = correlate(&report, None);
        assert!(threats.iter().any(|t| t.id == "CORR-008"));
    }
}
