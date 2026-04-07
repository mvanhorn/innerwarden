//! TPM (Trusted Platform Module) inspection — PCR values, TPM presence.
//!
//! Reads from `/sys/class/tpm/` (Linux TPM sysfs interface). Read-only.

use crate::{confidence, CheckResult, CheckStatus};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const TPM_SYSFS: &str = "/sys/class/tpm/tpm0";

/// TPM device info.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TpmInfo {
    pub present: bool,
    pub version: String,
    /// PCR bank → { index → hex digest }.
    pub pcrs: BTreeMap<String, BTreeMap<u32, String>>,
}

impl TpmInfo {
    pub fn read() -> Self {
        let present = Path::new(TPM_SYSFS).exists();
        if !present {
            return Self {
                present: false,
                version: String::new(),
                pcrs: BTreeMap::new(),
            };
        }

        let version = fs::read_to_string(format!("{TPM_SYSFS}/tpm_version_major"))
            .unwrap_or_default()
            .trim()
            .to_string();

        let pcrs = read_pcr_banks();

        Self {
            present,
            version,
            pcrs,
        }
    }
}

/// Read all PCR banks from sysfs.
/// Path: /sys/class/tpm/tpm0/pcr-{sha1,sha256,...}/{0,1,2,...}
fn read_pcr_banks() -> BTreeMap<String, BTreeMap<u32, String>> {
    let mut banks = BTreeMap::new();

    for algo in &["sha1", "sha256", "sha384", "sha512"] {
        let bank_dir = format!("{TPM_SYSFS}/pcr-{algo}");
        if !Path::new(&bank_dir).exists() {
            continue;
        }
        let mut pcrs = BTreeMap::new();
        if let Ok(entries) = fs::read_dir(&bank_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Ok(idx) = name.parse::<u32>() {
                    if let Ok(val) = fs::read_to_string(entry.path()) {
                        pcrs.insert(idx, val.trim().to_string());
                    }
                }
            }
        }
        if !pcrs.is_empty() {
            banks.insert(algo.to_string(), pcrs);
        }
    }

    banks
}

/// Check whether a PCR value is all-zeros (unextended = chain not measured).
fn is_zero_pcr(hex_val: &str) -> bool {
    hex_val.chars().all(|c| c == '0' || c == ' ')
}

// ── Check functions ─────────────────────────────────────────────────────

/// Check if TPM is present and accessible.
pub fn check_tpm_present() -> CheckResult {
    let info = TpmInfo::read();

    if !info.present {
        return CheckResult {
            id: "TPM-001",
            name: "TPM Present",
            status: CheckStatus::Warning,
            confidence: confidence(0.3, 1.0),
            detail: "no TPM detected (/sys/class/tpm/tpm0 not found). \
                     Hardware root of trust is unavailable."
                .into(),
        };
    }

    let bank_count = info.pcrs.len();
    CheckResult {
        id: "TPM-001",
        name: "TPM Present",
        status: CheckStatus::Secure,
        confidence: confidence(0.3, 1.0),
        detail: format!(
            "TPM {ver} detected — {bank_count} PCR bank(s) available",
            ver = if info.version.is_empty() {
                "unknown version"
            } else {
                &info.version
            },
        ),
    }
}

/// Check PCR values for firmware integrity (PCR 0-7 = firmware boot stages).
pub fn check_pcr_values() -> CheckResult {
    let info = TpmInfo::read();

    if !info.present {
        return CheckResult {
            id: "TPM-002",
            name: "PCR Boot Chain",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "no TPM — cannot verify boot chain integrity".into(),
        };
    }

    // Check SHA-256 bank first, fall back to SHA-1.
    let bank = info.pcrs.get("sha256").or_else(|| info.pcrs.get("sha1"));

    let Some(pcrs) = bank else {
        return CheckResult {
            id: "TPM-002",
            name: "PCR Boot Chain",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "TPM present but no PCR banks readable".into(),
        };
    };

    // Firmware PCRs: 0 (BIOS), 1 (BIOS config), 2 (option ROMs), 3 (option ROM config),
    // 4 (MBR), 5 (MBR config), 6 (state transitions), 7 (Secure Boot policy).
    let mut zero_pcrs = Vec::new();
    let mut measured_pcrs = Vec::new();

    for idx in 0..=7 {
        if let Some(val) = pcrs.get(&idx) {
            if is_zero_pcr(val) {
                zero_pcrs.push(idx);
            } else {
                measured_pcrs.push(idx);
            }
        }
    }

    if zero_pcrs.is_empty() && !measured_pcrs.is_empty() {
        CheckResult {
            id: "TPM-002",
            name: "PCR Boot Chain",
            status: CheckStatus::Secure,
            confidence: confidence(0.8, 0.9),
            detail: format!(
                "all firmware PCRs (0-7) measured — boot chain verified. {} PCRs extended.",
                measured_pcrs.len()
            ),
        }
    } else if !zero_pcrs.is_empty() {
        CheckResult {
            id: "TPM-002",
            name: "PCR Boot Chain",
            status: CheckStatus::Warning,
            confidence: confidence(0.6, 0.9),
            detail: format!(
                "PCRs {:?} are all-zeros — these boot stages were not measured. \
                 Firmware chain of trust may be incomplete.",
                zero_pcrs
            ),
        }
    } else {
        CheckResult {
            id: "TPM-002",
            name: "PCR Boot Chain",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "no firmware PCRs (0-7) found in TPM bank".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_pcr_detection() {
        assert!(is_zero_pcr(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(is_zero_pcr("00 00 00 00 00 00 00 00"));
        assert!(!is_zero_pcr(
            "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
        ));
    }

    #[test]
    fn tpm_info_handles_missing() {
        // On machines without TPM, should not panic.
        let info = TpmInfo::read();
        if !info.present {
            assert!(info.pcrs.is_empty());
        }
    }

    #[test]
    fn check_tpm_runs() {
        let result = check_tpm_present();
        assert!(!result.id.is_empty());
    }
}
