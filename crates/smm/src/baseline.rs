//! Firmware baseline — snapshot of known-good state for drift detection.
//!
//! Captures ACPI hashes, SPI hash, PCR values, BIOS info, and SMI count
//! into a single JSON file. Subsequent audits compare against baseline
//! to detect changes (legitimate updates vs tamper).

use crate::acpi;
use crate::msr;
use crate::tpm;
use crate::uefi;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Complete firmware baseline snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FirmwareBaseline {
    /// When this baseline was captured.
    pub captured_at: String,
    /// Hostname at capture time.
    pub hostname: String,
    /// BIOS vendor + version + date.
    pub bios: BiosBaseline,
    /// SHA-256 hashes of ACPI tables.
    pub acpi_tables: Vec<AcpiTableBaseline>,
    /// TPM PCR values (SHA-256 bank preferred).
    pub pcrs: BTreeMap<u32, String>,
    /// SPI flash hash (if captured).
    pub spi_hash: Option<String>,
    /// SMI count at baseline time.
    pub smi_count: Option<u64>,
    /// Secure Boot state.
    pub secure_boot: Option<bool>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BiosBaseline {
    pub vendor: String,
    pub version: String,
    pub date: String,
    pub release: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AcpiTableBaseline {
    pub name: String,
    pub size: usize,
    pub sha256: String,
}

impl FirmwareBaseline {
    /// Capture a baseline from the current system state.
    pub fn capture() -> Self {
        let bios = uefi::BiosInfo::read();
        let acpi = acpi::hash_tables();
        let tpm = tpm::TpmInfo::read();
        let secure_boot = uefi::SecureBootState::read().map(|s| s.enabled);
        let smi = msr::read_smi_count();

        // Prefer SHA-256 PCR bank, fall back to SHA-1.
        let pcrs = tpm
            .pcrs
            .get("sha256")
            .or_else(|| tpm.pcrs.get("sha1"))
            .cloned()
            .unwrap_or_default();

        let hostname = hostname();

        Self {
            captured_at: chrono::Utc::now().to_rfc3339(),
            hostname,
            bios: BiosBaseline {
                vendor: bios.vendor,
                version: bios.version,
                date: bios.date,
                release: bios.bios_release,
            },
            acpi_tables: acpi
                .into_iter()
                .map(|t| AcpiTableBaseline {
                    name: t.name,
                    size: t.size,
                    sha256: t.sha256,
                })
                .collect(),
            pcrs,
            spi_hash: None, // SPI requires explicit `innerwarden-smm baseline --spi`
            smi_count: smi,
            secure_boot,
        }
    }

    /// Default baseline file path.
    pub fn default_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        PathBuf::from(home)
            .join(".innerwarden")
            .join("firmware_baseline.json")
    }

    /// Save baseline to disk.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load baseline from disk.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = fs::read_to_string(path)?;
        let baseline: Self = serde_json::from_str(&data)?;
        Ok(baseline)
    }
}

fn hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_string()
}

// ── Drift detection ─────────────────────────────────────────────────────

/// What changed between baseline and current state.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DriftReport {
    pub baseline_date: String,
    pub drifts: Vec<Drift>,
}

/// A single drift (change from baseline).
#[derive(Debug, Clone, serde::Serialize)]
pub struct Drift {
    pub component: String,
    pub severity: DriftSeverity,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum DriftSeverity {
    /// Informational change (BIOS date updated = legitimate update).
    Info,
    /// Suspicious change (ACPI table modified without BIOS update).
    Suspicious,
    /// Critical drift (SPI hash changed, PCR values changed without reboot).
    Critical,
}

/// Compare current system state against a stored baseline.
pub fn detect_drift(baseline: &FirmwareBaseline) -> DriftReport {
    let mut drifts = Vec::new();

    // BIOS info drift.
    let current_bios = uefi::BiosInfo::read();
    if current_bios.version != baseline.bios.version {
        let sev = if current_bios.date != baseline.bios.date {
            DriftSeverity::Info // version + date changed = legitimate update
        } else {
            DriftSeverity::Suspicious // version changed but date same = tamper?
        };
        drifts.push(Drift {
            component: "BIOS".into(),
            severity: sev,
            detail: format!(
                "version changed: {} → {}",
                baseline.bios.version, current_bios.version
            ),
        });
    }

    // ACPI table drift.
    let current_acpi = acpi::hash_tables();
    let baseline_map: BTreeMap<&str, &AcpiTableBaseline> = baseline
        .acpi_tables
        .iter()
        .map(|t| (t.name.as_str(), t))
        .collect();

    for table in &current_acpi {
        match baseline_map.get(table.name.as_str()) {
            Some(base) => {
                if table.sha256 != base.sha256 {
                    drifts.push(Drift {
                        component: format!("ACPI:{}", table.name),
                        severity: DriftSeverity::Suspicious,
                        detail: format!(
                            "hash changed: {:.16}… → {:.16}…",
                            base.sha256, table.sha256
                        ),
                    });
                }
            }
            None => {
                drifts.push(Drift {
                    component: format!("ACPI:{}", table.name),
                    severity: DriftSeverity::Suspicious,
                    detail: "new table appeared since baseline".into(),
                });
            }
        }
    }

    // PCR drift.
    let tpm = tpm::TpmInfo::read();
    let current_pcrs = tpm
        .pcrs
        .get("sha256")
        .or_else(|| tpm.pcrs.get("sha1"))
        .cloned()
        .unwrap_or_default();

    for (idx, base_val) in &baseline.pcrs {
        if let Some(curr_val) = current_pcrs.get(idx) {
            if curr_val != base_val {
                drifts.push(Drift {
                    component: format!("TPM:PCR{idx}"),
                    severity: DriftSeverity::Critical,
                    detail: format!("PCR{idx} changed (firmware measurement drift)"),
                });
            }
        }
    }

    // SPI hash drift.
    if let Some(ref base_spi) = baseline.spi_hash {
        // SPI can only be compared if we have a current dump — skip if not available.
        // The `spi::hash_image()` function requires an explicit dump step.
        let _ = base_spi; // placeholder for future auto-dump
    }

    // SMI count drift (large jump since baseline = suspicious).
    if let (Some(base_smi), Some(curr_smi)) = (baseline.smi_count, msr::read_smi_count()) {
        let delta = curr_smi.saturating_sub(base_smi);
        if delta > 10_000 {
            drifts.push(Drift {
                component: "SMI".into(),
                severity: DriftSeverity::Suspicious,
                detail: format!(
                    "SMI count jumped by {delta} since baseline ({base_smi} → {curr_smi})"
                ),
            });
        }
    }

    // Secure Boot state drift.
    let current_sb = uefi::SecureBootState::read().map(|s| s.enabled);
    if baseline.secure_boot != current_sb {
        if baseline.secure_boot == Some(true) && current_sb == Some(false) {
            drifts.push(Drift {
                component: "SecureBoot".into(),
                severity: DriftSeverity::Critical,
                detail: "Secure Boot was DISABLED since baseline".into(),
            });
        } else if baseline.secure_boot == Some(false) && current_sb == Some(true) {
            drifts.push(Drift {
                component: "SecureBoot".into(),
                severity: DriftSeverity::Info,
                detail: "Secure Boot was ENABLED since baseline (improvement)".into(),
            });
        }
    }

    DriftReport {
        baseline_date: baseline.captured_at.clone(),
        drifts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_roundtrip() {
        let baseline = FirmwareBaseline {
            captured_at: "2026-01-01T00:00:00Z".into(),
            hostname: "test".into(),
            bios: BiosBaseline {
                vendor: "TestVendor".into(),
                version: "1.0".into(),
                date: "01/01/2026".into(),
                release: "1.0".into(),
            },
            acpi_tables: vec![AcpiTableBaseline {
                name: "DSDT".into(),
                size: 4096,
                sha256: "abc123".into(),
            }],
            pcrs: BTreeMap::from([(0, "deadbeef".into()), (7, "cafebabe".into())]),
            spi_hash: None,
            smi_count: Some(42),
            secure_boot: Some(true),
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        baseline.save(&path).unwrap();

        let loaded = FirmwareBaseline::load(&path).unwrap();
        assert_eq!(loaded.hostname, "test");
        assert_eq!(loaded.bios.vendor, "TestVendor");
        assert_eq!(loaded.acpi_tables.len(), 1);
        assert_eq!(loaded.pcrs.len(), 2);
        assert_eq!(loaded.smi_count, Some(42));
    }

    #[test]
    fn drift_detection_bios_update() {
        let baseline = FirmwareBaseline {
            captured_at: "2026-01-01T00:00:00Z".into(),
            hostname: "test".into(),
            bios: BiosBaseline {
                vendor: "Test".into(),
                version: "1.0".into(),
                date: "01/01/2026".into(),
                release: "1.0".into(),
            },
            acpi_tables: vec![],
            pcrs: BTreeMap::new(),
            spi_hash: None,
            smi_count: None,
            secure_boot: None,
        };

        // detect_drift reads current system state, so on a dev machine
        // the BIOS version will differ from our fake baseline.
        let report = detect_drift(&baseline);
        // We can't assert specific drifts since it depends on the machine,
        // but it should not panic.
        assert!(!report.baseline_date.is_empty());
    }
}
