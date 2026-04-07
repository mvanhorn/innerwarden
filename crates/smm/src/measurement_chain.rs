//! Software measurement chain — PCR-like hash chain without hardware TPM.
//!
//! Implements a transitive trust chain similar to TPM measured boot,
//! but entirely in software. Each component's hash is "extended" into
//! the previous measurement, creating a tamper-evident chain.
//!
//! If ANY component in the chain changes, the final chain value changes,
//! making it impossible to modify one component without detection.
//!
//! Chain: kernel → modules → init → critical binaries → config files
//!
//! Formula: PCR_new = SHA256(PCR_old || SHA256(component))

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::{confidence, CheckResult, CheckStatus};

/// A single measurement in the chain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Measurement {
    /// What was measured (e.g., "/boot/vmlinuz", "/proc/modules").
    pub target: String,
    /// SHA-256 of the component's content.
    pub hash: String,
    /// Running chain value after this measurement (PCR extend).
    pub chain_value: String,
    /// Size in bytes (0 for virtual files).
    pub size: u64,
}

/// Complete measurement chain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MeasurementChain {
    /// When this chain was computed.
    pub captured_at: String,
    /// Ordered list of measurements.
    pub measurements: Vec<Measurement>,
    /// Final chain value — the aggregate integrity.
    pub final_value: String,
}

/// Default targets to measure. Ordered by boot sequence.
const DEFAULT_TARGETS: &[&str] = &[
    // Kernel image.
    "/boot/vmlinuz",
    "/boot/vmlinuz-linux",
    // Init system.
    "/sbin/init",
    "/usr/lib/systemd/systemd",
    // Critical security binaries.
    "/usr/bin/sudo",
    "/usr/bin/ssh",
    "/usr/sbin/sshd",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/login",
    // Package managers (supply chain).
    "/usr/bin/apt",
    "/usr/bin/dpkg",
    "/usr/bin/rpm",
    "/usr/bin/yum",
    // Critical config.
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    // PAM modules.
    "/etc/pam.d/sshd",
    "/etc/pam.d/sudo",
];

/// PCR-extend operation: new_value = SHA256(old_value || measurement_hash).
fn pcr_extend(current: &str, measurement: &str) -> String {
    let combined = format!("{current}{measurement}");
    hex::encode(Sha256::digest(combined.as_bytes()))
}

impl MeasurementChain {
    /// Build a measurement chain from the default targets.
    pub fn measure() -> Self {
        Self::measure_targets(DEFAULT_TARGETS)
    }

    /// Build a measurement chain from custom targets.
    pub fn measure_targets(targets: &[&str]) -> Self {
        let mut measurements = Vec::new();
        // Start with a known initial value (all zeros, like TPM PCR reset).
        let mut chain = "0".repeat(64); // 256 bits of zeros

        for target in targets {
            let path = Path::new(target);

            // Try to find the actual file (some systems use different paths).
            let real_path = if path.exists() {
                path.to_path_buf()
            } else {
                // Try common alternatives.
                find_alternative(target).unwrap_or_else(|| path.to_path_buf())
            };

            if !real_path.exists() {
                continue;
            }

            let (hash, size) = hash_file(&real_path);
            chain = pcr_extend(&chain, &hash);

            measurements.push(Measurement {
                target: target.to_string(),
                hash,
                chain_value: chain.clone(),
                size,
            });
        }

        // Also measure virtual kernel state.
        // /proc/modules: loaded kernel modules list.
        if let Ok(content) = fs::read_to_string("/proc/modules") {
            // Sort lines for deterministic hash (module load order can vary).
            let mut lines: Vec<&str> = content.lines().collect();
            lines.sort();
            let sorted = lines.join("\n");
            let hash = hex::encode(Sha256::digest(sorted.as_bytes()));
            chain = pcr_extend(&chain, &hash);
            measurements.push(Measurement {
                target: "/proc/modules".into(),
                hash,
                chain_value: chain.clone(),
                size: 0,
            });
        }

        // /proc/cmdline: kernel boot parameters.
        if let Ok(content) = fs::read_to_string("/proc/cmdline") {
            let hash = hex::encode(Sha256::digest(content.trim().as_bytes()));
            chain = pcr_extend(&chain, &hash);
            measurements.push(Measurement {
                target: "/proc/cmdline".into(),
                hash,
                chain_value: chain.clone(),
                size: 0,
            });
        }

        MeasurementChain {
            captured_at: ::chrono::Utc::now().to_rfc3339(),
            measurements,
            final_value: chain,
        }
    }

    /// Compare two chains and return which measurements differ.
    pub fn diff(&self, other: &MeasurementChain) -> Vec<ChainDiff> {
        let mut diffs = Vec::new();
        let other_map: BTreeMap<&str, &Measurement> = other
            .measurements
            .iter()
            .map(|m| (m.target.as_str(), m))
            .collect();

        for m in &self.measurements {
            match other_map.get(m.target.as_str()) {
                Some(other_m) => {
                    if m.hash != other_m.hash {
                        diffs.push(ChainDiff {
                            target: m.target.clone(),
                            kind: DiffKind::Modified,
                            detail: format!(
                                "hash changed: {:.16}… → {:.16}…",
                                other_m.hash, m.hash
                            ),
                        });
                    }
                }
                None => {
                    diffs.push(ChainDiff {
                        target: m.target.clone(),
                        kind: DiffKind::Added,
                        detail: "new in current chain (not in baseline)".into(),
                    });
                }
            }
        }

        // Check for targets that were in baseline but missing now.
        let current_targets: BTreeMap<&str, &Measurement> = self
            .measurements
            .iter()
            .map(|m| (m.target.as_str(), m))
            .collect();
        for m in &other.measurements {
            if !current_targets.contains_key(m.target.as_str()) {
                diffs.push(ChainDiff {
                    target: m.target.clone(),
                    kind: DiffKind::Removed,
                    detail: "was in baseline but missing now".into(),
                });
            }
        }

        diffs
    }
}

/// Difference between two chain measurements.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainDiff {
    pub target: String,
    pub kind: DiffKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum DiffKind {
    Modified,
    Added,
    Removed,
}

fn hash_file(path: &Path) -> (String, u64) {
    match fs::read(path) {
        Ok(data) => {
            let size = data.len() as u64;
            let hash = hex::encode(Sha256::digest(&data));
            (hash, size)
        }
        Err(_) => ("error".into(), 0),
    }
}

fn find_alternative(target: &str) -> Option<std::path::PathBuf> {
    // Common path alternatives across distros.
    let alternatives: &[(&str, &[&str])] = &[
        (
            "/boot/vmlinuz",
            &[
                "/boot/vmlinuz-linux",
                "/boot/Image",    // ARM
                "/boot/Image.gz", // ARM compressed
            ],
        ),
        (
            "/sbin/init",
            &["/usr/lib/systemd/systemd", "/lib/systemd/systemd"],
        ),
        ("/usr/bin/apt", &["/usr/bin/apt-get"]),
    ];

    for (pat, alts) in alternatives {
        if target == *pat {
            for alt in *alts {
                let p = Path::new(alt);
                if p.exists() {
                    return Some(p.to_path_buf());
                }
            }
        }
    }
    None
}

// ── Check function ──────────────────────────────────────────────────────

/// Build and verify the software measurement chain.
pub fn check_measurement_chain() -> CheckResult {
    let chain = MeasurementChain::measure();

    if chain.measurements.is_empty() {
        return CheckResult {
            id: "CHAIN-001",
            name: "Measurement Chain",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "no targets measurable (not Linux or permissions issue)".into(),
        };
    }

    // Check for critical binaries that couldn't be hashed.
    let errors: Vec<&Measurement> = chain
        .measurements
        .iter()
        .filter(|m| m.hash == "error")
        .collect();

    if !errors.is_empty() {
        return CheckResult {
            id: "CHAIN-001",
            name: "Measurement Chain",
            status: CheckStatus::Warning,
            confidence: confidence(0.4, 0.7),
            detail: format!(
                "chain has {} component(s), but {} failed to hash: {}. \
                 Final chain: {:.16}…",
                chain.measurements.len(),
                errors.len(),
                errors
                    .iter()
                    .map(|m| m.target.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                chain.final_value,
            ),
        };
    }

    CheckResult {
        id: "CHAIN-001",
        name: "Measurement Chain",
        status: CheckStatus::Secure,
        confidence: confidence(0.8, 0.9),
        detail: format!(
            "{} components measured. Chain: {:.16}… \
             Run baseline to enable drift detection.",
            chain.measurements.len(),
            chain.final_value,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcr_extend_deterministic() {
        let init = "0".repeat(64);
        let hash = hex::encode(Sha256::digest(b"test data"));
        let result = pcr_extend(&init, &hash);
        assert_eq!(result.len(), 64); // SHA-256 hex = 64 chars

        // Same inputs should produce same output.
        let result2 = pcr_extend(&init, &hash);
        assert_eq!(result, result2);
    }

    #[test]
    fn pcr_extend_changes_with_input() {
        let init = "0".repeat(64);
        let r1 = pcr_extend(&init, "aaa");
        let r2 = pcr_extend(&init, "bbb");
        assert_ne!(r1, r2);
    }

    #[test]
    fn chain_order_matters() {
        let c1 = {
            let mut chain = "0".repeat(64);
            chain = pcr_extend(&chain, "first");
            chain = pcr_extend(&chain, "second");
            chain
        };
        let c2 = {
            let mut chain = "0".repeat(64);
            chain = pcr_extend(&chain, "second");
            chain = pcr_extend(&chain, "first");
            chain
        };
        assert_ne!(c1, c2, "chain order must matter (like TPM PCR extend)");
    }

    #[test]
    fn chain_diff_detection() {
        let m1 = MeasurementChain {
            captured_at: "t1".into(),
            measurements: vec![
                Measurement {
                    target: "/usr/bin/sudo".into(),
                    hash: "abc123".into(),
                    chain_value: "chain1".into(),
                    size: 1000,
                },
                Measurement {
                    target: "/usr/bin/ssh".into(),
                    hash: "def456".into(),
                    chain_value: "chain2".into(),
                    size: 2000,
                },
            ],
            final_value: "final1".into(),
        };

        let m2 = MeasurementChain {
            captured_at: "t2".into(),
            measurements: vec![
                Measurement {
                    target: "/usr/bin/sudo".into(),
                    hash: "MODIFIED".into(), // changed!
                    chain_value: "chain1_new".into(),
                    size: 1000,
                },
                Measurement {
                    target: "/usr/bin/ssh".into(),
                    hash: "def456".into(), // same
                    chain_value: "chain2".into(),
                    size: 2000,
                },
            ],
            final_value: "final2".into(),
        };

        let diffs = m2.diff(&m1);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].target, "/usr/bin/sudo");
        assert_eq!(diffs[0].kind, DiffKind::Modified);
    }

    #[test]
    fn measure_runs() {
        let chain = MeasurementChain::measure();
        // On dev machines, at least /proc/cmdline should be measurable.
        // On macOS, might be empty.
        let _ = chain;
    }

    #[test]
    fn check_runs() {
        let result = check_measurement_chain();
        assert_eq!(result.id, "CHAIN-001");
    }
}
