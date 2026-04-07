//! SPI flash integrity — firmware image hashing for tamper detection.
//!
//! Uses `flashrom` (if available) to read the SPI flash chip non-destructively,
//! then hashes the image for baseline comparison. Detects firmware rootkits
//! like LoJax, MosaicRegressor, and CosmicStrand.

use crate::{confidence, CheckResult, CheckStatus};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// SPI flash baseline — stored hash of the firmware image.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SpiBaseline {
    pub sha256: String,
    pub size: usize,
    pub captured_at: String,
    pub method: String,
}

/// Dump SPI flash to a file using `flashrom --read`.
/// Returns the path to the dumped image. This is a READ-ONLY operation.
pub fn dump_flash(output: &Path) -> anyhow::Result<PathBuf> {
    let status = Command::new("flashrom")
        .args([
            "--programmer",
            "internal",
            "--read",
            output.to_str().unwrap(),
        ])
        .output()?;

    if !status.status.success() {
        let stderr = String::from_utf8_lossy(&status.stderr);
        anyhow::bail!("flashrom read failed: {stderr}");
    }

    Ok(output.to_path_buf())
}

/// Hash a firmware image file.
pub fn hash_image(path: &Path) -> anyhow::Result<SpiBaseline> {
    let data = fs::read(path)?;
    let hash = hex::encode(Sha256::digest(&data));
    Ok(SpiBaseline {
        sha256: hash,
        size: data.len(),
        captured_at: chrono::Utc::now().to_rfc3339(),
        method: "flashrom --read".into(),
    })
}

/// Compare a current flash dump against a stored baseline.
pub fn verify_against_baseline(current: &SpiBaseline, baseline: &SpiBaseline) -> CheckResult {
    if current.sha256 == baseline.sha256 {
        CheckResult {
            id: "SPI-001",
            name: "SPI Flash Integrity",
            status: CheckStatus::Secure,
            confidence: confidence(0.95, 1.0),
            detail: format!(
                "firmware hash matches baseline (sha256:{:.16}…, {} bytes)",
                current.sha256, current.size
            ),
        }
    } else {
        CheckResult {
            id: "SPI-001",
            name: "SPI Flash Integrity",
            status: CheckStatus::Critical,
            confidence: confidence(0.95, 1.0),
            detail: format!(
                "FIRMWARE MODIFIED! Current sha256:{:.16}… != baseline sha256:{:.16}…. \
                 Possible firmware rootkit. Verify with vendor update logs.",
                current.sha256, baseline.sha256
            ),
        }
    }
}

/// Check if flashrom is available.
pub fn flashrom_available() -> bool {
    Command::new("flashrom")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ── Check function ──────────────────────────────────────────────────────

/// Check SPI flash baseline status.
pub fn check_flash_baseline() -> CheckResult {
    if !flashrom_available() {
        return CheckResult {
            id: "SPI-001",
            name: "SPI Flash Integrity",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "flashrom not installed. Install with: apt install flashrom".into(),
        };
    }

    // We don't auto-dump (requires root + can be slow). Just report readiness.
    CheckResult {
        id: "SPI-001",
        name: "SPI Flash Integrity",
        status: CheckStatus::Secure,
        confidence: confidence(0.2, 1.0),
        detail: "flashrom available — run `innerwarden-smm baseline` to capture SPI flash hash"
            .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_match() {
        let base = SpiBaseline {
            sha256: "abc123".into(),
            size: 8 * 1024 * 1024,
            captured_at: "2026-01-01T00:00:00Z".into(),
            method: "flashrom".into(),
        };
        let current = base.clone();
        let result = verify_against_baseline(&current, &base);
        assert_eq!(result.status, CheckStatus::Secure);
    }

    #[test]
    fn baseline_mismatch_critical() {
        let base = SpiBaseline {
            sha256: "abc123".into(),
            size: 8 * 1024 * 1024,
            captured_at: "2026-01-01T00:00:00Z".into(),
            method: "flashrom".into(),
        };
        let tampered = SpiBaseline {
            sha256: "def456".into(),
            ..base.clone()
        };
        let result = verify_against_baseline(&tampered, &base);
        assert_eq!(result.status, CheckStatus::Critical);
        assert!(result.detail.contains("FIRMWARE MODIFIED"));
    }
}
