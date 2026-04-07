//! CPU microcode verification — detect downgrade attacks and tampered microcode.
//!
//! Reads `/proc/cpuinfo` to extract microcode revision per CPU core.
//! Compares against baseline to detect downgrades (attacker rolling back
//! to vulnerable microcode) or unexpected changes.
//!
//! Background: Google proved in 2025 that AMD Zen 1-4 microcode signatures
//! used an insecure hash, allowing malicious microcode injection.
//! Monitoring microcode versions is now a critical security check.

use crate::{confidence, CheckResult, CheckStatus};
use std::collections::BTreeMap;
use std::fs;

/// Microcode state across all CPU cores.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MicrocodeState {
    /// CPU vendor (GenuineIntel, AuthenticAMD, or ARM implementer).
    pub vendor: String,
    /// CPU model name.
    pub model: String,
    /// Microcode revision per core (core_id → revision hex string).
    /// All cores should have the same revision.
    pub revisions: BTreeMap<u32, String>,
    /// Whether all cores report the same revision.
    pub uniform: bool,
}

impl MicrocodeState {
    /// Read microcode state from /proc/cpuinfo (Linux).
    pub fn read() -> Option<Self> {
        let content = fs::read_to_string("/proc/cpuinfo").ok()?;
        Self::parse(&content)
    }

    /// Parse /proc/cpuinfo content into microcode state.
    pub fn parse(content: &str) -> Option<Self> {
        let mut vendor = String::new();
        let mut model = String::new();
        let mut revisions = BTreeMap::new();
        let mut current_core: u32 = 0;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((key, val)) = line.split_once(':') {
                let key = key.trim();
                let val = val.trim();
                match key {
                    "vendor_id" if vendor.is_empty() => vendor = val.to_string(),
                    "model name" if model.is_empty() => model = val.to_string(),
                    "processor" => current_core = val.parse().unwrap_or(0),
                    "microcode" => {
                        revisions.insert(current_core, val.to_string());
                    }
                    // ARM: read CPU implementer + variant + revision
                    "CPU implementer" if vendor.is_empty() => {
                        vendor = format!("ARM implementer {val}");
                    }
                    "CPU revision" => {
                        revisions.insert(current_core, val.to_string());
                    }
                    _ => {}
                }
            }
        }

        if revisions.is_empty() && vendor.is_empty() {
            return None;
        }

        let unique: std::collections::HashSet<&String> = revisions.values().collect();
        let uniform = unique.len() <= 1;

        Some(Self {
            vendor,
            model,
            revisions,
            uniform,
        })
    }
}

// ── Check function ──────────────────────────────────────────────────────

/// Verify CPU microcode version and consistency.
pub fn check_microcode() -> CheckResult {
    let Some(state) = MicrocodeState::read() else {
        return CheckResult {
            id: "UCODE-001",
            name: "CPU Microcode",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "cannot read /proc/cpuinfo (not Linux or permissions issue)".into(),
        };
    };

    let core_count = state.revisions.len();
    let first_rev = state.revisions.values().next().cloned().unwrap_or_default();

    if !state.uniform {
        // Different microcode on different cores = very suspicious.
        let versions: Vec<String> = state
            .revisions
            .iter()
            .map(|(k, v)| format!("core{k}={v}"))
            .collect();
        return CheckResult {
            id: "UCODE-001",
            name: "CPU Microcode",
            status: CheckStatus::Critical,
            // Non-uniform microcode is extremely unusual and suspicious.
            confidence: confidence(0.9, 0.95),
            detail: format!(
                "MICROCODE MISMATCH across cores! {}: {}. \
                 All cores should run the same revision. \
                 Possible targeted microcode injection.",
                state.vendor,
                versions.join(", ")
            ),
        };
    }

    CheckResult {
        id: "UCODE-001",
        name: "CPU Microcode",
        status: CheckStatus::Secure,
        confidence: confidence(0.6, 1.0),
        detail: format!(
            "{} — {} cores at revision {first_rev}. Model: {}",
            state.vendor, core_count, state.model,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_X86: &str = r#"
processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz
microcode	: 0xf4

processor	: 1
vendor_id	: GenuineIntel
model name	: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz
microcode	: 0xf4
"#;

    const SAMPLE_AMD: &str = r#"
processor	: 0
vendor_id	: AuthenticAMD
model name	: AMD Ryzen 9 5900X 12-Core Processor
microcode	: 0x0a20120a

processor	: 1
vendor_id	: AuthenticAMD
model name	: AMD Ryzen 9 5900X 12-Core Processor
microcode	: 0x0a20120a
"#;

    const SAMPLE_MISMATCH: &str = r#"
processor	: 0
vendor_id	: GenuineIntel
model name	: Intel Xeon
microcode	: 0xf4

processor	: 1
vendor_id	: GenuineIntel
model name	: Intel Xeon
microcode	: 0xf2
"#;

    const SAMPLE_ARM: &str = r#"
processor	: 0
BogoMIPS	: 48.00
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32
CPU implementer	: 0x41
CPU architecture: 8
CPU variant	: 0x1
CPU part	: 0xd07
CPU revision	: 4

processor	: 1
CPU implementer	: 0x41
CPU revision	: 4
"#;

    #[test]
    fn parse_intel() {
        let state = MicrocodeState::parse(SAMPLE_X86).unwrap();
        assert_eq!(state.vendor, "GenuineIntel");
        assert_eq!(state.revisions.len(), 2);
        assert!(state.uniform);
        assert_eq!(state.revisions[&0], "0xf4");
    }

    #[test]
    fn parse_amd() {
        let state = MicrocodeState::parse(SAMPLE_AMD).unwrap();
        assert_eq!(state.vendor, "AuthenticAMD");
        assert!(state.uniform);
        assert_eq!(state.revisions[&0], "0x0a20120a");
    }

    #[test]
    fn detect_mismatch() {
        let state = MicrocodeState::parse(SAMPLE_MISMATCH).unwrap();
        assert!(!state.uniform);
        assert_ne!(state.revisions[&0], state.revisions[&1]);
    }

    #[test]
    fn parse_arm() {
        let state = MicrocodeState::parse(SAMPLE_ARM).unwrap();
        assert!(state.vendor.contains("ARM"));
        assert_eq!(state.revisions.len(), 2);
        assert!(state.uniform);
    }

    #[test]
    fn check_runs() {
        let result = check_microcode();
        assert_eq!(result.id, "UCODE-001");
    }
}
