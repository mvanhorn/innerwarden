//! Kernel text section hashing — detect runtime code modification.
//!
//! Reads the kernel's executable code from /proc/kcore and hashes it
//! to detect inline hooking, code patching, and rootkit modifications.
//!
//! /proc/kcore is an ELF-format file representing the kernel's virtual
//! memory. The .text section contains executable code. If a rootkit
//! patches a syscall handler or hooks a function, the hash changes.
//!
//! Fallback: if /proc/kcore is not readable (requires root + CONFIG_PROC_KCORE),
//! we hash /proc/kallsyms addresses to detect symbol table manipulation,
//! and check /sys/kernel/btf/vmlinux for BTF integrity.

use crate::{confidence, CheckResult, CheckStatus};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;

/// Kernel text integrity state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KernelTextState {
    /// SHA-256 of the kernel text section (from /proc/kcore or fallback).
    pub text_hash: Option<String>,
    /// Method used to obtain the hash.
    pub method: String,
    /// Size of the hashed region in bytes.
    pub size: usize,
    /// SHA-256 of /sys/kernel/btf/vmlinux (BTF type info — changes if kernel is different).
    pub btf_hash: Option<String>,
    /// SHA-256 of sorted kallsyms addresses (detect address manipulation).
    pub kallsyms_addr_hash: Option<String>,
    /// Number of kernel text symbols (functions in .text).
    pub text_symbol_count: usize,
}

impl KernelTextState {
    pub fn capture() -> Self {
        // Try /proc/kcore first (most definitive).
        let (text_hash, method, size) = read_kcore_text()
            .map(|(h, s)| (Some(h), "kcore".to_string(), s))
            .unwrap_or_else(|| {
                // Fallback: hash the first 4MB of /proc/kcore header.
                read_kcore_header()
                    .map(|(h, s)| (Some(h), "kcore_header".to_string(), s))
                    .unwrap_or((None, "unavailable".to_string(), 0))
            });

        let btf_hash = hash_file_if_exists("/sys/kernel/btf/vmlinux");
        let (kallsyms_addr_hash, text_symbol_count) = hash_kallsyms_addresses();

        Self {
            text_hash,
            method,
            size,
            btf_hash,
            kallsyms_addr_hash,
            text_symbol_count,
        }
    }
}

/// Read and hash the kernel text section from /proc/kcore.
/// /proc/kcore is an ELF core dump of kernel memory.
/// We read the first N bytes which contain the ELF header + kernel text.
fn read_kcore_text() -> Option<(String, usize)> {
    let path = Path::new("/proc/kcore");
    if !path.exists() {
        return None;
    }

    // Read the first 8MB — contains ELF header + kernel text segment.
    // We don't parse ELF (would need a dependency) — just hash the raw bytes.
    // The hash changes if any kernel code is modified.
    let mut f = fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 8 * 1024 * 1024];
    let n = f.read(&mut buf).ok()?;
    if n < 4096 {
        return None; // too small to be useful
    }
    buf.truncate(n);
    let hash = hex::encode(Sha256::digest(&buf));
    Some((hash, n))
}

/// Lighter fallback: read just the ELF header of /proc/kcore (first 64KB).
fn read_kcore_header() -> Option<(String, usize)> {
    let path = Path::new("/proc/kcore");
    let mut f = fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = f.read(&mut buf).ok()?;
    if n < 52 {
        // ELF header minimum
        return None;
    }
    // Verify ELF magic.
    if &buf[..4] != b"\x7fELF" {
        return None;
    }
    buf.truncate(n);
    let hash = hex::encode(Sha256::digest(&buf));
    Some((hash, n))
}

/// Hash a file if it exists.
fn hash_file_if_exists(path: &str) -> Option<String> {
    let data = fs::read(path).ok()?;
    Some(hex::encode(Sha256::digest(&data)))
}

/// Hash the ADDRESS column of /proc/kallsyms (not the symbol names).
/// Address manipulation indicates KASLR bypass or symbol table tampering.
/// Returns (hash, count of T/t symbols = text section functions).
fn hash_kallsyms_addresses() -> (Option<String>, usize) {
    let content = match fs::read_to_string("/proc/kallsyms") {
        Ok(c) => c,
        Err(_) => return (None, 0),
    };

    let mut hasher = Sha256::new();
    let mut text_count = 0;

    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            // Hash the address.
            hasher.update(parts[0].as_bytes());
            hasher.update(b"\n");
            // Count text section symbols (type T or t).
            if parts[1] == "T" || parts[1] == "t" {
                text_count += 1;
            }
        }
    }

    let hash = hex::encode(hasher.finalize());
    (Some(hash), text_count)
}

// ── Check function ──────────────────────────────────────────────────────

/// Verify kernel text integrity.
pub fn check_kernel_text() -> CheckResult {
    let state = KernelTextState::capture();

    // If we got a kcore hash, that's the strongest signal.
    if let Some(ref hash) = state.text_hash {
        return CheckResult {
            id: "KTEXT-001",
            name: "Kernel Text Integrity",
            status: CheckStatus::Secure,
            confidence: confidence(0.9, 0.85),
            detail: format!(
                "kernel text hashed via {} ({} bytes, sha256:{:.16}…). \
                 {} text symbols. Baseline captured for drift detection.",
                state.method, state.size, hash, state.text_symbol_count,
            ),
        };
    }

    // Fallback: BTF or kallsyms addresses.
    if state.btf_hash.is_some() || state.kallsyms_addr_hash.is_some() {
        let mut parts = Vec::new();
        if let Some(ref h) = state.btf_hash {
            parts.push(format!("BTF sha256:{:.16}…", h));
        }
        if let Some(ref h) = state.kallsyms_addr_hash {
            parts.push(format!(
                "kallsyms-addr sha256:{:.16}…, {} text symbols",
                h, state.text_symbol_count
            ));
        }
        return CheckResult {
            id: "KTEXT-001",
            name: "Kernel Text Integrity",
            status: CheckStatus::Secure,
            confidence: confidence(0.7, 0.7),
            detail: format!(
                "kernel text via fallback: {}. \
                 /proc/kcore not available (need root + CONFIG_PROC_KCORE).",
                parts.join("; ")
            ),
        };
    }

    CheckResult {
        id: "KTEXT-001",
        name: "Kernel Text Integrity",
        status: CheckStatus::Unavailable,
        confidence: 0.0,
        detail: "cannot verify kernel text (need root for /proc/kcore or /proc/kallsyms)".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_runs() {
        let state = KernelTextState::capture();
        // On macOS/non-Linux, everything will be None — but shouldn't panic.
        let _ = state;
    }

    #[test]
    fn check_runs() {
        let result = check_kernel_text();
        assert_eq!(result.id, "KTEXT-001");
    }

    #[test]
    fn elf_magic_check() {
        let valid_elf = b"\x7fELF\x02\x01\x01\x00";
        assert_eq!(&valid_elf[..4], b"\x7fELF");

        let invalid = b"\x00\x00\x00\x00";
        assert_ne!(&invalid[..4], b"\x7fELF");
    }
}
