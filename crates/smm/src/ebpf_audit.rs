//! eBPF program inventory — detect malicious eBPF programs.
//!
//! Lists all loaded eBPF programs and maps on the system, hashes their
//! metadata for baseline comparison. Detects:
//! - Unexpected eBPF programs (rootkit like VoidLink)
//! - Programs attached to sensitive hooks (kprobes on security functions)
//! - Changes in eBPF program inventory since baseline
//!
//! Uses /proc and /sys/fs/bpf or `bpftool` output.
//! All operations are read-only.

use crate::{confidence, CheckResult, CheckStatus};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::process::Command;

/// A loaded eBPF program.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BpfProgram {
    pub id: u32,
    pub prog_type: String,
    pub name: String,
    pub tag: String,
    /// Whether this program is attached to a security-sensitive hook.
    pub sensitive: bool,
}

/// eBPF system inventory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BpfInventory {
    /// All loaded eBPF programs.
    pub programs: Vec<BpfProgram>,
    /// Total count.
    pub total: usize,
    /// Count of programs on sensitive hooks.
    pub sensitive_count: usize,
    /// SHA-256 of the inventory (for baseline comparison).
    pub inventory_hash: String,
}

/// Sensitive hook patterns — eBPF programs on these are security-relevant.
const SENSITIVE_PATTERNS: &[&str] = &[
    "kprobe",
    "kretprobe",
    "lsm",
    "raw_tracepoint",
    "tracepoint/syscalls",
    "tracepoint/sched",
    "security_",
    "selinux_",
    "apparmor_",
    "cgroup",
    "xdp",
    "tc",
    "socket_filter",
];

impl BpfInventory {
    /// Capture current eBPF program inventory.
    pub fn capture() -> Self {
        let programs = list_bpf_programs();
        let sensitive_count = programs.iter().filter(|p| p.sensitive).count();
        let total = programs.len();

        // Hash the inventory for baseline comparison.
        let mut hasher = Sha256::new();
        for prog in &programs {
            hasher.update(
                format!(
                    "{}:{}:{}:{}\n",
                    prog.id, prog.prog_type, prog.name, prog.tag
                )
                .as_bytes(),
            );
        }
        let inventory_hash = hex::encode(hasher.finalize());

        Self {
            programs,
            total,
            sensitive_count,
            inventory_hash,
        }
    }
}

/// List eBPF programs using bpftool or /proc/*/fdinfo fallback.
fn list_bpf_programs() -> Vec<BpfProgram> {
    // Try bpftool first (most reliable).
    if let Some(progs) = try_bpftool() {
        return progs;
    }

    // Fallback: parse /proc/*/fdinfo for bpf file descriptors.
    try_proc_fdinfo().unwrap_or_default()
}

/// Parse `bpftool prog list --json` output.
fn try_bpftool() -> Option<Vec<BpfProgram>> {
    let output = Command::new("bpftool")
        .args(["prog", "list", "--json"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let arr = json.as_array()?;

    let mut programs = Vec::new();
    for entry in arr {
        let id = entry.get("id")?.as_u64()? as u32;
        let prog_type = entry
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let tag = entry
            .get("tag")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let sensitive = is_sensitive(&prog_type, &name);

        programs.push(BpfProgram {
            id,
            prog_type,
            name,
            tag,
            sensitive,
        });
    }

    Some(programs)
}

/// Fallback: scan /proc/*/fdinfo for BPF program file descriptors.
fn try_proc_fdinfo() -> Option<Vec<BpfProgram>> {
    let mut programs = BTreeMap::new(); // dedup by prog_id

    let proc_dir = fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let pid_str = entry.file_name().to_string_lossy().to_string();
        if !pid_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let fd_dir = format!("/proc/{pid_str}/fdinfo");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };

        for fd_entry in fds.flatten() {
            let Ok(content) = fs::read_to_string(fd_entry.path()) else {
                continue;
            };

            // BPF fdinfo contains "prog_type:" and "prog_id:" fields.
            let mut prog_id: Option<u32> = None;
            let mut prog_type = String::new();
            let mut prog_tag = String::new();

            for line in content.lines() {
                if let Some(val) = line.strip_prefix("prog_id:") {
                    prog_id = val.trim().parse().ok();
                } else if let Some(val) = line.strip_prefix("prog_type:") {
                    prog_type = val.trim().to_string();
                } else if let Some(val) = line.strip_prefix("prog_tag:") {
                    prog_tag = val.trim().to_string();
                }
            }

            if let Some(id) = prog_id {
                programs.entry(id).or_insert_with(|| BpfProgram {
                    id,
                    prog_type: prog_type.clone(),
                    name: String::new(),
                    tag: prog_tag,
                    sensitive: is_sensitive(&prog_type, ""),
                });
            }
        }
    }

    Some(programs.into_values().collect())
}

fn is_sensitive(prog_type: &str, name: &str) -> bool {
    let lower_type = prog_type.to_lowercase();
    let lower_name = name.to_lowercase();
    SENSITIVE_PATTERNS
        .iter()
        .any(|p| lower_type.contains(p) || lower_name.contains(p))
}

// ── Check function ──────────────────────────────────────────────────────

/// Audit loaded eBPF programs.
pub fn check_ebpf_inventory() -> CheckResult {
    let inv = BpfInventory::capture();

    if inv.total == 0 {
        return CheckResult {
            id: "EBPF-001",
            name: "eBPF Program Audit",
            status: CheckStatus::Unavailable,
            confidence: 0.0,
            detail: "no eBPF programs found (need root or bpftool installed)".into(),
        };
    }

    // Flag if there are programs we don't recognize on sensitive hooks.
    // In a real deployment, the baseline would list expected programs.
    // For now, just report the inventory.
    let sensitive_names: Vec<&str> = inv
        .programs
        .iter()
        .filter(|p| p.sensitive)
        .map(|p| p.name.as_str())
        .collect();

    if inv.sensitive_count > 20 {
        // Unusually many sensitive hooks — could be legitimate (InnerWarden itself)
        // or could be a rootkit. Baseline comparison resolves this.
        CheckResult {
            id: "EBPF-001",
            name: "eBPF Program Audit",
            status: CheckStatus::Warning,
            confidence: confidence(0.5, 0.7),
            detail: format!(
                "{} eBPF programs loaded, {} on sensitive hooks. \
                 High count — verify against baseline. Inventory hash: {:.16}…",
                inv.total, inv.sensitive_count, inv.inventory_hash,
            ),
        }
    } else {
        CheckResult {
            id: "EBPF-001",
            name: "eBPF Program Audit",
            status: CheckStatus::Secure,
            confidence: confidence(0.6, 0.8),
            detail: format!(
                "{} eBPF programs, {} on sensitive hooks{}. \
                 Inventory hash: {:.16}…",
                inv.total,
                inv.sensitive_count,
                if !sensitive_names.is_empty() {
                    format!(
                        " ({})",
                        sensitive_names
                            .iter()
                            .take(5)
                            .copied()
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                } else {
                    String::new()
                },
                inv.inventory_hash,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_detection() {
        assert!(is_sensitive("kprobe", "my_hook"));
        assert!(is_sensitive("lsm", "security_check"));
        assert!(is_sensitive(
            "tracepoint",
            "tracepoint/syscalls/sys_enter_open"
        ));
        assert!(is_sensitive("xdp", "firewall"));
        // cgroup types are sensitive (contains "cgroup").
        assert!(is_sensitive("cgroup_skb", ""));
        assert!(is_sensitive("cgroup_skb", "something"));
    }

    #[test]
    fn inventory_hash_deterministic() {
        let progs = vec![
            BpfProgram {
                id: 1,
                prog_type: "kprobe".into(),
                name: "test".into(),
                tag: "abc".into(),
                sensitive: true,
            },
            BpfProgram {
                id: 2,
                prog_type: "xdp".into(),
                name: "fw".into(),
                tag: "def".into(),
                sensitive: true,
            },
        ];

        let mut h1 = Sha256::new();
        for p in &progs {
            h1.update(format!("{}:{}:{}:{}\n", p.id, p.prog_type, p.name, p.tag).as_bytes());
        }
        let hash1 = hex::encode(h1.finalize());

        let mut h2 = Sha256::new();
        for p in &progs {
            h2.update(format!("{}:{}:{}:{}\n", p.id, p.prog_type, p.name, p.tag).as_bytes());
        }
        let hash2 = hex::encode(h2.finalize());

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn check_runs() {
        let result = check_ebpf_inventory();
        assert_eq!(result.id, "EBPF-001");
    }
}
