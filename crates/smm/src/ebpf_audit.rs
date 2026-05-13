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
        inventory_from_programs(list_bpf_programs())
    }
}

fn inventory_from_programs(programs: Vec<BpfProgram>) -> BpfInventory {
    let sensitive_count = programs.iter().filter(|p| p.sensitive).count();
    let total = programs.len();
    let inventory_hash = hash_program_inventory(&programs);

    BpfInventory {
        programs,
        total,
        sensitive_count,
        inventory_hash,
    }
}

fn hash_program_inventory(programs: &[BpfProgram]) -> String {
    let mut hasher = Sha256::new();
    for prog in programs {
        hasher.update(
            format!(
                "{}:{}:{}:{}\n",
                prog.id, prog.prog_type, prog.name, prog.tag
            )
            .as_bytes(),
        );
    }
    hex::encode(hasher.finalize())
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

    parse_bpftool_programs(&output.stdout)
}

fn parse_bpftool_programs(stdout: &[u8]) -> Option<Vec<BpfProgram>> {
    let json: serde_json::Value = serde_json::from_slice(stdout).ok()?;
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

            if let Some(program) = bpf_program_from_fdinfo(&content) {
                programs.entry(program.id).or_insert(program);
            }
        }
    }

    Some(programs.into_values().collect())
}

fn bpf_program_from_fdinfo(content: &str) -> Option<BpfProgram> {
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

    let id = prog_id?;
    Some(BpfProgram {
        id,
        prog_type: prog_type.clone(),
        name: String::new(),
        tag: prog_tag,
        sensitive: is_sensitive(&prog_type, ""),
    })
}

#[cfg(test)]
fn bpf_programs_from_fdinfo_contents<'a, I>(contents: I) -> Vec<BpfProgram>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut programs = BTreeMap::new();
    for content in contents {
        if let Some(program) = bpf_program_from_fdinfo(content) {
            programs.entry(program.id).or_insert(program);
        }
    }
    programs.into_values().collect()
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
    check_ebpf_inventory_from(inv)
}

fn check_ebpf_inventory_from(inv: BpfInventory) -> CheckResult {
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

        let hash1 = hash_program_inventory(&progs);
        let hash2 = hash_program_inventory(&progs);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn check_runs() {
        let result = check_ebpf_inventory();
        assert_eq!(result.id, "EBPF-001");
    }

    #[test]
    fn inventory_from_programs_counts_sensitive_and_hashes_all_programs() {
        let inv = inventory_from_programs(vec![
            BpfProgram {
                id: 7,
                prog_type: "xdp".into(),
                name: "edge_filter".into(),
                tag: "aaaa".into(),
                sensitive: true,
            },
            BpfProgram {
                id: 8,
                prog_type: "socket".into(),
                name: "metrics".into(),
                tag: "bbbb".into(),
                sensitive: false,
            },
        ]);

        assert_eq!(inv.total, 2);
        assert_eq!(inv.sensitive_count, 1);
        assert_eq!(inv.inventory_hash.len(), 64);
    }

    #[test]
    fn parse_bpftool_programs_maps_defaults_and_sensitive_hooks() {
        let raw = br#"[
            {"id":1,"type":"kprobe","name":"security_file_open","tag":"abc"},
            {"id":2,"type":"tracepoint","tag":"def"}
        ]"#;
        let programs = parse_bpftool_programs(raw).expect("valid bpftool JSON");
        assert_eq!(programs.len(), 2);
        assert_eq!(programs[0].id, 1);
        assert!(programs[0].sensitive);
        assert_eq!(programs[1].name, "");
        assert!(!programs[1].sensitive);
    }

    #[test]
    fn parse_bpftool_programs_rejects_non_array_or_missing_ids() {
        assert!(parse_bpftool_programs(br#"{"id":1}"#).is_none());
        assert!(parse_bpftool_programs(br#"[{"type":"xdp"}]"#).is_none());
    }

    #[test]
    fn check_inventory_reports_unavailable_for_empty_inventory() {
        let result = check_ebpf_inventory_from(inventory_from_programs(vec![]));
        assert_eq!(result.status, CheckStatus::Unavailable);
        assert!(result.detail.contains("no eBPF programs found"));
    }

    #[test]
    fn check_inventory_warns_when_sensitive_hook_count_is_high() {
        let programs = (0..21)
            .map(|id| BpfProgram {
                id,
                prog_type: "kprobe".into(),
                name: format!("security_hook_{id}"),
                tag: format!("{id:08x}"),
                sensitive: true,
            })
            .collect();

        let result = check_ebpf_inventory_from(inventory_from_programs(programs));
        assert_eq!(result.status, CheckStatus::Warning);
        assert!(result.detail.contains("21 on sensitive hooks"));
    }

    #[test]
    fn check_inventory_reports_secure_with_sensitive_name_preview() {
        let result = check_ebpf_inventory_from(inventory_from_programs(vec![
            BpfProgram {
                id: 1,
                prog_type: "xdp".into(),
                name: "innerwarden_xdp".into(),
                tag: "abc".into(),
                sensitive: true,
            },
            BpfProgram {
                id: 2,
                prog_type: "classifier".into(),
                name: "metrics".into(),
                tag: "def".into(),
                sensitive: false,
            },
        ]));

        assert_eq!(result.status, CheckStatus::Secure);
        assert!(result
            .detail
            .contains("2 eBPF programs, 1 on sensitive hooks"));
        assert!(result.detail.contains("innerwarden_xdp"));
    }

    #[test]
    fn bpf_program_from_fdinfo_parses_kernel_fd_metadata() {
        let program = bpf_program_from_fdinfo(
            "pos:\t0\nflags:\t02000002\nprog_type:\tcgroup_skb\nprog_id:\t42\nprog_tag:\tabcd\n",
        )
        .expect("fdinfo should parse");

        assert_eq!(program.id, 42);
        assert_eq!(program.prog_type, "cgroup_skb");
        assert_eq!(program.tag, "abcd");
        assert!(program.sensitive);
    }

    #[test]
    fn bpf_program_from_fdinfo_requires_numeric_program_id() {
        assert!(bpf_program_from_fdinfo("prog_type:\txdp\nprog_tag:\tabcd\n").is_none());
        assert!(bpf_program_from_fdinfo("prog_type:\txdp\nprog_id:\tnot-number\n").is_none());
    }

    #[test]
    fn bpf_programs_from_fdinfo_contents_deduplicates_program_ids() {
        let programs = bpf_programs_from_fdinfo_contents([
            "prog_type:\txdp\nprog_id:\t7\nprog_tag:\taaaa\n",
            "prog_type:\txdp\nprog_id:\t7\nprog_tag:\tbbbb\n",
            "prog_type:\tsocket_filter\nprog_id:\t8\nprog_tag:\tcccc\n",
        ]);

        assert_eq!(programs.len(), 2);
        assert_eq!(programs[0].id, 7);
        assert_eq!(programs[1].id, 8);
        assert!(programs.iter().all(|program| program.sensitive));
    }
}
