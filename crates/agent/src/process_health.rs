//! Self-observation for the agent process.
//!
//! The agent spawns external commands (tcpdump for pcap capture, tcpdump
//! again for monitor-ip, honeypot helpers, forensic tools). A bug in any of
//! those spawn paths can leave child processes around indefinitely; the
//! pcap_capture regression that motivated this module accumulated 20
//! orphaned tcpdumps over a single 16-hour uptime before it was noticed.
//!
//! This module walks /proc once to report a cheap snapshot: child count,
//! oldest child age, and a per-command breakdown. The snapshot is exposed
//! through /api/status and logged as a warning when it exceeds a threshold,
//! so a future spawn leak is visible on the dashboard without waiting for
//! someone to run ps on the host.
//!
//! Linux-only. Non-Linux builds (macOS dev, tests) return an empty snapshot.

use std::collections::HashMap;

use serde::Serialize;

/// Log a warning when the child count is at or above this value.
pub const CHILDREN_WARN_THRESHOLD: usize = 5;

/// A snapshot of the agent's direct child processes.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ProcessHealth {
    /// Total number of direct children of the agent process.
    pub children_total: usize,
    /// Age in seconds of the oldest child, or None when there are no
    /// children. Useful to distinguish "3 transient tcpdumps just started"
    /// from "3 tcpdumps stuck for an hour".
    pub oldest_child_age_secs: Option<u64>,
    /// Count of children grouped by command name (comm field in /proc).
    pub children_by_comm: HashMap<String, usize>,
}

impl ProcessHealth {
    /// Take a snapshot of the current process's direct children.
    ///
    /// Safe to call from any async context: pure /proc reads, no
    /// allocations that can fail, no blocking syscalls beyond readdir.
    pub fn snapshot() -> Self {
        #[cfg(target_os = "linux")]
        {
            snapshot_linux()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::default()
        }
    }

    /// True when the snapshot suggests a spawn leak: either a lot of
    /// children, or an old one. Callers can use this to emit a single
    /// aggregated warning rather than spamming per-child.
    pub fn looks_stuck(&self) -> bool {
        self.children_total >= CHILDREN_WARN_THRESHOLD
            || self
                .oldest_child_age_secs
                .map(|age| age > 300)
                .unwrap_or(false)
    }
}

#[cfg(target_os = "linux")]
fn snapshot_linux() -> ProcessHealth {
    let own_pid = std::process::id();
    let Ok(read_dir) = std::fs::read_dir("/proc") else {
        return ProcessHealth::default();
    };

    let own_uptime_secs = read_uptime_secs().unwrap_or(0);
    let mut children_total = 0usize;
    let mut oldest_age: Option<u64> = None;
    let mut by_comm: HashMap<String, usize> = HashMap::new();

    for entry in read_dir.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let status_path = entry.path().join("status");
        let Ok(status) = std::fs::read_to_string(&status_path) else {
            // Process disappeared between readdir and read - normal.
            continue;
        };

        let mut ppid: Option<u32> = None;
        let mut comm: Option<String> = None;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Name:\t") {
                comm = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("PPid:\t") {
                ppid = rest.trim().parse::<u32>().ok();
            }
            if ppid.is_some() && comm.is_some() {
                break;
            }
        }
        if ppid != Some(own_pid) {
            continue;
        }

        children_total += 1;
        if let Some(c) = comm {
            *by_comm.entry(c).or_insert(0) += 1;
        }

        if let Some(age) = child_age_secs(name_str, own_uptime_secs) {
            oldest_age = Some(oldest_age.map(|o| o.max(age)).unwrap_or(age));
        }
    }

    ProcessHealth {
        children_total,
        oldest_child_age_secs: oldest_age,
        children_by_comm: by_comm,
    }
}

/// Read the system uptime in seconds from /proc/uptime. The first field
/// is the boot-relative seconds as f64.
#[cfg(target_os = "linux")]
fn read_uptime_secs() -> Option<u64> {
    let contents = std::fs::read_to_string("/proc/uptime").ok()?;
    let first = contents.split_whitespace().next()?;
    first.parse::<f64>().ok().map(|f| f as u64)
}

/// Compute a child's age in seconds using field 22 of /proc/PID/stat
/// (starttime, in clock ticks since boot).
#[cfg(target_os = "linux")]
fn child_age_secs(pid_str: &str, own_uptime_secs: u64) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid_str}/stat")).ok()?;
    // The comm field (position 2) can contain spaces and parentheses, so
    // find the last ')' and parse fields after that.
    let close = stat.rfind(')')?;
    let tail = &stat[close + 1..];
    // After the comm field, fields are whitespace-separated. starttime is
    // field 22 of the whole record, or field 22 - 2 = 20 of the tail (the
    // leading space pushes index by 1, so we want index 19 in zero-based
    // terms after trimming).
    let tokens: Vec<&str> = tail.split_whitespace().collect();
    let starttime_ticks = tokens.get(19)?.parse::<u64>().ok()?;

    // USER_HZ is 100 on every mainstream Linux target we care about.
    // libc::sysconf(_SC_CLK_TCK) would be more portable but the agent
    // already assumes Linux userspace elsewhere.
    const USER_HZ: u64 = 100;
    let start_since_boot_secs = starttime_ticks / USER_HZ;
    own_uptime_secs.checked_sub(start_since_boot_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_snapshot_looks_healthy() {
        let h = ProcessHealth::default();
        assert_eq!(h.children_total, 0);
        assert_eq!(h.oldest_child_age_secs, None);
        assert!(!h.looks_stuck());
    }

    #[test]
    fn looks_stuck_on_high_child_count() {
        let h = ProcessHealth {
            children_total: CHILDREN_WARN_THRESHOLD,
            oldest_child_age_secs: Some(10),
            children_by_comm: HashMap::from([("tcpdump".into(), CHILDREN_WARN_THRESHOLD)]),
        };
        assert!(h.looks_stuck());
    }

    #[test]
    fn looks_stuck_on_old_child() {
        let h = ProcessHealth {
            children_total: 1,
            oldest_child_age_secs: Some(600),
            children_by_comm: HashMap::from([("tcpdump".into(), 1)]),
        };
        assert!(h.looks_stuck());
    }

    #[test]
    fn fresh_small_count_is_not_stuck() {
        let h = ProcessHealth {
            children_total: 2,
            oldest_child_age_secs: Some(45),
            children_by_comm: HashMap::from([("tcpdump".into(), 2)]),
        };
        assert!(!h.looks_stuck());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn snapshot_does_not_panic_on_live_system() {
        // Sanity check: the snapshot function must complete cleanly on the
        // host running the test, even if that host has no matching children.
        let _ = ProcessHealth::snapshot();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn snapshot_counts_live_child() {
        // Spawn a real child process and verify that the snapshot picks
        // it up: total+1, the comm is in the breakdown, and its age is
        // small (0-2s at the moment of capture). This exercises the
        // /proc walk, the PPid parsing, the comm extraction, and the
        // age-from-starttime calculation in one go.
        let before = ProcessHealth::snapshot();
        let mut child = std::process::Command::new("sleep")
            .arg("3")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn sleep child");

        // Give /proc a tick to reflect the new child.
        std::thread::sleep(std::time::Duration::from_millis(100));

        let during = ProcessHealth::snapshot();
        assert!(
            during.children_total >= before.children_total + 1,
            "expected child_total to grow by at least 1 ({} -> {})",
            before.children_total,
            during.children_total
        );
        assert!(
            during.children_by_comm.contains_key("sleep"),
            "expected 'sleep' in comm breakdown, got {:?}",
            during.children_by_comm
        );
        assert!(
            during.oldest_child_age_secs.is_some(),
            "oldest_child_age_secs must be populated once children exist"
        );
        assert!(
            during.oldest_child_age_secs.unwrap() < 30,
            "freshly spawned child should not report a 30s+ age"
        );

        let _ = child.kill();
        let _ = child.wait();
    }
}
