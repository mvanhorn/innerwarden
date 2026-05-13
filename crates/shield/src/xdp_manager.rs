// xdp_manager.rs — XDP BPF Map Management
//
// Interface to manage the XDP blocklist via bpftool subprocess calls.
// In tests, a mock mode avoids actual bpftool execution.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

/// Entry in the managed blocklist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistEntry {
    pub ip: String,
    pub added_at: chrono::DateTime<chrono::Utc>,
    pub reason: String,
}

/// Manages an XDP BPF map for wire-speed IP blocking.
pub struct XdpManager {
    bpf_path: String,
    bpftool_bin: String,
    /// Internal in-memory mirror of the blocklist.
    blocklist: Vec<BlocklistEntry>,
    /// When true, skip actual bpftool calls (for tests / dry-run).
    dry_run: bool,
}

impl XdpManager {
    pub fn new(bpf_path: &str) -> Self {
        Self {
            bpf_path: bpf_path.to_string(),
            bpftool_bin: "bpftool".into(),
            blocklist: Vec::new(),
            dry_run: false,
        }
    }

    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub fn with_bpftool_bin(mut self, bpftool_bin: impl Into<String>) -> Self {
        self.bpftool_bin = bpftool_bin.into();
        self
    }

    /// Add an IP (v4 or v6) to the XDP blocklist.
    pub fn add_to_blocklist(&mut self, ip: &str, reason: &str) -> Result<()> {
        // Skip if already present.
        if self.blocklist.iter().any(|e| e.ip == ip) {
            return Ok(());
        }

        if !self.dry_run {
            let (map_name, key_hex) = ip_to_bpf_map_and_key(ip)?;
            let pinned = pinned_map_path(&self.bpf_path, map_name);
            let args = bpftool_update_args(&pinned, &key_hex);
            let output = Command::new(&self.bpftool_bin)
                .args(args.iter().map(String::as_str))
                .output()
                .context("Failed to execute bpftool map update")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("bpftool map update failed for {}: {}", ip, stderr);
            }
        }

        self.blocklist.push(BlocklistEntry {
            ip: ip.to_string(),
            added_at: chrono::Utc::now(),
            reason: reason.to_string(),
        });

        tracing::info!(ip, reason, "Added IP to XDP blocklist");
        Ok(())
    }

    /// Remove an IP (v4 or v6) from the XDP blocklist.
    pub fn remove_from_blocklist(&mut self, ip: &str) -> Result<()> {
        let idx = self.blocklist.iter().position(|e| e.ip == ip);
        if idx.is_none() {
            return Ok(());
        }

        if !self.dry_run {
            if let Ok((map_name, key_hex)) = ip_to_bpf_map_and_key(ip) {
                let pinned = pinned_map_path(&self.bpf_path, map_name);
                let args = bpftool_delete_args(&pinned, &key_hex);
                let output = Command::new(&self.bpftool_bin)
                    .args(args.iter().map(String::as_str))
                    .output()
                    .context("Failed to execute bpftool map delete")?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::warn!(ip, error = %stderr, "bpftool map delete failed");
                }
            }
        }

        if let Some(i) = idx {
            self.blocklist.remove(i);
        }

        tracing::info!(ip, "Removed IP from XDP blocklist");
        Ok(())
    }

    /// Check if an IP is in the blocklist.
    pub fn is_blocked(&self, ip: &str) -> bool {
        self.blocklist.iter().any(|e| e.ip == ip)
    }

    /// Get all currently blocked IPs.
    pub fn get_blocklist(&self) -> Vec<String> {
        self.blocklist.iter().map(|e| e.ip.clone()).collect()
    }

    /// Get detailed blocklist entries.
    pub fn get_blocklist_entries(&self) -> &[BlocklistEntry] {
        &self.blocklist
    }

    /// Number of IPs in the blocklist.
    pub fn blocklist_count(&self) -> usize {
        self.blocklist.len()
    }

    /// BPF pin path.
    pub fn bpf_path(&self) -> &str {
        &self.bpf_path
    }

    /// Remove IPs that have been blocked longer than `max_age`.
    /// Called during de-escalation to release stale blocks.
    pub fn cleanup_stale(
        &mut self,
        max_age: std::time::Duration,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        let cutoff =
            now - chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::seconds(300));
        let stale: Vec<String> = self
            .blocklist
            .iter()
            .filter(|e| e.added_at < cutoff)
            .map(|e| e.ip.clone())
            .collect();
        for ip in &stale {
            let _ = self.remove_from_blocklist(ip);
        }
        if !stale.is_empty() {
            tracing::info!(count = stale.len(), "XDP: cleaned stale blocklist entries");
        }
    }
}

/// Convert an IP address to (map_name, bpftool hex key).
/// IPv4 → ("blocklist", "0xc0 0xa8 ..."), IPv6 → ("blocklist_v6", "0x20 0x01 ...").
fn ip_to_bpf_map_and_key(ip: &str) -> Result<(&'static str, String)> {
    if let Ok(v4) = ip.parse::<Ipv4Addr>() {
        let b = v4.octets();
        Ok((
            "blocklist",
            format!(
                "0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}",
                b[0], b[1], b[2], b[3]
            ),
        ))
    } else if let Ok(v6) = ip.parse::<Ipv6Addr>() {
        let b = v6.octets();
        let hex: Vec<String> = b.iter().map(|x| format!("0x{:02x}", x)).collect();
        Ok(("blocklist_v6", hex.join(" ")))
    } else {
        anyhow::bail!("invalid IP address: {}", ip)
    }
}

fn pinned_map_path(bpf_path: &str, map_name: &str) -> String {
    format!("{bpf_path}/{map_name}")
}

fn bpftool_update_args(pinned_map: &str, key_hex: &str) -> Vec<String> {
    [
        "map", "update", "pinned", pinned_map, "key", key_hex, "value", "0x01", "0x00", "0x00",
        "0x00",
    ]
    .iter()
    .map(|arg| (*arg).to_string())
    .collect()
}

fn bpftool_delete_args(pinned_map: &str, key_hex: &str) -> Vec<String> {
    ["map", "delete", "pinned", pinned_map, "key", key_hex]
        .iter()
        .map(|arg| (*arg).to_string())
        .collect()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    fn fake_bpftool(exit_code: i32, stderr: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let args_file = dir.path().join("args.txt");
        let script_path = dir.path().join("bpftool");
        let script = format!(
            "#!/bin/sh\nprintf '%s ' \"$@\" > '{}'\nprintf '{}' >&2\nexit {}\n",
            args_file.display(),
            stderr,
            exit_code
        );
        std::fs::write(&script_path, script).expect("write fake bpftool");
        let mut perms = std::fs::metadata(&script_path)
            .expect("script metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("chmod fake bpftool");
        (dir, script_path)
    }

    #[test]
    fn add_and_list_dry_run() {
        let mut mgr = XdpManager::new("/sys/fs/bpf/innerwarden").with_dry_run(true);
        mgr.add_to_blocklist("10.0.0.1", "rate_limit").unwrap();
        mgr.add_to_blocklist("10.0.0.2", "syn_flood").unwrap();

        let list = mgr.get_blocklist();
        assert_eq!(list.len(), 2);
        assert!(list.contains(&"10.0.0.1".to_string()));
        assert!(list.contains(&"10.0.0.2".to_string()));
    }

    #[test]
    fn remove_dry_run() {
        let mut mgr = XdpManager::new("/sys/fs/bpf/innerwarden").with_dry_run(true);
        mgr.add_to_blocklist("10.0.0.1", "test").unwrap();
        assert_eq!(mgr.blocklist_count(), 1);

        mgr.remove_from_blocklist("10.0.0.1").unwrap();
        assert_eq!(mgr.blocklist_count(), 0);
    }

    #[test]
    fn duplicate_add_is_noop() {
        let mut mgr = XdpManager::new("/sys/fs/bpf/innerwarden").with_dry_run(true);
        mgr.add_to_blocklist("10.0.0.1", "first_reason").unwrap();
        mgr.add_to_blocklist("10.0.0.1", "second_reason").unwrap();

        assert_eq!(mgr.blocklist_count(), 1);
        assert_eq!(mgr.get_blocklist_entries()[0].reason, "first_reason");
    }

    #[test]
    fn ipv4_key_correct() {
        let (map, key) = ip_to_bpf_map_and_key("192.168.1.100").unwrap();
        assert_eq!(map, "blocklist");
        assert_eq!(key, "0xc0 0xa8 0x01 0x64");
    }

    #[test]
    fn ipv6_key_correct() {
        let (map, key) = ip_to_bpf_map_and_key("2001:db8::1").unwrap();
        assert_eq!(map, "blocklist_v6");
        assert!(key.starts_with("0x20 0x01 0x0d 0xb8"));
    }

    #[test]
    fn invalid_ip_returns_error() {
        assert!(ip_to_bpf_map_and_key("not-an-ip").is_err());
    }

    #[test]
    fn remove_nonexistent_is_ok() {
        let mut mgr = XdpManager::new("/sys/fs/bpf/innerwarden").with_dry_run(true);
        assert!(mgr.remove_from_blocklist("10.0.0.99").is_ok());
    }

    #[test]
    fn blocklist_entries_detail() {
        let mut mgr = XdpManager::new("/sys/fs/bpf/innerwarden").with_dry_run(true);
        mgr.add_to_blocklist("10.0.0.5", "escalation").unwrap();
        let entries = mgr.get_blocklist_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip, "10.0.0.5");
        assert_eq!(entries[0].reason, "escalation");
    }

    #[test]
    fn manager_accessors_track_path_membership_and_count() {
        let mut mgr = XdpManager::new("/sys/fs/bpf/innerwarden").with_dry_run(true);
        assert_eq!(mgr.bpf_path(), "/sys/fs/bpf/innerwarden");
        assert!(!mgr.is_blocked("203.0.113.7"));

        mgr.add_to_blocklist("203.0.113.7", "test").unwrap();

        assert!(mgr.is_blocked("203.0.113.7"));
        assert_eq!(mgr.blocklist_count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn non_dry_run_add_invokes_configured_bpftool_and_records_entry() {
        let (dir, script_path) = fake_bpftool(0, "");
        let args_file = dir.path().join("args.txt");
        let mut mgr =
            XdpManager::new("/pins").with_bpftool_bin(script_path.to_string_lossy().to_string());

        mgr.add_to_blocklist("203.0.113.7", "manual").unwrap();

        let args = std::fs::read_to_string(args_file).expect("args file");
        assert!(args.contains("map update pinned /pins/blocklist key 0xcb 0x00 0x71 0x07"));
        assert!(mgr.is_blocked("203.0.113.7"));
        assert_eq!(mgr.get_blocklist_entries()[0].reason, "manual");
    }

    #[cfg(unix)]
    #[test]
    fn non_dry_run_add_returns_error_without_mutating_when_bpftool_fails() {
        let (_dir, script_path) = fake_bpftool(2, "denied");
        let mut mgr =
            XdpManager::new("/pins").with_bpftool_bin(script_path.to_string_lossy().to_string());

        let err = mgr
            .add_to_blocklist("203.0.113.7", "manual")
            .expect_err("bpftool failure should bubble");

        assert!(err.to_string().contains("bpftool map update failed"));
        assert_eq!(mgr.blocklist_count(), 0);
    }

    #[test]
    fn non_dry_run_add_validates_ip_before_running_bpftool() {
        let mut mgr = XdpManager::new("/pins").with_bpftool_bin("/definitely/missing/bpftool");

        let err = mgr
            .add_to_blocklist("not-an-ip", "manual")
            .expect_err("invalid IP should fail before subprocess");

        assert!(err.to_string().contains("invalid IP address"));
        assert_eq!(mgr.blocklist_count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn duplicate_add_skips_bpftool_even_when_not_dry_run() {
        let (dir, script_path) = fake_bpftool(2, "should not run");
        let args_file = dir.path().join("args.txt");
        let mut mgr =
            XdpManager::new("/pins").with_bpftool_bin(script_path.to_string_lossy().to_string());
        mgr.blocklist.push(BlocklistEntry {
            ip: "203.0.113.7".to_string(),
            added_at: chrono::Utc::now(),
            reason: "first".to_string(),
        });

        mgr.add_to_blocklist("203.0.113.7", "second").unwrap();

        assert_eq!(mgr.blocklist_count(), 1);
        assert_eq!(mgr.get_blocklist_entries()[0].reason, "first");
        assert!(!args_file.exists());
    }

    #[cfg(unix)]
    #[test]
    fn non_dry_run_remove_invokes_bpftool_and_removes_even_on_delete_failure() {
        let (dir, script_path) = fake_bpftool(2, "delete denied");
        let args_file = dir.path().join("args.txt");
        let mut mgr =
            XdpManager::new("/pins").with_bpftool_bin(script_path.to_string_lossy().to_string());
        mgr.blocklist.push(BlocklistEntry {
            ip: "2001:db8::1".to_string(),
            added_at: chrono::Utc::now(),
            reason: "test".to_string(),
        });

        mgr.remove_from_blocklist("2001:db8::1").unwrap();

        let args = std::fs::read_to_string(args_file).expect("args file");
        assert!(args.contains("map delete pinned /pins/blocklist_v6 key"));
        assert!(!mgr.is_blocked("2001:db8::1"));
    }

    #[test]
    fn cleanup_stale_removes_only_entries_older_than_cutoff() {
        let now = chrono::Utc::now();
        let mut mgr = XdpManager::new("/sys/fs/bpf/innerwarden").with_dry_run(true);
        mgr.blocklist.push(BlocklistEntry {
            ip: "10.0.0.1".to_string(),
            added_at: now - chrono::Duration::seconds(601),
            reason: "old".to_string(),
        });
        mgr.blocklist.push(BlocklistEntry {
            ip: "10.0.0.2".to_string(),
            added_at: now - chrono::Duration::seconds(100),
            reason: "fresh".to_string(),
        });

        mgr.cleanup_stale(std::time::Duration::from_secs(300), now);

        assert!(!mgr.is_blocked("10.0.0.1"));
        assert!(mgr.is_blocked("10.0.0.2"));
    }

    #[test]
    fn cleanup_stale_uses_default_age_when_duration_overflows_chrono() {
        let now = chrono::Utc::now();
        let mut mgr = XdpManager::new("/sys/fs/bpf/innerwarden").with_dry_run(true);
        mgr.blocklist.push(BlocklistEntry {
            ip: "10.0.0.3".to_string(),
            added_at: now - chrono::Duration::seconds(301),
            reason: "old".to_string(),
        });

        mgr.cleanup_stale(std::time::Duration::MAX, now);

        assert!(!mgr.is_blocked("10.0.0.3"));
    }

    #[test]
    fn bpftool_argument_builders_use_pinned_map_and_key() {
        let pinned = pinned_map_path("/sys/fs/bpf/innerwarden", "blocklist");
        assert_eq!(pinned, "/sys/fs/bpf/innerwarden/blocklist");

        let update = bpftool_update_args(&pinned, "0xcb 0x00 0x71 0x07");
        assert_eq!(
            update,
            vec![
                "map",
                "update",
                "pinned",
                "/sys/fs/bpf/innerwarden/blocklist",
                "key",
                "0xcb 0x00 0x71 0x07",
                "value",
                "0x01",
                "0x00",
                "0x00",
                "0x00",
            ]
        );

        let delete = bpftool_delete_args(&pinned, "0xcb 0x00 0x71 0x07");
        assert_eq!(
            delete,
            vec![
                "map",
                "delete",
                "pinned",
                "/sys/fs/bpf/innerwarden/blocklist",
                "key",
                "0xcb 0x00 0x71 0x07",
            ]
        );
    }

    #[test]
    fn ipv6_key_contains_all_sixteen_octets() {
        let (_map, key) = ip_to_bpf_map_and_key("2001:db8::1").unwrap();
        assert_eq!(key.split_whitespace().count(), 16);
        assert!(key.ends_with("0x00 0x01"));
    }
}
