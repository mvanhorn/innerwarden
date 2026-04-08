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
    /// Internal in-memory mirror of the blocklist.
    blocklist: Vec<BlocklistEntry>,
    /// When true, skip actual bpftool calls (for tests / dry-run).
    dry_run: bool,
}

impl XdpManager {
    pub fn new(bpf_path: &str) -> Self {
        Self {
            bpf_path: bpf_path.to_string(),
            blocklist: Vec::new(),
            dry_run: false,
        }
    }

    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
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
            let output = Command::new("bpftool")
                .args([
                    "map",
                    "update",
                    "pinned",
                    &format!("{}/{}", self.bpf_path, map_name),
                    "key",
                    &key_hex,
                    "value",
                    "0x01",
                    "0x00",
                    "0x00",
                    "0x00",
                ])
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
                let output = Command::new("bpftool")
                    .args([
                        "map",
                        "delete",
                        "pinned",
                        &format!("{}/{}", self.bpf_path, map_name),
                        "key",
                        &key_hex,
                    ])
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

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
}
