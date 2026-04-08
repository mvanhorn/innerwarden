// origin_lockdown.rs — Cloudflare-only origin lockdown
//
// When Shield enters UnderAttack/Critical, restrict HTTP/HTTPS (ports 80, 443)
// to only accept traffic from Cloudflare IP ranges. Direct-to-origin traffic
// is dropped via iptables + ipset, closing the bypass vector.
//
// Cloudflare publishes their IP ranges at:
//   https://www.cloudflare.com/ips-v4
//   https://www.cloudflare.com/ips-v6
//
// Architecture:
//   1. On startup: create ipset "cloudflare" with Cloudflare CIDRs
//   2. On escalation (UnderAttack/Critical): insert iptables rules
//   3. On de-escalation (Normal/Elevated): remove iptables rules
//   4. Periodically refresh Cloudflare CIDRs (every 6 hours)
//
// What is NOT blocked during lockdown:
//   - SSH (port 49222 or configured port)
//   - Localhost/loopback
//   - ICMP (ping)
//   - Established/related connections
//   - Oracle Cloud health checks (169.254.169.254)
//   - Outbound connections from the server

use anyhow::{Context, Result};
use tracing::{error, info, warn};

/// Cloudflare IPv4 ranges (hardcoded fallback, updated from API on startup).
/// Source: https://www.cloudflare.com/ips-v4 (as of 2026-03)
const CF_IPV4_FALLBACK: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
];

/// Iptables chain name for lockdown rules.
const CHAIN_NAME: &str = "INNERWARDEN_LOCKDOWN";

/// ipset name for Cloudflare CIDRs.
const IPSET_NAME: &str = "cloudflare_cidrs";

pub struct OriginLockdown {
    /// Whether lockdown is currently active.
    active: bool,
    /// Ports to restrict during lockdown.
    locked_ports: Vec<u16>,
    /// Ports that are NEVER restricted (SSH, etc).
    exempt_ports: Vec<u16>,
    /// HTTP client for fetching Cloudflare IPs.
    client: reqwest::Client,
}

impl OriginLockdown {
    pub fn new() -> Self {
        let ssh_port: u16 = std::env::var("SHIELD_SSH_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(49222);

        Self {
            active: false,
            locked_ports: vec![80, 443, 8787], // HTTP, HTTPS, dashboard
            exempt_ports: vec![ssh_port, 22, 9090], // SSH, Shield API
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Initialize: create ipset and populate with Cloudflare CIDRs.
    /// Called once at startup. Fail-silent on ipset errors.
    pub async fn init(&self) {
        // Destroy old ipset if exists, then recreate
        let _ = run_cmd("ipset", &["destroy", IPSET_NAME]);
        if let Err(e) = run_cmd(
            "ipset",
            &["create", IPSET_NAME, "hash:net", "family", "inet"],
        ) {
            warn!(error = %e, "Failed to create ipset — origin lockdown unavailable");
            return;
        }

        // Fetch fresh Cloudflare CIDRs, fallback to hardcoded
        let cidrs = self.fetch_cloudflare_cidrs().await;
        let mut count = 0;
        for cidr in &cidrs {
            if run_cmd("ipset", &["add", IPSET_NAME, cidr, "-exist"]).is_ok() {
                count += 1;
            }
        }

        // Create the iptables chain (idempotent)
        let _ = run_cmd("iptables", &["-N", CHAIN_NAME]);
        // Flush it in case of stale rules from a previous run
        let _ = run_cmd("iptables", &["-F", CHAIN_NAME]);

        info!(
            cidrs = count,
            "Origin lockdown initialized (ipset ready, inactive)"
        );
    }

    /// Activate lockdown: only Cloudflare CIDRs can reach locked ports.
    pub fn activate(&mut self) -> Result<()> {
        if self.active {
            return Ok(());
        }

        // Build the chain rules:
        // 1. Allow established/related (don't break existing connections)
        // 2. Allow loopback
        // 3. Allow exempt ports from anywhere (SSH)
        // 4. Allow locked ports ONLY from Cloudflare CIDRs
        // 5. Drop locked ports from anywhere else

        // Flush chain
        run_cmd("iptables", &["-F", CHAIN_NAME])?;

        // Allow established connections (critical for transition period)
        run_cmd(
            "iptables",
            &[
                "-A",
                CHAIN_NAME,
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
        )?;

        // Allow loopback
        run_cmd(
            "iptables",
            &["-A", CHAIN_NAME, "-s", "127.0.0.0/8", "-j", "ACCEPT"],
        )?;

        // Allow Oracle Cloud metadata (health checks)
        run_cmd(
            "iptables",
            &["-A", CHAIN_NAME, "-s", "169.254.169.254/32", "-j", "ACCEPT"],
        )?;

        // Allow exempt ports from anywhere (SSH)
        for port in &self.exempt_ports {
            run_cmd(
                "iptables",
                &[
                    "-A",
                    CHAIN_NAME,
                    "-p",
                    "tcp",
                    "--dport",
                    &port.to_string(),
                    "-j",
                    "ACCEPT",
                ],
            )?;
        }

        // For locked ports: allow from Cloudflare, drop everything else
        for port in &self.locked_ports {
            let port_str = port.to_string();
            // Allow from Cloudflare CIDRs
            run_cmd(
                "iptables",
                &[
                    "-A",
                    CHAIN_NAME,
                    "-p",
                    "tcp",
                    "--dport",
                    &port_str,
                    "-m",
                    "set",
                    "--match-set",
                    IPSET_NAME,
                    "src",
                    "-j",
                    "ACCEPT",
                ],
            )?;
            // Drop from anyone else
            run_cmd(
                "iptables",
                &[
                    "-A", CHAIN_NAME, "-p", "tcp", "--dport", &port_str, "-j", "DROP",
                ],
            )?;
        }

        // Insert the chain into INPUT (at position 1, before other rules)
        // Remove first if already there (idempotent)
        let _ = run_cmd("iptables", &["-D", "INPUT", "-j", CHAIN_NAME]);
        run_cmd("iptables", &["-I", "INPUT", "1", "-j", CHAIN_NAME])?;

        self.active = true;
        info!(
            locked_ports = ?self.locked_ports,
            exempt_ports = ?self.exempt_ports,
            "Origin lockdown ACTIVATED — HTTP/HTTPS restricted to Cloudflare only"
        );

        Ok(())
    }

    /// Deactivate lockdown: allow direct traffic again.
    pub fn deactivate(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }

        // Remove chain from INPUT
        let _ = run_cmd("iptables", &["-D", "INPUT", "-j", CHAIN_NAME]);
        // Flush the chain
        let _ = run_cmd("iptables", &["-F", CHAIN_NAME]);

        self.active = false;
        info!("Origin lockdown DEACTIVATED — direct access restored");

        Ok(())
    }

    /// Check escalation state and toggle lockdown.
    pub fn check_and_toggle(&mut self, state: crate::escalation::EscalationState) {
        let should_lock = matches!(
            state,
            crate::escalation::EscalationState::UnderAttack
                | crate::escalation::EscalationState::Critical
        );

        if should_lock && !self.active {
            if let Err(e) = self.activate() {
                error!(error = %e, "Failed to activate origin lockdown");
            }
        } else if !should_lock && self.active {
            if let Err(e) = self.deactivate() {
                error!(error = %e, "Failed to deactivate origin lockdown");
            }
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Refresh Cloudflare CIDRs from their API.
    pub async fn refresh_cidrs(&self) {
        let cidrs = self.fetch_cloudflare_cidrs().await;
        // Flush and re-add (atomic swap not possible with ipset hash:net)
        let _ = run_cmd("ipset", &["flush", IPSET_NAME]);
        let mut count = 0;
        for cidr in &cidrs {
            if run_cmd("ipset", &["add", IPSET_NAME, cidr, "-exist"]).is_ok() {
                count += 1;
            }
        }
        info!(cidrs = count, "Cloudflare CIDRs refreshed");
    }

    /// Fetch Cloudflare IPv4 CIDRs from their public endpoint.
    /// Falls back to hardcoded list on any error.
    async fn fetch_cloudflare_cidrs(&self) -> Vec<String> {
        match self
            .client
            .get("https://www.cloudflare.com/ips-v4")
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => match resp.text().await {
                Ok(body) => {
                    let cidrs: Vec<String> = body
                        .lines()
                        .map(|l| l.trim().to_string())
                        .filter(|l| !l.is_empty() && l.contains('/'))
                        .collect();
                    if cidrs.len() >= 10 {
                        info!(count = cidrs.len(), "Fetched Cloudflare CIDRs from API");
                        return cidrs;
                    }
                    warn!("Cloudflare CIDRs API returned too few entries, using fallback");
                }
                Err(e) => warn!(error = %e, "Failed to read Cloudflare CIDRs response"),
            },
            Ok(resp) => warn!(status = %resp.status(), "Cloudflare CIDRs API non-2xx"),
            Err(e) => warn!(error = %e, "Failed to fetch Cloudflare CIDRs"),
        }

        // Fallback
        info!("Using hardcoded Cloudflare CIDRs fallback");
        CF_IPV4_FALLBACK.iter().map(|s| s.to_string()).collect()
    }
}

/// Run a system command. Returns Ok(()) on success, Err on failure.
fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let output = std::process::Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {cmd}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{cmd} failed: {stderr}");
    }

    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_defaults() {
        let lock = OriginLockdown::new();
        assert!(!lock.active);
        assert!(lock.locked_ports.contains(&80));
        assert!(lock.locked_ports.contains(&443));
        assert!(lock.locked_ports.contains(&8787));
    }

    #[test]
    fn fallback_cidrs_count() {
        assert!(CF_IPV4_FALLBACK.len() >= 14);
    }

    #[test]
    fn fallback_cidrs_are_valid() {
        for cidr in CF_IPV4_FALLBACK {
            assert!(cidr.contains('/'), "invalid CIDR: {cidr}");
            let parts: Vec<&str> = cidr.split('/').collect();
            assert_eq!(parts.len(), 2);
            let _prefix: u8 = parts[1].parse().expect("invalid prefix length");
        }
    }
}
