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

fn ssh_port_from_env_value(value: Option<&str>) -> u16 {
    value.and_then(|s| s.parse().ok()).unwrap_or(49222)
}

fn state_requires_lockdown(state: crate::escalation::EscalationState) -> bool {
    matches!(
        state,
        crate::escalation::EscalationState::UnderAttack
            | crate::escalation::EscalationState::Critical
    )
}

fn parse_cloudflare_cidrs(body: &str) -> Vec<String> {
    body.lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && line.contains('/'))
        .collect()
}

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
        let ssh_port_env = std::env::var("SHIELD_SSH_PORT").ok();
        let ssh_port = ssh_port_from_env_value(ssh_port_env.as_deref());

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
        self.activate_with_runner(|args| run_cmd_args("iptables", args))
    }

    fn activate_with_runner<F>(&mut self, mut run: F) -> Result<()>
    where
        F: FnMut(&[String]) -> Result<()>,
    {
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
        for args in activation_iptables_args(&self.locked_ports, &self.exempt_ports) {
            run(&args)?;
        }

        // Insert the chain into INPUT (at position 1, before other rules)
        // Remove first if already there (idempotent)
        let _ = run(&input_chain_delete_args());
        run(&input_chain_insert_args())?;

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
        self.deactivate_with_runner(|args| run_cmd_args("iptables", args))
    }

    fn deactivate_with_runner<F>(&mut self, mut run: F) -> Result<()>
    where
        F: FnMut(&[String]) -> Result<()>,
    {
        if !self.active {
            return Ok(());
        }

        // Remove chain from INPUT
        for args in deactivation_iptables_args() {
            let _ = run(&args);
        }

        self.active = false;
        info!("Origin lockdown DEACTIVATED — direct access restored");

        Ok(())
    }

    /// Check escalation state and toggle lockdown.
    pub fn check_and_toggle(&mut self, state: crate::escalation::EscalationState) {
        let should_lock = state_requires_lockdown(state);

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
        self.refresh_cidrs_with_runner(&cidrs, |args| run_cmd_args("ipset", args));
    }

    fn refresh_cidrs_with_runner<F>(&self, cidrs: &[String], mut run: F) -> usize
    where
        F: FnMut(&[String]) -> Result<()>,
    {
        // Flush and re-add (atomic swap not possible with ipset hash:net)
        let _ = run(&command_args(&["flush", IPSET_NAME]));
        let mut count = 0;
        for cidr in cidrs {
            if run(&command_args(&["add", IPSET_NAME, cidr, "-exist"])).is_ok() {
                count += 1;
            }
        }
        info!(cidrs = count, "Cloudflare CIDRs refreshed");
        count
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
                    let cidrs = parse_cloudflare_cidrs(&body);
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

fn run_cmd_args(cmd: &str, args: &[String]) -> Result<()> {
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    run_cmd(cmd, &borrowed)
}

fn command_args(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_string()).collect()
}

fn append_tcp_port_rule(commands: &mut Vec<Vec<String>>, port: u16, jump: &str) {
    commands.push(vec![
        "-A".into(),
        CHAIN_NAME.into(),
        "-p".into(),
        "tcp".into(),
        "--dport".into(),
        port.to_string(),
        "-j".into(),
        jump.into(),
    ]);
}

fn activation_iptables_args(locked_ports: &[u16], exempt_ports: &[u16]) -> Vec<Vec<String>> {
    let mut commands = vec![
        command_args(&["-F", CHAIN_NAME]),
        command_args(&[
            "-A",
            CHAIN_NAME,
            "-m",
            "state",
            "--state",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ]),
        command_args(&["-A", CHAIN_NAME, "-s", "127.0.0.0/8", "-j", "ACCEPT"]),
        command_args(&["-A", CHAIN_NAME, "-s", "169.254.169.254/32", "-j", "ACCEPT"]),
    ];

    for port in exempt_ports {
        append_tcp_port_rule(&mut commands, *port, "ACCEPT");
    }

    for port in locked_ports {
        commands.push(vec![
            "-A".into(),
            CHAIN_NAME.into(),
            "-p".into(),
            "tcp".into(),
            "--dport".into(),
            port.to_string(),
            "-m".into(),
            "set".into(),
            "--match-set".into(),
            IPSET_NAME.into(),
            "src".into(),
            "-j".into(),
            "ACCEPT".into(),
        ]);
        append_tcp_port_rule(&mut commands, *port, "DROP");
    }

    commands
}

fn input_chain_delete_args() -> Vec<String> {
    command_args(&["-D", "INPUT", "-j", CHAIN_NAME])
}

fn input_chain_insert_args() -> Vec<String> {
    command_args(&["-I", "INPUT", "1", "-j", CHAIN_NAME])
}

fn deactivation_iptables_args() -> Vec<Vec<String>> {
    vec![input_chain_delete_args(), command_args(&["-F", CHAIN_NAME])]
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_defaults() {
        // Initialization path: constructor should start inactive and protect
        // the standard HTTP/HTTPS/dashboard ports.
        let lock = OriginLockdown::new();
        assert!(!lock.active);
        assert!(lock.locked_ports.contains(&80));
        assert!(lock.locked_ports.contains(&443));
        assert!(lock.locked_ports.contains(&8787));
    }

    #[test]
    fn ssh_port_from_env_value_uses_valid_override_or_default() {
        assert_eq!(ssh_port_from_env_value(Some("2222")), 2222);
        assert_eq!(ssh_port_from_env_value(Some("not-a-port")), 49222);
        assert_eq!(ssh_port_from_env_value(None), 49222);
    }

    #[test]
    fn fallback_cidrs_count() {
        // Data path: embedded fallback list must contain enough CIDRs to keep
        // lockdown usable when remote fetch fails.
        assert!(CF_IPV4_FALLBACK.len() >= 14);
    }

    #[test]
    fn fallback_cidrs_are_valid() {
        // Validation path: fallback CIDRs should stay parseable as prefix
        // notation.
        for cidr in CF_IPV4_FALLBACK {
            assert!(cidr.contains('/'), "invalid CIDR: {cidr}");
            let parts: Vec<&str> = cidr.split('/').collect();
            assert_eq!(parts.len(), 2);
            let _prefix: u8 = parts[1].parse().expect("invalid prefix length");
        }
    }

    #[test]
    fn state_requires_lockdown_only_for_attack_states() {
        // State path: lockdown should be enabled only for attack states and
        // disabled for normal/elevated operation.
        assert!(state_requires_lockdown(
            crate::escalation::EscalationState::UnderAttack
        ));
        assert!(state_requires_lockdown(
            crate::escalation::EscalationState::Critical
        ));
        assert!(!state_requires_lockdown(
            crate::escalation::EscalationState::Normal
        ));
        assert!(!state_requires_lockdown(
            crate::escalation::EscalationState::Elevated
        ));
    }

    #[test]
    fn parse_cloudflare_cidrs_filters_noise_lines() {
        // Parser path: CIDR parser should drop blank and malformed rows while
        // preserving valid prefixes.
        let body = "173.245.48.0/20\n\n#comment\ninvalid\n104.16.0.0/13\n";
        let cidrs = parse_cloudflare_cidrs(body);
        assert_eq!(cidrs, vec!["173.245.48.0/20", "104.16.0.0/13"]);
    }

    #[test]
    fn parse_cloudflare_cidrs_accepts_whitespace_trim() {
        // Parser path: leading/trailing spaces from API responses should be
        // trimmed before CIDRs are inserted into ipset.
        let body = "  198.41.128.0/17  \n\t172.64.0.0/13\t\n";
        let cidrs = parse_cloudflare_cidrs(body);
        assert_eq!(cidrs, vec!["198.41.128.0/17", "172.64.0.0/13"]);
    }

    #[test]
    fn activation_iptables_args_builds_expected_guardrails_and_locked_ports() {
        let commands = activation_iptables_args(&[80], &[49222, 22]);

        assert_eq!(commands[0], command_args(&["-F", CHAIN_NAME]));
        assert!(commands.contains(&command_args(&[
            "-A",
            CHAIN_NAME,
            "-m",
            "state",
            "--state",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ])));
        assert!(commands.contains(&command_args(&[
            "-A",
            CHAIN_NAME,
            "-s",
            "127.0.0.0/8",
            "-j",
            "ACCEPT",
        ])));
        assert!(commands.contains(&command_args(&[
            "-A", CHAIN_NAME, "-p", "tcp", "--dport", "49222", "-j", "ACCEPT",
        ])));
        assert!(commands.contains(&command_args(&[
            "-A",
            CHAIN_NAME,
            "-p",
            "tcp",
            "--dport",
            "80",
            "-m",
            "set",
            "--match-set",
            IPSET_NAME,
            "src",
            "-j",
            "ACCEPT",
        ])));
        assert!(commands.contains(&command_args(&[
            "-A", CHAIN_NAME, "-p", "tcp", "--dport", "80", "-j", "DROP",
        ])));
    }

    #[test]
    fn input_chain_and_deactivation_args_are_idempotent_shape() {
        assert_eq!(
            input_chain_delete_args(),
            command_args(&["-D", "INPUT", "-j", CHAIN_NAME])
        );
        assert_eq!(
            input_chain_insert_args(),
            command_args(&["-I", "INPUT", "1", "-j", CHAIN_NAME])
        );
        assert_eq!(
            deactivation_iptables_args(),
            vec![
                command_args(&["-D", "INPUT", "-j", CHAIN_NAME]),
                command_args(&["-F", CHAIN_NAME]),
            ]
        );
    }

    #[test]
    fn activate_with_runner_records_commands_and_marks_active() {
        let mut lock = OriginLockdown::new();
        lock.locked_ports = vec![80];
        lock.exempt_ports = vec![22];
        let mut commands = Vec::new();

        lock.activate_with_runner(|args| {
            commands.push(args.to_vec());
            Ok(())
        })
        .expect("activation should succeed");

        assert!(lock.is_active());
        assert_eq!(commands.first(), Some(&command_args(&["-F", CHAIN_NAME])));
        assert!(commands.contains(&input_chain_delete_args()));
        assert_eq!(commands.last(), Some(&input_chain_insert_args()));
    }

    #[test]
    fn activate_with_runner_is_noop_when_already_active() {
        let mut lock = OriginLockdown::new();
        lock.active = true;
        let mut calls = 0;

        lock.activate_with_runner(|_| {
            calls += 1;
            Ok(())
        })
        .expect("already active should be ok");

        assert_eq!(calls, 0);
        assert!(lock.is_active());
    }

    #[test]
    fn activate_with_runner_propagates_failure_before_marking_active() {
        let mut lock = OriginLockdown::new();
        let err = lock.activate_with_runner(|_| anyhow::bail!("iptables denied"));

        assert!(err.is_err());
        assert!(!lock.is_active());
    }

    #[test]
    fn deactivate_with_runner_ignores_cleanup_errors_and_marks_inactive() {
        let mut lock = OriginLockdown::new();
        lock.active = true;
        let mut calls = 0;

        lock.deactivate_with_runner(|_| {
            calls += 1;
            anyhow::bail!("already absent")
        })
        .expect("cleanup errors should be ignored");

        assert_eq!(calls, 2);
        assert!(!lock.is_active());
    }

    #[test]
    fn refresh_cidrs_with_runner_counts_successful_adds_only() {
        let lock = OriginLockdown::new();
        let cidrs = vec!["173.245.48.0/20".to_string(), "104.16.0.0/13".to_string()];
        let mut commands = Vec::new();
        let mut add_calls = 0;

        let added = lock.refresh_cidrs_with_runner(&cidrs, |args| {
            commands.push(args.to_vec());
            if args.first().map(String::as_str) == Some("add") {
                add_calls += 1;
                if add_calls == 2 {
                    anyhow::bail!("duplicate")
                }
            }
            Ok(())
        });

        assert_eq!(added, 1);
        assert_eq!(commands[0], command_args(&["flush", IPSET_NAME]));
        assert_eq!(commands.len(), 3);
    }
}
