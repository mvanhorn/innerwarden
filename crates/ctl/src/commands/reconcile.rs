//! `innerwarden system reconcile-blocks` — cross-check the firewall's
//! active DENY rules against the cloud provider safelist and emit the
//! operator's cleanup plan.
//!
//! The motivating incident (operator audit 2026-04-19 after the
//! CL-008 cascade + cloud_safelist fix landed): 60 ufw DENY rules
//! targeting Cloudflare, Oracle OCI peers, link-local, and Telegram
//! ranges were still in place, all installed *before* the safelist
//! existed. New blocks respect the safelist; old ones rot until their
//! TTL expires (up to 7 days). This command surfaces those zombies.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::Cli;

/// Parsed ufw rule: the numeric position in `ufw status numbered`
/// output, plus the target IP or CIDR the rule blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UfwRule {
    pub index: u32,
    pub target: String,
}

pub(crate) fn cmd_reconcile_blocks(_cli: &Cli, _data_dir: &Path, apply: bool) -> Result<()> {
    let ufw_out = run_ufw_status()?;
    let rules = parse_ufw_rules(&ufw_out);

    let safelist = safelist_cidrs();
    let matches: Vec<(UfwRule, String)> = rules
        .iter()
        .filter_map(|r| {
            match_safelist(&r.target, &safelist).map(|hit| (r.clone(), hit.to_string()))
        })
        .collect();

    println!("Reconcile block-list against cloud safelist");
    println!("  ufw DENY rules scanned:        {}", rules.len());
    println!("  matches inside safelist range: {}", matches.len());
    if matches.is_empty() {
        println!("\nAll blocks are outside known cloud provider ranges. Nothing to do.");
        return Ok(());
    }

    println!();
    for (rule, hit) in &matches {
        println!(
            "  rule #{:>4}  {:<20}  inside {}",
            rule.index, rule.target, hit
        );
    }

    if !apply {
        println!("\n(dry run) pass --apply to unblock every rule listed above.");
        println!("Each target will be released via `innerwarden action unblock`,");
        println!("which keeps the agent's response tracking in sync with the firewall.");
        return Ok(());
    }

    println!("\nUnblocking {} rule(s)…", matches.len());
    let mut cleaned = 0usize;
    let mut failed = 0usize;
    for (rule, _) in &matches {
        match unblock_target(&rule.target) {
            Ok(()) => {
                cleaned += 1;
                println!("  unblocked {}", rule.target);
            }
            Err(e) => {
                failed += 1;
                eprintln!("  failed to unblock {}: {e}", rule.target);
            }
        }
    }
    println!("\ndone. cleaned {cleaned}, failed {failed}");
    Ok(())
}

fn run_ufw_status() -> Result<String> {
    let out = Command::new("sudo")
        .args(["ufw", "status", "numbered"])
        .output()
        .context("spawn `sudo ufw status numbered`")?;
    if !out.status.success() {
        anyhow::bail!(
            "ufw status exited with {}; is ufw installed and enabled?",
            out.status
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn unblock_target(target: &str) -> Result<()> {
    let status = Command::new("sudo")
        .args([
            "innerwarden",
            "action",
            "unblock",
            target,
            "--reason",
            "reconcile-blocks: target in cloud safelist",
        ])
        .status()
        .context("spawn `innerwarden action unblock`")?;
    if !status.success() {
        anyhow::bail!("unblock exited with {status}");
    }
    Ok(())
}

/// Parse `ufw status numbered` output into a list of DENY rules targeting
/// a single IP or CIDR. Lines that do not match the agent-authored format
/// (`[NN] Anywhere DENY IN <ip> # innerwarden`) are skipped so operator
/// rules with comments of their own are left alone.
pub(crate) fn parse_ufw_rules(ufw_output: &str) -> Vec<UfwRule> {
    let mut out = Vec::new();
    for line in ufw_output.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix('[') else {
            continue;
        };
        let Some((num_str, after_num)) = rest.split_once(']') else {
            continue;
        };
        let Ok(index) = num_str.trim().parse::<u32>() else {
            continue;
        };
        // We only want the agent-authored rules so the operator's own
        // manual rules stay untouched.
        if !line.contains("# innerwarden") {
            continue;
        }
        // Need "DENY IN" somewhere after the index.
        if !after_num.contains("DENY IN") {
            continue;
        }
        // Target is the token after "DENY IN".
        let Some(after_deny) = after_num.split("DENY IN").nth(1) else {
            continue;
        };
        let target = after_deny
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        if target.is_empty() {
            continue;
        }
        out.push(UfwRule { index, target });
    }
    out
}

/// Returns the CIDR that contains the target, or `None` when the target
/// lies outside every safelist range. Works for bare IPv4 addresses and
/// `addr/prefix` CIDR blocks.
pub(crate) fn match_safelist<'a>(
    target: &str,
    safelist: &'a [ipnet::IpNet],
) -> Option<&'a ipnet::IpNet> {
    // Allow either a plain IP ("1.2.3.4") or a CIDR ("10.0.0.0/8").
    let (ip, prefix_len): (IpAddr, u8) = if let Some((addr, prefix)) = target.split_once('/') {
        let ip: IpAddr = addr.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        (ip, prefix)
    } else {
        let ip: IpAddr = target.parse().ok()?;
        let host_prefix = if ip.is_ipv4() { 32 } else { 128 };
        (ip, host_prefix)
    };
    let net = ipnet::IpNet::new(ip, prefix_len).ok()?;
    safelist.iter().find(|range| range.contains(&net))
}

/// Hardcoded subset of `cloud_safelist.rs` covering the four categories
/// the operator unambiguously wants released: Cloudflare CDN, Oracle OCI
/// peer infra, link-local / loopback / multicast, and Telegram edge.
///
/// CLOUD_PROVIDER_RANGES (DigitalOcean / AWS / Azure customer VPS) is
/// intentionally omitted because those ranges host attacker-owned VPSes
/// as often as legitimate services; an operator who wants those released
/// can still do it per-IP with `innerwarden action unblock`.
fn safelist_cidrs() -> Vec<ipnet::IpNet> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for s in RECONCILE_RANGES {
        if seen.insert(*s) {
            if let Ok(net) = s.parse() {
                out.push(net);
            }
        }
    }
    out
}

/// CIDRs kept in sync with the matching constants in
/// `crates/agent/src/cloud_safelist.rs`. Covered sets:
///   - `CLOUDFLARE_RANGES`
///   - `AGENT_SERVICE_RANGES`
///   - `ORACLE_PEER_RANGES`
///   - `LINK_LOCAL_RANGES`
const RECONCILE_RANGES: &[&str] = &[
    // Cloudflare IPv4 ranges
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
    // Telegram edge (agent notification endpoint)
    "149.154.160.0/20",
    "91.108.0.0/16",
    "91.108.4.0/22",
    "91.108.56.0/22",
    "95.161.64.0/20",
    // AWS eu-west-1 ELB (CrowdSec CAPI + Anthropic API hosted here)
    "52.48.0.0/14",
    "63.32.0.0/14",
    "18.200.0.0/14",
    "3.248.0.0/13",
    // AbuseIPDB + Ubuntu + GeoIP (agent service endpoints)
    "208.95.112.0/24",
    "185.125.188.0/23",
    "91.189.88.0/21",
    "162.213.32.0/22",
    // Oracle OCI peer ranges
    "138.1.16.0/22",
    "140.91.0.0/16",
    "147.154.224.0/19",
    "193.122.0.0/15",
    // Link-local / loopback / multicast
    "169.254.0.0/16",
    "127.0.0.0/8",
    "224.0.0.0/4",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skips_header_lines() {
        let out = "Status: active\n\n     To                         Action      From\n     --                         ------      ----\n";
        assert!(parse_ufw_rules(out).is_empty());
    }

    #[test]
    fn parse_reads_single_ip_agent_rule() {
        let out = "[ 42] Anywhere                   DENY IN     1.2.3.4                    # innerwarden\n";
        let rules = parse_ufw_rules(out);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].index, 42);
        assert_eq!(rules[0].target, "1.2.3.4");
    }

    #[test]
    fn parse_reads_cidr_agent_rule() {
        let out = "[100] Anywhere                   DENY IN     136.216.0.0/16             # innerwarden\n";
        let rules = parse_ufw_rules(out);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].target, "136.216.0.0/16");
    }

    #[test]
    fn parse_ignores_operator_owned_rules() {
        // Rules without the `# innerwarden` marker belong to the operator
        // or to other tools; leave them alone.
        let out = "[  1] 80/tcp                     DENY IN     Anywhere                   # block npm admin\n";
        assert!(parse_ufw_rules(out).is_empty());
    }

    #[test]
    fn parse_ignores_allow_rules() {
        let out = "[  5] Anywhere                   ALLOW IN    10.0.0.5                   # innerwarden\n";
        assert!(parse_ufw_rules(out).is_empty());
    }

    #[test]
    fn parse_reads_multiple_rules_in_order() {
        let out = "\
[  7] Anywhere                   DENY IN     1.2.3.4                    # innerwarden
[  8] Anywhere                   DENY IN     5.6.7.8                    # innerwarden
";
        let rules = parse_ufw_rules(out);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].index, 7);
        assert_eq!(rules[1].index, 8);
    }

    #[test]
    fn safelist_ip_inside_cloudflare_range_matches() {
        let list = safelist_cidrs();
        assert!(match_safelist("104.16.198.238", &list).is_some());
        assert!(match_safelist("172.64.200.173", &list).is_some());
    }

    #[test]
    fn safelist_ip_outside_ranges_does_not_match() {
        let list = safelist_cidrs();
        assert!(match_safelist("1.2.3.4", &list).is_none());
        // 8.8.8.8 (Google DNS) is not in the conservative cleanup set;
        // GCE customer ranges deliberately excluded.
        assert!(match_safelist("8.8.8.8", &list).is_none());
    }

    #[test]
    fn safelist_matches_cidr_target_when_fully_contained() {
        let list = safelist_cidrs();
        // 104.16.0.0/16 fits inside 104.16.0.0/13.
        assert!(match_safelist("104.16.0.0/16", &list).is_some());
    }

    #[test]
    fn safelist_rejects_cidr_target_wider_than_any_range() {
        let list = safelist_cidrs();
        // 104.0.0.0/8 is wider than any safelist range and must not match,
        // otherwise a wildly over-broad operator rule would be released.
        assert!(match_safelist("104.0.0.0/8", &list).is_none());
    }

    #[test]
    fn safelist_matches_loopback_and_multicast() {
        let list = safelist_cidrs();
        assert!(match_safelist("127.0.0.1", &list).is_some());
        assert!(match_safelist("169.254.169.254", &list).is_some());
        assert!(match_safelist("226.20.72.184", &list).is_some());
    }

    #[test]
    fn safelist_matches_oracle_peer_ranges() {
        let list = safelist_cidrs();
        assert!(match_safelist("147.154.245.65", &list).is_some());
        assert!(match_safelist("140.91.26.100", &list).is_some());
        assert!(match_safelist("138.1.16.172", &list).is_some());
    }

    #[test]
    fn invalid_target_string_is_not_matched() {
        let list = safelist_cidrs();
        assert!(match_safelist("", &list).is_none());
        assert!(match_safelist("not-an-ip", &list).is_none());
        assert!(match_safelist("1.2.3.4/abc", &list).is_none());
    }
}
