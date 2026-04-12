//! Cloud provider IP safelist — IPs that should NOT be auto-blocked.
//!
//! Major cloud providers (Google Cloud, AWS, Cloudflare, Azure, Oracle) publish
//! their IP ranges. Attackers can use these, but auto-blocking them risks
//! blocking legitimate traffic (Googlebot, CDN, APIs).
//!
//! Policy: DETECT but DON'T AUTO-BLOCK. Let AI evaluate with context.
//! The AI can still decide to block if the evidence is strong enough.

use std::net::IpAddr;
use std::sync::OnceLock;
use tracing::info;

/// Parsed CIDR range for fast matching.
struct CidrRange {
    base: u32,
    mask: u32,
}

impl CidrRange {
    fn from_str(cidr: &str) -> Option<Self> {
        let (base_str, prefix_str) = cidr.split_once('/')?;
        let prefix_len: u32 = prefix_str.parse().ok()?;
        if prefix_len > 32 {
            return None;
        }
        let base: IpAddr = base_str.parse().ok()?;
        let base_u32 = match base {
            IpAddr::V4(v4) => u32::from(v4),
            _ => return None,
        };
        let shift = 32u32.saturating_sub(prefix_len);
        let mask = if shift >= 32 { 0u32 } else { !0u32 << shift };
        Some(Self {
            base: base_u32 & mask,
            mask,
        })
    }

    fn contains(&self, ip: u32) -> bool {
        (ip & self.mask) == self.base
    }
}

/// Cloud provider safelist — loaded once, checked on every auto-block decision.
static CLOUD_RANGES: OnceLock<Vec<CidrRange>> = OnceLock::new();
static CLOUD_PROVIDER_COUNT: OnceLock<usize> = OnceLock::new();

/// Local interface IPs of the host the agent runs on (eth0, bond0, etc.).
/// Populated at startup via `init_local_interface_ips()`. Traffic with
/// src_ip == one of these is the host itself talking to the outside world,
/// which in incidents like "Packet flood from 10.0.0.238" is the server's
/// own VPC IP misclassified as an attacker.
static LOCAL_INTERFACE_IPS: OnceLock<Vec<u32>> = OnceLock::new();

/// Cloudflare IPv4 ranges (from https://www.cloudflare.com/ips-v4).
/// Updated 2026-04-01. These rarely change.
const CLOUDFLARE_RANGES: &[&str] = &[
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
];

/// Agent-owned service endpoints — IPs the agent itself talks to for its
/// notification, enrichment, and threat-intel pipelines. Traffic to these
/// destinations is *self-traffic* and MUST NOT fire data-exfil / C2-beacon
/// style detectors in the operator view. Added after spec 015 surfaced the
/// self-detection pattern (see the dashboard flood on 2026-04-11 where the
/// agent was flagging its own Telegram calls as "Data Exfil → CRITICAL").
const AGENT_SERVICE_RANGES: &[&str] = &[
    // Telegram (Bot API + MTProto) — AS62041
    "149.154.160.0/20",
    "91.108.0.0/16",
    "91.108.4.0/22",
    "91.108.56.0/22",
    "95.161.64.0/20",
    // CrowdSec CAPI (cloud threat intelligence API) — hosted on AWS
    // eu-west-1. The local CrowdSec agent (pid crowdsec, uid 0) polls
    // these IPs for community blocklists and pushes local decisions.
    // Observed 2026-04-12: 6 AWS eu-west-1 IPs appearing as
    // "Cross-layer chain: Cryptominer Deployment Chain" because the
    // correlation engine saw crowdsec outbound + CPU spike = CL-014 FP.
    // CrowdSec uses an ELB that rotates across the /16, so we safelist
    // the ranges that the eu-west-1 ELBs live in.
    "52.48.0.0/14",   // AWS eu-west-1 ELB range (covers 52.48-51.x)
    "63.32.0.0/14",   // AWS eu-west-1 ELB range (covers 63.32-35.x)
    "18.200.0.0/14",  // AWS eu-west-1 ELB range (covers 18.200-203.x)
    "3.248.0.0/13",   // AWS eu-west-1 ELB range (covers 3.248-255.x)
    // ip-api.com (GeoIP enrichment used by crate::geoip)
    "208.95.112.0/24",
    // Canonical / Ubuntu archive + snapcraft + livepatch
    "185.125.188.0/23",
    "91.189.88.0/21",
    "162.213.32.0/22",
];

/// Oracle Cloud peer ranges not already covered by CLOUD_PROVIDER_RANGES.
/// These are the infrastructure peers of OCI instances (metadata, NTP,
/// internal DNS, OKE control plane, etc.) that an OCI-hosted agent will
/// regularly connect to. Keeping them separate from the main cloud list
/// makes it obvious *why* they're in the safelist — they're the agent's
/// own home provider, not some random customer workload.
const ORACLE_PEER_RANGES: &[&str] = &[
    "138.1.16.0/22",    // OCI peer range
    "140.91.0.0/16",    // OCI London peers
    "147.154.224.0/19", // OCI peer /19 — covers gomon (147.154.245.65) + other OCI infra
    "193.122.0.0/15",   // OCI EU-London
];

/// Link-local and cloud instance metadata ranges. Every major cloud uses
/// 169.254.169.254 for instance metadata (IMDS); Oracle, AWS, GCP, Azure
/// all share the convention. 169.254.0.0/16 is the IPv4 link-local range
/// (RFC 3927). Traffic to any of these is self-infrastructure by definition
/// — the operator never cares about "exfil to 169.254.169.254" or
/// "slowloris on metadata endpoint". Observed 2026-04-11 as
/// "Slow HTTP connection (possible slowloris)" FP fired by agent host
/// polling the OCI metadata service.
const LINK_LOCAL_RANGES: &[&str] = &[
    "169.254.0.0/16",  // IPv4 link-local (RFC 3927), includes all IMDS endpoints
    "127.0.0.0/8",     // loopback — never operator-relevant as a remote dst
    "224.0.0.0/4",     // multicast
];

/// Major cloud provider CIDR ranges that should not be auto-blocked.
/// These are broad ranges — individual IPs may still be malicious,
/// but auto-blocking risks collateral damage.
const CLOUD_PROVIDER_RANGES: &[&str] = &[
    // Google Cloud Platform (major allocations)
    "34.0.0.0/9",      // 34.0-127.x — GCE
    "35.184.0.0/13",   // 35.184-191.x — GCE
    "35.192.0.0/12",   // 35.192-207.x — GCE
    "35.208.0.0/12",   // 35.208-223.x — GCE
    "35.224.0.0/12",   // 35.224-239.x — GCE
    "35.240.0.0/13",   // 35.240-247.x — GCE
    "130.211.0.0/16",  // GCE load balancers
    "142.250.0.0/15",  // Google services
    "172.217.0.0/16",  // Google services
    "216.58.192.0/19", // Google services
    "209.85.128.0/17", // Google mail/services
    // AWS (major allocations)
    "3.0.0.0/9",     // 3.0-127.x — EC2
    "13.0.0.0/8",    // 13.x — EC2 various
    "15.0.0.0/11",   // 15.0-31.x — EC2
    "18.0.0.0/10",   // 18.0-63.x — EC2
    "44.192.0.0/11", // 44.192-223.x — EC2
    "52.0.0.0/11",   // 52.0-31.x — EC2
    "54.0.0.0/8",    // 54.x — EC2
    "99.80.0.0/12",  // 99.80-95.x — EC2
    // Azure (major allocations)
    "20.0.0.0/11",    // 20.0-31.x — Azure
    "40.64.0.0/10",   // 40.64-127.x — Azure
    "52.128.0.0/10",  // 52.128-191.x — Azure
    "104.40.0.0/13",  // 104.40-47.x — Azure
    "168.61.0.0/16",  // Azure
    "191.232.0.0/13", // Azure
    // Oracle Cloud
    "129.146.0.0/16", // OCI
    "130.35.0.0/16",  // OCI
    "130.61.0.0/16",  // OCI
    "132.145.0.0/16", // OCI
    "134.70.0.0/16",  // OCI
    "140.204.0.0/16", // OCI
    "140.238.0.0/16", // OCI
    "144.24.0.0/14",  // OCI
    "150.136.0.0/13", // OCI
    "152.67.0.0/16",  // OCI
    "152.70.0.0/15",  // OCI
    // DigitalOcean
    "64.227.0.0/16",
    "134.209.0.0/16",
    "157.230.0.0/16",
    "159.65.0.0/16",
    "159.89.0.0/16",
    "161.35.0.0/16",
    "164.90.0.0/16",
    "165.22.0.0/16",
    "165.227.0.0/16",
    "167.71.0.0/16",
    "167.172.0.0/16",
    "174.138.0.0/16",
    "178.128.0.0/16",
    "188.166.0.0/16",
    "206.189.0.0/16",
    "209.97.0.0/16",
    "209.122.0.0/16",
    // Hetzner
    "49.12.0.0/14",
    "78.46.0.0/15",
    "88.198.0.0/16",
    "88.99.0.0/16",
    "95.216.0.0/15",
    "116.202.0.0/15",
    "116.203.0.0/16",
    "128.140.0.0/16",
    "135.181.0.0/16",
    "136.243.0.0/16",
    "138.201.0.0/16",
    "142.132.0.0/16",
    "148.251.0.0/16",
    "157.90.0.0/16",
    "159.69.0.0/16",
    "162.55.0.0/16",
    "167.235.0.0/16",
    "168.119.0.0/16",
    "176.9.0.0/16",
    "178.63.0.0/16",
    "195.201.0.0/16",
    "213.133.96.0/19",
    "213.239.192.0/18",
];

/// Initialize the cloud safelist. Call once at agent startup.
pub fn init() {
    let mut ranges = Vec::new();

    for cidr in CLOUDFLARE_RANGES
        .iter()
        .chain(CLOUD_PROVIDER_RANGES.iter())
        .chain(AGENT_SERVICE_RANGES.iter())
        .chain(ORACLE_PEER_RANGES.iter())
        .chain(LINK_LOCAL_RANGES.iter())
    {
        if let Some(r) = CidrRange::from_str(cidr) {
            ranges.push(r);
        }
    }

    let count = ranges.len();
    let _ = CLOUD_RANGES.set(ranges);
    let _ = CLOUD_PROVIDER_COUNT.set(count);
    info!(ranges = count, "Cloud provider safelist loaded");

    // Best-effort: read the host's own IPv4 interface addresses so
    // incidents with src/dst == own IP can be recognized as self-traffic.
    // Falls back to an empty list if /proc/net/fib_trie is unreadable;
    // that just means the own-IP detection is a no-op, not a crash.
    init_local_interface_ips();
}

/// Populate `LOCAL_INTERFACE_IPS` from `/proc/net/fib_trie`. This file
/// exposes every locally-bound IPv4 address (loopback, eth0, docker0, etc.)
/// as `|-- <ip>` lines followed by `/32 host LOCAL`. Parsing is deliberately
/// forgiving — any unexpected format just yields an empty list.
fn init_local_interface_ips() {
    let content = match std::fs::read_to_string("/proc/net/fib_trie") {
        Ok(c) => c,
        Err(_) => {
            let _ = LOCAL_INTERFACE_IPS.set(Vec::new());
            return;
        }
    };

    let mut ips: Vec<u32> = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        // Each local address appears as "|-- <ip>" with the next non-empty
        // line containing "/32 host LOCAL". We accept any line whose next
        // line mentions "host LOCAL" — the routing table can tag as
        // "host BROADCAST" or "host LINK" too, which we ignore.
        if let Some(rest) = trimmed.strip_prefix("|-- ") {
            if let Some(next) = lines.get(i + 1) {
                if next.contains("host LOCAL") {
                    if let Ok(std::net::IpAddr::V4(v4)) = rest.trim().parse::<IpAddr>() {
                        ips.push(u32::from(v4));
                    }
                }
            }
        }
    }

    ips.sort_unstable();
    ips.dedup();
    let n = ips.len();
    let _ = LOCAL_INTERFACE_IPS.set(ips);
    info!(
        local_ips = n,
        "Local interface IPs loaded for self-traffic detection"
    );
}

/// Returns true if the IP should be treated as *self-traffic* — either a
/// known cloud provider, the agent's own notification / enrichment
/// endpoints (Telegram, GeoIP), the OCI peer ranges of the host the
/// agent runs on, link-local / metadata IPs, OR one of the host's own
/// IPv4 interface addresses.
///
/// Callers that generate operator-facing incidents should use this to
/// flag the incident as `research_only` instead of surfacing it in the
/// threats feed.
pub fn is_self_traffic_ip(ip_str: &str) -> bool {
    is_cloud_provider_ip(ip_str) || is_local_interface_ip(ip_str)
}

/// Returns true if `ip_str` is one of the host's own locally-bound IPv4
/// addresses (populated at startup from `/proc/net/fib_trie`). This
/// catches the case where a sensor detector emits an incident whose
/// only IP entity is the server's own VPC/eth0 address — observed
/// 2026-04-11 as "Packet flood → 10.0.0.238" and "Slow HTTP from
/// 10.0.0.238 → 169.254.169.254" FPs. Returns false if the local-IP
/// list could not be loaded (best-effort).
pub fn is_local_interface_ip(ip_str: &str) -> bool {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    let ip_u32 = match ip {
        IpAddr::V4(v4) => u32::from(v4),
        _ => return false,
    };
    match LOCAL_INTERFACE_IPS.get() {
        Some(list) => list.binary_search(&ip_u32).is_ok(),
        None => false,
    }
}

/// Returns true if `comm` is the agent itself or one of its spawned
/// workers. Matches the graph detector convention (`detect_network_sniffing`)
/// used in spec 015.
#[allow(dead_code)] // reserved for future process-side self-filter unification
pub fn is_agent_process(comm: &str) -> bool {
    matches!(
        comm,
        "innerwarden-agent"
            | "innerwarden-sensor"
            | "innerwarden-watchdog"
            | "tokio-rt-worker"
            | "openclaw-gatewa"
            | "crowdsec"
            | "gomon"
    )
}

/// Check if an IP belongs to a known cloud provider.
/// Returns true if the IP should NOT be auto-blocked.
pub fn is_cloud_provider_ip(ip_str: &str) -> bool {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    let ip_u32 = match ip {
        IpAddr::V4(v4) => u32::from(v4),
        _ => return false,
    };

    if let Some(ranges) = CLOUD_RANGES.get() {
        ranges.iter().any(|r| r.contains(ip_u32))
    } else {
        false
    }
}

/// Get the provider name for logging (best-effort, broad match).
pub fn identify_provider(ip_str: &str) -> Option<&'static str> {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return None;
    };
    let first_octet = match ip {
        IpAddr::V4(v4) => v4.octets()[0],
        _ => return None,
    };

    // Broad heuristic based on first octet
    match first_octet {
        34 | 35 | 130 | 142 | 172 | 216 | 209 => Some("Google Cloud"),
        3 | 13 | 15 | 18 | 44 | 52 | 54 | 99 => Some("AWS"),
        20 | 40 | 104 | 168 | 191 => Some("Azure"),
        129 | 132 | 134 | 140 | 144 | 150 | 152 => Some("Oracle Cloud"),
        64 | 157 | 159 | 161 | 164 | 165 | 167 | 174 | 178 | 188 | 206 => Some("DigitalOcean"),
        173 | 108 | 190 | 162 | 141 | 197 | 198 => Some("Cloudflare"),
        49 | 78 | 88 | 95 | 116 | 128 | 135 | 136 | 138 | 148 | 176 | 195 | 213 => Some("Hetzner"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_detected() {
        init();
        assert!(is_cloud_provider_ip("104.16.0.1"));
        assert!(is_cloud_provider_ip("172.64.1.1"));
        assert!(is_cloud_provider_ip("104.23.217.2"));
    }

    #[test]
    fn google_detected() {
        init();
        assert!(is_cloud_provider_ip("34.95.197.36"));
        assert!(is_cloud_provider_ip("35.200.190.223"));
        assert!(is_cloud_provider_ip("142.250.1.1"));
    }

    #[test]
    fn aws_detected() {
        init();
        assert!(is_cloud_provider_ip("3.5.1.1"));
        assert!(is_cloud_provider_ip("52.1.1.1"));
        assert!(is_cloud_provider_ip("54.200.1.1"));
    }

    #[test]
    fn random_ip_not_cloud() {
        init();
        assert!(!is_cloud_provider_ip("93.152.217.51")); // real attacker
        assert!(!is_cloud_provider_ip("1.2.3.4"));
        assert!(!is_cloud_provider_ip("185.143.223.100"));
    }

    #[test]
    fn provider_identified() {
        assert_eq!(identify_provider("34.95.197.36"), Some("Google Cloud"));
        assert_eq!(identify_provider("52.1.1.1"), Some("AWS"));
        assert_eq!(identify_provider("20.12.41.6"), Some("Azure"));
    }

    #[test]
    fn telegram_detected() {
        // Spec 015 follow-up: Telegram Bot API must be recognized as
        // self-traffic. Without this, 222+ false positives per day from
        // the agent's own notification channel (149.154.166.110:443).
        init();
        assert!(is_self_traffic_ip("149.154.160.1"));
        assert!(is_self_traffic_ip("149.154.166.110"));
        assert!(is_self_traffic_ip("149.154.175.255"));
        assert!(is_self_traffic_ip("91.108.4.200"));
    }

    #[test]
    fn ip_api_com_detected() {
        // GeoIP enrichment endpoint used by crate::geoip.
        init();
        assert!(is_self_traffic_ip("208.95.112.1"));
    }

    #[test]
    fn canonical_detected() {
        // Ubuntu apt archive + snapcraft + livepatch.
        init();
        assert!(is_self_traffic_ip("185.125.188.58"));
        assert!(is_self_traffic_ip("91.189.88.1"));
    }

    #[test]
    fn oracle_peer_range_detected() {
        // OCI London peer ranges outside the main CLOUD_PROVIDER_RANGES
        // list. These are the /20 the server peers with on its internal
        // network, not random Oracle customer IPs.
        init();
        assert!(is_self_traffic_ip("147.154.225.94"));
        assert!(is_self_traffic_ip("138.1.16.172"));
        assert!(is_self_traffic_ip("140.91.26.100"));
    }

    #[test]
    fn real_attacker_still_detected() {
        // Safety net: random external IPs that are NOT cloud providers or
        // agent services must still be reported to the operator.
        init();
        assert!(!is_self_traffic_ip("147.185.132.13")); // dashboard shows this as an attacker
        assert!(!is_self_traffic_ip("198.235.24.154"));
        assert!(!is_self_traffic_ip("185.113.139.51"));
    }

    #[test]
    fn agent_process_recognition() {
        assert!(is_agent_process("innerwarden-agent"));
        assert!(is_agent_process("innerwarden-sensor"));
        assert!(is_agent_process("tokio-rt-worker"));
        assert!(is_agent_process("openclaw-gatewa"));
        assert!(!is_agent_process("sshd"));
        assert!(!is_agent_process("bash"));
    }
}
