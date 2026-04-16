//! Shared target validator for firewall skills (ufw/iptables/nftables/pf).
//!
//! Each firewall skill must reject malformed strings before invoking the
//! corresponding CLI, otherwise ufw/iptables/nftables returns
//! `ERROR: Bad source address` on add — often after partially accepting the
//! rule — and the response lifecycle ends up with a zombie "Active" entry
//! that can never be reverted. That is the root cause of the
//! orphaned-response dashboard alert.

/// Returns true if `s` is a single IPv4/IPv6 address, or a valid CIDR
/// (`<ip>/<prefix>`) that `ufw`, `iptables -s`, `nftables ip saddr`, and
/// `pfctl` all accept.
///
/// Rejects: empty strings, octet-out-of-range ("129.950.5.0"), short IPv4
/// forms ("137.274.6"), garbage ("not-an-ip"), CIDR with invalid IP part,
/// CIDR with prefix out of range, CIDR with non-numeric prefix.
pub(super) fn is_valid_firewall_target(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    match s.split_once('/') {
        Some((ip_part, prefix_part)) => match (
            ip_part.parse::<std::net::IpAddr>(),
            prefix_part.parse::<u8>(),
        ) {
            (Ok(std::net::IpAddr::V4(_)), Ok(p)) => p <= 32,
            (Ok(std::net::IpAddr::V6(_)), Ok(p)) => p <= 128,
            _ => false,
        },
        None => s.parse::<std::net::IpAddr>().is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_ipv4_ipv6() {
        assert!(is_valid_firewall_target("1.2.3.4"));
        assert!(is_valid_firewall_target("255.255.255.255"));
        assert!(is_valid_firewall_target("0.0.0.0"));
        assert!(is_valid_firewall_target("::1"));
        assert!(is_valid_firewall_target("2001:db8::1"));
    }

    #[test]
    fn accepts_valid_cidrs() {
        assert!(is_valid_firewall_target("10.0.0.0/8"));
        assert!(is_valid_firewall_target("192.168.0.0/16"));
        assert!(is_valid_firewall_target("136.216.0.0/16"));
        assert!(is_valid_firewall_target("192.168.1.1/32"));
        assert!(is_valid_firewall_target("::/0"));
        assert!(is_valid_firewall_target("2001:db8::/32"));
        assert!(is_valid_firewall_target("fe80::/10"));
    }

    #[test]
    fn rejects_empty_and_garbage() {
        assert!(!is_valid_firewall_target(""));
        assert!(!is_valid_firewall_target(" "));
        assert!(!is_valid_firewall_target("not-an-ip"));
        assert!(!is_valid_firewall_target("/"));
        assert!(!is_valid_firewall_target("/16"));
    }

    #[test]
    fn rejects_out_of_range_octets() {
        // Exact samples from the production incident.
        for bad in [
            "129.950.5.0",
            "129.525.8.0",
            "130.890.9.0",
            "130.932.0.0",
            "130.806.3.0",
            "130.806.1.17",
            "129.491.8.0",
            "129.952.2.0",
            "129.950.5.15",
            "129.950.5.5",
        ] {
            assert!(
                !is_valid_firewall_target(bad),
                "'{bad}' must be rejected"
            );
        }
    }

    #[test]
    fn rejects_malformed_ipv4() {
        assert!(!is_valid_firewall_target("137.274.6")); // 3 octets
        assert!(!is_valid_firewall_target("1.2.3"));
        assert!(!is_valid_firewall_target("1.2.3.4.5"));
    }

    #[test]
    fn rejects_invalid_cidr() {
        assert!(!is_valid_firewall_target("129.950.5.0/24"));
        assert!(!is_valid_firewall_target("10.0.0.0/33"));
        assert!(!is_valid_firewall_target("2001:db8::/129"));
        assert!(!is_valid_firewall_target("10.0.0.0/"));
        assert!(!is_valid_firewall_target("10.0.0.0/-1"));
        assert!(!is_valid_firewall_target("10.0.0.0/abc"));
    }
}
