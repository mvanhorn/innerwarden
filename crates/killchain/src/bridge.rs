//! Chain-to-IP bridge — extracts C2 IP from PID chain state.
//!
//! Provides utilities to extract command-and-control IP information from
//! accumulated PID chain state, filtering out private/reserved addresses
//! so that only actionable public C2 IPs surface in incidents.

use crate::patterns::CHAIN_SOCKET;
use crate::types::PidChainState;

/// Returns `(ip, port)` if the PID has the CHAIN_SOCKET flag set,
/// a stored `last_connect_ip`, and the IP is publicly routable.
pub fn extract_c2(state: &PidChainState) -> Option<(String, u16)> {
    if state.flags & CHAIN_SOCKET == 0 {
        return None;
    }

    let ip = state.last_connect_ip.as_deref()?;
    let port = state.last_connect_port?;

    if is_private_ip(ip) {
        return None;
    }

    Some((ip.to_string(), port))
}

/// Returns `true` when `ip` falls into a reserved/non-routable range:
///
/// - `10.0.0.0/8`        (RFC 1918)
/// - `172.16.0.0/12`     (RFC 1918)
/// - `192.168.0.0/16`    (RFC 1918)
/// - `127.0.0.0/8`       (loopback)
/// - `169.254.0.0/16`    (link-local)
/// - `192.0.2.0/24`      (TEST-NET-1, documentation)
/// - `198.51.100.0/24`   (TEST-NET-2, documentation)
/// - `203.0.113.0/24`    (TEST-NET-3, documentation)
/// - `0.0.0.0`           (unspecified)
///
/// Non-parseable strings also return `true` (treat as non-routable).
pub fn is_private_ip(ip: &str) -> bool {
    let octets: Vec<u8> = match ip
        .split('.')
        .map(|s| s.parse::<u8>())
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) if v.len() == 4 => v,
        _ => return true, // unparseable -> treat as private / non-routable
    };

    let (a, b, c, _d) = (octets[0], octets[1], octets[2], octets[3]);

    match a {
        // 0.0.0.0 — unspecified
        0 => true,
        // 10.0.0.0/8
        10 => true,
        // 127.0.0.0/8 — loopback
        127 => true,
        // 169.254.0.0/16 — link-local
        169 if b == 254 => true,
        // 172.16.0.0/12
        172 if (16..=31).contains(&b) => true,
        // 192.168.0.0/16
        192 if b == 168 => true,
        // 192.0.2.0/24 — TEST-NET-1
        192 if b == 0 && c == 2 => true,
        // 198.51.100.0/24 — TEST-NET-2
        198 if b == 51 && c == 100 => true,
        // 203.0.113.0/24 — TEST-NET-3
        203 if b == 0 && c == 113 => true,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PidChainState;
    use chrono::Utc;

    fn make_state(flags: u32, ip: Option<&str>, port: Option<u16>) -> PidChainState {
        let mut state =
            PidChainState::new(1000, 1000, "test".into(), "testhost".into(), Utc::now());
        state.flags = flags;
        state.last_connect_ip = ip.map(|s| s.to_string());
        state.last_connect_port = port;
        state
    }

    #[test]
    fn public_ip_extracted_correctly() {
        let state = make_state(CHAIN_SOCKET, Some("185.234.1.1"), Some(4444));
        let result = extract_c2(&state);
        assert_eq!(result, Some(("185.234.1.1".to_string(), 4444)));
    }

    #[test]
    fn private_10_filtered() {
        let state = make_state(CHAIN_SOCKET, Some("10.0.0.1"), Some(80));
        assert_eq!(extract_c2(&state), None);
    }

    #[test]
    fn private_172_filtered() {
        for second in 16..=31u8 {
            let ip = format!("172.{}.0.1", second);
            let state = make_state(CHAIN_SOCKET, Some(&ip), Some(80));
            assert_eq!(extract_c2(&state), None, "should filter {}", ip);
        }
    }

    #[test]
    fn private_192_168_filtered() {
        let state = make_state(CHAIN_SOCKET, Some("192.168.1.1"), Some(22));
        assert_eq!(extract_c2(&state), None);
    }

    #[test]
    fn loopback_filtered() {
        let state = make_state(CHAIN_SOCKET, Some("127.0.0.1"), Some(8080));
        assert_eq!(extract_c2(&state), None);
    }

    #[test]
    fn link_local_filtered() {
        let state = make_state(CHAIN_SOCKET, Some("169.254.1.1"), Some(80));
        assert_eq!(extract_c2(&state), None);
    }

    #[test]
    fn documentation_ranges_filtered() {
        for ip in &["192.0.2.1", "198.51.100.1", "203.0.113.1"] {
            let state = make_state(CHAIN_SOCKET, Some(ip), Some(80));
            assert_eq!(extract_c2(&state), None, "should filter {}", ip);
        }
    }

    #[test]
    fn no_socket_flag_returns_none() {
        // Has IP and port but no CHAIN_SOCKET flag
        let state = make_state(0, Some("8.8.8.8"), Some(53));
        assert_eq!(extract_c2(&state), None);
    }

    #[test]
    fn no_connect_ip_returns_none() {
        let state = make_state(CHAIN_SOCKET, None, Some(4444));
        assert_eq!(extract_c2(&state), None);
    }

    #[test]
    fn no_connect_port_returns_none() {
        let state = make_state(CHAIN_SOCKET, Some("8.8.8.8"), None);
        assert_eq!(extract_c2(&state), None);
    }
}
