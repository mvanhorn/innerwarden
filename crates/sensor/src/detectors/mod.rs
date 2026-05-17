#[allow(dead_code)]
pub mod allowlists;
pub mod c2_callback;
pub mod container_escape;
pub mod credential_stuffing;
pub mod crypto_miner;
pub mod distributed_ssh;
pub mod exec_context;
pub mod suspicious_login;

/// IPs that should be treated as external even though they're technically private.
/// Set once at startup from the dynamic allowlist's [test_external_ips] section.
static TEST_EXTERNAL_IPS: std::sync::OnceLock<std::collections::HashSet<String>> =
    std::sync::OnceLock::new();

/// Initialize test external IPs from the dynamic allowlist.
/// Call once at startup after loading the allowlist.
pub fn init_test_external_ips(ips: std::collections::HashSet<String>) {
    let _ = TEST_EXTERNAL_IPS.set(ips);
}

// ---------------------------------------------------------------------------
// Host self-awareness: own IPs and listening ports
// ---------------------------------------------------------------------------

/// The host's own IP addresses (all local interfaces).
/// Set once at startup from /proc/net/fib_trie.
static OWN_IPS: std::sync::OnceLock<std::collections::HashSet<String>> = std::sync::OnceLock::new();

/// Ports the host is actively listening on.
/// Set once at startup from /proc/net/tcp + tcp6.
static OWN_LISTENING_PORTS: std::sync::OnceLock<std::collections::HashSet<u16>> =
    std::sync::OnceLock::new();

/// Initialize the host's own IPs from /proc/net/fib_trie.
/// Call once at sensor startup.
pub fn init_host_inventory() {
    let ips = discover_own_ips();
    let ports = discover_listening_ports();
    if !ips.is_empty() {
        tracing::info!(
            own_ips = ips.len(),
            listening_ports = ports.len(),
            "host inventory: self-awareness initialized"
        );
    }
    let _ = OWN_IPS.set(ips);
    let _ = OWN_LISTENING_PORTS.set(ports);
}

/// Check if an IP belongs to this host (any local interface).
pub fn is_own_ip(ip: &str) -> bool {
    OWN_IPS.get().is_some_and(|set| set.contains(ip))
}

/// Check if a port is being listened on by this host.
#[allow(dead_code)]
pub fn is_own_listening_port(port: u16) -> bool {
    OWN_LISTENING_PORTS
        .get()
        .is_some_and(|set| set.contains(&port))
}

/// Discover the host's own IPv4 addresses from /proc/net/fib_trie.
/// Same logic as agent's cloud_safelist::init_local_interface_ips.
fn discover_own_ips() -> std::collections::HashSet<String> {
    let Ok(content) = std::fs::read_to_string("/proc/net/fib_trie") else {
        // Not Linux or /proc not available (macOS, containers without /proc)
        return std::collections::HashSet::new();
    };

    parse_own_ips(&content)
}

fn parse_own_ips(content: &str) -> std::collections::HashSet<String> {
    let mut ips = std::collections::HashSet::new();
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        // Pattern: "|-- X.X.X.X" followed by "/32 host LOCAL"
        if let Some(ip_str) = trimmed.strip_prefix("|-- ") {
            if i + 1 < lines.len() {
                let next = lines[i + 1].trim();
                if next.contains("/32 host LOCAL") {
                    // Skip loopback and link-local — those are already handled by is_internal_ip
                    if !ip_str.starts_with("127.") && !ip_str.starts_with("169.254.") {
                        ips.insert(ip_str.to_string());
                    }
                }
            }
        }
    }

    ips
}

/// Discover listening TCP ports from /proc/net/tcp and /proc/net/tcp6.
fn discover_listening_ports() -> std::collections::HashSet<u16> {
    let mut ports = std::collections::HashSet::new();

    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        ports.extend(parse_listening_ports(&content));
    }

    ports
}

fn parse_listening_ports(content: &str) -> std::collections::HashSet<u16> {
    let mut ports = std::collections::HashSet::new();

    for line in content.lines().skip(1) {
        // Format: "  sl  local_address rem_address   st ..."
        // local_address = hex_ip:hex_port
        // st = 0A means LISTEN
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let st = parts[3];
        if st != "0A" {
            continue; // Not LISTEN state
        }
        // Parse port from local_address (second field, after colon)
        if let Some(port_hex) = parts[1].split(':').nth(1) {
            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                if port > 0 {
                    ports.insert(port);
                }
            }
        }
    }

    ports
}

/// Returns true if the IP is private, loopback, link-local, or documentation range.
/// Respects [test_external_ips] overrides from the dynamic allowlist.
pub fn is_internal_ip(ip: &str) -> bool {
    // Check test_external override first
    if let Some(test_ips) = TEST_EXTERNAL_IPS.get() {
        if test_ips.contains(ip) {
            return false; // Treat as external for testing
        }
    }

    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    match addr {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}
/// Verify that a process name matches a known infrastructure binary path.
/// Prevents evasion by renaming a malicious binary to "crowdsec" etc.
/// Returns true only if the comm matches AND /proc/PID/exe points to a
/// legitimate system path (not /tmp, /dev/shm, or user home dirs).
pub fn is_verified_infra_process(comm: &str, pid: u32, allowed_comms: &[&str]) -> bool {
    if !allowed_comms.iter().any(|c| comm.starts_with(c)) {
        return false;
    }
    // Verify binary path via /proc — catches name spoofing
    let exe_path = format!("/proc/{pid}/exe");
    match std::fs::read_link(&exe_path) {
        Ok(path) => {
            let p = path.to_string_lossy();
            // Legitimate paths: /usr/bin, /usr/sbin, /usr/local/bin, /snap, /opt
            // NOT: /tmp, /dev/shm, /var/tmp, /home (attacker-writable)
            p.starts_with("/usr/")
                || p.starts_with("/snap/")
                || p.starts_with("/opt/")
                || p.starts_with("/sbin/")
                || p.starts_with("/bin/")
        }
        Err(_) => {
            // Process might have exited — allow if comm matches
            // (better to have a brief FN gap than block infra permanently)
            true
        }
    }
}

pub mod dns_tunneling;
pub mod docker_anomaly;
pub mod execution_guard;
pub mod fileless;
pub mod integrity_alert;
pub mod lateral_movement;
pub mod log_tampering;
pub mod port_scan;
pub mod privesc;
pub mod process_tree;
pub mod search_abuse;
pub mod ssh_bruteforce;
pub mod sudo_abuse;
pub mod user_agent_scanner;
pub mod web_scan;

// v0.5.0 detectors
pub mod credential_harvest;
pub mod crontab_persistence;
pub mod data_exfiltration;
pub mod kernel_module_load;
pub mod outbound_anomaly;
pub mod process_injection;
pub mod ransomware;
pub mod reverse_shell;
pub mod rootkit;
pub mod ssh_key_injection;
pub mod systemd_persistence;
pub mod user_creation;
pub mod web_shell;

pub mod discovery_burst;
pub mod sensitive_write;

// v0.6.0 detectors
pub mod cgroup_abuse;
pub mod container_drift;
pub mod data_exfil_ebpf;
pub mod host_drift;
pub mod io_uring_anomaly;
pub mod mitre_hunt;
pub mod packet_flood;
pub mod sigma_rule;
#[allow(dead_code)]
pub mod stego_detect;
pub mod yara_scan;

// v0.10.1 detectors — MITRE gap closers
pub mod data_encoding;
pub mod datasets;
pub mod dns_c2;
pub mod proto_anomaly;
pub mod sandbox_evasion;
pub mod threat_intel;

// spec 050-PR1 — Reconnaissance
pub mod discovery_anomaly;
pub mod nmap_scan;
pub mod wordlist_scan;

// spec 050-PR2 — Collection
pub mod archive_pwd_protected;
pub mod automated_file_collection;
pub mod clipboard_read;
pub mod keylogger_bash_trap;
pub mod screen_capture;

// spec 050-PR3 — C2 variants
pub mod c2_non_standard_port;
pub mod c2_protocol_tunneling;
pub mod c2_web_tunnel;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_own_ips_keeps_local_host_entries_and_filters_special_ranges() {
        let content = "\
           |-- 10.0.0.15
              /32 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
           |-- 169.254.12.7
              /32 host LOCAL
           |-- 192.168.1.20
              /32 host LOCAL
           |-- 8.8.8.8
              /32 host REMOTE
";

        let ips = parse_own_ips(content);
        assert!(ips.contains("10.0.0.15"));
        assert!(ips.contains("192.168.1.20"));
        assert!(!ips.contains("127.0.0.1"));
        assert!(!ips.contains("169.254.12.7"));
        assert!(!ips.contains("8.8.8.8"));
    }

    #[test]
    fn parse_listening_ports_keeps_only_listen_rows_with_nonzero_ports() {
        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:22B8 00000000:0000 0A 00000000:00000000 00:00000000 00000000   100        0 1 1 0000000000000000 100 0 0 10 0
   1: 00000000:0000 00000000:0000 0A 00000000:00000000 00:00000000 00000000   100        0 1 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1F90 00000000:0000 01 00000000:00000000 00:00000000 00000000   100        0 1 1 0000000000000000 100 0 0 10 0
";

        let ports = parse_listening_ports(content);
        assert_eq!(ports.len(), 1);
        assert!(ports.contains(&8888));
    }

    #[test]
    fn internal_ip_classification_covers_ipv4_ipv6_and_invalid_input() {
        assert!(is_internal_ip("10.0.0.1"));
        assert!(is_internal_ip("127.0.0.1"));
        assert!(is_internal_ip("::1"));
        assert!(is_internal_ip("::"));
        assert!(!is_internal_ip("8.8.8.8"));
        assert!(!is_internal_ip("not-an-ip"));
    }

    #[test]
    fn verified_infra_process_rejects_unexpected_comm_names() {
        assert!(!is_verified_infra_process(
            "definitely-not-nginx",
            999_999,
            &["nginx", "sshd"],
        ));
    }

    #[test]
    fn verified_infra_process_allows_matching_comm_when_process_already_exited() {
        assert!(is_verified_infra_process(
            "nginx-worker",
            999_999,
            &["nginx", "sshd"],
        ));
    }
}
