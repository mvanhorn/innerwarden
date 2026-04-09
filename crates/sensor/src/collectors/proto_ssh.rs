//! SSH protocol parser for reassembled TCP streams.
//!
//! Extracts: version strings, auth methods, tunneling indicators.
//! Works on any port (not just 22).

/// Parsed SSH session info.
#[derive(Debug, Clone)]
pub struct SshSession {
    pub client_version: String,
    pub server_version: String,
    pub has_tunnel_request: bool,
    pub signals: Vec<String>,
}

/// Parse SSH version exchange from client and server streams.
pub fn parse_session(client_data: &[u8], server_data: &[u8]) -> Option<SshSession> {
    let client_version = extract_version(client_data)?;
    let server_version = extract_version(server_data).unwrap_or_default();

    let mut signals = Vec::new();

    // Known malicious SSH clients
    let cv_lower = client_version.to_lowercase();
    if cv_lower.contains("paramiko") {
        signals.push("python_ssh_lib".into());
    }
    if cv_lower.contains("libssh") && !cv_lower.contains("openssh") {
        signals.push("libssh_client".into());
    }
    if cv_lower.contains("putty") && !cv_lower.contains("openssh") {
        signals.push("putty_client".into());
    }
    if cv_lower.contains("go") || cv_lower.contains("golang") {
        signals.push("go_ssh_client".into());
    }
    if cv_lower.contains("ncrack") || cv_lower.contains("hydra") || cv_lower.contains("medusa") {
        signals.push("bruteforce_tool".into());
    }

    // Version anomalies
    if !client_version.starts_with("SSH-2.0-") && !client_version.starts_with("SSH-1.") {
        signals.push("malformed_version".into());
    }
    if client_version.len() > 200 {
        signals.push("oversized_version_string".into());
    }

    // Tunnel indicators (check for channel requests in data beyond version exchange)
    let has_tunnel_request = client_data
        .windows(15)
        .any(|w| w.starts_with(b"direct-tcpip") || w.starts_with(b"forwarded-tcpip"));

    if has_tunnel_request {
        signals.push("ssh_tunnel_detected".into());
    }

    // Non-standard port (caller should add this if port != 22)

    Some(SshSession {
        client_version,
        server_version,
        has_tunnel_request,
        signals,
    })
}

fn extract_version(data: &[u8]) -> Option<String> {
    // SSH version string is the first line: "SSH-2.0-OpenSSH_8.9\r\n"
    let text = std::str::from_utf8(data.get(..data.len().min(300))?).ok()?;
    let line = text.lines().find(|l| l.starts_with("SSH-"))?;
    Some(line.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_openssh() {
        let client = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n";
        let server = b"SSH-2.0-OpenSSH_9.6p1\r\n";
        let session = parse_session(client, server).unwrap();
        assert!(session.client_version.contains("OpenSSH"));
        assert!(session.server_version.contains("OpenSSH"));
        assert!(session.signals.is_empty());
    }

    #[test]
    fn test_detect_paramiko() {
        let client = b"SSH-2.0-paramiko_3.4.0\r\n";
        let server = b"SSH-2.0-OpenSSH_9.6\r\n";
        let session = parse_session(client, server).unwrap();
        assert!(session.signals.contains(&"python_ssh_lib".to_string()));
    }

    #[test]
    fn test_detect_tunnel() {
        let mut client = b"SSH-2.0-OpenSSH_8.9\r\n".to_vec();
        client.extend_from_slice(&[0; 20]);
        client.extend_from_slice(b"direct-tcpip");
        client.extend_from_slice(&[0; 20]);
        let server = b"SSH-2.0-OpenSSH_9.6\r\n";
        let session = parse_session(&client, server).unwrap();
        assert!(session.has_tunnel_request);
        assert!(session.signals.contains(&"ssh_tunnel_detected".to_string()));
    }
}
