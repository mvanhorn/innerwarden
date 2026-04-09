//! SMB protocol parser for reassembled TCP streams.
//!
//! Detects SMB lateral movement patterns: file access, share enumeration,
//! remote execution via named pipes (psexec, smbexec).
//! Works on any port (not just 445).

/// Parsed SMB session info.
#[derive(Debug, Clone)]
pub struct SmbSession {
    pub version: SmbVersion,
    pub shares_accessed: Vec<String>,
    pub files_accessed: Vec<String>,
    pub named_pipes: Vec<String>,
    pub signals: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SmbVersion {
    Smb1,
    Smb2,
    Smb3,
    Unknown,
}

/// Parse SMB session from reassembled client data.
pub fn parse_session(client_data: &[u8]) -> Option<SmbSession> {
    if client_data.len() < 8 {
        return None;
    }

    let mut session = SmbSession {
        version: SmbVersion::Unknown,
        shares_accessed: Vec::new(),
        files_accessed: Vec::new(),
        named_pipes: Vec::new(),
        signals: Vec::new(),
    };

    // Detect SMB version from magic bytes
    // SMB1: \xFF\x53\x4D\x42 ("SMB")
    // SMB2/3: \xFE\x53\x4D\x42 ("SMB2")
    let mut offset = 0;
    while offset + 8 < client_data.len() {
        // NetBIOS session header (4 bytes) + SMB header
        let nb_len = if client_data[offset] == 0x00 && offset + 4 < client_data.len() {
            let len = u32::from_be_bytes([
                0,
                client_data[offset + 1],
                client_data[offset + 2],
                client_data[offset + 3],
            ]) as usize;
            offset += 4;
            len
        } else {
            break;
        };

        if offset + 4 > client_data.len() {
            break;
        }

        // SMB1 magic
        if client_data[offset] == 0xFF
            && client_data[offset + 1] == b'S'
            && client_data[offset + 2] == b'M'
            && client_data[offset + 3] == b'B'
        {
            session.version = SmbVersion::Smb1;
            // SMB1 command byte at offset+4
            if offset + 5 <= client_data.len() {
                let cmd = client_data[offset + 4];
                match cmd {
                    0x75 => session.signals.push("tree_connect".into()),     // Tree Connect
                    0x2D => session.signals.push("open_file".into()),         // Open
                    0x32 => session.signals.push("transaction".into()),       // Transaction
                    0xA2 => session.signals.push("nt_create".into()),         // NT Create AndX
                    _ => {}
                }
            }
        }
        // SMB2/3 magic
        else if client_data[offset] == 0xFE
            && client_data[offset + 1] == b'S'
            && client_data[offset + 2] == b'M'
            && client_data[offset + 3] == b'B'
        {
            if session.version == SmbVersion::Unknown {
                session.version = SmbVersion::Smb2;
            }
            // SMB2 command at offset+12 (2 bytes LE)
            if offset + 14 <= client_data.len() {
                let cmd = u16::from_le_bytes([
                    client_data[offset + 12],
                    client_data[offset + 13],
                ]);
                match cmd {
                    0x0003 => session.signals.push("tree_connect".into()),    // TREE_CONNECT
                    0x0005 => session.signals.push("create_file".into()),     // CREATE
                    0x0008 => session.signals.push("read_file".into()),       // READ
                    0x0009 => session.signals.push("write_file".into()),      // WRITE
                    0x000B => session.signals.push("ioctl".into()),           // IOCTL (psexec uses this)
                    _ => {}
                }
            }
        }

        // Move to next message
        offset += nb_len;
        if nb_len == 0 {
            break;
        }
    }

    // Scan for named pipe strings (lateral movement indicators)
    let pipe_patterns = [
        ("\\IPC$", "ipc_share"),
        ("\\ADMIN$", "admin_share"),
        ("\\C$", "c_share"),
        ("svcctl", "remote_service_control"),   // psexec
        ("atsvc", "remote_task_scheduler"),      // at.exe
        ("srvsvc", "server_service"),            // share enumeration
        ("samr", "sam_enumeration"),             // user enumeration
        ("lsarpc", "lsa_enumeration"),           // policy enumeration
        ("winreg", "remote_registry"),           // registry access
        ("PSEXESVC", "psexec_service"),          // psexec indicator
    ];

    let data_str = String::from_utf8_lossy(client_data);
    for (pattern, signal_name) in &pipe_patterns {
        if data_str.contains(pattern) {
            session.named_pipes.push(pattern.to_string());
            session.signals.push(signal_name.to_string());
        }
    }

    // Only return if we detected something meaningful
    if session.version == SmbVersion::Unknown && session.signals.is_empty() {
        return None;
    }

    // Flag high-risk combinations
    if session.signals.contains(&"ipc_share".to_string())
        && (session.signals.contains(&"remote_service_control".to_string())
            || session.signals.contains(&"psexec_service".to_string()))
    {
        session.signals.push("LATERAL_MOVEMENT_PSEXEC".into());
    }

    if session.signals.contains(&"sam_enumeration".to_string())
        || session.signals.contains(&"lsa_enumeration".to_string())
    {
        session.signals.push("CREDENTIAL_ENUMERATION".into());
    }

    Some(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_psexec_named_pipes() {
        // Build a minimal SMB2 message with named pipe strings in the data
        let mut data = vec![0x00, 0x00, 0x00, 0x50]; // NB header, len=80
        data.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // SMB2 magic
        data.extend_from_slice(&[0; 72]); // Pad to fill NB length
        // Append named pipe strings (scanned by string matching)
        data.extend_from_slice(b"\\IPC$\x00svcctl\x00PSEXESVC\x00");

        let session = parse_session(&data).unwrap();
        assert_eq!(session.version, SmbVersion::Smb2);
        assert!(session.signals.contains(&"ipc_share".to_string()));
        assert!(session.signals.contains(&"remote_service_control".to_string()));
        assert!(session.signals.contains(&"psexec_service".to_string()));
        assert!(session.signals.contains(&"LATERAL_MOVEMENT_PSEXEC".to_string()));
    }

    #[test]
    fn test_no_smb() {
        let data = b"GET / HTTP/1.1\r\n\r\n";
        assert!(parse_session(data).is_none());
    }
}
