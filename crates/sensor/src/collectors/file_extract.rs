//! File extraction from reassembled network streams.
//!
//! Extracts files from HTTP responses (downloads, uploads) and stores them
//! in a filestore with SHA-256 naming for automatic deduplication.
//! Extracted files are scanned against YARA rules and fed into AI triage.
//!
//! This catches malware delivery that never touches disk (fileless via
//! network → memory execution) by capturing the file FROM THE WIRE.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use super::proto_http;
use super::tcp_stream::{AppProtocol, FlowEvent};

/// Result of extracting a file from a network stream.
#[derive(Debug, Clone)]
pub struct ExtractedFile {
    /// SHA-256 hash of the file content (hex, lowercase).
    pub sha256: String,
    /// Original filename from Content-Disposition, or derived from URI.
    pub filename: String,
    /// MIME type from Content-Type header.
    pub content_type: String,
    /// File size in bytes.
    pub size: usize,
    /// Source flow information.
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    /// URI the file was downloaded from.
    pub uri: String,
    /// Path where the file was stored in the filestore.
    pub stored_path: Option<PathBuf>,
    /// Timestamp of extraction.
    pub timestamp: DateTime<Utc>,
    /// Security signals.
    pub signals: Vec<String>,
}

/// Extract files from a completed flow event.
/// Currently supports HTTP response bodies.
pub fn extract_from_flow(fe: &FlowEvent, filestore_dir: &Path) -> Option<ExtractedFile> {
    match fe.app_proto {
        AppProtocol::Http => extract_from_http(fe, filestore_dir),
        _ => None,
    }
}

fn extract_from_http(fe: &FlowEvent, filestore_dir: &Path) -> Option<ExtractedFile> {
    // Parse HTTP request (for URI/Host) and response (for body/headers)
    let req = proto_http::parse_request(&fe.client_data)?;
    let resp = proto_http::parse_response(&fe.server_data)?;

    // Only extract if response has a body worth analyzing
    if resp.body.is_empty() || resp.body.len() < 100 {
        return None;
    }

    // Only extract binary/executable content or explicit file downloads
    let dominated_type = resp.content_type.to_lowercase();
    let is_binary = dominated_type.contains("octet-stream")
        || dominated_type.contains("x-executable")
        || dominated_type.contains("x-msdos-program")
        || dominated_type.contains("x-elf")
        || dominated_type.contains("x-sharedlib")
        || dominated_type.contains("x-object")
        || dominated_type.contains("x-perl")
        || dominated_type.contains("x-python")
        || dominated_type.contains("x-shellscript")
        || dominated_type.contains("x-sh")
        || dominated_type.contains("x-csh")
        || dominated_type.contains("javascript")
        || dominated_type.contains("x-php")
        || dominated_type.contains("java-archive")
        || dominated_type.contains("zip")
        || dominated_type.contains("gzip")
        || dominated_type.contains("x-tar")
        || dominated_type.contains("x-bzip")
        || dominated_type.contains("x-7z")
        || dominated_type.contains("x-rar");

    let has_disposition = resp.content_disposition.is_some();

    // Check for ELF magic, PE magic, shebang, or script markers in body
    let has_exec_magic = resp.body.len() >= 4
        && (resp.body.starts_with(b"\x7fELF")           // ELF binary
            || resp.body.starts_with(b"MZ")              // PE (Windows, but relevant)
            || resp.body.starts_with(b"#!/")             // Shebang script
            || resp.body.starts_with(b"<?php")           // PHP
            || resp.body.starts_with(b"PK\x03\x04"));   // ZIP/JAR

    if !is_binary && !has_disposition && !has_exec_magic {
        return None;
    }

    // Compute SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&resp.body);
    let sha256 = format!("{:x}", hasher.finalize());

    // Extract filename
    let filename = extract_filename(&resp, &req.uri);

    // Security signals
    let mut signals = Vec::new();

    if has_exec_magic {
        if resp.body.starts_with(b"\x7fELF") {
            signals.push("elf_binary_download".into());
        } else if resp.body.starts_with(b"#!/") {
            signals.push("script_download".into());
        } else if resp.body.starts_with(b"<?php") {
            signals.push("php_download".into());
        } else if resp.body.starts_with(b"MZ") {
            signals.push("pe_binary_download".into());
        } else if resp.body.starts_with(b"PK\x03\x04") {
            signals.push("archive_download".into());
        }
    }

    if resp.body.len() > 1_000_000 {
        signals.push(format!("large_file:{}MB", resp.body.len() / 1_000_000));
    }

    // Check for obfuscation indicators
    let entropy = shannon_entropy(&resp.body);
    if entropy > 7.0 && resp.body.len() > 10_000 {
        signals.push(format!("high_entropy:{:.1}", entropy));
    }

    // Check for known packer signatures
    if resp.body.len() >= 16 {
        if resp.body.windows(3).any(|w| w == b"UPX") {
            signals.push("upx_packed".into());
        }
    }

    // Store to filestore
    let stored_path = store_file(filestore_dir, &sha256, &resp.body, &filename);

    let src_ip = fe.key.src_ip_str();
    let dst_ip = fe.key.dst_ip_str();

    info!(
        sha256 = %sha256,
        filename = %filename,
        size = resp.body.len(),
        content_type = %resp.content_type,
        src = format!("{}:{}", src_ip, fe.key.src_port),
        dst = format!("{}:{}", dst_ip, fe.key.dst_port),
        signals = ?signals,
        "file extracted from network stream"
    );

    Some(ExtractedFile {
        sha256,
        filename,
        content_type: resp.content_type,
        size: resp.body.len(),
        src_ip,
        dst_ip,
        src_port: fe.key.src_port,
        dst_port: fe.key.dst_port,
        uri: req.uri,
        stored_path,
        timestamp: Utc::now(),
        signals,
    })
}

/// Extract filename from Content-Disposition or URI.
fn extract_filename(resp: &proto_http::HttpResponse, uri: &str) -> String {
    // Try Content-Disposition first
    if let Some(ref disp) = resp.content_disposition {
        if let Some(start) = disp.find("filename=") {
            let name = &disp[start + 9..];
            let name = name.trim_matches('"').trim_matches('\'');
            let name = name.split(';').next().unwrap_or(name);
            if !name.is_empty() {
                return sanitize_filename(name);
            }
        }
    }

    // Fall back to last path component of URI
    let path = uri.split('?').next().unwrap_or(uri);
    let component = path.rsplit('/').next().unwrap_or("unknown");
    if component.is_empty() || component == "/" {
        "unknown".into()
    } else {
        sanitize_filename(component)
    }
}

/// Sanitize a filename for safe storage (remove path components, limit length).
fn sanitize_filename(name: &str) -> String {
    let clean: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect();
    let truncated = &clean[..clean.len().min(100)];
    if truncated.is_empty() {
        "unknown".into()
    } else {
        truncated.to_string()
    }
}

/// Store extracted file in the filestore using SHA-256 as filename (dedup).
fn store_file(
    filestore_dir: &Path,
    sha256: &str,
    data: &[u8],
    original_name: &str,
) -> Option<PathBuf> {
    let dir = filestore_dir.join("extracted");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        warn!(error = %e, "failed to create filestore dir");
        return None;
    }

    // Use SHA-256 prefix as subdirectory for filesystem efficiency
    let subdir = dir.join(&sha256[..2]);
    std::fs::create_dir_all(&subdir).ok()?;

    let ext = original_name
        .rsplit('.')
        .next()
        .filter(|e| e.len() <= 10)
        .unwrap_or("bin");

    let path = subdir.join(format!("{sha256}.{ext}"));

    // Skip if already exists (dedup)
    if path.exists() {
        debug!(sha256, "file already in filestore (dedup)");
        return Some(path);
    }

    match std::fs::write(&path, data) {
        Ok(()) => {
            info!(sha256, size = data.len(), path = %path.display(), "file stored");
            Some(path)
        }
        Err(e) => {
            warn!(sha256, error = %e, "failed to store extracted file");
            None
        }
    }
}

/// Shannon entropy of a byte slice (0-8 bits per byte).
fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f32;
    let mut entropy: f32 = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Convert an ExtractedFile into an InnerWarden Event.
pub fn to_event(
    ef: &ExtractedFile,
    host_id: &str,
) -> innerwarden_core::event::Event {
    use innerwarden_core::event::{Event, Severity};
    use innerwarden_core::entities::EntityRef;

    let severity = if ef.signals.iter().any(|s| {
        s.contains("elf_binary") || s.contains("pe_binary") || s.contains("upx_packed")
    }) {
        Severity::High
    } else if ef.signals.iter().any(|s| {
        s.contains("script") || s.contains("php") || s.contains("high_entropy")
    }) {
        Severity::Medium
    } else {
        Severity::Low
    };

    Event {
        ts: ef.timestamp,
        host: host_id.to_string(),
        source: "file_extract".into(),
        kind: "file.extracted_from_network".into(),
        severity,
        summary: format!(
            "File extracted: {} ({} bytes, {}) from {} via {}",
            ef.filename, ef.size, ef.content_type, ef.src_ip, ef.uri
        ),
        details: serde_json::json!({
            "sha256": ef.sha256,
            "filename": ef.filename,
            "content_type": ef.content_type,
            "size": ef.size,
            "src_ip": ef.src_ip,
            "dst_ip": ef.dst_ip,
            "dst_port": ef.dst_port,
            "uri": ef.uri,
            "stored_path": ef.stored_path.as_ref().map(|p| p.display().to_string()),
            "signals": ef.signals,
        }),
        tags: vec!["file_extraction".into(), "network".into()],
        entities: vec![
            EntityRef::ip(ef.src_ip.clone()),
            EntityRef::path(ef.filename.clone()),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_filename_from_disposition() {
        let resp = proto_http::HttpResponse {
            status_code: 200,
            reason: "OK".into(),
            version: "HTTP/1.1".into(),
            headers: vec![],
            body: vec![],
            content_type: "application/octet-stream".into(),
            content_length: None,
            content_disposition: Some("attachment; filename=\"malware.exe\"".into()),
        };
        assert_eq!(extract_filename(&resp, "/download"), "malware.exe");
    }

    #[test]
    fn test_extract_filename_from_uri() {
        let resp = proto_http::HttpResponse {
            status_code: 200,
            reason: "OK".into(),
            version: "HTTP/1.1".into(),
            headers: vec![],
            body: vec![],
            content_type: "application/octet-stream".into(),
            content_length: None,
            content_disposition: None,
        };
        assert_eq!(extract_filename(&resp, "/downloads/payload.sh"), "payload.sh");
    }

    #[test]
    fn test_sanitize_filename() {
        let sanitized = sanitize_filename("../../../etc/passwd");
        assert!(!sanitized.contains('/'));
        assert!(sanitized.contains("passwd"));
        assert_eq!(sanitize_filename("normal-file_v2.tar.gz"), "normal-file_v2.tar.gz");
        assert_eq!(sanitize_filename(""), "unknown");
    }

    #[test]
    fn test_shannon_entropy() {
        // Random-ish data has high entropy
        let high_data: Vec<u8> = (0..=255).collect();
        assert!(shannon_entropy(&high_data) > 7.0);

        // Repeated data has low entropy
        let low_data = vec![0x41u8; 100];
        assert!(shannon_entropy(&low_data) < 0.1);
    }

    #[test]
    fn test_store_and_dedup() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"fake binary content for testing";
        let hash = "abc123def456";

        let path1 = store_file(dir.path(), hash, data, "test.bin");
        assert!(path1.is_some());

        // Second store with same hash should dedup
        let path2 = store_file(dir.path(), hash, data, "test.bin");
        assert_eq!(path1, path2);
    }
}
