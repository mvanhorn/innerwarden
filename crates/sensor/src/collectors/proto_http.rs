//! HTTP/1.x protocol parser for reassembled TCP streams.
//!
//! Parses HTTP requests and responses from reassembled byte streams,
//! extracting: method, URI, headers, body, status code.
//!
//! Works on any port (feeds from tcp_stream reassembly, not port-filtered).

/// Parsed HTTP request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub host: String,
    pub user_agent: String,
    pub content_type: String,
    pub content_length: Option<usize>,
}

/// Parsed HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub reason: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub content_type: String,
    pub content_length: Option<usize>,
    pub content_disposition: Option<String>,
}

/// Parse an HTTP request from raw bytes.
pub fn parse_request(data: &[u8]) -> Option<HttpRequest> {
    let text = std::str::from_utf8(data).ok()?;
    let header_end = text.find("\r\n\r\n")?;
    let header_section = &text[..header_end];
    let body_start = header_end + 4;

    let mut lines = header_section.lines();

    // Request line: METHOD URI VERSION
    let request_line = lines.next()?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next()?.to_string();
    let uri = parts.next()?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    // Validate method
    if !matches!(
        method.as_str(),
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT" | "TRACE"
    ) {
        return None;
    }

    // Parse headers
    let mut headers = Vec::new();
    let mut host = String::new();
    let mut user_agent = String::new();
    let mut content_type = String::new();
    let mut content_length = None;

    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();

            let lower = name.to_lowercase();
            match lower.as_str() {
                "host" => host = value.clone(),
                "user-agent" => user_agent = value.clone(),
                "content-type" => content_type = value.clone(),
                "content-length" => content_length = value.parse().ok(),
                _ => {}
            }

            headers.push((name, value));
        }
    }

    let body = if body_start < data.len() {
        data[body_start..].to_vec()
    } else {
        Vec::new()
    };

    Some(HttpRequest {
        method,
        uri,
        version,
        headers,
        body,
        host,
        user_agent,
        content_type,
        content_length,
    })
}

/// Parse an HTTP response from raw bytes.
pub fn parse_response(data: &[u8]) -> Option<HttpResponse> {
    let text = std::str::from_utf8(data).ok()?;
    let header_end = text.find("\r\n\r\n")?;
    let header_section = &text[..header_end];
    let body_start = header_end + 4;

    let mut lines = header_section.lines();

    // Status line: VERSION STATUS REASON
    let status_line = lines.next()?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next()?.to_string();
    let status_code: u16 = parts.next()?.parse().ok()?;
    let reason = parts.next().unwrap_or("").to_string();

    if !version.starts_with("HTTP/") {
        return None;
    }

    let mut headers = Vec::new();
    let mut content_type = String::new();
    let mut content_length = None;
    let mut content_disposition = None;

    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();

            let lower = name.to_lowercase();
            match lower.as_str() {
                "content-type" => content_type = value.clone(),
                "content-length" => content_length = value.parse().ok(),
                "content-disposition" => content_disposition = Some(value.clone()),
                _ => {}
            }

            headers.push((name, value));
        }
    }

    let body = if body_start < data.len() {
        data[body_start..].to_vec()
    } else {
        Vec::new()
    };

    Some(HttpResponse {
        status_code,
        reason,
        version,
        headers,
        body,
        content_type,
        content_length,
        content_disposition,
    })
}

/// Extract interesting security signals from parsed HTTP.
pub fn extract_signals(req: &HttpRequest, resp: Option<&HttpResponse>) -> Vec<String> {
    let mut signals = Vec::new();

    // Suspicious URI patterns
    let uri_lower = req.uri.to_lowercase();
    if uri_lower.contains("../") || uri_lower.contains("..\\") {
        signals.push("path_traversal".into());
    }
    if uri_lower.contains("/etc/passwd")
        || uri_lower.contains("/etc/shadow")
        || uri_lower.contains("wp-config")
    {
        signals.push("sensitive_file_access".into());
    }
    if uri_lower.contains("cmd=") || uri_lower.contains("exec=") || uri_lower.contains("shell") {
        signals.push("command_injection_attempt".into());
    }
    if uri_lower.contains("union") && uri_lower.contains("select") {
        signals.push("sql_injection_attempt".into());
    }
    if uri_lower.contains("<script") || uri_lower.contains("javascript:") {
        signals.push("xss_attempt".into());
    }

    // Suspicious User-Agent
    if req.user_agent.is_empty() {
        signals.push("empty_user_agent".into());
    } else if req.user_agent.len() < 10 && !req.user_agent.contains('/') {
        signals.push("suspicious_user_agent".into());
    }
    let ua_lower = req.user_agent.to_lowercase();
    if ua_lower.contains("sqlmap")
        || ua_lower.contains("nikto")
        || ua_lower.contains("nmap")
        || ua_lower.contains("masscan")
        || ua_lower.contains("zgrab")
        || ua_lower.contains("gobuster")
        || ua_lower.contains("dirbuster")
    {
        signals.push(format!("scanner_tool:{}", req.user_agent.split('/').next().unwrap_or("unknown")));
    }

    // Suspicious request body
    if !req.body.is_empty() {
        let body_str = String::from_utf8_lossy(&req.body[..req.body.len().min(1000)]);
        let body_lower = body_str.to_lowercase();
        if body_lower.contains("<?php") || body_lower.contains("system(") {
            signals.push("webshell_upload".into());
        }
        if body_lower.contains("base64_decode") || body_lower.contains("eval(") {
            signals.push("code_injection_body".into());
        }
    }

    // Response analysis
    if let Some(resp) = resp {
        // File download
        if resp.content_disposition.is_some() {
            signals.push("file_download".into());
        }
        // Large response (potential data exfil or malware download)
        if let Some(len) = resp.content_length {
            if len > 1_000_000 {
                signals.push(format!("large_response:{}MB", len / 1_000_000));
            }
        }
        // Binary content type
        if resp.content_type.contains("octet-stream")
            || resp.content_type.contains("x-executable")
            || resp.content_type.contains("x-msdos-program")
        {
            signals.push("binary_download".into());
        }
    }

    signals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_get_request() {
        let raw = b"GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        let req = parse_request(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.uri, "/api/v1/users");
        assert_eq!(req.host, "example.com");
        assert_eq!(req.user_agent, "Mozilla/5.0");
    }

    #[test]
    fn test_parse_post_with_body() {
        let raw = b"POST /login HTTP/1.1\r\nHost: app.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 25\r\n\r\nusername=admin&password=pw";
        let req = parse_request(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.content_type, "application/x-www-form-urlencoded");
        assert_eq!(req.body, b"username=admin&password=pw");
    }

    #[test]
    fn test_parse_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_type, "text/html");
        assert_eq!(resp.body, b"hello");
    }

    #[test]
    fn test_extract_signals_path_traversal() {
        let req = HttpRequest {
            method: "GET".into(),
            uri: "/../../etc/passwd".into(),
            version: "HTTP/1.1".into(),
            headers: vec![],
            body: vec![],
            host: "target.com".into(),
            user_agent: "curl/7.0".into(),
            content_type: String::new(),
            content_length: None,
        };
        let signals = extract_signals(&req, None);
        assert!(signals.contains(&"path_traversal".to_string()));
        assert!(signals.contains(&"sensitive_file_access".to_string()));
    }

    #[test]
    fn test_extract_signals_scanner() {
        let req = HttpRequest {
            method: "GET".into(),
            uri: "/".into(),
            version: "HTTP/1.1".into(),
            headers: vec![],
            body: vec![],
            host: "target.com".into(),
            user_agent: "sqlmap/1.6".into(),
            content_type: String::new(),
            content_length: None,
        };
        let signals = extract_signals(&req, None);
        assert!(signals.iter().any(|s| s.starts_with("scanner_tool")));
    }

    #[test]
    fn test_invalid_request() {
        assert!(parse_request(b"not http at all").is_none());
        assert!(parse_request(b"INVALID / HTTP/1.1\r\n\r\n").is_none());
    }
}
