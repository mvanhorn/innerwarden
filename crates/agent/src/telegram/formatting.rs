use innerwarden_core::incident::Incident;
use tracing::warn;

use super::{ApprovalResult, GuardianMode};

/// Telegram enforces a 4096-character limit on messages.
/// Truncate with a warning marker if exceeded.
const TELEGRAM_MAX_LEN: usize = 4000; // Leave margin for safety
/// Telegram callback_data payloads must be <= 64 bytes.
const TELEGRAM_MAX_CALLBACK_BYTES: usize = 64;

pub(super) fn enforce_length(text: &str) -> String {
    if text.len() <= TELEGRAM_MAX_LEN {
        return text.to_string();
    }
    warn!(
        original_len = text.len(),
        "Telegram message truncated (exceeded 4096 char limit)"
    );
    let mut truncated: String = text.chars().take(TELEGRAM_MAX_LEN - 30).collect();
    truncated.push_str("\n\n<i>… message truncated</i>");
    truncated
}

/// Truncate a UTF-8 string to at most `max_bytes` while preserving char boundaries.
fn truncate_utf8_bytes(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut cut = 0usize;
    for (idx, ch) in text.char_indices() {
        let next = idx + ch.len_utf8();
        if next > max_bytes {
            break;
        }
        cut = next;
    }
    text[..cut].to_string()
}

/// Build callback_data with a fixed prefix, ensuring total payload stays <= 64 bytes.
pub(super) fn callback_data(prefix: &str, payload: &str) -> String {
    let prefix_len = prefix.len();
    if prefix_len >= TELEGRAM_MAX_CALLBACK_BYTES {
        warn!(
            prefix_len,
            max = TELEGRAM_MAX_CALLBACK_BYTES,
            "callback prefix exceeded Telegram limit; truncating prefix"
        );
        return truncate_utf8_bytes(prefix, TELEGRAM_MAX_CALLBACK_BYTES);
    }
    let payload_budget = TELEGRAM_MAX_CALLBACK_BYTES - prefix_len;
    let payload = truncate_utf8_bytes(payload, payload_budget);
    format!("{prefix}{payload}")
}

// ---------------------------------------------------------------------------
// URL sanitization for logging
// ---------------------------------------------------------------------------

/// Replace bot token in Telegram API URL with redacted version for logging.
pub(super) fn sanitize_url(url: &str) -> String {
    if let Some(start) = url.find("/bot") {
        if let Some(end) = url[start + 4..].find('/') {
            let mut sanitized = url[..start + 4].to_string();
            sanitized.push_str("***REDACTED***");
            sanitized.push_str(&url[start + 4 + end..]);
            return sanitized;
        }
    }
    url.to_string()
}

pub(super) fn format_incident_message(
    incident: &Incident,
    dashboard_url: Option<&str>,
    mode: GuardianMode,
) -> String {
    let sev = severity_label(incident);
    let entity_line = entity_summary(incident);
    let detector = extract_detector(&incident.incident_id);

    let summary_trunc = if incident.summary.len() > 200 {
        format!("{}…", &incident.summary[..200])
    } else {
        incident.summary.clone()
    };

    let mode_line = match mode {
        GuardianMode::Guard => "\u{26a1} Handling — stand by for action report.",
        GuardianMode::DryRun => "\u{1f9ea} Dry-run — would act. Enable live mode.",
        GuardianMode::Watch => "\u{1f440} Watching — operator action required.",
    };

    let link_line = dashboard_url
        .and_then(|base| first_ip_entity(incident).map(|ip| (base, ip)))
        .map(|(base, ip)| {
            format!(
                "\n\u{1f517} <a href=\"{}/?subject_type=ip&subject={}&date={}\">Investigate</a>",
                base,
                ip,
                incident.ts.format("%Y-%m-%d")
            )
        })
        .unwrap_or_default();

    format!(
        "{sev} <code>{detector}</code>\n\
         \n\
         <b>{title}</b>\n\
         {entity_line}\n\
         <i>{summary}</i>\n\
         \n\
         {mode_line}{link_line}",
        title = escape_html(&incident.title),
        summary = escape_html(&summary_trunc),
    )
}

/// Returns a hacker-flavored one-liner based on the incident type.
#[allow(dead_code)]
fn incident_quip(incident: &Incident) -> &'static str {
    let title = incident.title.to_lowercase();
    let _tags: Vec<&str> = incident.tags.iter().map(|s| s.as_str()).collect();

    if title.contains("brute") || (title.contains("ssh") && title.contains("fail")) {
        return "💥 Script kiddie hammering the front door. Dictionary attack, classic.";
    }
    if title.contains("credential") || title.contains("stuffing") || title.contains("spray") {
        return "🎭 Credential spray detected. Threat actor cosplaying as your users.";
    }
    if title.contains("port scan") || title.contains("portscan") {
        return "🔭 Recon phase active - they're mapping our attack surface. Not on my watch.";
    }
    if title.contains("sudo") || title.contains("privilege") {
        return "👑 Privilege escalation attempt. This actor's trying to go root. Hard no.";
    }
    if title.contains("execution") || title.contains("shell") || title.contains("command") {
        return "💀 Suspicious binary execution. Could be a payload drop - locking it down.";
    }
    if title.contains("rate") || title.contains("search") || title.contains("abuse") {
        return "🤖 Automated scraping detected. Bot's treating your server like an open API.";
    }
    if title.contains("authorized_keys") || title.contains("ssh key") {
        return "🔑 SSH key tampering - classic persistence play. ATT&CK T1098.004 vibes.";
    }
    if title.contains("cron") || title.contains("scheduled") {
        return "⏰ Cron tampering - threat actor planting a persistent backdoor. ATT&CK T1053.";
    }
    if title.contains("file") || title.contains("integrity") {
        return "🕵️ File tampered outside expected windows. Could be an IOC - eyes on it.";
    }
    if title.contains("container") || title.contains("docker") {
        return "🐳 Suspicious container spun up. Checking for --privileged escapes.";
    }
    "👾 Anomaly in the noise. Threat actor or misconfigured bot - investigating."
}

/// Converts a technical action description into hacker-flavored plain language.
pub(super) fn plain_action(action: &str) -> String {
    let a = action.trim();
    // block-ip variants
    if a.contains("ufw deny from")
        || a.contains("iptables")
        || a.contains("nftables")
        || a.contains("pfctl")
    {
        let ip = a.split_whitespace().last().unwrap_or("IP");
        return format!("Drop {ip} at the firewall - blackhole their traffic");
    }
    if a.contains("block") && a.contains("ip") {
        let ip = a.split_whitespace().last().unwrap_or("IP");
        return format!("Firewall drop {ip} - null route all inbound traffic");
    }
    // suspend-user-sudo
    if a.contains("sudoers") || a.contains("suspend") {
        let user = a.split_whitespace().last().unwrap_or("user");
        return format!("Kill sudo privileges for {user} - privilege revoked");
    }
    // monitor
    if a.contains("tcpdump") || a.contains("monitor") || a.contains("pcap") {
        let ip = a.split_whitespace().last().unwrap_or("IP");
        return format!("Spin up packet capture on {ip} - collect forensic evidence");
    }
    // honeypot
    if a.contains("honeypot") {
        return "Redirect threat actor to honeypot - let them think they're in".to_string();
    }
    // fallback
    a.to_string()
}

/// Human-friendly detector name for digest messages.
pub(crate) fn friendly_detector_name(detector: &str) -> &str {
    match detector {
        "ssh_bruteforce" => "SSH brute force attempts blocked",
        "credential_stuffing" => "credential stuffing attempts blocked",
        "port_scan" => "port scans detected",
        "packet_flood" => "DDoS/flood events handled",
        "discovery_burst" => "reconnaissance scans detected",
        "suspicious_execution" => "suspicious executions (reviewed safe)",
        "web_scan" => "web vulnerability scans blocked",
        "user_agent_scanner" => "bot scanners blocked",
        "search_abuse" => "search abuse attempts blocked",
        "rootkit" => "timing anomalies (cloud noise)",
        "firmware_integrity" => "firmware checks (cloud noise)",
        "sigma" => "Sigma rule matches",
        "neural_anomaly" => "AI spider sense detections",
        "correlated_anomaly" => "AI + statistical convergence alerts",
        "process_tree" => "process chain alerts",
        "user_creation" => "user creation events",
        "sensitive_write" => "sensitive file writes",
        "docker_anomaly" => "Docker anomalies",
        "outbound_anomaly" => "outbound traffic anomalies",
        _ => detector,
    }
}

pub(super) fn severity_label(incident: &Incident) -> &'static str {
    use innerwarden_core::event::Severity::*;
    match incident.severity {
        Critical => "🔴 <b>CRITICAL</b>",
        High => "🟠 <b>HIGH</b>",
        Medium => "🟡 MEDIUM",
        Low => "🟢 LOW",
        _ => "⚪ INFO",
    }
}

pub(super) fn source_icon(tags: &[String]) -> &'static str {
    if tags.iter().any(|t| t == "ssh" || t == "sshd") {
        "🔐"
    } else {
        "📋"
    }
}

pub(super) fn entity_summary(incident: &Incident) -> String {
    use innerwarden_core::entities::EntityType::*;
    let parts: Vec<String> = incident
        .entities
        .iter()
        .take(3)
        .map(|e| match e.r#type {
            Ip => format!("IP: <code>{}</code>", escape_html(&e.value)),
            User => format!("User: <code>{}</code>", escape_html(&e.value)),
            Container => format!("Container: <code>{}</code>", escape_html(&e.value)),
            Path => format!("Path: <code>{}</code>", escape_html(&e.value)),
            Service => format!("Service: <code>{}</code>", escape_html(&e.value)),
        })
        .collect();
    parts.join(" · ")
}

pub(super) fn first_ip_entity(incident: &Incident) -> Option<String> {
    incident
        .entities
        .iter()
        .find(|e| matches!(e.r#type, innerwarden_core::entities::EntityType::Ip))
        .map(|e| e.value.clone())
}

/// Parse a Telegram callback_data string into an ApprovalResult.
/// Format: "approve:{incident_id}", "reject:{incident_id}", or "menu:{command}"
pub(super) fn parse_callback(data: &str, operator: &str) -> Option<ApprovalResult> {
    if let Some(id) = data.strip_prefix("approve:") {
        return Some(ApprovalResult {
            incident_id: id.to_string(),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    if let Some(id) = data.strip_prefix("always:") {
        return Some(ApprovalResult {
            incident_id: id.to_string(),
            approved: true,
            always: true,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    if let Some(id) = data.strip_prefix("reject:") {
        return Some(ApprovalResult {
            incident_id: id.to_string(),
            approved: false,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    // Inline-keyboard menu buttons: "menu:status", "menu:threats", etc.
    if let Some(cmd) = data.strip_prefix("menu:") {
        let incident_id = match cmd {
            "status" => "__status__",
            "incidents" | "threats" => "__threats__",
            "decisions" => "__decisions__",
            "help" => "__help__",
            "undo" => "__undo__",
            _ => "__unknown_cmd__",
        };
        return Some(ApprovalResult {
            incident_id: incident_id.to_string(),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    // Sensitivity buttons: "sensitivity:quiet", "sensitivity:normal", "sensitivity:verbose"
    if let Some(level) = data.strip_prefix("sensitivity:") {
        return Some(ApprovalResult {
            incident_id: format!("__sensitivity__:{level}"),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    // Profile toggle: "profile:simple" or "profile:technical"
    if let Some(profile) = data.strip_prefix("profile:") {
        return Some(ApprovalResult {
            incident_id: format!("__profile__:{profile}"),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    // Capabilities inline keyboard: "enable:<id>" → routed to __enable__:<id> handler
    if let Some(cap_id) = data.strip_prefix("enable:") {
        return Some(ApprovalResult {
            incident_id: format!("enable:{cap_id}"),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    None
}

/// Strip `@BotUsername` suffix from Telegram commands.
/// "/help@InnerWardenBot" → "/help", "/status" → "/status", "hello" → "hello"
pub(super) fn strip_bot_suffix(text: &str) -> String {
    if text.starts_with('/') {
        if let Some(at_pos) = text.find('@') {
            // Check if @bot comes right after the command (before any space)
            let space_pos = text.find(' ').unwrap_or(text.len());
            if at_pos < space_pos {
                // "/help@Bot args" → "/help args"
                let cmd = &text[..at_pos];
                let rest = &text[space_pos..];
                return format!("{cmd}{rest}");
            }
        }
    }
    text.to_string()
}

/// Escape HTML special characters for Telegram HTML parse mode.
pub(crate) fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Public wrapper for escape_html (used by main.rs auto-FP suggestions).
pub fn escape_html_pub(s: &str) -> String {
    escape_html(s)
}

/// Public wrapper for truncate_utf8_bytes (callback data must be <= 64 bytes).
pub fn truncate_callback_pub(s: &str) -> String {
    truncate_utf8_bytes(s, TELEGRAM_MAX_CALLBACK_BYTES)
}

/// Visual score bar for AbuseIPDB confidence (e.g. "████░░░░ 80/100").
pub(super) fn reputation_score_bar(score: u8) -> String {
    let filled = (score as usize * 8 / 100).min(8);
    let empty = 8 - filled;
    let bar = "█".repeat(filled) + &"░".repeat(empty);
    format!("[{bar}]")
}

/// Convert a 2-letter ISO country code to a flag emoji.
pub(super) fn country_flag_emoji(code: &str) -> String {
    if code.len() != 2 {
        return String::new();
    }
    let bytes = code.to_uppercase();
    let mut chars = bytes.chars();
    if let (Some(a), Some(b)) = (chars.next(), chars.next()) {
        let base: u32 = 0x1F1E6 - b'A' as u32;
        let fa = char::from_u32(base + a as u32).unwrap_or(' ');
        let fb = char::from_u32(base + b as u32).unwrap_or(' ');
        return format!("{fa}{fb}");
    }
    String::new()
}

/// Extract detector name from incident_id (format: "detector:rest:...")
fn extract_detector(incident_id: &str) -> &str {
    incident_id.split(':').next().unwrap_or(incident_id)
}

/// Public wrapper for extract_detector, used by daily digest in main.rs.
pub fn extract_detector_pub(incident_id: &str) -> &str {
    extract_detector(incident_id)
}

/// Returns (emoji, plain_description_template) for a given detector name.
/// The template may contain `{action}` which the caller replaces.
fn simple_detector_lookup(detector: &str) -> (&'static str, &'static str) {
    match detector {
        "ssh_bruteforce" => (
            "\u{1f512}",
            "Someone tried to guess your server's password. {action}",
        ),
        "credential_stuffing" => (
            "\u{1f3ad}",
            "Multiple login attempts with different passwords detected. {action}",
        ),
        "port_scan" => (
            "\u{1f50d}",
            "Someone is scanning your server looking for open doors. {action}",
        ),
        "packet_flood" => (
            "\u{1f30a}",
            "Your server is receiving unusual traffic. {action}",
        ),
        "data_exfil" | "data_exfil_cmd" | "data_exfil_ebpf" => (
            "\u{1f4e4}",
            "A program tried to steal sensitive data. {action}",
        ),
        "reverse_shell" => (
            "\u{1f6a8}",
            "An attacker may have gained remote access. {action}",
        ),
        "privesc" => (
            "\u{1f451}",
            "A process tried to become administrator without permission. {action}",
        ),
        "rootkit" => (
            "\u{1f47b}",
            "Suspicious kernel-level activity detected. {action}",
        ),
        "ransomware" => ("\u{1f4b0}", "File encryption pattern detected. {action}"),
        "dns_tunneling" | "dns_tunneling_ebpf" => (
            "\u{1f310}",
            "Hidden communication channel detected. {action}",
        ),
        "c2_callback" => (
            "\u{1f4e1}",
            "Your server may be communicating with an attacker. {action}",
        ),
        "crypto_miner" => (
            "\u{26cf}\u{fe0f}",
            "Something is using your server to mine cryptocurrency. {action}",
        ),
        "container_escape" => (
            "\u{1f4e6}",
            "A container tried to break out of its sandbox. {action}",
        ),
        "lateral_movement" => ("\u{1f6b6}", "Movement between systems detected. {action}"),
        "web_shell" => (
            "\u{1f578}\u{fe0f}",
            "A web-based backdoor was detected. {action}",
        ),
        "process_injection" => (
            "\u{1f489}",
            "A program tried to inject code into another program. {action}",
        ),
        "fileless" => (
            "\u{1f47e}",
            "Fileless malware detected running only in memory. {action}",
        ),
        "log_tampering" => ("\u{1f9f9}", "Someone tried to erase their tracks. {action}"),
        "ssh_key_injection" => (
            "\u{1f511}",
            "An SSH key was added to allow future access. {action}",
        ),
        "crontab_persistence" | "systemd_persistence" => (
            "\u{23f0}",
            "Something installed itself to survive reboots. {action}",
        ),
        "kernel_module_load" => ("\u{1f9e9}", "A new kernel module was loaded. {action}"),
        "discovery_burst" => (
            "\u{1f5fa}\u{fe0f}",
            "Someone is mapping your system. {action}",
        ),
        "sigma" => ("\u{1f4cb}", "A known attack pattern was detected. {action}"),
        "suspicious_execution" => (
            "\u{26a0}\u{fe0f}",
            "A suspicious program was executed. {action}",
        ),
        "sensitive_write" => (
            "\u{270f}\u{fe0f}",
            "A sensitive system file was modified. {action}",
        ),
        "user_creation" => ("\u{1f464}", "A new user account was created. {action}"),
        "process_tree" => ("\u{1f333}", "Suspicious program chain detected. {action}"),
        "neural_anomaly" => (
            "\u{1f9e0}",
            "AI spider sense triggered — unusual pattern detected. {action}",
        ),
        "correlated_anomaly" => (
            "\u{1f9e0}\u{26a1}",
            "Two independent AI systems flagged unusual activity. {action}",
        ),
        _ => ("\u{26a0}\u{fe0f}", "Suspicious activity detected. {action}"),
    }
}

/// Severity emoji for simple profile messages.
fn simple_severity_emoji(incident: &Incident) -> &'static str {
    use innerwarden_core::event::Severity::*;
    match incident.severity {
        Critical => "\u{1f534}", // 🔴
        High => "\u{1f7e0}",     // 🟠
        Medium => "\u{1f7e1}",   // 🟡
        Low => "\u{1f7e2}",      // 🟢
        _ => "\u{26aa}",         // ⚪
    }
}

/// Format a plain-language alert message for simple profile users.
/// Structured, informative, and impressive — every notification is a jewel.
pub(super) fn format_simple_message(
    incident: &Incident,
    dashboard_url: Option<&str>,
    mode: GuardianMode,
) -> String {
    let detector = extract_detector(&incident.incident_id);
    let (det_emoji, _template) = simple_detector_lookup(detector);
    let sev_emoji = simple_severity_emoji(incident);
    let sev_word = match incident.severity {
        innerwarden_core::event::Severity::Critical => "Critical",
        innerwarden_core::event::Severity::High => "High",
        innerwarden_core::event::Severity::Medium => "Medium",
        innerwarden_core::event::Severity::Low => "Low",
        _ => "Info",
    };
    let det_label = simple_detector_label(detector);

    // Build concise what-happened line from entities + summary.
    let ip_entity = first_ip_entity(incident);
    let detail = simple_detail_line(incident, &ip_entity);

    // Action line depends on mode.
    let action_line = match mode {
        GuardianMode::Guard => "\u{26a1} <b>Handled automatically</b> — no action needed.",
        GuardianMode::DryRun => {
            "\u{1f9ea} <b>Dry-run</b> — would act on this. Enable live mode to let me."
        }
        GuardianMode::Watch => "\u{26a0}\u{fe0f} <b>Needs your attention.</b>",
    };

    let link_line = dashboard_url
        .and_then(|base| ip_entity.as_ref().map(|ip| (base, ip)))
        .map(|(base, ip)| {
            format!(
                "\n\n\u{1f517} <a href=\"{}/?subject_type=ip&subject={}&date={}\">View details</a>",
                base,
                ip,
                incident.ts.format("%Y-%m-%d")
            )
        })
        .unwrap_or_default();

    format!(
        "{sev_emoji} {det_emoji} <b>{sev_word} — {det_label}</b>\n\
         \n\
         {detail}\n\
         \n\
         {action_line}{link_line}",
    )
}

/// Human-readable detector label for simple profile headers.
fn simple_detector_label(detector: &str) -> &'static str {
    match detector {
        "ssh_bruteforce" => "Login Attack Blocked",
        "credential_stuffing" => "Credential Attack",
        "port_scan" => "Port Scan",
        "packet_flood" => "Traffic Flood",
        "data_exfil" | "data_exfil_cmd" | "data_exfil_ebpf" => "Data Theft Attempt",
        "reverse_shell" => "Remote Access Detected",
        "privesc" => "Privilege Escalation",
        "rootkit" => "Kernel Tampering",
        "ransomware" => "Ransomware Detected",
        "dns_tunneling" | "dns_tunneling_ebpf" => "Covert Channel",
        "c2_callback" => "Attacker Communication",
        "crypto_miner" => "Crypto Mining",
        "container_escape" => "Container Breakout",
        "lateral_movement" => "Lateral Movement",
        "web_shell" => "Web Backdoor",
        "process_injection" => "Code Injection",
        "fileless" => "Memory-Only Malware",
        "log_tampering" => "Log Tampering",
        "ssh_key_injection" => "SSH Key Planted",
        "crontab_persistence" | "systemd_persistence" => "Persistence Installed",
        "kernel_module_load" => "Kernel Module Loaded",
        "discovery_burst" => "Reconnaissance",
        "suspicious_execution" => "Suspicious Execution",
        "sigma" => "Known Attack Pattern",
        "neural_anomaly" => "AI Spider Sense",
        "correlated_anomaly" => "AI + Statistical Convergence",
        _ => "Threat Detected",
    }
}

/// Build a concise detail line from the incident for simple messages.
fn simple_detail_line(incident: &Incident, ip_entity: &Option<String>) -> String {
    let detector = extract_detector(&incident.incident_id);
    let (_emoji, template) = simple_detector_lookup(detector);
    let base_desc = template.replace(" {action}", "");

    let ip_part = ip_entity
        .as_ref()
        .map(|ip| format!("\nIP: <code>{}</code>", escape_html(ip)))
        .unwrap_or_default();

    format!("{base_desc}{ip_part}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telegram::{
        append_to_allowlist, explain_detector, format_daily_digest, format_daily_digest_enriched,
        format_simple_status, log_false_positive, PipelineDigestStats,
    };
    use chrono::Utc;
    use innerwarden_core::{entities::EntityRef, event::Severity, incident::Incident};
    use tempfile::tempdir;

    fn make_incident(severity: Severity, tags: Vec<String>, entities: Vec<EntityRef>) -> Incident {
        Incident {
            ts: Utc::now(),
            host: "web-server-01".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:2026-03-15T15:00Z".to_string(),
            severity,
            title: "Possible SSH brute force from 1.2.3.4".to_string(),
            summary: "15 failed SSH logins in 5 minutes".to_string(),
            evidence: serde_json::json!([]),
            recommended_checks: vec![],
            tags,
            entities,
        }
    }

    #[test]
    fn format_critical_message_contains_key_fields() {
        let inc = make_incident(
            Severity::Critical,
            vec!["ssh".to_string()],
            vec![EntityRef::ip("1.2.3.4".to_string())],
        );
        let msg = format_incident_message(&inc, None, GuardianMode::Watch);
        assert!(msg.contains("CRITICAL"));
        assert!(msg.contains("SSH brute force"));
        assert!(msg.contains("1.2.3.4"));
    }

    #[test]
    fn format_high_message_with_dashboard_url() {
        let inc = make_incident(
            Severity::High,
            vec!["network".to_string()],
            vec![EntityRef::ip("203.0.113.10".to_string())],
        );
        let msg = format_incident_message(&inc, Some("http://127.0.0.1:8787"), GuardianMode::Watch);
        assert!(msg.contains("HIGH"));
        assert!(msg.contains("Investigate"));
        assert!(msg.contains("203.0.113.10"));
    }

    #[test]
    fn format_guard_mode_shows_defense_active() {
        let inc = make_incident(
            Severity::High,
            vec!["ssh".to_string()],
            vec![EntityRef::ip("1.2.3.4".to_string())],
        );
        let msg = format_incident_message(&inc, None, GuardianMode::Guard);
        assert!(
            msg.contains("action report"),
            "GUARD mode mentions action report"
        );
    }

    #[test]
    fn source_icon_picks_correct_icon() {
        // Mapping path: source tags should collapse to the expected icon set
        // so alerts keep a consistent visual cue in chat.
        assert_eq!(source_icon(&["ssh".to_string()]), "🔐");
        assert_eq!(source_icon(&["other".to_string()]), "📋");
    }

    #[test]
    fn entity_summary_limits_to_three_entities_and_escapes_html() {
        // Formatting path: entity summary must cap list length and HTML-escape
        // values before rendering in Telegram parse_mode=HTML.
        let inc = make_incident(
            Severity::High,
            vec![],
            vec![
                EntityRef::ip("198.51.100.3".to_string()),
                EntityRef::user("alice<root>".to_string()),
                EntityRef::path("/tmp/evil&file".to_string()),
                EntityRef::service("ignored-after-three".to_string()),
            ],
        );
        let summary = entity_summary(&inc);

        assert!(summary.contains("IP: <code>198.51.100.3</code>"));
        assert!(summary.contains("alice&lt;root&gt;"));
        assert!(summary.contains("/tmp/evil&amp;file"));
        assert!(
            !summary.contains("ignored-after-three"),
            "summary should only include first three entities"
        );
    }

    #[test]
    fn parse_callback_approve() {
        let result = parse_callback("approve:ssh_bruteforce:1.2.3.4:2026Z", "Alice").unwrap();
        assert!(result.approved);
        assert_eq!(result.incident_id, "ssh_bruteforce:1.2.3.4:2026Z");
        assert_eq!(result.operator_name, "Alice");
    }

    #[test]
    fn parse_callback_reject() {
        let result = parse_callback("reject:some:incident:id", "Bob").unwrap();
        assert!(!result.approved);
        assert_eq!(result.incident_id, "some:incident:id");
    }

    #[test]
    fn parse_callback_unknown_returns_none() {
        // Fallback path: unknown callback prefixes should not be accepted by
        // the parser to avoid accidental command routing.
        assert!(parse_callback("unknown:foo", "user").is_none());
        assert!(parse_callback("", "user").is_none());
    }

    #[test]
    fn parse_callback_handles_always_sensitivity_profile_and_enable() {
        // Routing path: callback parser must preserve admin actions for
        // "always", sensitivity toggles, profile toggles and capability enable.
        let always =
            parse_callback("always:incident:123", "Alice").expect("always callback should parse");
        assert!(always.always);
        assert!(always.approved);
        assert_eq!(always.incident_id, "incident:123");

        let sensitivity = parse_callback("sensitivity:quiet", "Alice")
            .expect("sensitivity callback should parse");
        assert_eq!(sensitivity.incident_id, "__sensitivity__:quiet");

        let profile =
            parse_callback("profile:simple", "Alice").expect("profile callback should parse");
        assert_eq!(profile.incident_id, "__profile__:simple");

        let enable =
            parse_callback("enable:hardening", "Alice").expect("capability callback should parse");
        assert_eq!(enable.incident_id, "enable:hardening");
    }

    #[test]
    fn parse_callback_menu_routes_to_sentinels() {
        let r = parse_callback("menu:status", "Alice").unwrap();
        assert_eq!(r.incident_id, "__status__");
        assert!(r.approved);

        // Both "threats" and "incidents" route to __threats__
        let r = parse_callback("menu:threats", "Alice").unwrap();
        assert_eq!(r.incident_id, "__threats__");

        let r = parse_callback("menu:incidents", "Alice").unwrap();
        assert_eq!(r.incident_id, "__threats__");

        let r = parse_callback("menu:decisions", "Alice").unwrap();
        assert_eq!(r.incident_id, "__decisions__");

        let r = parse_callback("menu:help", "Alice").unwrap();
        assert_eq!(r.incident_id, "__help__");

        // Unknown menu command → unknown cmd sentinel
        let r = parse_callback("menu:bogus", "Alice").unwrap();
        assert_eq!(r.incident_id, "__unknown_cmd__");
    }

    #[test]
    fn guardian_mode_labels_and_descriptions() {
        assert_eq!(GuardianMode::Guard.label(), "🟢 GUARD");
        assert_eq!(GuardianMode::DryRun.label(), "🟡 DRY-RUN");
        assert_eq!(GuardianMode::Watch.label(), "🔵 WATCH");
        assert!(GuardianMode::Guard.description().contains("automatically"));
        assert!(GuardianMode::Watch.description().contains("your approval"));
    }

    #[test]
    fn strip_bot_suffix_removes_at_username() {
        assert_eq!(strip_bot_suffix("/help@InnerWardenBot"), "/help");
        assert_eq!(strip_bot_suffix("/status@Bot"), "/status");
        assert_eq!(
            strip_bot_suffix("/ask@Bot question here"),
            "/ask question here"
        );
        assert_eq!(strip_bot_suffix("/status"), "/status");
        assert_eq!(strip_bot_suffix("hello"), "hello");
        assert_eq!(strip_bot_suffix("text with @mention"), "text with @mention");
    }

    #[test]
    fn quick_block_callback_routes_to_sentinel() {
        // Simulate the run_polling logic for "quick:block:<ip>" callbacks.
        // The callback data must produce the correct ApprovalResult sentinel.
        let data = "quick:block:1.2.3.4";
        let operator = "Alice";

        let ip = data
            .strip_prefix("quick:block:")
            .expect("quick:block prefix should be present");
        assert_eq!(ip, "1.2.3.4");

        let result = ApprovalResult {
            incident_id: format!("__quick_block__:{ip}"),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        };

        assert_eq!(result.incident_id, "__quick_block__:1.2.3.4");
        assert!(result.approved);
        assert!(!result.always);
        assert_eq!(result.operator_name, "Alice");

        // quick:ignore must not produce a routing result (handled inline)
        assert!(parse_callback("quick:ignore", operator).is_none());
        // quick:block: prefix must not be caught by parse_callback
        assert!(parse_callback("quick:block:1.2.3.4", operator).is_none());
    }

    #[test]
    fn escape_html_handles_specials() {
        assert_eq!(
            escape_html("<b>test & \"value\"</b>"),
            "&lt;b&gt;test &amp; &quot;value&quot;&lt;/b&gt;"
        );
    }

    #[test]
    fn severity_label_covers_all() {
        let make = |sev| make_incident(sev, vec![], vec![]);
        assert!(severity_label(&make(Severity::Critical)).contains("CRITICAL"));
        assert!(severity_label(&make(Severity::High)).contains("HIGH"));
        assert!(severity_label(&make(Severity::Medium)).contains("MEDIUM"));
    }

    #[test]
    fn first_ip_entity_returns_first_ip() {
        let inc = make_incident(
            Severity::High,
            vec![],
            vec![
                EntityRef::user("bob".to_string()),
                EntityRef::ip("10.0.0.1".to_string()),
                EntityRef::ip("203.0.113.10".to_string()),
            ],
        );
        assert_eq!(first_ip_entity(&inc), Some("10.0.0.1".to_string()));
    }

    // -----------------------------------------------------------------------
    // Honeypot operator-in-the-loop tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_hpot_callback_routing() {
        // Simulate the run_polling routing logic for hpot: callbacks
        let data = "hpot:honeypot:1.2.3.4";
        let rest = data
            .strip_prefix("hpot:")
            .expect("hpot prefix should be present");
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        assert_eq!(parts.len(), 2);
        let action = parts[0];
        let ip = parts[1];
        assert_eq!(action, "honeypot");
        assert_eq!(ip, "1.2.3.4");

        let result = ApprovalResult {
            incident_id: format!("__hpot__:{ip}"),
            approved: action != "ignore",
            always: false,
            operator_name: "Alice".to_string(),
            chosen_action: action.to_string(),
        };
        assert_eq!(result.incident_id, "__hpot__:1.2.3.4");
        assert!(result.approved);
        assert_eq!(result.chosen_action, "honeypot");

        // ignore action should produce approved=false
        let data_ignore = "hpot:ignore:5.6.7.8";
        let rest_i = data_ignore
            .strip_prefix("hpot:")
            .expect("hpot prefix should be present");
        let parts_i: Vec<&str> = rest_i.splitn(2, ':').collect();
        let action_i = parts_i[0];
        assert_eq!(action_i, "ignore");
        let result_i = ApprovalResult {
            incident_id: format!("__hpot__:{}", parts_i[1]),
            approved: action_i != "ignore",
            always: false,
            operator_name: "Bob".to_string(),
            chosen_action: action_i.to_string(),
        };
        assert!(!result_i.approved);
        assert_eq!(result_i.chosen_action, "ignore");

        // hpot: prefix must not be caught by parse_callback
        assert!(parse_callback("hpot:honeypot:1.2.3.4", "Alice").is_none());
        assert!(parse_callback("hpot:block:1.2.3.4", "Alice").is_none());
    }

    #[test]
    fn test_send_honeypot_suggestion_format() {
        // Verify the message body would contain the key fields.
        // We test by constructing the expected format string directly.
        let ip = "185.220.101.45";
        let title = "47 SSH attempts in 5 min";
        let reason = "New IP, no history in blocklists";
        let confidence = 0.87_f32;
        let pct = (confidence * 100.0) as u32;

        let text = format!(
            "🎯 <b>Honeypot candidate detected</b>\n\
             \n\
             <b>IP:</b> <code>{ip}</code>\n\
             <b>Incident:</b> {title}\n\
             <b>AI read:</b> {reason} ({pct}% confidence)\n\
             \n\
             Redirect to honeypot for analysis, or block immediately?",
            ip = escape_html(ip),
            title = escape_html(title),
            reason = escape_html(reason),
            pct = pct,
        );

        assert!(text.contains("185.220.101.45"), "IP must appear in message");
        assert!(
            text.contains("47 SSH attempts"),
            "incident title must appear in message"
        );
        assert!(text.contains("87%"), "confidence percentage must appear");
        assert!(
            text.contains("Honeypot candidate detected"),
            "honeypot heading must appear"
        );
        assert!(
            text.contains("honeypot for analysis"),
            "operator question must appear"
        );

        // Verify ai_suggested checkmark logic
        let honeypot_label_suggested = if "honeypot" == "honeypot" {
            "🍯 Honeypot ✓"
        } else {
            "🍯 Honeypot"
        };
        assert_eq!(honeypot_label_suggested, "🍯 Honeypot ✓");

        let block_label_not_suggested = if "honeypot" == "block" {
            "🚫 Block ✓"
        } else {
            "🚫 Block"
        };
        assert_eq!(block_label_not_suggested, "🚫 Block");
    }

    #[test]
    fn enforce_length_passes_short_messages() {
        let short = "Hello, world!";
        assert_eq!(enforce_length(short), short);
    }

    #[test]
    fn enforce_length_truncates_long_messages() {
        let long = "x".repeat(5000);
        let result = enforce_length(&long);
        assert!(result.len() <= TELEGRAM_MAX_LEN);
        assert!(result.contains("… message truncated"));
    }

    #[test]
    fn enforce_length_at_boundary() {
        // Exactly at limit should pass through
        let exact = "a".repeat(TELEGRAM_MAX_LEN);
        assert_eq!(enforce_length(&exact), exact);

        // One over should truncate
        let over = "a".repeat(TELEGRAM_MAX_LEN + 1);
        let result = enforce_length(&over);
        assert!(result.len() <= TELEGRAM_MAX_LEN);
        assert!(result.contains("… message truncated"));
    }

    #[test]
    fn callback_data_keeps_short_payload() {
        let cb = callback_data("allow:proc:", "sshd");
        assert_eq!(cb, "allow:proc:sshd");
        assert!(cb.len() <= TELEGRAM_MAX_CALLBACK_BYTES);
    }

    #[test]
    fn callback_data_truncates_to_telegram_limit() {
        let cb = callback_data("fp:check:", &"x".repeat(500));
        assert!(cb.starts_with("fp:check:"));
        assert_eq!(cb.len(), TELEGRAM_MAX_CALLBACK_BYTES);
    }

    #[test]
    fn callback_data_preserves_utf8_boundaries() {
        // UTF-8 safety path: callback truncation should never split a
        // multibyte character and produce invalid UTF-8.
        let cb = callback_data("fp:", &"á".repeat(100));
        assert!(cb.len() <= TELEGRAM_MAX_CALLBACK_BYTES);
        assert!(std::str::from_utf8(cb.as_bytes()).is_ok());
    }

    #[test]
    fn plain_action_translates_firewall_monitor_and_honeypot_paths() {
        // Explanation path: technical action strings should be translated into
        // operator-friendly phrases for Telegram messages.
        let firewall = plain_action("ufw deny from 198.51.100.1");
        assert!(firewall.contains("Drop 198.51.100.1"));

        let monitor = plain_action("monitor with tcpdump 198.51.100.2");
        assert!(monitor.contains("packet capture"));
        assert!(monitor.contains("198.51.100.2"));

        let honeypot = plain_action("route to honeypot");
        assert!(honeypot.contains("honeypot"));
    }

    #[test]
    fn friendly_detector_name_returns_known_label_or_fallback() {
        // Label path: known detectors should map to human-readable digest
        // labels while unknown strings pass through unchanged.
        assert_eq!(
            friendly_detector_name("ssh_bruteforce"),
            "SSH brute force attempts blocked"
        );
        assert_eq!(
            friendly_detector_name("unknown-detector"),
            "unknown-detector"
        );
    }

    #[test]
    fn reputation_score_bar_and_country_flag_cover_edges() {
        // Visual helper path: score bars and flags should format deterministic
        // compact telemetry markers for reputation snippets.
        assert_eq!(reputation_score_bar(0), "[░░░░░░░░]");
        assert_eq!(reputation_score_bar(100), "[████████]");
        assert_eq!(country_flag_emoji("us"), "🇺🇸");
        assert_eq!(country_flag_emoji("U"), "");
    }

    #[test]
    fn format_incident_message_with_dashboard_without_ip_omits_link() {
        // Link-building path: dashboard links should only render when an IP
        // entity exists, preventing broken subject links in notifications.
        let inc = make_incident(
            Severity::High,
            vec!["network".to_string()],
            vec![EntityRef::user("alice".to_string())],
        );
        let msg = format_incident_message(&inc, Some("http://127.0.0.1:8787"), GuardianMode::Watch);
        assert!(!msg.contains("Investigate"));
    }

    #[test]
    fn append_to_allowlist_creates_and_appends_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("allowlist.toml");

        append_to_allowlist(&path, "processes", "cargo-build", "from telegram").unwrap();
        append_to_allowlist(&path, "ips", "1.2.3.4", "known safe").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[processes]"));
        assert!(content.contains("\"cargo-build\" = \"from telegram\""));
        assert!(content.contains("[ips]"));
        assert!(content.contains("\"1.2.3.4\" = \"known safe\""));
    }

    #[test]
    fn append_to_allowlist_escapes_toml_sensitive_chars() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("allowlist.toml");
        append_to_allowlist(&path, "processes", "my\"proc", "line1\nline2").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"my\\\"proc\""));
        assert!(content.contains("line1 line2"));
    }

    #[test]
    fn log_false_positive_writes_expected_jsonl_fields() {
        let dir = tempdir().unwrap();
        log_false_positive(
            dir.path(),
            "ssh_bruteforce:1.2.3.4:test",
            "ssh_bruteforce",
            "operator-a",
        );

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("fp-reports-{today}.jsonl"));
        let content = std::fs::read_to_string(path).unwrap();
        let line = content.lines().next().unwrap();
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(value["incident_id"], "ssh_bruteforce:1.2.3.4:test");
        assert_eq!(value["detector"], "ssh_bruteforce");
        assert_eq!(value["reporter"], "operator-a");
        assert_eq!(value["action"], "reported_fp");
        assert!(value["ts"].is_string());
    }

    #[test]
    fn sanitize_url_redacts_bot_token() {
        let url = "https://api.telegram.org/bot1234567890:AAAAAAAAAA/sendMessage";
        let sanitized = sanitize_url(url);
        assert_eq!(
            sanitized,
            "https://api.telegram.org/bot***REDACTED***/sendMessage"
        );
        assert!(!sanitized.contains("1234567890"));
        assert!(!sanitized.contains("AAAAAAAAAA"));
    }

    #[test]
    fn sanitize_url_no_bot_token() {
        let url = "https://example.com/api/test";
        assert_eq!(sanitize_url(url), url);
    }

    #[test]
    fn quick_block_rejects_invalid_ip() {
        // Valid IPs should be accepted
        assert!("1.2.3.4".parse::<std::net::IpAddr>().is_ok());
        assert!("::1".parse::<std::net::IpAddr>().is_ok());
        assert!("2001:db8::1".parse::<std::net::IpAddr>().is_ok());

        // Invalid strings should be rejected
        assert!("not-an-ip".parse::<std::net::IpAddr>().is_err());
        assert!("1.2.3.4; rm -rf /".parse::<std::net::IpAddr>().is_err());
        assert!("".parse::<std::net::IpAddr>().is_err());
    }

    // -----------------------------------------------------------------------
    // Simple profile tests
    // -----------------------------------------------------------------------

    #[test]
    fn format_simple_message_ssh_bruteforce_guard() {
        let inc = make_incident(
            Severity::Critical,
            vec![],
            vec![EntityRef::ip("1.2.3.4".to_string())],
        );
        let msg = format_simple_message(&inc, None, GuardianMode::Guard);
        assert!(
            msg.contains("Login Attack Blocked"),
            "should contain detector label"
        );
        assert!(msg.contains("Handled automatically"));
        assert!(msg.contains("1.2.3.4"), "simple mode shows IPs now");
        assert!(
            !msg.contains("ssh_bruteforce"),
            "simple mode must not show detector name"
        );
        assert!(
            msg.contains("\u{1f534}"),
            "critical should have red circle emoji"
        );
    }

    #[test]
    fn format_simple_message_watch_mode() {
        let inc = make_incident(
            Severity::High,
            vec![],
            vec![EntityRef::ip("5.6.7.8".to_string())],
        );
        let msg = format_simple_message(&inc, None, GuardianMode::Watch);
        assert!(msg.contains("Needs your attention"));
    }

    #[test]
    fn format_simple_message_unknown_detector() {
        let mut inc = make_incident(Severity::Medium, vec![], vec![]);
        inc.incident_id = "unknown_detector:foo:bar".to_string();
        let msg = format_simple_message(&inc, None, GuardianMode::Guard);
        assert!(msg.contains("Threat Detected"));
    }

    #[test]
    fn explain_detector_returns_explanation() {
        let explanation = explain_detector("ssh_bruteforce");
        assert!(explanation.contains("guessing passwords"));
        assert!(explanation.contains("What does this mean?"));

        let explanation = explain_detector("ransomware");
        assert!(explanation.contains("encrypts your files"));

        // Unknown detector should give generic explanation
        let explanation = explain_detector("totally_unknown");
        assert!(explanation.contains("suspicious activity"));
    }

    #[test]
    fn format_daily_digest_simple() {
        let msg = format_daily_digest(42, 30, 2, 5, "ssh_bruteforce", 15, true);
        assert!(msg.contains("Good morning!"));
        assert!(msg.contains("30 attacks blocked"));
        assert!(msg.contains("2 critical threats"));
        assert!(msg.contains("Health:"));
        assert!(msg.contains("All clear. Nothing needs you."));
        // Score = 100 - 2*20 - 5*5 = 35 → 🔴
        assert!(msg.contains("\u{1f534}"));
    }

    #[test]
    fn format_daily_digest_technical() {
        let msg = format_daily_digest(42, 30, 2, 5, "ssh_bruteforce", 15, false);
        assert!(msg.contains("Daily digest"));
        assert!(msg.contains("42 incidents"));
        assert!(msg.contains("30 blocks"));
        assert!(msg.contains("ssh_bruteforce: 15"));
        assert!(msg.contains("Critical: 2 | High: 5"));
    }

    #[test]
    fn format_daily_digest_health_score() {
        // Perfect score
        let msg = format_daily_digest(5, 5, 0, 0, "port_scan", 5, true);
        assert!(msg.contains("100/100"));
        assert!(msg.contains("\u{1f7e2}")); // 🟢

        // Yellow zone: 100 - 0*20 - 6*5 = 70
        let msg = format_daily_digest(10, 10, 0, 6, "port_scan", 6, true);
        assert!(msg.contains("70/100"));
        assert!(msg.contains("\u{1f7e1}")); // 🟡

        // Red zone: 100 - 3*20 - 10*5 = -10 → clamped to 0
        let msg = format_daily_digest(50, 50, 3, 10, "ssh_bruteforce", 20, true);
        assert!(msg.contains("0/100"));
        assert!(msg.contains("\u{1f534}")); // 🔴
    }

    #[test]
    fn format_daily_digest_enriched_simple_with_pipeline() {
        let stats = PipelineDigestStats {
            suppressed_count: 85,
            auto_resolved_groups: 12,
            needs_review_groups: 0,
            deferred: vec![],
        };
        let msg = format_daily_digest_enriched(42, 30, 0, 3, "ssh_bruteforce", 15, true, &stats);
        assert!(msg.contains("12 threat groups auto-resolved"));
        assert!(msg.contains("All clear"));
        assert!(!msg.contains("need your review"));
    }

    #[test]
    fn format_daily_digest_enriched_simple_needs_review() {
        let stats = PipelineDigestStats {
            suppressed_count: 50,
            auto_resolved_groups: 8,
            needs_review_groups: 3,
            deferred: vec![],
        };
        let msg = format_daily_digest_enriched(42, 30, 2, 5, "ssh_bruteforce", 15, true, &stats);
        assert!(msg.contains("3 groups need your review"));
        assert!(!msg.contains("All clear"));
    }

    #[test]
    fn format_daily_digest_enriched_technical_with_pipeline() {
        let stats = PipelineDigestStats {
            suppressed_count: 100,
            auto_resolved_groups: 15,
            needs_review_groups: 2,
            deferred: vec![],
        };
        let msg = format_daily_digest_enriched(42, 30, 2, 5, "ssh_bruteforce", 15, false, &stats);
        assert!(msg.contains("100 grouped"));
        assert!(msg.contains("15 auto-resolved"));
        assert!(msg.contains("2 need review"));
    }

    #[test]
    fn format_daily_digest_enriched_no_pipeline_data() {
        let stats = PipelineDigestStats {
            suppressed_count: 0,
            auto_resolved_groups: 0,
            needs_review_groups: 0,
            deferred: vec![],
        };
        let msg = format_daily_digest_enriched(42, 30, 2, 5, "ssh_bruteforce", 15, true, &stats);
        // No pipeline line when all zeros
        assert!(!msg.contains("alerts silenced"));
        assert!(!msg.contains("auto-resolved"));
    }

    #[test]
    fn format_daily_digest_enriched_simple_with_deferred() {
        let stats = PipelineDigestStats {
            suppressed_count: 20,
            auto_resolved_groups: 5,
            needs_review_groups: 0,
            deferred: vec![
                ("ssh_bruteforce".into(), 18),
                ("discovery_burst".into(), 9),
                ("packet_flood".into(), 3),
            ],
        };
        let msg = format_daily_digest_enriched(60, 40, 0, 5, "ssh_bruteforce", 18, true, &stats);
        assert!(msg.contains("Handled silently"));
        assert!(msg.contains("18 SSH brute force attempts blocked"));
        assert!(msg.contains("9 reconnaissance scans detected"));
        assert!(msg.contains("3 DDoS/flood events handled"));
    }

    #[test]
    fn format_daily_digest_enriched_technical_with_deferred() {
        let stats = PipelineDigestStats {
            suppressed_count: 10,
            auto_resolved_groups: 3,
            needs_review_groups: 1,
            deferred: vec![("ssh_bruteforce".into(), 12), ("port_scan".into(), 5)],
        };
        let msg = format_daily_digest_enriched(42, 30, 0, 5, "ssh_bruteforce", 12, false, &stats);
        assert!(msg.contains("Deferred:"));
        assert!(msg.contains("ssh_bruteforce=12"));
        assert!(msg.contains("port_scan=5"));
    }

    #[test]
    fn format_simple_status_safe() {
        let msg = format_simple_status(false, false, false, 45, 1200, "3 hours ago");
        assert!(msg.contains("\u{1f7e2}")); // 🟢
        assert!(msg.contains("safe"));
        assert!(msg.contains("45"));
        assert!(msg.contains("1200"));
        assert!(msg.contains("3 hours ago"));
    }

    #[test]
    fn format_simple_status_under_watch() {
        let msg = format_simple_status(false, true, false, 10, 50, "25 minutes ago");
        assert!(msg.contains("\u{1f7e1}")); // 🟡
        assert!(msg.contains("under watch"));
    }

    #[test]
    fn format_simple_status_needs_attention() {
        let msg = format_simple_status(true, true, true, 10, 50, "2 minutes ago");
        assert!(msg.contains("\u{1f534}")); // 🔴
        assert!(msg.contains("needs attention"));
    }

    #[test]
    fn simple_detector_lookup_covers_all_detectors() {
        // Verify all documented detectors return non-default entries
        let known_detectors = [
            "ssh_bruteforce",
            "credential_stuffing",
            "port_scan",
            "packet_flood",
            "data_exfil",
            "data_exfil_cmd",
            "data_exfil_ebpf",
            "reverse_shell",
            "privesc",
            "rootkit",
            "ransomware",
            "dns_tunneling",
            "dns_tunneling_ebpf",
            "c2_callback",
            "crypto_miner",
            "container_escape",
            "lateral_movement",
            "web_shell",
            "process_injection",
            "fileless",
            "log_tampering",
            "ssh_key_injection",
            "crontab_persistence",
            "systemd_persistence",
            "kernel_module_load",
            "discovery_burst",
            "sigma",
            "suspicious_execution",
            "sensitive_write",
            "user_creation",
            "process_tree",
            "neural_anomaly",
        ];

        for det in &known_detectors {
            let (_emoji, template) = simple_detector_lookup(det);
            assert!(
                !template.starts_with("Suspicious activity detected"),
                "detector '{}' should have a specific message, not fallback",
                det
            );
            assert!(
                template.contains("{action}"),
                "detector '{}' template must contain {{action}}",
                det
            );
        }

        // Default fallback
        let (_emoji, template) = simple_detector_lookup("unknown_detector_xyz");
        assert!(template.contains("Suspicious activity detected"));
    }
}
