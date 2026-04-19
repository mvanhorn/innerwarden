// Auto-extracted from mod.rs — dashboard helpers handlers.
//
// Several of the JSONL-based helpers in this file (incident_detector,
// extract_ip_entities, determine_outcome, dated_path, etc.) are only
// exercised by the `#[cfg(test)] mod tests` in `dashboard/mod.rs` and by
// the legacy `build_*` fallback functions in `dashboard/investigation.rs`
// which are themselves only reached through test fixtures now that the
// live dashboard reads from the knowledge graph (Phase 6/7). They are
// retained to keep that legacy test coverage wired up until spec 016
// deprecates the JSONL path entirely.
#![allow(dead_code)]

use super::*;

pub(super) fn safe_read_data_file(data_dir: &Path, filename: &str) -> Option<String> {
    let base = data_dir.canonicalize().ok()?;
    let target = data_dir.join(filename);
    // File might not exist yet — canonicalize fails for missing files.
    // In that case, verify the parent dir is safe and the filename is simple.
    if let Ok(canonical) = target.canonicalize() {
        if !canonical.starts_with(&base) {
            return None; // path traversal attempt
        }
        std::fs::read_to_string(canonical).ok()
    } else {
        // File doesn't exist — that's OK (return None, caller handles default)
        None
    }
}

/// Write a file safely inside data_dir (prevents path traversal).
pub(super) fn safe_write_data_file(data_dir: &Path, filename: &str, contents: &str) -> bool {
    // Only allow simple filenames (no slashes, no ..)
    if filename.contains('/') || filename.contains("..") {
        return false;
    }
    let Some(base) = data_dir.canonicalize().ok() else {
        return false;
    };
    let target = base.join(filename);
    if !target.starts_with(&base) {
        return false;
    }
    std::fs::write(target, contents).is_ok()
}
pub(super) fn extract_ip_entities(
    entities: &[innerwarden_core::entities::EntityRef],
) -> Vec<String> {
    extract_entity_values(entities, EntityType::Ip)
}

pub(super) fn extract_entity_values(
    entities: &[innerwarden_core::entities::EntityRef],
    entity_type: EntityType,
) -> Vec<String> {
    entities
        .iter()
        .filter(|e| e.r#type == entity_type)
        .map(|e| e.value.clone())
        .collect()
}

pub(super) fn incident_detector(incident_id: &str) -> String {
    incident_id
        .split(':')
        .next()
        .unwrap_or("unknown")
        .to_string()
}

pub(super) fn incident_matches_filters(
    incident: &innerwarden_core::incident::Incident,
    filters: &InvestigationFilters,
) -> bool {
    if let Some(min) = filters.severity_min {
        let sev = severity_order(&format!("{:?}", incident.severity).to_lowercase());
        if sev < min {
            return false;
        }
    }
    if let Some(detector) = &filters.detector {
        if incident_detector(&incident.incident_id) != *detector {
            return false;
        }
    }
    true
}

pub(super) fn event_matches_filters(
    event: &innerwarden_core::event::Event,
    filters: &InvestigationFilters,
) -> bool {
    if let Some(min) = filters.severity_min {
        let sev = severity_order(&format!("{:?}", event.severity).to_lowercase());
        if sev < min {
            return false;
        }
    }
    true
}

pub(super) fn incident_group_values(
    incident: &innerwarden_core::incident::Incident,
    group_by: PivotKind,
) -> Vec<String> {
    match group_by {
        PivotKind::Ip => extract_entity_values(&incident.entities, EntityType::Ip),
        PivotKind::User => extract_entity_values(&incident.entities, EntityType::User),
        PivotKind::Detector => vec![incident_detector(&incident.incident_id)],
    }
}

pub(super) fn event_group_values(
    event: &innerwarden_core::event::Event,
    group_by: PivotKind,
) -> Vec<String> {
    match group_by {
        PivotKind::Ip => extract_entity_values(&event.entities, EntityType::Ip),
        PivotKind::User => extract_entity_values(&event.entities, EntityType::User),
        PivotKind::Detector => Vec::new(),
    }
}

pub(super) fn incident_matches_subject(
    incident: &innerwarden_core::incident::Incident,
    subject_type: PivotKind,
    subject: &str,
) -> bool {
    match subject_type {
        PivotKind::Ip => extract_entity_values(&incident.entities, EntityType::Ip)
            .iter()
            .any(|ip| ip == subject),
        PivotKind::User => extract_entity_values(&incident.entities, EntityType::User)
            .iter()
            .any(|user| user == subject),
        PivotKind::Detector => incident_detector(&incident.incident_id) == subject,
    }
}

pub(super) fn has_intersection(values: &[String], set: &BTreeSet<String>) -> bool {
    values.iter().any(|v| set.contains(v))
}

pub(super) fn determine_outcome_for_ips(
    decisions: &[DecisionEntry],
    ips: &BTreeSet<String>,
    has_incident: bool,
) -> String {
    let mut has_escalated = false;
    let mut has_monitoring = false;
    let mut has_honeypot = false;
    let mut has_dismissed = false;
    let mut has_active = false;

    for ip in ips {
        match determine_outcome(decisions, ip, has_incident).as_str() {
            "blocked" => return "blocked".to_string(),
            "escalated" => has_escalated = true,
            "honeypot" => has_honeypot = true,
            "monitoring" => has_monitoring = true,
            "dismissed" => has_dismissed = true,
            "active" => has_active = true,
            _ => {}
        }
    }

    // Spec 028-c: escalated wins over monitoring/honeypot/dismissed when
    // aggregating across multiple IPs because escalate-without-resolution is
    // the strongest "still needs action" signal short of a permanent block.
    if has_escalated {
        return "escalated".to_string();
    }
    if has_honeypot {
        return "honeypot".to_string();
    }
    if has_monitoring {
        return "monitoring".to_string();
    }
    if has_active {
        return "active".to_string();
    }
    if has_dismissed {
        return "dismissed".to_string();
    }
    if has_incident {
        return "active".to_string();
    }
    "unknown".to_string()
}

/// Determine the outcome for an IP given the full decisions list and whether
/// it has at least one incident.
///
/// Precedence: blocked (permanent) > escalated (needs attention) > monitoring >
/// honeypot > dismissed > active > unknown.
///
/// Spec 028-c added `escalated`: IPs whose most impactful decision is an
/// "escalate" label (written by observation-verify when the Fase 3 scorer
/// returns VerificationResult::Escalate) surface as their own outcome rather
/// than sitting under `active`, so the dashboard can route them to the "needs
/// attention" bucket.
pub(super) fn determine_outcome(
    decisions: &[DecisionEntry],
    ip: &str,
    has_incident: bool,
) -> String {
    let ip_decisions: Vec<&DecisionEntry> = decisions
        .iter()
        .filter(|d| d.target_ip.as_deref() == Some(ip))
        .collect();

    for d in &ip_decisions {
        if d.action_type == "block_ip"
            && d.auto_executed
            && !d.dry_run
            && (d.execution_result.contains("ok") || d.execution_result.starts_with("Blocked"))
        {
            return "blocked".to_string();
        }
    }
    // Spec 028-c: escalate wins over monitor/honeypot/dismiss because an
    // escalated incident without a resolving decision is explicitly the
    // "needs your attention" state. Only a real block (above) supersedes.
    for d in &ip_decisions {
        if d.action_type == "escalate" {
            return "escalated".to_string();
        }
    }
    for d in &ip_decisions {
        if d.action_type == "monitor" && d.auto_executed && !d.dry_run {
            return "monitoring".to_string();
        }
    }
    for d in &ip_decisions {
        if d.action_type == "honeypot" && d.auto_executed && !d.dry_run {
            return "honeypot".to_string();
        }
    }
    for d in &ip_decisions {
        if (d.action_type == "dismiss" || d.action_type == "ignore") && d.auto_executed {
            return "dismissed".to_string();
        }
    }
    if has_incident {
        return "active".to_string();
    }
    "unknown".to_string()
}

pub(super) fn resolve_date(raw: Option<&str>) -> String {
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let Some(candidate) = raw else {
        return today;
    };
    if candidate.len() != 10 {
        return today;
    }
    if chrono::NaiveDate::parse_from_str(candidate, "%Y-%m-%d").is_ok() {
        return candidate.to_string();
    }
    today
}

pub(super) fn normalize_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(50).clamp(1, 500)
}

/// Build a dated JSONL path, rejecting any path-traversal attempts.
/// Only allows YYYY-MM-DD date strings (already validated by resolve_date).
pub(super) fn dated_path(data_dir: &Path, prefix: &str, date: &str) -> PathBuf {
    // Defense-in-depth: strip any path separators or dots from date
    let safe_date: String = date
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    let filename = format!("{prefix}-{safe_date}.jsonl");
    // Ensure filename has no path components
    let safe_filename = Path::new(&filename)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    data_dir.join(safe_filename)
}

/// File content cache entry - avoids re-reading + re-parsing JSONL on every request.
pub(super) struct FileCache {
    raw: String,
    size: u64,
    modified: std::time::SystemTime,
    cached_at: std::time::Instant,
}

/// Global JSONL file cache. Key: file path string. TTL: 5 seconds.
/// Under bot attack, this prevents hundreds of file reads per second.
pub(super) static JSONL_CACHE: LazyLock<Mutex<HashMap<String, FileCache>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) const JSONL_CACHE_TTL_SECS: u64 = 5;

pub(super) fn read_jsonl<T: DeserializeOwned>(path: &Path) -> Vec<T> {
    let key = path.to_string_lossy().to_string();

    // Check cache first
    let meta = std::fs::metadata(path).ok();
    let file_size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
    let file_modified = meta
        .as_ref()
        .and_then(|m| m.modified().ok())
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

    {
        let cache = JSONL_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache.get(&key) {
            if entry.size == file_size
                && entry.modified == file_modified
                && entry.cached_at.elapsed().as_secs() < JSONL_CACHE_TTL_SECS
            {
                // Cache hit - parse from cached string (avoids file I/O)
                return entry
                    .raw
                    .lines()
                    .filter_map(|line| {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            return None;
                        }
                        serde_json::from_str::<T>(trimmed).ok()
                    })
                    .collect();
            }
        }
    }

    // Cache miss - read only the tail of the file (last 256KB ≈ 500 entries).
    // Dashboard lists show max 50-100 items; reading the full file wastes memory.
    pub(super) const MAX_READ_BYTES: u64 = 256 * 1024;
    let content = if file_size > MAX_READ_BYTES {
        match std::fs::File::open(path) {
            Ok(mut f) => {
                use std::io::{Read, Seek, SeekFrom};
                let _ = f.seek(SeekFrom::End(-(MAX_READ_BYTES as i64)));
                let mut buf = String::with_capacity(MAX_READ_BYTES as usize);
                let _ = f.read_to_string(&mut buf);
                // Drop the first (possibly partial) line
                if let Some(pos) = buf.find('\n') {
                    buf.drain(..=pos);
                }
                buf
            }
            Err(_) => return Vec::new(),
        }
    } else {
        match std::fs::read_to_string(path) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        }
    };

    let result = content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            match serde_json::from_str::<T>(trimmed) {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "dashboard: skipping malformed JSONL line"
                    );
                    None
                }
            }
        })
        .collect();

    // Store in cache (only cache small results)
    if content.len() < 512 * 1024 {
        let mut cache = JSONL_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        // Prune stale entries
        if cache.len() > 20 {
            cache.retain(|_, v| v.cached_at.elapsed().as_secs() < JSONL_CACHE_TTL_SECS * 2);
        }
        cache.insert(
            key,
            FileCache {
                raw: content,
                size: file_size,
                modified: file_modified,
                cached_at: std::time::Instant::now(),
            },
        );
    }

    result
}

// ---------------------------------------------------------------------------
// Formatting & Escaping Helpers
// ---------------------------------------------------------------------------

pub(crate) fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len() + 10);
    for c in input.chars() {
        match c {
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '&' => escaped.push_str("&amp;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            '/' => escaped.push_str("&#x2F;"),
            // Null bytes or non-printable chars can be wiped
            '\0' => escaped.push_str(""),
            _ => escaped.push(c),
        }
    }
    escaped
}

pub(crate) fn format_size(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        return format!("{:.1} GB", bytes as f64 / 1_073_741_824.0);
    }
    if bytes >= 1_048_576 {
        return format!("{:.1} MB", bytes as f64 / 1_048_576.0);
    }
    if bytes >= 1024 {
        return format!("{:.1} KB", bytes as f64 / 1024.0);
    }
    format!("{} B", bytes)
}

pub(crate) fn format_duration(secs: u64) -> String {
    if secs < 60 {
        return format!("{}s", secs);
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{}m {}s", mins, secs % 60);
    }
    format!("{}h {}m", mins / 60, mins % 60)
}

pub(crate) fn truncate_ip(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        format!("{}.{}.x.x", parts[0], parts[1])
    } else {
        // Fallback or IPv6
        let chars: Vec<char> = ip.chars().collect();
        if chars.len() > 10 {
            let truncated: String = chars[0..8].iter().collect();
            format!("{}...", truncated)
        } else {
            ip.to_string()
        }
    }
}

pub(crate) fn format_percentage(value: f64) -> String {
    format!("{:.1}%", value)
}

pub(crate) fn format_timestamp(ts: chrono::DateTime<chrono::Utc>) -> String {
    ts.format("%Y-%m-%d %H:%M:%S").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_html_prevents_xss() {
        // Basic script injection
        let payload_1 = "<script>alert('xss')</script>";
        let esc_1 = escape_html(payload_1);
        assert_eq!(
            esc_1,
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;&#x2F;script&gt;"
        );

        // Quotes bounding evasion
        let payload_2 = "\" onmouseover=\"alert(1)\"";
        let esc_2 = escape_html(payload_2);
        assert_eq!(esc_2, "&quot; onmouseover=&quot;alert(1)&quot;");

        // Null bytes
        let payload_3 = "test\0test";
        let esc_3 = escape_html(payload_3);
        assert_eq!(esc_3, "testtest");

        // Ampersand double-escape injection verification
        let payload_4 = "a & b &amp; c";
        let esc_4 = escape_html(payload_4);
        assert_eq!(esc_4, "a &amp; b &amp;amp; c");
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1500), "1.5 KB");
        assert_eq!(format_size(1_500_000), "1.4 MB");
        assert_eq!(format_size(2_500_000_000), "2.3 GB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(125), "2m 5s");
        assert_eq!(format_duration(3600), "1h 0m");
        assert_eq!(format_duration(3665), "1h 1m");
    }

    #[test]
    fn test_truncate_ip() {
        assert_eq!(truncate_ip("192.168.1.5"), "192.168.x.x");
        assert_eq!(truncate_ip("10.0.0.1"), "10.0.x.x");
        // IPv6 truncates to length
        assert_eq!(
            truncate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            "2001:0db..."
        );
        // Short domains
        assert_eq!(truncate_ip("localhost"), "localhost");
    }

    #[test]
    fn test_format_percentage() {
        assert_eq!(format_percentage(85.45), "85.5%");
        assert_eq!(format_percentage(100.0), "100.0%");
    }

    #[test]
    fn test_escape_html_advanced() {
        assert_eq!(escape_html(""), "", "empty string");
        assert_eq!(
            escape_html("🔥 Unicode test"),
            "🔥 Unicode test",
            "Unicode untouched"
        );
        assert_eq!(
            escape_html("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;&#x2F;script&gt;"
        );
        assert_eq!(escape_html("\"quotes\""), "&quot;quotes&quot;");
        assert_eq!(escape_html("a & b"), "a &amp; b");
        assert_eq!(escape_html("null\0byte"), "nullbyte");
        let long_str = "X".repeat(10_000);
        assert_eq!(escape_html(&long_str), long_str, "10k characters scaling");
    }

    #[test]
    fn test_resolve_date_edge_cases() {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        assert_eq!(resolve_date(None), today);
        assert_eq!(resolve_date(Some("invalid-date-format")), today);
        assert_eq!(resolve_date(Some("2024-05")), today); // Incomplete
        assert_eq!(resolve_date(Some("2024-05-15")), "2024-05-15");
    }

    #[test]
    fn test_normalize_limit_bounds() {
        assert_eq!(normalize_limit(None), 50);
        assert_eq!(normalize_limit(Some(0)), 1); // clamped min
        assert_eq!(normalize_limit(Some(1000)), 500); // clamped max
        assert_eq!(normalize_limit(Some(250)), 250);
    }

    #[test]
    fn test_dated_path_generation() {
        let pb = PathBuf::from("/var/data");
        // Safe generation
        assert_eq!(
            dated_path(&pb, "incidents", "2024-05-15").to_string_lossy(),
            "/var/data/incidents-2024-05-15.jsonl"
        );
        assert_eq!(
            dated_path(&pb, "incidents", "../etc/passwd").to_string_lossy(),
            "/var/data/incidents-.jsonl" // Letters and dots removed, leaving only valid chars via filter
        );
    }

    #[test]
    fn test_incident_detector_extraction() {
        assert_eq!(incident_detector("ssh_brute_force:1234"), "ssh_brute_force");
        assert_eq!(incident_detector("no_colon_id"), "no_colon_id");
        assert_eq!(incident_detector(""), "");
    }

    #[test]
    fn test_extract_ip_entities_empty() {
        assert!(extract_ip_entities(&[]).is_empty());
    }

    #[test]
    fn test_extract_entity_values_filter() {
        use innerwarden_core::entities::{EntityRef, EntityType};
        let entities = vec![
            EntityRef {
                r#type: EntityType::Ip,
                value: "1.2.3.4".into(),
            },
            EntityRef {
                r#type: EntityType::User,
                value: "root".into(),
            },
        ];
        let ips = extract_entity_values(&entities, EntityType::Ip);
        assert_eq!(ips, vec!["1.2.3.4"]);

        let users = extract_entity_values(&entities, EntityType::User);
        assert_eq!(users, vec!["root"]);
    }

    #[test]
    fn test_has_intersection() {
        let mut set = BTreeSet::new();
        set.insert("alpha".to_string());
        set.insert("beta".to_string());

        assert!(has_intersection(&["beta".to_string()], &set));
        assert!(!has_intersection(&["gamma".to_string()], &set));
        assert!(!has_intersection(&[], &set));
    }

    #[test]
    fn test_safe_write_path_traversal() {
        // Prevents slashes and dots
        let pb = PathBuf::from("./");
        assert_eq!(safe_write_data_file(&pb, "../../etc/passwd", "test"), false);
        assert_eq!(
            safe_write_data_file(&pb, "/absolute/path.txt", "test"),
            false
        );
    }

    #[test]
    fn test_determine_outcome_for_ips_hierarchy() {
        let decisions = vec![];
        let mut ips = BTreeSet::new();
        ips.insert("1.2.3.4".to_string());

        // No decisions, no incident => unknown
        assert_eq!(
            determine_outcome_for_ips(&decisions, &ips, false),
            "unknown"
        );
        // No decisions, has incident => active
        assert_eq!(determine_outcome_for_ips(&decisions, &ips, true), "active");
    }

    // Spec 028-c: aggregating across multiple IPs, escalated wins over
    // monitoring/honeypot/dismissed as long as no blocked IP is present.
    #[test]
    fn test_determine_outcome_for_ips_escalated_wins_over_monitoring() {
        let escalated = DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: "x".into(),
            host: "h".into(),
            ai_provider: "observation-verify".into(),
            action_type: "escalate".into(),
            target_ip: Some("1.2.3.4".into()),
            target_user: None,
            skill_id: None,
            confidence: 0.8,
            auto_executed: true,
            dry_run: false,
            reason: "r".into(),
            estimated_threat: "medium".into(),
            execution_result: "pending-fase4".into(),
            prev_hash: None,
        };
        let monitor = DecisionEntry {
            ts: chrono::Utc::now(),
            incident_id: "y".into(),
            host: "h".into(),
            ai_provider: "mock".into(),
            action_type: "monitor".into(),
            target_ip: Some("5.6.7.8".into()),
            target_user: None,
            skill_id: None,
            confidence: 0.7,
            auto_executed: true,
            dry_run: false,
            reason: "r".into(),
            estimated_threat: "low".into(),
            execution_result: "ok".into(),
            prev_hash: None,
        };
        let mut ips = BTreeSet::new();
        ips.insert("1.2.3.4".into());
        ips.insert("5.6.7.8".into());
        assert_eq!(
            determine_outcome_for_ips(&[escalated, monitor], &ips, true),
            "escalated"
        );
    }

    #[test]
    fn test_format_duration_scale() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(59), "59s");
        assert_eq!(format_duration(61), "1m 1s");
        assert_eq!(format_duration(3601), "1h 0m");
    }
}
