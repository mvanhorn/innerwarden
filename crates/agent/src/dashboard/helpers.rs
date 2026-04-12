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
    let mut has_monitoring = false;
    let mut has_honeypot = false;
    let mut has_dismissed = false;
    let mut has_active = false;

    for ip in ips {
        match determine_outcome(decisions, ip, has_incident).as_str() {
            "blocked" => return "blocked".to_string(),
            "honeypot" => has_honeypot = true,
            "monitoring" => has_monitoring = true,
            "dismissed" => has_dismissed = true,
            "active" => has_active = true,
            _ => {}
        }
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
            && d.execution_result.contains("ok")
        {
            return "blocked".to_string();
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
