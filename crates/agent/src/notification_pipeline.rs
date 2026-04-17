//! Notification pipeline — incident grouping, channel filtering, and digest.
//!
//! Replaces the per-channel TelegramBatcher with a unified pipeline that groups
//! incidents by detector+entity, filters per-channel by level, and builds digests.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use innerwarden_core::entities::EntityType;
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;
use serde::Serialize;

use crate::config::{ChannelFilterLevel, NotificationPipelineConfig};

// ---------------------------------------------------------------------------
// Incident Group
// ---------------------------------------------------------------------------

/// A group of related incidents (same detector + entity) within a time window.
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub(crate) struct IncidentGroup {
    pub detector: String,
    pub entity_type: EntityType,
    pub entity_value: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub count: u32,
    pub severity_max: Severity,
    pub auto_resolved: bool,
    pub sample_incident_id: String,
    /// Whether the first notification for this group has been dispatched.
    #[serde(skip)]
    first_notified: bool,
    /// Whether a count-threshold summary has already been emitted.
    #[serde(skip)]
    threshold_summary_sent: bool,
}

impl IncidentGroup {
    fn new(
        incident: &Incident,
        detector: String,
        entity_type: EntityType,
        entity_value: String,
    ) -> Self {
        Self {
            detector,
            entity_type,
            entity_value,
            first_seen: incident.ts,
            last_seen: incident.ts,
            count: 1,
            severity_max: incident.severity.clone(),
            auto_resolved: false,
            sample_incident_id: incident.incident_id.clone(),
            first_notified: false,
            threshold_summary_sent: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Group Summary (emitted on window close or count threshold)
// ---------------------------------------------------------------------------

/// Summary emitted when a group closes or hits the count threshold.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct GroupSummary {
    pub detector: String,
    pub entity_type: EntityType,
    pub entity_value: String,
    pub count: u32,
    pub severity_max: Severity,
    pub auto_resolved: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl GroupSummary {
    /// Format as HTML for Telegram/Slack.
    pub fn format_html(&self) -> String {
        let sev_emoji = match self.severity_max {
            Severity::Critical => "\u{1f534}", // 🔴
            Severity::High => "\u{1f7e0}",     // 🟠
            Severity::Medium => "\u{1f7e1}",   // 🟡
            _ => "\u{1f7e2}",                  // 🟢
        };
        let label = match self.detector.as_str() {
            "ssh_bruteforce" => "login attempts",
            "credential_stuffing" => "credential attacks",
            "port_scan" => "port scans",
            "packet_flood" => "traffic floods",
            "discovery_burst" => "recon scans",
            "reverse_shell" => "reverse shell attempts",
            "data_exfil" | "data_exfil_cmd" | "data_exfil_ebpf" => "data theft attempts",
            "suspicious_execution" => "suspicious executions",
            "web_scan" => "web scans",
            "rootkit" => "kernel anomalies",
            _ => &self.detector,
        };
        let resolved = if self.auto_resolved {
            " \u{2014} auto-resolved"
        } else {
            ""
        };
        let entity_str = if self.entity_value == "unknown" || self.entity_value == "timing" {
            String::new()
        } else {
            format!(" from <code>{}</code>", self.entity_value)
        };
        format!(
            "{sev_emoji} <b>{}</b> {label}{entity_str}{resolved}",
            self.count,
        )
    }
}

#[allow(dead_code)]
fn entity_type_label(et: &EntityType) -> &'static str {
    match et {
        EntityType::Ip => "IP",
        EntityType::User => "user",
        EntityType::Container => "container",
        EntityType::Path => "path",
        EntityType::Service => "service",
    }
}

// ---------------------------------------------------------------------------
// Grouping result — what the caller should do after inserting
// ---------------------------------------------------------------------------

/// Result of inserting an incident into the grouping engine.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GroupAction {
    /// First incident in a new group — notify immediately.
    NotifyImmediately,
    /// Subsequent incident in an existing group — suppress individual notification.
    Suppress,
}

// ---------------------------------------------------------------------------
// Grouping Engine
// ---------------------------------------------------------------------------

const MAX_GROUPS: usize = 1000;

/// Groups incidents by detector+entity within a sliding time window.
pub(crate) struct GroupingEngine {
    groups: HashMap<String, IncidentGroup>,
    window_secs: u64,
    count_threshold: u32,
    digest_stats: DigestStats,
}

impl GroupingEngine {
    pub fn new(config: &NotificationPipelineConfig) -> Self {
        Self {
            groups: HashMap::new(),
            window_secs: config.group_window_secs,
            count_threshold: config.group_count_threshold,
            digest_stats: DigestStats::default(),
        }
    }

    /// Insert an incident. Returns the action the caller should take.
    pub fn insert(&mut self, incident: &Incident) -> GroupAction {
        let (detector, entity_type, entity_value) = extract_group_key(incident);
        let key = format!("{detector}:{entity_type:?}:{entity_value}");

        // Evict oldest groups if at capacity
        if self.groups.len() >= MAX_GROUPS && !self.groups.contains_key(&key) {
            self.evict_oldest();
        }

        let now = incident.ts;

        if let Some(group) = self.groups.get_mut(&key) {
            // Check if existing group's window has expired
            let elapsed = (now - group.first_seen).num_seconds().unsigned_abs();
            if elapsed >= self.window_secs {
                // Window expired — start a new group
                let new_group = IncidentGroup::new(incident, detector, entity_type, entity_value);
                self.groups.insert(key, new_group);
                return GroupAction::NotifyImmediately;
            }

            // Existing group, within window — update and suppress
            group.count += 1;
            group.last_seen = now;
            if severity_rank(&incident.severity) > severity_rank(&group.severity_max) {
                group.severity_max = incident.severity.clone();
            }
            self.digest_stats.suppressed_count += 1;
            GroupAction::Suppress
        } else {
            // New group
            let new_group = IncidentGroup::new(incident, detector, entity_type, entity_value);
            self.groups.insert(key, new_group);
            GroupAction::NotifyImmediately
        }
    }

    /// Mark the group containing this incident as auto-resolved.
    pub fn mark_auto_resolved(&mut self, incident: &Incident) {
        let (detector, entity_type, entity_value) = extract_group_key(incident);
        let key = format!("{detector}:{entity_type:?}:{entity_value}");
        if let Some(group) = self.groups.get_mut(&key) {
            group.auto_resolved = true;
        }
    }

    /// Tick: collect summaries for groups that hit count threshold or expired windows.
    /// Call this periodically (e.g., every few seconds in the agent loop).
    pub fn tick(&mut self) -> Vec<GroupSummary> {
        let now = Utc::now();
        let mut summaries = Vec::new();
        let mut expired_keys = Vec::new();

        for (key, group) in &mut self.groups {
            let elapsed = (now - group.first_seen).num_seconds().unsigned_abs();

            // Count threshold — emit early summary (once)
            if group.count >= self.count_threshold && !group.threshold_summary_sent {
                group.threshold_summary_sent = true;
                summaries.push(GroupSummary {
                    detector: group.detector.clone(),
                    entity_type: group.entity_type.clone(),
                    entity_value: group.entity_value.clone(),
                    count: group.count,
                    severity_max: group.severity_max.clone(),
                    auto_resolved: group.auto_resolved,
                    first_seen: group.first_seen,
                    last_seen: group.last_seen,
                });
            }

            // Window expired — emit final summary and mark for removal
            if elapsed >= self.window_secs {
                // Only emit if we haven't already emitted a threshold summary with the same count,
                // or if more incidents arrived after the threshold summary.
                if !group.threshold_summary_sent || group.count > self.count_threshold {
                    summaries.push(GroupSummary {
                        detector: group.detector.clone(),
                        entity_type: group.entity_type.clone(),
                        entity_value: group.entity_value.clone(),
                        count: group.count,
                        severity_max: group.severity_max.clone(),
                        auto_resolved: group.auto_resolved,
                        first_seen: group.first_seen,
                        last_seen: group.last_seen,
                    });
                }
                expired_keys.push(key.clone());
            }
        }

        for key in &expired_keys {
            if let Some(group) = self.groups.remove(key) {
                self.digest_stats.total_groups_closed += 1;
                if group.auto_resolved {
                    self.digest_stats.auto_resolved_groups += 1;
                } else {
                    self.digest_stats.needs_review_groups += 1;
                }
            }
        }

        summaries
    }

    /// Number of active groups (for dashboard/metrics).
    #[allow(dead_code)]
    pub fn active_group_count(&self) -> usize {
        self.groups.len()
    }

    /// Get a snapshot of all active groups (for the dashboard API).
    #[allow(dead_code)]
    pub fn active_groups(&self) -> Vec<IncidentGroup> {
        self.groups.values().cloned().collect()
    }

    /// Serialise active groups to a JSON value suitable for the dashboard
    /// `/api/incident-groups` endpoint. Spec 005 T017 / SC3 — ensures the
    /// dashboard shows the full incident picture with live counters while
    /// Telegram stays quiet on already-handled activity.
    pub fn snapshot_json(&self) -> serde_json::Value {
        // Sort by last_seen descending so the busiest group is at the top.
        let mut groups: Vec<&IncidentGroup> = self.groups.values().collect();
        groups.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        serde_json::json!({
            "active_count": groups.len(),
            "groups": groups,
            "snapshot_ts": chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Evict the oldest group (by first_seen) to make room.
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .groups
            .iter()
            .min_by_key(|(_, g)| g.first_seen)
            .map(|(k, _)| k.clone())
        {
            self.groups.remove(&oldest_key);
        }
    }
}

// ---------------------------------------------------------------------------
// Channel filter
// ---------------------------------------------------------------------------

/// Decide whether an incident group should be forwarded to a channel.
#[allow(dead_code)]
pub(crate) fn should_notify_channel(group: &IncidentGroup, level: ChannelFilterLevel) -> bool {
    filter_by_level(level, &group.severity_max, group.auto_resolved)
}

/// Decide whether a group summary should be forwarded to a channel.
pub(crate) fn should_notify_summary(summary: &GroupSummary, level: ChannelFilterLevel) -> bool {
    filter_by_level(level, &summary.severity_max, summary.auto_resolved)
}

fn filter_by_level(level: ChannelFilterLevel, severity: &Severity, auto_resolved: bool) -> bool {
    match level {
        ChannelFilterLevel::All => true,
        ChannelFilterLevel::None => false,
        ChannelFilterLevel::Critical => {
            !auto_resolved && matches!(severity, Severity::High | Severity::Critical)
        }
        ChannelFilterLevel::Actionable => {
            if auto_resolved {
                // Auto-resolved → not actionable, UNLESS Critical
                matches!(severity, Severity::Critical)
            } else {
                // Not auto-resolved → actionable
                true
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Immediate-threat classification (Telegram gate)
// ---------------------------------------------------------------------------

/// Detectors that represent a real, active threat requiring the operator's
/// immediate attention.  Everything else is informational / auto-handled and
/// belongs in the daily digest — not an individual Telegram notification.
const IMMEDIATE_THREAT_DETECTORS: &[&str] = &[
    "reverse_shell",
    "data_exfil",
    "data_exfil_cmd",
    "data_exfil_ebpf",
    "ransomware",
    "privesc",
    "lateral_movement",
    "container_escape",
    "web_shell",
    "process_injection",
    "fileless",
    "c2_callback",
    "credential_harvest",
    "ssh_key_injection",
    "kernel_module_load",
    "log_tampering",
    "dns_tunneling",
    "dns_tunneling_ebpf",
    "crontab_persistence",
    "systemd_persistence",
    // AI detections — correlated anomaly (baseline+neural agree) is advisory.
    // Demoted from immediate to daily-briefing-only: Medium severity, no
    // actionable context for operator. Pure neural_anomaly only pings at
    // Critical (score > 0.9), which passes the gate via the severity check.
];

/// Returns `true` when this incident represents an active threat that warrants
/// an immediate Telegram notification.  Critical severity always qualifies
/// regardless of detector.
pub(crate) fn is_immediate_threat(incident: &Incident) -> bool {
    let detector = incident.incident_id.split(':').next().unwrap_or("unknown");

    // Neural model is advisory only — never triggers notifications.
    // It observes and logs for operator review in the Brain dashboard tab.
    if detector == "neural_anomaly" || detector == "host_drift" {
        return false;
    }

    // Critical is always immediate — no exceptions.
    if matches!(incident.severity, Severity::Critical) {
        return true;
    }

    is_immediate_threat_detector(detector)
}

/// Returns `true` when this detector name represents an immediate threat.
/// Used for both incidents and group summaries.
pub(crate) fn is_immediate_threat_detector(detector: &str) -> bool {
    IMMEDIATE_THREAT_DETECTORS.contains(&detector)
}

/// Returns `true` when a group summary warrants an immediate Telegram
/// notification.  Non-threat detectors go to daily digest only.
pub(crate) fn is_immediate_threat_summary(summary: &GroupSummary) -> bool {
    if matches!(summary.severity_max, Severity::Critical) {
        return true;
    }
    is_immediate_threat_detector(&summary.detector)
}

// ---------------------------------------------------------------------------
// Environment-aware adjustments
// ---------------------------------------------------------------------------

/// Detectors whose notifications are suppressed on cloud VPS (expected noise).
const CLOUD_SUPPRESSED_DETECTORS: &[&str] = &[
    "firmware_integrity", // timing anomalies from hypervisor jitter
    "rootkit",            // timing-based detection unreliable on cloud
];

/// Detectors whose severity is demoted for known admin UIDs.
#[allow(dead_code)]
const ADMIN_DEMOTED_DETECTORS: &[&str] = &[
    "ssh_bruteforce", // admin ssh is expected
    "sudo_abuse",     // admin sudo is expected
];

/// Check if this incident should be suppressed based on environment profile.
/// Returns true if the incident should NOT generate any notification.
pub(crate) fn should_suppress_for_environment(
    incident: &Incident,
    profile: &crate::environment_profile::EnvironmentProfile,
) -> bool {
    let detector = incident.incident_id.split(':').next().unwrap_or("unknown");

    // Cloud VPS: suppress timing-based detectors up to High severity.
    // On cloud/VM, hypervisor jitter makes timing analysis unreliable.
    // Only Critical timing anomalies go through (indicating persistent pattern).
    if profile.is_cloud()
        && CLOUD_SUPPRESSED_DETECTORS
            .iter()
            .any(|d| detector.contains(d))
        && !matches!(incident.severity, Severity::Critical)
    {
        return true;
    }

    false
}

/// Check if this incident is from a known admin UID and should be demoted.
/// Returns true if the incident should be treated as LOW severity for notification purposes.
#[allow(dead_code)]
pub(crate) fn is_admin_routine(
    incident: &Incident,
    profile: &crate::environment_profile::EnvironmentProfile,
) -> bool {
    let detector = incident.incident_id.split(':').next().unwrap_or("unknown");

    // Only check admin-demotable detectors
    if !ADMIN_DEMOTED_DETECTORS.iter().any(|d| detector.contains(d)) {
        return false;
    }

    // Check if any entity is a known admin UID
    // The UID would be in an entity of type User with value like "uid:1001" or just "1001"
    for entity in &incident.entities {
        if entity.r#type == innerwarden_core::entities::EntityType::User {
            // Try to parse UID from the value
            let uid_str = entity.value.strip_prefix("uid:").unwrap_or(&entity.value);
            if let Ok(uid) = uid_str.parse::<u32>() {
                if profile.is_human_uid(uid) {
                    return true;
                }
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Spec 005 Phase 7 — Operator Feedback Loop
// ---------------------------------------------------------------------------
//
// Implicit feedback via "absence of operator action". Each time the pipeline
// emits a first notification for a group, we log a pending entry. An entry
// older than IGNORE_WINDOW_SECS with no operator action recorded against the
// same (detector, entity_type) key is converted into a persistent "ignore"
// tally. Once a key has `IGNORE_THRESHOLD` tallies, future groups with that
// key are considered operator-desensitised: the gate demotes them from
// Actionable to daily-briefing.
//
// Explicit feedback — operator taps "Not a threat" / "Block" / "Allow" — is
// routed through `on_operator_action`, which clears any pending entry AND
// resets the tally for that key (positive signal: the operator is still
// engaged with this class of threat).
//
// Persistence: `notification-feedback.jsonl` — one JSON line per event
// (`sent`, `ignored`, `action`). The in-memory state is a pure projection
// of the file and is rebuilt at startup, so the loop survives restarts.

const IGNORE_WINDOW_SECS: i64 = 86_400; // 24h
const IGNORE_THRESHOLD: u32 = 3;

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum FeedbackEvent {
    Sent {
        ts: DateTime<Utc>,
        detector: String,
        entity_type: EntityType,
        entity_value: String,
        incident_id: String,
    },
    Ignored {
        ts: DateTime<Utc>,
        detector: String,
        entity_type: EntityType,
        incident_id: String,
    },
    Action {
        ts: DateTime<Utc>,
        detector: String,
        entity_type: EntityType,
        action: String,
    },
}

/// Tracks pending notifications and ignore tallies. Not Send+Sync because the
/// agent only holds it inside AgentState which is already single-threaded in
/// the main loop path.
#[derive(Debug, Default)]
pub(crate) struct FeedbackTracker {
    /// Pending notifications that have not yet received operator attention.
    /// Keyed by incident_id so operator actions can retire the exact entry.
    pending: HashMap<String, PendingNotification>,
    /// Count of ignored (detector, entity_type) pairs. Resets on any operator
    /// action for the same key.
    ignored_tally: HashMap<(String, EntityType), u32>,
}

#[derive(Debug, Clone)]
struct PendingNotification {
    sent_at: DateTime<Utc>,
    detector: String,
    entity_type: EntityType,
    entity_value: String,
    incident_id: String,
}

impl FeedbackTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a notification was sent for an incident. Idempotent: a
    /// second call for the same incident_id updates the timestamp only.
    pub fn on_notification_sent(
        &mut self,
        detector: &str,
        entity_type: EntityType,
        entity_value: &str,
        incident_id: &str,
        now: DateTime<Utc>,
    ) -> FeedbackEvent {
        self.pending.insert(
            incident_id.to_string(),
            PendingNotification {
                sent_at: now,
                detector: detector.to_string(),
                entity_type: entity_type.clone(),
                entity_value: entity_value.to_string(),
                incident_id: incident_id.to_string(),
            },
        );
        FeedbackEvent::Sent {
            ts: now,
            detector: detector.to_string(),
            entity_type,
            entity_value: entity_value.to_string(),
            incident_id: incident_id.to_string(),
        }
    }

    /// Record an operator action for an incident (tap on Block / Ignore /
    /// Allow). Clears any pending entry and resets the ignore tally for the
    /// owning key.
    pub fn on_operator_action(
        &mut self,
        incident_id: &str,
        action: &str,
        now: DateTime<Utc>,
    ) -> Option<FeedbackEvent> {
        let pending = self.pending.remove(incident_id)?;
        let key = (pending.detector.clone(), pending.entity_type.clone());
        self.ignored_tally.remove(&key);
        Some(FeedbackEvent::Action {
            ts: now,
            detector: pending.detector,
            entity_type: pending.entity_type,
            action: action.to_string(),
        })
    }

    /// Move every pending entry older than `IGNORE_WINDOW_SECS` into the
    /// ignore tally and return the corresponding FeedbackEvents for
    /// persistence.
    pub fn tick(&mut self, now: DateTime<Utc>) -> Vec<FeedbackEvent> {
        let cutoff = now - chrono::Duration::seconds(IGNORE_WINDOW_SECS);
        let ripe: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, p)| p.sent_at < cutoff)
            .map(|(id, _)| id.clone())
            .collect();
        let mut events = Vec::with_capacity(ripe.len());
        for id in ripe {
            if let Some(p) = self.pending.remove(&id) {
                let key = (p.detector.clone(), p.entity_type.clone());
                *self.ignored_tally.entry(key).or_insert(0) += 1;
                events.push(FeedbackEvent::Ignored {
                    ts: now,
                    detector: p.detector,
                    entity_type: p.entity_type,
                    incident_id: p.incident_id,
                });
            }
        }
        events
    }

    /// True when the (detector, entity_type) pair has reached the ignore
    /// threshold and should be demoted. Used by the notification gate.
    pub fn is_demoted(&self, detector: &str, entity_type: &EntityType) -> bool {
        self.ignored_tally
            .get(&(detector.to_string(), entity_type.clone()))
            .copied()
            .unwrap_or(0)
            >= IGNORE_THRESHOLD
    }

    /// Number of pending notifications — surfaced for tests and dashboard.
    #[allow(dead_code)]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Apply a persisted FeedbackEvent to in-memory state during startup
    /// replay. `Sent` is only honoured if the notification is still fresh;
    /// older `Sent` entries are ignored (the `Ignored` follow-up will have
    /// been logged already).
    pub fn replay_event(&mut self, event: &FeedbackEvent, now: DateTime<Utc>) {
        let cutoff = now - chrono::Duration::seconds(IGNORE_WINDOW_SECS);
        match event {
            FeedbackEvent::Sent {
                ts,
                detector,
                entity_type,
                entity_value,
                incident_id,
            } => {
                if *ts > cutoff {
                    self.pending.insert(
                        incident_id.clone(),
                        PendingNotification {
                            sent_at: *ts,
                            detector: detector.clone(),
                            entity_type: entity_type.clone(),
                            entity_value: entity_value.clone(),
                            incident_id: incident_id.clone(),
                        },
                    );
                }
            }
            FeedbackEvent::Ignored {
                detector,
                entity_type,
                incident_id,
                ..
            } => {
                self.pending.remove(incident_id);
                let key = (detector.clone(), entity_type.clone());
                *self.ignored_tally.entry(key).or_insert(0) += 1;
            }
            FeedbackEvent::Action {
                detector,
                entity_type,
                ..
            } => {
                let key = (detector.clone(), entity_type.clone());
                self.ignored_tally.remove(&key);
            }
        }
    }
}

/// File-based persistence for feedback events. JSONL, append-only.
pub(crate) mod feedback_store {
    use super::FeedbackEvent;
    use std::io::Write;
    use std::path::Path;

    pub fn path(data_dir: &Path) -> std::path::PathBuf {
        data_dir.join("notification-feedback.jsonl")
    }

    pub fn append(data_dir: &Path, event: &FeedbackEvent) -> anyhow::Result<()> {
        let p = path(data_dir);
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)?;
        let line = serde_json::to_string(event)?;
        writeln!(f, "{line}")?;
        Ok(())
    }

    pub fn append_many(data_dir: &Path, events: &[FeedbackEvent]) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let p = path(data_dir);
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)?;
        for event in events {
            let line = serde_json::to_string(event)?;
            writeln!(f, "{line}")?;
        }
        Ok(())
    }

    pub fn load(data_dir: &Path) -> Vec<FeedbackEvent> {
        let p = path(data_dir);
        let Ok(content) = std::fs::read_to_string(p) else {
            return Vec::new();
        };
        content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Digest Stats — accumulated from closed groups
// ---------------------------------------------------------------------------

/// Stats accumulated from closed groups for digest messages.
#[derive(Debug, Default, Clone)]
pub(crate) struct DigestStats {
    /// Total incidents grouped (suppressed individual notifications).
    pub suppressed_count: u32,
    /// Groups that were auto-resolved (obvious gate, abuseipdb, crowdsec).
    pub auto_resolved_groups: u32,
    /// Groups that were NOT auto-resolved (need review).
    pub needs_review_groups: u32,
    /// Total groups closed in this period.
    pub total_groups_closed: u32,
}

impl GroupingEngine {
    /// Drain accumulated digest stats and reset counters.
    pub fn drain_digest_stats(&mut self) -> DigestStats {
        std::mem::take(&mut self.digest_stats)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract (detector, primary_entity_type, primary_entity_value) from an incident.
/// Primary entity: first IP, or first User, or first entity of any type.
fn extract_group_key(incident: &Incident) -> (String, EntityType, String) {
    let parts: Vec<&str> = incident.incident_id.splitn(3, ':').collect();
    let detector = parts.first().unwrap_or(&"unknown").to_string();

    // Pick best entity: prefer IP, then User, then first available
    let entity = incident
        .entities
        .iter()
        .find(|e| e.r#type == EntityType::Ip)
        .or_else(|| {
            incident
                .entities
                .iter()
                .find(|e| e.r#type == EntityType::User)
        })
        .or_else(|| incident.entities.first());

    match entity {
        Some(e) => (detector, e.r#type.clone(), e.value.clone()),
        None => {
            // Fallback: extract entity from incident_id (e.g., "ssh_bruteforce:1.2.3.4:ts")
            if let Some(middle) = parts.get(1) {
                let middle = *middle;
                if middle.parse::<std::net::IpAddr>().is_ok() {
                    (detector, EntityType::Ip, middle.to_string())
                } else if middle.starts_with("uid") || middle.starts_with("user") {
                    (detector, EntityType::User, middle.to_string())
                } else if middle == "unknown" || middle == "timing" {
                    // Group by detector only — all "rootkit:timing:*" go together
                    (detector, EntityType::Ip, middle.to_string())
                } else {
                    (detector, EntityType::Ip, middle.to_string())
                }
            } else {
                (detector, EntityType::Ip, "unknown".to_string())
            }
        }
    }
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Debug => 0,
        Severity::Info => 1,
        Severity::Low => 2,
        Severity::Medium => 3,
        Severity::High => 4,
        Severity::Critical => 5,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;

    fn make_incident(detector: &str, ip: &str, severity: Severity) -> Incident {
        Incident {
            ts: Utc::now(),
            host: "test".into(),
            incident_id: format!("{detector}:{ip}:test"),
            severity,
            title: format!("{detector} alert"),
            summary: "test".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        }
    }

    fn make_incident_at(
        detector: &str,
        ip: &str,
        severity: Severity,
        ts: DateTime<Utc>,
    ) -> Incident {
        let mut inc = make_incident(detector, ip, severity);
        inc.ts = ts;
        inc
    }

    fn default_config() -> NotificationPipelineConfig {
        NotificationPipelineConfig {
            group_window_secs: 3600,
            group_count_threshold: 10,
        }
    }

    #[test]
    fn first_incident_notifies_immediately() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        assert_eq!(engine.insert(&inc), GroupAction::NotifyImmediately);
        assert_eq!(engine.active_group_count(), 1);
    }

    #[test]
    fn subsequent_same_group_suppressed() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc1 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        let inc2 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);

        assert_eq!(engine.insert(&inc1), GroupAction::NotifyImmediately);
        assert_eq!(engine.insert(&inc2), GroupAction::Suppress);
        assert_eq!(engine.active_group_count(), 1);
    }

    #[test]
    fn different_entity_creates_new_group() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc1 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        let inc2 = make_incident("ssh_bruteforce", "5.6.7.8", Severity::High);

        assert_eq!(engine.insert(&inc1), GroupAction::NotifyImmediately);
        assert_eq!(engine.insert(&inc2), GroupAction::NotifyImmediately);
        assert_eq!(engine.active_group_count(), 2);
    }

    #[test]
    fn different_detector_creates_new_group() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc1 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        let inc2 = make_incident("port_scan", "1.2.3.4", Severity::Medium);

        assert_eq!(engine.insert(&inc1), GroupAction::NotifyImmediately);
        assert_eq!(engine.insert(&inc2), GroupAction::NotifyImmediately);
        assert_eq!(engine.active_group_count(), 2);
    }

    #[test]
    fn window_expiry_starts_new_group() {
        let mut engine = GroupingEngine::new(&default_config());
        let t0 = Utc::now() - chrono::Duration::hours(2);
        let t1 = Utc::now();

        let inc1 = make_incident_at("ssh_bruteforce", "1.2.3.4", Severity::High, t0);
        let inc2 = make_incident_at("ssh_bruteforce", "1.2.3.4", Severity::High, t1);

        assert_eq!(engine.insert(&inc1), GroupAction::NotifyImmediately);
        assert_eq!(engine.insert(&inc2), GroupAction::NotifyImmediately);
        // Old group replaced by new one
        assert_eq!(engine.active_group_count(), 1);
    }

    #[test]
    fn tick_emits_count_threshold_summary() {
        let cfg = NotificationPipelineConfig {
            group_window_secs: 3600,
            group_count_threshold: 3,
        };
        let mut engine = GroupingEngine::new(&cfg);

        for i in 0..3 {
            let inc = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
            engine.insert(&inc);
            let _ = i;
        }

        let summaries = engine.tick();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].count, 3);
        assert_eq!(summaries[0].detector, "ssh_bruteforce");
    }

    #[test]
    fn tick_emits_window_expiry_summary() {
        let mut engine = GroupingEngine::new(&NotificationPipelineConfig {
            group_window_secs: 1, // 1 second window for test
            group_count_threshold: 100,
        });

        let t0 = Utc::now() - chrono::Duration::seconds(5);
        let inc = make_incident_at("ssh_bruteforce", "1.2.3.4", Severity::High, t0);
        engine.insert(&inc);

        let summaries = engine.tick();
        assert_eq!(summaries.len(), 1);
        // Group should be removed after expiry
        assert_eq!(engine.active_group_count(), 0);
    }

    #[test]
    fn lru_eviction_at_capacity() {
        let cfg = NotificationPipelineConfig {
            group_window_secs: 3600,
            group_count_threshold: 10,
        };
        let mut engine = GroupingEngine::new(&cfg);

        // Fill to MAX_GROUPS — use unique detector:IP combos
        for i in 0..MAX_GROUPS {
            let a = (i >> 16) & 0xFF;
            let b = (i >> 8) & 0xFF;
            let c = i & 0xFF;
            let inc = make_incident("ssh_bruteforce", &format!("10.{a}.{b}.{c}"), Severity::High);
            engine.insert(&inc);
        }
        assert_eq!(engine.active_group_count(), MAX_GROUPS);

        // Insert one more — should evict oldest
        let inc = make_incident("ssh_bruteforce", "99.99.99.99", Severity::High);
        assert_eq!(engine.insert(&inc), GroupAction::NotifyImmediately);
        assert_eq!(engine.active_group_count(), MAX_GROUPS);
    }

    #[test]
    fn severity_max_tracks_highest() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc1 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::Low);
        let inc2 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::Critical);

        engine.insert(&inc1);
        engine.insert(&inc2);

        let groups = engine.active_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].severity_max, Severity::Critical);
    }

    #[test]
    fn mark_auto_resolved() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        engine.insert(&inc);

        engine.mark_auto_resolved(&inc);
        let groups = engine.active_groups();
        assert!(groups[0].auto_resolved);
    }

    // -- Channel filter tests --

    fn make_group(severity: Severity, auto_resolved: bool) -> IncidentGroup {
        IncidentGroup {
            detector: "test".into(),
            entity_type: EntityType::Ip,
            entity_value: "1.2.3.4".into(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            count: 1,
            severity_max: severity,
            auto_resolved,
            sample_incident_id: "test:1".into(),
            first_notified: false,
            threshold_summary_sent: false,
        }
    }

    #[test]
    fn filter_all_passes_everything() {
        assert!(should_notify_channel(
            &make_group(Severity::Low, true),
            ChannelFilterLevel::All
        ));
        assert!(should_notify_channel(
            &make_group(Severity::Low, false),
            ChannelFilterLevel::All
        ));
    }

    #[test]
    fn filter_none_blocks_everything() {
        assert!(!should_notify_channel(
            &make_group(Severity::Critical, false),
            ChannelFilterLevel::None
        ));
    }

    #[test]
    fn filter_critical_passes_high_unresolved() {
        assert!(should_notify_channel(
            &make_group(Severity::High, false),
            ChannelFilterLevel::Critical
        ));
        assert!(should_notify_channel(
            &make_group(Severity::Critical, false),
            ChannelFilterLevel::Critical
        ));
        assert!(!should_notify_channel(
            &make_group(Severity::Medium, false),
            ChannelFilterLevel::Critical
        ));
        assert!(!should_notify_channel(
            &make_group(Severity::High, true),
            ChannelFilterLevel::Critical
        ));
    }

    #[test]
    fn filter_actionable_blocks_auto_resolved_except_critical() {
        // Auto-resolved non-critical → not actionable
        assert!(!should_notify_channel(
            &make_group(Severity::High, true),
            ChannelFilterLevel::Actionable
        ));
        // Auto-resolved critical → still actionable
        assert!(should_notify_channel(
            &make_group(Severity::Critical, true),
            ChannelFilterLevel::Actionable
        ));
        // Not auto-resolved → actionable
        assert!(should_notify_channel(
            &make_group(Severity::Low, false),
            ChannelFilterLevel::Actionable
        ));
    }

    // -- Summary filter tests --

    fn make_summary(severity: Severity, auto_resolved: bool) -> GroupSummary {
        GroupSummary {
            detector: "test".into(),
            entity_type: EntityType::Ip,
            entity_value: "1.2.3.4".into(),
            count: 5,
            severity_max: severity,
            auto_resolved,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    #[test]
    fn summary_filter_actionable_blocks_auto_resolved() {
        assert!(!should_notify_summary(
            &make_summary(Severity::High, true),
            ChannelFilterLevel::Actionable
        ));
        assert!(should_notify_summary(
            &make_summary(Severity::High, false),
            ChannelFilterLevel::Actionable
        ));
    }

    #[test]
    fn summary_filter_critical_only_high_and_critical() {
        assert!(should_notify_summary(
            &make_summary(Severity::Critical, false),
            ChannelFilterLevel::Critical
        ));
        assert!(!should_notify_summary(
            &make_summary(Severity::Medium, false),
            ChannelFilterLevel::Critical
        ));
    }

    #[test]
    fn summary_filter_none_blocks_all() {
        assert!(!should_notify_summary(
            &make_summary(Severity::Critical, false),
            ChannelFilterLevel::None
        ));
    }

    #[test]
    fn summary_filter_all_passes_all() {
        assert!(should_notify_summary(
            &make_summary(Severity::Low, true),
            ChannelFilterLevel::All
        ));
    }

    // -- Backward compat: default config produces same behavior --

    // -- Digest stats tests --

    #[test]
    fn digest_stats_accumulate_on_suppress() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc1 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        let inc2 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);

        engine.insert(&inc1); // NotifyImmediately
        engine.insert(&inc2); // Suppress

        let stats = engine.drain_digest_stats();
        assert_eq!(stats.suppressed_count, 1);
    }

    #[test]
    fn digest_stats_accumulate_on_group_close() {
        let mut engine = GroupingEngine::new(&NotificationPipelineConfig {
            group_window_secs: 1,
            group_count_threshold: 100,
        });

        let t0 = Utc::now() - chrono::Duration::seconds(5);
        let inc1 = make_incident_at("ssh_bruteforce", "1.2.3.4", Severity::High, t0);
        engine.insert(&inc1);
        engine.mark_auto_resolved(&inc1);

        let inc2 = make_incident_at("port_scan", "5.6.7.8", Severity::Medium, t0);
        engine.insert(&inc2);

        engine.tick(); // both groups expire

        let stats = engine.drain_digest_stats();
        assert_eq!(stats.total_groups_closed, 2);
        assert_eq!(stats.auto_resolved_groups, 1);
        assert_eq!(stats.needs_review_groups, 1);
    }

    #[test]
    fn drain_resets_digest_stats() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc1 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        let inc2 = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        engine.insert(&inc1);
        engine.insert(&inc2);

        let stats = engine.drain_digest_stats();
        assert_eq!(stats.suppressed_count, 1);

        let stats2 = engine.drain_digest_stats();
        assert_eq!(stats2.suppressed_count, 0);
    }

    // -- Environment suppression tests --

    #[test]
    fn cloud_suppresses_low_timing_anomaly() {
        let mut profile = crate::environment_profile::EnvironmentProfile::default();
        profile.platform = "cloud_vps".into();

        let inc = make_incident("firmware_integrity", "1.2.3.4", Severity::Low);
        assert!(should_suppress_for_environment(&inc, &profile));
    }

    #[test]
    fn cloud_suppresses_high_timing_anomaly() {
        let mut profile = crate::environment_profile::EnvironmentProfile::default();
        profile.platform = "cloud_vps".into();

        let inc = make_incident("firmware_integrity", "1.2.3.4", Severity::High);
        assert!(should_suppress_for_environment(&inc, &profile));
    }

    #[test]
    fn cloud_does_not_suppress_critical_timing_anomaly() {
        let mut profile = crate::environment_profile::EnvironmentProfile::default();
        profile.platform = "cloud_vps".into();

        let inc = make_incident("firmware_integrity", "1.2.3.4", Severity::Critical);
        assert!(!should_suppress_for_environment(&inc, &profile));
    }

    #[test]
    fn bare_metal_does_not_suppress_timing() {
        let mut profile = crate::environment_profile::EnvironmentProfile::default();
        profile.platform = "bare_metal".into();

        let inc = make_incident("firmware_integrity", "1.2.3.4", Severity::Low);
        assert!(!should_suppress_for_environment(&inc, &profile));
    }

    #[test]
    fn admin_routine_detected() {
        let mut profile = crate::environment_profile::EnvironmentProfile::default();
        profile.human_uids = vec![1001];

        let mut inc = make_incident("sudo_abuse", "1001", Severity::Medium);
        inc.entities = vec![innerwarden_core::entities::EntityRef {
            r#type: innerwarden_core::entities::EntityType::User,
            value: "1001".into(),
        }];
        assert!(is_admin_routine(&inc, &profile));
    }

    #[test]
    fn non_admin_not_demoted() {
        let mut profile = crate::environment_profile::EnvironmentProfile::default();
        profile.human_uids = vec![1001];

        let mut inc = make_incident("sudo_abuse", "9999", Severity::Medium);
        inc.entities = vec![innerwarden_core::entities::EntityRef {
            r#type: innerwarden_core::entities::EntityType::User,
            value: "9999".into(),
        }];
        assert!(!is_admin_routine(&inc, &profile));
    }

    // -- Backward compat --

    #[test]
    fn default_channel_config_is_actionable() {
        let cfg = crate::config::ChannelNotificationConfig::default();
        assert_eq!(cfg.notification_level, ChannelFilterLevel::Actionable);
        // Actionable with auto_resolved=false passes everything (same as current behavior)
        assert!(filter_by_level(
            cfg.notification_level,
            &Severity::Low,
            false
        ));
        assert!(filter_by_level(
            cfg.notification_level,
            &Severity::High,
            false
        ));
        assert!(filter_by_level(
            cfg.notification_level,
            &Severity::Critical,
            false
        ));
    }

    // -- Immediate threat classification tests --

    #[test]
    fn reverse_shell_is_immediate_threat() {
        let inc = make_incident("reverse_shell", "1.2.3.4", Severity::High);
        assert!(is_immediate_threat(&inc));
    }

    #[test]
    fn data_exfil_is_immediate_threat() {
        let inc = make_incident("data_exfil", "1.2.3.4", Severity::High);
        assert!(is_immediate_threat(&inc));
        let inc2 = make_incident("data_exfil_ebpf", "1.2.3.4", Severity::High);
        assert!(is_immediate_threat(&inc2));
    }

    #[test]
    fn ransomware_is_immediate_threat() {
        let inc = make_incident("ransomware", "1.2.3.4", Severity::High);
        assert!(is_immediate_threat(&inc));
    }

    #[test]
    fn ssh_bruteforce_is_not_immediate_threat() {
        let inc = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        assert!(!is_immediate_threat(&inc));
    }

    #[test]
    fn discovery_burst_is_not_immediate_threat() {
        let inc = make_incident("discovery_burst", "1.2.3.4", Severity::Medium);
        assert!(!is_immediate_threat(&inc));
    }

    #[test]
    fn suspicious_execution_is_not_immediate_threat() {
        let inc = make_incident("suspicious_execution", "unknown", Severity::Low);
        assert!(!is_immediate_threat(&inc));
    }

    #[test]
    fn packet_flood_is_not_immediate_threat() {
        let inc = make_incident("packet_flood", "10.0.0.1", Severity::High);
        assert!(!is_immediate_threat(&inc));
    }

    #[test]
    fn critical_severity_always_immediate() {
        // Even a "noisy" detector becomes immediate at Critical severity.
        let inc = make_incident("ssh_bruteforce", "1.2.3.4", Severity::Critical);
        assert!(is_immediate_threat(&inc));
    }

    #[test]
    fn port_scan_is_not_immediate_threat() {
        let inc = make_incident("port_scan", "5.6.7.8", Severity::Medium);
        assert!(!is_immediate_threat(&inc));
    }

    #[test]
    fn persistence_detectors_are_immediate() {
        let inc1 = make_incident("crontab_persistence", "unknown", Severity::High);
        assert!(is_immediate_threat(&inc1));
        let inc2 = make_incident("systemd_persistence", "unknown", Severity::High);
        assert!(is_immediate_threat(&inc2));
    }

    // ─── Spec 005 T017 — snapshot for dashboard /api/incident-groups ───

    #[test]
    fn snapshot_json_empty_engine_has_zero_groups() {
        let engine = GroupingEngine::new(&default_config());
        let snap = engine.snapshot_json();
        assert_eq!(snap["active_count"].as_u64(), Some(0));
        assert!(snap["groups"].as_array().unwrap().is_empty());
        assert!(snap["snapshot_ts"].as_str().is_some());
    }

    #[test]
    fn snapshot_json_reflects_inserted_groups() {
        let mut engine = GroupingEngine::new(&default_config());
        let base = Utc::now() - chrono::Duration::minutes(5);
        let inc_a = make_incident_at("ssh_bruteforce", "1.1.1.1", Severity::High, base);
        engine.insert(&inc_a);
        let inc_b = make_incident_at(
            "port_scan",
            "2.2.2.2",
            Severity::Medium,
            base + chrono::Duration::minutes(2),
        );
        engine.insert(&inc_b);

        let snap = engine.snapshot_json();
        assert_eq!(snap["active_count"].as_u64(), Some(2));
        let groups = snap["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);

        // Most recently-seen first: port_scan (2 min later) precedes ssh_bruteforce.
        assert_eq!(groups[0]["detector"], "port_scan");
        assert_eq!(groups[0]["entity_type"], "ip");
        assert_eq!(groups[0]["entity_value"], "2.2.2.2");
        assert_eq!(groups[0]["count"].as_u64(), Some(1));
        assert_eq!(groups[0]["auto_resolved"].as_bool(), Some(false));
        assert_eq!(groups[1]["detector"], "ssh_bruteforce");
    }

    #[test]
    fn snapshot_json_preserves_auto_resolved_flag() {
        let mut engine = GroupingEngine::new(&default_config());
        let inc = make_incident("ssh_bruteforce", "1.2.3.4", Severity::High);
        engine.insert(&inc);
        engine.mark_auto_resolved(&inc);
        let snap = engine.snapshot_json();
        assert_eq!(
            snap["groups"][0]["auto_resolved"].as_bool(),
            Some(true),
            "mark_auto_resolved must round-trip through the dashboard snapshot"
        );
    }

    // ─── Spec 005 Phase 7 — Feedback tracker tests ────────────────────

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn feedback_pending_increments_and_decrements() {
        let mut t = FeedbackTracker::new();
        assert_eq!(t.pending_count(), 0);
        t.on_notification_sent(
            "ssh_bruteforce",
            EntityType::Ip,
            "1.2.3.4",
            "inc-1",
            now(),
        );
        assert_eq!(t.pending_count(), 1);
        let _ = t.on_operator_action("inc-1", "block", now());
        assert_eq!(t.pending_count(), 0);
    }

    #[test]
    fn feedback_aged_pending_converts_to_ignore_tally() {
        let mut t = FeedbackTracker::new();
        let old = Utc::now() - chrono::Duration::hours(25);
        t.on_notification_sent(
            "ssh_bruteforce",
            EntityType::Ip,
            "1.2.3.4",
            "inc-a",
            old,
        );
        let events = t.tick(Utc::now());
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], FeedbackEvent::Ignored { .. }));
        assert_eq!(t.pending_count(), 0);
        assert!(!t.is_demoted("ssh_bruteforce", &EntityType::Ip));
    }

    #[test]
    fn feedback_demotes_after_three_ignores() {
        let mut t = FeedbackTracker::new();
        let old = Utc::now() - chrono::Duration::hours(25);
        for i in 0..3 {
            t.on_notification_sent(
                "ssh_bruteforce",
                EntityType::Ip,
                "1.2.3.4",
                &format!("inc-{i}"),
                old,
            );
        }
        t.tick(Utc::now());
        assert!(t.is_demoted("ssh_bruteforce", &EntityType::Ip));
        // Different entity type → independent tally.
        assert!(!t.is_demoted("ssh_bruteforce", &EntityType::User));
    }

    #[test]
    fn feedback_operator_action_resets_ignore_tally() {
        let mut t = FeedbackTracker::new();
        let old = Utc::now() - chrono::Duration::hours(25);
        for i in 0..3 {
            t.on_notification_sent(
                "ssh_bruteforce",
                EntityType::Ip,
                "1.2.3.4",
                &format!("inc-{i}"),
                old,
            );
        }
        t.tick(Utc::now());
        assert!(t.is_demoted("ssh_bruteforce", &EntityType::Ip));

        // Operator now engages with a fresh notification for the same key.
        t.on_notification_sent(
            "ssh_bruteforce",
            EntityType::Ip,
            "1.2.3.4",
            "inc-fresh",
            Utc::now(),
        );
        let _ = t.on_operator_action("inc-fresh", "block", Utc::now());
        assert!(
            !t.is_demoted("ssh_bruteforce", &EntityType::Ip),
            "explicit operator engagement must clear the demotion"
        );
    }

    #[test]
    fn feedback_replay_reconstructs_state() {
        // Simulate: three ignored events recorded historically, then an
        // operator action — replay must land on "not demoted".
        let mut t = FeedbackTracker::new();
        let past = Utc::now() - chrono::Duration::hours(48);
        for _ in 0..3 {
            let ev = FeedbackEvent::Ignored {
                ts: past,
                detector: "ssh_bruteforce".into(),
                entity_type: EntityType::Ip,
                incident_id: "x".into(),
            };
            t.replay_event(&ev, Utc::now());
        }
        assert!(t.is_demoted("ssh_bruteforce", &EntityType::Ip));

        let action = FeedbackEvent::Action {
            ts: past,
            detector: "ssh_bruteforce".into(),
            entity_type: EntityType::Ip,
            action: "block".into(),
        };
        t.replay_event(&action, Utc::now());
        assert!(!t.is_demoted("ssh_bruteforce", &EntityType::Ip));
    }

    #[test]
    fn feedback_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let events = vec![
            FeedbackEvent::Sent {
                ts: Utc::now(),
                detector: "ssh_bruteforce".into(),
                entity_type: EntityType::Ip,
                entity_value: "1.2.3.4".into(),
                incident_id: "inc-1".into(),
            },
            FeedbackEvent::Action {
                ts: Utc::now(),
                detector: "ssh_bruteforce".into(),
                entity_type: EntityType::Ip,
                action: "block".into(),
            },
        ];
        feedback_store::append_many(dir.path(), &events).unwrap();
        let loaded = feedback_store::load(dir.path());
        assert_eq!(loaded.len(), 2);
        assert!(matches!(loaded[0], FeedbackEvent::Sent { .. }));
        assert!(matches!(loaded[1], FeedbackEvent::Action { .. }));
    }
}
