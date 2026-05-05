//! Baseline Learning and Anomaly Detection.
//!
//! Learns what is "normal" for a host over a 7-day training period, then
//! detects deviations that could indicate zero-day attacks, insider threats,
//! or compromised systems — without any predefined rules.
//!
//! Tracked baselines:
//! - Event rate per hour by source (24-hour profile)
//! - Process lineages (parent→child relationships)
//! - User login hours
//! - Outbound network destinations per process

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use chrono::{Timelike, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use innerwarden_core::entities::EntityType;
use innerwarden_core::event::{Event, Severity};

use crate::knowledge_graph::intern::intern;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Days of data needed before baselines are considered mature.
const TRAINING_DAYS: u32 = 7;
/// Minimum events per hour baseline to trigger rate anomaly.
const MIN_RATE_BASELINE: f32 = 5.0;
/// Rate drop threshold to trigger silence anomaly (80% drop).
const SILENCE_THRESHOLD: f32 = 0.20;
/// Rate spike threshold (300% increase).
const SPIKE_THRESHOLD: f32 = 3.0;
/// Maximum process lineages to track.
const MAX_LINEAGES: usize = 5_000;
/// Maximum outbound destinations per process.
const MAX_DESTINATIONS_PER_PROCESS: usize = 500;
/// Maximum processes to track destinations for.
const MAX_DESTINATION_PROCESSES: usize = 200;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Persistent baseline store.
///
/// Wave 6b (memory-opt, 2026-05-05): the four high-reuse keyed
/// collections below switched from `String` to `Arc<str>`. Cardinality
/// in steady state is small (~10 distinct sources, ~50 distinct
/// users, ~hundreds of process lineages), but the call sites
/// `.entry(event.source.clone())` were pre-Wave-6b allocating a fresh
/// `String` PER EVENT regardless of whether the entry already
/// existed (HashMap takes owned keys, drops duplicates after the
/// hash lookup). With `Arc<str>` interned at the call site every
/// repeated event is a 16-byte pointer-clone instead of a string
/// alloc + free. Wire format on `baseline.json` is unchanged
/// (serde renders `Arc<str>` as JSON string).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStore {
    /// Events per hour by source. Key = source name (e.g., "auth_log").
    /// Value = 24-element array, each element is the average event count for that hour.
    event_rate_by_hour: HashMap<Arc<str>, [f32; 24]>,

    /// Known normal process lineages (parent_comm→child_comm).
    /// Lineage strings (e.g. "systemd > sshd > bash") repeat across
    /// every observed event from the same parent chain.
    process_lineages: HashSet<Arc<str>>,

    /// User login hour profile. Key = username.
    /// Value = 24-element array, each bit indicates login activity seen in that hour.
    user_login_hours: HashMap<Arc<str>, [u8; 24]>,

    /// Normal outbound destinations per process. Key = process name.
    /// Value = set of destination IPs/hostnames seen.
    process_destinations: HashMap<Arc<str>, HashSet<String>>,

    /// Has the learning period completed?
    mature: bool,

    /// Number of distinct days of data observed.
    training_days: u32,

    /// Dates observed (YYYY-MM-DD), used to count training_days.
    observed_dates: HashSet<String>,

    /// Running event counts for current hour (for rate calculation).
    current_hour_counts: HashMap<Arc<str>, u32>,
    /// Which hour the current counts belong to.
    current_hour: u8,

    /// Total observations (for stats).
    total_observations: u64,

    /// 2026-05-03: ring buffer of the most recent anomalies detected,
    /// surfaced to the dashboard's Baseline tab so the operator can
    /// see "what changed in the last 24h" instead of just "what does
    /// the agent consider normal". Bounded so the buffer never grows
    /// unbounded and persistence stays cheap. Cleared entries past
    /// the cap drop oldest-first.
    #[serde(default)]
    pub recent_anomalies: std::collections::VecDeque<TimedAnomaly>,
}

/// An anomaly stamped with the wall-clock time it fired. Kept
/// separate from `AnomalyReport` so the in-memory detection path
/// stays cheap (no timestamp until the report is being persisted
/// for the dashboard).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimedAnomaly {
    pub ts: chrono::DateTime<Utc>,
    pub anomaly_type: AnomalyType,
    pub description: String,
    pub expected: String,
    pub observed: String,
    pub severity: Severity,
    /// Optional subject (user, process, IP) extracted from the
    /// anomaly source so the dashboard can render an actionable
    /// link directly to the relevant journey.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

/// Maximum recent anomalies kept in memory and persisted. Sized to
/// give the operator a 24-48h window of context without bloating
/// `baseline.json`.
const MAX_RECENT_ANOMALIES: usize = 50;

/// An anomaly detected by the baseline engine.
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyReport {
    pub anomaly_type: AnomalyType,
    pub description: String,
    pub expected: String,
    pub observed: String,
    pub confidence: f32,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    /// Event rate dropped significantly vs baseline.
    EventRateDrop,
    /// Event rate spiked significantly vs baseline.
    EventRateSpike,
    /// Previously unseen process lineage.
    ProcessLineage,
    /// User login at unusual hour.
    UserLoginTime,
    /// Process connecting to previously unseen destination.
    NewDestination,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl BaselineStore {
    /// Create a new empty baseline store.
    pub fn new() -> Self {
        Self {
            event_rate_by_hour: HashMap::new(),
            process_lineages: HashSet::new(),
            user_login_hours: HashMap::new(),
            process_destinations: HashMap::new(),
            recent_anomalies: std::collections::VecDeque::new(),
            mature: false,
            training_days: 0,
            observed_dates: HashSet::new(),
            current_hour_counts: HashMap::new(),
            current_hour: 0,
            total_observations: 0,
        }
    }

    /// Is the baseline mature (training period complete)?
    #[allow(dead_code)]
    pub fn is_mature(&self) -> bool {
        self.mature
    }

    /// Days of training data collected.
    #[allow(dead_code)]
    pub fn training_days(&self) -> u32 {
        self.training_days
    }

    /// Total events observed.
    #[allow(dead_code)]
    pub fn total_observations(&self) -> u64 {
        self.total_observations
    }

    /// 2026-05-03: append an anomaly to the ring buffer that the
    /// dashboard's Baseline tab consumes. Bounded to MAX_RECENT_ANOMALIES;
    /// drops oldest first. Each entry is timestamped at insertion so
    /// the UI can display "what changed in the last 24h" without
    /// re-deriving from logs.
    pub fn record_anomaly(&mut self, anomaly: &AnomalyReport, subject: Option<String>) {
        let timed = TimedAnomaly {
            ts: chrono::Utc::now(),
            anomaly_type: anomaly.anomaly_type.clone(),
            description: anomaly.description.clone(),
            expected: anomaly.expected.clone(),
            observed: anomaly.observed.clone(),
            severity: anomaly.severity.clone(),
            subject,
        };
        self.recent_anomalies.push_back(timed);
        while self.recent_anomalies.len() > MAX_RECENT_ANOMALIES {
            self.recent_anomalies.pop_front();
        }
    }

    /// 2026-05-03: how many anomalies fired in the last `secs` seconds.
    /// Used by the dashboard hero card to render "X different
    /// patterns nas últimas 24h".
    #[allow(dead_code)]
    pub fn anomalies_within(&self, secs: i64) -> usize {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(secs);
        self.recent_anomalies
            .iter()
            .filter(|a| a.ts > cutoff)
            .count()
    }

    /// Observe an event to update baselines (always) and check for anomalies
    /// (only when mature).
    ///
    /// Returns anomalies found (empty vec during training).
    pub fn observe_event(&mut self, event: &Event) -> Vec<AnomalyReport> {
        self.total_observations += 1;
        let hour = event.ts.hour() as u8;
        let date = event.ts.format("%Y-%m-%d").to_string();

        // Track training days
        if self.observed_dates.insert(date) {
            self.training_days = self.observed_dates.len() as u32;
            if !self.mature && self.training_days >= TRAINING_DAYS {
                self.mature = true;
                info!(
                    days = self.training_days,
                    lineages = self.process_lineages.len(),
                    "baseline learning complete — anomaly detection active"
                );
            }
        }

        // Flush hourly counts when the hour changes
        if hour != self.current_hour {
            self.flush_hour_counts();
            self.current_hour = hour;
        }

        // Update event rate counts.
        // Wave 6b: intern source so the HashMap key allocation is
        // shared across every event with the same source.
        *self
            .current_hour_counts
            .entry(intern(&event.source))
            .or_default() += 1;

        // Track process lineages from eBPF exec events
        // NOTE: We track the lineage string before inserting so anomaly
        // detection can check if it's new before it's learned.
        let mut new_lineage: Option<String> = None;
        if event.source == "ebpf" && event.kind == "shell.command_exec" {
            if let (Some(ppid_comm), Some(comm)) = (
                event.details.get("parent_comm").and_then(|v| v.as_str()),
                event.details.get("comm").and_then(|v| v.as_str()),
            ) {
                let lineage = format!("{ppid_comm}→{comm}");
                // Wave 6b: HashSet<Arc<str>>::contains accepts &str via
                // Borrow; intern only on insert so the heap allocation
                // is shared across repeats of the same lineage.
                let is_new = !self.process_lineages.contains(lineage.as_str());
                if self.process_lineages.len() < MAX_LINEAGES {
                    self.process_lineages.insert(intern(&lineage));
                }
                if is_new && self.mature {
                    new_lineage = Some(lineage);
                }
            }
        }

        // Track user login hours — only SUCCESSFUL logins from real
        // sources, with valid usernames.
        //
        // Three filters applied (Wave 5b 2026-05-03 — operator hit a
        // baseline.json full of `Admin`, `AdminGPON`, `123456789`,
        // `!`, `"`, etc., none of which are real Linux accounts):
        //
        //   1. Skip honeypot sources. The agent's honeypot binds 0.0.0.0:2222
        //      and accepts any credential to fool attackers; if the session
        //      log ever flows back through the event pipeline (now or via a
        //      future wiring) it must NOT contaminate baseline.
        //   2. Skip events tagged `honeypot`. Same rationale — defence in
        //      depth against any path that bypasses the source check.
        //   3. Skip entity values that don't look like Linux usernames.
        //      POSIX/util-linux constraints: must start with `[a-z_]`, then
        //      `[a-z0-9_-]`, optional trailing `$`. Anything outside is
        //      either spoofed (Accepted password for "AdminGPON" emitted by
        //      a third-party sshd-honeypot) or a bug in the auth_log parser
        //      misreading e.g. quoted shell tokens. Either way, the
        //      operator-facing heatmap should not show it.
        let is_honeypot =
            event.source.starts_with("honeypot") || event.tags.iter().any(|t| t == "honeypot");
        if !is_honeypot && (event.kind == "ssh.login_success" || event.kind.contains("accepted")) {
            for entity in &event.entities {
                if entity.r#type == EntityType::User && is_valid_unix_username(&entity.value) {
                    // Wave 6b: usernames repeat per login event; intern
                    // so the map key is shared across the day.
                    let profile = self
                        .user_login_hours
                        .entry(intern(&entity.value))
                        .or_insert([0; 24]);
                    profile[hour as usize] = profile[hour as usize].saturating_add(1);
                }
            }
        }

        // Track outbound destinations per process
        // Check for new destination BEFORE inserting (same pattern as lineages).
        let mut new_destination: Option<(String, String, usize)> = None;
        if event.kind == "network.outbound_connect" {
            if let Some(comm) = event.details.get("comm").and_then(|v| v.as_str()) {
                if let Some(dst_ip) = event.details.get("dst_ip").and_then(|v| v.as_str()) {
                    if let Some(known_dests) = self.process_destinations.get(comm) {
                        if !known_dests.contains(dst_ip) && known_dests.len() >= 3 && self.mature {
                            new_destination =
                                Some((comm.to_string(), dst_ip.to_string(), known_dests.len()));
                        }
                    }
                    if self.process_destinations.len() < MAX_DESTINATION_PROCESSES {
                        // Wave 6b: process names (`comm`) are bounded
                        // — `sshd`, `bash`, `curl`, etc. — and repeat
                        // across every observed connect; intern so
                        // the map key allocation is shared.
                        let dests = self.process_destinations.entry(intern(comm)).or_default();
                        if dests.len() < MAX_DESTINATIONS_PER_PROCESS {
                            dests.insert(dst_ip.to_string());
                        }
                    }
                }
            }
        }

        // Anomaly detection only when mature
        if !self.mature {
            return Vec::new();
        }

        let mut anomalies = Vec::new();

        // Check process lineage anomaly (using pre-computed new_lineage)
        if let Some(lineage) = new_lineage {
            anomalies.push(AnomalyReport {
                anomaly_type: AnomalyType::ProcessLineage,
                description: format!("Previously unseen process lineage: {lineage}"),
                expected: "Known process lineage".into(),
                observed: lineage,
                confidence: 0.7,
                severity: Severity::Medium,
            });
        }

        // Check user login time anomaly
        if event.kind.contains("login") || event.kind.contains("accepted") {
            for entity in &event.entities {
                if entity.r#type == EntityType::User {
                    if let Some(profile) = self.user_login_hours.get(entity.value.as_str()) {
                        if profile[hour as usize] == 0 {
                            // User never logged in at this hour before
                            anomalies.push(AnomalyReport {
                                anomaly_type: AnomalyType::UserLoginTime,
                                description: format!(
                                    "User '{}' logged in at {}:00 UTC (never seen at this hour)",
                                    entity.value, hour
                                ),
                                expected: format!("Login hours: {}", format_active_hours(profile)),
                                observed: format!("{}:00 UTC", hour),
                                confidence: 0.6,
                                severity: Severity::Medium,
                            });
                        }
                    }
                }
            }
        }

        // Check new outbound destination (using pre-computed new_destination)
        if let Some((comm, dst_ip, known_count)) = new_destination {
            anomalies.push(AnomalyReport {
                anomaly_type: AnomalyType::NewDestination,
                description: format!(
                    "Process '{}' connected to new destination {} (not in {} known destinations)",
                    comm, dst_ip, known_count
                ),
                expected: format!("{} known destinations", known_count),
                observed: dst_ip,
                confidence: 0.5,
                severity: Severity::Low,
            });
        }

        anomalies
    }

    /// Check event rate anomalies. Call this periodically (e.g., every 5 minutes).
    ///
    /// Returns anomalies for sources whose event rate significantly deviates
    /// from the baseline for the current hour.
    pub fn check_rate_anomalies(&self) -> Vec<AnomalyReport> {
        if !self.mature {
            return Vec::new();
        }

        let hour = Utc::now().hour() as usize;
        let mut anomalies = Vec::new();

        for (source, count) in &self.current_hour_counts {
            if let Some(baseline) = self.event_rate_by_hour.get(source) {
                let expected = baseline[hour];
                if expected < MIN_RATE_BASELINE {
                    continue; // Not enough data to compare
                }

                let current = *count as f32;
                let ratio = current / expected;

                // Silence detection: rate dropped >80%
                if ratio < SILENCE_THRESHOLD && current < expected - MIN_RATE_BASELINE {
                    anomalies.push(AnomalyReport {
                        anomaly_type: AnomalyType::EventRateDrop,
                        description: format!(
                            "Event rate for '{}' dropped {:.0}% vs baseline ({} vs {:.0} expected at {}:00)",
                            source,
                            (1.0 - ratio) * 100.0,
                            count,
                            expected,
                            hour
                        ),
                        expected: format!("{:.0} events", expected),
                        observed: format!("{} events", count),
                        confidence: 0.7,
                        severity: Severity::High, // Silence is dangerous
                    });
                }

                // Spike detection: rate increased >300%
                if ratio > SPIKE_THRESHOLD {
                    anomalies.push(AnomalyReport {
                        anomaly_type: AnomalyType::EventRateSpike,
                        description: format!(
                            "Event rate for '{}' spiked {:.0}x vs baseline ({} vs {:.0} expected at {}:00)",
                            source,
                            ratio,
                            count,
                            expected,
                            hour
                        ),
                        expected: format!("{:.0} events", expected),
                        observed: format!("{} events", count),
                        confidence: 0.6,
                        severity: Severity::Medium,
                    });
                }
            }
        }

        anomalies
    }

    /// Persist the baseline to a JSON file (and SQLite blob if available).
    pub fn save(&self, data_dir: &Path, store: Option<&innerwarden_store::Store>) {
        let path = data_dir.join("baseline.json");
        match serde_json::to_string(self) {
            Ok(json) => {
                // Dual-write: SQLite blob + JSON file
                if let Some(sq) = store {
                    if let Err(e) = sq.set_blob("baseline", &json) {
                        warn!("failed to write baseline blob: {e}");
                    }
                }
                if let Err(e) = std::fs::write(&path, json) {
                    warn!("failed to write baseline.json: {e}");
                }
            }
            Err(e) => warn!("failed to serialize baseline: {e}"),
        }
    }

    /// Load a baseline — try SQLite blob first, fall back to JSON file.
    pub fn load(data_dir: &Path, store: Option<&innerwarden_store::Store>) -> Self {
        // Try SQLite blob first
        if let Some(sq) = store {
            if let Ok(Some(json)) = sq.get_blob("baseline") {
                match serde_json::from_str(&json) {
                    Ok(b) => {
                        info!("loaded baseline from sqlite blob");
                        return b;
                    }
                    Err(e) => warn!("failed to deserialize baseline blob: {e}"),
                }
            }
        }
        // Fall back to JSON file
        let path = data_dir.join("baseline.json");
        let Ok(content) = std::fs::read_to_string(&path) else {
            return Self::new();
        };
        match serde_json::from_str(&content) {
            Ok(store) => {
                info!("loaded baseline from disk");
                store
            }
            Err(e) => {
                warn!("failed to deserialize baseline: {e}");
                Self::new()
            }
        }
    }

    /// 2026-05-03 (Wave 5b): one-shot cleanup of pre-Wave-5b pollution.
    /// Removes any `user_login_hours` entries whose key does not look
    /// like a valid Linux username. Run at boot after `load`. Safe to
    /// call repeatedly — idempotent and cheap (linear in user count).
    ///
    /// Returns the number of entries removed so the caller can log
    /// the operator-visible delta.
    pub fn prune_invalid_users(&mut self) -> usize {
        let before = self.user_login_hours.len();
        self.user_login_hours
            .retain(|user, _| is_valid_unix_username(user));
        before - self.user_login_hours.len()
    }

    // ── Internal ───────────────────────────────────────────────────

    /// Flush current hour counts into the running average.
    fn flush_hour_counts(&mut self) {
        let hour = self.current_hour as usize;
        for (source, count) in &self.current_hour_counts {
            let profile = self
                .event_rate_by_hour
                .entry(source.clone())
                .or_insert([0.0; 24]);
            // Exponential moving average: new = 0.8 * old + 0.2 * current
            // This gives more weight to recent data while retaining history.
            profile[hour] = profile[hour] * 0.8 + *count as f32 * 0.2;
        }
        self.current_hour_counts.clear();
    }
}

impl Default for BaselineStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// 2026-05-03 (Wave 5b): does `name` look like a valid Linux username?
///
/// Rule from POSIX 3.437 + util-linux `useradd(8)` `NAME_REGEX`:
/// must start with `[a-z_]`, then `[a-z0-9_-]`, optionally end with `$`
/// (Samba-style machine accounts). Length 1..=32. Operator-extension
/// note: this is NOT meant to be exhaustive — anyone running a host
/// with `NAME_REGEX` overridden in `/etc/login.defs` to allow `[A-Z]`
/// will see those names rejected here. The trade-off is intentional:
/// the operator's complaint was that `Admin`, `AdminGPON`, `1234`,
/// `123456789`, `!`, `"`, `(`, `)`, `*` were appearing as "users who
/// log in" — every one of those fails this check, while every real
/// account on the prod hosts (`ubuntu`, `_apt`, `systemd-resolve`,
/// `snap_daemon`) passes.
///
/// Pure function. No I/O. Tested below.
fn is_valid_unix_username(name: &str) -> bool {
    let bytes = name.as_bytes();
    let len = bytes.len();
    if !(1..=32).contains(&len) {
        return false;
    }
    // First char: [a-z_]
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first == b'_') {
        return false;
    }
    // Middle chars: [a-z0-9_-]
    let middle_end = if bytes[len - 1] == b'$' { len - 1 } else { len };
    for &b in &bytes[1..middle_end] {
        let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-';
        if !ok {
            return false;
        }
    }
    true
}

fn format_active_hours(profile: &[u8; 24]) -> String {
    let active: Vec<String> = profile
        .iter()
        .enumerate()
        .filter(|(_, v)| **v > 0)
        .map(|(h, _)| format!("{h}:00"))
        .collect();
    if active.is_empty() {
        "none".to_string()
    } else {
        active.join(", ")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;

    /// Wave 6b (AUDIT-WAVE6B-INTERN) anchor: 1000 events with the same
    /// `source = "auth_log"` produce a `current_hour_counts` HashMap
    /// with ONE entry whose key is pointer-equal to
    /// `intern("auth_log")`. Same shape as the telemetry anchor —
    /// proves the interning is wired at the per-event insert site
    /// for `current_hour_counts`.
    #[test]
    fn observe_event_interns_current_hour_counts_key() {
        let mut store = BaselineStore::new();
        let ev = make_event("auth_log", "ssh.login_failed");
        for _ in 0..1000 {
            let _ = store.observe_event(&ev);
        }
        let canonical = intern("auth_log");
        let stored = store
            .current_hour_counts
            .keys()
            .find(|k| k.as_ref() == "auth_log")
            .expect("auth_log key present");
        assert!(
            Arc::ptr_eq(stored, &canonical),
            "current_hour_counts key must share Arc allocation with intern(\"auth_log\")"
        );
        assert_eq!(
            store.current_hour_counts.get("auth_log").copied(),
            Some(1000)
        );
    }

    /// Wave 6b: user_login_hours map keys are interned. 100 successful
    /// logins for `ubuntu` produce ONE entry whose key is pointer-equal
    /// to `intern("ubuntu")`.
    #[test]
    fn observe_event_interns_user_login_hours_key() {
        let mut store = BaselineStore::new();
        let mut ev = make_event("auth_log", "ssh.login_success");
        ev.entities = vec![EntityRef::user("ubuntu")];
        for _ in 0..100 {
            let _ = store.observe_event(&ev);
        }
        let canonical = intern("ubuntu");
        let stored = store
            .user_login_hours
            .keys()
            .find(|k| k.as_ref() == "ubuntu")
            .expect("ubuntu key present");
        assert!(
            Arc::ptr_eq(stored, &canonical),
            "user_login_hours key must share Arc allocation with intern(\"ubuntu\")"
        );
    }

    /// Wave 6b: process_lineages set members are interned. Same
    /// lineage observed many times produces ONE Arc<str> entry.
    #[test]
    fn observe_event_interns_process_lineages_member() {
        let mut store = BaselineStore::new();
        let ev = make_exec_event("systemd", "sshd");
        for _ in 0..200 {
            let _ = store.observe_event(&ev);
        }
        let canonical = intern("systemd→sshd");
        let stored = store
            .process_lineages
            .iter()
            .find(|s| s.as_ref() == "systemd→sshd")
            .expect("lineage present");
        assert!(
            Arc::ptr_eq(stored, &canonical),
            "process_lineages member must share Arc allocation with intern(\"systemd→sshd\")"
        );
    }

    /// Wave 6b: round-trip JSON serialize → deserialize keeps the on-
    /// disk wire format unchanged. Pre- and post-Wave-6b agents must
    /// be able to load the SAME `baseline.json`.
    #[test]
    fn baseline_store_arc_str_keys_round_trip_through_json() {
        let mut store = BaselineStore::new();
        let ev = make_event("auth_log", "ssh.login_failed");
        for _ in 0..3 {
            let _ = store.observe_event(&ev);
        }
        let json = serde_json::to_string(&store).expect("serialize");
        // Wire format check: keys appear as plain JSON strings.
        assert!(
            json.contains("\"auth_log\""),
            "auth_log must appear as plain string: {json}"
        );
        let back: BaselineStore = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            back.current_hour_counts.get("auth_log").copied(),
            Some(3),
            "round-trip preserves count under same key"
        );
    }

    fn make_event(source: &str, kind: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: source.into(),
            kind: kind.into(),
            severity: Severity::Info,
            summary: String::new(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        }
    }

    fn make_exec_event(parent: &str, child: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "shell.command_exec".into(),
            severity: Severity::Info,
            summary: String::new(),
            details: serde_json::json!({
                "parent_comm": parent,
                "comm": child,
                "pid": 1234,
                "uid": 0,
            }),
            tags: vec!["ebpf".into()],
            entities: vec![],
        }
    }

    fn make_login_event(user: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "auth_log".into(),
            kind: "ssh.login_accepted".into(),
            severity: Severity::Info,
            summary: String::new(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::user(user)],
        }
    }

    fn make_connect_event(comm: &str, dst_ip: &str) -> Event {
        Event {
            ts: Utc::now(),
            host: "test".into(),
            source: "ebpf".into(),
            kind: "network.outbound_connect".into(),
            severity: Severity::Info,
            summary: String::new(),
            details: serde_json::json!({
                "comm": comm,
                "dst_ip": dst_ip,
                "dst_port": 443,
            }),
            tags: vec!["ebpf".into()],
            entities: vec![EntityRef::ip(dst_ip)],
        }
    }

    #[test]
    fn new_baseline_is_immature() {
        let store = BaselineStore::new();
        assert!(!store.is_mature());
        assert_eq!(store.training_days(), 0);
    }

    // ── Wave 5b 2026-05-03 — username sanity + honeypot filter ────
    //
    // Operator hit a baseline.json with `Admin`, `AdminGPON`,
    // `123456789`, `!`, `(`, `*` etc. recorded as if they had real
    // login hours. None of those are valid Linux usernames; all are
    // brute-force attempts that somehow reached the success branch
    // (third-party sshd-honeypot, log spoofing, or auth_log parser
    // edge case). The filter has three layers, each pinned by a
    // test below so a refactor that drops any layer ships red.

    #[test]
    fn is_valid_unix_username_accepts_real_accounts() {
        // Every account on the prod hosts the operator runs.
        // Note: Samba machine accounts like `DOMAIN$` (uppercase + $)
        // are intentionally NOT supported — InnerWarden's target
        // deployment is Linux servers and the cost of allowing
        // `[A-Z]` would be re-admitting `Admin`, `AdminGPON`,
        // `Administrator` (the actual operator complaint). If a
        // future Samba deployment surfaces, lift the lowercase
        // restriction here AND document via an operator-configurable
        // override; do not silently broaden.
        for ok in &[
            "ubuntu",
            "root",
            "snap_daemon",
            "_apt",
            "systemd-resolve",
            "messagebus",
            "syslog",
            "u", // single-char minimum
        ] {
            assert!(
                is_valid_unix_username(ok),
                "real username `{ok}` was rejected"
            );
        }
    }

    #[test]
    fn is_valid_unix_username_rejects_brute_force_and_garbage() {
        // Exact strings observed in the operator's polluted baseline
        // on 2026-05-03. Every one of these MUST fail the check.
        for bad in &[
            "Admin",         // capital A — Linux usernames are lowercase
            "AdminGPON",     // capital + GPON router brute-force list
            "Administrator", // Windows-style
            "1234",          // starts with digit
            "123456789",     // starts with digit
            "2k18",          // starts with digit
            "!",
            "\"",
            "(",
            ")",
            "*",
            ".",
            "",                                       // empty
            "abcdefghijklmnopqrstuvwxyz0123456789ab", // 38 chars (>32)
            "user with space",
            "user@host",
            "../../etc/passwd",
        ] {
            assert!(
                !is_valid_unix_username(bad),
                "garbage username `{bad}` was accepted"
            );
        }
    }

    #[test]
    fn observe_event_skips_honeypot_source_logins() {
        // ANCHOR: the honeypot accepts every credential to fool
        // attackers. If its session log is ever wired back into the
        // event pipeline, baseline must NOT record those usernames.
        let mut store = BaselineStore::new();
        let mut ev = make_login_event("ubuntu");
        ev.source = "honeypot_ssh".into();
        store.observe_event(&ev);
        assert!(
            store.user_login_hours.is_empty(),
            "honeypot_ssh source must not write to user_login_hours"
        );
    }

    #[test]
    fn observe_event_skips_honeypot_tagged_logins() {
        // ANCHOR: defence-in-depth — even if a future code path
        // emits the honeypot session as source="auth_log" but tags
        // it with "honeypot", the tag must also gate the write.
        let mut store = BaselineStore::new();
        let mut ev = make_login_event("ubuntu");
        ev.tags = vec!["honeypot".into()];
        store.observe_event(&ev);
        assert!(
            store.user_login_hours.is_empty(),
            "honeypot-tagged event must not write to user_login_hours"
        );
    }

    #[test]
    fn observe_event_skips_invalid_usernames() {
        // ANCHOR: even from a non-honeypot source, a username that
        // fails `is_valid_unix_username` must not be recorded. This
        // is the actual operator-hit case: real auth_log emitted
        // `ssh.login_success` with entities=["AdminGPON"] (likely
        // a PAM module misconfig or third-party sshd) and baseline
        // recorded it.
        let mut store = BaselineStore::new();
        for bad in &["AdminGPON", "1234", "!", "Administrator"] {
            store.observe_event(&make_login_event(bad));
        }
        assert!(
            store.user_login_hours.is_empty(),
            "invalid usernames must not write to user_login_hours"
        );
        // And good usernames must still pass.
        store.observe_event(&make_login_event("ubuntu"));
        assert!(
            store.user_login_hours.contains_key("ubuntu"),
            "real username must still be recorded"
        );
    }

    #[test]
    fn prune_invalid_users_cleans_pre_wave5b_pollution() {
        // ANCHOR: existing baseline.json files on prod hosts will
        // still carry pollution from before Wave 5b. The boot path
        // calls `prune_invalid_users` once at load time. This test
        // pins the cleanup so a future refactor that drops the
        // call leaves the operator looking at garbage.
        let mut store = BaselineStore::new();
        store.user_login_hours.insert("ubuntu".into(), [1; 24]);
        store.user_login_hours.insert("snap_daemon".into(), [0; 24]);
        store.user_login_hours.insert("AdminGPON".into(), [3; 24]);
        store.user_login_hours.insert("123456789".into(), [5; 24]);
        store.user_login_hours.insert("(".into(), [7; 24]);
        let removed = store.prune_invalid_users();
        assert_eq!(removed, 3, "expected 3 invalid entries pruned");
        assert!(store.user_login_hours.contains_key("ubuntu"));
        assert!(store.user_login_hours.contains_key("snap_daemon"));
        assert!(!store.user_login_hours.contains_key("AdminGPON"));
        assert!(!store.user_login_hours.contains_key("("));
    }

    #[test]
    fn training_period_tracks_days() {
        let mut store = BaselineStore::new();
        // Simulate events across 7 different days
        for day in 1..=7 {
            let mut ev = make_event("auth_log", "ssh.login_failed");
            ev.ts = chrono::NaiveDate::from_ymd_opt(2026, 3, day)
                .unwrap()
                .and_hms_opt(12, 0, 0)
                .unwrap()
                .and_utc();
            store.observe_event(&ev);
        }
        assert!(store.is_mature());
        assert_eq!(store.training_days(), 7);
    }

    #[test]
    fn no_anomalies_during_training() {
        let mut store = BaselineStore::new();
        let ev = make_exec_event("nginx", "sh");
        let anomalies = store.observe_event(&ev);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn process_lineage_anomaly_after_training() {
        let mut store = BaselineStore::new();

        // Train for 7 days with known lineage
        for day in 1..=7 {
            let mut ev = make_exec_event("nginx", "worker");
            ev.ts = chrono::NaiveDate::from_ymd_opt(2026, 3, day)
                .unwrap()
                .and_hms_opt(12, 0, 0)
                .unwrap()
                .and_utc();
            store.observe_event(&ev);
        }
        assert!(store.is_mature());

        // Now a new lineage should trigger anomaly
        let ev = make_exec_event("nginx", "sh");
        let anomalies = store.observe_event(&ev);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].anomaly_type,
            AnomalyType::ProcessLineage
        ));
    }

    #[test]
    fn known_lineage_no_anomaly() {
        let mut store = BaselineStore::new();

        // Train with nginx→sh
        for day in 1..=7 {
            let mut ev = make_exec_event("nginx", "sh");
            ev.ts = chrono::NaiveDate::from_ymd_opt(2026, 3, day)
                .unwrap()
                .and_hms_opt(12, 0, 0)
                .unwrap()
                .and_utc();
            store.observe_event(&ev);
        }

        // Same lineage again — no anomaly
        let ev = make_exec_event("nginx", "sh");
        let anomalies = store.observe_event(&ev);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn new_destination_anomaly() {
        let mut store = BaselineStore::new();

        // Train for 7 days with known destinations
        for day in 1..=7 {
            for ip in &["1.1.1.1", "8.8.8.8", "9.9.9.9"] {
                let mut ev = make_connect_event("curl", ip);
                ev.ts = chrono::NaiveDate::from_ymd_opt(2026, 3, day)
                    .unwrap()
                    .and_hms_opt(12, 0, 0)
                    .unwrap()
                    .and_utc();
                store.observe_event(&ev);
            }
        }
        assert!(store.is_mature());

        // New destination should trigger anomaly
        let ev = make_connect_event("curl", "185.220.101.45");
        let anomalies = store.observe_event(&ev);
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].anomaly_type,
            AnomalyType::NewDestination
        ));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut store = BaselineStore::new();
        store.process_lineages.insert("nginx→worker".into());
        store.training_days = 5;
        store.save(dir.path(), None);

        let loaded = BaselineStore::load(dir.path(), None);
        assert_eq!(loaded.training_days, 5);
        assert!(loaded.process_lineages.contains("nginx→worker"));
    }

    #[test]
    fn rate_anomaly_silence() {
        let mut store = BaselineStore::new();
        // Fake a mature baseline with known rate
        store.mature = true;
        store.training_days = 7;
        let hour = Utc::now().hour() as usize;
        store.event_rate_by_hour.insert("auth_log".into(), {
            let mut arr = [0.0f32; 24];
            arr[hour] = 100.0; // baseline: 100 events at this hour
            arr
        });
        // Current hour: only 5 events (95% drop)
        store.current_hour = hour as u8;
        store.current_hour_counts.insert("auth_log".into(), 5);

        let anomalies = store.check_rate_anomalies();
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].anomaly_type,
            AnomalyType::EventRateDrop
        ));
        assert_eq!(anomalies[0].severity, Severity::High);
    }

    #[test]
    fn rate_anomaly_spike() {
        let mut store = BaselineStore::new();
        store.mature = true;
        store.training_days = 7;
        let hour = Utc::now().hour() as usize;
        store.event_rate_by_hour.insert("auth_log".into(), {
            let mut arr = [0.0f32; 24];
            arr[hour] = 10.0; // baseline: 10 events at this hour
            arr
        });
        store.current_hour = hour as u8;
        store.current_hour_counts.insert("auth_log".into(), 50); // 5x spike

        let anomalies = store.check_rate_anomalies();
        assert_eq!(anomalies.len(), 1);
        assert!(matches!(
            anomalies[0].anomaly_type,
            AnomalyType::EventRateSpike
        ));
    }

    // ── recent_anomalies ring buffer (PR #414 / Baseline redesign) ──
    //
    // The dashboard's Baseline tab consumes recent_anomalies to render
    // deviation cards. Buffer is bounded so the JSON payload + RAM
    // stay tiny. These tests pin the contract: append-on-call, drop
    // oldest first when over cap, count-by-window predicate.

    fn dummy_anomaly(severity: Severity) -> AnomalyReport {
        AnomalyReport {
            anomaly_type: AnomalyType::UserLoginTime,
            description: "user logged at 3am".to_string(),
            expected: "9-18h".to_string(),
            observed: "03:47".to_string(),
            confidence: 0.9,
            severity,
        }
    }

    #[test]
    fn record_anomaly_appends_to_recent_buffer() {
        let mut store = BaselineStore::new();
        assert_eq!(store.recent_anomalies.len(), 0);
        store.record_anomaly(&dummy_anomaly(Severity::Medium), Some("ubuntu".to_string()));
        assert_eq!(store.recent_anomalies.len(), 1);
        let a = &store.recent_anomalies[0];
        assert_eq!(a.subject.as_deref(), Some("ubuntu"));
        assert!(matches!(a.severity, Severity::Medium));
        assert!(matches!(a.anomaly_type, AnomalyType::UserLoginTime));
    }

    #[test]
    fn record_anomaly_caps_at_max_recent_anomalies() {
        let mut store = BaselineStore::new();
        // Push more than the cap. Cap value is intentionally not
        // imported here so the test enforces the *behaviour*
        // ("bounded buffer") even if the constant changes.
        for i in 0..(MAX_RECENT_ANOMALIES + 25) {
            store.record_anomaly(&dummy_anomaly(Severity::Low), Some(format!("subj-{i}")));
        }
        assert_eq!(
            store.recent_anomalies.len(),
            MAX_RECENT_ANOMALIES,
            "buffer must not exceed cap"
        );
        // Oldest entries dropped first: subject of first remaining
        // entry is the (cap)-th push (0-indexed: subj-25).
        let first = store.recent_anomalies.front().unwrap();
        assert_eq!(first.subject.as_deref(), Some("subj-25"));
    }

    #[test]
    fn record_anomaly_preserves_insertion_order() {
        let mut store = BaselineStore::new();
        store.record_anomaly(&dummy_anomaly(Severity::Low), Some("a".to_string()));
        store.record_anomaly(&dummy_anomaly(Severity::Medium), Some("b".to_string()));
        store.record_anomaly(&dummy_anomaly(Severity::High), Some("c".to_string()));
        let subjects: Vec<_> = store
            .recent_anomalies
            .iter()
            .map(|a| a.subject.as_deref().unwrap_or("").to_string())
            .collect();
        assert_eq!(subjects, vec!["a", "b", "c"]);
    }

    #[test]
    fn record_anomaly_accepts_none_subject() {
        let mut store = BaselineStore::new();
        store.record_anomaly(&dummy_anomaly(Severity::Low), None);
        assert_eq!(store.recent_anomalies.len(), 1);
        assert!(store.recent_anomalies[0].subject.is_none());
    }

    #[test]
    fn anomalies_within_filters_by_time_window() {
        let mut store = BaselineStore::new();
        // Push three anomalies, then manually backdate two of them
        // to test the time-window filter.
        for s in ["a", "b", "c"] {
            store.record_anomaly(&dummy_anomaly(Severity::Low), Some(s.to_string()));
        }
        // Backdate first two: 'a' = 25h ago, 'b' = 10 min ago, 'c' = now.
        store.recent_anomalies[0].ts = Utc::now() - chrono::Duration::hours(25);
        store.recent_anomalies[1].ts = Utc::now() - chrono::Duration::minutes(10);
        // last 1h window catches only 'b' and 'c'.
        assert_eq!(store.anomalies_within(3600), 2);
        // last 24h window catches 'b' and 'c' but not 'a'.
        assert_eq!(store.anomalies_within(24 * 3600), 2);
        // last 30 days catches all three.
        assert_eq!(store.anomalies_within(30 * 24 * 3600), 3);
        // Window of 0 catches nothing.
        assert_eq!(store.anomalies_within(0), 0);
    }

    #[test]
    fn anomalies_within_returns_zero_on_empty_buffer() {
        let store = BaselineStore::new();
        assert_eq!(store.anomalies_within(24 * 3600), 0);
    }

    #[test]
    fn timed_anomaly_serializes_with_subject_field() {
        // The JSON schema is consumed by the dashboard's Baseline
        // tab. Pin the wire shape so a future struct refactor that
        // renames a field is caught at build time, not at the
        // dashboard layer.
        let mut store = BaselineStore::new();
        store.record_anomaly(
            &dummy_anomaly(Severity::Critical),
            Some("203.0.113.7".to_string()),
        );
        let json = serde_json::to_value(&store.recent_anomalies).unwrap();
        let arr = json.as_array().unwrap();
        let entry = &arr[0];
        for field in [
            "ts",
            "anomaly_type",
            "description",
            "expected",
            "observed",
            "severity",
            "subject",
        ] {
            assert!(
                entry.get(field).is_some(),
                "TimedAnomaly serialization must include `{field}` for the dashboard"
            );
        }
        assert_eq!(entry["subject"].as_str(), Some("203.0.113.7"));
    }

    #[test]
    fn timed_anomaly_omits_subject_when_none() {
        // `skip_serializing_if = "Option::is_none"` keeps the JSON
        // payload tight. Dashboard handles missing field gracefully.
        let mut store = BaselineStore::new();
        store.record_anomaly(&dummy_anomaly(Severity::Low), None);
        let json = serde_json::to_value(&store.recent_anomalies).unwrap();
        let entry = &json.as_array().unwrap()[0];
        assert!(
            entry.get("subject").is_none(),
            "subject field must be skipped when None — keeps JSON tight"
        );
    }

    #[test]
    fn baseline_store_serializes_recent_anomalies_with_default_empty() {
        // Default `recent_anomalies` deserialization is exercised by
        // load() of pre-PR-#414 baseline.json files. Round-trip a
        // store with NO recent_anomalies and verify it deserializes
        // as an empty buffer (back-compat anchor).
        let mut store = BaselineStore::new();
        store.record_anomaly(&dummy_anomaly(Severity::Medium), Some("u".to_string()));
        let json = serde_json::to_string(&store).unwrap();
        let restored: BaselineStore = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.recent_anomalies.len(), 1);
        // Pre-PR-#414 baselines lack the field entirely; serde
        // `default` populates an empty deque.
        let legacy_json = r#"{
            "event_rate_by_hour": {},
            "process_lineages": [],
            "user_login_hours": {},
            "process_destinations": {},
            "mature": false,
            "training_days": 0,
            "observed_dates": [],
            "current_hour_counts": {},
            "current_hour": 0,
            "total_observations": 0
        }"#;
        let legacy: BaselineStore = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(legacy.recent_anomalies.len(), 0);
    }
}
