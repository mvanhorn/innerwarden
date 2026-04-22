use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use innerwarden_core::{event::Event, incident::Incident};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::ai::AiAction;
use crate::correlation;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    pub ts: DateTime<Utc>,
    pub tick: String,
    pub events_by_collector: BTreeMap<String, u64>,
    pub incidents_by_detector: BTreeMap<String, u64>,
    pub gate_pass_count: u64,
    /// Added by spec 024 Phase 7 (feedback loop). Snapshots written before
    /// that land on disk without this field, so default to 0 on replay.
    #[serde(default)]
    pub gate_suppressed_total: u64,
    pub ai_sent_count: u64,
    /// Added by spec 024 Phase 7 (telegram-sent counter for the
    /// `innerwarden_telegram_msgs_per_hour` drift metric). Default to 0
    /// on replay of pre-Phase-7 snapshots.
    #[serde(default)]
    pub telegram_sent_count: u64,
    pub ai_decision_count: u64,
    pub avg_decision_latency_ms: f64,
    pub errors_by_component: BTreeMap<String, u64>,
    pub decisions_by_action: BTreeMap<String, u64>,
    pub dry_run_execution_count: u64,
    pub real_execution_count: u64,
}

#[derive(Debug, Default)]
pub struct TelemetryState {
    events_by_collector: BTreeMap<String, u64>,
    incidents_by_detector: BTreeMap<String, u64>,
    gate_pass_count: u64,
    gate_suppressed_total: Arc<AtomicU64>,
    ai_sent_count: u64,
    telegram_sent_count: Arc<AtomicU64>,
    ai_decision_count: u64,
    decision_latency_sum_ms: u128,
    errors_by_component: BTreeMap<String, u64>,
    decisions_by_action: BTreeMap<String, u64>,
    dry_run_execution_count: u64,
    real_execution_count: u64,
}

impl TelemetryState {
    pub fn with_external_counters(
        telegram_sent_count: Arc<AtomicU64>,
        gate_suppressed_total: Arc<AtomicU64>,
    ) -> Self {
        Self {
            telegram_sent_count,
            gate_suppressed_total,
            ..Self::default()
        }
    }

    pub fn observe_events(&mut self, events: &[Event]) {
        for event in events {
            *self
                .events_by_collector
                .entry(event.source.clone())
                .or_insert(0) += 1;
        }
    }

    pub fn observe_incident(&mut self, incident: &Incident) {
        let kind = correlation::detector_kind(incident);
        *self.incidents_by_detector.entry(kind).or_insert(0) += 1;
    }

    pub fn observe_gate_pass(&mut self) {
        self.gate_pass_count += 1;
    }

    pub fn gate_suppressed_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.gate_suppressed_total)
    }

    pub fn observe_ai_sent(&mut self) {
        self.ai_sent_count += 1;
    }

    pub fn observe_ai_decision(&mut self, action: &AiAction, latency_ms: u128) {
        self.ai_decision_count += 1;
        self.decision_latency_sum_ms += latency_ms;
        *self
            .decisions_by_action
            .entry(action_tag(action).to_string())
            .or_insert(0) += 1;
    }

    pub fn observe_execution_path(&mut self, dry_run: bool) {
        if dry_run {
            self.dry_run_execution_count += 1;
        } else {
            self.real_execution_count += 1;
        }
    }

    pub fn observe_error(&mut self, component: &str) {
        *self
            .errors_by_component
            .entry(component.to_string())
            .or_insert(0) += 1;
    }

    pub fn snapshot(&self, tick: &str) -> TelemetrySnapshot {
        let avg_latency = if self.ai_decision_count > 0 {
            self.decision_latency_sum_ms as f64 / self.ai_decision_count as f64
        } else {
            0.0
        };

        TelemetrySnapshot {
            ts: Utc::now(),
            tick: tick.to_string(),
            events_by_collector: self.events_by_collector.clone(),
            incidents_by_detector: self.incidents_by_detector.clone(),
            gate_pass_count: self.gate_pass_count,
            gate_suppressed_total: self.gate_suppressed_total.load(Ordering::Relaxed),
            ai_sent_count: self.ai_sent_count,
            telegram_sent_count: self.telegram_sent_count.load(Ordering::Relaxed),
            ai_decision_count: self.ai_decision_count,
            avg_decision_latency_ms: avg_latency,
            errors_by_component: self.errors_by_component.clone(),
            decisions_by_action: self.decisions_by_action.clone(),
            dry_run_execution_count: self.dry_run_execution_count,
            real_execution_count: self.real_execution_count,
        }
    }
}

pub struct TelemetryWriter {
    data_dir: std::path::PathBuf,
    current_date: String,
    writer: BufWriter<File>,
}

impl TelemetryWriter {
    pub fn new(data_dir: &Path) -> Result<Self> {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let file = open_or_create(data_dir, &today)?;
        Ok(Self {
            data_dir: data_dir.to_owned(),
            current_date: today,
            writer: BufWriter::new(file),
        })
    }

    pub fn write(&mut self, snapshot: &TelemetrySnapshot) -> Result<()> {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        if today != self.current_date {
            if let Err(e) = self.writer.flush() {
                warn!("telemetry flush failed during date rollover: {e}");
            }
            let file = open_or_create(&self.data_dir, &today)?;
            self.writer = BufWriter::new(file);
            self.current_date = today;
        }

        let line =
            serde_json::to_string(snapshot).context("failed to serialize telemetry snapshot")?;
        writeln!(self.writer, "{line}").context("failed to write telemetry snapshot")?;
        self.writer
            .flush()
            .context("failed to flush telemetry snapshot")?;
        Ok(())
    }

    pub fn flush(&mut self) {
        if let Err(e) = self.writer.flush() {
            warn!("telemetry writer flush failed: {e}");
        }
    }
}

pub fn read_latest_snapshot(data_dir: &Path, date: &str) -> Option<TelemetrySnapshot> {
    let path = telemetry_path_for_date(data_dir, date)?;
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);

    let mut latest: Option<TelemetrySnapshot> = None;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                warn!("failed to read telemetry line: {e}");
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<TelemetrySnapshot>(trimmed) {
            Ok(snapshot) => match &latest {
                Some(current) if current.ts >= snapshot.ts => {}
                _ => latest = Some(snapshot),
            },
            Err(e) => {
                warn!("failed to parse telemetry snapshot: {e}");
                continue;
            }
        }
    }

    latest
}

/// Returns the newest telemetry snapshot whose timestamp is <= `not_after`.
/// This is used to compute trailing-window deltas (for example, "last hour")
/// from cumulative counters.
pub fn read_snapshot_at(
    data_dir: &Path,
    date: &str,
    not_after: DateTime<Utc>,
) -> Option<TelemetrySnapshot> {
    let path = telemetry_path_for_date(data_dir, date)?;
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);

    let mut candidate: Option<TelemetrySnapshot> = None;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                warn!("failed to read telemetry line: {e}");
                continue;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<TelemetrySnapshot>(trimmed) {
            Ok(snapshot) => {
                if snapshot.ts > not_after {
                    continue;
                }
                match &candidate {
                    Some(current) if current.ts >= snapshot.ts => {}
                    _ => candidate = Some(snapshot),
                }
            }
            Err(e) => {
                warn!("failed to parse telemetry snapshot: {e}");
            }
        }
    }

    candidate
}

fn action_tag(action: &AiAction) -> &'static str {
    match action {
        AiAction::BlockIp { .. } => "block_ip",
        AiAction::Monitor { .. } => "monitor",
        AiAction::Honeypot { .. } => "honeypot",
        AiAction::SuspendUserSudo { .. } => "suspend_user_sudo",
        AiAction::KillProcess { .. } => "kill_process",
        AiAction::BlockContainer { .. } => "block_container",
        AiAction::RequestConfirmation { .. } => "request_confirmation",
        AiAction::KillChainResponse { .. } => "kill_chain_response",
        AiAction::Ignore { .. } => "ignore",
        AiAction::Dismiss { .. } => "dismiss",
    }
}

fn open_or_create(data_dir: &Path, date: &str) -> Result<File> {
    let safe_date: String = date
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    let path = data_dir.join(format!("telemetry-{safe_date}.jsonl"));
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))
}

fn telemetry_path_for_date(data_dir: &Path, date: &str) -> Option<std::path::PathBuf> {
    // Validate date format strictly - reject anything that isn't YYYY-MM-DD.
    let parsed = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()?;
    let safe_date = parsed.format("%Y-%m-%d").to_string();
    let canonical = std::fs::canonicalize(data_dir).ok()?;
    let target = canonical.join(format!("telemetry-{safe_date}.jsonl"));
    if !target.starts_with(&canonical) {
        return None;
    }
    Some(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai;
    use chrono::Utc;
    use innerwarden_core::{
        entities::EntityRef,
        event::{Event, Severity},
        incident::Incident,
    };
    use tempfile::TempDir;

    #[test]
    fn telemetry_state_tracks_counts_and_latency() {
        let gate_counter = Arc::new(AtomicU64::new(0));
        let telegram_counter = Arc::new(AtomicU64::new(0));
        let mut state =
            TelemetryState::with_external_counters(telegram_counter.clone(), gate_counter.clone());

        let ev = Event {
            ts: Utc::now(),
            host: "h".into(),
            source: "auth.log".into(),
            kind: "ssh.login_failed".into(),
            severity: Severity::Info,
            summary: "x".into(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        state.observe_events(&[ev]);

        let inc = Incident {
            ts: Utc::now(),
            host: "h".into(),
            incident_id: "ssh_bruteforce:1.2.3.4:test".into(),
            severity: Severity::High,
            title: "t".into(),
            summary: "s".into(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        state.observe_incident(&inc);
        state.observe_gate_pass();
        gate_counter.fetch_add(1, Ordering::Relaxed);
        telegram_counter.fetch_add(1, Ordering::Relaxed);
        state.observe_ai_sent();
        state.observe_ai_decision(
            &ai::AiAction::BlockIp {
                ip: "1.2.3.4".to_string(),
                skill_id: "block-ip-ufw".to_string(),
            },
            120,
        );
        state.observe_execution_path(true);
        state.observe_error("ai_provider");

        let snap = state.snapshot("incident_tick");
        assert_eq!(snap.events_by_collector.get("auth.log").copied(), Some(1));
        assert_eq!(
            snap.incidents_by_detector.get("ssh_bruteforce").copied(),
            Some(1)
        );
        assert_eq!(snap.gate_pass_count, 1);
        assert_eq!(snap.gate_suppressed_total, 1);
        assert_eq!(snap.ai_sent_count, 1);
        assert_eq!(snap.telegram_sent_count, 1);
        assert_eq!(snap.ai_decision_count, 1);
        assert_eq!(snap.avg_decision_latency_ms, 120.0);
        assert_eq!(snap.dry_run_execution_count, 1);
        assert_eq!(snap.real_execution_count, 0);
        assert_eq!(
            snap.errors_by_component.get("ai_provider").copied(),
            Some(1)
        );
        assert_eq!(snap.decisions_by_action.get("block_ip").copied(), Some(1));
    }

    #[test]
    fn telemetry_writer_and_reader_roundtrip() {
        let dir = TempDir::new().unwrap();
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let mut writer = TelemetryWriter::new(dir.path()).unwrap();

        let gate_counter = Arc::new(AtomicU64::new(0));
        let telegram_counter = Arc::new(AtomicU64::new(0));
        let mut state =
            TelemetryState::with_external_counters(telegram_counter.clone(), gate_counter.clone());
        state.observe_gate_pass();
        telegram_counter.fetch_add(1, Ordering::Relaxed);
        let first = state.snapshot("incident_tick");
        writer.write(&first).unwrap();

        state.observe_ai_sent();
        let second = state.snapshot("incident_tick");
        writer.write(&second).unwrap();
        writer.flush();

        let latest = read_latest_snapshot(dir.path(), &date).unwrap();
        assert_eq!(latest.ai_sent_count, 1);
        assert_eq!(latest.gate_pass_count, 1);
        assert_eq!(latest.telegram_sent_count, 1);
    }

    #[test]
    fn read_snapshot_at_returns_nearest_snapshot_not_after_threshold() {
        let dir = TempDir::new().unwrap();
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let path = dir.path().join(format!("telemetry-{date}.jsonl"));

        let now = Utc::now();
        let older = TelemetrySnapshot {
            ts: now - chrono::Duration::minutes(75),
            tick: "old".to_string(),
            events_by_collector: BTreeMap::new(),
            incidents_by_detector: BTreeMap::new(),
            gate_pass_count: 0,
            gate_suppressed_total: 0,
            ai_sent_count: 0,
            telegram_sent_count: 1,
            ai_decision_count: 0,
            avg_decision_latency_ms: 0.0,
            errors_by_component: BTreeMap::new(),
            decisions_by_action: BTreeMap::new(),
            dry_run_execution_count: 0,
            real_execution_count: 0,
        };
        let newer = TelemetrySnapshot {
            ts: now - chrono::Duration::minutes(61),
            tick: "near".to_string(),
            events_by_collector: BTreeMap::new(),
            incidents_by_detector: BTreeMap::new(),
            gate_pass_count: 0,
            gate_suppressed_total: 0,
            ai_sent_count: 0,
            telegram_sent_count: 2,
            ai_decision_count: 0,
            avg_decision_latency_ms: 0.0,
            errors_by_component: BTreeMap::new(),
            decisions_by_action: BTreeMap::new(),
            dry_run_execution_count: 0,
            real_execution_count: 0,
        };
        let too_new = TelemetrySnapshot {
            ts: now - chrono::Duration::minutes(10),
            tick: "future".to_string(),
            events_by_collector: BTreeMap::new(),
            incidents_by_detector: BTreeMap::new(),
            gate_pass_count: 0,
            gate_suppressed_total: 0,
            ai_sent_count: 0,
            telegram_sent_count: 99,
            ai_decision_count: 0,
            avg_decision_latency_ms: 0.0,
            errors_by_component: BTreeMap::new(),
            decisions_by_action: BTreeMap::new(),
            dry_run_execution_count: 0,
            real_execution_count: 0,
        };

        let mut content = String::new();
        content.push_str(&serde_json::to_string(&older).unwrap());
        content.push('\n');
        content.push_str(&serde_json::to_string(&newer).unwrap());
        content.push('\n');
        content.push_str(&serde_json::to_string(&too_new).unwrap());
        content.push('\n');
        std::fs::write(path, content).unwrap();

        let threshold = now - chrono::Duration::hours(1);
        let chosen = read_snapshot_at(dir.path(), &date, threshold).unwrap();
        assert_eq!(chosen.tick, "near");
        assert_eq!(chosen.telegram_sent_count, 2);
    }

    #[test]
    fn snapshot_deserialises_without_gate_suppressed_or_telegram_sent() {
        // Pre-spec-024-Phase-7 snapshots landed on disk without the new
        // fields. After the upgrade they would fail parsing and flood the
        // log with warnings. `#[serde(default)]` on both fields makes
        // replay tolerant.
        let legacy = r#"{
            "ts": "2026-04-17T16:50:00Z",
            "tick": "incident_tick",
            "events_by_collector": {"auth.log": 42},
            "incidents_by_detector": {},
            "gate_pass_count": 3,
            "ai_sent_count": 1,
            "ai_decision_count": 1,
            "avg_decision_latency_ms": 120.0,
            "errors_by_component": {},
            "decisions_by_action": {},
            "dry_run_execution_count": 1,
            "real_execution_count": 0
        }"#;
        let parsed: TelemetrySnapshot =
            serde_json::from_str(legacy).expect("legacy snapshot must parse");
        assert_eq!(parsed.gate_suppressed_total, 0);
        assert_eq!(parsed.telegram_sent_count, 0);
        assert_eq!(parsed.gate_pass_count, 3);
        assert_eq!(parsed.ai_sent_count, 1);
    }
}
