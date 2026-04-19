use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Timelike, Utc};
use innerwarden_store::Store;

const BREAKER_NS: &str = "circuit_breaker";
const RATE_PREFIX: &str = "block_rate";
const TRIPPED_PREFIX: &str = "tripped_at";

/// Snapshot of the breaker state for a given UTC hour. Pure data type so
/// tests can assert on the full read-out without capturing stdout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatusSnapshot {
    pub hour: String,
    pub count: u64,
    pub tripped_at: Option<String>,
}

/// Outcome of clearing the breaker for a given UTC hour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResetOutcome {
    pub hour: String,
    pub cleared_counter: bool,
    pub cleared_trip_marker: bool,
}

impl ResetOutcome {
    pub fn was_already_clean(&self) -> bool {
        !self.cleared_counter && !self.cleared_trip_marker
    }
}

pub(crate) fn cmd_circuit_status(agent_config: &Path, data_dir: &Path, json: bool) -> Result<()> {
    let dir = resolve_store_dir(agent_config, data_dir);
    let store =
        Store::open(&dir).with_context(|| format!("open sqlite store at {}", dir.display()))?;
    let snapshot = read_status(&store, Utc::now());
    render_status(&snapshot, json, &mut std::io::stdout())
}

pub(crate) fn cmd_circuit_reset(agent_config: &Path, data_dir: &Path, json: bool) -> Result<()> {
    let dir = resolve_store_dir(agent_config, data_dir);
    let store =
        Store::open(&dir).with_context(|| format!("open sqlite store at {}", dir.display()))?;
    let outcome = reset_hour(&store, Utc::now());
    render_reset(&outcome, json, &mut std::io::stdout())
}

pub(crate) fn read_status(store: &Store, now: DateTime<Utc>) -> StatusSnapshot {
    let hour = format_hour(now);
    let count = load_count(store, &hour);
    let tripped_at = load_tripped(store, &hour);
    StatusSnapshot {
        hour,
        count,
        tripped_at,
    }
}

pub(crate) fn reset_hour(store: &Store, now: DateTime<Utc>) -> ResetOutcome {
    let hour = format_hour(now);
    let cleared_counter = store
        .kv_delete(BREAKER_NS, &rate_key(&hour))
        .unwrap_or(false);
    let cleared_trip_marker = store
        .kv_delete(BREAKER_NS, &tripped_key(&hour))
        .unwrap_or(false);
    ResetOutcome {
        hour,
        cleared_counter,
        cleared_trip_marker,
    }
}

pub(crate) fn render_status(
    s: &StatusSnapshot,
    json: bool,
    w: &mut dyn std::io::Write,
) -> Result<()> {
    if json {
        let payload = serde_json::json!({
            "hour": s.hour,
            "count": s.count,
            "tripped_at": s.tripped_at,
        });
        writeln!(w, "{}", serde_json::to_string_pretty(&payload)?)?;
    } else {
        writeln!(w, "Circuit breaker status")?;
        writeln!(w, "  hour (UTC):  {}", s.hour)?;
        writeln!(w, "  blocks:      {}", s.count)?;
        match &s.tripped_at {
            Some(ts) => writeln!(
                w,
                "  tripped at:  {ts} (refusing further blocks until next hour or reset)"
            )?,
            None => writeln!(w, "  tripped at:  not tripped")?,
        }
    }
    Ok(())
}

pub(crate) fn render_reset(o: &ResetOutcome, json: bool, w: &mut dyn std::io::Write) -> Result<()> {
    if json {
        let payload = serde_json::json!({
            "hour": o.hour,
            "cleared_counter": o.cleared_counter,
            "cleared_trip_marker": o.cleared_trip_marker,
        });
        writeln!(w, "{}", serde_json::to_string_pretty(&payload)?)?;
    } else {
        writeln!(w, "Circuit breaker reset for hour {} (UTC)", o.hour)?;
        writeln!(w, "  counter cleared:     {}", o.cleared_counter)?;
        writeln!(w, "  trip marker cleared: {}", o.cleared_trip_marker)?;
        if o.was_already_clean() {
            writeln!(w, "  (breaker was already clean)")?;
        }
    }
    Ok(())
}

pub(crate) fn resolve_store_dir(agent_config: &Path, data_dir: &Path) -> PathBuf {
    if data_dir == Path::new("/var/lib/innerwarden") && agent_config.exists() {
        if let Some(dir) = std::fs::read_to_string(agent_config)
            .ok()
            .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
            .and_then(|doc| {
                doc.get("output")
                    .and_then(|o| o.get("data_dir"))
                    .and_then(|d| d.as_str())
                    .map(PathBuf::from)
            })
        {
            return dir;
        }
    }
    data_dir.to_path_buf()
}

fn format_hour(now: DateTime<Utc>) -> String {
    let d = now.date_naive();
    format!(
        "{:04}-{:02}-{:02}T{:02}",
        d.format("%Y").to_string().parse::<i32>().unwrap_or(0),
        d.format("%m").to_string().parse::<u32>().unwrap_or(0),
        d.format("%d").to_string().parse::<u32>().unwrap_or(0),
        now.hour(),
    )
}

fn rate_key(hour: &str) -> String {
    format!("{RATE_PREFIX}/{hour}")
}

fn tripped_key(hour: &str) -> String {
    format!("{TRIPPED_PREFIX}/{hour}")
}

fn load_count(store: &Store, hour: &str) -> u64 {
    store
        .kv_get_str(BREAKER_NS, &rate_key(hour))
        .ok()
        .flatten()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

fn load_tripped(store: &Store, hour: &str) -> Option<String> {
    store
        .kv_get_str(BREAKER_NS, &tripped_key(hour))
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn ts(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn format_hour_pads_zero() {
        assert_eq!(format_hour(ts("2026-01-02T03:04:05Z")), "2026-01-02T03");
    }

    #[test]
    fn load_count_returns_zero_when_missing() {
        let store = Store::open_memory().unwrap();
        assert_eq!(load_count(&store, "2026-04-19T12"), 0);
    }

    #[test]
    fn load_count_parses_stored_value() {
        let store = Store::open_memory().unwrap();
        store
            .kv_set(BREAKER_NS, &rate_key("2026-04-19T12"), b"42")
            .unwrap();
        assert_eq!(load_count(&store, "2026-04-19T12"), 42);
    }

    #[test]
    fn load_count_returns_zero_on_garbage() {
        let store = Store::open_memory().unwrap();
        store
            .kv_set(BREAKER_NS, &rate_key("2026-04-19T12"), b"not-a-number")
            .unwrap();
        assert_eq!(load_count(&store, "2026-04-19T12"), 0);
    }

    #[test]
    fn load_tripped_returns_none_when_clean() {
        let store = Store::open_memory().unwrap();
        assert!(load_tripped(&store, "2026-04-19T12").is_none());
    }

    #[test]
    fn load_tripped_returns_timestamp_when_set() {
        let store = Store::open_memory().unwrap();
        store
            .kv_set(
                BREAKER_NS,
                &tripped_key("2026-04-19T12"),
                b"2026-04-19T12:34:56Z",
            )
            .unwrap();
        assert_eq!(
            load_tripped(&store, "2026-04-19T12").as_deref(),
            Some("2026-04-19T12:34:56Z")
        );
    }

    #[test]
    fn read_status_reports_clean_breaker() {
        let store = Store::open_memory().unwrap();
        let snap = read_status(&store, ts("2026-04-19T12:00:00Z"));
        assert_eq!(snap.hour, "2026-04-19T12");
        assert_eq!(snap.count, 0);
        assert!(snap.tripped_at.is_none());
    }

    #[test]
    fn read_status_reports_tripped_breaker() {
        let store = Store::open_memory().unwrap();
        let hour = "2026-04-19T12";
        store.kv_set(BREAKER_NS, &rate_key(hour), b"105").unwrap();
        store
            .kv_set(BREAKER_NS, &tripped_key(hour), b"2026-04-19T12:05:00Z")
            .unwrap();
        let snap = read_status(&store, ts("2026-04-19T12:30:00Z"));
        assert_eq!(snap.count, 105);
        assert_eq!(snap.tripped_at.as_deref(), Some("2026-04-19T12:05:00Z"));
    }

    #[test]
    fn reset_hour_clears_existing_state() {
        let store = Store::open_memory().unwrap();
        let hour = "2026-04-19T12";
        store.kv_set(BREAKER_NS, &rate_key(hour), b"150").unwrap();
        store
            .kv_set(BREAKER_NS, &tripped_key(hour), b"2026-04-19T12:00:00Z")
            .unwrap();
        let outcome = reset_hour(&store, ts("2026-04-19T12:45:00Z"));
        assert!(outcome.cleared_counter);
        assert!(outcome.cleared_trip_marker);
        assert!(!outcome.was_already_clean());
        assert_eq!(load_count(&store, hour), 0);
        assert!(load_tripped(&store, hour).is_none());
    }

    #[test]
    fn reset_hour_on_clean_breaker_is_noop() {
        let store = Store::open_memory().unwrap();
        let outcome = reset_hour(&store, ts("2026-04-19T12:00:00Z"));
        assert!(!outcome.cleared_counter);
        assert!(!outcome.cleared_trip_marker);
        assert!(outcome.was_already_clean());
    }

    #[test]
    fn reset_hour_only_touches_current_hour() {
        // Reset must NOT wipe next hour's trip marker if one exists (edge
        // case: agent rolled a new hour mid-reset).
        let store = Store::open_memory().unwrap();
        store
            .kv_set(BREAKER_NS, &rate_key("2026-04-19T13"), b"1")
            .unwrap();
        reset_hour(&store, ts("2026-04-19T12:00:00Z"));
        assert_eq!(load_count(&store, "2026-04-19T13"), 1);
    }

    #[test]
    fn render_status_plaintext_happy_path() {
        let s = StatusSnapshot {
            hour: "2026-04-19T12".into(),
            count: 7,
            tripped_at: None,
        };
        let mut buf = Vec::new();
        render_status(&s, false, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("hour (UTC):  2026-04-19T12"));
        assert!(out.contains("blocks:      7"));
        assert!(out.contains("not tripped"));
    }

    #[test]
    fn render_status_plaintext_tripped() {
        let s = StatusSnapshot {
            hour: "2026-04-19T12".into(),
            count: 105,
            tripped_at: Some("2026-04-19T12:05:00Z".into()),
        };
        let mut buf = Vec::new();
        render_status(&s, false, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("tripped at:  2026-04-19T12:05:00Z"));
        assert!(out.contains("refusing further blocks"));
    }

    #[test]
    fn render_status_json_shape() {
        let s = StatusSnapshot {
            hour: "2026-04-19T12".into(),
            count: 3,
            tripped_at: Some("2026-04-19T12:01:00Z".into()),
        };
        let mut buf = Vec::new();
        render_status(&s, true, &mut buf).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["hour"], "2026-04-19T12");
        assert_eq!(v["count"], 3);
        assert_eq!(v["tripped_at"], "2026-04-19T12:01:00Z");
    }

    #[test]
    fn render_reset_plaintext_when_cleared() {
        let o = ResetOutcome {
            hour: "2026-04-19T12".into(),
            cleared_counter: true,
            cleared_trip_marker: true,
        };
        let mut buf = Vec::new();
        render_reset(&o, false, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Circuit breaker reset for hour 2026-04-19T12"));
        assert!(out.contains("counter cleared:     true"));
        assert!(out.contains("trip marker cleared: true"));
        assert!(!out.contains("already clean"));
    }

    #[test]
    fn render_reset_plaintext_when_already_clean() {
        let o = ResetOutcome {
            hour: "2026-04-19T12".into(),
            cleared_counter: false,
            cleared_trip_marker: false,
        };
        let mut buf = Vec::new();
        render_reset(&o, false, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("already clean"));
    }

    #[test]
    fn render_reset_json_shape() {
        let o = ResetOutcome {
            hour: "2026-04-19T12".into(),
            cleared_counter: true,
            cleared_trip_marker: false,
        };
        let mut buf = Vec::new();
        render_reset(&o, true, &mut buf).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["hour"], "2026-04-19T12");
        assert_eq!(v["cleared_counter"], true);
        assert_eq!(v["cleared_trip_marker"], false);
    }

    #[test]
    fn resolve_store_dir_falls_back_to_data_dir_when_default_unmatched() {
        // When operator passed a custom --data-dir, never consult agent.toml.
        let explicit = PathBuf::from("/tmp/explicit");
        assert_eq!(
            resolve_store_dir(Path::new("/does/not/exist.toml"), &explicit),
            explicit
        );
    }

    #[test]
    fn resolve_store_dir_reads_agent_toml_at_default_path() {
        let tmp = tempdir().unwrap();
        let cfg = tmp.path().join("agent.toml");
        std::fs::write(&cfg, "[output]\ndata_dir = \"/tmp/from-agent-toml\"\n").unwrap();
        let resolved = resolve_store_dir(&cfg, Path::new("/var/lib/innerwarden"));
        assert_eq!(resolved, PathBuf::from("/tmp/from-agent-toml"));
    }

    #[test]
    fn resolve_store_dir_ignores_agent_toml_without_data_dir() {
        let tmp = tempdir().unwrap();
        let cfg = tmp.path().join("agent.toml");
        std::fs::write(&cfg, "[ai]\nenabled = false\n").unwrap();
        let resolved = resolve_store_dir(&cfg, Path::new("/var/lib/innerwarden"));
        assert_eq!(resolved, PathBuf::from("/var/lib/innerwarden"));
    }

    #[test]
    fn resolve_store_dir_ignores_missing_agent_toml() {
        let resolved = resolve_store_dir(
            Path::new("/nonexistent/agent.toml"),
            Path::new("/var/lib/innerwarden"),
        );
        assert_eq!(resolved, PathBuf::from("/var/lib/innerwarden"));
    }

    #[test]
    fn cmd_circuit_status_smoke_runs_against_real_store() {
        // End-to-end: open a real sqlite-backed Store, populate, run the
        // full status command, assert it returns Ok (bubbled errors would
        // surface missing coverage on the file-open path).
        let tmp = tempdir().unwrap();
        cmd_circuit_status(Path::new("/nonexistent/agent.toml"), tmp.path(), false).unwrap();
        cmd_circuit_status(Path::new("/nonexistent/agent.toml"), tmp.path(), true).unwrap();
    }

    #[test]
    fn cmd_circuit_reset_smoke_runs_against_real_store() {
        let tmp = tempdir().unwrap();
        cmd_circuit_reset(Path::new("/nonexistent/agent.toml"), tmp.path(), false).unwrap();
        cmd_circuit_reset(Path::new("/nonexistent/agent.toml"), tmp.path(), true).unwrap();
    }
}
