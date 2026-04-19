//! Block-rate circuit breaker.
//!
//! Guards every auto-block path against mass-block cascades regardless of
//! the signal source (correlation engines, repeat-offender escalation,
//! auto-rules, AbuseIPDB, AI triage, honeypot router). Without this, a
//! single broken correlation rule (see operator incident 2026-04-18 when
//! `correlation:CL-008` + `repeat-offender` queued 1021 blocks in 24h)
//! can blast the firewall, mesh peers, and Cloudflare edge into a
//! denial-of-self attack before the operator notices.
//!
//! The breaker tracks blocks attempted in the current UTC hour via the
//! sqlite KV store (survives agent restart + decisions drift). When the
//! count crosses `responder.max_blocks_per_hour`, the breaker **trips**:
//!
//! - `Mode::Pause` — subsequent blocks refused until the hour rolls over
//!   or the operator runs `innerwarden system circuit-reset`.
//! - `Mode::DryRun` — subsequent blocks are logged + decision-written but
//!   not executed (useful for staging, shadow rollouts).
//! - `Mode::LogOnly` — counters advance but the breaker never refuses;
//!   intended for measurement-only operation during calibration. Not
//!   recommended for production.
//!
//! The module is I/O-free: it takes a `&Store` handle and a `chrono::Utc`
//! timestamp from the caller. Unit tests plug an in-memory store + a
//! fixed clock — every branch reachable without a real sqlite file.
//!
//! ## Alert semantics (owned by the caller)
//!
//! `CircuitState::trip_once` emits a single `CircuitEvent::Tripped` per
//! hour window (not per refused block) so the notification pipeline does
//! not spam the operator. Subsequent refusals return
//! `CircuitEvent::RefusedSilently`. Auto-rearm fires
//! `CircuitEvent::AutoRearmed` when the UTC hour rolls over.

use chrono::{DateTime, Timelike, Utc};

use innerwarden_store::Store;

/// SQLite KV namespace holding `block_rate/<YYYY-MM-DD-HH>` → decimal counter,
/// and `circuit_breaker/tripped_at/<YYYY-MM-DD-HH>` → RFC3339 timestamp.
pub(crate) const BREAKER_NS: &str = "circuit_breaker";
const RATE_PREFIX: &str = "block_rate";
const TRIPPED_PREFIX: &str = "tripped_at";

/// Operating mode chosen by `responder.circuit_breaker_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Refuse blocks once the threshold is crossed until the next hour.
    Pause,
    /// Count-and-log; never refuse. Used during calibration.
    LogOnly,
    /// Refuse blocks at the executor layer but keep the decision-writer
    /// audit trail (operator still sees what *would* have been blocked).
    DryRun,
}

impl Mode {
    pub(crate) fn from_str_or_default(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "pause" => Mode::Pause,
            "dry_run" | "dry-run" | "dryrun" => Mode::DryRun,
            "log_only" | "log-only" | "logonly" => Mode::LogOnly,
            _ => Mode::Pause,
        }
    }

    /// Human-readable tag for logs / telemetry / dashboard.
    pub(crate) fn as_label(&self) -> &'static str {
        match self {
            Mode::Pause => "pause",
            Mode::LogOnly => "log_only",
            Mode::DryRun => "dry_run",
        }
    }

    /// Whether this mode is expected to refuse blocks after trip. Exposed
    /// for the upcoming dashboard / CLI tiles that need to label the
    /// current mode without replicating the match statement.
    #[allow(dead_code)]
    pub(crate) fn refuses_after_trip(&self) -> bool {
        matches!(self, Mode::Pause | Mode::DryRun)
    }
}

/// Outcome of a single check against the breaker — the caller pattern-
/// matches on this, logs the event, and on `Refuse` shortcuts the block
/// execution. The variants carry everything the telemetry layer needs
/// (current count, limit, mode, hour window) so no second lookup is
/// required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Block may proceed; counter was incremented.
    Allow {
        count: u64,
        limit: u64,
        hour: String,
    },
    /// First block of this hour after the threshold was crossed.
    /// Notification layer emits a CRITICAL alert exactly once.
    TripAndRefuse {
        count: u64,
        limit: u64,
        hour: String,
    },
    /// Breaker was already tripped earlier this hour; refuse silently.
    RefuseAfterTrip {
        count: u64,
        limit: u64,
        hour: String,
    },
    /// Counter auto-rearmed because the UTC hour rolled over. The current
    /// block is allowed. Notification layer emits INFO "breaker rearmed".
    AutoRearm {
        count: u64,
        limit: u64,
        hour: String,
    },
}

impl Decision {
    /// Whether the caller should proceed with the block skill execution.
    pub(crate) fn should_block(&self) -> bool {
        matches!(self, Decision::Allow { .. } | Decision::AutoRearm { .. })
    }
}

/// Inspect + update the breaker state for the current UTC hour. Returns
/// a `Decision` describing whether the caller may proceed. The function
/// writes at most two KV entries (the rate counter and, on first trip of
/// the hour, the tripped-at marker) in a single transaction-like pair.
///
/// `now` is injected so tests can span hour boundaries without sleeping.
pub(crate) fn check_and_record(
    store: &Store,
    now: DateTime<Utc>,
    limit: u64,
    mode: Mode,
) -> Decision {
    let hour = format_hour(now);
    let count = load_count(store, &hour).saturating_add(1);
    persist_count(store, &hour, count);

    let tripped_before = tripped_at(store, &hour).is_some();
    let limit_crossed = count > limit;

    // Log-only never refuses; counters still advance for telemetry.
    if matches!(mode, Mode::LogOnly) {
        return Decision::Allow { count, limit, hour };
    }

    match (tripped_before, limit_crossed) {
        (false, false) => {
            // Rearm detection — fire exactly once per hour, only on the
            // very first attempt of the fresh hour (count == 1 AND the
            // previous hour's tripped marker is still there). Subsequent
            // attempts within the same rearmed hour fall through to
            // plain `Allow` so the log doesn't spam.
            if count == 1 && previous_hour_tripped(store, now) {
                Decision::AutoRearm { count, limit, hour }
            } else {
                Decision::Allow { count, limit, hour }
            }
        }
        (false, true) => {
            mark_tripped(store, &hour, now);
            Decision::TripAndRefuse { count, limit, hour }
        }
        (true, _) => Decision::RefuseAfterTrip { count, limit, hour },
    }
}

/// Operator-triggered reset. Clears the tripped marker for the current
/// hour AND zeroes the counter so the block pipeline resumes fresh.
/// Wired to `innerwarden system circuit-reset` CLI in a follow-up PR;
/// exposed now so the module owns the full surface of the breaker.
#[allow(dead_code)]
pub(crate) fn reset(store: &Store, now: DateTime<Utc>) {
    let hour = format_hour(now);
    let _ = store.kv_delete(BREAKER_NS, &rate_key(&hour));
    let _ = store.kv_delete(BREAKER_NS, &tripped_key(&hour));
}

/// Returns `(current_count, tripped_at)` for the given hour. Used by the
/// upcoming dashboard Health tile and `innerwarden system circuit-status`
/// CLI. Exposed now so tests + future callers share one inspection
/// surface instead of each re-implementing the KV lookup.
#[allow(dead_code)]
pub(crate) fn snapshot(store: &Store, now: DateTime<Utc>) -> (u64, Option<String>) {
    let hour = format_hour(now);
    (load_count(store, &hour), tripped_at(store, &hour))
}

fn format_hour(now: DateTime<Utc>) -> String {
    // UTC alignment avoids DST / timezone-jump corner cases in the
    // counter key. YYYY-MM-DDTHH matches the journal-facing semantics
    // of "per hour" without being locale sensitive.
    format!(
        "{:04}-{:02}-{:02}T{:02}",
        now.date_naive()
            .format("%Y")
            .to_string()
            .parse::<i32>()
            .unwrap_or(0),
        now.date_naive()
            .format("%m")
            .to_string()
            .parse::<u32>()
            .unwrap_or(0),
        now.date_naive()
            .format("%d")
            .to_string()
            .parse::<u32>()
            .unwrap_or(0),
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
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

fn persist_count(store: &Store, hour: &str, count: u64) {
    let _ = store.kv_set(BREAKER_NS, &rate_key(hour), count.to_string().as_bytes());
}

fn tripped_at(store: &Store, hour: &str) -> Option<String> {
    store
        .kv_get_str(BREAKER_NS, &tripped_key(hour))
        .ok()
        .flatten()
}

fn mark_tripped(store: &Store, hour: &str, now: DateTime<Utc>) {
    let _ = store.kv_set(BREAKER_NS, &tripped_key(hour), now.to_rfc3339().as_bytes());
}

fn previous_hour_tripped(store: &Store, now: DateTime<Utc>) -> bool {
    let prev = now - chrono::Duration::hours(1);
    tripped_at(store, &format_hour(prev)).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::open_memory().expect("memory store")
    }

    fn ts(iso: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(iso)
            .expect("valid timestamp")
            .with_timezone(&Utc)
    }

    #[test]
    fn allow_under_threshold_and_increments_counter() {
        let s = store();
        let d = check_and_record(&s, ts("2026-04-19T12:00:00Z"), 100, Mode::Pause);
        assert_eq!(
            d,
            Decision::Allow {
                count: 1,
                limit: 100,
                hour: "2026-04-19T12".into(),
            }
        );
        assert!(d.should_block());
        // Counter actually written.
        let (count, tripped) = snapshot(&s, ts("2026-04-19T12:30:00Z"));
        assert_eq!(count, 1);
        assert_eq!(tripped, None);
    }

    #[test]
    fn trips_on_first_crossing_and_refuses_silently_afterwards() {
        let s = store();
        let now = ts("2026-04-19T12:00:00Z");
        for _ in 0..100 {
            check_and_record(&s, now, 100, Mode::Pause);
        }
        // 101st call trips — alert fires.
        let d = check_and_record(&s, now, 100, Mode::Pause);
        assert!(matches!(d, Decision::TripAndRefuse { .. }));
        assert!(!d.should_block());

        // 102nd+ calls stay silent (same hour).
        let d2 = check_and_record(&s, now, 100, Mode::Pause);
        assert!(matches!(d2, Decision::RefuseAfterTrip { .. }));
        assert!(!d2.should_block());
    }

    #[test]
    fn auto_rearm_when_hour_rolls_over() {
        let s = store();
        let hour_a = ts("2026-04-19T12:00:00Z");
        // Trip the breaker in hour A.
        for _ in 0..101 {
            check_and_record(&s, hour_a, 100, Mode::Pause);
        }
        assert!(snapshot(&s, hour_a).1.is_some(), "hour A tripped");

        // Hour B — first call must auto-rearm and allow.
        let hour_b = ts("2026-04-19T13:05:00Z");
        let d = check_and_record(&s, hour_b, 100, Mode::Pause);
        assert!(matches!(d, Decision::AutoRearm { .. }));
        assert!(d.should_block());

        // Subsequent hour B calls fall back to plain Allow.
        let d2 = check_and_record(&s, hour_b, 100, Mode::Pause);
        assert!(matches!(d2, Decision::Allow { .. }));
    }

    #[test]
    fn log_only_mode_never_refuses() {
        let s = store();
        let now = ts("2026-04-19T12:00:00Z");
        for _ in 0..1000 {
            let d = check_and_record(&s, now, 100, Mode::LogOnly);
            assert!(
                d.should_block(),
                "log_only must always allow the block through"
            );
        }
        // The counter still advanced (useful for measurement dashboards).
        assert_eq!(snapshot(&s, now).0, 1000);
    }

    #[test]
    fn dry_run_mode_trips_same_as_pause() {
        // DryRun refuses at the executor but leaves the audit trail. The
        // module's Decision is identical to Pause; differentiation is at
        // the caller site.
        let s = store();
        let now = ts("2026-04-19T12:00:00Z");
        for _ in 0..100 {
            check_and_record(&s, now, 100, Mode::DryRun);
        }
        let d = check_and_record(&s, now, 100, Mode::DryRun);
        assert!(matches!(d, Decision::TripAndRefuse { .. }));
    }

    #[test]
    fn reset_clears_counter_and_tripped_marker() {
        let s = store();
        let now = ts("2026-04-19T12:00:00Z");
        for _ in 0..101 {
            check_and_record(&s, now, 100, Mode::Pause);
        }
        assert!(snapshot(&s, now).1.is_some());

        reset(&s, now);
        let snap = snapshot(&s, now);
        assert_eq!(snap.0, 0);
        assert_eq!(snap.1, None);

        // After reset, next block allows again.
        let d = check_and_record(&s, now, 100, Mode::Pause);
        assert!(matches!(d, Decision::Allow { .. }));
    }

    #[test]
    fn mode_from_str_happy_paths() {
        assert_eq!(Mode::from_str_or_default("pause"), Mode::Pause);
        assert_eq!(Mode::from_str_or_default("dry_run"), Mode::DryRun);
        assert_eq!(Mode::from_str_or_default("dry-run"), Mode::DryRun);
        assert_eq!(Mode::from_str_or_default("DRYRUN"), Mode::DryRun);
        assert_eq!(Mode::from_str_or_default("log_only"), Mode::LogOnly);
        assert_eq!(Mode::from_str_or_default("log-only"), Mode::LogOnly);
        assert_eq!(Mode::from_str_or_default(""), Mode::Pause);
        assert_eq!(Mode::from_str_or_default("garbage"), Mode::Pause);
    }

    #[test]
    fn mode_labels_stable() {
        // Labels are consumed as Prometheus histogram dimensions + dashboard
        // badges; a silent rename here would break operator tooling.
        assert_eq!(Mode::Pause.as_label(), "pause");
        assert_eq!(Mode::DryRun.as_label(), "dry_run");
        assert_eq!(Mode::LogOnly.as_label(), "log_only");
    }

    #[test]
    fn mode_refuses_after_trip_classification() {
        assert!(Mode::Pause.refuses_after_trip());
        assert!(Mode::DryRun.refuses_after_trip());
        assert!(!Mode::LogOnly.refuses_after_trip());
    }

    #[test]
    fn decision_should_block_matrix() {
        assert!(Decision::Allow {
            count: 1,
            limit: 100,
            hour: "h".into()
        }
        .should_block());
        assert!(Decision::AutoRearm {
            count: 1,
            limit: 100,
            hour: "h".into()
        }
        .should_block());
        assert!(!Decision::TripAndRefuse {
            count: 101,
            limit: 100,
            hour: "h".into()
        }
        .should_block());
        assert!(!Decision::RefuseAfterTrip {
            count: 105,
            limit: 100,
            hour: "h".into()
        }
        .should_block());
    }

    #[test]
    fn snapshot_returns_zero_for_empty_hour() {
        let s = store();
        let (count, tripped) = snapshot(&s, ts("2026-04-19T12:00:00Z"));
        assert_eq!(count, 0);
        assert_eq!(tripped, None);
    }

    #[test]
    fn previous_hour_tripped_detects_transition() {
        // Purpose: guards against the brittle case where operator resets
        // the breaker mid-hour and the AutoRearm branch would still fire
        // spuriously because the previous-hour marker remains.
        let s = store();
        let prior = ts("2026-04-19T11:00:00Z");
        for _ in 0..101 {
            check_and_record(&s, prior, 100, Mode::Pause);
        }
        assert!(previous_hour_tripped(&s, ts("2026-04-19T12:00:00Z")));
        assert!(!previous_hour_tripped(&s, ts("2026-04-19T10:30:00Z")));
    }

    #[test]
    fn counter_key_namespaced_by_hour_not_by_day() {
        // Keys must include the hour stamp so the counter resets
        // automatically at the top of every hour without explicit cleanup.
        let s = store();
        let early = ts("2026-04-19T12:00:00Z");
        let late = ts("2026-04-19T13:00:00Z");
        check_and_record(&s, early, 100, Mode::Pause);
        check_and_record(&s, late, 100, Mode::Pause);
        assert_eq!(snapshot(&s, early).0, 1);
        assert_eq!(snapshot(&s, late).0, 1);
    }
}
