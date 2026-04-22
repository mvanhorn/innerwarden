//! Date-aware 5-minute timeline bucket keys.
//!
//! `KnowledgeGraph::event_timeline` and `dashboard/sensors.rs::detector_timeline`
//! both bucket counts into 5-minute slots. The original key format was a bare
//! `"HH:MM"` (e.g. `"14:30"`), which has two problems:
//!
//! 1. **No date dimension** — under multi-day agent uptime, the same time of
//!    day on two different calendar days collapses into one bucket. The
//!    sensors tab and any windowed query (`report.rs::compute_recent_window`)
//!    cannot distinguish "today at 14:30" from "yesterday at 14:30".
//! 2. **String compare against a wall-clock cutoff fails near midnight** —
//!    `report.rs:903` was doing `bucket.as_str() >= cutoff.format("%H:%M")`.
//!    At 02:00 UTC the cutoff was `"20:00"` (yesterday) but today's snapshot
//!    only had buckets `"00:00".."02:00"`, all alphabetically less than
//!    `"20:00"`, so the loop counted zero events. The 6h window report
//!    silently dropped to zero around midnight.
//!
//! The new key format is ISO 8601-ish: `"YYYY-MM-DDTHH:MM"`. Lexicographic
//! sort matches chronological sort, parsing is `chrono::NaiveDateTime::parse`,
//! and the date dimension survives multi-day uptime.
//!
//! `parse_bucket_key` accepts BOTH formats for back-compat: when the agent
//! restarts and loads an old `HH:MM`-only snapshot, the legacy keys are
//! interpreted as the snapshot's `analyzed_date`. New keys written from now
//! on are always date-prefixed, so the mixed window narrows to a single day
//! after the first slow-loop tick post-upgrade.

use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};

/// Format a UTC instant into the 5-minute bucket key
/// `"YYYY-MM-DDTHH:MM"` used by `event_timeline`.
pub fn format_bucket_key(ts: DateTime<Utc>) -> String {
    let hour = ts.format("%H").to_string();
    let min: u32 = ts.format("%M").to_string().parse().unwrap_or(0);
    format!("{}T{}:{:02}", ts.format("%Y-%m-%d"), hour, (min / 5) * 5)
}

/// Parse a bucket key back into a UTC instant. Accepts both the new
/// date-prefixed form `"YYYY-MM-DDTHH:MM"` and the legacy bare form
/// `"HH:MM"`. For the legacy form the caller must supply the date the
/// snapshot was associated with (typically the snapshot's `analyzed_date`).
///
/// Returns `None` if the key cannot be parsed under either schema.
pub fn parse_bucket_key(key: &str, fallback_date: NaiveDate) -> Option<DateTime<Utc>> {
    if let Ok(naive) = NaiveDateTime::parse_from_str(key, "%Y-%m-%dT%H:%M") {
        return Utc.from_local_datetime(&naive).single();
    }
    // Legacy bare HH:MM
    if let Ok(time) = NaiveTime::parse_from_str(key, "%H:%M") {
        let naive = NaiveDateTime::new(fallback_date, time);
        return Utc.from_local_datetime(&naive).single();
    }
    None
}

/// Strip the date prefix from a bucket key, returning the bare `HH:MM`.
/// Used by the sensors tab JSON serializer to keep the chart's x-axis
/// labels short (the chart only ever shows a single day at a time, so the
/// date prefix is redundant for display). Returns the input unchanged when
/// the key is already in legacy form.
pub fn strip_date_prefix(key: &str) -> &str {
    match key.find('T') {
        Some(i) => &key[i + 1..],
        None => key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(year: i32, month: u32, day: u32, hour: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, min, 0)
            .unwrap()
    }

    #[test]
    fn format_bucket_key_aligns_to_5_minutes() {
        // 14:37 → 14:35
        assert_eq!(
            format_bucket_key(utc(2026, 4, 22, 14, 37)),
            "2026-04-22T14:35"
        );
        // 14:30 → 14:30 (already aligned)
        assert_eq!(
            format_bucket_key(utc(2026, 4, 22, 14, 30)),
            "2026-04-22T14:30"
        );
        // 14:34 → 14:30
        assert_eq!(
            format_bucket_key(utc(2026, 4, 22, 14, 34)),
            "2026-04-22T14:30"
        );
        // 23:59 → 23:55 (last bucket of day)
        assert_eq!(
            format_bucket_key(utc(2026, 4, 22, 23, 59)),
            "2026-04-22T23:55"
        );
        // 00:00 → 00:00 (first bucket of day)
        assert_eq!(
            format_bucket_key(utc(2026, 4, 22, 0, 0)),
            "2026-04-22T00:00"
        );
    }

    #[test]
    fn format_bucket_keys_sort_lexicographically_in_chronological_order() {
        // Across midnight the lexicographic and chronological orders MUST agree
        // — this is the property that lets us continue using a `BTreeMap` with
        // a `String` key and still iterate in time order.
        let a = format_bucket_key(utc(2026, 4, 22, 23, 55));
        let b = format_bucket_key(utc(2026, 4, 23, 0, 0));
        assert!(
            a < b,
            "bucket keys must sort chronologically across midnight"
        );
    }

    #[test]
    fn parse_bucket_key_round_trips_iso_form() {
        let ts = utc(2026, 4, 22, 14, 30);
        let key = format_bucket_key(ts);
        let parsed = parse_bucket_key(&key, NaiveDate::from_ymd_opt(2099, 1, 1).unwrap());
        assert_eq!(parsed, Some(ts));
    }

    #[test]
    fn parse_bucket_key_treats_legacy_hhmm_as_fallback_date() {
        // Old format that pre-existed this fix. Reader uses the snapshot's
        // analyzed_date as the calendar context.
        let snap_date = NaiveDate::from_ymd_opt(2026, 4, 22).unwrap();
        let parsed = parse_bucket_key("14:30", snap_date);
        assert_eq!(parsed, Some(utc(2026, 4, 22, 14, 30)));
    }

    #[test]
    fn parse_bucket_key_rejects_garbage() {
        let snap_date = NaiveDate::from_ymd_opt(2026, 4, 22).unwrap();
        assert_eq!(parse_bucket_key("not-a-bucket", snap_date), None);
        assert_eq!(parse_bucket_key("", snap_date), None);
        // Date-only without time: not a valid bucket either.
        assert_eq!(parse_bucket_key("2026-04-22", snap_date), None);
    }

    #[test]
    fn strip_date_prefix_short_circuits_when_no_t_present() {
        assert_eq!(strip_date_prefix("14:30"), "14:30");
        assert_eq!(strip_date_prefix("2026-04-22T14:30"), "14:30");
        assert_eq!(strip_date_prefix(""), "");
    }
}
