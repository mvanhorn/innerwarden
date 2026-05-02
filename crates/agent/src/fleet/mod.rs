//! MSSP fleet — Phase 1 backend skeleton.
//!
//! Spec 038. The manager dashboard polls each configured spoke's
//! `/api/status` endpoint at a fixed cadence and caches the result
//! in `FleetState`. The `GET /api/fleet/hosts` handler reads the
//! cache; nothing in this module mutates spoke state.
//!
//! ## Why no SSE / push
//!
//! Phase 1 keeps the manager-side surface minimal: one tokio task,
//! one in-memory map. Real-time push (manager subscribes to spoke
//! SSE) is a Phase 5 polish if the operator surfaces a need. A 30-second
//! poll interval already matches the dashboard's slow-loop cadence
//! and is small enough that an offline host is detected within one
//! poll cycle.

pub mod poller;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::Serialize;

/// Slim subset of `OverviewResponse` the fleet poller caches per
/// spoke. Phase 2: the manager parses the spoke's `/api/overview`
/// body defensively and stores only the numeric fields that drive
/// fleet aggregation. Skipping the full struct insulates the
/// manager from cosmetic field changes on the spoke side and keeps
/// the cache footprint small (~80 bytes per host).
#[derive(Debug, Clone, Serialize)]
pub struct FleetHostOverview {
    /// Date the spoke reported. Manager records it but does not act
    /// on date-mismatch — the spoke owns that dimension.
    pub date: String,
    pub events_count: u64,
    pub incidents_count: u64,
    pub decisions_count: u64,
    pub blocked_count: u64,
    pub observing_count: u64,
    pub attention_count: u64,
    pub handled_ips_today: u64,
    /// `health.kind` from the spoke's `OverviewSnapshot` when
    /// present. Drives the manager's `Degraded` verdict: a 200-OK
    /// spoke with `health_kind = "ai_not_responding"` flips its
    /// fleet card from Up to Degraded.
    pub health_kind: Option<String>,
}

/// Snapshot of one spoke's last-known reachability + headline KPIs.
#[derive(Debug, Clone, Serialize)]
pub struct HostStatus {
    /// Stable id from `[fleet.hosts]` config. Used as map key + the
    /// path component for drill-down endpoints (`/api/fleet/host/<id>/...`).
    pub id: String,
    /// Spoke base URL (no trailing slash). The poller appends
    /// `/api/overview` to this when probing.
    pub url: String,
    /// Liveness verdict produced by the most recent poll attempt.
    pub state: HostState,
    /// Wall-clock UTC time of the most recent attempt, regardless of
    /// outcome. `None` until the first poll completes.
    pub last_polled_at: Option<DateTime<Utc>>,
    /// Short error string set when `state` is `Down` or `Degraded`.
    /// Trimmed to 200 chars so a misbehaving spoke cannot inflate
    /// the manager's response payload.
    pub last_error: Option<String>,
    /// Phase 2: most recent overview snapshot from this spoke.
    /// `None` while the host is Down or before the first successful
    /// poll. Serialised as `null` in JSON so the frontend can
    /// distinguish "spoke is up but the snapshot is being fetched"
    /// from "spoke just came up".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overview: Option<FleetHostOverview>,
}

/// Liveness verdict per spoke.
///
/// `Unknown` is the bootstrap state before the first poll. `Up`
/// means the spoke responded `200 OK` to `/api/status`. `Down`
/// means the spoke is unreachable or returned a non-2xx code.
/// `Degraded` is reserved for the case where the spoke responds
/// but its own `SystemHealth` is `AiNotResponding` / `Degraded`
/// — Phase 2 wires that distinction; Phase 1 only emits Up/Down/Unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
pub enum HostState {
    Unknown,
    Up,
    Down,
    /// Reserved for Phase 2: spoke responds 200 but its own
    /// SystemHealth is `AiNotResponding` / `Degraded` / etc. Phase 1
    /// only emits Up/Down/Unknown so the variant is unused for now.
    Degraded,
}

/// Shared, cheaply-cloneable handle to the in-memory fleet cache.
/// The dashboard route handler clones this through axum state; the
/// background poller writes through it.
#[derive(Clone)]
pub struct FleetState {
    inner: Arc<RwLock<HashMap<String, HostStatus>>>,
}

impl FleetState {
    /// Build an empty cache pre-seeded with the configured host
    /// list in `Unknown` state. Pre-seeding means the very first
    /// `GET /api/fleet/hosts` after boot returns the host roster
    /// even before the first poll lands; the operator sees the
    /// fleet shape immediately and watches `state` flip to `Up`
    /// over the next poll cycle.
    pub fn from_config(hosts: &[crate::config::FleetHostConfig]) -> Self {
        let mut map = HashMap::new();
        for host in hosts {
            map.insert(
                host.id.clone(),
                HostStatus {
                    id: host.id.clone(),
                    url: host.url.trim_end_matches('/').to_string(),
                    state: HostState::Unknown,
                    last_polled_at: None,
                    last_error: None,
                    overview: None,
                },
            );
        }
        Self {
            inner: Arc::new(RwLock::new(map)),
        }
    }

    /// Returns the current cache as an owned `Vec`, sorted by host id
    /// so the dashboard renders a stable ordering across polls.
    pub fn snapshot(&self) -> Vec<HostStatus> {
        let map = self.inner.read().unwrap_or_else(|p| p.into_inner());
        let mut hosts: Vec<HostStatus> = map.values().cloned().collect();
        hosts.sort_by(|a, b| a.id.cmp(&b.id));
        hosts
    }

    /// Apply a poll result for one host. Called by the poller task.
    /// Unknown host ids are silently ignored: the cache is seeded
    /// from config, so a stale id arriving here means a config
    /// reload removed the host between polls. Better to drop the
    /// stale write than to grow the map indefinitely.
    ///
    /// `overview` is optional: a Down host or a malformed response
    /// passes `None` to clear the previous snapshot so a stale
    /// overview cannot mask the host being unreachable.
    pub(crate) fn record(
        &self,
        id: &str,
        state: HostState,
        error: Option<String>,
        overview: Option<FleetHostOverview>,
    ) {
        let mut map = self.inner.write().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = map.get_mut(id) {
            entry.state = state;
            entry.last_polled_at = Some(Utc::now());
            entry.last_error = error.map(|s| {
                if s.len() > 200 {
                    let mut truncated: String = s.chars().take(200).collect();
                    truncated.push_str(" ...");
                    truncated
                } else {
                    s
                }
            });
            entry.overview = overview;
        }
    }
}

/// Aggregate KPI counts across every UP host in the fleet, plus the
/// per-host breakdown the dashboard uses to render individual cards.
/// Phase 2 contract: the frontend Fleet tab consumes this shape.
#[derive(Debug, Clone, Serialize)]
pub struct FleetOverviewResponse {
    pub fleet: FleetSummary,
    pub by_host: Vec<HostStatus>,
}

/// Aggregated counters across hosts whose overview is present
/// (i.e. Up or Degraded with a successful poll). Hosts in `Down` /
/// `Unknown` contribute zero to these sums but still increment
/// `down_count` / `unknown_count` so the operator sees the gap.
#[derive(Debug, Clone, Serialize, Default)]
pub struct FleetSummary {
    pub host_count: usize,
    pub up_count: usize,
    pub down_count: usize,
    pub degraded_count: usize,
    pub unknown_count: usize,
    pub events_count: u64,
    pub incidents_count: u64,
    pub decisions_count: u64,
    pub blocked_count: u64,
    pub observing_count: u64,
    pub attention_count: u64,
    pub handled_ips_today: u64,
    /// True when at least one host reports a non-`operating_normally`
    /// health_kind. Drives the fleet KPI tile colour.
    pub any_unhealthy: bool,
}

impl FleetState {
    /// Build the aggregate response from the current cache snapshot.
    /// Pure function over the cache; cheap to call on every request
    /// (the cache itself is updated out-of-band by the poller).
    pub fn aggregate_overview(&self) -> FleetOverviewResponse {
        let hosts = self.snapshot();
        let mut summary = FleetSummary {
            host_count: hosts.len(),
            ..Default::default()
        };
        for host in &hosts {
            match host.state {
                HostState::Up => summary.up_count += 1,
                HostState::Down => summary.down_count += 1,
                HostState::Degraded => summary.degraded_count += 1,
                HostState::Unknown => summary.unknown_count += 1,
            }
            if let Some(o) = &host.overview {
                summary.events_count += o.events_count;
                summary.incidents_count += o.incidents_count;
                summary.decisions_count += o.decisions_count;
                summary.blocked_count += o.blocked_count;
                summary.observing_count += o.observing_count;
                summary.attention_count += o.attention_count;
                summary.handled_ips_today += o.handled_ips_today;
                if let Some(kind) = &o.health_kind {
                    if kind != "operating_normally" {
                        summary.any_unhealthy = true;
                    }
                }
            }
        }
        FleetOverviewResponse {
            fleet: summary,
            by_host: hosts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FleetHostConfig;

    fn host(id: &str, url: &str) -> FleetHostConfig {
        FleetHostConfig {
            id: id.into(),
            url: url.into(),
            token_env: String::new(),
        }
    }

    #[test]
    fn from_config_seeds_unknown_state_for_each_host() {
        let cfg = vec![
            host("prod-eu", "https://eu.example.com:8787"),
            host("prod-us", "https://us.example.com:8787/"),
        ];
        let state = FleetState::from_config(&cfg);
        let snap = state.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].id, "prod-eu");
        assert_eq!(snap[1].id, "prod-us");
        // Trailing slash stripped so the poller can append /api/status
        // without producing `//api/status`.
        assert_eq!(snap[1].url, "https://us.example.com:8787");
        assert_eq!(snap[0].state, HostState::Unknown);
        assert!(snap[0].last_polled_at.is_none());
        assert!(snap[0].last_error.is_none());
    }

    #[test]
    fn record_flips_state_and_stamps_timestamp() {
        let cfg = vec![host("prod-eu", "https://eu.example.com:8787")];
        let state = FleetState::from_config(&cfg);
        state.record("prod-eu", HostState::Up, None, None);
        let snap = state.snapshot();
        assert_eq!(snap[0].state, HostState::Up);
        assert!(snap[0].last_polled_at.is_some());
        assert!(snap[0].last_error.is_none());
    }

    #[test]
    fn record_truncates_long_error_strings() {
        let cfg = vec![host("prod-eu", "https://eu.example.com:8787")];
        let state = FleetState::from_config(&cfg);
        let err = "x".repeat(500);
        state.record("prod-eu", HostState::Down, Some(err), None);
        let snap = state.snapshot();
        let stored = snap[0].last_error.as_ref().expect("error stored");
        // 200 chars + " ..." suffix; bytes-wise either ≤ 204 or close
        // to it depending on whether ASCII.
        assert!(
            stored.len() <= 220,
            "got len={} err={}",
            stored.len(),
            stored
        );
        assert!(stored.ends_with(" ..."));
    }

    #[test]
    fn record_for_unknown_host_is_noop() {
        let cfg = vec![host("prod-eu", "https://eu.example.com:8787")];
        let state = FleetState::from_config(&cfg);
        // Stale id from a prior config — must NOT inflate the map.
        state.record("removed-host", HostState::Down, None, None);
        let snap = state.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].id, "prod-eu");
        assert_eq!(snap[0].state, HostState::Unknown);
    }

    #[test]
    fn snapshot_is_sorted_by_id() {
        let cfg = vec![
            host("zebra", "https://a"),
            host("alpha", "https://b"),
            host("mike", "https://c"),
        ];
        let state = FleetState::from_config(&cfg);
        let snap = state.snapshot();
        assert_eq!(snap[0].id, "alpha");
        assert_eq!(snap[1].id, "mike");
        assert_eq!(snap[2].id, "zebra");
    }
}
