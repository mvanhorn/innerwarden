//! `/api/fleet/hosts` handler — spec 038 Phase 1.
//!
//! The dashboard route returns a JSON array of `HostStatus`
//! snapshots when fleet is enabled, and 404 when fleet is disabled.
//! 404 (rather than empty array) is the unambiguous "this manager
//! does not run a fleet" signal so a future frontend can hide the
//! Fleet tab without ambiguity.

use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

pub(super) async fn api_fleet_hosts(State(state): State<super::DashboardState>) -> Response {
    match &state.fleet_state {
        Some(fleet) => Json(serde_json::json!({
            "hosts": fleet.snapshot(),
        }))
        .into_response(),
        None => fleet_disabled_response(),
    }
}

/// Phase 2: aggregate KPIs across the fleet plus per-host breakdown.
/// Returns 404 with the same shape as `/api/fleet/hosts` when fleet
/// mode is disabled so the frontend can probe either endpoint to
/// decide whether to render the Fleet tab.
pub(super) async fn api_fleet_overview(State(state): State<super::DashboardState>) -> Response {
    match &state.fleet_state {
        Some(fleet) => Json(fleet.aggregate_overview()).into_response(),
        None => fleet_disabled_response(),
    }
}

fn fleet_disabled_response() -> Response {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"error":"fleet mode not enabled"}"#))
        .unwrap()
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FleetHostConfig;
    use crate::fleet::{FleetHostOverview, FleetState, HostState};

    fn host(id: &str, url: &str) -> FleetHostConfig {
        FleetHostConfig {
            id: id.into(),
            url: url.into(),
            token_env: String::new(),
        }
    }

    #[test]
    fn fleet_state_snapshot_serialises_to_expected_json_shape() {
        let cfg = vec![
            host("prod-eu", "https://eu.example.com:8787"),
            host("prod-us", "https://us.example.com:8787"),
        ];
        let fleet = FleetState::from_config(&cfg);
        let snap = fleet.snapshot();
        // Anchor: the response body shape is `{ "hosts": [...] }`
        // with each entry carrying id / url / state / last_polled_at /
        // last_error. Phase 3's frontend consumes this contract; the
        // anchor keeps the field names stable.
        let body = serde_json::json!({ "hosts": snap });
        let pretty = serde_json::to_string(&body).expect("serialise");
        assert!(pretty.contains("\"hosts\""));
        assert!(pretty.contains("\"id\":\"prod-eu\""));
        assert!(pretty.contains("\"state\":\"unknown\""));
        assert!(pretty.contains("\"url\":\"https://eu.example.com:8787\""));
        assert!(
            pretty.contains("\"last_polled_at\":null"),
            "first-poll-pending host must serialise last_polled_at as null"
        );
    }

    /// Phase 2: aggregate_overview must sum across hosts whose
    /// overview is present and surface UP/DOWN/Degraded counts. The
    /// frontend's KPI tiles read from this contract; the anchor
    /// pins both the shape and the numeric arithmetic.
    #[test]
    fn aggregate_overview_sums_across_hosts() {
        let cfg = vec![
            host("a", "https://a.example.com"),
            host("b", "https://b.example.com"),
            host("c", "https://c.example.com"),
        ];
        let fleet = FleetState::from_config(&cfg);
        // a: up + healthy
        fleet.record(
            "a",
            HostState::Up,
            None,
            Some(FleetHostOverview {
                date: "2026-05-02".into(),
                events_count: 100,
                incidents_count: 10,
                decisions_count: 9,
                blocked_count: 7,
                observing_count: 1,
                attention_count: 2,
                handled_ips_today: 8,
                health_kind: Some("operating_normally".into()),
            }),
        );
        // b: degraded (spoke health is ai_not_responding)
        fleet.record(
            "b",
            HostState::Degraded,
            None,
            Some(FleetHostOverview {
                date: "2026-05-02".into(),
                events_count: 50,
                incidents_count: 5,
                decisions_count: 5,
                blocked_count: 2,
                observing_count: 0,
                attention_count: 3,
                handled_ips_today: 4,
                health_kind: Some("ai_not_responding".into()),
            }),
        );
        // c: down (no overview)
        fleet.record(
            "c",
            HostState::Down,
            Some("connection refused".into()),
            None,
        );

        let agg = fleet.aggregate_overview();
        assert_eq!(agg.fleet.host_count, 3);
        assert_eq!(agg.fleet.up_count, 1);
        assert_eq!(agg.fleet.degraded_count, 1);
        assert_eq!(agg.fleet.down_count, 1);
        assert_eq!(agg.fleet.events_count, 150);
        assert_eq!(agg.fleet.incidents_count, 15);
        assert_eq!(agg.fleet.blocked_count, 9);
        assert_eq!(agg.fleet.attention_count, 5);
        assert_eq!(agg.fleet.handled_ips_today, 12);
        assert!(
            agg.fleet.any_unhealthy,
            "host b's ai_not_responding kind must flip the fleet flag"
        );
        // Per-host preserved + sorted by id.
        assert_eq!(agg.by_host.len(), 3);
        assert_eq!(agg.by_host[0].id, "a");
        assert_eq!(agg.by_host[2].id, "c");
        // Down host carries the error string + null overview.
        assert!(agg.by_host[2].overview.is_none());
        assert_eq!(
            agg.by_host[2].last_error.as_deref(),
            Some("connection refused")
        );
    }

    #[test]
    fn aggregate_overview_serialises_to_frontend_contract() {
        let cfg = vec![host("a", "https://a")];
        let fleet = FleetState::from_config(&cfg);
        fleet.record(
            "a",
            HostState::Up,
            None,
            Some(FleetHostOverview {
                date: "2026-05-02".into(),
                events_count: 1,
                incidents_count: 2,
                decisions_count: 3,
                blocked_count: 4,
                observing_count: 5,
                attention_count: 6,
                handled_ips_today: 7,
                health_kind: Some("operating_normally".into()),
            }),
        );
        let agg = fleet.aggregate_overview();
        let body = serde_json::to_string(&agg).expect("serialise");
        // Phase 3's renderFleet reads `fleet` (summary) and
        // `by_host` (per-host array). The anchor pins both keys
        // plus the inner field names the frontend dereferences.
        assert!(body.contains("\"fleet\""));
        assert!(body.contains("\"by_host\""));
        assert!(body.contains("\"events_count\":1"));
        assert!(body.contains("\"any_unhealthy\":false"));
        assert!(body.contains("\"overview\""));
        assert!(body.contains("\"health_kind\":\"operating_normally\""));
    }
}
