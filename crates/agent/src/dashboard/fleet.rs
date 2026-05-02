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
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"error":"fleet mode not enabled"}"#))
            .unwrap()
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FleetHostConfig;
    use crate::fleet::FleetState;

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
}
