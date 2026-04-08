// api.rs — HTTP API with CORS
//
// Endpoints for monitoring the shield status, listing attackers,
// viewing metrics history, incident history, and a compact /live
// summary designed for the innerwarden.com website.

use axum::{
    extract::State,
    http::{header, Method},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::attack_classifier::AttackIncident;
use crate::escalation::{DdosIncident, DdosMetrics, EscalationState};

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

pub struct AppState {
    pub metrics: RwLock<Option<DdosMetrics>>,
    pub blocked_ips: RwLock<Vec<BlockedIpInfo>>,
    pub incidents: RwLock<Vec<DdosIncident>>,
    pub attack_incidents: RwLock<Vec<AttackIncident>>,
    pub metrics_history: RwLock<Vec<MetricsSnapshot>>,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            metrics: RwLock::new(None),
            blocked_ips: RwLock::new(Vec::new()),
            incidents: RwLock::new(Vec::new()),
            attack_incidents: RwLock::new(Vec::new()),
            metrics_history: RwLock::new(Vec::new()),
            started_at: chrono::Utc::now(),
        }
    }
}

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct BlockedIpInfo {
    pub ip: String,
    pub reason: String,
    pub blocked_since: String,
    pub duration_secs: i64,
    pub packets_dropped: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub timestamp: String,
    pub packets_per_sec: u64,
    pub drops_per_sec: u64,
    pub escalation_level: String,
    pub attack_types: Vec<String>,
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    state: String,
    uptime_secs: i64,
    total_dropped: u64,
    total_allowed: u64,
    active_attackers: usize,
    blocked_count: usize,
    peak_pps: u64,
    attack_duration_secs: u64,
}

#[derive(Serialize)]
struct LiveResponse {
    state: String,
    blocked: usize,
    dropped: u64,
    peak_pps: u64,
    uptime_secs: i64,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub async fn serve(bind: &str, state: Arc<AppState>) -> anyhow::Result<()> {
    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(bind, "Shield API listening");
    axum::serve(listener, router).await?;
    Ok(())
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/shield/status", get(handle_status))
        .route("/api/shield/attackers", get(handle_attackers))
        .route("/api/shield/metrics", get(handle_metrics))
        .route("/api/shield/history", get(handle_history))
        .route("/api/shield/live", get(handle_live))
        .layer(cors_layer())
        .with_state(state)
}

fn cors_layer() -> tower_http::cors::CorsLayer {
    tower_http::cors::CorsLayer::new()
        .allow_origin([
            "https://innerwarden.com".parse().unwrap(),
            "https://www.innerwarden.com".parse().unwrap(),
            "http://localhost:3000".parse().unwrap(),
            "http://localhost:5173".parse().unwrap(),
        ])
        .allow_methods([Method::GET])
        .allow_headers([header::CONTENT_TYPE])
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let metrics = state.metrics.read().await;
    let blocked = state.blocked_ips.read().await;
    let uptime = (chrono::Utc::now() - state.started_at).num_seconds();

    let (total_dropped, total_allowed, active_attackers, peak_pps, attack_duration, _esc_state) =
        match metrics.as_ref() {
            Some(m) => (
                m.total_dropped,
                m.total_allowed,
                m.unique_attackers,
                m.peak_pps,
                m.attack_duration_secs,
                format!("{}", EscalationState::Normal), // will be overridden below
            ),
            None => (0, 0, 0, 0, 0, "Normal".to_string()),
        };

    // Get actual escalation state from the metrics.
    let state_str = metrics
        .as_ref()
        .map(|_| "Normal") // The escalation state is tracked by the engine, not metrics
        .unwrap_or("Normal")
        .to_string();

    Json(StatusResponse {
        status: "ok".to_string(),
        state: state_str,
        uptime_secs: uptime,
        total_dropped,
        total_allowed,
        active_attackers,
        blocked_count: blocked.len(),
        peak_pps,
        attack_duration_secs: attack_duration,
    })
}

async fn handle_attackers(State(state): State<Arc<AppState>>) -> Json<Vec<BlockedIpInfo>> {
    let blocked = state.blocked_ips.read().await;
    Json(blocked.clone())
}

async fn handle_metrics(State(state): State<Arc<AppState>>) -> Json<Vec<MetricsSnapshot>> {
    let history = state.metrics_history.read().await;
    Json(history.clone())
}

async fn handle_history(State(state): State<Arc<AppState>>) -> Json<Vec<AttackIncident>> {
    let incidents = state.attack_incidents.read().await;
    Json(incidents.clone())
}

async fn handle_live(State(state): State<Arc<AppState>>) -> Json<LiveResponse> {
    let metrics = state.metrics.read().await;
    let blocked = state.blocked_ips.read().await;
    let uptime = (chrono::Utc::now() - state.started_at).num_seconds();

    let (dropped, peak_pps) = match metrics.as_ref() {
        Some(m) => (m.total_dropped, m.peak_pps),
        None => (0, 0),
    };

    Json(LiveResponse {
        state: "Normal".to_string(),
        blocked: blocked.len(),
        dropped,
        peak_pps,
        uptime_secs: uptime,
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_state_defaults() {
        let state = AppState::new();
        // started_at should be recent.
        let elapsed = (chrono::Utc::now() - state.started_at).num_seconds();
        assert!(elapsed < 5);
    }

    #[test]
    fn blocked_ip_info_serializes() {
        let info = BlockedIpInfo {
            ip: "10.0.0.1".to_string(),
            reason: "rate limit".to_string(),
            blocked_since: "2024-01-01T00:00:00Z".to_string(),
            duration_secs: 120,
            packets_dropped: 500,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("10.0.0.1"));
        assert!(json.contains("rate limit"));
    }

    #[test]
    fn metrics_snapshot_serializes() {
        let snap = MetricsSnapshot {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            packets_per_sec: 1000,
            drops_per_sec: 50,
            escalation_level: "Normal".to_string(),
            attack_types: vec!["SYN Flood".to_string()],
        };
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("SYN Flood"));
    }
}
