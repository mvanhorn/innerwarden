pub(crate) mod state;
pub(crate) mod types;

// Re-export types used by other modules in the crate.
pub use auth::generate_password_hash_interactive;
pub use state::{AgentGuardAlert, DashboardActionConfig, DeepSecuritySnapshot};
pub use types::AdvisoryEntry;

#[allow(unused_imports)]
use state::*;
#[allow(unused_imports)]
use types::*;

mod actions;
mod agent_api;
mod auth;
mod brain;
mod compliance;
mod data_api;
mod helpers;
mod intelligence;
mod investigation;
mod live_feed;
mod push;
mod sensors;
mod sse;

#[allow(unused_imports)]
use actions::*;
#[allow(unused_imports)]
use agent_api::*;
#[allow(unused_imports)]
use auth::*;
#[allow(unused_imports)]
use brain::*;
#[allow(unused_imports)]
use compliance::*;
#[allow(unused_imports)]
use data_api::*;
#[allow(unused_imports)]
use helpers::*;
#[allow(unused_imports)]
use intelligence::*;
#[allow(unused_imports)]
use investigation::*;
#[allow(unused_imports)]
use live_feed::*;
#[allow(unused_imports)]
use push::*;
#[allow(unused_imports)]
use sensors::*;
#[allow(unused_imports)]
use sse::*;

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, RwLock};

use anyhow::{Context, Result};
use argon2::password_hash::{PasswordHashString, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chrono::{DateTime, Datelike, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;
use tracing::{info, warn};

#[cfg(test)]
use crate::correlation::build_clusters;
use crate::decisions::DecisionEntry;
use crate::mitre;
use crate::report::{self as report_mod, TrialReport};
use innerwarden_core::audit::{append_admin_action, AdminActionEntry};
use innerwarden_core::entities::{EntityRef, EntityType};
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;

// ---------------------------------------------------------------------------
// Security headers middleware
// ---------------------------------------------------------------------------

async fn security_headers(req: axum::extract::Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert("x-xss-protection", "0".parse().unwrap());
    headers.insert(
        "referrer-policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    resp
}

// ---------------------------------------------------------------------------
// Shared state / auth
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DashboardAuth {
    username: String,
    password_hash: PasswordHashString,
}

impl DashboardAuth {
    /// Load credentials from environment variables.
    /// Returns `None` if neither env var is set (open access mode).
    /// Returns `Err` if vars are partially set or malformed.
    pub fn try_from_env() -> Result<Option<Self>> {
        let user = std::env::var("INNERWARDEN_DASHBOARD_USER").ok();
        let hash = std::env::var("INNERWARDEN_DASHBOARD_PASSWORD_HASH").ok();

        match (user, hash) {
            (None, None) => Ok(None), // no auth configured - open access
            (Some(username), Some(password_hash_raw)) => {
                if username.trim().is_empty() {
                    anyhow::bail!("INNERWARDEN_DASHBOARD_USER cannot be empty");
                }
                let password_hash =
                    PasswordHashString::new(&password_hash_raw).map_err(|_| {
                        anyhow::anyhow!(
                            "INNERWARDEN_DASHBOARD_PASSWORD_HASH is not a valid PHC hash string"
                        )
                    })?;
                Ok(Some(Self {
                    username,
                    password_hash,
                }))
            }
            (Some(_), None) => anyhow::bail!(
                "INNERWARDEN_DASHBOARD_USER is set but INNERWARDEN_DASHBOARD_PASSWORD_HASH is missing.\n\
                 Generate one with: innerwarden-agent --dashboard-generate-password-hash"
            ),
            (None, Some(_)) => anyhow::bail!(
                "INNERWARDEN_DASHBOARD_PASSWORD_HASH is set but INNERWARDEN_DASHBOARD_USER is missing."
            ),
        }
    }

    fn verify(&self, user: &str, password: &str) -> bool {
        // Use constant-time comparison for the username to prevent
        // timing side-channels that could enumerate valid usernames.
        if !constant_time_eq(user, &self.username) {
            return false;
        }
        let parsed = PasswordHash::new(self.password_hash.as_str());
        match parsed {
            Ok(hash) => Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok(),
            Err(_) => false,
        }
    }
}

/// Constant-time string equality to prevent timing side-channel attacks.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn serve(
    data_dir: PathBuf,
    bind: String,
    auth: Option<DashboardAuth>,
    action_cfg: DashboardActionConfig,
    web_push_vapid_public_key: String,
    trusted_proxy_strs: Vec<String>,
    session_timeout_minutes: u64,
    max_sessions: usize,
    advisory_cache: Arc<RwLock<VecDeque<AdvisoryEntry>>>,
    rule_engine: Arc<innerwarden_agent_guard::rules::RuleEngine>,
    agent_alert_tx: tokio::sync::mpsc::Sender<AgentGuardAlert>,
    deep_security: Arc<RwLock<DeepSecuritySnapshot>>,
    knowledge_graph: Arc<std::sync::RwLock<crate::knowledge_graph::KnowledgeGraph>>,
    ai_provider: Option<Arc<dyn crate::ai::AiProvider>>,
    briefing_state: Arc<tokio::sync::Mutex<Option<crate::briefing::Briefing>>>,
    briefing_hour: u8,
    briefing_minute: u8,
    sqlite_store: Option<Arc<innerwarden_store::Store>>,
) -> Result<()> {
    if auth.is_none() {
        warn!(
            "dashboard is running WITHOUT authentication - \
             set INNERWARDEN_DASHBOARD_USER and INNERWARDEN_DASHBOARD_PASSWORD_HASH \
             in agent.env to require a login"
        );
    }

    // HTTPS warning: credentials sent in plaintext over non-localhost HTTP
    if auth.is_some() {
        let is_localhost = bind.starts_with("127.0.0.1")
            || bind.starts_with("[::1]")
            || bind.starts_with("localhost");
        if !is_localhost {
            warn!(
                bind = %bind,
                "dashboard is accessible over HTTP on a non-localhost address. \
                 Credentials will be sent in plaintext. Consider using a reverse \
                 proxy with TLS or binding to 127.0.0.1."
            );
        }
    }

    // D6: broadcast channel - capacity 64 is plenty; lagged receivers are dropped.
    let (event_tx, _) = broadcast::channel::<SsePayload>(64);

    let insecure_http = auth.is_some() && {
        let is_localhost = bind.starts_with("127.0.0.1")
            || bind.starts_with("[::1]")
            || bind.starts_with("localhost");
        !is_localhost
    };

    // Parse trusted proxy IPs at startup - only these connecting IPs may
    // set X-Forwarded-For / X-Real-IP headers.
    let trusted_proxies: Vec<IpAddr> = trusted_proxy_strs
        .iter()
        .filter_map(|s| {
            s.parse::<IpAddr>()
                .map_err(|e| {
                    warn!(proxy = %s, error = %e, "ignoring invalid trusted_proxy IP");
                    e
                })
                .ok()
        })
        .collect();
    if !trusted_proxies.is_empty() {
        info!(
            count = trusted_proxies.len(),
            "loaded trusted proxy IPs for X-Forwarded-For"
        );
    }

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let sessions: Arc<RwLock<HashMap<String, Session>>> = Arc::new(RwLock::new(HashMap::new()));
    let state = DashboardState {
        data_dir: data_dir.clone(),
        action_cfg: Arc::new(action_cfg),
        event_tx: event_tx.clone(),
        web_push_vapid_public_key,
        insecure_http,
        last_activity: Arc::new(std::sync::atomic::AtomicU64::new(now_secs)),
        sensor_cache: Arc::new(tokio::sync::Mutex::new((0, serde_json::json!({})))),
        trusted_proxies: Arc::new(trusted_proxies),
        sessions: sessions.clone(),
        session_timeout_minutes,
        max_sessions,
        advisory_cache: advisory_cache.clone(),
        agent_registry: Arc::new(tokio::sync::Mutex::new(
            innerwarden_agent_guard::registry::Registry::new(),
        )),
        rule_engine,
        agent_alert_tx,
        deep_security,
        knowledge_graph,
        ai_provider,
        latest_briefing: briefing_state,
        briefing_hour,
        briefing_minute,
        sqlite_store,
    };
    let auth_layer = middleware::from_fn_with_state(
        (
            auth.clone(),
            state.trusted_proxies.clone(),
            state.sessions.clone(),
            session_timeout_minutes,
        ),
        require_auth,
    );
    let activity_state = state.last_activity.clone();
    let activity_layer = middleware::from_fn(move |req: Request<Body>, next: Next| {
        let ts = activity_state.clone();
        async move {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            ts.store(now, std::sync::atomic::Ordering::Relaxed);
            next.run(req).await
        }
    });
    // Global rate limiter - rejects requests from IPs exceeding 120/min with 429.
    // Prevents memory exhaustion from bot traffic when dashboard is internet-facing.
    let rate_limit_proxies = state.trusted_proxies.clone();
    let rate_limit_layer = middleware::from_fn(move |req: Request<Body>, next: Next| {
        let proxies = rate_limit_proxies.clone();
        async move {
            let ip = extract_client_ip(&req, &proxies);
            if global_rate_check(&ip) {
                return axum::http::Response::builder()
                    .status(429)
                    .header("retry-after", "60")
                    .body(Body::from("Too Many Requests"))
                    .unwrap()
                    .into_response();
            }
            next.run(req).await
        }
    });

    // Agent API routes - no auth required (localhost service-to-service)
    // These are used by AI agents (OpenClaw, n8n, etc.) to query security state.
    let agent_api = Router::new()
        .route(
            "/api/agent/security-context",
            get(api_agent_security_context),
        )
        .route("/api/agent/check-ip", get(api_agent_check_ip))
        .route("/api/agent/check-command", post(api_agent_check_command))
        .route(
            "/api/advisor/check-command",
            post(api_advisor_check_command),
        )
        .route("/metrics", get(api_prometheus_metrics))
        .route("/api/agent-guard/connect", post(api_agent_guard_connect))
        .route(
            "/api/agent-guard/disconnect",
            post(api_agent_guard_disconnect),
        )
        .route("/api/agent-guard/agents", get(api_agent_guard_list))
        .with_state(state.clone());

    // Auth login route - public (no auth required; this IS the auth endpoint)
    let auth_login = Router::new()
        .route("/api/auth/login", post(api_auth_login))
        .with_state(state.clone());

    // Dashboard routes - auth required
    let dashboard = Router::new()
        .route("/", get(index))
        .route("/app.css", get(serve_css))
        .route("/js/api.js", get(serve_js_api))
        .route("/js/helpers.js", get(serve_js_helpers))
        .route("/js/state.js", get(serve_js_state))
        .route("/js/nav.js", get(serve_js_nav))
        .route("/js/home.js", get(serve_js_home))
        .route("/js/threats.js", get(serve_js_threats))
        .route("/js/journey.js", get(serve_js_journey))
        .route("/js/sensors.js", get(serve_js_sensors))
        .route("/js/reports.js", get(serve_js_reports))
        .route("/js/status.js", get(serve_js_status))
        .route("/js/compliance.js", get(serve_js_compliance))
        .route("/js/honeypot.js", get(serve_js_honeypot))
        .route("/js/intel.js", get(serve_js_intel))
        .route("/js/graph.js", get(serve_js_graph))
        .route("/js/monthly.js", get(serve_js_monthly))
        .route("/js/responses.js", get(serve_js_responses))
        .route("/js/actions.js", get(serve_js_actions))
        .route("/js/sse.js", get(serve_js_sse))
        .route("/api/overview", get(api_overview))
        .route("/api/incidents", get(api_incidents))
        .route("/api/decisions", get(api_decisions))
        .route("/api/entities", get(api_entities))
        .route("/api/pivots", get(api_pivots))
        .route("/api/clusters", get(api_clusters))
        .route("/api/journey", get(api_journey))
        .route("/api/export", get(api_export))
        .route("/api/report", get(api_report))
        .route("/api/report/dates", get(api_report_dates))
        .route("/api/quickwins", get(api_quickwins))
        // AI Intelligence Briefing
        .route("/api/briefing", get(api_briefing))
        .route("/api/briefing/generate", post(api_briefing_generate))
        // AI Explain — plain-language threat explanation for non-technical operators
        .route("/api/ai-explain", get(api_ai_explain))
        // Sensors activity
        .route("/api/sensors", get(api_sensors))
        // E6 - system status
        .route("/api/status", get(api_status))
        .route("/api/collectors", get(api_collectors))
        // D3 - operator-initiated actions (POST, require auth, respect dry_run)
        .route("/api/action/block-ip", post(api_action_block_ip))
        .route("/api/action/suspend-user", post(api_action_suspend_user))
        .route("/api/action/config", get(api_action_config))
        // Honeypot tab
        .route("/api/honeypot/sessions", get(api_honeypot_sessions))
        .route("/api/action/honeypot", post(api_action_honeypot))
        // Compliance tab
        .route("/api/admin-actions", get(api_admin_actions))
        .route("/api/advisory-cache", get(api_advisory_cache))
        .route("/api/compliance", get(api_compliance))
        // Attacker Intelligence & Monthly Reports
        .route("/api/attacker-profiles", get(api_attacker_profiles))
        .route(
            "/api/attacker-profiles/:ip",
            get(api_attacker_profile_detail),
        )
        .route("/api/threat-report", get(api_threat_report))
        .route("/api/threat-report/months", get(api_threat_report_months))
        .route("/api/campaigns", get(api_campaigns))
        .route("/api/correlation-chains", get(api_correlation_chains))
        .route("/api/baseline-status", get(api_baseline_status))
        .route("/api/graph/stats", get(api_graph_stats))
        .route("/api/graph/view", get(api_graph_view))
        .route("/api/graph/neighborhood", get(api_graph_neighborhood))
        .route("/api/graph/path", get(api_graph_path))
        .route("/api/graph/process-tree", get(api_graph_process_tree))
        .route("/api/graph/timeline", get(api_graph_timeline))
        .route("/api/graph/threats", get(api_graph_threats))
        .route("/api/playbook-log", get(api_playbook_log))
        .route("/api/responses", get(api_responses))
        .route("/api/mitre/navigator", get(api_mitre_navigator))
        .route("/api/mitre/coverage", get(api_mitre_coverage))
        // Defender Brain (AlphaZero)
        .route("/api/defender-brain/recent", get(api_brain_recent))
        .route("/api/defender-brain/stats", get(api_brain_stats))
        .route("/api/defender-brain/feedback", post(api_brain_feedback))
        // Deep Security (integrated modules)
        .route("/api/deep-security", get(api_deep_security))
        // D6 - SSE live event stream
        .route("/api/events/stream", get(api_events_stream))
        // Web Push
        .route("/sw.js", get(service_worker_js))
        .route("/favicon.ico", get(|| async { StatusCode::NO_CONTENT }))
        .route("/api/push/vapid-key", get(api_push_vapid_key))
        .route(
            "/api/push/subscribe",
            post(api_push_subscribe).delete(api_push_unsubscribe),
        )
        // Session management endpoints (auth-protected)
        .route("/api/auth/logout", post(api_auth_logout))
        .route("/api/auth/sessions", get(api_auth_sessions))
        .layer(auth_layer)
        .with_state(state.clone());

    // Public live-feed routes - CORS-enabled, no auth, read-only
    let live_api = Router::new()
        .route("/api/live-feed", get(api_live_feed))
        .route("/api/live-feed/stream", get(api_live_feed_stream))
        .route("/api/live-feed/geoip", get(api_live_feed_geoip))
        .route("/api/live-feed/honeypot", get(api_live_feed_honeypot))
        .route("/api/live-feed/mitre", get(api_live_feed_mitre))
        .layer(middleware::from_fn(cors_middleware))
        .with_state(state);

    let app = agent_api
        .merge(auth_login)
        .merge(live_api)
        .merge(dashboard)
        .layer(middleware::from_fn(security_headers))
        .layer(activity_layer)
        .layer(rate_limit_layer);

    // D6: spawn file watcher and heartbeat tasks
    tokio::spawn(watch_for_new_entries(data_dir, event_tx.clone()));
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let _ = event_tx.send(SsePayload {
                kind: "heartbeat".to_string(),
                data: None,
            });
        }
    });

    // Session + advisory cleanup: remove expired entries every 60 seconds
    let cleanup_sessions = sessions;
    let cleanup_timeout = session_timeout_minutes;
    let cleanup_advisory_cache = advisory_cache.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let mut map = cleanup_sessions.write().unwrap_or_else(|e| e.into_inner());
            map.retain(|_, session| !session.is_expired(cleanup_timeout));
            // Evict advisories older than 1 hour
            if let Ok(mut cache) = cleanup_advisory_cache.write() {
                let cutoff = Utc::now() - chrono::Duration::hours(1);
                cache.retain(|e| e.ts > cutoff);
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("failed to bind dashboard listener on {bind}"))?;

    info!(
        bind = %bind,
        "dashboard read-only mode started"
    );
    axum::serve(listener, app)
        .await
        .context("dashboard server failed")
}

// ---------------------------------------------------------------------------

async fn index() -> impl IntoResponse {
    (
        [
            (header::CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
            (header::PRAGMA, "no-cache"),
        ],
        Html(INDEX_HTML),
    )
}

async fn serve_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS)
}

macro_rules! js_handler {
    ($name:ident, $content:expr) => {
        async fn $name() -> impl IntoResponse {
            (
                [(
                    header::CONTENT_TYPE,
                    "application/javascript; charset=utf-8",
                )],
                $content,
            )
        }
    };
}

js_handler!(serve_js_api, JS_API);
js_handler!(serve_js_helpers, JS_HELPERS);
js_handler!(serve_js_state, JS_STATE);
js_handler!(serve_js_nav, JS_NAV);
js_handler!(serve_js_home, JS_HOME);
js_handler!(serve_js_threats, JS_THREATS);
js_handler!(serve_js_journey, JS_JOURNEY);
js_handler!(serve_js_sensors, JS_SENSORS);
js_handler!(serve_js_reports, JS_REPORTS);
js_handler!(serve_js_status, JS_STATUS);
js_handler!(serve_js_compliance, JS_COMPLIANCE);
js_handler!(serve_js_honeypot, JS_HONEYPOT);
js_handler!(serve_js_intel, JS_INTEL);
js_handler!(serve_js_graph, JS_GRAPH);
js_handler!(serve_js_monthly, JS_MONTHLY);
js_handler!(serve_js_responses, JS_RESPONSES);
js_handler!(serve_js_actions, JS_ACTIONS);
js_handler!(serve_js_sse, JS_SSE);

// ---------------------------------------------------------------------------
// D10 - Report API
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

const INDEX_HTML: &str = include_str!("frontend/html/index.html");
const APP_CSS: &str = include_str!("frontend/css/app.css");
const JS_API: &str = include_str!("frontend/js/api.js");
const JS_HELPERS: &str = include_str!("frontend/js/helpers.js");
const JS_STATE: &str = include_str!("frontend/js/state.js");
const JS_NAV: &str = include_str!("frontend/js/nav.js");
const JS_HOME: &str = include_str!("frontend/js/home.js");
const JS_THREATS: &str = include_str!("frontend/js/threats.js");
const JS_JOURNEY: &str = include_str!("frontend/js/journey.js");
const JS_SENSORS: &str = include_str!("frontend/js/sensors.js");
const JS_REPORTS: &str = include_str!("frontend/js/reports.js");
const JS_STATUS: &str = include_str!("frontend/js/status.js");
const JS_COMPLIANCE: &str = include_str!("frontend/js/compliance.js");
const JS_HONEYPOT: &str = include_str!("frontend/js/honeypot.js");
const JS_INTEL: &str = include_str!("frontend/js/intel.js");
const JS_GRAPH: &str = include_str!("frontend/js/graph.js");
const JS_MONTHLY: &str = include_str!("frontend/js/monthly.js");
const JS_RESPONSES: &str = include_str!("frontend/js/responses.js");
const JS_ACTIONS: &str = include_str!("frontend/js/actions.js");
const JS_SSE: &str = include_str!("frontend/js/sse.js");

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::TelemetrySnapshot;
    use argon2::password_hash::SaltString;
    use argon2::PasswordHasher;
    use chrono::Utc;
    use innerwarden_core::{
        entities::EntityRef,
        event::{Event, Severity},
        incident::Incident,
    };
    use rand_core::{OsRng, RngCore};
    use tempfile::TempDir;

    // ── Existing tests (unchanged) ──────────────────────────────────────

    #[test]
    fn normalize_limit_is_bounded() {
        assert_eq!(normalize_limit(None), 50);
        assert_eq!(normalize_limit(Some(0)), 1);
        assert_eq!(normalize_limit(Some(10)), 10);
        assert_eq!(normalize_limit(Some(9999)), 500);
    }

    #[test]
    fn resolve_date_falls_back_to_today_on_invalid_values() {
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        assert_eq!(resolve_date(None), today);
        assert_eq!(resolve_date(Some("not-a-date")), today);
        assert_eq!(resolve_date(Some("2026-99-01")), today);
        assert_eq!(resolve_date(Some("2026-03-13")), "2026-03-13");
    }

    #[test]
    fn overview_counts_jsonl_artifacts() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        let event_path = dated_path(dir.path(), "events", date);
        let incident_path = dated_path(dir.path(), "incidents", date);
        let decision_path = dated_path(dir.path(), "decisions", date);
        let telemetry_path = dated_path(dir.path(), "telemetry", date);

        let event = Event {
            ts: Utc::now(),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Info,
            summary: "x".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        std::fs::write(
            &event_path,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&event).unwrap(),
                "{malformed"
            ),
        )
        .unwrap();

        let incident = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:test".to_string(),
            severity: Severity::High,
            title: "t".to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec!["ssh".to_string()],
            entities: vec![EntityRef::ip("1.2.3.4")],
        };
        std::fs::write(
            &incident_path,
            format!("{}\n", serde_json::to_string(&incident).unwrap()),
        )
        .unwrap();

        let decision = DecisionEntry {
            ts: Utc::now(),
            incident_id: "ssh_bruteforce:1.2.3.4:test".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.9,
            auto_executed: true,
            dry_run: true,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
        };
        std::fs::write(
            &decision_path,
            format!("{}\n", serde_json::to_string(&decision).unwrap()),
        )
        .unwrap();

        let snapshot = TelemetrySnapshot {
            ts: Utc::now(),
            tick: "incident_tick".to_string(),
            events_by_collector: BTreeMap::new(),
            incidents_by_detector: BTreeMap::new(),
            gate_pass_count: 1,
            ai_sent_count: 1,
            ai_decision_count: 1,
            avg_decision_latency_ms: 120.0,
            errors_by_component: BTreeMap::new(),
            decisions_by_action: BTreeMap::new(),
            dry_run_execution_count: 1,
            real_execution_count: 0,
        };
        std::fs::write(
            &telemetry_path,
            format!("{}\n", serde_json::to_string(&snapshot).unwrap()),
        )
        .unwrap();

        let ov = compute_overview(dir.path(), date);
        // events_count uses fast line counting (not JSON parsing), so malformed lines count too
        assert_eq!(ov.events_count, 2);
        assert_eq!(ov.incidents_count, 1);
        assert_eq!(ov.decisions_count, 1);
        assert_eq!(ov.top_detectors.len(), 1);
        assert_eq!(ov.top_detectors[0].detector, "ssh_bruteforce");
        assert!(ov.latest_telemetry.is_some());
    }

    #[test]
    fn parse_basic_auth_header_works() {
        let encoded = BASE64_STANDARD.encode("admin:supersecret");
        let header = format!("Basic {encoded}");
        let parsed = parse_basic_auth(&header).unwrap();
        assert_eq!(parsed.0, "admin");
        assert_eq!(parsed.1, "supersecret");
    }

    #[test]
    fn dashboard_auth_verifies_valid_credentials() {
        // Generate the test password at runtime from OS entropy so the test
        // has no hard-coded cryptographic literal. A 24-byte random password
        // is mapped into `a..z` for readability in test output, and the
        // "wrong" variant is derived by appending a non-alphabetic byte so it
        // can never accidentally collide with `correct_pw`.
        let mut pw_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut pw_bytes);
        let correct_pw: String = pw_bytes
            .iter()
            .map(|b| char::from(b'a' + (b % 26)))
            .collect();
        let wrong_pw: String = format!("{correct_pw}!");

        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(correct_pw.as_bytes(), &salt)
            .unwrap()
            .to_string();
        let auth = DashboardAuth {
            username: "admin".to_string(),
            password_hash: PasswordHashString::new(&hash).unwrap(),
        };

        assert!(auth.verify("admin", &correct_pw));
        assert!(!auth.verify("admin", &wrong_pw));
        assert!(!auth.verify("other", &correct_pw));
    }

    // ── New D2 tests ────────────────────────────────────────────────────

    #[test]
    fn attackers_groups_by_ip() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        // Two incidents from the same IP - different detectors.
        let inc1 = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.10:abc".to_string(),
            severity: Severity::Critical,
            title: "t1".to_string(),
            summary: "s1".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10")],
        };
        let inc2 = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.10:def".to_string(),
            severity: Severity::High,
            title: "t2".to_string(),
            summary: "s2".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10")],
        };
        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&inc1).unwrap(),
                serde_json::to_string(&inc2).unwrap()
            ),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let attackers = build_attackers(dir.path(), date, &filters, 50);
        assert_eq!(attackers.len(), 1, "should aggregate to a single IP");
        assert_eq!(attackers[0].ip, "203.0.113.10");
        assert_eq!(attackers[0].incident_count, 2);
        // max_severity should be the highest observed (critical > high).
        assert_eq!(attackers[0].max_severity, "critical");
        assert_eq!(attackers[0].detectors, vec!["ssh_bruteforce"]);
    }

    #[test]
    fn journey_assembles_all_kinds() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";
        let ip = "203.0.113.10";

        let event = Event {
            ts: Utc::now(),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Medium,
            summary: "SSH login failed".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        };
        let incident = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: format!("ssh_bruteforce:{ip}:x"),
            severity: Severity::Critical,
            title: "Brute Force".to_string(),
            summary: "9 failures".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        };
        let decision = DecisionEntry {
            ts: Utc::now(),
            incident_id: format!("ssh_bruteforce:{ip}:x"),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some(ip.to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.95,
            auto_executed: true,
            dry_run: true,
            reason: "brute force detected".to_string(),
            estimated_threat: "critical".to_string(),
            execution_result: "ok (dry_run)".to_string(),
            prev_hash: None,
        };

        std::fs::write(
            dated_path(dir.path(), "events", date),
            format!("{}\n", serde_json::to_string(&event).unwrap()),
        )
        .unwrap();
        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!("{}\n", serde_json::to_string(&incident).unwrap()),
        )
        .unwrap();
        std::fs::write(
            dated_path(dir.path(), "decisions", date),
            format!("{}\n", serde_json::to_string(&decision).unwrap()),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let journey = build_journey(dir.path(), date, PivotKind::Ip, ip, &filters, None);
        assert_eq!(
            journey.entries.len(),
            3,
            "should have event + incident + decision"
        );
        let kinds: Vec<&str> = journey.entries.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"event"), "missing event entry");
        assert!(kinds.contains(&"incident"), "missing incident entry");
        assert!(kinds.contains(&"decision"), "missing decision entry");
        assert_eq!(journey.subject_type, "ip");
        assert_eq!(journey.subject, ip);
        assert!(journey.first_seen.is_some());
        assert!(journey.last_seen.is_some());
        assert_eq!(journey.summary.events_count, 1);
        assert_eq!(journey.summary.incidents_count, 1);
        assert_eq!(journey.summary.decisions_count, 1);
        assert!(!journey.summary.hints.is_empty());
        assert!(journey
            .summary
            .pivot_shortcuts
            .iter()
            .any(|token| token == "ip:203.0.113.10"));
    }

    #[test]
    fn journey_window_filter_limits_entries() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";
        let ip = "203.0.113.10";
        let now = Utc::now();

        let event = Event {
            ts: now - chrono::Duration::seconds(120),
            host: "h".to_string(),
            source: "auth.log".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Severity::Medium,
            summary: "SSH login failed".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        };
        let incident = Incident {
            ts: now - chrono::Duration::seconds(45),
            host: "h".to_string(),
            incident_id: format!("ssh_bruteforce:{ip}:x"),
            severity: Severity::Critical,
            title: "Brute Force".to_string(),
            summary: "9 failures".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip(ip)],
        };
        let decision = DecisionEntry {
            ts: now,
            incident_id: format!("ssh_bruteforce:{ip}:x"),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some(ip.to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.95,
            auto_executed: true,
            dry_run: false,
            reason: "brute force detected".to_string(),
            estimated_threat: "critical".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
        };

        std::fs::write(
            dated_path(dir.path(), "events", date),
            format!("{}\n", serde_json::to_string(&event).unwrap()),
        )
        .unwrap();
        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!("{}\n", serde_json::to_string(&incident).unwrap()),
        )
        .unwrap();
        std::fs::write(
            dated_path(dir.path(), "decisions", date),
            format!("{}\n", serde_json::to_string(&decision).unwrap()),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let journey = build_journey(dir.path(), date, PivotKind::Ip, ip, &filters, Some(60));
        assert_eq!(journey.entries.len(), 2);
        assert!(!journey.entries.iter().any(|e| e.kind == "event"));
        assert_eq!(journey.summary.events_count, 0);
        assert_eq!(journey.summary.incidents_count, 1);
        assert_eq!(journey.summary.decisions_count, 1);
    }

    #[test]
    fn pivots_group_by_user() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        let inc1 = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.10:abc".to_string(),
            severity: Severity::High,
            title: "t1".to_string(),
            summary: "s1".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10"), EntityRef::user("root")],
        };
        let inc2 = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "sudo_abuse:deploy:def".to_string(),
            severity: Severity::Critical,
            title: "t2".to_string(),
            summary: "s2".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("198.51.100.9"), EntityRef::user("deploy")],
        };
        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&inc1).unwrap(),
                serde_json::to_string(&inc2).unwrap()
            ),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let pivots = build_pivots(dir.path(), date, PivotKind::User, &filters, 50);
        assert_eq!(pivots.len(), 2);
        assert_eq!(pivots[0].group_by, "user");
        assert!(pivots.iter().any(|p| p.value == "root"));
        assert!(pivots.iter().any(|p| p.value == "deploy"));
    }

    #[test]
    fn journey_user_pivot_includes_related_decision() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";

        let incident = Incident {
            ts: Utc::now(),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.10:x".to_string(),
            severity: Severity::Critical,
            title: "Brute Force".to_string(),
            summary: "9 failures".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10"), EntityRef::user("root")],
        };
        let decision = DecisionEntry {
            ts: Utc::now(),
            incident_id: "ssh_bruteforce:203.0.113.10:x".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("203.0.113.10".to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 0.95,
            auto_executed: true,
            dry_run: false,
            reason: "brute force detected".to_string(),
            estimated_threat: "critical".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
        };

        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!("{}\n", serde_json::to_string(&incident).unwrap()),
        )
        .unwrap();
        std::fs::write(
            dated_path(dir.path(), "decisions", date),
            format!("{}\n", serde_json::to_string(&decision).unwrap()),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let journey = build_journey(dir.path(), date, PivotKind::User, "root", &filters, None);
        assert_eq!(journey.subject_type, "user");
        assert_eq!(journey.subject, "root");
        assert!(journey.entries.iter().any(|e| e.kind == "incident"));
        assert!(journey.entries.iter().any(|e| e.kind == "decision"));
        assert_eq!(journey.outcome, "blocked");
    }

    #[test]
    fn clusters_group_related_incidents() {
        let dir = TempDir::new().unwrap();
        let date = "2026-03-13";
        let ts = Utc::now();

        let inc1 = Incident {
            ts,
            host: "h".to_string(),
            incident_id: "port_scan:203.0.113.10:a".to_string(),
            severity: Severity::High,
            title: "scan".to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10")],
        };
        let inc2 = Incident {
            ts: ts + chrono::Duration::seconds(40),
            host: "h".to_string(),
            incident_id: "ssh_bruteforce:203.0.113.10:b".to_string(),
            severity: Severity::Critical,
            title: "bf".to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!({}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::ip("203.0.113.10"), EntityRef::user("root")],
        };

        std::fs::write(
            dated_path(dir.path(), "incidents", date),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&inc1).unwrap(),
                serde_json::to_string(&inc2).unwrap()
            ),
        )
        .unwrap();

        let filters = InvestigationFilters::from_query(None, None);
        let clusters = build_cluster_items(dir.path(), date, &filters, 20, 300);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].incident_count, 2);
        assert_eq!(clusters[0].pivot_type, "ip");
        assert_eq!(clusters[0].pivot_value, "203.0.113.10");
    }

    #[test]
    fn markdown_export_contains_sections() {
        let snapshot = InvestigationExport {
            generated_at: Utc::now(),
            date: "2026-03-13".to_string(),
            filters: serde_json::json!({"severity_min":"high"}),
            group_by: "ip".to_string(),
            subject_type: Some("ip".to_string()),
            subject: Some("203.0.113.10".to_string()),
            overview: OverviewResponse {
                date: "2026-03-13".to_string(),
                events_count: 10,
                incidents_count: 2,
                decisions_count: 1,
                ai_confirmed: 1,
                ai_responded: 0,
                ai_ignored: 0,
                unresolved_count: 1,
                safely_resolved: 0,
                severity_breakdown: std::collections::HashMap::new(),
                allowlisted_count: 0,
                top_detectors: vec![],
                latest_telemetry: None,
            },
            pivots: vec![PivotItem {
                group_by: "ip".to_string(),
                value: "203.0.113.10".to_string(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                max_severity: "critical".to_string(),
                incident_count: 2,
                event_count: 8,
                outcome: "active".to_string(),
                detectors: vec!["ssh_bruteforce".to_string()],
            }],
            clusters: vec![ClusterItem {
                cluster_id: "cluster-001".to_string(),
                pivot: "ip:203.0.113.10".to_string(),
                pivot_type: "ip".to_string(),
                pivot_value: "203.0.113.10".to_string(),
                start_ts: Utc::now(),
                end_ts: Utc::now(),
                incident_count: 2,
                detector_kinds: vec!["ssh_bruteforce".to_string()],
                incident_ids: vec!["x".to_string(), "y".to_string()],
            }],
            journey: Some(JourneyResponse {
                subject_type: "ip".to_string(),
                subject: "203.0.113.10".to_string(),
                date: "2026-03-13".to_string(),
                first_seen: Some(Utc::now()),
                last_seen: Some(Utc::now()),
                outcome: "active".to_string(),
                summary: JourneySummary {
                    total_entries: 1,
                    events_count: 1,
                    incidents_count: 0,
                    decisions_count: 0,
                    honeypot_count: 0,
                    first_event: Some(Utc::now()),
                    first_incident: None,
                    first_decision: None,
                    first_honeypot: None,
                    pivot_shortcuts: vec!["ip:203.0.113.10".to_string()],
                    hints: vec!["Signals observed".to_string()],
                },
                verdict: JourneyVerdict {
                    entry_vector: "ssh_bruteforce".to_string(),
                    access_status: "attempted".to_string(),
                    privilege_status: "no_evidence".to_string(),
                    containment_status: "unknown".to_string(),
                    honeypot_status: "not_engaged".to_string(),
                    confidence: "medium".to_string(),
                },
                chapters: vec![],
                entries: vec![],
            }),
        };

        let markdown = render_markdown_snapshot(&snapshot);
        assert!(markdown.contains("# InnerWarden Investigation Snapshot"));
        assert!(markdown.contains("## Correlation Clusters"));
        assert!(markdown.contains("cluster-001"));
        assert!(markdown.contains("## Journey"));
        assert!(markdown.contains("Subject: `ip:203.0.113.10`"));
        assert!(markdown.contains("### Guided Summary"));
        assert!(markdown.contains("### Investigation Hints"));
    }

    #[test]
    fn outcome_blocked_when_block_ip_ok() {
        let blocked = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: false,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
        };
        assert_eq!(determine_outcome(&[blocked], "1.2.3.4", true), "blocked");

        let dry_run_block = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: true,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok (dry_run)".to_string(),
            prev_hash: None,
        };
        assert_eq!(
            determine_outcome(&[dry_run_block], "1.2.3.4", true),
            "active"
        );

        // Failed execution - should not count as blocked.
        let failed = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.9,
            auto_executed: true,
            dry_run: false,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "error: permission denied".to_string(),
            prev_hash: None,
        };
        assert_eq!(determine_outcome(&[failed], "1.2.3.4", true), "active");

        // No decisions at all, has incident → active.
        assert_eq!(determine_outcome(&[], "1.2.3.4", true), "active");

        // No decisions, no incident → unknown.
        assert_eq!(determine_outcome(&[], "1.2.3.4", false), "unknown");
    }

    // ── D3 tests ────────────────────────────────────────────────────────

    #[test]
    fn action_config_disabled_by_default() {
        let cfg = DashboardActionConfig::default();
        assert!(
            !cfg.enabled,
            "actions must be disabled by default for safety"
        );
        assert!(cfg.dry_run, "dry_run must be true by default");
    }

    #[test]
    fn append_decision_entry_writes_jsonl() {
        let dir = TempDir::new().unwrap();
        let entry = DecisionEntry {
            ts: Utc::now(),
            incident_id: "dashboard:manual:test".to_string(),
            host: "testhost".to_string(),
            ai_provider: "dashboard:operator".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: Some("block-ip-ufw".to_string()),
            confidence: 1.0,
            auto_executed: true,
            dry_run: true,
            reason: "manual block for testing".to_string(),
            estimated_threat: "manual".to_string(),
            execution_result: "ok (dry_run)".to_string(),
            prev_hash: None,
        };

        append_decision_entry(dir.path(), &entry).unwrap();

        // File must exist and contain exactly one valid JSON line.
        let date = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let path = dir.path().join(format!("decisions-{date}.jsonl"));
        assert!(path.exists(), "decisions JSONL must be created");
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: DecisionEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed.ai_provider, "dashboard:operator");
        assert_eq!(parsed.action_type, "block_ip");
        assert_eq!(parsed.target_ip.as_deref(), Some("1.2.3.4"));

        // Appending a second entry should produce two lines.
        append_decision_entry(dir.path(), &entry).unwrap();
        let contents2 = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents2.lines().count(), 2);
    }

    #[test]
    fn make_synthetic_incident_populates_ip_entity() {
        let inc = make_synthetic_incident("test-id", "203.0.113.1", "brute force test");
        assert!(inc.incident_id.contains("dashboard:manual"));
        assert!(inc.incident_id.contains("test-id"));
        assert_eq!(inc.entities.len(), 1);
        assert_eq!(inc.entities[0].value, "203.0.113.1");
        assert!(inc.tags.contains(&"dashboard".to_string()));
        assert!(inc.tags.contains(&"manual".to_string()));
    }

    #[test]
    fn action_cfg_block_skill_selection() {
        // Verify the skill_id format follows convention (used in allowlist check).
        let backends = [
            ("ufw", "block-ip-ufw"),
            ("iptables", "block-ip-iptables"),
            ("nftables", "block-ip-nftables"),
        ];
        for (backend, expected_id) in backends {
            let cfg = DashboardActionConfig {
                enabled: true,
                dry_run: true,
                block_backend: backend.to_string(),
                allowed_skills: vec![expected_id.to_string()],
                ai_enabled: false,
                ai_provider: "openai".to_string(),
                ai_model: "gpt-4o-mini".to_string(),
                ..DashboardActionConfig::default()
            };
            let skill_id = format!("block-ip-{}", cfg.block_backend);
            assert_eq!(skill_id, expected_id);
            assert!(cfg.allowed_skills.contains(&skill_id));
        }
    }

    // ── D5 tests ─────────────────────────────────────────────────────────

    #[test]
    fn verdict_detected_entry_vector_from_incident() {
        let incident_entry = JourneyEntry {
            ts: Utc::now(),
            kind: "incident".to_string(),
            data: serde_json::json!({ "incident_id": "ssh_bruteforce:abc123" }),
        };
        // With only an incident (no events), access_status is "inconclusive"
        // and the entry vector is extracted from the incident_id prefix.
        let verdict = derive_verdict(&[incident_entry], "active");
        assert_eq!(verdict.entry_vector, "ssh_bruteforce");
        assert_eq!(verdict.access_status, "inconclusive");
        assert_eq!(verdict.containment_status, "active");
        assert_eq!(verdict.confidence, "low");
    }

    #[test]
    fn verdict_blocked_outcome_sets_containment_status() {
        let decision_entry = JourneyEntry {
            ts: Utc::now(),
            kind: "decision".to_string(),
            data: serde_json::json!({
                "action_type": "block_ip",
                "execution_result": "ok",
                "dry_run": false,
            }),
        };
        let verdict = derive_verdict(&[decision_entry], "blocked");
        assert_eq!(verdict.containment_status, "blocked");
        // Incident + decision → medium confidence (no events)
        assert_eq!(verdict.confidence, "low");
    }

    #[test]
    fn chapters_group_entries_by_stage() {
        // Three incident entries followed by one decision - should produce
        // an "initial_access_attempt" chapter and a "response" chapter.
        let entries: Vec<JourneyEntry> = vec![
            JourneyEntry {
                ts: Utc::now(),
                kind: "incident".to_string(),
                data: serde_json::json!({ "incident_id": "ssh_bruteforce:1" }),
            },
            JourneyEntry {
                ts: Utc::now(),
                kind: "incident".to_string(),
                data: serde_json::json!({ "incident_id": "ssh_bruteforce:2" }),
            },
            JourneyEntry {
                ts: Utc::now(),
                kind: "decision".to_string(),
                data: serde_json::json!({ "action_type": "block_ip" }),
            },
        ];
        let chapters = derive_chapters(&entries);
        // At minimum one chapter must be produced.
        assert!(!chapters.is_empty());
        // All entry indices must be valid.
        for ch in &chapters {
            for &idx in &ch.entry_indices {
                assert!(idx < entries.len());
            }
        }
        // Total entry coverage: every entry should appear in exactly one chapter.
        let total_covered: usize = chapters.iter().map(|ch| ch.entry_indices.len()).sum();
        assert_eq!(total_covered, entries.len());
    }

    // ── Memory safety tests ─────────────────────────────────────────────

    #[test]
    fn global_rate_limiter_rejects_after_limit() {
        let test_ip = "rate-test-192.0.2.99";
        // Fill up to the limit
        for _ in 0..GLOBAL_RATE_LIMIT_PER_MIN {
            assert!(!global_rate_check(test_ip), "should allow under limit");
        }
        // Next request should be rejected
        assert!(global_rate_check(test_ip), "should reject at limit");
    }

    #[test]
    fn global_rate_limiter_prunes_stale_ips() {
        // Insert 1100+ unique IPs to trigger the >1000 prune path
        for i in 0..1100 {
            global_rate_check(&format!("prune-test-{i}"));
        }
        // Should not panic or OOM - the prune ran and cleaned up
        let map = GLOBAL_RATE_LIMITER
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // After prune, stale entries removed (all are <60s old so still present,
        // but the code path executed without error)
        assert!(map.len() <= 1200, "map should not grow unbounded");
    }

    #[test]
    fn jsonl_cache_returns_same_data_on_cache_hit() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test-cache.jsonl");
        std::fs::write(
            &path,
            "{\"ts\":\"2026-01-01T00:00:00Z\",\"host\":\"test\",\"source\":\"test\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"test\",\"details\":{},\"tags\":[],\"entities\":[]}\n",
        )
        .unwrap();

        let first: Vec<Event> = read_jsonl(&path);
        assert_eq!(first.len(), 1);

        // Second call should hit cache (same file, no modification)
        let second: Vec<Event> = read_jsonl(&path);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].kind, second[0].kind);
    }

    #[test]
    fn jsonl_cache_invalidates_on_file_change() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test-invalidate.jsonl");
        let line = "{\"ts\":\"2026-01-01T00:00:00Z\",\"host\":\"test\",\"source\":\"test\",\"kind\":\"ssh.login_failed\",\"severity\":\"info\",\"summary\":\"test\",\"details\":{},\"tags\":[],\"entities\":[]}\n";

        std::fs::write(&path, line).unwrap();
        let first: Vec<Event> = read_jsonl(&path);
        assert_eq!(first.len(), 1);

        // Append a line - file size changes, cache should invalidate
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(line.as_bytes()).unwrap();

        let second: Vec<Event> = read_jsonl(&path);
        assert_eq!(second.len(), 2);
    }
}
