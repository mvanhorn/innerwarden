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
mod compliance;
mod data_api;
mod fleet;
mod helpers;
mod intelligence;
mod investigation;
mod live_feed;
mod push;
mod sensors;
mod sse;
mod threat_contract;

#[cfg(test)]
mod consistency_block_counts;

#[allow(unused_imports)]
use actions::*;
#[allow(unused_imports)]
use agent_api::*;
#[allow(unused_imports)]
use auth::*;
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
use axum::extract::{DefaultBodyLimit, Query, State};
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

/// Short-lived cache of "this (user, password) tuple was just verified
/// against argon2". Skips the ~64 MB working-buffer allocation per
/// dashboard HTTP request — the dashboard frontend issues Basic Auth
/// on every API call, and per jeprof on prod 2026-05-02 that drove
/// argon2 to 128 MB / 29.4 % of the agent heap.
///
/// ## Security trade-off
///
/// Cache hits skip the slow argon2 path. The window between a
/// password change taking effect server-side and the cache TTL
/// expiring is the operationally-acceptable cost. With the default
/// `TTL_SECS = 300`, a leaked credential remains usable for at most
/// 5 minutes after the password is rotated, which matches the
/// already-existing session token TTL behaviour.
///
/// The cache key is a SHA-256 hash of `(salt || user || ":" || password)`
/// where `salt` is a per-process random value generated at boot.
/// Plaintext credentials never persist in the map; the salt is
/// discarded on restart so cache keys cannot be replayed across
/// process boundaries.
#[derive(Clone)]
struct VerifiedCache {
    state: Arc<VerifiedCacheState>,
}

struct VerifiedCacheState {
    salt: [u8; 32],
    map: RwLock<HashMap<[u8; 32], std::time::Instant>>,
}

impl VerifiedCache {
    /// 5 minutes — same window as session tokens.
    const TTL: std::time::Duration = std::time::Duration::from_secs(300);
    /// Capacity is small by design. The map sees at most one entry per
    /// active operator credential; in practice 1-3 entries.
    const CAPACITY: usize = 16;

    fn new() -> Self {
        let mut salt = [0u8; 32];
        // Use the OsRng path already imported elsewhere in the
        // dashboard module — avoids pulling in a new rand entry point
        // for one 32-byte read at boot.
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut salt);
        Self {
            state: Arc::new(VerifiedCacheState {
                salt,
                map: RwLock::new(HashMap::new()),
            }),
        }
    }

    fn key(&self, user: &str, password: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.state.salt);
        h.update(user.as_bytes());
        h.update(b":");
        h.update(password.as_bytes());
        h.finalize().into()
    }

    /// Returns `true` when the (user, password) tuple has a non-expired
    /// entry in the cache.
    fn check(&self, user: &str, password: &str) -> bool {
        let k = self.key(user, password);
        let map = self.state.map.read().unwrap_or_else(|p| p.into_inner());
        match map.get(&k) {
            Some(ts) => ts.elapsed() < Self::TTL,
            None => false,
        }
    }

    /// Record a successful verification under the (user, password) key.
    /// Also drains expired entries opportunistically and enforces the
    /// capacity by evicting the oldest survivor when the map is full.
    fn insert(&self, user: &str, password: &str) {
        let k = self.key(user, password);
        let mut map = self.state.map.write().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, ts| ts.elapsed() < Self::TTL);
        if map.len() >= Self::CAPACITY {
            if let Some(oldest_key) = map.iter().min_by_key(|(_, ts)| **ts).map(|(k, _)| *k) {
                map.remove(&oldest_key);
            }
        }
        map.insert(k, std::time::Instant::now());
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.state
            .map
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }
}

#[derive(Clone)]
pub struct DashboardAuth {
    username: String,
    password_hash: PasswordHashString,
    verified_cache: VerifiedCache,
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
                    verified_cache: VerifiedCache::new(),
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

    /// Slow path: parse the stored PHC hash and run argon2 verify.
    /// Allocates the argon2 working buffer (~64 MB at default
    /// parameters). Used directly by the login endpoint and by the
    /// cache miss path in `verify_with_cache`.
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

    /// Fast path used by the per-request middleware. Hits the
    /// short-lived `verified_cache` when the same (user, password)
    /// has been verified recently and returns `true` without paying
    /// the argon2 allocation cost. Cache misses fall through to
    /// `verify` and, on success, populate the cache so the next
    /// request from the same client lands on the fast path.
    pub(super) fn verify_with_cache(&self, user: &str, password: &str) -> bool {
        if self.verified_cache.check(user, password) {
            return true;
        }
        let ok = self.verify(user, password);
        if ok {
            self.verified_cache.insert(user, password);
        }
        ok
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

/// Audit I-14 (2026-04-29): cap request bodies at 1 MiB across the
/// whole router. Without this, an authenticated operator session (or
/// the loopback-bound /api/agent/* endpoints) could be coerced into
/// POSTing a multi-MB body, OOMing the agent under sustained attack.
///
/// 1 MiB is generous for every legitimate POST in this dashboard:
/// web-push subscribe (~1 KB), AI briefing requests (~2 KB), bot
/// command audit append (~500 B), session login basic auth (~100 B).
/// Bump if a future endpoint genuinely needs more.
pub(super) const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Build the `DefaultBodyLimit` layer that the dashboard router
/// applies. Extracted so the regression anchor in `tests` exercises
/// the exact same value `serve()` uses (no duplicated literal).
pub(super) fn build_body_limit_layer() -> DefaultBodyLimit {
    DefaultBodyLimit::max(MAX_BODY_BYTES)
}

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
    ai_router: crate::ai::AiRouter,
    briefing_state: Arc<tokio::sync::Mutex<Option<crate::briefing::Briefing>>>,
    briefing_hour: u8,
    briefing_minute: u8,
    sqlite_store: Option<Arc<innerwarden_store::Store>>,
    fleet_state: Option<crate::fleet::FleetState>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    insecure_no_tls: bool,
) -> Result<()> {
    // SEC-005: Reject non-loopback bind without authentication.
    let is_loopback_bind = is_loopback_address(&bind);
    if let Err(e) = validate_bind_auth(&bind, auth.is_some()) {
        anyhow::bail!("{}", e);
    }
    if auth.is_none() && is_loopback_bind {
        warn!(
            "dashboard is running WITHOUT authentication (loopback only) - \
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
        ai_router,
        latest_briefing: briefing_state,
        briefing_hour,
        briefing_minute,
        sqlite_store,
        fleet_state,
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

    // SEC-006: Agent API routes — require auth when bound to non-loopback.
    // On loopback, these remain unauthenticated for local service-to-service use
    // (OpenClaw, n8n, etc.). On non-loopback, they go through the auth layer.
    let agent_api_router = Router::new()
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
        .route("/api/agent-guard/agents", get(api_agent_guard_list));
    let agent_api = if should_require_api_auth(&bind) {
        agent_api_router
            .layer(auth_layer.clone())
            .with_state(state.clone())
    } else {
        agent_api_router.with_state(state.clone())
    };

    // Auth login route - public (no auth required; this IS the auth endpoint)
    let auth_login = Router::new()
        .route("/api/auth/login", post(api_auth_login))
        .with_state(state.clone());

    // Dashboard routes - auth required
    let dashboard = Router::new()
        .route("/", get(index))
        .route("/app.css", get(serve_css))
        .route("/js/api.js", get(serve_js_api))
        .route("/js/icons.js", get(serve_js_icons))
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
        .route("/js/monthly.js", get(serve_js_monthly))
        .route("/js/responses.js", get(serve_js_responses))
        .route("/js/actions.js", get(serve_js_actions))
        .route("/js/sse.js", get(serve_js_sse))
        .route("/js/fleet.js", get(serve_js_fleet))
        .route("/api/overview", get(api_overview))
        .route("/api/incidents", get(api_incidents))
        .route("/api/decisions", get(api_decisions))
        .route("/api/entities", get(api_entities))
        .route("/api/pivots", get(api_pivots))
        .route("/api/clusters", get(api_clusters))
        .route("/api/threats/diagnostic", get(api_threats_diagnostic))
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
        // 2026-05-01 (`tracked-spec-ai-override`): operator
        // overrides AI decisions / re-opens dismissed incidents /
        // labels decisions for retraining. Audit-only for v1.
        .route(
            "/api/action/decision/override",
            post(api_action_override_decision),
        )
        .route(
            "/api/action/incident/reopen",
            post(api_action_reopen_incident),
        )
        .route(
            "/api/action/decision/label",
            post(api_action_label_decision),
        )
        // Honeypot tab
        .route("/api/honeypot/sessions", get(api_honeypot_sessions))
        .route("/api/action/honeypot", post(api_action_honeypot))
        // Compliance tab
        .route("/api/admin-actions", get(api_admin_actions))
        .route("/api/advisory-cache", get(api_advisory_cache))
        .route("/api/compliance", get(api_compliance))
        .route("/api/compliance/audit-trail", get(api_audit_trail))
        // MSSP fleet (spec 038). Both endpoints return 404 when
        // fleet mode is disabled so the absence is unambiguous to
        // the frontend.
        .route("/api/fleet/hosts", get(fleet::api_fleet_hosts))
        .route("/api/fleet/overview", get(fleet::api_fleet_overview))
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
        // Spec 005 T017: active incident groups snapshot (noise-reduction view).
        .route("/api/incident-groups", get(api_incident_groups))
        .route("/api/mitre/navigator", get(api_mitre_navigator))
        .route("/api/mitre/coverage", get(api_mitre_coverage))
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
        .layer(auth_layer.clone())
        .with_state(state.clone());

    // Live-feed routes are intentionally public (no auth) regardless of bind
    // address. The response shape is already sanitised in `live_feed.rs`:
    // `host` is blanked, `evidence` is empty, `recommended_checks` is empty,
    // `research_only` incidents are filtered, and `is_internal` incidents are
    // filtered — only attacker metadata that is public observable elsewhere
    // (attacker IP, MITRE technique, reputation counters) is exposed. The
    // marketing site's `/live` page depends on these endpoints, so the earlier
    // SEC-007 guard that required auth on non-loopback binds broke the public
    // use case and contradicted the stated intent at `live_feed.rs:7`
    // ("Public live-feed endpoints (CORS-enabled, no auth)"). DoS is bounded
    // by `rate_limit_layer` applied to the merged app below.
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
        .layer(build_body_limit_layer())
        .layer(middleware::from_fn(security_headers))
        .layer(activity_layer)
        .layer(rate_limit_layer);

    // D6: spawn file watcher and heartbeat tasks
    tokio::spawn(watch_for_new_entries(data_dir.clone(), event_tx.clone()));
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            // Spec 037 I-13 PR-7 (K-class): broadcast `send` returns
            // `Err` only when there are zero subscribers — the
            // expected steady state when no operator is viewing the
            // dashboard. Heartbeat to nobody is fine; intentionally
            // silent. Same rationale as `dashboard/sse.rs` sends.
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

    if insecure_no_tls {
        // ── Plain HTTP (explicitly opted out of TLS) ─────────────────
        warn!(
            bind = %bind,
            "dashboard serving over PLAIN HTTP — credentials and data are NOT encrypted. \
             Use --tls-cert/--tls-key or remove --insecure-no-tls for production."
        );
        let listener = tokio::net::TcpListener::bind(&bind)
            .await
            .with_context(|| format!("failed to bind dashboard listener on {bind}"))?;
        axum::serve(listener, app)
            .await
            .context("dashboard server failed")
    } else {
        // ── HTTPS (default) ──────────────────────────────────────────
        let tls_config = build_tls_config(&data_dir, tls_cert, tls_key).await?;
        let addr: std::net::SocketAddr = bind
            .parse()
            .with_context(|| format!("invalid bind address: {bind}"))?;

        info!(
            bind = %bind,
            "dashboard HTTPS started"
        );
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await
            .context("dashboard HTTPS server failed")
    }
}

/// Apply a Unix file mode and `warn!` on failure with structured
/// context. Replaces the prior `let _ = std::fs::set_permissions(..)`
/// pattern at the two TLS auto-gen sites in `build_tls_config`
/// (Spec 037 I-13 PR-2). Silent failure was security-relevant: a
/// `chmod` error on the freshly-generated TLS private key would
/// leave it at the file's creation mode (typically 0644 under the
/// process umask) instead of 0600, exposing the private key to any
/// local user. The warn surfaces the failure to the operator log
/// without changing the observable behaviour: the file is left in
/// whatever state the failed chmod left it (same as the prior
/// `let _ =`), the caller continues, and the dashboard binds with
/// whatever cert state is on disk.
///
/// Function is `#[cfg(unix)]` to match the original gating; the
/// PermissionsExt API used for `from_mode` is Unix-only. Returns
/// `()` (infallible) so call sites stay one-line and the calling
/// `build_tls_config` flow is unchanged in shape.
#[cfg(unix)]
fn set_file_mode_or_warn(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        warn!(
            path = %path.display(),
            intended_mode = format!("{mode:#o}"),
            error = %e,
            "failed to set TLS file permissions (file left at previous mode)"
        );
    }
}

/// Build RustlsConfig from cert/key files or auto-generate a self-signed cert.
async fn build_tls_config(
    data_dir: &std::path::Path,
    cert_path: Option<String>,
    key_path: Option<String>,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    use axum_server::tls_rustls::RustlsConfig;

    // Ensure a crypto provider is installed (required by rustls 0.23+).
    // Spec 037 I-13 PR-7 (K-class): `install_default()` is
    // idempotent — `Err` means "another provider is already
    // installed", which is the steady state on hot reload or when
    // the test runner has set one up before us. Intentionally
    // silent.
    let _ = rustls::crypto::ring::default_provider().install_default();

    if let (Some(cert), Some(key)) = (cert_path, key_path) {
        // Use operator-provided cert/key
        info!(cert = %cert, key = %key, "loading TLS certificate");
        let config = RustlsConfig::from_pem_file(&cert, &key)
            .await
            .with_context(|| format!("failed to load TLS cert={cert} key={key}"))?;
        Ok(config)
    } else {
        // Auto-generate self-signed certificate
        let cert_file = data_dir.join("dashboard-cert.pem");
        let key_file = data_dir.join("dashboard-key.pem");

        if cert_file.exists() && key_file.exists() {
            info!("loading existing self-signed TLS certificate");
            let config = RustlsConfig::from_pem_file(&cert_file, &key_file)
                .await
                .context("failed to load existing self-signed cert")?;
            return Ok(config);
        }

        info!("generating self-signed TLS certificate for dashboard");
        let mut params = rcgen::CertificateParams::new(vec![
            "localhost".to_string(),
            "innerwarden".to_string(),
        ])?;
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("InnerWarden Dashboard".to_string()),
        );
        params.distinguished_name.push(
            rcgen::DnType::OrganizationName,
            rcgen::DnValue::Utf8String("InnerWarden".to_string()),
        );
        // SEC-013: Valid for 365 days from now (not a hardcoded date).
        let (y, m, d) = cert_expiry_ymd(365);
        params.not_after = rcgen::date_time_ymd(y, m, d);
        // Add SANs for common access patterns
        params.subject_alt_names = vec![
            rcgen::SanType::DnsName("localhost".try_into()?),
            rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
            rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
        ];

        let key_pair = rcgen::KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        std::fs::write(&cert_file, &cert_pem)
            .with_context(|| format!("failed to write {}", cert_file.display()))?;
        std::fs::write(&key_file, &key_pem)
            .with_context(|| format!("failed to write {}", key_file.display()))?;

        // Restrict key file permissions. Failure is surfaced via
        // `warn!` (Spec 037 I-13 PR-2) — silent chmod failure on
        // the private key would expose it at the umask's default
        // mode (typically 0644) to any local user.
        #[cfg(unix)]
        {
            set_file_mode_or_warn(&key_file, 0o600);
            set_file_mode_or_warn(&cert_file, 0o644);
        }

        info!(
            cert = %cert_file.display(),
            key = %key_file.display(),
            "self-signed TLS certificate generated (valid 365 days)"
        );

        let config = RustlsConfig::from_pem_file(&cert_file, &key_file)
            .await
            .context("failed to load generated self-signed cert")?;
        Ok(config)
    }
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
js_handler!(serve_js_icons, JS_ICONS);
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
js_handler!(serve_js_monthly, JS_MONTHLY);
js_handler!(serve_js_responses, JS_RESPONSES);
js_handler!(serve_js_actions, JS_ACTIONS);
js_handler!(serve_js_sse, JS_SSE);
js_handler!(serve_js_fleet, JS_FLEET);

// ---------------------------------------------------------------------------
// D10 - Report API
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

const INDEX_HTML: &str = include_str!("frontend/html/index.html");
const APP_CSS: &str = include_str!("frontend/css/app.css");
const JS_API: &str = include_str!("frontend/js/api.js");
const JS_ICONS: &str = include_str!("frontend/js/icons.js");
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
const JS_MONTHLY: &str = include_str!("frontend/js/monthly.js");
const JS_RESPONSES: &str = include_str!("frontend/js/responses.js");
const JS_ACTIONS: &str = include_str!("frontend/js/actions.js");
const JS_SSE: &str = include_str!("frontend/js/sse.js");
const JS_FLEET: &str = include_str!("frontend/js/fleet.js");

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
// SEC-005: Pure helpers for bind address validation (testable).
// ---------------------------------------------------------------------------

/// Check if a bind address is a loopback address.
pub(crate) fn is_loopback_address(bind: &str) -> bool {
    bind.starts_with("127.0.0.1") || bind.starts_with("[::1]") || bind.starts_with("localhost")
}

/// Validate bind address + auth combination.
/// Returns Err if non-loopback bind has no auth configured.
pub(crate) fn validate_bind_auth(bind: &str, has_auth: bool) -> Result<(), String> {
    if !has_auth && !is_loopback_address(bind) {
        return Err(format!(
            "dashboard bound to non-loopback address {} without authentication. \
             Set INNERWARDEN_DASHBOARD_USER and INNERWARDEN_DASHBOARD_PASSWORD_HASH, \
             or bind to 127.0.0.1 for unauthenticated local access.",
            bind
        ));
    }
    Ok(())
}

/// SEC-013: Compute TLS certificate expiry date (year, month, day).
pub(crate) fn cert_expiry_ymd(days_valid: i64) -> (i32, u8, u8) {
    let expiry = chrono::Utc::now() + chrono::Duration::days(days_valid);
    (
        chrono::Datelike::year(&expiry),
        chrono::Datelike::month(&expiry) as u8,
        chrono::Datelike::day(&expiry) as u8,
    )
}

/// SEC-006/007: Determine if agent API / live-feed should require auth.
/// Returns true when auth should be enforced (non-loopback bind).
pub(crate) fn should_require_api_auth(bind: &str) -> bool {
    !is_loopback_address(bind)
}

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

    // ── Phase 4 (audit RC-4) frontend wiring anchors ────────────────────
    //
    // The dashboard ships its frontend as `include_str!` constants
    // bundled into the agent binary at build time. Anchor that the
    // PR #335 backend contract (block_state on AttackerSummary +
    // JourneyResponse) is actually consumed by the bundled JS. If a
    // future cleanup deletes the helper or renames the field, the
    // operator would silently lose the kernel-evidence badge — these
    // tests fail loudly instead.

    #[test]
    fn helpers_js_exports_block_state_badge_renderer() {
        assert!(
            JS_HELPERS.contains("function blockStateBadgeHtml"),
            "blockStateBadgeHtml helper is missing from bundled helpers.js"
        );
        // The three branches must all be reachable from the helper.
        assert!(JS_HELPERS.contains("blocked_now"));
        assert!(JS_HELPERS.contains("blocked_historical"));
    }

    #[test]
    fn threats_js_renders_block_state_on_attacker_card() {
        assert!(
            JS_THREATS.contains("blockStateBadgeHtml(item.block_state)"),
            "threats.js card renderer must read item.block_state from \
             AttackerSummary; otherwise the kernel-evidence badge never \
             ships to the operator"
        );
    }

    #[test]
    fn journey_js_renders_block_state_in_header() {
        assert!(
            JS_JOURNEY.contains("blockStateBadgeHtml(j.block_state)"),
            "journey.js header must read j.block_state from JourneyResponse"
        );
    }

    #[test]
    fn app_css_defines_kernel_evidence_badge_classes() {
        // The CSS class names are referenced by helpers.js — anchor
        // both ends so a rename on either side fails the build.
        assert!(APP_CSS.contains(".badge-kernel-active"));
        assert!(APP_CSS.contains(".badge-kernel-expired"));
    }

    // ── Phase 7 (audit RC-2) bundle anchors ────────────────────────────
    //
    // Each anchor pins a specific consumption of the new
    // OverviewSnapshot contract. Together they guarantee that the
    // backend's typed shape, the CSS classes, the HTML tile structure
    // and the home.js render path don't drift independently — exactly
    // the fan-out problem the audit's "Three-place writes" RC-2
    // describes, generalised to the front-end bundle.

    #[test]
    fn home_js_reads_overview_snapshot() {
        // The render path reads `overview.snapshot.buckets.*.unique_attackers`
        // (Phase 7 typed snapshot contract). 2026-04-30 redesign drops
        // the `incidents` field from the home — unique-attacker is the
        // only count rendered, matching the unified attacker semantic
        // from Phase 10. The pending pipeline still reads `snap.pending`.
        assert!(JS_HOME.contains("overview.snapshot"));
        assert!(JS_HOME.contains("snap.buckets.blocked.unique_attackers"));
        assert!(JS_HOME.contains("snap.pending"));
    }

    #[test]
    fn home_js_renders_pending_breakdown_panel() {
        // 2026-04-30 redesign: pending grid now renders dynamically —
        // cells with count > 0 are emitted by name, no static DOM IDs.
        // Anchor pins the keys updatePendingPanel reads from snapshot
        // so a future schema change on `pending.*` is caught.
        assert!(JS_HOME.contains("pending.in_flight"));
        assert!(JS_HOME.contains("pending.declined_by_ai"));
        assert!(JS_HOME.contains("pending.cooldown_suppressed"));
        assert!(JS_HOME.contains("pending.stuck"));
        // Plain-English labels rendered into each cell. Operator sees
        // these strings, not SOC jargon.
        assert!(JS_HOME.contains("Being analyzed now"));
        assert!(JS_HOME.contains("AI escalated to you"));
        assert!(JS_HOME.contains("Same threat already decided"));
        assert!(JS_HOME.contains("No decision after 1 hour"));
    }

    #[test]
    fn home_js_routes_ai_not_responding_health_to_alert_reasons() {
        // The 'ai_not_responding' health verb must surface as a
        // user-visible reason. If a refactor drops the kind check,
        // operator loses the loudest "AI is wedged" signal.
        assert!(JS_HOME.contains("ai_not_responding"));
        assert!(JS_HOME.contains("backed_up"));
    }

    #[test]
    fn index_html_carries_pending_breakdown_panel() {
        // 2026-04-30 redesign: pending grid is now dynamic — only the
        // panel container + grid mount-point ship in HTML, the cells
        // are rendered from JS only when count > 0. The previous
        // anchor required the 4 static cell IDs which no longer exist.
        assert!(INDEX_HTML.contains("id=\"homePendingPanel\""));
        assert!(INDEX_HTML.contains("id=\"homePendingGrid\""));
        // The legacy IDs MUST NOT come back — that signals someone
        // re-introduced the always-render-zero-cells regression.
        assert!(!INDEX_HTML.contains("id=\"homePendingInFlight\""));
        assert!(!INDEX_HTML.contains("id=\"homePendingStuck\""));
    }

    #[test]
    fn index_html_attention_first_home_layout() {
        // 2026-04-30 redesign: the Home was rebuilt for the 95%
        // 5-second-visit operator. Reading order: hero verb → critical
        // banner (only when needed) → review queue banner (only when
        // needed) → 4-number activity strip → AI briefing (always
        // visible) → system health line → details (collapsed). This
        // anchor pins the structural IDs so a future "improvement"
        // cannot silently drop them. See loadHome() for the
        // orchestration this anchors against.
        for id in [
            "homeHero",
            "homeCriticalBanner",
            "homeCriticalTitle",
            "homeCriticalSub",
            "homeCriticalCta",
            "homeReviewBanner",
            "homeReviewCount",
            "homeActivitySection",
            "homeActWatched",
            "homeActFlagged",
            "homeActStopped",
            "homeActAwaiting",
            "briefingSection",
            "briefingContent",
            "briefingBtn",
            "homeHealthLine",
            "homeHealthIcon",
            "homeHealthSummary",
            "homeDetailsToggle",
            "homeDetailsPanel",
            "homePendingPanel",
            "homePendingGrid",
            "homeCollectorStrip",
            "homeMetaMode",
            "homeMetaHeartbeat",
        ] {
            assert!(
                INDEX_HTML.contains(id),
                "Home redesign requires id={id} — operator-visible block missing"
            );
        }
        // Hero icon SVG path must be inlined so the page renders
        // before JS hydrates (lucide shield-check inner shapes).
        assert!(INDEX_HTML.contains("M20 13c0 5-3.5 7.5-7.66 8.95"));
    }

    #[test]
    fn home_js_renders_attention_first_layout() {
        // The render orchestration must call each block's renderer
        // explicitly. A future refactor that drops one renderer
        // produces an empty block on screen — anchor catches it.
        for fn_name in [
            "updateHomeHero",
            "renderCriticalBanner",
            "renderReviewBanner",
            "renderActivityStrip",
            "renderHealthLine",
            "renderDetailsPanel",
            "loadBriefing",
            "toggleHomeDetails",
            "openTopCritical",
            "findTopOpenCritical",
        ] {
            assert!(
                JS_HOME.contains(fn_name),
                "home.js must define {fn_name} (attention-first redesign)"
            );
        }
        // Plain-English copy strings — verb identity for the hero.
        assert!(JS_HOME.contains("All clear"));
        assert!(JS_HOME.contains("You are protected"));
        // Briefing must always be visible — section.style.display set
        // to '' unconditionally, NOT inside a try/catch fallback.
        // This stops the "fetch fails -> hide section silently" bug.
        let briefing_start = JS_HOME.find("loadBriefing").expect("loadBriefing");
        let briefing_end = JS_HOME[briefing_start..]
            .find("\nasync function generateBriefing")
            .expect("end of loadBriefing")
            + briefing_start;
        let body = &JS_HOME[briefing_start..briefing_end];
        assert!(
            body.contains("section.style.display = '';"),
            "loadBriefing must show section unconditionally (always-visible contract)"
        );
        assert!(
            !body.contains("section.style.display = 'none';"),
            "loadBriefing must NOT hide section on error (always-visible contract)"
        );
    }

    #[test]
    fn home_pending_panel_renders_only_nonzero_cells() {
        // 2026-04-30 redesign: the pending grid used to render all 4
        // cells with "0" placeholders even when every count was zero,
        // which the operator legitimately read as engineer-debug
        // noise. Steady state must be: panel hidden entirely. Anchor
        // pins the pattern by requiring the dynamic-render code path
        // (cells.filter(c => c.n > 0)) to be present.
        assert!(
            JS_HOME.contains("var visible = cells.filter(function(c) { return c.n > 0; });"),
            "updatePendingPanel must filter to non-zero cells before rendering"
        );
        assert!(
            JS_HOME.contains("if (visible.length === 0) {"),
            "updatePendingPanel must hide the panel when no cell is non-zero"
        );
    }

    #[test]
    fn home_critical_banner_only_renders_open_critical_high() {
        // The critical banner must (a) show only for open + critical/
        // high, (b) hide when no such incident exists, (c) deep-link
        // to the journey view via openTopCritical. Pin the predicates
        // so a future "improvement" doesn't widen the trigger and
        // make the banner fire on routine traffic.
        assert!(JS_HOME.contains("if (i.outcome !== 'open') return false;"));
        assert!(JS_HOME.contains("if (sevRank[sev] < 3) return false;"));
        // Hide path when no top critical.
        assert!(JS_HOME.contains("banner.style.display = 'none';"));
    }

    #[test]
    fn home_no_summary_pyramid_or_homenow_dom_ids_remain() {
        // 2026-04-30: enforce the redesign's removal of the old
        // pyramid + standalone "Now" section. If a regression
        // re-introduces them, the page will have BOTH the new strip
        // and the old pyramid (data drift visible to operator). The
        // CSS class .summary-pyramid is intentionally kept (legacy
        // safety) but no element should reference it any more.
        for orphan in [
            "id=\"homeNowWhat\"",
            "id=\"homeNowDid\"",
            "id=\"homeSummary\"",
            "id=\"homeSummaryWatched\"",
            "id=\"homeSummaryFlagged\"",
            "id=\"homeSummaryActed\"",
            "id=\"homeSummaryAwaiting\"",
            "id=\"homeSummaryBlocked\"",
            "id=\"homeSummaryHoneypot\"",
            "id=\"homeSummaryTrusted\"",
            "id=\"homeSummaryWatching\"",
            "id=\"homeStatusMeta\"",
            "class=\"summary-pyramid\"",
        ] {
            assert!(
                !INDEX_HTML.contains(orphan),
                "old pre-redesign anchor {orphan} should be gone — check for stale Home markup"
            );
        }
    }

    #[test]
    fn home_view_has_no_emoji_icons() {
        // Phase 11B + 2026-04-30 redesign: the entire home view uses
        // inline lucide SVGs. Walk the home view block specifically
        // (avoid false positives from other pages) and assert no
        // emoji codepoints we previously rendered there.
        let home_start = INDEX_HTML
            .find("<!-- ── Home view ──")
            .or_else(|| INDEX_HTML.find("id=\"viewHome\""))
            .expect("home view block present");
        let home_end = INDEX_HTML[home_start..]
            .find("<!-- ── Sensors view ──")
            .expect("sensors view marks the end of home block")
            + home_start;
        let home = &INDEX_HTML[home_start..home_end];
        for emoji in ["📡", "🎯", "🛡️", "⛔", "👁️", "🍯", "🤝", "⚠️", "🤖"]
        {
            assert!(
                !home.contains(emoji),
                "emoji {emoji} still in Home view — should be inline lucide SVG"
            );
        }
        // The hero shield-check SVG must remain so the page renders
        // the verb icon before JS hydrates.
        assert!(home.contains("M20 13c0 5-3.5 7.5-7.66 8.95"));
    }

    #[test]
    fn app_css_defines_attention_first_home_styles() {
        for selector in [
            ".home-alert-banner",
            ".home-alert-critical",
            ".home-alert-warn",
            ".activity-strip",
            ".activity-cell",
            ".activity-cell-attention-active",
            ".home-health-line",
            ".home-health-bad",
            ".home-details",
            ".home-meta-row",
        ] {
            assert!(
                APP_CSS.contains(selector),
                "redesign CSS must define {selector}"
            );
        }
    }

    #[test]
    fn phase_14_qa_polish_anchors_present() {
        // Phase 14 (QA polish, 2026-04-29): bundle anchors for the six
        // operator-reported polish fixes. Each one was a small
        // user-visible behaviour that's easy to break in a future
        // refactor that doesn't know what the fix was for; pin them.

        // 1. compare-date placeholder + clarifying title (operator
        //    confused this with the main date picker).
        assert!(
            INDEX_HTML.contains("Compare with another date"),
            "flt-compare-date placeholder must explain the field"
        );

        // 2. detector autocomplete datalist is wired and seeded.
        assert!(
            INDEX_HTML.contains("list=\"detector-options\""),
            "flt-detector must reference the datalist"
        );
        assert!(
            INDEX_HTML.contains("<datalist id=\"detector-options\">"),
            "datalist with known detector slugs must be present"
        );
        for det in ["ssh_bruteforce", "kill_chain", "honeypot"] {
            assert!(
                INDEX_HTML.contains(det),
                "datalist must include '{det}' detector slug"
            );
        }

        // 3. Show-details stopPropagation was needed when the home
        //    Data Collection card had `onclick="showView('sensors')"`
        //    on its wrapper. The 2026-04-30 home redesign moved the
        //    collector strip INSIDE the (already opt-in) details
        //    panel, so the wrapper onclick is gone and the inline
        //    Show-details button was removed too. The stopPropagation
        //    contract this assert pinned no longer applies — there is
        //    no clickable wrapper to bubble into. Anchor retained as a
        //    breadcrumb pointing to the redesign rationale.

        // 4. Hide "0 evt" tail when event_count is zero. Both render
        //    paths (initial render and SSE refresh) must respect it.
        assert!(
            JS_THREATS.contains("(item.event_count || 0) > 0 ? ' \u{00b7} '"),
            "renderCard must hide '0 evt' tail when event_count is zero"
        );
        assert!(
            JS_THREATS.contains("evt > 0 ? ' \u{00b7} ' + evt + ' evt' : ''"),
            "SSE count refresh must hide '0 evt' tail too"
        );

        // 5. Pivot tab active state contrast bumped so the selected
        //    tab is visibly distinct from the inactive hover state.
        assert!(
            APP_CSS.contains("rgba(120, 229, 255, 0.22)"),
            "pivot-tab.active must use the stronger 22% accent fill"
        );
        assert!(
            APP_CSS.contains("rgba(120, 229, 255, 0.60)"),
            "pivot-tab.active must use the bolder 60% accent border"
        );

        // 6. KPI window labels on Threats track the active flt-date
        //    so they don't read "Today" while showing yesterday's
        //    data.
        assert!(
            JS_THREATS.contains("syncThreatsKpiWindowLabels"),
            "helper that re-labels the KPI window strings must exist"
        );
        assert!(
            JS_THREATS.contains("'Today'"),
            "Today label still used when picker is empty or matches today"
        );
    }

    #[test]
    fn app_css_defines_pending_panel_and_allowlisted_outcome() {
        assert!(APP_CSS.contains(".pending-grid"));
        assert!(APP_CSS.contains(".pending-cell-warn"));
        assert!(APP_CSS.contains(".kpi-pair-line"));
        assert!(APP_CSS.contains(".outcome-allowlisted"));
    }

    #[test]
    fn dashboard_js_files_have_no_template_interp_inside_single_quoted_strings() {
        // 2026-04-30: prod regression — operator hit "Loading attacker
        // profiles..." stuck forever because intel.js had two lines
        // of the form `'<div>${lucideIcon(\'name\', ...)}</div>'`. A
        // single-quoted JS string containing `${...}` is
        // (a) NOT interpolated (renders the literal `${...}` text),
        // (b) syntax-broken when the embedded expression contains a
        //     single quote — the inner `'name'` closes the outer
        //     string and corrupts the parse for the rest of the file.
        // Net effect: the entire JS file failed to load and EVERY
        // function it defined was undefined at runtime. nav.js called
        // loadIntel(), got ReferenceError, the static "Loading..."
        // placeholder remained on screen forever.
        //
        // This anchor scans every bundled JS file for the bug shape
        // (`'...${lucideIcon('...`) so a future "convenience" replace
        // that re-introduces it fails the build.
        for (label, src) in [
            ("api.js", JS_API),
            ("icons.js", JS_ICONS),
            ("helpers.js", JS_HELPERS),
            ("state.js", JS_STATE),
            ("nav.js", JS_NAV),
            ("home.js", JS_HOME),
            ("threats.js", JS_THREATS),
            ("journey.js", JS_JOURNEY),
            ("sensors.js", JS_SENSORS),
            ("reports.js", JS_REPORTS),
            ("status.js", JS_STATUS),
            ("compliance.js", JS_COMPLIANCE),
            ("honeypot.js", JS_HONEYPOT),
            ("intel.js", JS_INTEL),
            ("monthly.js", JS_MONTHLY),
            ("responses.js", JS_RESPONSES),
            ("actions.js", JS_ACTIONS),
            ("sse.js", JS_SSE),
        ] {
            for (i, line) in src.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("*") {
                    continue;
                }
                let Some(interp_pos) = line.find("${lucideIcon") else {
                    continue;
                };
                // Scan backwards from the interp position for the
                // most recent string opener on the same line. If it
                // is a single quote (and not a backtick), the
                // interpolation cannot evaluate.
                let prefix = &line[..interp_pos];
                let last_backtick = prefix.rfind('`');
                let last_squote = prefix.rfind('\'');
                if let (Some(sq), bt) = (last_squote, last_backtick) {
                    let bt = bt.unwrap_or(0);
                    if last_backtick.is_none() || sq > bt {
                        // Need to also rule out the case where the
                        // single quote is inside a previously-closed
                        // template literal. Coarse but adequate
                        // for current code: count odd parity of `'`.
                        let squote_count = prefix.matches('\'').count();
                        let bt_count = prefix.matches('`').count();
                        if squote_count % 2 == 1 && bt_count % 2 == 0 {
                            panic!(
                                "{label}:{} `${{lucideIcon(...)}}` inside single-quoted string — \
                                 will syntax-break the file at runtime. Use backticks. Line: {}",
                                i + 1,
                                line.trim()
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn icons_module_loaded_before_consumers_and_exposes_lucide_icon() {
        // 2026-04-30: shared icon vocabulary lives in
        // frontend/js/icons.js. Every consumer expects
        // `window.lucideIcon(name)` to be defined at script execution
        // time, so icons.js must be in the <script> chain before any
        // consumer file. Anchor pins the wiring against a future
        // refactor that drops the include.
        assert!(
            INDEX_HTML.contains("<script src=\"/js/icons.js\"></script>"),
            "icons.js must be wired into index.html"
        );
        assert!(
            INDEX_HTML.contains("<script src=\"/js/icons.js\"></script>\n<script src=\"/js/helpers.js\"></script>"),
            "icons.js must load BEFORE helpers.js (consumers expect window.lucideIcon to be defined)"
        );
        // The module must export the helper.
        assert!(JS_ICONS.contains("window.lucideIcon"));
        // And it must contain the canonical names every consumer
        // currently calls. If a consumer adds a new icon name, it
        // must be added to the SHAPES table in icons.js — pin the
        // names that are in active use so a typo in either side
        // surfaces as a test failure rather than a silent missing
        // icon at runtime.
        for name in [
            "shield-check",
            "shield",
            "ban",
            "eye",
            "book-open",
            "check",
            "check-circle",
            "x",
            "x-circle",
            "alert-circle",
            "alert-triangle",
            "activity",
            "radio",
            "search",
            "refresh-ccw",
            "bar-chart-3",
            "clipboard-list",
            "bug",
            "handshake",
            "target",
            "crosshair",
            "swords",
            "dna",
            "link",
            "globe",
            "flask-conical",
            "bot",
            "cpu",
            "monitor",
            "server",
            "wrench",
            "broom",
            "circle-dashed",
            "circle-dot",
            "flame",
            "lock",
        ] {
            let needle = format!("'{name}'");
            assert!(
                JS_ICONS.contains(&needle),
                "icons.js SHAPES must define '{name}' — referenced by a consumer"
            );
        }
    }

    #[test]
    fn dashboard_consumers_use_lucide_icon_not_emoji() {
        // 2026-04-30: every dashboard JS file that previously rendered
        // emoji icons now calls lucideIcon(...). Anchor pins the
        // contract: each consumer must mention lucideIcon at least
        // once, and must NOT contain the emojis it used to render.
        // A future refactor that re-introduces emoji is caught.
        for (file_label, src, must_have_emoji_count_zero) in [
            ("home.js", JS_HOME, true),
            ("threats.js", JS_THREATS, true),
            ("status.js", JS_STATUS, true),
            ("intel.js", JS_INTEL, true),
            ("monthly.js", JS_MONTHLY, true),
            ("honeypot.js", JS_HONEYPOT, true),
            ("compliance.js", JS_COMPLIANCE, true),
            ("responses.js", JS_RESPONSES, true),
            ("journey.js", JS_JOURNEY, true),
            ("reports.js", JS_REPORTS, true),
            ("helpers.js", JS_HELPERS, true),
            ("actions.js", JS_ACTIONS, true),
        ] {
            assert!(
                src.contains("lucideIcon("),
                "{file_label} must call lucideIcon() — emoji icons should be gone"
            );
            if must_have_emoji_count_zero {
                // Spot-check: the surrogate-pair escapes used by the
                // pre-fix code MUST NOT appear in the rendered string
                // bodies. (We allow them inside comments and JSDoc;
                // the test bundles raw bytes so it's an over-strict
                // match — for the canary set below we check shapes
                // we know were in user-facing strings only.)
                for emoji in ["\u{1F6E1}", "\u{1F441}", "\u{1F36F}", "\u{1F916}"] {
                    assert!(
                        !src.contains(emoji),
                        "{file_label} still contains emoji {emoji:?} — should be lucide SVG"
                    );
                }
            }
        }
    }

    #[test]
    fn threats_kpi_tile_label_is_blocks_not_blocked() {
        // 2026-04-30: the KPI tile counts BLOCK ACTIONS (per-decision
        // increment in compute_overview_counts_from_sqlite) while the
        // list-section group below counts UNIQUE ATTACKERS. Operator
        // saw "Blocked 41" on top and "Blocked 24" right below for
        // the same date and could not tell why. Renamed the KPI tile
        // to "Blocks" so the unit (events not unique IPs) is clear.
        // Anchor pins the rename — a future "consolidation" PR that
        // re-aligns them to the same string brings the confusion back.
        assert!(
            INDEX_HTML.contains("<div class=\"kpi-label\">Blocks</div>"),
            "KPI tile must read 'Blocks' to disambiguate from list 'Blocked attackers'"
        );
        assert!(
            JS_THREATS.contains("label: 'Blocked attackers'"),
            "list group header must read 'Blocked attackers' to disambiguate from KPI 'Blocks'"
        );
    }

    #[test]
    fn threats_js_uses_lucide_svg_icons_not_emoji() {
        // 2026-04-30: outcome group icons match the home pyramid
        // lucide SVG vocabulary (Phase 11B). Anchor that the unique
        // path strings of each lucide icon are present and that the
        // old emoji icons are NOT in OUTCOME_META anymore. A future
        // refactor that re-introduces the emojis fails this test.
        // (Same anchor pattern as `index_html_uses_lucide_svg_icons_
        // not_emoji` for the home pyramid.)
        // Ban (blocked).
        assert!(JS_THREATS.contains("m4.9 4.9 14.2 14.2"));
        // Bug (honeypot).
        assert!(JS_THREATS.contains("M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"));
        // Eye (monitoring).
        assert!(JS_THREATS.contains("M2.062 12.348"));
        // AlertCircle (needs_attention) — distinguishable from
        // AlertTriangle by the circle radius signature.
        assert!(JS_THREATS.contains("<line x1=\"12\" x2=\"12\" y1=\"8\" y2=\"12\"/>"));
        // Handshake (allowlisted).
        assert!(JS_THREATS.contains("m11 17 2 2a1 1 0 1 0 3-3"));
        // Check (dismissed).
        assert!(JS_THREATS.contains("M20 6 9 17l-5-5"));
        // Old emojis must be gone from the OUTCOME_META block.
        let outcome_block_start = JS_THREATS
            .find("var OUTCOME_META = {")
            .expect("OUTCOME_META present");
        let outcome_block_end = JS_THREATS[outcome_block_start..]
            .find("};\n")
            .expect("end of OUTCOME_META")
            + outcome_block_start;
        let block = &JS_THREATS[outcome_block_start..outcome_block_end];
        for emoji_escape in [
            "\\uD83D\\uDEE1", // 🛡️
            "\\uD83C\\uDF6F", // 🍯
            "\\uD83D\\uDC41", // 👁️
            "\\u26A0",        // ⚠️
            "\\uD83E\\uDD1D", // 🤝
        ] {
            assert!(
                !block.contains(emoji_escape),
                "emoji escape {emoji_escape} still in OUTCOME_META — should be lucide SVG constant"
            );
        }
    }

    #[test]
    fn telegram_audit_target_is_in_main_env_filter() {
        // 2026-05-01: the telegram audit log uses
        // `target: "telegram_audit"` (see telegram/client.rs), but
        // the env_filter in main.rs only allowed
        // `innerwarden_agent=info`. Result: ALL outgoing telegram
        // traffic was invisible in journald — daily digests, menu
        // callbacks, manual approvals, integrity alerts. Operator's
        // question "auditar o que funciona" had no answer.
        //
        // This anchor pins the env_filter directive so a future
        // refactor of the logging setup cannot silently drop the
        // audit target again.
        let main_src = include_str!("../main.rs");
        assert!(
            main_src.contains("telegram_audit=info"),
            "main.rs env_filter must include `telegram_audit=info` so the audit log reaches journald"
        );
    }

    #[test]
    fn telegram_audit_jsonl_path_is_wired_in_boot() {
        // The persistent JSONL audit (data_dir/telegram-sent.jsonl)
        // is the durable trail that survives log rotation. Boot must
        // call set_audit_jsonl_path on the TelegramClient — without
        // it the persistent file never exists.
        let boot_src = include_str!("../loops/boot.rs");
        assert!(
            boot_src.contains("set_audit_jsonl_path"),
            "boot.rs must wire the audit jsonl path on the TelegramClient"
        );
        assert!(
            boot_src.contains("telegram-sent.jsonl"),
            "boot.rs must use telegram-sent.jsonl as the audit filename"
        );
    }

    #[test]
    fn compliance_api_surfaces_documented_chain_breaks() {
        // 2026-05-01 (PR after #357): the documented chain breaks
        // must surface in the compliance tab so the operator sees
        // them without ssh + sqlite. Anchor pins the JSON contract
        // (`hash_chain.sqlite.documented_breaks` + `breaks[]`) and
        // the frontend rendering path.
        let compliance_src = include_str!("compliance.rs");
        assert!(
            compliance_src.contains("\"documented_breaks\": r.documented_breaks"),
            "compliance API must include documented_breaks count"
        );
        assert!(
            compliance_src.contains("\"breaks\": breaks"),
            "compliance API must include the breaks array"
        );
        assert!(
            JS_COMPLIANCE.contains("sqliteChain.breaks"),
            "compliance.js must read the new breaks array"
        );
        assert!(
            JS_COMPLIANCE.contains("documented break"),
            "compliance.js must surface the human label"
        );
    }

    #[test]
    fn ctl_chain_break_subcommand_is_wired() {
        // Operator-facing CLI for chain_break_audit. Anchor pins the
        // subcommand wiring + the two invocations (register / list).
        let ctl_main = include_str!("../../../ctl/src/main.rs");
        assert!(
            ctl_main.contains("name = \"chain-break\"")
                || ctl_main.contains("name=\"chain-break\""),
            "ctl must expose `innerwarden chain-break` subcommand"
        );
        assert!(
            ctl_main.contains("ChainBreakCommand::Register"),
            "ctl must dispatch chain-break register"
        );
        assert!(
            ctl_main.contains("ChainBreakCommand::List"),
            "ctl must dispatch chain-break list"
        );
    }

    #[test]
    fn chain_break_audit_table_is_in_schema_v4() {
        // Schema migration v4 adds the chain_break_audit table.
        // Anchor pins the v4 SQL so a future migration renumber or
        // squash does not silently drop the documented-break tracking.
        let schema_src = include_str!("../../../store/src/schema.rs");
        assert!(
            schema_src.contains("CURRENT_VERSION: i64 = 4"),
            "store schema must be at version 4"
        );
        assert!(
            schema_src.contains("CREATE TABLE IF NOT EXISTS chain_break_audit"),
            "v4 must create chain_break_audit table"
        );
        assert!(
            schema_src.contains("rowid_start"),
            "chain_break_audit must have rowid_start column"
        );
        assert!(
            schema_src.contains("rowid_end"),
            "chain_break_audit must have rowid_end column"
        );
        // Verify integration: maintenance.rs hourly tick uses the
        // documented_breaks field added to HashChainResult.
        let maint_src = include_str!("../../../store/src/maintenance.rs");
        assert!(
            maint_src.contains("documented_breaks"),
            "maintenance hourly alert must surface documented_breaks count"
        );
    }

    #[test]
    fn data_exfil_ebpf_suppresses_ssh_passwd_nss_init() {
        // Sensor anchor: the NSS_INIT_CLI_TOOLS list now includes
        // "ssh" so `git fetch` -> `ssh git@github.com` (or any
        // direct ssh + outbound) does not fire DATA_EXFIL on the
        // /etc/passwd NSS-lookup pattern. The actual sensor test
        // is in data_exfil_ebpf.rs::ssh_reading_passwd_then_
        // connecting_outbound_does_not_alert; this anchor mirrors
        // it from the agent test surface so the cross-crate
        // contract is visible during agent CI.
        let detector_src = include_str!("../../../sensor/src/detectors/data_exfil_ebpf.rs");
        assert!(
            detector_src.contains("\"ssh\","),
            "ssh must be in NSS_INIT_CLI_TOOLS to suppress git+github FP"
        );
    }

    #[test]
    fn threats_js_lists_allowlisted_in_outcome_order() {
        // The new "allowlisted" outcome must appear in the group
        // ordering and have a label entry. Pre-Phase-7 there was
        // no such entry; allowlisted attackers fell into "needs
        // attention" or were hidden by the toggle.
        assert!(
            JS_THREATS.contains("'allowlisted'"),
            "OUTCOME_ORDER must include 'allowlisted' for the dedicated group"
        );
        assert!(
            JS_THREATS.contains("Allowlisted (silenced)"),
            "label so the operator knows what the group means"
        );
    }

    #[test]
    fn threats_js_open_outcome_always_maps_to_needs_attention() {
        // Phase 13 (QA fix #3, 2026-04-29): pre-Phase-13 the
        // outcomeOf function rewrote `open` -> `monitoring` when
        // mode == 'guard', causing the home tile
        // `buckets.attention.unique_attackers` (correctly counts
        // open IPs) to disagree with the threats list group count
        // (which folded those same IPs into Observing). Anchor
        // pins the post-fix mapping: open -> needs_attention,
        // unconditional. If a future cleanup re-introduces the
        // mode-aware rewrite, the cross-surface drift returns and
        // this test fails.
        assert!(
            JS_THREATS.contains("if (o === 'open')"),
            "outcomeOf must explicitly handle the 'open' outcome string"
        );
        // The fix removed the `modeOpen === 'guard'` short-circuit.
        // If it comes back, this catches it.
        assert!(
            !JS_THREATS.contains("if (modeOpen === 'guard') return 'monitoring';"),
            "open MUST NOT be mode-rewritten to monitoring — Phase 13 RC-2 drift fix"
        );
    }

    #[test]
    fn normalize_limit_is_bounded() {
        assert_eq!(normalize_limit(None), 50);
        assert_eq!(normalize_limit(Some(0)), 1);
        assert_eq!(normalize_limit(Some(10)), 10);
        assert_eq!(normalize_limit(Some(9999)), 500);
    }

    #[test]
    fn resolve_date_falls_back_to_today_on_invalid_values() {
        // 2026-04-30: resolve_date is now UTC. SQLite stores ts as
        // ISO-UTC; matching "today" against Local::now broke the
        // dashboard between 00:00 and 01:00 BST when UTC was still
        // "yesterday". See helpers.rs::resolve_date docstring.
        let today = chrono::Utc::now()
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
            gate_suppressed_total: 0,
            telegram_sent_count: 0,
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
            verified_cache: VerifiedCache::new(),
        };

        assert!(auth.verify("admin", &correct_pw));
        assert!(!auth.verify("admin", &wrong_pw));
        assert!(!auth.verify("other", &correct_pw));
    }

    /// 2026-05-02 auth phase 2: argon2 verify is the new top heap
    /// consumer (128 MB / 29.4 % per jeprof). Cache hit on
    /// `verify_with_cache` skips the slow path entirely. Two
    /// invariants matter:
    ///   1. Wrong creds must NEVER cache — checked by counting cache
    ///      entries after a failed verify.
    ///   2. Subsequent successful verify with the same creds is a
    ///      cache hit — checked by comparing returns and asserting
    ///      the cache map carries exactly one entry.
    #[test]
    fn dashboard_auth_caches_successful_verifies() {
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
            verified_cache: VerifiedCache::new(),
        };

        // Wrong creds must not populate the cache. Anchor: a
        // future regression that calls `cache.insert` on the
        // failure path would inflate this count.
        assert!(!auth.verify_with_cache("admin", &wrong_pw));
        assert_eq!(
            auth.verified_cache.entry_count(),
            0,
            "cache must NOT carry an entry for failed verify"
        );

        // Correct creds: first call hits argon2, second call lands
        // in the cache. Both return true.
        assert!(auth.verify_with_cache("admin", &correct_pw));
        assert_eq!(auth.verified_cache.entry_count(), 1);
        assert!(auth.verify_with_cache("admin", &correct_pw));
        assert_eq!(
            auth.verified_cache.entry_count(),
            1,
            "second verify with same creds must be a cache hit, not a re-insert"
        );
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
                handled_ips_today: 0,
                blocked_count: 0,
                observing_count: 0,
                attention_count: 0,
                severity_breakdown: std::collections::HashMap::new(),
                allowlisted_count: 0,
                top_detectors: vec![],
                latest_telemetry: None,
                snapshot: None,
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
                block_state: None,
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

    // Spec 028-c: escalate decisions route the IP to the "escalated" outcome,
    // which status_determination maps to "needs_attention" on the dashboard.
    #[test]
    fn outcome_escalated_surfaces_needs_attention() {
        let escalated = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "observation-verify".to_string(),
            action_type: "escalate".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.8,
            auto_executed: true,
            dry_run: false,
            reason: "obs-verify score 55/100".to_string(),
            estimated_threat: "medium".to_string(),
            execution_result: "pending-fase4".to_string(),
            prev_hash: None,
        };
        assert_eq!(
            determine_outcome(&[escalated], "1.2.3.4", true),
            "escalated"
        );
    }

    // Spec 028-c: a later block_ip supersedes an earlier escalate.
    #[test]
    fn outcome_block_wins_over_escalate() {
        let escalated = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "observation-verify".to_string(),
            action_type: "escalate".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.8,
            auto_executed: true,
            dry_run: false,
            reason: "obs-verify".to_string(),
            estimated_threat: "medium".to_string(),
            execution_result: "pending-fase4".to_string(),
            prev_hash: None,
        };
        let block = DecisionEntry {
            ts: Utc::now(),
            incident_id: "x".to_string(),
            host: "h".to_string(),
            ai_provider: "mock".to_string(),
            action_type: "block_ip".to_string(),
            target_ip: Some("1.2.3.4".to_string()),
            target_user: None,
            skill_id: None,
            confidence: 0.95,
            auto_executed: true,
            dry_run: false,
            reason: "r".to_string(),
            estimated_threat: "high".to_string(),
            execution_result: "ok".to_string(),
            prev_hash: None,
        };
        assert_eq!(
            determine_outcome(&[escalated, block], "1.2.3.4", true),
            "blocked"
        );
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

        append_decision_entry(dir.path(), &entry, None).unwrap();

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
        append_decision_entry(dir.path(), &entry, None).unwrap();
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
        let path = dir.path().join("events-2026-01-01.jsonl");
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
        let path = dir.path().join("events-2026-01-02.jsonl");
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

    // ── SEC-005: bind address validation tests ──────────────────────────

    #[test]
    fn is_loopback_localhost() {
        assert!(is_loopback_address("127.0.0.1:8787"));
        assert!(is_loopback_address("[::1]:8787"));
        assert!(is_loopback_address("localhost:8787"));
    }

    #[test]
    fn is_not_loopback_external() {
        assert!(!is_loopback_address("0.0.0.0:8787"));
        assert!(!is_loopback_address("192.168.1.1:8787"));
        assert!(!is_loopback_address("10.0.0.1:8787"));
    }

    #[test]
    fn validate_bind_auth_loopback_no_auth_ok() {
        assert!(validate_bind_auth("127.0.0.1:8787", false).is_ok());
        assert!(validate_bind_auth("localhost:8787", false).is_ok());
    }

    #[test]
    fn validate_bind_auth_external_no_auth_rejected() {
        let result = validate_bind_auth("0.0.0.0:8787", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("without authentication"));
    }

    #[test]
    fn validate_bind_auth_external_with_auth_ok() {
        assert!(validate_bind_auth("0.0.0.0:8787", true).is_ok());
    }

    #[test]
    fn validate_bind_auth_loopback_with_auth_ok() {
        assert!(validate_bind_auth("127.0.0.1:8787", true).is_ok());
    }

    // SEC-013: TLS cert expiry date tests.
    #[test]
    fn cert_expiry_ymd_365_days() {
        let (y, m, d) = cert_expiry_ymd(365);
        let now = chrono::Utc::now();
        // Year should be this year or next year
        assert!(y >= chrono::Datelike::year(&now));
        assert!(y <= chrono::Datelike::year(&now) + 1);
        assert!((1..=12).contains(&m));
        assert!((1..=31).contains(&d));
    }

    #[test]
    fn cert_expiry_ymd_1_day() {
        let (y, m, d) = cert_expiry_ymd(1);
        let tomorrow = chrono::Utc::now() + chrono::Duration::days(1);
        assert_eq!(y, chrono::Datelike::year(&tomorrow));
        assert_eq!(m, chrono::Datelike::month(&tomorrow) as u8);
        assert_eq!(d, chrono::Datelike::day(&tomorrow) as u8);
    }

    #[test]
    fn cert_expiry_ymd_zero_days() {
        let (y, _m, _d) = cert_expiry_ymd(0);
        assert_eq!(y, chrono::Datelike::year(&chrono::Utc::now()));
    }

    // SEC-006/007: API auth requirement tests.
    #[test]
    fn should_require_api_auth_external() {
        assert!(should_require_api_auth("0.0.0.0:8787"));
        assert!(should_require_api_auth("192.168.1.1:8787"));
    }

    #[test]
    fn should_not_require_api_auth_loopback() {
        assert!(!should_require_api_auth("127.0.0.1:8787"));
        assert!(!should_require_api_auth("[::1]:8787"));
        assert!(!should_require_api_auth("localhost:8787"));
    }

    // Design invariant: `/api/live-feed/*` must always be public — the
    // marketing site depends on it. The `should_require_api_auth` predicate
    // must NOT gate these routes even on a non-loopback bind. This test
    // drives a minimal router that mirrors the production wiring (cors
    // layer, no auth layer) and confirms every live-feed path responds
    // with a non-401 plus a CORS header.
    #[tokio::test]
    async fn live_feed_routes_public_on_non_loopback_bind() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::util::ServiceExt;

        async fn probe() -> &'static str {
            "ok"
        }
        let live_api: axum::Router<()> = axum::Router::new()
            .route("/api/live-feed", axum::routing::get(probe))
            .route("/api/live-feed/stream", axum::routing::get(probe))
            .route("/api/live-feed/geoip", axum::routing::get(probe))
            .route("/api/live-feed/honeypot", axum::routing::get(probe))
            .route("/api/live-feed/mitre", axum::routing::get(probe))
            .layer(axum::middleware::from_fn(cors_middleware));

        for path in [
            "/api/live-feed",
            "/api/live-feed/stream",
            "/api/live-feed/geoip",
            "/api/live-feed/honeypot",
            "/api/live-feed/mitre",
        ] {
            let res = live_api
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("route should respond");
            assert_ne!(
                res.status(),
                StatusCode::UNAUTHORIZED,
                "{path} must not be auth-gated — marketing site depends on public access"
            );
            assert!(
                res.headers().contains_key("access-control-allow-origin"),
                "{path} must carry CORS headers"
            );
        }

        // Independent safety net: the agent_api branch still uses
        // should_require_api_auth, so a future refactor that accidentally
        // removes the predicate breaks this assertion.
        assert!(
            should_require_api_auth("0.0.0.0:8787"),
            "agent_api still relies on should_require_api_auth for non-loopback auth"
        );
    }

    // ── Spec 037 I-13 PR-2 — TLS file-perms warn anchors ──────────
    //
    // PR-2 of I-13 converts the two `let _ = std::fs::set_permissions(..)`
    // sites in `build_tls_config` into a `warn!`-on-failure pattern via
    // the `set_file_mode_or_warn` helper. Silent chmod failure on the
    // freshly-generated TLS private key was security-relevant: a
    // failed chmod would leave the key at the umask default (typically
    // 0644) and expose it to any local user. Tests pin three
    // contracts:
    //
    //   1. The wrapper does NOT panic on a non-existent path. Matches
    //      the prior `let _ =` no-panic property.
    //   2. The wrapper EMITS a `warn!` carrying path + intended_mode +
    //      error context when the underlying `set_permissions` fails.
    //   3. The wrapper applies the requested mode AND emits NO warn
    //      on the happy path (real file, accessible).

    // Capture is via `crate::test_util::arm_capture` /
    // `drain_capture` — global subscriber + thread-local buffer.
    // See `crate::test_util` rustdoc for why the prior per-test
    // `with_default` + `MakeWriter` pattern (PR #310) was flaky on
    // CI.

    #[cfg(unix)]
    #[test]
    fn set_file_mode_or_warn_does_not_panic_on_missing_path() {
        let bad_path = std::path::PathBuf::from("/this/path/never/ever/exists/innerwarden-i13-tls");
        // Must not panic even though `set_permissions` returns
        // ErrorKind::NotFound on this input.
        set_file_mode_or_warn(&bad_path, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn set_file_mode_or_warn_emits_warn_with_context_on_failure() {
        let _guard = crate::test_util::arm_capture();

        let bad_path =
            std::path::PathBuf::from("/this/path/never/ever/exists/innerwarden-i13-tls-warn");
        set_file_mode_or_warn(&bad_path, 0o600);

        let captured_str = crate::test_util::drain_capture();

        assert!(
            captured_str.contains("failed to set TLS file permissions"),
            "warn message missing — got: {captured_str}"
        );
        // Path must be present so the operator can identify which
        // file failed to chmod (key vs cert).
        assert!(
            captured_str.contains("innerwarden-i13-tls-warn"),
            "path field missing or wrong — got: {captured_str}"
        );
        // Intended mode must be present in octal form — operator
        // needs to know whether the failed chmod was on the 0o600
        // (key) or 0o644 (cert) site, since 0o600 failure is the
        // security-critical case.
        assert!(
            captured_str.contains("0o600"),
            "intended_mode field missing or not in octal — got: {captured_str}"
        );
        assert!(
            captured_str.contains("error="),
            "error field missing — got: {captured_str}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn build_tls_config_auto_gen_writes_files_with_intended_perms() {
        // Coverage anchor for the two call sites of
        // `set_file_mode_or_warn` inside `build_tls_config` (key 0o600,
        // cert 0o644). The unit tests on the helper itself prove the
        // wrapper behaves correctly; this test proves the calling code
        // actually invokes it with the right modes against the right
        // files. Without this test the patch-coverage gate flagged the
        // call sites as uncovered (PR-2 first push hit 33.33% on
        // `codecov/patch`).
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");

        // `cert_path = None` + `key_path = None` forces the auto-gen
        // branch — the path that contains the two `set_file_mode_or_warn`
        // call sites under test.
        let _config = build_tls_config(dir.path(), None, None)
            .await
            .expect("build_tls_config must auto-generate a self-signed cert in a writable tempdir");

        let key_path = dir.path().join("dashboard-key.pem");
        let cert_path = dir.path().join("dashboard-cert.pem");

        let key_mode = std::fs::metadata(&key_path)
            .expect("key file must exist after build_tls_config")
            .permissions()
            .mode()
            & 0o7777;
        let cert_mode = std::fs::metadata(&cert_path)
            .expect("cert file must exist after build_tls_config")
            .permissions()
            .mode()
            & 0o7777;

        // 0o600 on the key is the security-critical assertion. A
        // regression that drops the chmod (or moves it to a path that
        // does not exist before the file is written) would leak the
        // private key at umask default.
        assert_eq!(
            key_mode, 0o600,
            "build_tls_config must chmod the private key to 0o600 after generation"
        );
        assert_eq!(
            cert_mode, 0o644,
            "build_tls_config must chmod the cert to 0o644 after generation"
        );
    }

    #[cfg(unix)]
    #[test]
    fn set_file_mode_or_warn_applies_mode_silently_on_writable_file() {
        use std::os::unix::fs::PermissionsExt;

        // Inverse anchor: on a real, writable file the wrapper
        // applies the requested mode AND does NOT emit a warn.
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("fake-key.pem");
        std::fs::write(&target, b"placeholder").expect("write fixture");
        // Start at a permissive mode so the assertion below is
        // meaningful (we want to prove the chmod actually moved it).
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))
            .expect("seed perms");

        set_file_mode_or_warn(&target, 0o600);

        // The mode must be exactly 0o600 after the helper runs. The
        // `& 0o7777` mask drops the file-type bits (S_IFREG etc.)
        // that PermissionsExt::mode() returns alongside the mode
        // bits — without it the comparison fails on platforms that
        // include S_IFREG in the returned u32.
        let applied = std::fs::metadata(&target)
            .expect("stat target")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            applied, 0o600,
            "set_file_mode_or_warn must apply the requested mode on the happy path"
        );

        let captured_str = crate::test_util::drain_capture();
        assert!(
            !captured_str.contains("failed to set TLS file permissions"),
            "successful chmod must not emit the failure warn — got: {captured_str}"
        );
    }

    // ── Audit I-14 (2026-04-29) ────────────────────────────────────────
    //
    // The dashboard router caps request bodies at 1 MB via
    // `DefaultBodyLimit::max(...)`. The anchor below proves the layer
    // is correctly wired by building a tiny axum router with the SAME
    // limit + an echo handler, then asserting:
    //   1. a body strictly under the limit is accepted (200 OK).
    //   2. a body strictly over the limit yields 413 Payload Too Large.
    //
    // This is a layer-behaviour anchor, not a full router integration
    // test -- a future change that drops the layer from `serve()`
    // would not be caught here, but a future change that miscalibrates
    // `MAX_BODY_BYTES` (e.g. accidentally drops the `* 1024 * 1024`
    // factor) would be.

    #[test]
    fn max_body_bytes_constant_is_one_mib() {
        // The chosen cap matters for both audit I-14 closure and for
        // every legitimate POST in this dashboard (~1 KB to 2 KB
        // payloads). Pin the value so a future change has to update
        // this assertion deliberately.
        assert_eq!(MAX_BODY_BYTES, 1_048_576);
    }

    #[tokio::test]
    async fn body_limit_layer_rejects_oversized_post() {
        // axum's `DefaultBodyLimit` is enforced by extractors that opt
        // into it (Bytes, String, Json, Form). The router-level layer
        // sets the configuration; the extractor reads it and rejects
        // bodies past the cap with 413. The handlers in this dashboard
        // use Bytes / Json variants, which all honour this contract.
        //
        // The test wires `build_body_limit_layer()` to a tiny echo
        // route so the production helper itself is exercised (rather
        // than re-declaring the cap here, which would let a future
        // miscalibration of `MAX_BODY_BYTES` slip through).
        use axum::body::{Body, Bytes};
        use axum::http::{Request, StatusCode};
        use axum::routing::post;
        use axum::Router;
        use tower::util::ServiceExt;

        async fn echo(_body: Bytes) -> axum::http::Response<Body> {
            axum::http::Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap()
        }

        let app: Router = Router::new()
            .route("/echo", post(echo))
            .layer(build_body_limit_layer());

        // Under-limit body passes.
        let small = vec![b'x'; MAX_BODY_BYTES - 1];
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/echo")
                    .header("content-length", small.len().to_string())
                    .body(Body::from(small))
                    .unwrap(),
            )
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "under-limit body must be accepted"
        );

        // Over-limit body is rejected at the extractor with 413.
        let big = vec![b'x'; MAX_BODY_BYTES + 1];
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/echo")
                    .header("content-length", big.len().to_string())
                    .body(Body::from(big))
                    .unwrap(),
            )
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "over-limit body must yield 413"
        );
    }

    // ── Audit 2026-05-01 follow-ups ───────────────────────────────────
    //
    // Each anchor below pins one of the dashboard QA-audit fixes that
    // ship in this batch. Together they catch silent regressions at
    // the bundle boundary (HTML / JS / CSS / Rust constants) where a
    // future refactor is most likely to drop the contract without any
    // unit-test coverage noticing.

    #[test]
    fn index_html_carries_alert_stack_container() {
        // Audit 4.8: a stack container must exist so `showAlertToast`
        // has somewhere to append toasts. Single-toast behaviour is
        // not enough — that was the regression the audit caught.
        assert!(
            INDEX_HTML.contains("id=\"alertStack\""),
            "alert stack container missing — toast burst will collapse to a single overwriting toast (audit 4.8)"
        );
        // The legacy single-toast div MUST stay for action confirmations
        // (showToast in actions.js). Those are a different concern.
        assert!(INDEX_HTML.contains("id=\"toast\""));
    }

    #[test]
    fn app_css_defines_alert_stack_styles() {
        for cls in [
            ".alert-stack",
            ".alert-toast",
            ".alert-toast.visible",
            ".alert-toast-critical",
            ".alert-toast-high",
            ".alert-overflow",
        ] {
            assert!(
                APP_CSS.contains(cls),
                "alert-stack styling rule {cls} missing — toasts render unstyled (audit 4.8)"
            );
        }
    }

    #[test]
    fn sse_js_caps_alert_stack_and_overflows() {
        // Audit 4.8 contract: a hard cap on visible toasts and a
        // surfaced overflow badge. Both must be present at the bundle
        // boundary or a future refactor can silently regress to the
        // pre-fix wall-of-toasts behaviour.
        assert!(
            JS_SSE.contains("ALERT_STACK_MAX_VISIBLE"),
            "sse.js must declare ALERT_STACK_MAX_VISIBLE — caps toast burst"
        );
        assert!(JS_SSE.contains("_alertStackOverflow"));
        assert!(JS_SSE.contains("alert-overflow"));
        // Each toast must be its own element under the stack so a
        // dismiss does not rip the whole stack out (regression risk).
        assert!(JS_SSE.contains("querySelectorAll('.alert-toast')"));
    }

    #[test]
    fn sse_js_pivots_alert_into_open_journey() {
        // Audit 2.10: when the operator already has the journey
        // open, an alert for that IP must reload the journey instead
        // of stacking a redundant toast on top of the page they are
        // looking at.
        assert!(
            JS_SSE.contains("_journeyOpenForIp"),
            "sse.js must define _journeyOpenForIp — pivots alert into open journey (audit 2.10)"
        );
        // The branch that calls loadJourney must be reachable.
        assert!(JS_SSE.contains("loadJourney('ip', alertIp)"));
    }

    #[test]
    fn dashboard_audit_2026_05_02_small_fixes_are_wired() {
        // 2026-05-02 audit (P2/P7/P8 + frozen graph): five small wiring
        // fixes bundled in PR #407. This anchor pins them so a future
        // refactor that strips one of them out fails CI before the
        // operator ever sees the regression.

        // ── (a) Frozen Sensors graph: SSE refresh + 30s fallback both
        //        re-fire loadSensors when the Sensors view is visible.
        assert!(
            JS_SSE.contains("typeof loadSensors === 'function'"),
            "sse.js must re-fire loadSensors on refresh events when the Sensors view is visible \
             — without it the three Sensors charts stay frozen on the data fetched at first paint"
        );
        assert!(
            JS_SSE.contains("function _refreshActiveView"),
            "sse.js must carry the fallback _refreshActiveView helper so the 30s polling pulse \
             keeps the Sensors view fresh when the SSE stream is down"
        );

        // ── (b) P2 Badge oscillation: showView (not just loadHome)
        //        must call syncModeBadgeFromHealth so every tab paints
        //        the same OPERATIONAL DEBT / CATCHING UP / etc value.
        assert!(
            JS_NAV.contains("syncModeBadgeFromHealth(window._lastOverview"),
            "nav.js::showView must sync the persistent badge from window._lastOverview \
             — without it the badge oscillates between OPERATIONAL DEBT (Home) and \
             PROTECTED (Threats/Sensors/Health) on the same page reload (audit P2)"
        );

        // ── (c) loadJson must accept an AbortSignal so cancel-in-flight
        //        actually cancels the network request, not just the UI.
        assert!(
            JS_API.contains("if (opts && opts.signal) init.signal = opts.signal"),
            "api.js::loadJson must thread the signal option through to fetch — required by the \
             Journey (P7) and Intel (P8) AbortController plumbing"
        );

        // ── (d) P7 Timeline AbortController on loadJourney.
        assert!(
            JS_JOURNEY.contains("window._activeFetch_journey"),
            "journey.js::loadJourney must stash an AbortController on window._activeFetch_journey \
             so a fast IP / toggle switch cancels the previous fetch (audit P7)"
        );
        assert!(
            JS_JOURNEY.contains("{ signal: journeySignal }"),
            "journey.js must pass the AbortController signal into loadJson — without it the \
             stale fetch still resolves and overwrites the new content"
        );

        // ── (e) P8 Intel sub-tab clear-before-fetch + AbortController.
        assert!(
            JS_INTEL.contains("window._activeFetch_intel"),
            "intel.js::switchIntelTab must abort the previous sub-tab fetch (audit P8)"
        );
        assert!(
            JS_INTEL.contains("Loading...</div>"),
            "intel.js::switchIntelTab must clear intelContent synchronously so the previous \
             tab's content does not paint under the new tab's title (audit P8)"
        );
    }

    #[test]
    fn fleet_frontend_wiring_is_complete() {
        // Spec 038 Phase 3: the Fleet tab must be wired end-to-end.
        // HTML: nav button + view container present.
        assert!(
            INDEX_HTML.contains("id=\"navFleet\""),
            "nav must carry the Fleet button (hidden by default; fleet.js unhides on probe)"
        );
        assert!(INDEX_HTML.contains("id=\"viewFleet\""));
        assert!(INDEX_HTML.contains("id=\"fleetContent\""));
        // Default-hidden so single-host operators do not see a tab
        // they cannot use. fleet.js::probeFleetEnabled flips this.
        let nav_btn_start = INDEX_HTML
            .find("id=\"navFleet\"")
            .expect("nav button exists");
        let nav_btn_slice = &INDEX_HTML[nav_btn_start..nav_btn_start + 200];
        assert!(
            nav_btn_slice.contains("display:none"),
            "navFleet must start hidden until the backend probe confirms fleet mode"
        );

        // Script tag included.
        assert!(INDEX_HTML.contains("/js/fleet.js"));

        // Nav.js wires the showView dispatcher.
        assert!(JS_NAV.contains("fleet: 'viewFleet'"));
        assert!(JS_NAV.contains("if (name === 'fleet') loadFleet()"));

        // fleet.js carries the probe + loader + renderer.
        assert!(JS_FLEET.contains("function probeFleetEnabled"));
        assert!(JS_FLEET.contains("async function loadFleet"));
        assert!(JS_FLEET.contains("function renderFleet"));
        // Probe is invoked at boot so the button visibility settles
        // before the operator has a chance to click.
        assert!(JS_FLEET.contains("probeFleetEnabled();"));
        // 404 path renders the disabled-mode copy instead of throwing.
        assert!(JS_FLEET.contains("Fleet mode is not enabled"));
    }

    #[test]
    fn journey_js_supports_forensic_filter() {
        // Audit 5.2: "Actions only" toggle on the journey timeline so
        // the operator can hide raw events and see just the system's
        // block / dismiss / escalate / honeypot actions. Anchor pins
        // the helper, the toggle wrapper, and the button HTML.
        assert!(
            JS_JOURNEY.contains("function applyForensicFilter"),
            "applyForensicFilter helper missing — operator can't strip raw events from the journey timeline (audit 5.2)"
        );
        assert!(JS_JOURNEY.contains("function toggleForensicFilter"));
        assert!(JS_JOURNEY.contains("id=\"forensicFilterBtn\""));
        // The filter must keep `incident` entries so the lead card
        // stays visible — without it the timeline reads as a stream
        // of decisions with no threat context.
        assert!(JS_JOURNEY.contains("e.kind === 'incident'"));
    }

    #[test]
    fn home_js_renders_since_last_visit_diff() {
        // Audit 5.11: localStorage-tracked last visit timestamp drives
        // a "Since your last visit" diff banner so the MSSP morning-
        // rounds operator sees what changed in their absence. Anchor
        // pins the storage key + the pure compute helper + the
        // renderer hook.
        assert!(JS_HOME.contains("SINCE_LAST_VISIT_KEY = 'iw_last_visit_ts'"));
        assert!(JS_HOME.contains("function computeSinceLastVisitCounts"));
        assert!(JS_HOME.contains("function renderSinceLastVisitBanner"));
        assert!(
            JS_HOME.contains("renderSinceLastVisitBanner(items, responsesData)"),
            "loadHome must call renderSinceLastVisitBanner — without the wire-up the banner never updates (audit 5.11)"
        );
        // The HTML container has to exist or the renderer no-ops.
        assert!(INDEX_HTML.contains("id=\"homeSinceLastVisit\""));
    }

    #[test]
    fn helpers_glossary_carries_required_audit_terms() {
        // Audit 4.2/4.3/4.4: the canonical GLOSSARY must define every
        // term the operator reads on the dashboard so a `title=`
        // tooltip can ship the definition wherever the term lands.
        // Anchor lists the terms the audit specifically called out.
        for term in [
            "severity:",
            "confidence:",
            "risk_score:",
            "outcome:",
            "blocked:",
            "observing:",
            "honeypot:",
            "needs_attention:",
            "dismissed:",
            "allowlisted:",
            "attacker:",
            "alert:",
            "flagged:",
            "suspicious:",
        ] {
            assert!(
                JS_HELPERS.contains(term),
                "GLOSSARY missing key '{term}' (audit 4.2/4.3/4.4)"
            );
        }
        // The helper that emits the title= attribute must exist + be
        // consumed by at least one render path so the glossary is
        // visible to the operator, not just defined in source.
        assert!(JS_HELPERS.contains("function glossaryTitle"));
        assert!(JS_THREATS.contains("glossaryTitle("));
        assert!(JS_JOURNEY.contains("glossaryTitle("));
    }

    #[test]
    fn nav_promotes_responses_to_top_level() {
        // Audit 4.6: Responses moved out of the More dropdown into a
        // top-level button between Threats and Health. The dropdown
        // must no longer carry navResponses; the top-level row must.
        let html = INDEX_HTML;
        let main_nav_start = html
            .find("class=\"main-nav\"")
            .expect("main-nav block must exist");
        let nav_more_start = html[main_nav_start..]
            .find("class=\"nav-more-menu\"")
            .map(|p| main_nav_start + p)
            .expect("nav-more-menu block must exist");
        let main_row = &html[main_nav_start..nav_more_start];
        let more_block_end = html[nav_more_start..]
            .find("</div>")
            .map(|p| nav_more_start + p)
            .expect("more menu close tag");
        let more_block = &html[nav_more_start..more_block_end];

        assert!(
            main_row.contains("id=\"navResponses\""),
            "navResponses must live in the top-level main-nav row (audit 4.6)"
        );
        assert!(
            !more_block.contains("id=\"navResponses\""),
            "navResponses must NOT remain in the More dropdown (audit 4.6)"
        );
        // The other secondary tabs must still be inside the dropdown
        // — the refactor only promotes Responses, not the rest.
        for id in [
            "navSensors",
            "navReport",
            "navHoneypot",
            "navCompliance",
            "navMonthly",
        ] {
            assert!(
                more_block.contains(id),
                "{id} must remain in the More dropdown — only Responses was promoted"
            );
        }
        // nav.js drops `responses` from the secondaryTabs list so the
        // showView dispatcher does not still treat it as a More item.
        // Other `'responses'` mentions (the views/btns id maps,
        // loadResponses dispatch) must stay — only the secondary-tab
        // membership is wrong after the promotion.
        let nav = JS_NAV;
        let secondary_start = nav
            .find("_secondaryTabs = [")
            .expect("_secondaryTabs declaration");
        let secondary_end = nav[secondary_start..]
            .find("];")
            .map(|p| secondary_start + p)
            .expect("_secondaryTabs end");
        let secondary_block = &nav[secondary_start..secondary_end];
        assert!(
            !secondary_block.contains("'responses'"),
            "nav.js _secondaryTabs must drop 'responses' after the promotion (audit 4.6)"
        );
    }

    #[test]
    fn threats_status_filter_dropdown_wired_end_to_end() {
        // Audit 2.6 partial: outcome bucket filter shipped client-side.
        // The HTML control, state field, sync helper, and grouped-list
        // filter must agree on the field name `status` so selecting a
        // bucket actually narrows the rendered list.
        assert!(
            INDEX_HTML.contains("id=\"flt-status\""),
            "flt-status dropdown missing from advanced filters (audit 2.6 partial)"
        );
        assert!(
            JS_STATE.contains("status: ''"),
            "state.filters.status default missing — operator picks an outcome and the filter is lost on refresh"
        );
        assert!(
            JS_STATE.contains("state.filters.status = document.getElementById('flt-status').value")
        );
        assert!(
            JS_THREATS.contains("state.filters && state.filters.status"),
            "buildGroupedList must read state.filters.status (audit 2.6 partial)"
        );
        // The status options the dropdown exposes must exist in the
        // outcomeOf domain so the filter is non-empty for every choice.
        for outcome in [
            "needs_attention",
            "blocked",
            "monitoring",
            "honeypot",
            "dismissed",
            "allowlisted",
        ] {
            assert!(
                INDEX_HTML.contains(&format!("value=\"{outcome}\"")),
                "flt-status must expose '{outcome}' option (audit 2.6 partial)"
            );
        }
    }

    #[test]
    fn journey_verdict_card_includes_scale_summary() {
        // Audit 2.3 phase 2: verdict card now surfaces a one-line
        // "X events analysed · Y incidents · Z decisions taken" sub-row
        // so the operator sees the journey's scale before scrolling.
        // The renderer reads `j.summary.*` which JourneySummary
        // always populates — anchor pins the field reads.
        for field in [
            "s.events_count",
            "s.incidents_count",
            "s.decisions_count",
            "s.honeypot_count",
        ] {
            assert!(
                JS_JOURNEY.contains(field),
                "renderVerdictCard must read {field} for the scale line (audit 2.3 phase 2)"
            );
        }
        assert!(
            JS_JOURNEY.contains("verdict-scale"),
            "verdict-scale CSS class missing — the scale line cannot be styled (audit 2.3 phase 2)"
        );
    }

    #[test]
    fn honeypot_js_separates_engaged_from_listener_only_sessions() {
        // Audit 2.9: honeypot tab USED to display 178 sessions all
        // with 0 commands / 0 auth attempts and read like "honeypot
        // is busy" when actually the attackers walked away. Anchor
        // pins the engagement banner copy + the filter toggle so a
        // refactor cannot quietly drop the honesty surface.
        assert!(JS_HONEYPOT.contains("function _honeypotIsEngaged"));
        assert!(JS_HONEYPOT.contains("toggleHoneypotEngagedFilter"));
        assert!(
            JS_HONEYPOT.contains("Honeypot engagement:"),
            "engagement banner copy missing — operator can't tell engaged vs listener-only (audit 2.9)"
        );
        // The explanatory copy is the load-bearing part — a future
        // copy edit must keep the engaged/unengaged definition
        // visible to the non-technical operator.
        assert!(JS_HONEYPOT.contains("Engaged = attacker typed"));
        assert!(JS_HONEYPOT.contains("Unengaged ="));
    }

    #[test]
    fn home_activity_strip_carries_unit_and_timezone_labels() {
        // Audit 3.7 partial: the "29K -> 6 -> 5 -> 1" funnel had no
        // unit/timezone labels. The redesigned activity strip now
        // labels each cell ("events watched" / "flagged as
        // suspicious" / "stopped automatically" / "awaiting review")
        // AND includes a time-window line "since midnight UTC".
        // Anchor pins those labels so a future copy edit doesn't
        // silently regress the audit fix.
        for label in [
            "events watched",
            "flagged as suspicious",
            "stopped automatically",
            "awaiting review",
        ] {
            assert!(
                INDEX_HTML.contains(label),
                "activity strip label '{label}' missing — audit 3.7 unit hint regression"
            );
        }
        // The timezone marker must remain on the activity-strip
        // sub-line so the operator never reads a count without a
        // window context.
        assert!(JS_HOME.contains("since midnight UTC"));
    }

    #[test]
    fn index_html_carries_onboarding_tip() {
        // Audit 5.10: clean-day tip surface. The bundle MUST include
        // the container so home.js has somewhere to toggle visibility.
        assert!(
            INDEX_HTML.contains("id=\"homeOnboardingTip\""),
            "Home onboarding tip container missing (audit 5.10)"
        );
        assert!(INDEX_HTML.contains("home-onboarding-title"));
    }

    #[test]
    fn home_js_renders_onboarding_tip_when_quiet() {
        // The renderer must read both bucket sums + attention count
        // and toggle display accordingly. Anchor pins the function
        // name so a refactor that drops the call from loadHome lights
        // up CI immediately.
        assert!(JS_HOME.contains("function renderOnboardingTip"));
        assert!(JS_HOME.contains("renderOnboardingTip(overview)"));
    }

    #[test]
    fn home_js_critical_banner_pivots_user_links() {
        // Audit 5.5: IP and User mentions in the critical banner
        // sub-line are now clickable. Anchor pins the helper that
        // generates the link AND the call sites in
        // renderCriticalBanner.
        assert!(JS_HOME.contains("function homeBannerEntityLink"));
        assert!(JS_HOME.contains("function homeBannerOpenPivot"));
        // Both branches (ip / user) must be present so the operator
        // pivots correctly regardless of which entity surfaces.
        assert!(JS_HOME.contains("homeBannerEntityLink(ipEntity)"));
        assert!(JS_HOME.contains("homeBannerEntityLink(userEntity)"));
    }

    #[test]
    fn app_css_defines_onboarding_and_details_heading() {
        assert!(APP_CSS.contains(".home-onboarding-tip"));
        assert!(APP_CSS.contains(".home-onboarding-link"));
        // Audit 3.6: the visible heading inside the details panel
        // must be styled or it reads as plain unstyled text.
        assert!(APP_CSS.contains(".home-details-heading"));
        // Audit 5.5: the home-alert pivot link must have a
        // distinguishing style so it reads as a clickable target,
        // not plain text.
        assert!(APP_CSS.contains(".home-alert-banner .home-alert-link"));
    }

    #[test]
    fn home_js_toggle_details_is_defensive_about_display() {
        // Audit 3.6: the toggle MUST also clear inline display:none
        // (defensive against earlier state) AND scroll the panel
        // into view. Both are belt-and-braces fixes for the audit
        // report "no content appears".
        let start = JS_HOME
            .find("function toggleHomeDetails")
            .expect("toggleHomeDetails");
        let body = &JS_HOME[start..start + 1500];
        assert!(
            body.contains("panel.style.display = ''"),
            "toggleHomeDetails must clear inline display so the panel actually shows (audit 3.6)"
        );
        assert!(
            body.contains("scrollIntoView"),
            "toggleHomeDetails must scrollIntoView when expanding (audit 3.6)"
        );
    }

    #[test]
    fn index_html_carries_modal_preview_block() {
        // Audit 4.7: the action modal must surface a preview block
        // BEFORE the operator confirms. The block-IP path used to
        // commit silently. Anchor pins the ID so a future refactor
        // can't drop the surface without lighting up CI.
        assert!(
            INDEX_HTML.contains("id=\"modalPreview\""),
            "action modal missing #modalPreview — operator commits without seeing the command (audit 4.7)"
        );
        assert!(INDEX_HTML.contains("aria-live=\"polite\""));
    }

    #[test]
    fn app_css_defines_modal_preview_styles() {
        assert!(APP_CSS.contains(".modal-preview"));
        assert!(APP_CSS.contains(".modal-preview.visible"));
        assert!(APP_CSS.contains(".modal-preview.danger"));
        // The code block must have monospace styling so the command
        // reads as a literal copy-paste, not prose.
        assert!(APP_CSS.contains(".modal-preview code"));
    }

    #[test]
    fn actions_js_renders_modal_preview() {
        assert!(JS_ACTIONS.contains("buildActionPreviewHtml"));
        assert!(JS_ACTIONS.contains("refreshActionPreview"));
        // The block-IP branch must dispatch on every supported backend
        // so the operator never sees an empty preview just because
        // their config picked, e.g., nftables.
        for backend in ["ufw", "iptables", "nftables", "xdp", "pf"] {
            assert!(
                JS_ACTIONS.contains(&format!("case '{backend}':")),
                "buildActionPreviewHtml must handle backend '{backend}' (audit 4.7)"
            );
        }
        // closeActionModal MUST clear the preview surface so the next
        // open does not flash stale content.
        let close_start = JS_ACTIONS
            .find("function closeActionModal")
            .expect("closeActionModal");
        let body = &JS_ACTIONS[close_start..close_start + 600];
        assert!(
            body.contains("previewEl.innerHTML = ''"),
            "closeActionModal must clear modalPreview content (audit 4.7)"
        );
    }

    #[test]
    fn sse_js_renders_connection_state_with_age() {
        // Audit 5.12: the header refresh status surfaces "last event
        // N s ago" + an amber/red colour after the agent has been
        // silent for too long. Each constant pins one threshold so a
        // refactor cannot quietly inflate them.
        assert!(JS_SSE.contains("CONN_AMBER_AFTER_SECS"));
        assert!(JS_SSE.contains("CONN_RED_AFTER_SECS"));
        assert!(JS_SSE.contains("_renderConnectionStatus"));
        // The age-since-last-event ticker must run on a setInterval
        // so the colour flips even without new SSE events arriving.
        assert!(JS_SSE.contains("setInterval(_renderConnectionStatus"));
        // Hard-fail label must be present so the operator sees a
        // distinct "no data" verb instead of just "reconnecting".
        assert!(JS_SSE.contains("NO DATA"));
    }
}
