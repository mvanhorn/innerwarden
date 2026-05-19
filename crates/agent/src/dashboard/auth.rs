// Auto-extracted from mod.rs — dashboard auth handlers

use super::*;
use rand_core::OsRng;
use std::sync::atomic::{AtomicI64, Ordering};

/// Write an admin-action audit entry, surfacing failures via `warn!`
/// with structured context. Replaces the prior `let _ =
/// append_admin_action(..)` pattern at the two login/logout sites
/// (Spec 037 I-13 PR-1) so that a write failure (canonicalize error,
/// flock failure, disk full, FS read-only) leaves a forensic record
/// instead of silently dropping the audit row.
///
/// Audit-trail integrity is compliance-relevant: the dashboard
/// `/api/compliance` surface advertises "admin actions audit trail"
/// as a control. A silently-dropped row breaks the contract without
/// any operator-visible signal. The warn is the minimum viable
/// signal — the row is still lost, but at least the loss is
/// recorded in the agent log + journald.
///
/// Function is intentionally non-async and infallible (returns `()`):
/// the calling handlers continue regardless of audit-write outcome
/// (same observable behaviour as the prior `let _ =`).
fn write_admin_audit_or_warn(data_dir: &std::path::Path, entry: &mut AdminActionEntry) {
    if let Err(e) = append_admin_action(data_dir, entry) {
        warn!(
            operator = %entry.operator,
            action = %entry.action,
            target = %entry.target,
            error = %e,
            "audit trail write failed (admin action lost)"
        );
    }
}

pub fn generate_password_hash_interactive() -> Result<()> {
    let password =
        rpassword::prompt_password("Dashboard password (input hidden): ").context("read failed")?;
    let confirm =
        rpassword::prompt_password("Confirm password: ").context("confirm read failed")?;
    if password != confirm {
        anyhow::bail!("password confirmation does not match");
    }
    if password.len() < 16 {
        warn!("dashboard password is shorter than 16 characters; consider a stronger secret");
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| anyhow::anyhow!("failed to generate argon2 hash"))?
        .to_string();
    println!("{hash}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Auth middleware + login rate limiting
// ---------------------------------------------------------------------------

/// Maximum failed login attempts before an IP is temporarily blocked.
pub(super) const LOGIN_RATE_LIMIT_MAX_ATTEMPTS: usize = 5;
/// Window (in seconds) for counting failed attempts AND the block duration.
pub(super) const LOGIN_RATE_LIMIT_WINDOW_SECS: u64 = 15 * 60; // 15 minutes

/// Global rate-limiter: maps source IP string → list of failed-login timestamps.
pub(super) static LOGIN_RATE_LIMITER: LazyLock<Mutex<HashMap<String, Vec<std::time::Instant>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// ---------------------------------------------------------------------------
// Global request rate limiter - prevents memory exhaustion from bot traffic
// ---------------------------------------------------------------------------

/// Max requests per IP per minute before returning 429.
/// Dashboard SPA makes ~6 parallel requests per page load + SSE refreshes.
pub(super) const GLOBAL_RATE_LIMIT_PER_MIN: usize = 300;

/// Global request rate limiter: maps IP → ring of timestamps.
/// Pruned lazily; entries older than 60s are ignored in count.
pub(super) static GLOBAL_RATE_LIMITER: LazyLock<Mutex<HashMap<String, Vec<std::time::Instant>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Check if an IP exceeds the global request rate limit. Records the request.
pub(super) fn global_rate_check(ip: &str) -> bool {
    let mut map = GLOBAL_RATE_LIMITER
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let cutoff = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(60))
        .unwrap_or_else(std::time::Instant::now);

    // Prune stale IPs periodically (when map grows large)
    if map.len() > 1000 {
        map.retain(|_, v| {
            v.retain(|t| *t > cutoff);
            !v.is_empty()
        });
    }

    let timestamps = map.entry(ip.to_string()).or_default();
    timestamps.retain(|t| *t > cutoff);
    timestamps.push(std::time::Instant::now());
    timestamps.len() > GLOBAL_RATE_LIMIT_PER_MIN
}

/// Extract a client IP string from the request.
/// Checks `X-Forwarded-For` and `X-Real-IP` headers first (reverse-proxy scenario),
/// then falls back to the socket peer address injected by `axum::serve`.
pub(super) fn extract_client_ip(req: &Request<Body>, trusted_proxies: &[IpAddr]) -> String {
    // Determine the raw connection IP first (socket peer from ConnectInfo).
    let conn_ip: Option<IpAddr> = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    // Only honour proxy headers when the connecting IP is a trusted proxy.
    let from_trusted_proxy = conn_ip
        .map(|ip| trusted_proxies.contains(&ip))
        .unwrap_or(false);

    if from_trusted_proxy {
        // X-Forwarded-For: first entry is the original client
        if let Some(val) = req.headers().get("x-forwarded-for") {
            if let Ok(s) = val.to_str() {
                if let Some(first) = s.split(',').next() {
                    let trimmed = first.trim();
                    if !trimmed.is_empty() {
                        return trimmed.to_string();
                    }
                }
            }
        }
        // X-Real-IP
        if let Some(val) = req.headers().get("x-real-ip") {
            if let Ok(s) = val.to_str() {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }

    // Fallback: socket peer address from axum::serve ConnectInfo
    if let Some(ip) = conn_ip {
        return ip.to_string();
    }
    "unknown".to_string()
}

/// Check whether `ip` is currently rate-limited and, if not, record a failed attempt.
/// Returns `true` if the IP should be blocked (too many recent failures).
pub(super) fn check_and_record_failed_login(ip: &str) -> bool {
    let mut map = LOGIN_RATE_LIMITER.lock().unwrap_or_else(|e| e.into_inner());
    let cutoff = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(LOGIN_RATE_LIMIT_WINDOW_SECS))
        .unwrap_or_else(std::time::Instant::now);

    let attempts = map.entry(ip.to_string()).or_default();
    // Purge old entries outside the window
    attempts.retain(|t| *t > cutoff);

    if attempts.len() >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS {
        return true; // already rate-limited
    }
    attempts.push(std::time::Instant::now());
    attempts.len() >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS
}

/// Returns `true` if `ip` is currently rate-limited (without recording a new attempt).
pub(super) fn is_rate_limited(ip: &str) -> bool {
    let map = LOGIN_RATE_LIMITER.lock().unwrap_or_else(|e| e.into_inner());
    let cutoff = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(LOGIN_RATE_LIMIT_WINDOW_SECS))
        .unwrap_or_else(std::time::Instant::now);
    if let Some(attempts) = map.get(ip) {
        let recent = attempts.iter().filter(|t| **t > cutoff).count();
        recent >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS
    } else {
        false
    }
}

/// Clear the rate-limit record for an IP (called on successful login).
pub(super) fn clear_rate_limit(ip: &str) {
    let mut map = LOGIN_RATE_LIMITER.lock().unwrap_or_else(|e| e.into_inner());
    map.remove(ip);
}

/// Pure check: should this request bypass the auth wall because it
/// arrived from the local loopback interface?
///
/// Wave 2026-05-17 fix: prior to this, the `agent_api` router was
/// either fully auth-walled or fully open based on the **bind**
/// address. Hosts that bound the dashboard to `0.0.0.0` (so the
/// operator could browse it from outside) had `sudo innerwarden agent
/// connect` blocked by the same 401 wall the browser had to clear —
/// even though the CLI runs as root on the same host and reaches the
/// dashboard via 127.0.0.1.
///
/// The right model is per-request: if the actual TCP peer IP is
/// loopback (127.0.0.1 or ::1), the caller is on the box already and
/// has root via the sudo wrapper — auth would be friction without
/// security gain. If the peer is a real remote IP, auth still
/// applies.
///
/// Critical detail: this MUST use the socket peer IP from
/// `ConnectInfo<SocketAddr>`, NOT the value of `extract_client_ip`.
/// `extract_client_ip` honours `X-Forwarded-For` / `X-Real-IP` when
/// the request arrives from a trusted proxy — a remote attacker behind
/// a misconfigured proxy that forwards `X-Forwarded-For: 127.0.0.1`
/// must NOT bypass auth.
pub(super) fn is_loopback_request(req: &Request<Body>) -> bool {
    let Some(conn_info) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
    else {
        // No ConnectInfo means the server forgot to wire
        // `into_make_service_with_connect_info` — fail SAFE
        // (no bypass).
        return false;
    };
    conn_info.0.ip().is_loopback()
}

/// Auth middleware variant that bypasses the wall for loopback
/// requests and otherwise delegates to `require_auth`. Used by the
/// `agent_api` router so `sudo innerwarden agent connect` (always
/// loopback) works without dashboard credentials even on hosts that
/// bind the dashboard publicly.
#[allow(clippy::type_complexity)]
pub(super) async fn loopback_bypass_or_require_auth(
    state: State<(
        Option<DashboardAuth>,
        Arc<Vec<IpAddr>>,
        Arc<RwLock<HashMap<String, Session>>>,
        u64,
    )>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    if is_loopback_request(&req) {
        // Stamp the authenticated-user sentinel so downstream handlers
        // (orphan resolution, audit trail) have a stable label for
        // local-CLI / local-AI-agent requests.
        req.extensions_mut()
            .insert(AuthenticatedUser("loopback".to_string()));
        return next.run(req).await;
    }
    require_auth(state, req, next).await
}

#[allow(clippy::type_complexity)]
pub(super) async fn require_auth(
    State((auth, trusted_proxies, sessions, session_timeout_minutes)): State<(
        Option<DashboardAuth>,
        Arc<Vec<IpAddr>>,
        Arc<RwLock<HashMap<String, Session>>>,
        u64,
    )>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    // No credentials configured → open access. Inject a sentinel so
    // handlers don't have to handle the missing-extension case.
    let Some(auth) = auth else {
        req.extensions_mut()
            .insert(AuthenticatedUser("anonymous".to_string()));
        return next.run(req).await;
    };

    let client_ip = extract_client_ip(&req, &trusted_proxies);

    // 1. Try Bearer token first (session-based auth)
    if let Some(token) = extract_bearer_token(&req) {
        let session_user = {
            let map = sessions.read().unwrap_or_else(|e| e.into_inner());
            if let Some(session) = map.get(token) {
                if !session.is_expired(session_timeout_minutes) {
                    session.touch();
                    Some(session.username.clone())
                } else {
                    None
                }
            } else {
                // Token not found - fall through to return error
                return (StatusCode::UNAUTHORIZED, "session expired or invalid").into_response();
            }
        };
        if let Some(user) = session_user {
            // PR #422 Wave 4a: thread the authenticated username into
            // request extensions so handlers (orphan resolution etc.)
            // can stamp audit rows with the real operator instead of
            // a hardcoded "dashboard" placeholder.
            req.extensions_mut().insert(AuthenticatedUser(user));
            return next.run(req).await;
        }
        // Expired - remove session
        sessions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(token);
        return (StatusCode::UNAUTHORIZED, "session expired or invalid").into_response();
    }

    // 2. Fall back to Basic Auth (backward compat for API clients)
    // Check if this IP is already rate-limited before doing any auth work
    if is_rate_limited(&client_ip) {
        warn!(ip = %client_ip, "login rate-limited: too many failed attempts");
        return rate_limited_response();
    }

    let Some(raw_header) = req.headers().get(header::AUTHORIZATION) else {
        return unauthorized_response();
    };
    let Ok(raw_header) = raw_header.to_str() else {
        return unauthorized_response();
    };
    let Some((user, password)) = parse_basic_auth(raw_header) else {
        return unauthorized_response();
    };
    // Per-request hot path: skip the ~64 MB argon2 working buffer
    // when the same credentials have been verified in the last
    // 5 minutes. Falls back to the slow path on cache miss.
    if !auth.verify_with_cache(&user, &password) {
        let blocked = check_and_record_failed_login(&client_ip);
        if blocked {
            warn!(
                ip = %client_ip,
                "login rate-limited after {} failed attempts in {} min window",
                LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
                LOGIN_RATE_LIMIT_WINDOW_SECS / 60
            );
            return rate_limited_response();
        }
        return unauthorized_response();
    }

    // Successful auth - clear any prior failed attempts for this IP
    clear_rate_limit(&client_ip);
    req.extensions_mut().insert(AuthenticatedUser(user));
    next.run(req).await
}

/// PR #422 Wave 4a: handler-side accessor for the authenticated
/// username injected by `require_auth`. Newtype around `String` so
/// `axum::Extension<AuthenticatedUser>` is unambiguous in handler
/// signatures and won't clash with any other extension's String.
#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedUser(pub String);

impl AuthenticatedUser {
    /// Default fallback when no auth layer ran — used by tests and
    /// by no-auth (loopback) deployments. Keeps audit rows non-empty
    /// without lying about provenance.
    pub const ANONYMOUS: &'static str = "anonymous";
}

/// Extract a Bearer token from the Authorization header.
pub(super) fn extract_bearer_token(req: &Request<Body>) -> Option<&str> {
    let header = req.headers().get(header::AUTHORIZATION)?;
    let value = header.to_str().ok()?;
    value.strip_prefix("Bearer ")
}

pub(super) fn parse_basic_auth(value: &str) -> Option<(String, String)> {
    let token = value.strip_prefix("Basic ")?;
    let decoded = BASE64_STANDARD.decode(token.as_bytes()).ok()?;
    let raw = String::from_utf8(decoded).ok()?;
    let (user, password) = raw.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

pub(super) fn unauthorized_response() -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "Authentication required").into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(r#"Basic realm="innerwarden-dashboard", charset="UTF-8""#),
    );
    response
}

pub(super) fn rate_limited_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        "Too many failed login attempts. Try again later.",
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Session auth endpoints
// ---------------------------------------------------------------------------

/// POST /api/auth/login - authenticate with Basic Auth header, returns a session token.
pub(super) async fn api_auth_login(
    State(state): State<DashboardState>,
    req: Request<Body>,
) -> Response {
    // Auth must be configured for session login to work
    let auth = match DashboardAuth::try_from_env() {
        Ok(Some(a)) => a,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "authentication not configured" })),
            )
                .into_response();
        }
    };

    let client_ip = extract_client_ip(&req, &state.trusted_proxies);

    // Check rate limiting
    if is_rate_limited(&client_ip) {
        warn!(ip = %client_ip, "login rate-limited: too many failed attempts");
        return rate_limited_response();
    }

    // Extract Basic Auth credentials
    let Some(raw_header) = req.headers().get(header::AUTHORIZATION) else {
        return unauthorized_response();
    };
    let Ok(raw_header) = raw_header.to_str() else {
        return unauthorized_response();
    };
    let Some((user, password)) = parse_basic_auth(raw_header) else {
        return unauthorized_response();
    };

    // Verify credentials. The login endpoint is rare in practice
    // (one call per session) but uses the cached verifier for
    // consistency: if the operator just authed via the per-request
    // middleware path, this hit is free.
    if !auth.verify_with_cache(&user, &password) {
        let blocked = check_and_record_failed_login(&client_ip);
        if blocked {
            warn!(
                ip = %client_ip,
                "login rate-limited after {} failed attempts in {} min window",
                LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
                LOGIN_RATE_LIMIT_WINDOW_SECS / 60
            );
            return rate_limited_response();
        }
        return unauthorized_response();
    }

    // Successful authentication - clear rate limit
    clear_rate_limit(&client_ip);

    // Generate session token and store session
    let token = generate_session_token();
    let now = Utc::now();
    let session = Session {
        username: user.clone(),
        created_at: now,
        last_activity: Arc::new(AtomicI64::new(now.timestamp())),
        client_ip: client_ip.clone(),
    };

    {
        let mut map = state.sessions.write().unwrap_or_else(|e| e.into_inner());

        // Enforce max_sessions: if exceeded, remove the oldest session
        while map.len() >= state.max_sessions {
            // Find the session with the oldest last_activity
            let oldest_key = map
                .iter()
                .min_by_key(|(_, s)| s.last_activity.load(Ordering::Relaxed))
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest_key {
                map.remove(&key);
            } else {
                break;
            }
        }

        map.insert(token.clone(), session);
    }

    // Audit log: login
    write_admin_audit_or_warn(
        &state.data_dir,
        &mut AdminActionEntry {
            ts: now,
            operator: user,
            source: "dashboard".into(),
            action: "login".into(),
            target: "session".into(),
            parameters: serde_json::json!({ "client_ip": client_ip }),
            result: "success".into(),
            prev_hash: None,
        },
    );

    info!(ip = %client_ip, "session login successful");

    Json(serde_json::json!({
        "token": token,
        "expires_in_minutes": state.session_timeout_minutes,
    }))
    .into_response()
}

/// POST /api/auth/logout - invalidate the current session.
pub(super) async fn api_auth_logout(
    State(state): State<DashboardState>,
    req: Request<Body>,
) -> Response {
    let token = match extract_bearer_token(&req) {
        Some(t) => t.to_string(),
        None => {
            return (StatusCode::BAD_REQUEST, "Bearer token required").into_response();
        }
    };

    // Remove session by token (token is never logged - CWE-532)
    let username = {
        let mut map = state.sessions.write().unwrap_or_else(|e| e.into_inner());
        // Use the token only as a lookup key, never log or serialize it
        let user = map.get(&token).map(|s| s.username.clone());
        if user.is_some() {
            map.remove(&token);
        }
        user
    };

    if let Some(user) = &username {
        let client_ip = extract_client_ip(&req, &state.trusted_proxies);
        write_admin_audit_or_warn(
            &state.data_dir,
            &mut AdminActionEntry {
                ts: Utc::now(),
                operator: user.clone(),
                source: "dashboard".into(),
                action: "logout".into(),
                target: "session".into(),
                parameters: serde_json::json!({ "client_ip": client_ip }),
                result: "success".into(),
                prev_hash: None,
            },
        );
        info!(user = %user, "session logout");
    }

    StatusCode::OK.into_response()
}

/// GET /api/auth/sessions - list active sessions (does not expose tokens).
pub(super) async fn api_auth_sessions(State(state): State<DashboardState>) -> impl IntoResponse {
    let map = state.sessions.read().unwrap_or_else(|e| e.into_inner());
    let items: Vec<serde_json::Value> = map
        .values()
        .filter(|s| !s.is_expired(state.session_timeout_minutes))
        .map(|s| {
            let last = s.last_activity.load(Ordering::Relaxed);
            let last_dt = DateTime::from_timestamp(last, 0)
                .unwrap_or(s.created_at)
                .to_rfc3339();
            serde_json::json!({
                "username": s.username,
                "created_at": s.created_at.to_rfc3339(),
                "last_activity": last_dt,
                "client_ip": s.client_ip,
            })
        })
        .collect();
    Json(serde_json::json!({
        "total": items.len(),
        "sessions": items,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_auth_valid() {
        // "admin:secret" in base64 is "YWRtaW46c2VjcmV0"
        let header = "Basic YWRtaW46c2VjcmV0";
        let (user, pass) = parse_basic_auth(header).expect("should parse valid auth");
        assert_eq!(user, "admin");
        assert_eq!(pass, "secret");
    }

    #[test]
    fn test_parse_basic_auth_malformed() {
        assert!(parse_basic_auth("Bearer YWRtaW46c2VjcmV0").is_none());
        assert!(parse_basic_auth("Basic").is_none());
        assert!(parse_basic_auth("Basic ").is_none()); // empty base64
                                                       // Not base64
        assert!(parse_basic_auth("Basic !@#$").is_none());
        // Valid base64 but no colon
        // "admin" in base64 is "YWRtaW4="
        assert!(parse_basic_auth("Basic YWRtaW4=").is_none());
    }

    #[test]
    fn parse_basic_auth_allows_colons_inside_password() {
        // "admin:secret:with:colons" encoded; split_once must only split
        // the username separator and preserve the rest of the password.
        let header = "Basic YWRtaW46c2VjcmV0OndpdGg6Y29sb25z";
        let (user, pass) = parse_basic_auth(header).expect("should parse valid auth");
        assert_eq!(user, "admin");
        assert_eq!(pass, "secret:with:colons");
    }

    #[test]
    fn parse_basic_auth_rejects_non_utf8_payload() {
        let header = "Basic //4=";
        assert!(parse_basic_auth(header).is_none());
    }

    #[test]
    fn test_extract_bearer_token() {
        let req = Request::builder()
            .header(header::AUTHORIZATION, "Bearer xyz123")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req), Some("xyz123"));

        let req2 = Request::builder()
            .header(header::AUTHORIZATION, "Basic YWRtaW46c2VjcmV0")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&req2), None);
    }

    #[test]
    fn extract_bearer_token_rejects_empty_wrong_case_and_invalid_header() {
        let empty = Request::builder()
            .header(header::AUTHORIZATION, "Bearer ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&empty), Some(""));

        let wrong_case = Request::builder()
            .header(header::AUTHORIZATION, "bearer xyz123")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_bearer_token(&wrong_case), None);

        let mut invalid = Request::builder().body(Body::empty()).unwrap();
        invalid.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_bytes(b"Bearer \xff").expect("opaque header bytes"),
        );
        assert_eq!(extract_bearer_token(&invalid), None);
    }

    #[test]
    fn test_rate_limiter_blocks_abuse() {
        let ip = "10.0.0.99";
        clear_rate_limit(ip);
        assert!(!is_rate_limited(ip));

        // Attempt up to limit
        for _ in 0..LOGIN_RATE_LIMIT_MAX_ATTEMPTS - 1 {
            let blocked = check_and_record_failed_login(ip);
            assert!(!blocked, "should not be blocked yet");
        }

        // Final attempt exceeds limit
        let blocked = check_and_record_failed_login(ip);
        assert!(blocked, "should be blocked");
        assert!(is_rate_limited(ip));

        // Auth success resets it
        clear_rate_limit(ip);
        assert!(!is_rate_limited(ip));
    }

    #[test]
    fn test_extract_client_ip_headers() {
        let trusted = vec!["127.0.0.1".parse().unwrap()];

        // Forwarded-For proxy IP extraction
        let mut req = Request::builder().body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                8080,
            )));
        req.headers_mut()
            .insert("x-forwarded-for", "1.1.1.1, 2.2.2.2".parse().unwrap());
        assert_eq!(extract_client_ip(&req, &trusted), "1.1.1.1");

        // Missing headers fallback to socket IP
        let mut req2 = Request::builder().body(Body::empty()).unwrap();
        req2.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::new(
                "10.0.0.5".parse().unwrap(),
                8080,
            )));
        assert_eq!(extract_client_ip(&req2, &trusted), "10.0.0.5");

        // Malicious header attempt from untrusted proxy should fallback to socket IP
        let mut req3 = Request::builder().body(Body::empty()).unwrap();
        req3.extensions_mut().insert(axum::extract::ConnectInfo(
            std::net::SocketAddr::new("10.0.0.5".parse().unwrap(), 8080), // 10.0.0.5 not trusted
        ));
        req3.headers_mut()
            .insert("x-forwarded-for", "1.1.1.1".parse().unwrap());
        assert_eq!(extract_client_ip(&req3, &trusted), "10.0.0.5");
    }

    #[test]
    fn extract_client_ip_uses_real_ip_and_ignores_empty_forwarded_for() {
        let trusted = vec!["127.0.0.1".parse().unwrap()];
        let mut req = Request::builder().body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                8080,
            )));
        req.headers_mut()
            .insert("x-forwarded-for", "   ".parse().unwrap());
        req.headers_mut()
            .insert("x-real-ip", "203.0.113.44".parse().unwrap());
        assert_eq!(extract_client_ip(&req, &trusted), "203.0.113.44");
    }

    #[test]
    fn extract_client_ip_returns_unknown_without_connect_info() {
        let req = Request::builder().body(Body::empty()).unwrap();
        assert_eq!(extract_client_ip(&req, &[]), "unknown");
    }

    #[test]
    fn test_session_expiry_check() {
        let ts = Utc::now() - chrono::Duration::minutes(60);
        let s = Session {
            username: "admin".into(),
            created_at: ts,
            last_activity: Arc::new(AtomicI64::new(ts.timestamp())),
            client_ip: "1.1.1.1".into(),
        };
        // Expired because last activity was 60 mins ago and timeout is 30 mins
        assert!(s.is_expired(30));

        // Not expired if timeout is 120 mins
        assert!(!s.is_expired(120));
    }

    #[test]
    fn test_session_touch_updates_activity() {
        let ts = Utc::now() - chrono::Duration::minutes(20);
        let s = Session {
            username: "admin".into(),
            created_at: ts,
            last_activity: Arc::new(AtomicI64::new(ts.timestamp())),
            client_ip: "1.1.1.1".into(),
        };
        s.touch();
        // Activity should be updated to now
        assert!(!s.is_expired(10));
    }

    #[test]
    fn test_unauthorized_responses() {
        let resp = unauthorized_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().contains_key(header::WWW_AUTHENTICATE));
        assert_eq!(
            resp.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Basic realm=\"innerwarden-dashboard\", charset=\"UTF-8\""
        );
    }

    #[test]
    fn test_rate_limited_response() {
        let resp = rate_limited_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // ── Spec 037 I-13 PR-1 — audit-trail warn anchors ──────────────
    //
    // PR-1 of I-13 converts the two `let _ = append_admin_action(..)`
    // sites in this file into a `warn!`-on-failure pattern via the
    // shared `write_admin_audit_or_warn` helper. Tests pin two
    // contracts:
    //
    //   1. The wrapper does NOT panic when the underlying append
    //      fails.
    //   2. The wrapper EMITS a `warn!` carrying operator + action +
    //      target + error context when the append fails.
    //
    // Capture is via the global subscriber + thread-local buffer in
    // `crate::test_util` (follow-up #3 PR-replacement). The earlier
    // per-test `with_default` + `CapturedLogs` MakeWriter pattern
    // was flaky on CI even with cross-test serialisation — see
    // `crate::test_util` rustdoc for the root cause.

    fn make_login_entry() -> AdminActionEntry {
        AdminActionEntry {
            ts: chrono::Utc::now(),
            operator: "alice".to_string(),
            source: "dashboard".to_string(),
            action: "login".to_string(),
            target: "session".to_string(),
            parameters: serde_json::json!({ "client_ip": "203.0.113.7" }),
            result: "success".to_string(),
            prev_hash: None,
        }
    }

    #[test]
    fn write_admin_audit_or_warn_does_not_panic_on_unwritable_path() {
        // Force `append_admin_action` to fail by handing it a path
        // that does not exist and cannot be canonicalized. The
        // wrapper must absorb the error and return `()` so the
        // calling login/logout handler proceeds normally — same
        // observable shape as the prior `let _ =`.
        let bad_path = std::path::PathBuf::from("/this/path/never/ever/exists/innerwarden-i13");
        let mut entry = make_login_entry();

        // The point of the test: this call must not panic.
        write_admin_audit_or_warn(&bad_path, &mut entry);
    }

    #[test]
    fn write_admin_audit_or_warn_emits_warn_with_context_on_failure() {
        let _guard = crate::test_util::arm_capture();

        let bad_path =
            std::path::PathBuf::from("/this/path/never/ever/exists/innerwarden-i13-warn");
        let mut entry = make_login_entry();
        write_admin_audit_or_warn(&bad_path, &mut entry);

        let captured_str = crate::test_util::drain_capture();

        // The message itself must be present so a future refactor
        // that drops the message string is detected.
        assert!(
            captured_str.contains("audit trail write failed"),
            "warn message missing — got: {captured_str}"
        );
        // Every structured field promised by the helper rustdoc
        // must be in the captured output. These are the load-bearing
        // forensic fields the operator will need to investigate.
        assert!(
            captured_str.contains("operator=\"alice\"") || captured_str.contains("operator=alice"),
            "operator field missing — got: {captured_str}"
        );
        assert!(
            captured_str.contains("action=\"login\"") || captured_str.contains("action=login"),
            "action field missing — got: {captured_str}"
        );
        assert!(
            captured_str.contains("target=\"session\"") || captured_str.contains("target=session"),
            "target field missing — got: {captured_str}"
        );
        // The `error=` key must be present; we don't pin the exact
        // anyhow message so a chrono/std/io message change doesn't
        // brittlefy the test.
        assert!(
            captured_str.contains("error="),
            "error field missing — got: {captured_str}"
        );
    }

    #[test]
    fn write_admin_audit_or_warn_succeeds_silently_on_writable_path() {
        // Inverse anchor: when the append succeeds, the wrapper
        // must NOT emit a warn — silent success is the steady-state.
        let _guard = crate::test_util::arm_capture();

        let dir = tempfile::tempdir().expect("tempdir");
        let mut entry = make_login_entry();
        write_admin_audit_or_warn(dir.path(), &mut entry);

        let captured_str = crate::test_util::drain_capture();
        assert!(
            !captured_str.contains("audit trail write failed"),
            "successful write must not emit the failure warn — got: {captured_str}"
        );
    }

    // ── Wave 5 anchors (AUDIT-WAVE5-DOC-DRIFT) ─────────────────────────
    //
    // Documentation that quotes a numeric value drifts when the source-
    // of-truth constant changes. Pre-fix THREAT_MODEL.md said the
    // global rate limit was 120 req/min/IP; the actual constant is
    // GLOBAL_RATE_LIMIT_PER_MIN = 300. SECURITY.md said "v0.1.x" was
    // the supported line; current version is v0.13.0. Both numbers
    // are now anchored to the source-of-truth so a future bump
    // breaks CI until the doc is also updated.

    #[test]
    fn threat_model_md_quotes_actual_global_rate_limit() {
        // Read THREAT_MODEL.md from the workspace root and assert the
        // documented rate limit matches GLOBAL_RATE_LIMIT_PER_MIN.
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // CARGO_MANIFEST_DIR is crates/agent; THREAT_MODEL.md is at
        // workspace root (../../).
        let doc = manifest.join("../../THREAT_MODEL.md");
        let content =
            std::fs::read_to_string(&doc).unwrap_or_else(|e| panic!("read {}: {e}", doc.display()));
        let needle = format!("{} req/min/IP", GLOBAL_RATE_LIMIT_PER_MIN);
        assert!(
            content.contains(&needle),
            "THREAT_MODEL.md must quote {needle:?} (matches GLOBAL_RATE_LIMIT_PER_MIN). \
             If you bumped the constant, update THREAT_MODEL.md too."
        );
    }

    #[test]
    fn security_md_supported_versions_matches_current_minor() {
        // CARGO_PKG_VERSION is e.g. "0.13.0"; the supported-versions
        // table should mention "v0.13.x" (the current minor line).
        // Anti-regression for the SECURITY.md / Cargo.toml drift that
        // had us still claiming v0.1.x as the supported line at v0.13.
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let doc = manifest.join("../../SECURITY.md");
        let content =
            std::fs::read_to_string(&doc).unwrap_or_else(|e| panic!("read {}: {e}", doc.display()));
        let pkg = env!("CARGO_PKG_VERSION");
        // Extract major.minor from "0.13.0" -> "0.13".
        let minor_prefix = pkg.split('.').take(2).collect::<Vec<_>>().join(".");
        let needle = format!("v{minor_prefix}.x");
        assert!(
            content.contains(&needle),
            "SECURITY.md must list {needle:?} as the supported line (matches CARGO_PKG_VERSION {pkg}). \
             If you cut a minor release, update SECURITY.md too."
        );
    }

    #[test]
    fn threat_model_md_does_not_quote_stale_rate_limit_value() {
        // Partial-edit anti-regression: pre-fix THREAT_MODEL.md said
        // "120 req/min/IP" with the constant at 300. A future edit
        // that bumps GLOBAL_RATE_LIMIT_PER_MIN but only updates one
        // of the two doc mentions would let the stale number linger.
        // This test fires whenever ANY non-current rate-limit-shape
        // value appears in the doc.
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let doc = manifest.join("../../THREAT_MODEL.md");
        let content =
            std::fs::read_to_string(&doc).unwrap_or_else(|e| panic!("read {}: {e}", doc.display()));
        let current = format!("{} req/min/IP", GLOBAL_RATE_LIMIT_PER_MIN);
        // Walk every "<N> req/min/IP"-shaped substring and assert
        // every one of them matches the current constant.
        for line in content.lines() {
            if let Some(idx) = line.find(" req/min/IP") {
                let prefix = &line[..idx];
                let num_start = prefix
                    .rfind(|c: char| !c.is_ascii_digit())
                    .map(|i| i + 1)
                    .unwrap_or(0);
                let quoted = &line[num_start..idx + " req/min/IP".len()];
                assert_eq!(
                    quoted, current,
                    "THREAT_MODEL.md quotes a stale rate-limit value {quoted:?} on line: {line:?}. \
                     The current constant is {GLOBAL_RATE_LIMIT_PER_MIN}; every mention must match."
                );
            }
        }
    }

    #[test]
    fn security_md_lists_only_current_minor_as_supported() {
        // Partial-edit anti-regression: a future minor bump that
        // updates the row but leaves an OLDER "v0.X.x | Yes" line
        // would still falsely advertise an unsupported series.
        // Walk the doc, find every `vMAJOR.MINOR.x` mention, and
        // assert that any one marked "Yes" matches the current
        // CARGO_PKG_VERSION minor.
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let doc = manifest.join("../../SECURITY.md");
        let content =
            std::fs::read_to_string(&doc).unwrap_or_else(|e| panic!("read {}: {e}", doc.display()));
        let pkg = env!("CARGO_PKG_VERSION");
        let minor_prefix = pkg.split('.').take(2).collect::<Vec<_>>().join(".");
        let current_supported = format!("v{minor_prefix}.x");

        for line in content.lines() {
            // Markdown table row that says "Yes": looks like
            // `| v0.13.x (latest release) | Yes |` or `| v0.X.x | Yes |`.
            if !line.contains("| Yes") && !line.contains("|Yes") {
                continue;
            }
            // Extract the `v<digits>.<digits>.x` token from the row.
            let v_idx = match line.find("| v") {
                Some(i) => i + 2,
                None => continue,
            };
            let after = &line[v_idx..];
            let end = after.find([' ', '|']).unwrap_or(after.len());
            let token = &after[..end];
            assert_eq!(
                token, current_supported,
                "SECURITY.md lists {token:?} as supported (Yes) but the current \
                 minor is {current_supported:?}. Every 'Yes' row must match the \
                 current CARGO_PKG_VERSION minor — older lines should be 'No'."
            );
        }
    }

    // ─── Wave 2026-05-17 — loopback bypass anchors ───────────────────────
    //
    // The per-request auth gate `is_loopback_request` decides whether
    // /api/agent-guard/* (and friends) skip the password wall. The
    // operator hit a 401 running `sudo innerwarden agent connect <pid>`
    // on a host whose dashboard was bound to 0.0.0.0; the fix bypasses
    // auth when the TCP peer IP is loopback. These tests anchor every
    // branch of that decision: loopback IPv4, loopback IPv6, a real
    // remote IP that must NOT bypass, and the failure-safe case where
    // `ConnectInfo` is missing (which would mean the server forgot to
    // call `into_make_service_with_connect_info` — must fail closed).

    fn req_with_connect_info(ip: std::net::IpAddr) -> Request<Body> {
        let mut req = Request::new(Body::empty());
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo::<SocketAddr>(SocketAddr::new(
                ip, 12345,
            )));
        req
    }

    #[test]
    fn is_loopback_request_true_for_ipv4_loopback() {
        let req = req_with_connect_info("127.0.0.1".parse().unwrap());
        assert!(is_loopback_request(&req));
    }

    #[test]
    fn is_loopback_request_true_for_ipv6_loopback() {
        let req = req_with_connect_info("::1".parse().unwrap());
        assert!(is_loopback_request(&req));
    }

    #[test]
    fn is_loopback_request_false_for_remote_ipv4() {
        let req = req_with_connect_info("198.51.100.42".parse().unwrap());
        assert!(!is_loopback_request(&req));
    }

    #[test]
    fn is_loopback_request_false_for_lan_ipv4() {
        // RFC1918 — a host on the operator's LAN is not "on the same
        // box" and must still hit the auth wall.
        let req = req_with_connect_info("192.168.0.42".parse().unwrap());
        assert!(!is_loopback_request(&req));
    }

    #[test]
    fn is_loopback_request_false_when_connect_info_missing() {
        // Defence in depth: if the serve site forgot to wire
        // `into_make_service_with_connect_info`, the helper must NOT
        // bypass auth — fail closed, not open.
        let req = Request::new(Body::empty());
        assert!(!is_loopback_request(&req));
    }

    #[test]
    fn is_loopback_request_ignores_x_forwarded_for_spoof() {
        // A remote attacker behind a misconfigured proxy that forwards
        // `X-Forwarded-For: 127.0.0.1` must NOT bypass auth. The helper
        // reads the socket peer, not the header — anchor this by
        // setting the header AND a real remote peer; result must still
        // be false.
        let mut req = req_with_connect_info("198.51.100.99".parse().unwrap());
        req.headers_mut()
            .insert("x-forwarded-for", "127.0.0.1".parse().unwrap());
        assert!(!is_loopback_request(&req));
    }
}
