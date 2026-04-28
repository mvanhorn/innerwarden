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

#[allow(clippy::type_complexity)]
pub(super) async fn require_auth(
    State((auth, trusted_proxies, sessions, session_timeout_minutes)): State<(
        Option<DashboardAuth>,
        Arc<Vec<IpAddr>>,
        Arc<RwLock<HashMap<String, Session>>>,
        u64,
    )>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // No credentials configured → open access
    let Some(auth) = auth else {
        return next.run(req).await;
    };

    let client_ip = extract_client_ip(&req, &trusted_proxies);

    // 1. Try Bearer token first (session-based auth)
    if let Some(token) = extract_bearer_token(&req) {
        let valid = {
            let map = sessions.read().unwrap_or_else(|e| e.into_inner());
            if let Some(session) = map.get(token) {
                if !session.is_expired(session_timeout_minutes) {
                    session.touch();
                    true
                } else {
                    false
                }
            } else {
                // Token not found - fall through to return error
                return (StatusCode::UNAUTHORIZED, "session expired or invalid").into_response();
            }
        };
        if valid {
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
    if !auth.verify(&user, &password) {
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
    next.run(req).await
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

    // Verify credentials
    if !auth.verify(&user, &password) {
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
}
