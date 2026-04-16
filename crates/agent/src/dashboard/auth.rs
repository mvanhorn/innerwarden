// Auto-extracted from mod.rs — dashboard auth handlers

use super::*;
use rand_core::OsRng;
use std::sync::atomic::{AtomicI64, Ordering};

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
    let _ = append_admin_action(
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
        let _ = append_admin_action(
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
}
