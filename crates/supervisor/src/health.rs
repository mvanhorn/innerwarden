//! Sync HTTP/HTTPS health check against the agent's `/metrics` endpoint.
//!
//! Three consecutive failures are required before [`HealthChecker::check`]
//! returns `Err` - the supervisor reacts by SIGKILLing the agent, which the
//! spawn loop notices on the next 100 ms tick. The 5 s per-request timeout
//! prevents a hung connection from stalling the supervisor itself.
//!
//! `ureq` is used instead of an async client because the supervisor is
//! deliberately tokio-free (small RSS, fewer transitive deps).
//!
//! # AUDIT-005 (2026-05-04 prod): HTTPS loopback probe
//!
//! Pre-fix the supervisor probed `http://127.0.0.1:8787` against an agent
//! that serves the dashboard over HTTPS by default. Every probe failed
//! with `protocol: http parse fail: invalid HTTP version` (ureq received
//! the TLS handshake bytes and tried to parse them as an HTTP response).
//! The supervisor then SIGKILLed the (perfectly healthy) agent every 30 s.
//! Prod accumulated 1100+ consecutive health-check failures over ~10 hours
//! before this was caught.
//!
//! Fix: support `https://` URLs. For loopback hosts (127.0.0.1, localhost,
//! ::1) automatically skip TLS certificate verification because (a) the
//! OSS agent serves a self-signed cert by default, (b) MITM on loopback
//! requires local root which already owns the agent process, and (c) we
//! do not want operators to maintain a CA bundle for the localhost probe.
//! Non-loopback HTTPS keeps verification on so a misconfigured remote
//! probe fails loud.

use anyhow::{bail, Result};
use tracing::{debug, warn};
use ureq::tls::TlsConfig;

pub struct HealthChecker {
    agent_api: String,
    consecutive_failures: u32,
    max_failures: u32,
    /// AUDIT-005: auto-derived in [`Self::new`] from `agent_api`. True iff
    /// the URL is HTTPS pointing at a loopback host. Stored once at
    /// construction so the hot probe path does not re-parse the URL on
    /// every call.
    skip_tls_verify: bool,
}

impl HealthChecker {
    pub fn new(agent_api: &str) -> Self {
        let skip_tls_verify = url_is_loopback_https(agent_api);
        Self {
            agent_api: agent_api.trim_end_matches('/').to_string(),
            consecutive_failures: 0,
            max_failures: 3,
            skip_tls_verify,
        }
    }

    /// Probe `<agent_api>/metrics`. Returns `Err` only after `max_failures`
    /// consecutive non-2xx or transport errors.
    pub fn check(&mut self) -> Result<()> {
        let url = format!("{}/metrics", self.agent_api);
        let mut builder =
            ureq::config::Config::builder().timeout_global(Some(std::time::Duration::from_secs(5)));
        if self.skip_tls_verify {
            // AUDIT-005: see module docs. ureq's `disable_verification`
            // turns off cert chain + hostname verification. We only set
            // this when `url_is_loopback_https` returned true, so an
            // operator who points the watchdog at a remote agent still
            // gets a real TLS check.
            builder = builder.tls_config(TlsConfig::builder().disable_verification(true).build());
        }
        let agent = ureq::Agent::new_with_config(builder.build());
        match agent.get(&url).call() {
            Ok(resp) if resp.status().is_success() => {
                if self.consecutive_failures > 0 {
                    debug!(
                        "agent health recovered after {} failures",
                        self.consecutive_failures
                    );
                }
                self.consecutive_failures = 0;
                Ok(())
            }
            Ok(resp) => {
                self.consecutive_failures += 1;
                warn!(
                    status = resp.status().as_u16(),
                    failures = self.consecutive_failures,
                    "agent health check returned non-200"
                );
                self.maybe_fail()
            }
            Err(e) => {
                self.consecutive_failures += 1;
                warn!(
                    error = %e,
                    failures = self.consecutive_failures,
                    "agent health check failed"
                );
                self.maybe_fail()
            }
        }
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    fn maybe_fail(&self) -> Result<()> {
        if self.consecutive_failures >= self.max_failures {
            bail!(
                "agent unresponsive: {} consecutive health check failures",
                self.consecutive_failures
            );
        }
        Ok(())
    }
}

/// AUDIT-005 anchor: `true` iff the URL is HTTPS AND the host is a
/// loopback literal. Used by [`HealthChecker::new`] to decide whether to
/// skip TLS certificate verification on the agent probe.
///
/// Loopback recognised: `127.0.0.1`, `localhost`, `::1`, `[::1]`. We do
/// NOT use a full-blown URL parser because (a) the supervisor is meant
/// to be dependency-light and (b) the function only needs to be
/// conservative — false negatives degrade to "verify the cert" which
/// is the safe default; false positives would skip verification on a
/// non-loopback host which is the failure mode we want to prevent.
fn url_is_loopback_https(url: &str) -> bool {
    let url = url.trim();
    let after_scheme = match url.strip_prefix("https://") {
        Some(rest) => rest,
        None => return false,
    };
    // Strip optional `userinfo@` (we never emit it but defensive parsing
    // makes the function robust against operator-provided URLs).
    let after_userinfo = after_scheme
        .rsplit_once('@')
        .map_or(after_scheme, |(_, h)| h);
    // Authority ends at the first `/`, `?`, or `#`. Take the host:port
    // part and then split off the optional `:port`.
    let authority_end = after_userinfo
        .find(['/', '?', '#'])
        .unwrap_or(after_userinfo.len());
    let authority = &after_userinfo[..authority_end];
    // IPv6 literals are wrapped in brackets: `[::1]:8787`. Detect this
    // shape before the generic `:port` strip so the colons inside the
    // address are not mistaken for the port separator.
    let host = if let Some(end) = authority
        .strip_prefix('[')
        .and_then(|a| a.find(']').map(|i| &a[..i]))
    {
        end
    } else {
        authority.split(':').next().unwrap_or("")
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_trailing_slash_from_api_url() {
        let h = HealthChecker::new("http://127.0.0.1:8787/");
        assert_eq!(h.agent_api, "http://127.0.0.1:8787");
    }

    #[test]
    fn maybe_fail_returns_ok_below_threshold() {
        let h = HealthChecker {
            agent_api: "x".into(),
            consecutive_failures: 2,
            max_failures: 3,
            skip_tls_verify: false,
        };
        assert!(h.maybe_fail().is_ok());
    }

    #[test]
    fn maybe_fail_returns_err_at_threshold() {
        let h = HealthChecker {
            agent_api: "x".into(),
            consecutive_failures: 3,
            max_failures: 3,
            skip_tls_verify: false,
        };
        let err = h.maybe_fail().unwrap_err();
        assert!(format!("{:#}", err).contains("3 consecutive"));
    }

    // ── AUDIT-005 anchors: loopback-HTTPS auto-skip-verify ────────────

    #[test]
    fn loopback_https_url_triggers_skip_verify() {
        // The exact prod failure shape from 2026-05-04: agent serves
        // self-signed HTTPS on 127.0.0.1:8787, watchdog probed plain HTTP
        // and got TLS bytes back. After this fix, the watchdog probes
        // HTTPS with verification disabled.
        let h = HealthChecker::new("https://127.0.0.1:8787");
        assert!(
            h.skip_tls_verify,
            "loopback HTTPS must auto-disable TLS verification"
        );
    }

    #[test]
    fn loopback_https_localhost_triggers_skip_verify() {
        let h = HealthChecker::new("https://localhost:8787");
        assert!(h.skip_tls_verify);
    }

    #[test]
    fn loopback_https_ipv6_triggers_skip_verify() {
        let h = HealthChecker::new("https://[::1]:8787");
        assert!(h.skip_tls_verify);
    }

    #[test]
    fn http_loopback_does_not_skip_verify() {
        // Plain HTTP - skip_tls_verify is irrelevant but should be false
        // for clarity. Anti-regression for accidentally widening the
        // skip-verify path to cover plain HTTP (which would be a
        // pointless toggle but might mask other config bugs).
        let h = HealthChecker::new("http://127.0.0.1:8787");
        assert!(!h.skip_tls_verify);
    }

    #[test]
    fn non_loopback_https_keeps_verify_on() {
        // Operator points the watchdog at a remote agent: TLS check
        // stays on so a misconfigured cert / wrong CA fails loud.
        // Anti-regression for "auto-disable on every HTTPS" which would
        // erase the protection AUDIT-005 is meant to keep on remote.
        let h = HealthChecker::new("https://10.0.0.5:8787");
        assert!(!h.skip_tls_verify);
        let h = HealthChecker::new("https://example.com:8787");
        assert!(!h.skip_tls_verify);
    }

    #[test]
    fn url_is_loopback_https_handles_path_and_userinfo() {
        // URL with a path component should still classify as loopback.
        assert!(url_is_loopback_https("https://127.0.0.1:8787/metrics"));
        // URL with userinfo (rare but legal): host is still loopback.
        assert!(url_is_loopback_https("https://user:pw@localhost:8787"));
        // URL with query string after the authority.
        assert!(url_is_loopback_https("https://127.0.0.1?x=1"));
    }

    #[test]
    fn url_is_loopback_https_rejects_non_https_schemes() {
        assert!(!url_is_loopback_https("http://127.0.0.1"));
        assert!(!url_is_loopback_https("ws://127.0.0.1"));
        assert!(!url_is_loopback_https(""));
        assert!(!url_is_loopback_https("not a url"));
    }

    #[test]
    fn url_is_loopback_https_rejects_lookalike_hosts() {
        // Hostnames that LOOK like loopback but are not. Anti-regression
        // for a future "starts_with" or substring-match shortcut that
        // would accidentally allow an attacker-controlled host like
        // `127.0.0.1.attacker.com` to skip TLS verification.
        assert!(!url_is_loopback_https("https://127.0.0.1.attacker.com"));
        assert!(!url_is_loopback_https("https://localhost.attacker.com"));
        assert!(!url_is_loopback_https("https://127.0.0.2"));
        assert!(!url_is_loopback_https("https://0.0.0.0"));
    }

    #[test]
    fn check_against_unreachable_endpoint_increments_failure_count() {
        // Bind to an OS-assigned port, then drop the listener so the address
        // is guaranteed-unused for the duration of the test.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let mut h = HealthChecker::new(&format!("http://{}", addr));
        // First two failures should not bubble; third should.
        let _ = h.check();
        let _ = h.check();
        let result = h.check();
        assert!(result.is_err());
        assert_eq!(h.consecutive_failures(), 3);
    }
}
