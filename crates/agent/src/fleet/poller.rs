//! Background poller for spec 038 Phase 1.
//!
//! One tokio task, one HTTP client. Loops over the configured spoke
//! list, hits `/api/status`, records `HostState::Up` on 2xx and
//! `HostState::Down` on anything else (timeout, transport error,
//! non-2xx response).
//!
//! Phase 2 will fold `OverviewSnapshot` into the cached entry so the
//! fleet dashboard does not need a second round-trip per host. Phase
//! 4 will handle 401 by re-running `POST /api/auth/login` against the
//! spoke and retrying with a fresh bearer token.

use std::sync::Arc;
use std::time::Duration;

use tokio::time;
use tracing::{debug, warn};

use crate::config::{FleetConfig, FleetHostConfig};

use super::{FleetState, HostState};

/// Spawn the poll loop. Returns immediately; the loop runs on the
/// tokio runtime until the agent shuts down. Cancellation safety is
/// provided implicitly by the `tokio::time::interval` ticker — the
/// agent's TaskGroup-cancellation tree (spec 036 I-04) reaches every
/// task started under the runtime.
pub fn spawn(state: FleetState, cfg: Arc<FleetConfig>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if cfg.hosts.is_empty() {
            debug!("fleet poller: no hosts configured, exiting");
            return;
        }

        // Build one shared HTTP client. Tight per-request timeout so
        // a hung spoke does not stall the whole loop. `rustls-tls`
        // is the workspace default (no system-cert dependency).
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.request_timeout_seconds.max(1)))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "fleet poller: failed to build HTTP client; aborting");
                return;
            }
        };

        let interval_secs = cfg.poll_interval_seconds.max(5);
        let mut ticker = time::interval(Duration::from_secs(interval_secs));
        // Skip the immediate first tick the interval emits; we want
        // the first poll to land at +interval, not at boot when many
        // other tasks are still warming up.
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            for host in &cfg.hosts {
                let outcome = poll_one(&client, host).await;
                match outcome {
                    Ok(()) => state.record(&host.id, HostState::Up, None),
                    Err(e) => {
                        let msg = format!("{e:#}");
                        debug!(host = %host.id, error = %msg, "fleet poll: down");
                        state.record(&host.id, HostState::Down, Some(msg));
                    }
                }
            }
        }
    })
}

/// Probe one spoke. Pure helper for unit-testability — given a
/// reqwest client + a host config, returns Ok on 2xx and Err on
/// every failure mode (timeout, DNS, transport, non-2xx).
async fn poll_one(client: &reqwest::Client, host: &FleetHostConfig) -> anyhow::Result<()> {
    let url = format!("{}/api/status", host.url.trim_end_matches('/'));
    let mut req = client.get(&url);
    if !host.token_env.is_empty() {
        if let Ok(token) = std::env::var(&host.token_env) {
            req = req.bearer_auth(token);
        }
    }
    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("HTTP {} from {}", status.as_u16(), url);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(id: &str, url: &str) -> FleetHostConfig {
        FleetHostConfig {
            id: id.into(),
            url: url.into(),
            token_env: String::new(),
        }
    }

    #[tokio::test]
    async fn poll_one_returns_ok_on_2xx() {
        let server = mockito::Server::new_async().await;
        let mut server = server;
        let _m = server
            .mock("GET", "/api/status")
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client");
        let h = host("test", &server.url());
        let r = poll_one(&client, &h).await;
        assert!(r.is_ok(), "got: {r:?}");
    }

    #[tokio::test]
    async fn poll_one_returns_err_on_non_2xx() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/status")
            .with_status(503)
            .create_async()
            .await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client");
        let h = host("test", &server.url());
        let r = poll_one(&client, &h).await;
        assert!(r.is_err(), "expected Err on 503");
        let msg = format!("{:#}", r.unwrap_err());
        assert!(msg.contains("503"), "expected status code in error: {msg}");
    }

    #[tokio::test]
    async fn poll_one_returns_err_on_unreachable_host() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .expect("client");
        // 127.0.0.1:1 is reserved + nothing listens; connect fails fast.
        let h = host("test", "http://127.0.0.1:1");
        let r = poll_one(&client, &h).await;
        assert!(r.is_err(), "expected transport error on unreachable host");
    }

    #[tokio::test]
    async fn poll_one_strips_trailing_slash_from_url() {
        let server = mockito::Server::new_async().await;
        let mut server = server;
        let _m = server
            .mock("GET", "/api/status")
            .with_status(200)
            .create_async()
            .await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client");
        // Note the explicit trailing slash on the URL — poll_one
        // must not produce `//api/status`.
        let h = host("test", &format!("{}/", server.url()));
        let r = poll_one(&client, &h).await;
        assert!(
            r.is_ok(),
            "trailing slash must not break URL composition: {r:?}"
        );
    }
}
