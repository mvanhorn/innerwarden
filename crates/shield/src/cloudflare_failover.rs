//! Cloudflare auto-failover — toggles DNS proxy on DDoS detection.
//!
//! When the Shield escalation engine reaches UnderAttack or Critical,
//! this module activates the Cloudflare proxy (orange cloud) to absorb
//! the attack. When the attack subsides and escalation returns to Normal
//! or Elevated, the proxy is deactivated (grey cloud) to restore direct
//! access for the live demo.
//!
//! Uses the Cloudflare API v4:
//!   PATCH /zones/{zone_id}/dns_records/{record_id}
//!   Body: {"proxied": true/false}

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::escalation::EscalationState;

/// Configuration for Cloudflare failover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareFailoverConfig {
    /// Whether auto-failover is enabled.
    pub enabled: bool,
    /// Cloudflare API token with DNS edit permission.
    pub api_token: String,
    /// Zone ID for the domain.
    pub zone_id: String,
    /// DNS record ID to toggle proxy on.
    pub record_id: String,
    /// Escalation states that trigger proxy activation.
    /// Default: UnderAttack and Critical.
    pub activate_on: Vec<String>,
    /// Minimum time to keep proxy active before deactivating (seconds).
    /// Prevents flapping during intermittent attacks.
    pub min_proxy_duration_secs: u64,
}

impl Default for CloudflareFailoverConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_token: String::new(),
            zone_id: String::new(),
            record_id: String::new(),
            activate_on: vec!["UnderAttack".to_string(), "Critical".to_string()],
            min_proxy_duration_secs: 300, // 5 minutes minimum
        }
    }
}

/// Manages the Cloudflare proxy state.
pub struct CloudflareFailover {
    config: CloudflareFailoverConfig,
    client: reqwest::Client,
    /// Current proxy state (true = orange cloud active).
    proxy_active: bool,
    /// When the proxy was last activated.
    proxy_activated_at: Option<DateTime<Utc>>,
    /// When the proxy was last deactivated.
    proxy_deactivated_at: Option<DateTime<Utc>>,
    /// Total number of failover activations.
    activation_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FailoverStatus {
    pub enabled: bool,
    pub proxy_active: bool,
    pub proxy_activated_at: Option<String>,
    pub proxy_deactivated_at: Option<String>,
    pub activation_count: u64,
}

impl CloudflareFailover {
    pub fn new(config: CloudflareFailoverConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");

        Self {
            config,
            client,
            proxy_active: false,
            proxy_activated_at: None,
            proxy_deactivated_at: None,
            activation_count: 0,
        }
    }

    /// Check escalation state and toggle proxy if needed.
    /// Returns true if proxy state changed.
    pub async fn check_and_toggle(&mut self, state: EscalationState) -> bool {
        if !self.config.enabled {
            return false;
        }

        let state_name = format!("{state:?}");
        let should_activate = self.config.activate_on.contains(&state_name);

        if should_activate && !self.proxy_active {
            // Activate proxy
            match self.set_proxy(true).await {
                Ok(()) => {
                    self.proxy_active = true;
                    self.proxy_activated_at = Some(Utc::now());
                    self.activation_count += 1;
                    info!(
                        state = %state_name,
                        activations = self.activation_count,
                        "Cloudflare proxy ACTIVATED — DDoS traffic will be absorbed"
                    );
                    return true;
                }
                Err(e) => {
                    warn!(error = %e, "failed to activate Cloudflare proxy");
                }
            }
        } else if !should_activate && self.proxy_active {
            // Check minimum duration before deactivating
            if let Some(activated_at) = self.proxy_activated_at {
                let elapsed = (Utc::now() - activated_at).num_seconds() as u64;
                if elapsed < self.config.min_proxy_duration_secs {
                    // Too soon to deactivate — wait
                    return false;
                }
            }

            // Deactivate proxy
            match self.set_proxy(false).await {
                Ok(()) => {
                    self.proxy_active = false;
                    self.proxy_deactivated_at = Some(Utc::now());
                    info!(
                        state = %state_name,
                        "Cloudflare proxy DEACTIVATED — direct access restored"
                    );
                    return true;
                }
                Err(e) => {
                    warn!(error = %e, "failed to deactivate Cloudflare proxy");
                }
            }
        }

        false
    }

    /// Call Cloudflare API to set proxy state.
    pub async fn set_proxy(&self, proxied: bool) -> Result<()> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            self.config.zone_id, self.config.record_id
        );

        let resp = self
            .client
            .patch(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({"proxied": proxied}))
            .send()
            .await
            .context("Cloudflare API request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Cloudflare API returned {status}: {body}");
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse Cloudflare response")?;

        if data["success"].as_bool() != Some(true) {
            anyhow::bail!("Cloudflare API returned success=false: {}", data["errors"]);
        }

        Ok(())
    }

    /// Get current failover status.
    pub fn status(&self) -> FailoverStatus {
        FailoverStatus {
            enabled: self.config.enabled,
            proxy_active: self.proxy_active,
            proxy_activated_at: self.proxy_activated_at.map(|t| t.to_rfc3339()),
            proxy_deactivated_at: self.proxy_deactivated_at.map(|t| t.to_rfc3339()),
            activation_count: self.activation_count,
        }
    }

    /// Is the proxy currently active?
    pub fn is_active(&self) -> bool {
        self.proxy_active
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(enabled: bool) -> CloudflareFailoverConfig {
        CloudflareFailoverConfig {
            enabled,
            api_token: "test-token".to_string(),
            zone_id: "test-zone".to_string(),
            record_id: "test-record".to_string(),
            activate_on: vec!["UnderAttack".to_string(), "Critical".to_string()],
            min_proxy_duration_secs: 300,
        }
    }

    #[test]
    fn disabled_does_nothing() {
        // Disabled path: failover should remain inactive with zero activations
        // when the feature toggle is off.
        let failover = CloudflareFailover::new(make_config(false));
        assert!(!failover.is_active());
        assert_eq!(failover.status().activation_count, 0);
    }

    #[test]
    fn status_reports_correctly() {
        // Status path: initial state should be inactive with no timestamps.
        let failover = CloudflareFailover::new(make_config(true));
        let status = failover.status();
        assert!(status.enabled);
        assert!(!status.proxy_active);
        assert!(status.proxy_activated_at.is_none());
    }

    #[test]
    fn default_config() {
        // Default path: baseline configuration should keep auto-failover off
        // and use a 5-minute minimum proxy duration.
        let config = CloudflareFailoverConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.min_proxy_duration_secs, 300);
        assert_eq!(config.activate_on.len(), 2);
    }

    #[test]
    fn activate_on_contains_correct_states() {
        // Trigger path: activation states should include only attack levels.
        let config = make_config(true);
        assert!(config.activate_on.contains(&"UnderAttack".to_string()));
        assert!(config.activate_on.contains(&"Critical".to_string()));
        assert!(!config.activate_on.contains(&"Normal".to_string()));
        assert!(!config.activate_on.contains(&"Elevated".to_string()));
    }

    #[test]
    fn disabled_config_preserves_inactive_status_snapshot() {
        // Guard path: disabled failover should remain inactive and expose no
        // activation timestamps in status snapshots.
        let failover = CloudflareFailover::new(make_config(false));
        let status = failover.status();
        assert!(!status.enabled);
        assert!(!status.proxy_active);
        assert!(status.proxy_activated_at.is_none());
    }

    #[test]
    fn status_reflects_manually_set_activation_metadata() {
        // Serialization path: status output should expose activation timestamps
        // and counters when state has already been toggled.
        let mut failover = CloudflareFailover::new(make_config(true));
        let now = Utc::now();
        failover.proxy_active = true;
        failover.proxy_activated_at = Some(now);
        failover.proxy_deactivated_at = Some(now);
        failover.activation_count = 4;

        let status = failover.status();
        assert!(status.proxy_active);
        assert_eq!(status.activation_count, 4);
        assert!(status.proxy_activated_at.is_some());
        assert!(status.proxy_deactivated_at.is_some());
    }

    #[test]
    fn is_active_tracks_internal_proxy_flag() {
        // Accessor path: `is_active` should mirror the internal proxy state
        // used by orchestration logic.
        let mut failover = CloudflareFailover::new(make_config(true));
        assert!(!failover.is_active());
        failover.proxy_active = true;
        assert!(failover.is_active());
    }
}
