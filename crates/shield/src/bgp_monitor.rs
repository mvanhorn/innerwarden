// bgp_monitor.rs — BGP hijack detection via RIPE Stat API
//
// Polls the RIPE Stat routing-status API every 5 minutes and checks
// that all BGP announcements for the operator's prefix originate from
// the expected ASN. Alerts via Telegram and writes incidents to JSONL.
//
// Reference: DFOH (USENIX NSDI 2024) — simplified for single-prefix monitoring.
// API: https://stat.ripe.net/data/routing-status/data.json?resource=PREFIX

use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BgpMonitorConfig {
    /// The IP prefix to monitor (e.g. "130.162.160.0/19").
    pub prefix: String,
    /// The expected origin ASN (e.g. 31898). Announcements from
    /// other ASNs for this prefix trigger a hijack alert.
    pub origin_asn: u32,
    /// Poll interval in seconds (default: 300 = 5 minutes).
    pub poll_interval_secs: u64,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BgpStatus {
    /// Whether the monitor has successfully polled at least once.
    pub connected: bool,
    /// Total polls completed.
    pub polls_completed: u64,
    /// Number of hijack alerts raised.
    pub hijack_alerts: u64,
    /// All origin ASNs currently seen for our prefix.
    pub observed_origins: Vec<u32>,
    /// Number of RIPE RIS peers seeing our prefix.
    pub peer_count: usize,
    /// Last poll timestamp.
    pub last_poll: Option<String>,
    /// Active hijack: the offending ASN, if any.
    pub active_hijack_asn: Option<u32>,
    /// Last error message, if any.
    pub last_error: Option<String>,
}

// ---------------------------------------------------------------------------
// Monitor
// ---------------------------------------------------------------------------

pub struct BgpMonitor {
    config: BgpMonitorConfig,
    pub status: Arc<RwLock<BgpStatus>>,
    data_dir: std::path::PathBuf,
    telegram: Option<crate::telegram_notify::TelegramNotifier>,
    cloudflare: Option<tokio::sync::Mutex<crate::cloudflare_failover::CloudflareFailover>>,
    client: reqwest::Client,
}

impl BgpMonitor {
    /// Create from environment variables. Returns None if not configured.
    ///
    /// Env vars:
    ///   SHIELD_BGP_PREFIX    — e.g. "130.162.160.0/19"
    ///   SHIELD_BGP_ORIGIN_AS — e.g. "31898"
    pub fn from_env(
        data_dir: &Path,
        telegram: Option<crate::telegram_notify::TelegramNotifier>,
    ) -> Option<Self> {
        let prefix = std::env::var("SHIELD_BGP_PREFIX").ok()?;
        let origin_asn: u32 = std::env::var("SHIELD_BGP_ORIGIN_AS").ok()?.parse().ok()?;

        if prefix.is_empty() {
            return None;
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .ok()?;

        // Cloudflare failover for BGP hijack response
        let cloudflare = if std::env::var("SHIELD_CLOUDFLARE_ENABLED").is_ok() {
            let cf_config = crate::cloudflare_failover::CloudflareFailoverConfig {
                enabled: true,
                api_token: std::env::var("SHIELD_CLOUDFLARE_TOKEN").unwrap_or_default(),
                zone_id: std::env::var("SHIELD_CLOUDFLARE_ZONE_ID").unwrap_or_default(),
                record_id: std::env::var("SHIELD_CLOUDFLARE_RECORD_ID").unwrap_or_default(),
                ..Default::default()
            };
            if cf_config.api_token.is_empty()
                || cf_config.zone_id.is_empty()
                || cf_config.record_id.is_empty()
            {
                None
            } else {
                info!("BGP monitor: Cloudflare auto-failover available for hijack response");
                Some(tokio::sync::Mutex::new(
                    crate::cloudflare_failover::CloudflareFailover::new(cf_config),
                ))
            }
        } else {
            None
        };

        info!(
            prefix = %prefix,
            origin_asn,
            cloudflare_failover = cloudflare.is_some(),
            "BGP hijack monitor enabled"
        );

        Some(Self {
            config: BgpMonitorConfig {
                prefix,
                origin_asn,
                poll_interval_secs: 300,
            },
            status: Arc::new(RwLock::new(BgpStatus::default())),
            data_dir: data_dir.to_owned(),
            telegram,
            cloudflare,
            client,
        })
    }

    /// Run the monitor loop. Polls RIPE Stat every 5 minutes.
    pub async fn run(self: Arc<Self>) {
        // Initial poll after 10s (let the daemon warm up)
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

        loop {
            match self.poll_ripe_stat().await {
                Ok(()) => {}
                Err(e) => {
                    warn!(error = %e, "BGP monitor: poll failed");
                    let mut s = self.status.write().await;
                    s.last_error = Some(format!("{e}"));
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(
                self.config.poll_interval_secs,
            ))
            .await;
        }
    }

    /// Poll RIPE Stat for current routing status of our prefix.
    async fn poll_ripe_stat(&self) -> anyhow::Result<()> {
        let url = format!(
            "https://stat.ripe.net/data/routing-status/data.json?resource={}",
            self.config.prefix
        );

        let response = self.client.get(&url).send().await?;
        if !response.status().is_success() {
            anyhow::bail!("RIPE Stat returned status {}", response.status());
        }

        let body: serde_json::Value = response.json().await?;
        let now = chrono::Utc::now();

        // RIPE Stat routing-status format:
        // data.origins: [{ "origin": 31898, "route_objects": [...] }]
        // data.visibility.v4.ris_peers_seeing: 327
        // data.last_seen.origin: "31898"
        let origins = body.pointer("/data/origins").and_then(|o| o.as_array());

        let total_peers = body
            .pointer("/data/visibility/v4/ris_peers_seeing")
            .and_then(|p| p.as_u64())
            .unwrap_or(0) as usize;

        // Collect all origin ASNs
        let mut observed_asns: Vec<u32> = Vec::new();
        let mut rogue_asns: Vec<u32> = Vec::new();

        // Primary: from origins array
        if let Some(origins) = origins {
            for origin_obj in origins {
                let asn = origin_obj
                    .get("origin")
                    .and_then(|o| o.as_u64())
                    .map(|n| n as u32);
                if let Some(asn) = asn {
                    if !observed_asns.contains(&asn) {
                        observed_asns.push(asn);
                    }
                    if asn != self.config.origin_asn && !rogue_asns.contains(&asn) {
                        rogue_asns.push(asn);
                    }
                }
            }
        }

        // Fallback: from last_seen.origin
        if observed_asns.is_empty() {
            if let Some(asn_str) = body
                .pointer("/data/last_seen/origin")
                .and_then(|o| o.as_str())
            {
                if let Ok(asn) = asn_str.parse::<u32>() {
                    observed_asns.push(asn);
                    if asn != self.config.origin_asn {
                        rogue_asns.push(asn);
                    }
                }
            }
        }

        if observed_asns.is_empty() {
            // No origins found — prefix might not be announced
            let mut s = self.status.write().await;
            s.connected = true;
            s.polls_completed += 1;
            s.last_poll = Some(now.to_rfc3339());
            s.observed_origins.clear();
            s.peer_count = 0;
            return Ok(());
        }

        // Update status
        {
            let mut s = self.status.write().await;
            s.connected = true;
            s.polls_completed += 1;
            s.last_poll = Some(now.to_rfc3339());
            s.observed_origins = observed_asns.clone();
            s.peer_count = total_peers;
            s.last_error = None;
        }

        // Check for hijack
        if rogue_asns.is_empty() {
            // All good — clear any previous hijack
            let was_hijacked = {
                let mut s = self.status.write().await;
                let had = s.active_hijack_asn.is_some();
                if had {
                    info!(
                        prefix = %self.config.prefix,
                        origin_asn = self.config.origin_asn,
                        "BGP hijack cleared — only legitimate origin AS seen"
                    );
                    s.active_hijack_asn = None;
                }
                had
            };

            // Deactivate Cloudflare proxy when hijack is cleared
            if was_hijacked {
                if let Some(ref cf) = self.cloudflare {
                    let cf = cf.lock().await;
                    match cf.set_proxy(false).await {
                        Ok(()) => info!("Cloudflare proxy DEACTIVATED — BGP hijack resolved"),
                        Err(e) => {
                            warn!(error = %e, "Failed to deactivate Cloudflare proxy after hijack clear")
                        }
                    }
                }
            }
        } else {
            // Hijack detected!
            for &rogue in &rogue_asns {
                warn!(
                    prefix = %self.config.prefix,
                    expected_asn = self.config.origin_asn,
                    rogue_asn = rogue,
                    "BGP HIJACK DETECTED — unexpected origin AS for our prefix"
                );

                {
                    let mut s = self.status.write().await;
                    s.hijack_alerts += 1;
                    s.active_hijack_asn = Some(rogue);
                }

                // Write incident
                self.write_hijack_incident(rogue);

                // Telegram alert
                if let Some(ref tg) = self.telegram {
                    tg.notify_bgp_hijack(&self.config.prefix, self.config.origin_asn, rogue, None)
                        .await;
                }
            }

            // Activate Cloudflare proxy — route traffic through CF to bypass hijack
            if let Some(ref cf) = self.cloudflare {
                let cf = cf.lock().await;
                if !cf.is_active() {
                    match cf.set_proxy(true).await {
                        Ok(()) => {
                            warn!("Cloudflare proxy ACTIVATED — bypassing BGP hijack via edge");
                            // Notify about the failover
                            if let Some(ref tg) = self.telegram {
                                tg.notify_escalation(
                                    "Normal",
                                    "BGP Hijack",
                                    0,
                                    rogue_asns.len(),
                                    true,
                                )
                                .await;
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "CRITICAL: Failed to activate Cloudflare proxy during BGP hijack")
                        }
                    }
                }
            }
        }

        info!(
            prefix = %self.config.prefix,
            origins = ?observed_asns,
            peers = total_peers,
            hijack = !rogue_asns.is_empty(),
            "BGP poll complete"
        );

        Ok(())
    }

    /// Write a BGP hijack incident to the agent's incidents JSONL.
    fn write_hijack_incident(&self, rogue_asn: u32) {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = self.data_dir.join(format!("incidents-{today}.jsonl"));

        let incident = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "host": crate::gethostname(),
            "incident_id": format!("bgp_hijack:AS{}:{}", rogue_asn, chrono::Utc::now().timestamp()),
            "severity": "critical",
            "source": "shield_bgp",
            "summary": format!(
                "BGP hijack detected: AS{} announcing prefix {} (expected origin: AS{})",
                rogue_asn, self.config.prefix, self.config.origin_asn
            ),
            "details": {
                "prefix": self.config.prefix,
                "expected_origin_asn": self.config.origin_asn,
                "rogue_origin_asn": rogue_asn,
                "source_feed": "RIPE Stat API",
            },
        });

        if let Ok(line) = serde_json::to_string(&incident) {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                let _ = writeln!(f, "{line}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if `announced` covers `our_prefix`.
fn prefix_covers(announced: &str, our_prefix: &str) -> bool {
    if announced == our_prefix {
        return true;
    }

    let (ann_net, ann_len) = match parse_cidr(announced) {
        Some(v) => v,
        None => return false,
    };
    let (our_net, our_len) = match parse_cidr(our_prefix) {
        Some(v) => v,
        None => return false,
    };

    if ann_len > our_len {
        return false;
    }

    let mask = if ann_len == 0 {
        0u32
    } else {
        !0u32 << (32 - ann_len)
    };
    (ann_net & mask) == (our_net & mask)
}

/// Parse "a.b.c.d/len" into (network_u32, prefix_len).
fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (addr_str, len_str) = cidr.split_once('/')?;
    let len: u32 = len_str.parse().ok()?;
    let octets: Vec<u8> = addr_str.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() != 4 {
        return None;
    }
    let ip = ((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        | (octets[3] as u32);
    Some((ip, len))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_exact_match() {
        assert!(prefix_covers("130.162.160.0/19", "130.162.160.0/19"));
    }

    #[test]
    fn prefix_supernet_covers() {
        assert!(prefix_covers("130.162.0.0/16", "130.162.160.0/19"));
    }

    #[test]
    fn prefix_subnet_does_not_cover() {
        assert!(!prefix_covers("130.162.160.0/20", "130.162.160.0/19"));
    }

    #[test]
    fn prefix_different_net() {
        assert!(!prefix_covers("10.0.0.0/8", "130.162.160.0/19"));
    }

    #[test]
    fn prefix_default_route_covers_all() {
        assert!(prefix_covers("0.0.0.0/0", "130.162.160.0/19"));
    }

    #[test]
    fn parse_cidr_valid() {
        let (ip, len) = parse_cidr("130.162.160.0/19").unwrap();
        assert_eq!(len, 19);
        assert_eq!(ip, 0x82A2A000);
    }

    #[test]
    fn parse_cidr_invalid() {
        assert!(parse_cidr("not-a-cidr").is_none());
        assert!(parse_cidr("130.162.160.0").is_none());
    }
}
