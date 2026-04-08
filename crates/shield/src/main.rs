// main.rs — Inner Warden Shield daemon
//
// Spawns: event ingest loop (every 2s), escalation ticker (every 5s),
// state persistence (every 30s), and the HTTP API server.

use innerwarden_shield::api;
use innerwarden_shield::attack_classifier;
use innerwarden_shield::bgp_monitor;
use innerwarden_shield::cloudflare_failover;
use innerwarden_shield::escalation;
use innerwarden_shield::ingest;
use innerwarden_shield::origin_lockdown;
use innerwarden_shield::rate_limiter;
use innerwarden_shield::store;
use innerwarden_shield::syn_tracker;
use innerwarden_shield::tcp_fingerprint;
use innerwarden_shield::telegram_notify;
use innerwarden_shield::xdp_manager;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

use innerwarden_shield::api::AppState;
use innerwarden_shield::attack_classifier::{AttackClassifier, ClassifierSignals};
use innerwarden_shield::escalation::{EscalationConfig, EscalationEngine};
use innerwarden_shield::ingest::EventIngestor;
use innerwarden_shield::rate_limiter::{IpRateLimiter, RateLimiterConfig};
use innerwarden_shield::store::{ShieldState, Store};
use innerwarden_shield::syn_tracker::{SynFloodConfig, SynFloodDetector};
use innerwarden_shield::tcp_fingerprint::TcpFingerprinter;
use innerwarden_shield::xdp_manager::XdpManager;

// ---------------------------------------------------------------------------
// CLI arguments
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "innerwarden-shield")]
#[command(
    about = "DDoS protection module — adaptive XDP rate limiting, SYN flood detection, auto-escalation"
)]
#[command(version)]
struct Args {
    /// Directory containing Inner Warden event JSONL files.
    #[arg(long, default_value = "./data")]
    data_dir: PathBuf,

    /// Directory for shield state persistence.
    #[arg(long, default_value = "./shield-data")]
    shield_dir: PathBuf,

    /// Address to bind the HTTP API.
    #[arg(long, default_value = "127.0.0.1:9090")]
    bind: String,

    /// Path to pinned BPF maps.
    #[arg(long, default_value = "/sys/fs/bpf/innerwarden")]
    bpf_path: String,

    /// Dry-run mode: do not execute bpftool commands.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

struct ShieldDaemon {
    rate_limiter: IpRateLimiter,
    syn_detector: SynFloodDetector,
    escalation: EscalationEngine,
    classifier: AttackClassifier,
    fingerprinter: TcpFingerprinter,
    xdp: XdpManager,
    ingestor: EventIngestor,
    store: Store,
    api_state: Arc<AppState>,
    cloudflare_failover: Option<cloudflare_failover::CloudflareFailover>,
    origin_lockdown: origin_lockdown::OriginLockdown,
    telegram: Option<telegram_notify::TelegramNotifier>,
    default_rl_config: RateLimiterConfig,
    /// Boot timestamp — skip escalation during warmup (first 30s) to avoid
    /// false positives from reading backlogged events.
    boot_time: chrono::DateTime<chrono::Utc>,
}

impl ShieldDaemon {
    fn new(args: &Args) -> Result<Self> {
        let store = Store::new(&args.shield_dir);
        let saved = store.load_state()?;
        let ddos_history = store.load_ddos_history()?;

        let rl_config = RateLimiterConfig::default();
        let rate_limiter = IpRateLimiter::new(rl_config.clone());
        let syn_detector = SynFloodDetector::new(SynFloodConfig::default());

        let esc_config = EscalationConfig::default();
        let mut escalation = EscalationEngine::new(esc_config);

        // Restore escalation state.
        let entered_at = saved
            .state_entered_at
            .parse()
            .unwrap_or_else(|_| chrono::Utc::now());
        escalation.restore(saved.escalation_state, entered_at, ddos_history);

        let classifier = AttackClassifier::new();
        let fingerprinter = TcpFingerprinter::new();
        let mut xdp = XdpManager::new(&args.bpf_path).with_dry_run(args.dry_run);

        // Restore blocked IPs.
        for entry in &saved.blocked_ips {
            let _ = xdp.add_to_blocklist(&entry.ip, &entry.reason);
        }

        let ingestor = EventIngestor::new(&args.data_dir);
        let api_state = Arc::new(AppState::new());

        // Cloudflare failover (configured via env vars)
        let cf_failover = if std::env::var("SHIELD_CLOUDFLARE_ENABLED").is_ok() {
            let config = cloudflare_failover::CloudflareFailoverConfig {
                enabled: true,
                api_token: std::env::var("SHIELD_CLOUDFLARE_TOKEN").unwrap_or_default(),
                zone_id: std::env::var("SHIELD_CLOUDFLARE_ZONE_ID").unwrap_or_default(),
                record_id: std::env::var("SHIELD_CLOUDFLARE_RECORD_ID").unwrap_or_default(),
                ..Default::default()
            };
            if config.api_token.is_empty()
                || config.zone_id.is_empty()
                || config.record_id.is_empty()
            {
                tracing::warn!(
                    "Cloudflare failover enabled but missing token/zone/record — disabled"
                );
                None
            } else {
                tracing::info!("Cloudflare auto-failover ENABLED — will activate proxy on DDoS");
                Some(cloudflare_failover::CloudflareFailover::new(config))
            }
        } else {
            None
        };

        Ok(Self {
            rate_limiter,
            syn_detector,
            escalation,
            classifier,
            fingerprinter,
            xdp,
            ingestor,
            store,
            api_state,
            cloudflare_failover: cf_failover,
            origin_lockdown: origin_lockdown::OriginLockdown::new(),
            telegram: telegram_notify::TelegramNotifier::from_env(),
            default_rl_config: RateLimiterConfig::default(),
            boot_time: chrono::Utc::now(),
        })
    }

    /// Main processing tick (called every 2s).
    async fn run_tick(&mut self) -> Result<()> {
        let now = chrono::Utc::now();

        // 1. Ingest new events.
        let events = self.ingestor.poll()?;
        let event_count = events.len();

        // 2. Process events through rate limiter, SYN tracker, fingerprinter.
        let mut new_blocks = 0u64;
        for event in &events {
            let decision =
                self.rate_limiter
                    .process_packet(&event.ip, event.bytes, event.timestamp);

            if decision == rate_limiter::RateLimitDecision::Drop {
                new_blocks += 1;
                let _ = self
                    .xdp
                    .add_to_blocklist(&event.ip, &format!("rate_limit:{}", event.kind));
            }

            if event.is_syn {
                self.syn_detector.record_syn(&event.ip, event.timestamp);
            }
            if event.is_syn_ack {
                self.syn_detector.record_ack(&event.ip, event.timestamp);
            }

            // Feed fingerprinter with default TCP params (real values come from eBPF).
            self.fingerprinter
                .record_connection(&event.ip, 65535, 64, event.timestamp);
        }

        // 3. Check SYN flood IPs.
        let syn_flagged = self.syn_detector.get_flagged_ips();
        for ip in &syn_flagged {
            let _ = self.xdp.add_to_blocklist(ip, "syn_flood");
        }

        // 4. Classify attacks.
        let syn_flood_active = !syn_flagged.is_empty()
            || self.syn_detector.check_global() != syn_tracker::SynVerdict::Normal;
        let rl_metrics = self.rate_limiter.get_metrics();

        let signals = ClassifierSignals {
            syn_flood_active,
            syn_flood_ips: syn_flagged.clone(),
            total_dropped: rl_metrics.total_dropped,
            peak_pps: rl_metrics.total_dropped, // simplified
            timestamp: now,
            ..Default::default()
        };
        self.classifier.classify(&signals);

        // 5. Build DDoS metrics and evaluate escalation.
        let dropped_per_sec = if event_count > 0 {
            new_blocks / 2 // per 2s tick
        } else {
            0
        };

        let metrics = self.escalation.build_metrics(
            dropped_per_sec,
            rl_metrics.blocked_ips,
            syn_flood_active,
            false, // udp_flood
            false, // http_flood
            rl_metrics.total_dropped,
            rl_metrics.total_allowed,
            rl_metrics.total_dropped, // simplified peak_pps
        );

        // During warmup (first 30s), feed metrics but don't act on backlog-triggered escalations
        let in_warmup = (now - self.boot_time).num_seconds() < 10;

        if let Some(transition) = self.escalation.update(&metrics) {
            // Ignore escalations during warmup (backlog false positives)
            if in_warmup {
                tracing::info!(
                    "Shield: ignoring warmup escalation {} → {}",
                    transition.from,
                    transition.to
                );
                // Reset back to Normal
                self.escalation.restore(
                    escalation::EscalationState::Normal,
                    now,
                    self.escalation.incidents().to_vec(),
                );
            } else {
                let factor = transition.to.rate_limit_factor();
                let mut config = self.default_rl_config.clone();
                config.bucket_max_tokens *= factor;
                config.bucket_refill_rate *= factor;
                config.window_max_rate = (config.window_max_rate as f64 * factor).max(1.0) as u64;
                self.rate_limiter.reset_config(config);

                tracing::warn!(
                    from = %transition.from,
                    to = %transition.to,
                    factor,
                    "Applied escalation rate limit adjustment"
                );

                // 5a-tg. Telegram notification on escalation
                if let Some(ref tg) = self.telegram {
                    let cf_active = self
                        .cloudflare_failover
                        .as_ref()
                        .is_some_and(|f| f.is_active());
                    tg.notify_escalation(
                        &format!("{}", transition.from),
                        &format!("{}", transition.to),
                        dropped_per_sec,
                        rl_metrics.blocked_ips,
                        cf_active,
                    )
                    .await;
                }
                // Write incident to JSONL so it appears on the live feed / dashboard
                write_shield_incident(
                    &self.ingestor.data_dir(),
                    &format!("{}", transition.from),
                    &format!("{}", transition.to),
                    dropped_per_sec,
                    rl_metrics.blocked_ips,
                );
            } // close else (non-warmup)
        }

        // 5b. Cloudflare auto-failover on escalation.
        if let Some(ref mut failover) = self.cloudflare_failover {
            failover.check_and_toggle(self.escalation.state()).await;
        }

        // 5b2. Origin lockdown: restrict HTTP/HTTPS to Cloudflare CIDRs only.
        self.origin_lockdown
            .check_and_toggle(self.escalation.state());

        // 5c. Adaptive kernel rate limiting via eBPF PID_RATE_LIMIT map.
        // On escalation, tighten the kernel-level per-PID rate limit.
        // Normal=100ms, Elevated=50ms, UnderAttack=20ms, Critical=10ms.
        if let Some(ref transition) = self.escalation.last_transition().cloned() {
            let rate_ns: u64 = match transition.to {
                escalation::EscalationState::Normal => 100_000_000, // 100ms
                escalation::EscalationState::Elevated => 50_000_000, // 50ms
                escalation::EscalationState::UnderAttack => 20_000_000, // 20ms
                escalation::EscalationState::Critical => 10_000_000, // 10ms
            };
            // Update the kernel rate limit via bpftool (best-effort)
            let _ = std::process::Command::new("bpftool")
                .args([
                    "map",
                    "update",
                    "pinned",
                    &format!("{}/PID_RATE_LIMIT_CONFIG", self.xdp.bpf_path()),
                    "key",
                    "0x00",
                    "0x00",
                    "0x00",
                    "0x00",
                    "value",
                    &format!("0x{:02x}", (rate_ns & 0xFF)),
                    &format!("0x{:02x}", ((rate_ns >> 8) & 0xFF)),
                    &format!("0x{:02x}", ((rate_ns >> 16) & 0xFF)),
                    &format!("0x{:02x}", ((rate_ns >> 24) & 0xFF)),
                    &format!("0x{:02x}", ((rate_ns >> 32) & 0xFF)),
                    &format!("0x{:02x}", ((rate_ns >> 40) & 0xFF)),
                    &format!("0x{:02x}", ((rate_ns >> 48) & 0xFF)),
                    &format!("0x{:02x}", ((rate_ns >> 56) & 0xFF)),
                ])
                .output();
            tracing::info!(
                state = %transition.to,
                rate_ms = rate_ns / 1_000_000,
                "Adaptive kernel rate limit adjusted"
            );
        }

        // 5d. XDP blocklist TTL — remove IPs blocked >5min when de-escalating.
        if self.escalation.state() == escalation::EscalationState::Normal {
            self.xdp
                .cleanup_stale(std::time::Duration::from_secs(300), now);
        }

        // 6. Decay stale entries.
        self.rate_limiter
            .cleanup_stale(std::time::Duration::from_secs(300), now);
        self.syn_detector.expire_all(now);
        self.fingerprinter
            .cleanup_stale(std::time::Duration::from_secs(600), now);

        // 7. Update API state.
        {
            let mut m = self.api_state.metrics.write().await;
            *m = Some(metrics);
        }
        {
            let blocked = self.rate_limiter.get_blocked_ips();
            let mut b = self.api_state.blocked_ips.write().await;
            *b = blocked
                .iter()
                .map(|bp| api::BlockedIpInfo {
                    ip: bp.ip.clone(),
                    reason: bp.reason.clone(),
                    blocked_since: bp.blocked_at.to_rfc3339(),
                    duration_secs: (now - bp.blocked_at).num_seconds(),
                    packets_dropped: bp.total_packets,
                })
                .collect();
        }
        {
            let mut h = self.api_state.metrics_history.write().await;
            let active_types: Vec<String> = self
                .classifier
                .active_attacks()
                .iter()
                .map(|a| format!("{}", a.attack_type))
                .collect();
            h.push(api::MetricsSnapshot {
                timestamp: now.to_rfc3339(),
                packets_per_sec: dropped_per_sec,
                drops_per_sec: dropped_per_sec,
                escalation_level: format!("{}", self.escalation.state()),
                attack_types: active_types,
            });
            if h.len() > 1000 {
                let drain = h.len() - 1000;
                h.drain(0..drain);
            }
        }
        {
            let mut i = self.api_state.incidents.write().await;
            *i = self.escalation.incidents().to_vec();
        }
        {
            let mut a = self.api_state.attack_incidents.write().await;
            *a = self.classifier.all_attacks().into_iter().cloned().collect();
        }

        if event_count > 0 {
            tracing::info!(
                events = event_count,
                new_blocks,
                state = %self.escalation.state(),
                tracked = self.rate_limiter.tracked_count(),
                "Tick complete"
            );
        }

        Ok(())
    }

    fn save_state(&self) -> Result<()> {
        let state = ShieldState {
            escalation_state: self.escalation.state(),
            state_entered_at: self.escalation.state_entered_at().to_rfc3339(),
            blocked_ips: self.xdp.get_blocklist_entries().to_vec(),
            last_saved: chrono::Utc::now().to_rfc3339(),
        };
        self.store.save_state(&state)?;
        self.store.save_ddos_history(self.escalation.incidents())?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    tracing::info!(
        data_dir = ?args.data_dir,
        bind = %args.bind,
        shield_dir = ?args.shield_dir,
        bpf_path = %args.bpf_path,
        dry_run = args.dry_run,
        "Starting innerwarden-shield"
    );

    let mut daemon = ShieldDaemon::new(&args)?;

    // Initialize origin lockdown (creates ipset with Cloudflare CIDRs).
    daemon.origin_lockdown.init().await;

    let api_state = daemon.api_state.clone();

    // Start the API server.
    let bind_addr = args.bind.clone();
    let _api_handle = tokio::spawn(async move {
        if let Err(e) = api::serve(&bind_addr, api_state).await {
            tracing::error!(error = %e, "API server failed");
        }
    });

    // Start BGP hijack monitor (if configured via env vars).
    let bgp_telegram = telegram_notify::TelegramNotifier::from_env();
    if let Some(bgp) = bgp_monitor::BgpMonitor::from_env(&args.data_dir, bgp_telegram) {
        let bgp = Arc::new(bgp);
        tokio::spawn(bgp.run());
        tracing::info!("BGP hijack monitor spawned");
    }

    // Main processing loop.
    let mut tick_interval = tokio::time::interval(tokio::time::Duration::from_secs(2));
    let mut save_counter = 0u64;

    loop {
        tokio::select! {
            _ = tick_interval.tick() => {
                if let Err(e) = daemon.run_tick().await {
                    tracing::error!(error = %e, "Tick failed");
                }

                save_counter += 1;
                // Save state every 15 ticks (30 seconds).
                if save_counter % 15 == 0 {
                    if let Err(e) = daemon.save_state() {
                        tracing::error!(error = %e, "Failed to save state");
                    }
                }
                // Refresh Cloudflare CIDRs every 10800 ticks (6 hours).
                if save_counter % 10800 == 0 {
                    daemon.origin_lockdown.refresh_cidrs().await;
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Shutting down...");
                // Deactivate origin lockdown to restore direct access
                let _ = daemon.origin_lockdown.deactivate();
                if let Err(e) = daemon.save_state() {
                    tracing::error!(error = %e, "Failed to save state on shutdown");
                }
                break;
            }
        }
    }

    Ok(())
}

/// Write a Shield escalation incident to the agent's incidents JSONL file
/// so it appears on the live feed and dashboard.
fn write_shield_incident(
    data_dir: &std::path::Path,
    from: &str,
    to: &str,
    drops_per_sec: u64,
    attackers: usize,
) {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let path = data_dir.join(format!("incidents-{today}.jsonl"));

    let severity = match to {
        "Critical" => "critical",
        "Under Attack" => "high",
        "Elevated" => "medium",
        _ => "low",
    };

    let incident = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "host": gethostname(),
        "incident_id": format!("shield:escalation:{}:{}", to.to_lowercase().replace(' ', "_"), chrono::Utc::now().format("%Y-%m-%dT%H:%MZ")),
        "severity": severity,
        "title": format!("Shield escalated: {from} → {to}"),
        "summary": format!("DDoS protection level changed from {from} to {to}. Drops/sec: {drops_per_sec}, active attackers: {attackers}."),
        "evidence": [{ "drops_per_sec": drops_per_sec, "attackers": attackers, "from": from, "to": to }],
        "recommended_checks": ["Check innerwarden-shield logs", "Review blocked IPs"],
        "tags": ["shield", "ddos", "escalation"],
        "entities": [],
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

pub(crate) fn gethostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}
