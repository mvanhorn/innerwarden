use std::io::Write;
use std::path::Path;

use tracing::{info, warn};

use innerwarden_shield::attack_classifier::AttackClassifier;
use innerwarden_shield::escalation::{EscalationConfig, EscalationEngine, EscalationState};
use innerwarden_shield::rate_limiter::{IpRateLimiter, RateLimitDecision, RateLimiterConfig};
use innerwarden_shield::store::Store;
use innerwarden_shield::syn_tracker::{SynFloodConfig, SynFloodDetector};
use innerwarden_shield::tcp_fingerprint::TcpFingerprinter;
use innerwarden_shield::xdp_manager::XdpManager;

/// Shield state held in the agent.
#[allow(dead_code)]
pub(crate) struct ShieldState {
    pub rate_limiter: IpRateLimiter,
    pub syn_detector: SynFloodDetector,
    pub escalation: EscalationEngine,
    pub classifier: AttackClassifier,
    pub fingerprinter: TcpFingerprinter,
    pub xdp: XdpManager,
    pub store: Store,
    pub tick_counter: u64,
    default_rl_config: RateLimiterConfig,
}

impl ShieldState {
    pub fn new(shield_dir: &Path, bpf_path: &str, dry_run: bool) -> Self {
        std::fs::create_dir_all(shield_dir).ok();
        let store = Store::new(shield_dir);
        let xdp = XdpManager::new(bpf_path).with_dry_run(dry_run);

        // Load persisted state
        let saved = store.load_state().ok();
        let escalation_config = EscalationConfig::default();
        let mut escalation = EscalationEngine::new(escalation_config);
        if let Some(ref state) = saved {
            let entered_at = state
                .state_entered_at
                .parse()
                .unwrap_or_else(|_| chrono::Utc::now());
            let ddos_history = store.load_ddos_history().unwrap_or_default();
            escalation.restore(state.escalation_state, entered_at, ddos_history);
        }

        let rl_config = RateLimiterConfig::default();

        Self {
            rate_limiter: IpRateLimiter::new(rl_config.clone()),
            syn_detector: SynFloodDetector::new(SynFloodConfig::default()),
            escalation,
            classifier: AttackClassifier::new(),
            fingerprinter: TcpFingerprinter::new(),
            xdp,
            store,
            tick_counter: 0,
            default_rl_config: rl_config,
        }
    }
}

/// Process a batch of sensor events through the shield pipeline.
/// Returns the number of drops, any new incidents, and IPs that were blocked by the shield.
/// `ip_risk_scores` provides attacker intel risk scores (0-100) for known IPs;
/// IPs with risk > 60 get 2x tighter rate limits (pre-emptive defense).
pub(crate) fn process_events(
    shield: &mut ShieldState,
    events: &[innerwarden_core::event::Event],
    ip_risk_scores: &std::collections::HashMap<String, u8>,
) -> (u64, Vec<serde_json::Value>, Vec<String>) {
    let mut drops = 0u64;
    let mut incidents = Vec::new();
    let mut blocked_ips = Vec::new();
    let now = chrono::Utc::now();

    for event in events {
        // Extract source IP from event
        let ip = event
            .details
            .get("src_ip")
            .or_else(|| event.details.get("ip"))
            .and_then(|v| v.as_str());

        let Some(ip) = ip else { continue };

        // Skip non-network events
        let is_network = event.kind.starts_with("network.")
            || event.kind.starts_with("ssh.")
            || event.kind.starts_with("http.")
            || event.kind.starts_with("dns.")
            || event.kind == "port_scan"
            || event.kind == "web_scan"
            || event.kind == "credential_stuffing";

        if !is_network {
            continue;
        }

        // Known high-risk IPs get tighter rate limits (pre-emptive defense).
        // Reduces effective bytes by 2x so they hit the limit faster.
        let risk = ip_risk_scores.get(ip).copied().unwrap_or(0);
        let effective_bytes = {
            let raw = event
                .details
                .get("bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(64);
            if risk > 60 {
                raw * 2
            } else {
                raw
            }
        };

        // Feed rate limiter
        let decision = shield.rate_limiter.process_packet(ip, effective_bytes, now);

        if matches!(decision, RateLimitDecision::Drop) {
            drops += 1;
            // Add to XDP blocklist
            let reason = format!("shield:rate_limit:{}", event.kind);
            if let Err(e) = shield.xdp.add_to_blocklist(ip, &reason) {
                warn!(ip, error = %e, "shield: failed to add to XDP blocklist");
            } else {
                blocked_ips.push(ip.to_string());
            }
        }

        // Track SYN/ACK for SYN flood detection
        if event.kind == "network.syn" || event.kind.contains("syn") {
            shield.syn_detector.record_syn(ip, now);
        }
        if event.kind == "network.ack" || event.kind.contains("established") {
            shield.syn_detector.record_ack(ip, now);
        }

        // TCP fingerprinting
        let window_size = event
            .details
            .get("window_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;
        let ttl = event
            .details
            .get("ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(64) as u8;
        if window_size > 0 {
            shield
                .fingerprinter
                .record_connection(ip, window_size, ttl, now);
        }
    }

    // Escalation tick (every 5 ticks = 10s at 2s poll)
    shield.tick_counter += 1;
    if shield.tick_counter.is_multiple_of(5) {
        let syn_flagged = shield.syn_detector.get_flagged_ips();
        let rl_metrics = shield.rate_limiter.get_metrics();

        let metrics = shield.escalation.build_metrics(
            drops / 2, // per-second rate (2s window)
            rl_metrics.blocked_ips,
            !syn_flagged.is_empty(),
            false, // udp_flood
            false, // http_flood
            rl_metrics.total_dropped,
            rl_metrics.total_allowed,
            rl_metrics.total_dropped, // simplified peak_pps
        );

        if let Some(transition) = shield.escalation.update(&metrics) {
            info!(
                from = %transition.from,
                to = %transition.to,
                "shield: escalation state changed"
            );

            // Apply rate limit factor for new state
            let factor = transition.to.rate_limit_factor();
            let mut config = shield.default_rl_config.clone();
            config.bucket_max_tokens *= factor;
            config.bucket_refill_rate *= factor;
            config.window_max_rate = (config.window_max_rate as f64 * factor).max(1.0) as u64;
            shield.rate_limiter.reset_config(config);

            // Create incident for the transition
            let severity = match transition.to {
                EscalationState::Critical => "critical",
                EscalationState::UnderAttack => "high",
                EscalationState::Elevated => "medium",
                _ => "low",
            };

            let host = std::fs::read_to_string("/etc/hostname")
                .unwrap_or_else(|_| "unknown".to_string())
                .trim()
                .to_string();

            let incident = serde_json::json!({
                "ts": chrono::Utc::now().to_rfc3339(),
                "host": host,
                "incident_id": format!("shield:escalation:{}:{}",
                    format!("{:?}", transition.to).to_lowercase(),
                    chrono::Utc::now().format("%Y-%m-%dT%H:%MZ")),
                "severity": severity,
                "title": format!("Shield escalation: {} \u{2192} {}", transition.from, transition.to),
                "summary": format!(
                    "DDoS protection escalated. Drops/sec: {}, Attackers: {}, SYN flood: {}",
                    drops / 2, rl_metrics.blocked_ips, !syn_flagged.is_empty()
                ),
                "tags": ["shield", "ddos", "escalation"],
                "entities": [],
            });
            incidents.push(incident);
        }

        // Persist state every 30s (every 6 escalation ticks = 30 main ticks)
        if shield.tick_counter.is_multiple_of(30) {
            let state = innerwarden_shield::store::ShieldState {
                escalation_state: shield.escalation.state(),
                state_entered_at: shield.escalation.state_entered_at().to_rfc3339(),
                blocked_ips: shield.xdp.get_blocklist_entries().to_vec(),
                last_saved: chrono::Utc::now().to_rfc3339(),
            };
            shield.store.save_state(&state).ok();
            shield
                .store
                .save_ddos_history(shield.escalation.incidents())
                .ok();
            // Cleanup stale entries
            shield
                .rate_limiter
                .cleanup_stale(std::time::Duration::from_secs(300), now);
            shield.syn_detector.expire_all(now);
            shield
                .fingerprinter
                .cleanup_stale(std::time::Duration::from_secs(300), now);
        }
    }

    (drops, incidents, blocked_ips)
}

/// Write shield incidents to the daily JSONL file.
pub(crate) fn write_incidents(data_dir: &Path, incidents: &[serde_json::Value]) {
    if incidents.is_empty() {
        return;
    }

    let today = chrono::Local::now().date_naive().format("%Y-%m-%d");
    let path = data_dir.join(format!("incidents-{today}.jsonl"));

    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut f) => {
            for inc in incidents {
                if let Ok(line) = serde_json::to_string(inc) {
                    let _ = writeln!(f, "{line}");
                }
            }
            info!(count = incidents.len(), "shield: emitted incidents");
        }
        Err(e) => warn!(error = %e, "shield: failed to write incidents"),
    }
}

/// Notify via Telegram for shield escalation events.
pub(crate) fn notify_telegram(
    telegram_client: &Option<std::sync::Arc<crate::telegram::TelegramClient>>,
    incidents: &[serde_json::Value],
) {
    let Some(tg) = telegram_client else { return };

    for inc in incidents {
        let severity = inc
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("low");
        if severity != "critical" && severity != "high" {
            continue;
        }

        let title = inc
            .get("title")
            .and_then(|t| t.as_str())
            .unwrap_or("Shield alert");
        let summary = inc.get("summary").and_then(|s| s.as_str()).unwrap_or("");

        let emoji = if severity == "critical" {
            "\u{1f534}"
        } else {
            "\u{1f7e0}"
        };
        let msg = format!(
            "\u{1f6e1}\u{fe0f} <b>DDoS Shield</b>\n\n\
             {emoji} {}\n\
             <b>{title}</b>\n\
             {summary}",
            severity.to_uppercase(),
        );
        let tg = tg.clone();
        tokio::spawn(async move {
            let _ = tg.send_alert_html(&msg).await;
        });
    }
}
