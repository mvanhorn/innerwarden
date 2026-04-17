//! Lightweight Telegram notifier for Shield escalation events.
//!
//! Sends a message when the Shield escalates or de-escalates.
//! Reads TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID from env vars
//! (same vars as the agent — shared /etc/innerwarden/agent.env).

use tracing::{info, warn};

fn escalation_emoji(to: &str) -> &'static str {
    match to {
        "Elevated" => "⚠️",
        "Under Attack" => "🔥",
        "Critical" => "🚨",
        "Normal" => "✅",
        _ => "🛡️",
    }
}

fn cloudflare_status_suffix(cloudflare_active: bool) -> &'static str {
    if cloudflare_active {
        "\n☁️ Cloudflare proxy: <b>ACTIVE</b>"
    } else {
        ""
    }
}

fn build_escalation_message(
    from: &str,
    to: &str,
    dropped_per_sec: u64,
    active_attackers: usize,
    cloudflare_active: bool,
) -> String {
    let emoji = escalation_emoji(to);
    let cf_status = cloudflare_status_suffix(cloudflare_active);

    format!(
        "{emoji} <b>Shield: {to}</b>\n\
         \n\
         Escalation: {from} → {to}\n\
         📊 Drops/sec: {dropped_per_sec}\n\
         🎯 Active attackers: {active_attackers}{cf_status}\n\
         \n\
         <i>XDP + rate limiting adjusted automatically.</i>",
    )
}

fn build_bgp_hijack_message(
    prefix: &str,
    expected_asn: u32,
    rogue_asn: u32,
    peer_asn: Option<u32>,
) -> String {
    let peer_info = peer_asn
        .map(|peer| format!("\n👁 Seen via peer: AS{peer}"))
        .unwrap_or_default();

    format!(
        "🚨 <b>BGP HIJACK DETECTED</b>\n\
         \n\
         Prefix: <code>{prefix}</code>\n\
         Expected origin: <b>AS{expected_asn}</b>\n\
         Rogue origin: <b>AS{rogue_asn}</b>{peer_info}\n\
         \n\
         Source: RIPE RIS Live\n\
         \n\
         <i>An unauthorized AS is announcing your prefix.\n\
         This could redirect your traffic to an attacker.</i>",
    )
}

pub struct TelegramNotifier {
    bot_token: String,
    chat_id: String,
    client: reqwest::Client,
}

impl TelegramNotifier {
    /// Create from environment variables. Returns None if not configured.
    pub fn from_env() -> Option<Self> {
        let bot_token = std::env::var("TELEGRAM_BOT_TOKEN").ok()?;
        let chat_id = std::env::var("TELEGRAM_CHAT_ID").ok()?;
        if bot_token.is_empty() || chat_id.is_empty() {
            return None;
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .ok()?;
        info!("Shield Telegram notifications enabled");
        Some(Self {
            bot_token,
            chat_id,
            client,
        })
    }

    /// Send an escalation notification.
    pub async fn notify_escalation(
        &self,
        from: &str,
        to: &str,
        dropped_per_sec: u64,
        active_attackers: usize,
        cloudflare_active: bool,
    ) {
        let text = build_escalation_message(
            from,
            to,
            dropped_per_sec,
            active_attackers,
            cloudflare_active,
        );

        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);

        let result = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_notification": to == "Normal",
            }))
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                info!(from, to, "Shield Telegram notification sent");
            }
            Ok(resp) => {
                warn!(status = %resp.status(), "Shield Telegram notification failed");
            }
            Err(e) => {
                warn!(error = %e, "Shield Telegram notification error");
            }
        }
    }

    /// Send a BGP hijack alert.
    pub async fn notify_bgp_hijack(
        &self,
        prefix: &str,
        expected_asn: u32,
        rogue_asn: u32,
        peer_asn: Option<u32>,
    ) {
        let text = build_bgp_hijack_message(prefix, expected_asn, rogue_asn, peer_asn);

        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);

        let result = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "HTML",
            }))
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                info!(prefix, rogue_asn, "BGP hijack Telegram alert sent");
            }
            Ok(resp) => {
                warn!(status = %resp.status(), "BGP hijack Telegram alert failed");
            }
            Err(e) => {
                warn!(error = %e, "BGP hijack Telegram alert error");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escalation_emoji_maps_known_states() {
        // Mapping path: escalation states should keep stable emoji markers for
        // quick operator scanning in Telegram.
        assert_eq!(escalation_emoji("Elevated"), "⚠️");
        assert_eq!(escalation_emoji("Under Attack"), "🔥");
        assert_eq!(escalation_emoji("Critical"), "🚨");
        assert_eq!(escalation_emoji("Normal"), "✅");
        assert_eq!(escalation_emoji("Unknown"), "🛡️");
    }

    #[test]
    fn escalation_message_includes_transition_and_metrics() {
        // Formatting path: escalation notifications should include transition,
        // drops/sec and attacker count for context.
        let msg = build_escalation_message("Elevated", "Critical", 1200, 17, false);
        assert!(msg.contains("Escalation: Elevated → Critical"));
        assert!(msg.contains("Drops/sec: 1200"));
        assert!(msg.contains("Active attackers: 17"));
    }

    #[test]
    fn escalation_message_adds_cloudflare_suffix_when_active() {
        // Conditional path: Cloudflare status line should only appear when the
        // proxy is active.
        let with_proxy = build_escalation_message("Normal", "Under Attack", 300, 5, true);
        let without_proxy = build_escalation_message("Normal", "Under Attack", 300, 5, false);
        assert!(with_proxy.contains("Cloudflare proxy: <b>ACTIVE</b>"));
        assert!(!without_proxy.contains("Cloudflare proxy: <b>ACTIVE</b>"));
    }

    #[test]
    fn bgp_message_conditionally_includes_peer_information() {
        // Evidence path: peer ASN detail should be present only when supplied
        // by the caller.
        let with_peer = build_bgp_hijack_message("203.0.113.0/24", 64500, 64566, Some(3356));
        let without_peer = build_bgp_hijack_message("203.0.113.0/24", 64500, 64566, None);
        assert!(with_peer.contains("Seen via peer: AS3356"));
        assert!(!without_peer.contains("Seen via peer:"));
    }
}
