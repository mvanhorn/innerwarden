//! Lightweight Telegram notifier for Shield escalation events.
//!
//! Sends a message when the Shield escalates or de-escalates.
//! Reads TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID from env vars
//! (same vars as the agent — shared /etc/innerwarden/agent.env).

use tracing::{info, warn};

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
        let emoji = match to {
            "Elevated" => "⚠️",
            "Under Attack" => "🔥",
            "Critical" => "🚨",
            "Normal" => "✅",
            _ => "🛡️",
        };

        let cf_status = if cloudflare_active {
            "\n☁️ Cloudflare proxy: <b>ACTIVE</b>"
        } else {
            ""
        };

        let text = format!(
            "{emoji} <b>Shield: {to}</b>\n\
             \n\
             Escalation: {from} → {to}\n\
             📊 Drops/sec: {dropped_per_sec}\n\
             🎯 Active attackers: {active_attackers}{cf_status}\n\
             \n\
             <i>XDP + rate limiting adjusted automatically.</i>",
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
        let peer_info = peer_asn
            .map(|p| format!("\n👁 Seen via peer: AS{p}"))
            .unwrap_or_default();

        let text = format!(
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
        );

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
