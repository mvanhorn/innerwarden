//! Lightweight Telegram notifier for Shield escalation events.
//!
//! Sends a message when the Shield escalates or de-escalates.
//! Reads TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID from env vars
//! (same vars as the agent — shared /etc/innerwarden/agent.env).

use tracing::{info, warn};

const TELEGRAM_API_BASE_URL: &str = "https://api.telegram.org";

#[cfg(test)]
fn telegram_send_message_url(bot_token: &str) -> String {
    telegram_send_message_url_for_base(TELEGRAM_API_BASE_URL, bot_token)
}

fn telegram_send_message_url_for_base(api_base_url: &str, bot_token: &str) -> String {
    format!(
        "{}/bot{bot_token}/sendMessage",
        api_base_url.trim_end_matches('/')
    )
}

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

fn escalation_payload(chat_id: &str, text: String, to: &str) -> serde_json::Value {
    serde_json::json!({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_notification": to == "Normal",
    })
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

fn bgp_hijack_payload(chat_id: &str, text: String) -> serde_json::Value {
    serde_json::json!({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
    })
}

pub struct TelegramNotifier {
    bot_token: String,
    chat_id: String,
    client: reqwest::Client,
    api_base_url: String,
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
            api_base_url: TELEGRAM_API_BASE_URL.into(),
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

        let url = telegram_send_message_url_for_base(&self.api_base_url, &self.bot_token);
        let payload = escalation_payload(&self.chat_id, text, to);

        let result = self.client.post(&url).json(&payload).send().await;

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

        let url = telegram_send_message_url_for_base(&self.api_base_url, &self.bot_token);
        let payload = bgp_hijack_payload(&self.chat_id, text);

        let result = self.client.post(&url).json(&payload).send().await;

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
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    fn notifier_for_base(api_base_url: String) -> TelegramNotifier {
        TelegramNotifier {
            bot_token: "token-123".into(),
            chat_id: "chat-1".into(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .expect("client should build"),
            api_base_url,
        }
    }

    fn request_complete(request: &[u8]) -> bool {
        let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
            return false;
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        request.len() >= header_end + 4 + content_length
    }

    fn spawn_telegram_server(status: &'static str) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener address");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            while !request_complete(&request) {
                let read = stream.read(&mut buf).expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..read]);
            }

            let response =
                format!("HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}");
            stream
                .write_all(response.as_bytes())
                .expect("write response");
            String::from_utf8_lossy(&request).into_owned()
        });

        (format!("http://{addr}"), handle)
    }

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

    #[test]
    fn cloudflare_status_suffix_is_empty_when_proxy_inactive() {
        assert_eq!(cloudflare_status_suffix(false), "");
        assert!(cloudflare_status_suffix(true).contains("Cloudflare proxy"));
    }

    #[test]
    fn telegram_url_uses_bot_token_without_leaking_chat_id() {
        let url = telegram_send_message_url("token-123");
        assert_eq!(url, "https://api.telegram.org/bottoken-123/sendMessage");
        assert!(!url.contains("chat"));
    }

    #[test]
    fn telegram_url_for_base_trims_trailing_slash() {
        let url = telegram_send_message_url_for_base("http://127.0.0.1:1234/", "token");
        assert_eq!(url, "http://127.0.0.1:1234/bottoken/sendMessage");
    }

    #[test]
    fn escalation_payload_disables_notification_only_for_normal_state() {
        let normal = escalation_payload("chat-1", "ok".to_string(), "Normal");
        assert_eq!(normal["chat_id"], "chat-1");
        assert_eq!(normal["parse_mode"], "HTML");
        assert_eq!(normal["disable_notification"], true);

        let critical = escalation_payload("chat-1", "fire".to_string(), "Critical");
        assert_eq!(critical["disable_notification"], false);
    }

    #[test]
    fn bgp_hijack_message_includes_expected_origin_rogue_origin_and_source() {
        let msg = build_bgp_hijack_message("198.51.100.0/24", 64500, 64496, None);
        assert!(msg.contains("Prefix: <code>198.51.100.0/24</code>"));
        assert!(msg.contains("Expected origin: <b>AS64500</b>"));
        assert!(msg.contains("Rogue origin: <b>AS64496</b>"));
        assert!(msg.contains("Source: RIPE RIS Live"));
    }

    #[test]
    fn bgp_payload_keeps_html_parse_mode_without_disable_notification_flag() {
        let payload = bgp_hijack_payload("chat-2", "alert".to_string());
        assert_eq!(payload["chat_id"], "chat-2");
        assert_eq!(payload["text"], "alert");
        assert_eq!(payload["parse_mode"], "HTML");
        assert!(payload.get("disable_notification").is_none());
    }

    #[tokio::test]
    async fn notify_escalation_posts_payload_to_send_message_endpoint() {
        let (base_url, handle) = spawn_telegram_server("200 OK");
        let notifier = notifier_for_base(base_url);

        notifier
            .notify_escalation("Normal", "Critical", 900, 4, true)
            .await;

        let request = handle.join().expect("server thread should finish");
        assert!(request.starts_with("POST /bottoken-123/sendMessage HTTP/1.1"));
        assert!(request.contains("\"chat_id\":\"chat-1\""));
        assert!(request.contains("\"disable_notification\":false"));
        assert!(request.contains("Cloudflare proxy"));
    }

    #[tokio::test]
    async fn notify_bgp_hijack_posts_alert_payload() {
        let (base_url, handle) = spawn_telegram_server("200 OK");
        let notifier = notifier_for_base(base_url);

        notifier
            .notify_bgp_hijack("203.0.113.0/24", 64500, 64496, Some(3356))
            .await;

        let request = handle.join().expect("server thread should finish");
        assert!(request.starts_with("POST /bottoken-123/sendMessage HTTP/1.1"));
        assert!(request.contains("\"parse_mode\":\"HTML\""));
        assert!(request.contains("BGP HIJACK DETECTED"));
        assert!(request.contains("AS3356"));
    }

    #[tokio::test]
    async fn notify_paths_return_on_http_failure_and_request_error() {
        let (base_url, handle) = spawn_telegram_server("500 Internal Server Error");
        let notifier = notifier_for_base(base_url);
        notifier
            .notify_bgp_hijack("203.0.113.0/24", 64500, 64496, None)
            .await;
        let request = handle.join().expect("server thread should finish");
        assert!(request.contains("BGP HIJACK DETECTED"));

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused listener");
        let addr = listener.local_addr().expect("unused listener address");
        drop(listener);

        let notifier = notifier_for_base(format!("http://{addr}"));
        notifier
            .notify_escalation("Critical", "Normal", 0, 0, false)
            .await;
    }
}
