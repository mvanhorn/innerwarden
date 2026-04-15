use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use tracing::{info, warn};

use crate::{neural_lifecycle, state_store, telegram, AgentState};

/// Throttle: only run the FP allowlist scan every 5 minutes.
/// Without this, the scan runs on every narrative tick (30s) and reads
/// 7 days of dated graph snapshots from disk on each call — wasteful and
/// pollutes logs with integrity-check pruning warnings.
static AUTOFP_LAST_RUN: Mutex<Option<Instant>> = Mutex::new(None);
const AUTOFP_INTERVAL_SECS: u64 = 300;

/// Suggest permanent allowlist entries via Telegram based on repeated FP reports.
pub(crate) async fn maybe_suggest_allowlist_from_fp_reports(
    data_dir: &Path,
    state: &mut AgentState,
) {
    if state.telegram_client.is_none() {
        return;
    }

    // Throttle: skip if last run was less than AUTOFP_INTERVAL_SECS ago.
    {
        let mut last = match AUTOFP_LAST_RUN.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if let Some(t) = *last {
            if t.elapsed().as_secs() < AUTOFP_INTERVAL_SECS {
                return;
            }
        }
        *last = Some(Instant::now());
    }

    // If any (detector, entity) pair has 3+ FP reports in last 7 days,
    // suggest permanent allowlist addition via Telegram.
    let fp_counts = neural_lifecycle::read_fp_report_counts(data_dir, 7);
    for (detector, entity, count) in &fp_counts {
        if *count >= 3 && !entity.is_empty() {
            // Cooldown: only suggest once per day per entity.
            let cooldown_key = format!("autofp_suggest:{entity}");
            if state
                .store
                .has_cooldown(state_store::CooldownTable::Notification, &cooldown_key)
            {
                continue;
            }

            let (text, keyboard) = build_autofp_message_and_keyboard(entity, detector, *count);

            if let Some(ref tg) = state.telegram_client {
                // Auto-FP suggestions go through notification gate.
                let gate_ctx =
                    crate::notification_gate::NotificationContext::for_autofp_suggestion();
                let gate_verdict = crate::notification_gate::should_notify(&gate_ctx);
                if matches!(
                    gate_verdict,
                    crate::notification_gate::NotificationVerdict::SendNow
                ) {
                    if let Err(e) = tg.send_text_with_keyboard(&text, keyboard).await {
                        warn!("failed to send auto-FP suggestion: {e:#}");
                    } else {
                        state.store.set_cooldown(
                            state_store::CooldownTable::Notification,
                            &cooldown_key,
                            chrono::Utc::now(),
                        );
                        info!(
                            entity = %entity,
                            detector = %detector,
                            count = count,
                            "auto-FP suggestion sent to Telegram"
                        );
                    }
                } else {
                    info!(
                        entity = %entity,
                        detector = %detector,
                        "auto-FP suggestion deferred to daily briefing"
                    );
                }
            }
        }
    }
}

pub(crate) fn build_autofp_message_and_keyboard(
    entity: &str,
    detector: &str,
    count: u32,
) -> (String, serde_json::Value) {
    let text = format!(
        "\u{1f4ca} <b>Auto-learn suggestion</b>\n\n\
         <code>{entity}</code> has been reported as false positive \
         {count} times for <code>{detector}</code>.\n\n\
         Add to allowlist permanently?",
        entity = telegram::escape_html_pub(entity),
        detector = telegram::escape_html_pub(detector),
    );
    let is_ip = entity.parse::<std::net::IpAddr>().is_ok();
    let section = if is_ip { "ip" } else { "proc" };
    let yes_cb = format!("autofp:yes:{section}:{entity}");
    let no_cb = format!("autofp:no:{entity}");

    let yes_cb = telegram::truncate_callback_pub(&yes_cb);
    let no_cb = telegram::truncate_callback_pub(&no_cb);

    let keyboard = serde_json::json!([
        [
            { "text": "\u{2705} Yes, allowlist", "callback_data": yes_cb },
            { "text": "\u{274c} No, keep monitoring", "callback_data": no_cb }
        ]
    ]);
    (text, keyboard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_autofp_message_and_keyboard_for_ip() {
        let (text, keyboard) = build_autofp_message_and_keyboard("8.8.8.8", "ssh_bruteforce", 3);

        // Assert text mentions both
        assert!(text.contains("8.8.8.8"));
        assert!(text.contains("ssh_bruteforce"));
        assert!(text.contains("3 times"));

        // IP entity means section is "ip"
        let yes_cb = keyboard[0][0]["callback_data"].as_str().unwrap();
        assert_eq!(yes_cb, "autofp:yes:ip:8.8.8.8");
    }

    #[test]
    fn test_build_autofp_message_and_keyboard_for_proc() {
        let (text, keyboard) = build_autofp_message_and_keyboard("/bin/bash", "suspicious_exec", 5);

        // Assert text mentions both
        assert!(text.contains("/bin/bash"));
        assert!(text.contains("suspicious_exec"));
        assert!(text.contains("5 times"));

        // Non-IP entity means section is "proc"
        let yes_cb = keyboard[0][0]["callback_data"].as_str().unwrap();
        assert_eq!(yes_cb, "autofp:yes:proc:/bin/bash");
    }
}
