use std::io::Write;
use std::path::Path;

use tracing::{info, warn};

use innerwarden_killchain::tracker::PidTracker;

use crate::correlation_engine;

/// Process a batch of sensor events through the kill chain tracker.
/// Returns incidents (JSON values) for any detected chains.
/// Also feeds the correlation engine with kill chain events.
pub(crate) fn process_events(
    tracker: &mut PidTracker,
    events: &[innerwarden_core::event::Event],
    correlation_engine: &mut correlation_engine::CorrelationEngine,
) -> Vec<serde_json::Value> {
    let mut all_incidents = Vec::new();

    for event in events {
        // Convert core Event to JSON for the killchain tracker.
        let json = event_to_tracker_json(event);
        let incidents = tracker.process_event(&json);

        for inc in &incidents {
            // Feed kill chain detections into the correlation engine.
            let pattern = inc
                .get("evidence")
                .and_then(|e| e.get("pattern"))
                .and_then(|p| p.as_str())
                .unwrap_or("unknown");

            let severity_str = inc
                .get("severity")
                .and_then(|s| s.as_str())
                .unwrap_or("medium");

            let kind = format!("killchain.{}", pattern);
            let corr_event = correlation_engine::CorrelationEngine::killchain_event(
                &kind,
                serde_json::json!({
                    "pattern": pattern,
                    "severity": severity_str,
                    "pid": inc.get("evidence").and_then(|e| e.get("pid")),
                }),
            );
            correlation_engine.observe(corr_event);
        }

        all_incidents.extend(incidents);
    }

    all_incidents
}

/// Write kill chain incidents to the daily JSONL file.
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
            info!(count = incidents.len(), "killchain: emitted incidents");
        }
        Err(e) => warn!(error = %e, "killchain: failed to write incidents"),
    }
}

/// Notify via Telegram for critical kill chain detections.
pub(crate) fn notify_telegram(
    telegram_client: &Option<std::sync::Arc<crate::telegram::TelegramClient>>,
    incidents: &[serde_json::Value],
) {
    let Some(tg) = telegram_client else { return };

    for inc in incidents {
        let severity = inc
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("medium");
        if severity != "critical" {
            continue;
        }

        let title = inc
            .get("title")
            .and_then(|t| t.as_str())
            .unwrap_or("Kill chain detected");
        let summary = inc.get("summary").and_then(|s| s.as_str()).unwrap_or("");
        let pattern = inc
            .get("evidence")
            .and_then(|e| e.get("pattern"))
            .and_then(|p| p.as_str())
            .unwrap_or("unknown");

        let msg = format!(
            "⛓️ <b>Kill Chain Alert</b>\n\n\
             🔴 CRITICAL\n\
             <b>{title}</b>\n\
             Pattern: {pattern}\n\
             {summary}",
        );
        let tg = tg.clone();
        tokio::spawn(async move {
            let _ = tg.send_raw_html(&msg).await;
        });
    }
}

/// Convert an innerwarden_core::Event to the JSON format expected by PidTracker.
fn event_to_tracker_json(event: &innerwarden_core::event::Event) -> serde_json::Value {
    serde_json::json!({
        "kind": event.kind,
        "source": event.source,
        "host": event.host,
        "ts": event.ts.to_rfc3339(),
        "details": event.details,
    })
}

/// Periodic maintenance: clean up stale PIDs from the tracker.
pub(crate) fn cleanup_stale(tracker: &mut PidTracker) {
    tracker.cleanup_stale();
}

/// Get tracker stats for telemetry/logging.
pub(crate) fn stats(tracker: &PidTracker) -> (usize, usize, usize) {
    tracker.stats()
}
