use super::formatting::{escape_html, friendly_detector_name};

/// Format the daily digest message.
/// Simple mode: friendly, non-technical. Technical mode: concise stats.
#[allow(dead_code)]
pub fn format_daily_digest(
    incidents_today: u32,
    blocks_today: u32,
    critical_count: u32,
    high_count: u32,
    top_detector: &str,
    top_count: u32,
    is_simple: bool,
) -> String {
    if is_simple {
        let raw_score = 100i32
            .saturating_sub(critical_count as i32 * 20)
            .saturating_sub(high_count as i32 * 5);
        let score = raw_score.clamp(0, 100) as u32;
        let health_emoji = if score >= 80 {
            "\u{1f7e2}" // 🟢
        } else if score >= 50 {
            "\u{1f7e1}" // 🟡
        } else {
            "\u{1f534}" // 🔴
        };

        format!(
            "\u{2600}\u{fe0f} Good morning! Your server in the last 24h:\n\
             \n\
             \u{00a0}\u{00a0}{blocks_today} attacks blocked\n\
             \u{00a0}\u{00a0}{critical_count} critical threats\n\
             \u{00a0}\u{00a0}Health: {score}/100 {health_emoji}\n\
             \n\
             All clear. Nothing needs you."
        )
    } else {
        let date = chrono::Local::now().format("%Y-%m-%d");
        format!(
            "\u{1f4ca} Daily digest ({date}):\n\
             \u{00a0}\u{00a0}Total: {incidents_today} incidents, {blocks_today} blocks\n\
             \u{00a0}\u{00a0}{top_detector}: {top_count}\n\
             \u{00a0}\u{00a0}Critical: {critical_count} | High: {high_count}",
            top_detector = escape_html(top_detector),
        )
    }
}

/// Pipeline digest stats for enriched daily digest.
pub struct PipelineDigestStats {
    pub suppressed_count: u32,
    pub auto_resolved_groups: u32,
    pub needs_review_groups: u32,
    /// Incidents deferred from immediate Telegram (per-detector counts).
    pub deferred: Vec<(String, u32)>,
}

/// Format an enriched daily digest with pipeline grouping stats.
#[allow(clippy::too_many_arguments)]
pub fn format_daily_digest_enriched(
    incidents_today: u32,
    blocks_today: u32,
    critical_count: u32,
    high_count: u32,
    top_detector: &str,
    top_count: u32,
    is_simple: bool,
    pipeline: &PipelineDigestStats,
) -> String {
    let raw_score = 100i32
        .saturating_sub(critical_count as i32 * 20)
        .saturating_sub(high_count as i32 * 5);
    let score = raw_score.clamp(0, 100) as u32;
    let health_emoji = if score >= 80 {
        "\u{1f7e2}" // 🟢
    } else if score >= 50 {
        "\u{1f7e1}" // 🟡
    } else {
        "\u{1f534}" // 🔴
    };

    if is_simple {
        let mut msg = format!(
            "\u{1f6e1}\u{fe0f} <b>Daily Security Briefing</b>\n\
             \n\
             {health_emoji} Server health: <b>{score}/100</b>\n\
             \n\
             While you were away, InnerWarden:\n\
             \u{00a0}\u{00a0}\u{2022} Blocked <b>{blocks_today}</b> attacks\n\
             \u{00a0}\u{00a0}\u{2022} Analyzed <b>{incidents_today}</b> security events\n\
             \u{00a0}\u{00a0}\u{2022} Detected <b>{critical_count}</b> critical, <b>{high_count}</b> high severity threats"
        );

        // Deferred incident breakdown — the bulk of silent work.
        if !pipeline.deferred.is_empty() {
            msg.push_str("\n\n\u{1f916} <b>Handled silently:</b>");
            for (detector, count) in &pipeline.deferred {
                let label = friendly_detector_name(detector);
                msg.push_str(&format!("\n\u{00a0}\u{00a0}\u{2022} {count} {label}"));
            }
        }

        if pipeline.auto_resolved_groups > 0 {
            msg.push_str(&format!(
                "\n\n\u{2705} {} threat groups auto-resolved",
                pipeline.auto_resolved_groups
            ));
        }

        if pipeline.needs_review_groups > 0 {
            msg.push_str(&format!(
                "\n\n\u{26a0}\u{fe0f} <b>{} groups need your review</b>",
                pipeline.needs_review_groups
            ));
        } else {
            msg.push_str("\n\n\u{2705} All clear. Nothing needs you.");
        }

        msg
    } else {
        let date = chrono::Local::now().format("%Y-%m-%d");
        let mut msg = format!(
            "\u{1f4ca} <b>Daily Digest</b> ({date})\n\
             \n\
             Health: {score}/100 {health_emoji}\n\
             Incidents: {incidents_today} | Blocks: {blocks_today}\n\
             Critical: {critical_count} | High: {high_count}\n\
             Top: {top_detector} ({top_count})",
            top_detector = escape_html(top_detector),
        );

        if pipeline.suppressed_count > 0 || pipeline.auto_resolved_groups > 0 {
            msg.push_str(&format!(
                "\nPipeline: {} grouped, {} auto-resolved, {} need review",
                pipeline.suppressed_count,
                pipeline.auto_resolved_groups,
                pipeline.needs_review_groups,
            ));
        }

        if !pipeline.deferred.is_empty() {
            msg.push_str("\nDeferred:");
            for (detector, count) in &pipeline.deferred {
                msg.push_str(&format!(" {detector}={count}"));
            }
        }

        msg
    }
}

// ---------------------------------------------------------------------------
// Simple /status
// ---------------------------------------------------------------------------

/// Format a simple /status response.
/// Returns the semaphore status message for non-technical users.
pub fn format_simple_status(
    has_critical_last_24h: bool,
    has_high_last_hour: bool,
    has_critical_last_hour: bool,
    uptime_days: u64,
    total_blocked: u64,
    last_threat_ago: &str,
) -> String {
    let (semaphore, status_word) = if has_critical_last_hour {
        ("\u{1f534}", "needs attention") // 🔴
    } else if has_high_last_hour {
        ("\u{1f7e1}", "under watch") // 🟡
    } else {
        ("\u{1f7e2}", "safe") // 🟢
    };

    // Suppress "no critical" label when there are none
    let _ = has_critical_last_24h;

    format!(
        "{semaphore} <b>Server is {status_word}</b>\n\
         \n\
         \u{1f6e1}\u{fe0f} Protected for <b>{uptime_days}</b> days\n\
         \u{1f6ab} <b>{total_blocked}</b> attacks blocked\n\
         \u{23f1}\u{fe0f} Last threat: {last_threat_ago}",
        last_threat_ago = escape_html(last_threat_ago),
    )
}
