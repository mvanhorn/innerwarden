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

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_pipeline() -> PipelineDigestStats {
        PipelineDigestStats {
            suppressed_count: 0,
            auto_resolved_groups: 0,
            needs_review_groups: 0,
            deferred: Vec::new(),
        }
    }

    #[test]
    fn format_daily_digest_simple_zero_incidents_is_all_clear() {
        let msg = format_daily_digest(0, 0, 0, 0, "n/a", 0, true);
        assert!(msg.contains("Good morning"));
        assert!(msg.contains("0 attacks blocked"));
        assert!(msg.contains("0 critical threats"));
        assert!(msg.contains("Health: 100/100"));
        assert!(msg.contains("All clear"));
    }

    #[test]
    fn format_daily_digest_simple_with_threats_lowers_score() {
        // 2 critical (-40) + 4 high (-20) -> score 40, yellow then red threshold
        let msg = format_daily_digest(10, 5, 2, 4, "rule_A", 7, true);
        assert!(msg.contains("5 attacks blocked"));
        assert!(msg.contains("2 critical threats"));
        // 100 - 2*20 - 4*5 = 40, falls below the yellow >=50 threshold -> red emoji.
        assert!(msg.contains("Health: 40/100"));
    }

    #[test]
    fn format_daily_digest_simple_floors_score_at_zero() {
        // 100 critical * 20 = -1900 raw; clamp to 0.
        let msg = format_daily_digest(0, 0, 100, 0, "n/a", 0, true);
        assert!(msg.contains("Health: 0/100"));
    }

    #[test]
    fn format_daily_digest_technical_includes_counts_and_top_detector() {
        let msg = format_daily_digest(7, 3, 1, 2, "WAF/cve-2025-1234", 4, false);
        assert!(msg.contains("Daily digest"));
        assert!(msg.contains("Total: 7 incidents, 3 blocks"));
        assert!(msg.contains("WAF/cve-2025-1234: 4"));
        assert!(msg.contains("Critical: 1 | High: 2"));
        // Technical mode does NOT include the simple-mode greeting.
        assert!(!msg.contains("Good morning"));
    }

    #[test]
    fn format_daily_digest_simple_vs_technical_differs() {
        let simple = format_daily_digest(5, 2, 1, 0, "rule_X", 1, true);
        let technical = format_daily_digest(5, 2, 1, 0, "rule_X", 1, false);
        assert_ne!(simple, technical);
        assert!(simple.contains("Good morning"));
        assert!(technical.contains("Daily digest"));
    }

    #[test]
    fn format_daily_digest_technical_html_escapes_top_detector() {
        let msg = format_daily_digest(0, 0, 0, 0, "evil<script>&", 0, false);
        assert!(msg.contains("evil&lt;script&gt;&amp;"));
        assert!(!msg.contains("evil<script>&:"));
    }

    #[test]
    fn format_daily_digest_enriched_zero_state_does_not_panic() {
        let msg = format_daily_digest_enriched(0, 0, 0, 0, "n/a", 0, true, &empty_pipeline());
        // Empty deferred + zero auto-resolved + zero needs-review -> ends with "All clear".
        assert!(msg.contains("Daily Security Briefing"));
        assert!(msg.contains("All clear. Nothing needs you."));
        assert!(!msg.contains("Handled silently:"));
        assert!(!msg.contains("threat groups auto-resolved"));
        assert!(!msg.contains("groups need your review"));
    }

    #[test]
    fn format_daily_digest_enriched_renders_deferred_entries() {
        let pipeline = PipelineDigestStats {
            suppressed_count: 4,
            auto_resolved_groups: 2,
            needs_review_groups: 0,
            deferred: vec![
                ("waf.path_traversal".to_string(), 12),
                ("waf.sql_injection".to_string(), 5),
            ],
        };

        let simple = format_daily_digest_enriched(20, 17, 0, 1, "waf", 12, true, &pipeline);
        assert!(simple.contains("Handled silently:"));
        // friendly_detector_name is exercised here; both counts must appear.
        assert!(simple.contains("12"));
        assert!(simple.contains("5"));
        assert!(simple.contains("2 threat groups auto-resolved"));
        assert!(simple.contains("All clear. Nothing needs you."));

        let technical = format_daily_digest_enriched(20, 17, 0, 1, "waf", 12, false, &pipeline);
        assert!(technical.contains("Daily Digest"));
        assert!(technical.contains("Pipeline: 4 grouped, 2 auto-resolved, 0 need review"));
        assert!(technical.contains("Deferred:"));
        assert!(technical.contains("waf.path_traversal=12"));
        assert!(technical.contains("waf.sql_injection=5"));
    }

    #[test]
    fn format_daily_digest_enriched_simple_renders_needs_review_warning() {
        let pipeline = PipelineDigestStats {
            suppressed_count: 0,
            auto_resolved_groups: 0,
            needs_review_groups: 3,
            deferred: Vec::new(),
        };

        let msg = format_daily_digest_enriched(2, 1, 1, 0, "n/a", 0, true, &pipeline);
        assert!(msg.contains("3 groups need your review"));
        // "All clear" is replaced by the review warning when needs_review_groups > 0.
        assert!(!msg.contains("All clear. Nothing needs you."));
    }

    #[test]
    fn format_daily_digest_enriched_technical_html_escapes_top_detector() {
        let pipeline = empty_pipeline();
        let msg = format_daily_digest_enriched(1, 0, 0, 0, "evil<script>&", 1, false, &pipeline);
        assert!(msg.contains("evil&lt;script&gt;&amp;"));
    }
}
