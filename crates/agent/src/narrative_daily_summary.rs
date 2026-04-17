use std::collections::HashMap;
use std::path::Path;

use chrono::Timelike as _;
use innerwarden_core::event::Severity;
use innerwarden_core::incident::Incident;
use tracing::{info, warn};

use crate::{bot_helpers, config, narrative, telegram, AgentState};

/// Regenerate daily markdown summary and send Telegram digest when due.
pub(crate) async fn maybe_write_daily_summary_and_digest(
    data_dir: &Path,
    today: &str,
    events_count: usize,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    // Regenerate daily summary when there are new events, subject to a minimum
    // rewrite interval to avoid thrashing on busy hosts.
    const NARRATIVE_MIN_INTERVAL_SECS: u64 = 300; // 5 minutes
    const NARRATIVE_MAX_STALE_SECS: u64 = 1800; // 30 minutes
    if cfg.narrative.enabled && events_count > 0 {
        let elapsed = state
            .last_narrative_at
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(u64::MAX); // None → never written → always write
        let should_write =
            elapsed >= NARRATIVE_MIN_INTERVAL_SECS || elapsed >= NARRATIVE_MAX_STALE_SECS;
        if should_write {
            // Generate synthetic events from accumulated counters (no file I/O)
            let all_events_synthetic = state.narrative_acc.synthetic_events();
            let all_incidents_ref = &state.narrative_acc.incidents;

            let host = all_incidents_ref
                .first()
                .map(|i| i.host.as_str())
                .unwrap_or("unknown");

            let responder_hint = narrative::ResponderHint {
                enabled: cfg.responder.enabled,
                dry_run: cfg.responder.dry_run,
                has_block_ip: cfg
                    .responder
                    .allowed_skills
                    .iter()
                    .any(|s| s.starts_with("block-ip")),
            };
            let md = narrative::generate_with_responder(
                today,
                host,
                &all_events_synthetic,
                all_incidents_ref,
                cfg.correlation.window_seconds,
                responder_hint,
            );
            if let Err(e) = narrative::write(data_dir, today, &md) {
                state.telemetry.observe_error("narrative_writer");
                warn!("failed to write daily summary: {e:#}");
            } else {
                state.last_narrative_at = Some(std::time::Instant::now());
                info!(date = today, "daily summary updated");

                // Daily Telegram digest
                if let Some(hour) = cfg.telegram.daily_summary_hour {
                    let now_local = chrono::Local::now();
                    let today_naive = now_local.date_naive();
                    let already_sent = state.last_daily_summary_telegram == Some(today_naive);
                    if !already_sent && now_local.hour() >= u32::from(hour) {
                        if let Some(tg) = &state.telegram_client {
                            let is_simple = cfg.telegram.is_simple_profile();
                            // Count incidents by severity and top detector
                            let mut incidents_today: u32 = 0;
                            let mut critical_count: u32 = 0;
                            let mut high_count: u32 = 0;
                            let mut detector_counts: HashMap<String, u32> = HashMap::new();
                            for inc in &state.narrative_acc.incidents {
                                incidents_today += 1;
                                let det = telegram::extract_detector_pub(&inc.incident_id);
                                // Effective severity: downgrade contained/noise
                                // detectors so the health score reflects real risk,
                                // not internet noise that was already handled.
                                let effective = effective_severity(inc, det);
                                match effective {
                                    innerwarden_core::event::Severity::Critical => {
                                        critical_count += 1;
                                    }
                                    innerwarden_core::event::Severity::High => {
                                        high_count += 1;
                                    }
                                    _ => {}
                                }
                                *detector_counts.entry(det.to_string()).or_insert(0) += 1;
                            }
                            let blocks_today =
                                bot_helpers::graph_count(&state.knowledge_graph, "decisions")
                                    as u32;
                            let (top_detector, top_count) = detector_counts
                                .iter()
                                .max_by_key(|(_, c)| *c)
                                .map(|(d, c)| (d.as_str(), *c))
                                .unwrap_or(("none", 0));
                            let pipeline_stats = state.grouping_engine.drain_digest_stats();
                            // Drain deferred incidents for digest breakdown.
                            let mut deferred: Vec<(String, u32)> =
                                state.telegram_deferred.drain().collect();
                            deferred.sort_by(|a, b| b.1.cmp(&a.1));
                            let text = telegram::format_daily_digest_enriched(
                                incidents_today,
                                blocks_today,
                                critical_count,
                                high_count,
                                top_detector,
                                top_count,
                                is_simple,
                                &telegram::PipelineDigestStats {
                                    suppressed_count: pipeline_stats.suppressed_count,
                                    auto_resolved_groups: pipeline_stats.auto_resolved_groups,
                                    needs_review_groups: pipeline_stats.needs_review_groups,
                                    deferred,
                                },
                            );
                            match tg.send_text_message(&text).await {
                                Ok(()) => {
                                    state.last_daily_summary_telegram = Some(today_naive);
                                    info!(date = today, "daily Telegram digest sent");
                                }
                                Err(e) => warn!("failed to send daily Telegram digest: {e:#}"),
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Compute effective severity for health score purposes.
///
/// Raw detector severity reflects what the detector saw, not the actual risk
/// to the server. Internet noise (scanners, bots) that was already contained
/// or that has zero chance of success should not tank the health score.
fn effective_severity(inc: &Incident, detector: &str) -> Severity {
    let raw = inc.severity.clone();

    // SSH brute-force on a key-only server cannot succeed. The harden/scan
    // module confirms PasswordAuthentication=no, so anything below Critical
    // (which would mean the attacker got past auth) is Low-impact noise.
    if detector == "ssh_bruteforce" && !matches!(raw, Severity::Critical) {
        return Severity::Low;
    }

    // Proto anomaly scanners: malformed SSH, HTTP on wrong port from external
    // scanners — these fail at protocol level. Already Low in the sensor for
    // SshVersionAnomaly, but ProtocolMismatch is High. For health score
    // purposes, external scanner traffic that triggered no further chain is
    // Medium at most.
    if detector == "proto_anomaly" && matches!(raw, Severity::High) {
        return Severity::Medium;
    }

    // Kill chain unknown: pattern not matched = incomplete sequence. Not a
    // confirmed attack chain. Medium is more accurate than the default.
    if detector == "killchain" {
        if let Some(pattern) = inc
            .evidence
            .get("pattern")
            .or_else(|| inc.evidence.get(0).and_then(|e| e.get("pattern")))
            .and_then(|p| p.as_str())
        {
            if pattern == "unknown" && matches!(raw, Severity::High | Severity::Medium) {
                return Severity::Low;
            }
        }
    }

    // Correlated anomaly is advisory (baseline+neural convergence).
    // Now Medium in the emitter but guard against older incidents.
    if detector == "correlated_anomaly" && matches!(raw, Severity::High) {
        return Severity::Medium;
    }

    // Threat intel hits that were auto-blocked are successes, not threats.
    if detector == "threat_intel" {
        if let Some(tags) = inc.tags.as_slice().iter().find(|t| *t == "auto_blocked") {
            let _ = tags;
            return Severity::Low;
        }
    }

    raw
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity;

    fn make_incident(
        detector: &str,
        severity: Severity,
        tags: Vec<&str>,
        evidence: serde_json::Value,
    ) -> Incident {
        Incident {
            ts: chrono::Utc::now(),
            host: "test".into(),
            incident_id: format!("{}:1.2.3.4:test", detector),
            severity,
            title: "Test".into(),
            summary: "".into(),
            evidence,
            recommended_checks: vec![],
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
            entities: vec![],
        }
    }

    // SSH brute-force on key-only server: anything below Critical → Low
    #[test]
    fn effective_severity_ssh_bruteforce_high_becomes_low() {
        let inc = make_incident(
            "ssh_bruteforce",
            Severity::High,
            vec![],
            serde_json::json!({}),
        );
        assert_eq!(effective_severity(&inc, "ssh_bruteforce"), Severity::Low);
    }

    // SSH brute-force at Critical stays Critical (attacker got past auth)
    #[test]
    fn effective_severity_ssh_bruteforce_critical_stays() {
        let inc = make_incident(
            "ssh_bruteforce",
            Severity::Critical,
            vec![],
            serde_json::json!({}),
        );
        assert_eq!(
            effective_severity(&inc, "ssh_bruteforce"),
            Severity::Critical
        );
    }

    // Proto anomaly: High → Medium
    #[test]
    fn effective_severity_proto_anomaly_high_to_medium() {
        let inc = make_incident(
            "proto_anomaly",
            Severity::High,
            vec![],
            serde_json::json!({}),
        );
        assert_eq!(effective_severity(&inc, "proto_anomaly"), Severity::Medium);
    }

    // Proto anomaly: Medium stays Medium (only High is clamped)
    #[test]
    fn effective_severity_proto_anomaly_medium_unchanged() {
        let inc = make_incident(
            "proto_anomaly",
            Severity::Medium,
            vec![],
            serde_json::json!({}),
        );
        assert_eq!(effective_severity(&inc, "proto_anomaly"), Severity::Medium);
    }

    // Killchain with unknown pattern: High → Low
    #[test]
    fn effective_severity_killchain_unknown_high_to_low() {
        let evidence = serde_json::json!({"pattern": "unknown"});
        let inc = make_incident("killchain", Severity::High, vec![], evidence);
        assert_eq!(effective_severity(&inc, "killchain"), Severity::Low);
    }

    // Threat intel auto_blocked → Low
    #[test]
    fn effective_severity_threat_intel_auto_blocked_to_low() {
        let inc = make_incident(
            "threat_intel",
            Severity::High,
            vec!["auto_blocked"],
            serde_json::json!({}),
        );
        assert_eq!(effective_severity(&inc, "threat_intel"), Severity::Low);
    }

    // Correlated anomaly: High → Medium
    #[test]
    fn effective_severity_correlated_anomaly_high_to_medium() {
        let inc = make_incident(
            "correlated_anomaly",
            Severity::High,
            vec![],
            serde_json::json!({}),
        );
        assert_eq!(
            effective_severity(&inc, "correlated_anomaly"),
            Severity::Medium
        );
    }
}
