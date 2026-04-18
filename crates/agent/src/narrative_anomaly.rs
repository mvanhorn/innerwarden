use tracing::info;

use crate::correlation_engine;
use crate::AgentState;

/// Process autoencoder observations and baseline+autoencoder fused incidents.
///
/// The autoencoder acts as a SIGNAL, not a standalone detector.
/// It observes events silently and stores the latest anomaly score in state.
/// Other detectors can use this score to boost confidence in their decisions.
/// Only the baseline+autoencoder FUSION generates incidents (two independent
/// detection systems agreeing = high confidence).
pub(crate) fn process_anomalies(
    _data_dir: &std::path::Path,
    _today: &str,
    events_entries: &[innerwarden_core::event::Event],
    state: &mut AgentState,
) {
    // ── Autoencoder observation (silent — no incidents) ──────────────────
    for ev in events_entries {
        // Feed every event to the autoencoder; it updates its sliding window
        // and returns a score only when the window is full and score > threshold.
        if let Some((score, _weighted)) = state.anomaly_engine.observe(ev) {
            state.last_autoencoder_anomaly_ts = Some(chrono::Utc::now());
            // Store the latest high score for enrichment by other detectors.
            // This is read by the AI decision pipeline to boost confidence.
            state.latest_anomaly_score = Some(score);

            info!(
                score = format!("{:.3}", score),
                maturity = format!("{:.2}", state.anomaly_engine.maturity),
                kind = %ev.kind,
                "autoencoder signal (silent — enrichment only)"
            );

            // Inject into correlation engine so neural anomalies can participate
            // in cross-layer chain detection (e.g. CL-046 Neural-Confirmed Attack).
            let entities = ev.entities.clone();
            let corr_event = correlation_engine::CorrelationEngine::neural_event(
                score,
                entities,
                serde_json::json!({
                    "score": score,
                    "maturity": state.anomaly_engine.maturity,
                    "trigger_kind": ev.kind,
                }),
            );
            state.correlation_engine.observe(corr_event);
        }
    }

    // ── Baseline + Autoencoder score fusion ─────────────────────────────
    if let (Some(baseline_ts), Some(autoencoder_ts)) = (
        state.last_baseline_anomaly_ts,
        state.last_autoencoder_anomaly_ts,
    ) {
        let gap = anomaly_gap_seconds(baseline_ts, autoencoder_ts);
        if anomalies_converged_within_window(baseline_ts, autoencoder_ts, 60) {
            info!(
                baseline_ts = %baseline_ts,
                autoencoder_ts = %autoencoder_ts,
                gap_secs = gap,
                "correlated anomaly: baseline + autoencoder convergence"
            );

            let host = events_entries
                .first()
                .map(|e| e.host.clone())
                .unwrap_or_default();
            let now = chrono::Utc::now();
            let cycles = state.anomaly_engine.training_cycles;

            let fused_incident = innerwarden_core::incident::Incident {
                ts: now,
                host,
                incident_id: correlated_anomaly_incident_id(now),
                severity: innerwarden_core::event::Severity::Medium,
                title: "AI + Statistical convergence — both models flagged unusual activity"
                    .to_string(),
                summary: format_correlated_anomaly_summary(gap, cycles),
                evidence: serde_json::json!({
                    "baseline_anomaly_ts": baseline_ts.to_rfc3339(),
                    "autoencoder_anomaly_ts": autoencoder_ts.to_rfc3339(),
                    "gap_seconds": gap,
                    "autoencoder_maturity": state.anomaly_engine.maturity,
                    "training_cycles": cycles,
                }),
                recommended_checks: vec![
                    "Investigate events in the flagged timeframe".to_string(),
                    "Cross-reference with rule-based detector incidents".to_string(),
                    "Check for lateral movement or exfiltration patterns".to_string(),
                ],
                tags: vec![
                    "correlated_anomaly".to_string(),
                    "baseline".to_string(),
                    "neural_model".to_string(),
                ],
                entities: vec![],
            };

            state.neural_incidents.push(fused_incident);

            // Reset to avoid duplicate fused incidents
            state.last_baseline_anomaly_ts = None;
            state.last_autoencoder_anomaly_ts = None;
        }
    }
}

fn format_correlated_anomaly_summary(gap: u64, cycles: u32) -> String {
    format!(
        "Two independent detection systems agreed within {gap} seconds: \
         the statistical baseline model and the neural autoencoder ({cycles} days \
         of training) both flagged anomalous behavior. When two different \
         approaches converge, confidence is high that something genuinely \
         unusual is happening on your server."
    )
}

fn anomaly_gap_seconds(
    baseline_ts: chrono::DateTime<chrono::Utc>,
    autoencoder_ts: chrono::DateTime<chrono::Utc>,
) -> u64 {
    (baseline_ts - autoencoder_ts).num_seconds().unsigned_abs()
}

fn anomalies_converged_within_window(
    baseline_ts: chrono::DateTime<chrono::Utc>,
    autoencoder_ts: chrono::DateTime<chrono::Utc>,
    window_secs: u64,
) -> bool {
    anomaly_gap_seconds(baseline_ts, autoencoder_ts) <= window_secs
}

fn correlated_anomaly_incident_id(now: chrono::DateTime<chrono::Utc>) -> String {
    format!(
        "correlated_anomaly:baseline_neural:{}",
        now.format("%Y-%m-%dT%H:%MZ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone, Utc};

    #[test]
    fn anomaly_gap_seconds_is_absolute_between_timestamps() {
        // Ensures anomaly gap calculation is order-independent for baseline/autoencoder timestamps.
        let a = Utc
            .with_ymd_and_hms(2026, 4, 17, 8, 0, 0)
            .single()
            .expect("valid timestamp");
        let b = Utc
            .with_ymd_and_hms(2026, 4, 17, 7, 59, 0)
            .single()
            .expect("valid timestamp");
        assert_eq!(anomaly_gap_seconds(a, b), 60);
        assert_eq!(anomaly_gap_seconds(b, a), 60);
    }

    #[test]
    fn anomalies_converged_within_window_checks_threshold_boundary() {
        // Covers convergence gate boundary so fusion only triggers inside the configured window.
        let now = Utc::now();
        assert!(anomalies_converged_within_window(
            now,
            now - Duration::seconds(60),
            60
        ));
        assert!(!anomalies_converged_within_window(
            now,
            now - Duration::seconds(61),
            60
        ));
    }

    #[test]
    fn correlated_anomaly_incident_id_uses_expected_prefix_and_timestamp() {
        // Guards incident ID format consumed by downstream dashboards and dedup logic.
        let now = Utc
            .with_ymd_and_hms(2026, 4, 17, 9, 30, 0)
            .single()
            .expect("valid timestamp");
        let id = correlated_anomaly_incident_id(now);
        assert!(id.starts_with("correlated_anomaly:baseline_neural:"));
        assert!(id.ends_with("2026-04-17T09:30Z"));
    }

    #[test]
    fn test_format_correlated_anomaly_summary() {
        let summary = format_correlated_anomaly_summary(45, 14);
        assert!(summary.contains("agreed within 45 seconds"));
        assert!(summary.contains("autoencoder (14 days of training)"));
        assert!(summary.contains("When two different approaches converge"));
    }

    #[test]
    fn test_format_correlated_anomaly_summary_edge_cases() {
        let zero_summary = format_correlated_anomaly_summary(0, 0);
        assert!(zero_summary.contains("agreed within 0 seconds"));
        assert!(zero_summary.contains("autoencoder (0 days of training)"));

        let large_summary = format_correlated_anomaly_summary(3600, 365);
        assert!(large_summary.contains("agreed within 3600 seconds"));
        assert!(large_summary.contains("autoencoder (365 days of training)"));
    }

    #[test]
    fn test_anomalies_converged_within_window_boundary() {
        let now = Utc::now();
        // Exact boundary
        assert!(anomalies_converged_within_window(
            now,
            now - Duration::seconds(60),
            60
        ));
        // One second outside
        assert!(!anomalies_converged_within_window(
            now,
            now - Duration::seconds(61),
            60
        ));
        // Same timestamp
        assert!(anomalies_converged_within_window(now, now, 60));
    }
}
