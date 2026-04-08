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
        let gap = (baseline_ts - autoencoder_ts).num_seconds().unsigned_abs();
        if gap <= 60 {
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
                incident_id: format!(
                    "correlated_anomaly:baseline_neural:{}",
                    now.format("%Y-%m-%dT%H:%MZ")
                ),
                severity: innerwarden_core::event::Severity::High,
                title: "AI + Statistical convergence — both models flagged unusual activity"
                    .to_string(),
                summary: format!(
                    "Two independent detection systems agreed within {gap} seconds: \
                     the statistical baseline model and the neural autoencoder ({cycles} days \
                     of training) both flagged anomalous behavior. When two different \
                     approaches converge, confidence is high that something genuinely \
                     unusual is happening on your server."
                ),
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
