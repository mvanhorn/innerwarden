use tracing::info;

use crate::AgentState;

/// Friendly event kind for user-facing messages.
fn friendly_event_kind(kind: &str) -> &str {
    match kind {
        "http.request" => "HTTP traffic",
        "dns.query" => "DNS activity",
        "ssh.login_failed" => "SSH login attempts",
        "shell.command_exec" => "command execution",
        "file.read_access" => "file access",
        "file.write" => "file modification",
        "process.exec" => "process execution",
        "network.connect" => "network connections",
        "suricata.alert" => "network traffic",
        _ => kind,
    }
}

/// Process autoencoder anomalies and baseline+autoencoder fused incidents.
pub(crate) fn process_anomalies(
    _data_dir: &std::path::Path,
    _today: &str,
    events_entries: &[innerwarden_core::event::Event],
    state: &mut AgentState,
) {
    // ── Autoencoder anomaly detection ────────────────────────────────────
    for ev in events_entries {
        if let Some((score, weighted)) = state.anomaly_engine.observe(ev) {
            state.last_autoencoder_anomaly_ts = Some(chrono::Utc::now());
            info!(
                score = format!("{:.3}", score),
                weighted = format!("{:.3}", weighted),
                maturity = format!("{:.2}", state.anomaly_engine.maturity),
                kind = %ev.kind,
                "autoencoder anomaly detected"
            );

            let pct = (score * 100.0) as u32;
            let cycles = state.anomaly_engine.training_cycles;
            let friendly_kind = friendly_event_kind(&ev.kind);

            let severity = if score > 0.9 {
                innerwarden_core::event::Severity::Critical
            } else if score > 0.8 {
                innerwarden_core::event::Severity::High
            } else {
                innerwarden_core::event::Severity::Medium
            };

            let title = if score > 0.9 {
                format!("AI Spider Sense: highly unusual {friendly_kind} — {pct}% anomaly")
            } else if score > 0.8 {
                format!("AI Spider Sense: unusual {friendly_kind} pattern — {pct}% anomaly")
            } else {
                format!("AI Spider Sense: {friendly_kind} anomaly detected — {pct}%")
            };

            let summary = format!(
                "InnerWarden's AI analyzed this against {cycles} days of learned behavior \
                 for your server. This {friendly_kind} pattern is unlike anything seen before — \
                 no rule covers this, only the neural model caught it."
            );

            let incident = innerwarden_core::incident::Incident {
                ts: ev.ts,
                host: ev.host.clone(),
                incident_id: format!("neural_anomaly:{}:{}", pct, ev.ts.format("%Y-%m-%dT%H:%MZ")),
                severity,
                title,
                summary,
                evidence: serde_json::json!({
                    "score": score,
                    "weighted": weighted,
                    "maturity": state.anomaly_engine.maturity,
                    "training_cycles": cycles,
                    "model": "autoencoder-48f",
                    "trigger_event": ev.kind,
                }),
                recommended_checks: vec![
                    "Review recent events around this timeframe".to_string(),
                    "Check if rule-based detectors also flagged this".to_string(),
                    "Compare with baseline event rates for anomalies".to_string(),
                ],
                tags: vec!["neural_model".to_string(), "autoencoder".to_string()],
                entities: ev.entities.clone(),
            };

            // Push to agent buffer — avoids permission issues with sensor's file.
            state.neural_incidents.push(incident);
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
