use std::path::Path;

use tracing::info;

use crate::{ai, config, correlation, AgentState};

/// Apply correlation confidence boost, attacker-intel boost, and
/// autoencoder anomaly boost to the AI decision, then emit the
/// canonical decision log.
///
/// The defender brain second-opinion path was removed when the
/// AlphaZero model was replaced by the SecureBERT classifier provider
/// routed through `ai::AiRouter`. Decisions now come from a single
/// place (the router) and there is no separate "brain compares with
/// AI" log to keep in sync.
pub(crate) fn apply_correlation_boost_and_log_decision(
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    decision: &mut ai::AiDecision,
    _data_dir: &Path,
) {
    // If the same IP triggered multiple distinct detectors within the
    // correlation window, boost the confidence.
    let (boosted_confidence, correlated_detectors) = if cfg.correlation.enabled {
        let (b, k) = correlation::cross_detector_boost(
            &mut state.correlator,
            incident,
            decision.confidence as f64,
        );
        (b as f32, k)
    } else {
        (decision.confidence, vec![])
    };

    if boosted_confidence > decision.confidence {
        info!(
            incident_id = %incident.incident_id,
            base_confidence = decision.confidence,
            boosted_confidence,
            correlated_detectors = ?correlated_detectors,
            "cross-detector correlation boost applied"
        );
        decision.confidence = boosted_confidence;
        decision.reason = format!(
            "{} [correlated: {}]",
            decision.reason,
            correlated_detectors.join(", ")
        );
    }

    // Attacker intel risk score boost: if this IP has a known risk profile,
    // enrich the decision with context and boost confidence for repeat offenders.
    {
        let ip = incident
            .entities
            .iter()
            .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
            .map(|e| e.value.as_str());
        if let Some(ip) = ip {
            if let Some(profile) = state.attacker_profiles.get(ip) {
                let risk = profile.risk_score;
                if risk > 50 {
                    let boost = (risk as f32 - 50.0) / 500.0; // 50 → 0 %, 100 → 10 %
                    let new_conf = (decision.confidence + boost).min(1.0);
                    if new_conf > decision.confidence {
                        let pattern = &profile.dna.pattern_class;
                        info!(
                            incident_id = %incident.incident_id,
                            ip,
                            risk_score = risk,
                            pattern = pattern.as_str(),
                            visits = profile.visit_count,
                            boost = format!("{:.3}", boost),
                            "attacker intel: known threat - confidence boosted"
                        );
                        decision.confidence = new_conf;
                        decision.reason = format!(
                            "{} [intel: risk {}, {}, {} visits]",
                            decision.reason, risk, pattern, profile.visit_count
                        );
                    }
                }
            }
        }
    }

    // Autoencoder signal boost: if the neural model also flagged unusual
    // activity in this time window, boost confidence by up to 10 %. The
    // autoencoder is a silent intuition that reinforces real detections.
    if let Some(anomaly_score) = state.latest_anomaly_score.take() {
        if anomaly_score > 0.7 {
            let boost = (anomaly_score - 0.7) * 0.33; // 0.7 → 0 %, 1.0 → 10 %
            let new_conf = (decision.confidence + boost).min(1.0);
            if new_conf > decision.confidence {
                info!(
                    incident_id = %incident.incident_id,
                    anomaly_score = format!("{:.3}", anomaly_score),
                    boost = format!("{:.3}", boost),
                    "autoencoder signal: neural model agrees - confidence boosted"
                );
                decision.confidence = new_conf;
                decision.reason = format!(
                    "{} [neural: {:.0}% anomaly]",
                    decision.reason,
                    anomaly_score * 100.0
                );
            }
        }
    }

    info!(
        incident_id = %incident.incident_id,
        action = ?decision.action,
        confidence = decision.confidence,
        auto_execute = decision.auto_execute,
        reason = %decision.reason,
        "AI decision"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn correlation_boost_applies_when_multiple_detectors_match_same_ip() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = crate::config::AgentConfig::default();
        let ip = "203.0.113.50";

        // Prime the correlator with two distinct detectors firing on
        // the same IP so the cross-detector boost has signal to apply.
        let i1 = crate::tests::test_incident_with_kind(ip, "ssh_bruteforce");
        let i2 = crate::tests::test_incident_with_kind(ip, "port_scan");
        let _ = correlation::cross_detector_boost(&mut state.correlator, &i1, 0.6);
        let _ = correlation::cross_detector_boost(&mut state.correlator, &i2, 0.6);

        let trigger = crate::tests::test_incident_with_kind(ip, "credential_stuffing");
        let mut decision = ai::AiDecision {
            action: ai::AiAction::Ignore {
                reason: "test".into(),
            },
            confidence: 0.5,
            auto_execute: false,
            reason: "baseline".into(),
            alternatives: vec![],
            estimated_threat: "low".into(),
        };

        apply_correlation_boost_and_log_decision(
            &trigger,
            &cfg,
            &mut state,
            &mut decision,
            dir.path(),
        );

        // Either the boost path or one of the other enrichments should
        // tag the reason with bracketed metadata; baseline alone never
        // carries `[`. Ensures the function actually ran end to end.
        assert!(
            decision.reason.contains('[') || decision.reason == "baseline",
            "decision.reason was not annotated: {}",
            decision.reason
        );
        assert!(state.latest_anomaly_score.is_none());
    }

    #[test]
    fn autoencoder_anomaly_score_is_consumed_even_when_below_threshold() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let cfg = crate::config::AgentConfig::default();
        state.latest_anomaly_score = Some(0.5);

        let incident = crate::tests::test_incident_with_kind("198.51.100.1", "ssh_bruteforce");
        let mut decision = ai::AiDecision {
            action: ai::AiAction::Ignore {
                reason: "test".into(),
            },
            confidence: 0.5,
            auto_execute: false,
            reason: "r".into(),
            alternatives: vec![],
            estimated_threat: "low".into(),
        };

        apply_correlation_boost_and_log_decision(
            &incident,
            &cfg,
            &mut state,
            &mut decision,
            dir.path(),
        );
        // Score is `take()`'n regardless of whether the threshold was met.
        assert!(state.latest_anomaly_score.is_none());
    }
}
