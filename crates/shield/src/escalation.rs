// escalation.rs — Auto-Escalation State Machine
//
// Based on Cloudflare L4Drop and SRodi/xdp-ddos-protect. Four-level
// state machine (Normal → Elevated → UnderAttack → Critical) with
// hysteresis for de-escalation.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscalationState {
    Normal,
    Elevated,
    UnderAttack,
    Critical,
}

impl std::fmt::Display for EscalationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Normal => write!(f, "Normal"),
            Self::Elevated => write!(f, "Elevated"),
            Self::UnderAttack => write!(f, "Under Attack"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

impl EscalationState {
    fn level(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Elevated => 1,
            Self::UnderAttack => 2,
            Self::Critical => 3,
        }
    }

    fn from_level(l: u8) -> Self {
        match l {
            0 => Self::Normal,
            1 => Self::Elevated,
            2 => Self::UnderAttack,
            _ => Self::Critical,
        }
    }

    /// Threshold multiplier for rate limiter configuration.
    /// Normal = 1.0 (defaults), Elevated = 0.5, UnderAttack = 0.2, Critical = 0.1.
    pub fn rate_limit_factor(self) -> f64 {
        match self {
            Self::Normal => 1.0,
            Self::Elevated => 0.5,
            Self::UnderAttack => 0.2,
            Self::Critical => 0.1,
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics snapshot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosMetrics {
    pub timestamp: DateTime<Utc>,
    pub packets_dropped_per_sec: u64,
    pub unique_attackers: usize,
    pub syn_flood_active: bool,
    pub udp_flood_active: bool,
    pub http_flood_active: bool,
    pub total_dropped: u64,
    pub total_allowed: u64,
    pub peak_pps: u64,
    pub attack_duration_secs: u64,
    pub server_cpu_impact: f64,
}

impl DdosMetrics {
    /// Drops per minute, estimated from per-second rate.
    pub fn drops_per_min(&self) -> u64 {
        self.packets_dropped_per_sec * 60
    }
}

// ---------------------------------------------------------------------------
// State transition record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from: EscalationState,
    pub to: EscalationState,
    pub at: DateTime<Utc>,
    pub trigger_drops_per_min: u64,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationConfig {
    /// Drops/min threshold: Normal → Elevated.
    pub elevated_drops_per_min: u64,
    /// Drops/min threshold: Elevated → UnderAttack.
    pub under_attack_drops_per_min: u64,
    /// Drops/min threshold: UnderAttack → Critical.
    pub critical_drops_per_min: u64,
    /// Minimum time in seconds a state must be held before de-escalating.
    pub min_state_duration_secs: i64,
    /// How many consecutive metric samples must be "calm" before de-escalating.
    pub calm_samples_required: usize,
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            elevated_drops_per_min: 50,
            under_attack_drops_per_min: 500,
            critical_drops_per_min: 5000,
            min_state_duration_secs: 300,
            calm_samples_required: 6, // 6 * 5s = 30s of calm
        }
    }
}

// ---------------------------------------------------------------------------
// DDoS incident
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosIncident {
    pub id: String,
    pub started: DateTime<Utc>,
    pub ended: Option<DateTime<Utc>>,
    pub peak_state: EscalationState,
    pub peak_pps: u64,
    pub total_dropped: u64,
    pub peak_attackers: usize,
    pub attack_type: String,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

pub struct EscalationEngine {
    state: EscalationState,
    state_entered_at: DateTime<Utc>,
    metrics_history: VecDeque<DdosMetrics>,
    config: EscalationConfig,
    min_state_duration: Duration,
    calm_counter: usize,
    transitions: Vec<StateTransition>,
    current_incident: Option<DdosIncident>,
    incidents: Vec<DdosIncident>,
    incident_counter: u64,
}

impl EscalationEngine {
    pub fn new(config: EscalationConfig) -> Self {
        let min_dur = Duration::seconds(config.min_state_duration_secs);
        Self {
            state: EscalationState::Normal,
            state_entered_at: Utc::now(),
            metrics_history: VecDeque::new(),
            config,
            min_state_duration: min_dur,
            calm_counter: 0,
            transitions: Vec::new(),
            current_incident: None,
            incidents: Vec::new(),
            incident_counter: 0,
        }
    }

    pub fn state(&self) -> EscalationState {
        self.state
    }

    pub fn state_entered_at(&self) -> DateTime<Utc> {
        self.state_entered_at
    }

    pub fn incidents(&self) -> &[DdosIncident] {
        &self.incidents
    }

    pub fn current_incident(&self) -> Option<&DdosIncident> {
        self.current_incident.as_ref()
    }

    /// Last state transition (if any occurred).
    pub fn last_transition(&self) -> Option<&StateTransition> {
        self.transitions.last()
    }

    pub fn transitions(&self) -> &[StateTransition] {
        &self.transitions
    }

    /// Feed a new metrics snapshot and return a transition if state changed.
    pub fn update(&mut self, metrics: &DdosMetrics) -> Option<StateTransition> {
        self.metrics_history.push_back(metrics.clone());
        if self.metrics_history.len() > 200 {
            self.metrics_history.pop_front();
        }

        let dpm = metrics.drops_per_min();
        let target = self.target_state(dpm);
        let now = metrics.timestamp;

        let previous = self.state;

        if target.level() > previous.level() {
            // Escalation: immediate.
            self.transition_to(target, now, dpm);
            return Some(StateTransition {
                from: previous,
                to: target,
                at: now,
                trigger_drops_per_min: dpm,
            });
        }

        if target.level() < previous.level() {
            // De-escalation: require min duration AND consecutive calm samples.
            let in_state = now - self.state_entered_at;
            if in_state >= self.min_state_duration {
                self.calm_counter += 1;
                if self.calm_counter >= self.config.calm_samples_required {
                    // De-escalate one level at a time.
                    let new_level = previous.level().saturating_sub(1);
                    let new_state = EscalationState::from_level(new_level);
                    self.transition_to(new_state, now, dpm);
                    return Some(StateTransition {
                        from: previous,
                        to: new_state,
                        at: now,
                        trigger_drops_per_min: dpm,
                    });
                }
            }
        } else {
            // Same level — reset calm counter.
            self.calm_counter = 0;
        }

        // Update current incident metrics if active.
        if let Some(ref mut incident) = self.current_incident {
            if metrics.peak_pps > incident.peak_pps {
                incident.peak_pps = metrics.peak_pps;
            }
            incident.total_dropped = metrics.total_dropped;
            if metrics.unique_attackers > incident.peak_attackers {
                incident.peak_attackers = metrics.unique_attackers;
            }
        }

        None
    }

    /// Restore persisted state.
    pub fn restore(
        &mut self,
        state: EscalationState,
        entered_at: DateTime<Utc>,
        incidents: Vec<DdosIncident>,
    ) {
        self.state = state;
        self.state_entered_at = entered_at;
        self.incidents = incidents;
    }

    /// Build a metrics snapshot from components.
    pub fn build_metrics(
        &self,
        dropped_per_sec: u64,
        unique_attackers: usize,
        syn_flood: bool,
        udp_flood: bool,
        http_flood: bool,
        total_dropped: u64,
        total_allowed: u64,
        peak_pps: u64,
    ) -> DdosMetrics {
        let attack_duration = self
            .current_incident
            .as_ref()
            .map(|i| (Utc::now() - i.started).num_seconds().max(0) as u64)
            .unwrap_or(0);

        DdosMetrics {
            timestamp: Utc::now(),
            packets_dropped_per_sec: dropped_per_sec,
            unique_attackers,
            syn_flood_active: syn_flood,
            udp_flood_active: udp_flood,
            http_flood_active: http_flood,
            total_dropped,
            total_allowed,
            peak_pps,
            attack_duration_secs: attack_duration,
            server_cpu_impact: 0.0,
        }
    }

    // -- internal --

    fn target_state(&self, drops_per_min: u64) -> EscalationState {
        if drops_per_min >= self.config.critical_drops_per_min {
            EscalationState::Critical
        } else if drops_per_min >= self.config.under_attack_drops_per_min {
            EscalationState::UnderAttack
        } else if drops_per_min >= self.config.elevated_drops_per_min {
            EscalationState::Elevated
        } else {
            EscalationState::Normal
        }
    }

    fn transition_to(&mut self, new_state: EscalationState, now: DateTime<Utc>, dpm: u64) {
        let previous = self.state;
        self.state = new_state;
        self.state_entered_at = now;
        self.calm_counter = 0;

        self.transitions.push(StateTransition {
            from: previous,
            to: new_state,
            at: now,
            trigger_drops_per_min: dpm,
        });

        tracing::warn!(
            from = %previous,
            to = %new_state,
            dpm,
            "Escalation state transition"
        );

        // Incident tracking.
        match new_state {
            EscalationState::Normal => {
                if let Some(mut inc) = self.current_incident.take() {
                    inc.ended = Some(now);
                    self.incidents.push(inc);
                }
            }
            _ if self.current_incident.is_none() => {
                self.incident_counter += 1;
                self.current_incident = Some(DdosIncident {
                    id: format!("ddos-{}", self.incident_counter),
                    started: now,
                    ended: None,
                    peak_state: new_state,
                    peak_pps: 0,
                    total_dropped: 0,
                    peak_attackers: 0,
                    attack_type: "unknown".to_string(),
                });
            }
            _ => {
                if let Some(ref mut inc) = self.current_incident {
                    if new_state.level() > inc.peak_state.level() {
                        inc.peak_state = new_state;
                    }
                }
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as CDur;

    fn ts(offset_secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + offset_secs, 0).unwrap()
    }

    fn make_metrics(dps: u64, now: DateTime<Utc>) -> DdosMetrics {
        DdosMetrics {
            timestamp: now,
            packets_dropped_per_sec: dps,
            unique_attackers: 5,
            syn_flood_active: false,
            udp_flood_active: false,
            http_flood_active: false,
            total_dropped: 0,
            total_allowed: 0,
            peak_pps: dps * 2,
            attack_duration_secs: 0,
            server_cpu_impact: 0.0,
        }
    }

    #[test]
    fn initial_state_is_normal() {
        let engine = EscalationEngine::new(EscalationConfig::default());
        assert_eq!(engine.state(), EscalationState::Normal);
    }

    #[test]
    fn escalate_normal_to_elevated() {
        let mut engine = EscalationEngine::new(EscalationConfig::default());
        let now = ts(0);
        // 50 drops/min = 50/60 ≈ 0.83 dps → but threshold is 50 dpm.
        // We need dps such that dps*60 >= 50. dps=1 → 60 dpm.
        let m = make_metrics(1, now);
        let result = engine.update(&m);
        assert!(result.is_some());
        assert_eq!(engine.state(), EscalationState::Elevated);
    }

    #[test]
    fn escalate_to_under_attack() {
        let config = EscalationConfig::default();
        let mut engine = EscalationEngine::new(config);
        let now = ts(0);
        // dps=9 → 540 dpm, above 500 threshold.
        let m = make_metrics(9, now);
        let result = engine.update(&m);
        assert!(result.is_some());
        assert_eq!(engine.state(), EscalationState::UnderAttack);
    }

    #[test]
    fn escalate_to_critical() {
        let mut engine = EscalationEngine::new(EscalationConfig::default());
        let now = ts(0);
        // dps=100 → 6000 dpm, above 5000 threshold.
        let m = make_metrics(100, now);
        let result = engine.update(&m);
        assert!(result.is_some());
        assert_eq!(engine.state(), EscalationState::Critical);
    }

    #[test]
    fn deescalation_requires_min_duration() {
        let config = EscalationConfig {
            min_state_duration_secs: 300,
            calm_samples_required: 1,
            ..Default::default()
        };
        let mut engine = EscalationEngine::new(config);
        let now = ts(0);

        // Escalate.
        engine.update(&make_metrics(1, now));
        assert_eq!(engine.state(), EscalationState::Elevated);

        // Try de-escalate immediately — should not work.
        let m = make_metrics(0, now + CDur::seconds(5));
        let result = engine.update(&m);
        assert!(result.is_none());
        assert_eq!(engine.state(), EscalationState::Elevated);
    }

    #[test]
    fn deescalation_after_min_duration() {
        let config = EscalationConfig {
            min_state_duration_secs: 10,
            calm_samples_required: 1,
            ..Default::default()
        };
        let mut engine = EscalationEngine::new(config);
        let now = ts(0);

        engine.update(&make_metrics(1, now));
        assert_eq!(engine.state(), EscalationState::Elevated);

        // Wait beyond min_state_duration.
        let later = now + CDur::seconds(15);
        let result = engine.update(&make_metrics(0, later));
        assert!(result.is_some());
        assert_eq!(engine.state(), EscalationState::Normal);
    }

    #[test]
    fn deescalation_one_level_at_a_time() {
        let config = EscalationConfig {
            min_state_duration_secs: 1,
            calm_samples_required: 1,
            ..Default::default()
        };
        let mut engine = EscalationEngine::new(config);
        let now = ts(0);

        // Go to Critical.
        engine.update(&make_metrics(100, now));
        assert_eq!(engine.state(), EscalationState::Critical);

        // Calm down — should only go to UnderAttack.
        let later = now + CDur::seconds(5);
        engine.update(&make_metrics(0, later));
        assert_eq!(engine.state(), EscalationState::UnderAttack);
    }

    #[test]
    fn calm_samples_required() {
        let config = EscalationConfig {
            min_state_duration_secs: 1,
            calm_samples_required: 3,
            ..Default::default()
        };
        let mut engine = EscalationEngine::new(config);
        let now = ts(0);

        engine.update(&make_metrics(1, now));
        assert_eq!(engine.state(), EscalationState::Elevated);

        // Need 3 consecutive calm samples after min_duration.
        for i in 1..=2 {
            let t = now + CDur::seconds(5 + i);
            engine.update(&make_metrics(0, t));
        }
        assert_eq!(engine.state(), EscalationState::Elevated); // not yet

        let t3 = now + CDur::seconds(8);
        engine.update(&make_metrics(0, t3));
        assert_eq!(engine.state(), EscalationState::Normal); // now
    }

    #[test]
    fn incident_created_on_escalation() {
        let mut engine = EscalationEngine::new(EscalationConfig::default());
        let now = ts(0);
        engine.update(&make_metrics(1, now));
        assert!(engine.current_incident().is_some());
    }

    #[test]
    fn incident_closed_on_return_to_normal() {
        let config = EscalationConfig {
            min_state_duration_secs: 1,
            calm_samples_required: 1,
            ..Default::default()
        };
        let mut engine = EscalationEngine::new(config);
        let now = ts(0);

        engine.update(&make_metrics(1, now));
        assert!(engine.current_incident().is_some());

        let later = now + CDur::seconds(5);
        engine.update(&make_metrics(0, later));
        assert!(engine.current_incident().is_none());
        assert_eq!(engine.incidents().len(), 1);
        assert!(engine.incidents()[0].ended.is_some());
    }

    #[test]
    fn rate_limit_factor_values() {
        assert!((EscalationState::Normal.rate_limit_factor() - 1.0).abs() < f64::EPSILON);
        assert!((EscalationState::Elevated.rate_limit_factor() - 0.5).abs() < f64::EPSILON);
        assert!((EscalationState::UnderAttack.rate_limit_factor() - 0.2).abs() < f64::EPSILON);
        assert!((EscalationState::Critical.rate_limit_factor() - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn display_formatting() {
        assert_eq!(format!("{}", EscalationState::Normal), "Normal");
        assert_eq!(format!("{}", EscalationState::Elevated), "Elevated");
        assert_eq!(format!("{}", EscalationState::UnderAttack), "Under Attack");
        assert_eq!(format!("{}", EscalationState::Critical), "Critical");
    }
}
