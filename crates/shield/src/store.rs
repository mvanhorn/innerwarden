// store.rs — Persistence
//
// Save/load shield state, DDoS incident history, rate EMA profiles,
// and blocked IPs to JSON files in a dedicated directory.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::attack_classifier::AttackIncident;
use crate::escalation::{DdosIncident, EscalationState};
use crate::rate_limiter::IpTracker;
use crate::xdp_manager::BlocklistEntry;

// ---------------------------------------------------------------------------
// Persisted state structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldState {
    pub escalation_state: EscalationState,
    pub state_entered_at: String,
    pub blocked_ips: Vec<BlocklistEntry>,
    pub last_saved: String,
}

impl Default for ShieldState {
    fn default() -> Self {
        Self {
            escalation_state: EscalationState::Normal,
            state_entered_at: chrono::Utc::now().to_rfc3339(),
            blocked_ips: Vec::new(),
            last_saved: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateProfiles {
    pub profiles: Vec<IpTracker>,
    pub last_saved: String,
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

pub struct Store {
    shield_dir: PathBuf,
}

impl Store {
    pub fn new(shield_dir: &Path) -> Self {
        Self {
            shield_dir: shield_dir.to_path_buf(),
        }
    }

    pub fn ensure_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.shield_dir)
            .with_context(|| format!("Failed to create shield dir: {:?}", self.shield_dir))?;
        Ok(())
    }

    // -- Shield state --

    pub fn save_state(&self, state: &ShieldState) -> Result<()> {
        self.ensure_dir()?;
        let path = self.shield_dir.join("shield-state.json");
        let json =
            serde_json::to_string_pretty(state).context("Failed to serialize shield state")?;
        std::fs::write(&path, json).with_context(|| format!("Failed to write {:?}", path))?;
        tracing::debug!(path = ?path, "Saved shield state");
        Ok(())
    }

    pub fn load_state(&self) -> Result<ShieldState> {
        let path = self.shield_dir.join("shield-state.json");
        if !path.exists() {
            return Ok(ShieldState::default());
        }
        let json =
            std::fs::read_to_string(&path).with_context(|| format!("Failed to read {:?}", path))?;
        let state: ShieldState =
            serde_json::from_str(&json).with_context(|| format!("Failed to parse {:?}", path))?;
        Ok(state)
    }

    // -- DDoS history --

    pub fn save_ddos_history(&self, incidents: &[DdosIncident]) -> Result<()> {
        self.ensure_dir()?;
        let path = self.shield_dir.join("ddos-history.json");
        let json =
            serde_json::to_string_pretty(incidents).context("Failed to serialize DDoS history")?;
        std::fs::write(&path, json).with_context(|| format!("Failed to write {:?}", path))?;
        Ok(())
    }

    pub fn load_ddos_history(&self) -> Result<Vec<DdosIncident>> {
        let path = self.shield_dir.join("ddos-history.json");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let json =
            std::fs::read_to_string(&path).with_context(|| format!("Failed to read {:?}", path))?;
        let incidents: Vec<DdosIncident> =
            serde_json::from_str(&json).with_context(|| format!("Failed to parse {:?}", path))?;
        Ok(incidents)
    }

    // -- Attack incidents --

    pub fn save_attack_incidents(&self, incidents: &[AttackIncident]) -> Result<()> {
        self.ensure_dir()?;
        let path = self.shield_dir.join("attack-incidents.json");
        let json = serde_json::to_string_pretty(incidents)
            .context("Failed to serialize attack incidents")?;
        std::fs::write(&path, json).with_context(|| format!("Failed to write {:?}", path))?;
        Ok(())
    }

    pub fn load_attack_incidents(&self) -> Result<Vec<AttackIncident>> {
        let path = self.shield_dir.join("attack-incidents.json");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let json =
            std::fs::read_to_string(&path).with_context(|| format!("Failed to read {:?}", path))?;
        let incidents: Vec<AttackIncident> =
            serde_json::from_str(&json).with_context(|| format!("Failed to parse {:?}", path))?;
        Ok(incidents)
    }

    // -- Rate profiles --

    pub fn save_rate_profiles(&self, trackers: &[IpTracker]) -> Result<()> {
        self.ensure_dir()?;
        let path = self.shield_dir.join("rate-profiles.json");
        let profiles = RateProfiles {
            profiles: trackers.to_vec(),
            last_saved: chrono::Utc::now().to_rfc3339(),
        };
        let json =
            serde_json::to_string_pretty(&profiles).context("Failed to serialize rate profiles")?;
        std::fs::write(&path, json).with_context(|| format!("Failed to write {:?}", path))?;
        Ok(())
    }

    pub fn load_rate_profiles(&self) -> Result<Vec<IpTracker>> {
        let path = self.shield_dir.join("rate-profiles.json");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let json =
            std::fs::read_to_string(&path).with_context(|| format!("Failed to read {:?}", path))?;
        let profiles: RateProfiles =
            serde_json::from_str(&json).with_context(|| format!("Failed to parse {:?}", path))?;
        Ok(profiles.profiles)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_and_load_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());

        let state = ShieldState {
            escalation_state: EscalationState::Elevated,
            state_entered_at: "2024-01-01T00:00:00Z".to_string(),
            blocked_ips: vec![BlocklistEntry {
                ip: "10.0.0.1".to_string(),
                added_at: chrono::Utc::now(),
                reason: "rate_limit".to_string(),
            }],
            last_saved: chrono::Utc::now().to_rfc3339(),
        };

        store.save_state(&state).unwrap();
        let loaded = store.load_state().unwrap();
        assert_eq!(loaded.escalation_state, EscalationState::Elevated);
        assert_eq!(loaded.blocked_ips.len(), 1);
    }

    #[test]
    fn load_state_default_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(&dir.path().join("nonexistent"));
        let state = store.load_state().unwrap();
        assert_eq!(state.escalation_state, EscalationState::Normal);
    }

    #[test]
    fn save_and_load_ddos_history() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());

        let incidents = vec![crate::escalation::DdosIncident {
            id: "ddos-1".to_string(),
            started: chrono::Utc::now(),
            ended: Some(chrono::Utc::now()),
            peak_state: EscalationState::UnderAttack,
            peak_pps: 5000,
            total_dropped: 10000,
            peak_attackers: 15,
            attack_type: "volumetric".to_string(),
        }];

        store.save_ddos_history(&incidents).unwrap();
        let loaded = store.load_ddos_history().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].attack_type, "volumetric");
    }

    #[test]
    fn save_and_load_attack_incidents() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());

        let incidents = vec![crate::attack_classifier::AttackIncident {
            id: "atk-1".to_string(),
            attack_type: crate::attack_classifier::AttackType::SynFlood,
            started: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            source_ips: ["10.0.0.1".to_string()].into_iter().collect(),
            packets_dropped: 500,
            peak_pps: 2000,
            confidence: 0.9,
        }];

        store.save_attack_incidents(&incidents).unwrap();
        let loaded = store.load_attack_incidents().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "atk-1");
    }

    #[test]
    fn load_missing_ddos_history_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let loaded = store.load_ddos_history().unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn load_missing_attack_incidents_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path());
        let loaded = store.load_attack_incidents().unwrap();
        assert!(loaded.is_empty());
    }
}
