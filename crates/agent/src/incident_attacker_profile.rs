use crate::{attacker_intel, AgentState, LocalIpReputation};

/// Update local IP reputation and attacker profile for all IP entities in the incident.
pub(crate) fn update_incident_ip_profiles(
    incident: &innerwarden_core::incident::Incident,
    state: &mut AgentState,
) {
    for entity in &incident.entities {
        if entity.r#type == innerwarden_core::entities::EntityType::Ip {
            state
                .ip_reputations
                .entry(entity.value.clone())
                .or_insert_with(LocalIpReputation::new)
                .record_incident();

            // Attacker intelligence: build unified profile.
            let profile = state
                .attacker_profiles
                .entry(entity.value.clone())
                .or_insert_with(|| attacker_intel::new_profile(&entity.value, incident.ts));
            attacker_intel::observe_incident(profile, incident);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;

    #[test]
    fn update_incident_ip_profiles_updates_reputation_and_profile_for_ip_entities() {
        // Invariant: every IP entity increments local reputation and attacker profile counters.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let incident = crate::tests::test_incident("203.0.113.10");

        update_incident_ip_profiles(&incident, &mut state);
        update_incident_ip_profiles(&incident, &mut state);

        let rep = state
            .ip_reputations
            .get("203.0.113.10")
            .expect("IP reputation should be created");
        assert_eq!(rep.total_incidents, 2);

        let profile = state
            .attacker_profiles
            .get("203.0.113.10")
            .expect("attacker profile should be created");
        assert_eq!(profile.total_incidents, 2);
    }

    #[test]
    fn update_incident_ip_profiles_skips_non_ip_entities() {
        // Invariant: non-IP entities must not mutate IP reputation or attacker profile maps.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut incident = crate::tests::test_incident("203.0.113.11");
        incident.entities = vec![EntityRef::user("root")];

        update_incident_ip_profiles(&incident, &mut state);

        assert!(state.ip_reputations.is_empty());
        assert!(state.attacker_profiles.is_empty());
    }
}
