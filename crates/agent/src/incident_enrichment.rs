use tracing::{debug, info};

use crate::{abuseipdb, attacker_intel, geoip, AgentState};

pub(crate) fn log_threat_feed_match(
    incident: &innerwarden_core::incident::Incident,
    state: &AgentState,
) {
    // Threat feed gate: if the IP is in any threat feed, log it for enrichment.
    // This is informational - does not auto-block (feeds may have false positives).
    let Some(tf) = state.threat_feed.as_ref() else {
        return;
    };

    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str());
    if let Some(ip) = primary_ip {
        if tf.is_known_malicious_ip(ip) {
            info!(
                ip,
                incident_id = %incident.incident_id,
                "threat feed match: IP found in external IOC feed"
            );
        }
    }
}

pub(crate) async fn lookup_incident_geoip(
    incident: &innerwarden_core::incident::Incident,
    state: &AgentState,
) -> Option<geoip::GeoInfo> {
    let client = state.geoip_client.as_ref()?;

    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str());
    if let Some(ip) = primary_ip {
        client.lookup(ip).await
    } else {
        None
    }
}

pub(crate) fn enrich_attacker_identity(
    incident: &innerwarden_core::incident::Incident,
    state: &mut AgentState,
    ip_geo: Option<&geoip::GeoInfo>,
    ip_reputation: Option<&abuseipdb::IpReputation>,
) {
    // Enrich attacker profile with GeoIP + AbuseIPDB (only on first encounter).
    if ip_geo.is_none() && ip_reputation.is_none() {
        return;
    }

    let primary_ip = incident
        .entities
        .iter()
        .find(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
        .map(|e| e.value.as_str());
    if let Some(ip) = primary_ip {
        let crowdsec_listed = state
            .crowdsec
            .as_ref()
            .is_some_and(|cs| cs.is_known_threat(ip));
        // Ensure profile exists — enrichment may run before the main
        // attacker_intel pipeline creates the profile. Without this,
        // GeoIP/AbuseIPDB data was silently discarded for new IPs.
        let profile = state
            .attacker_profiles
            .entry(ip.to_string())
            .or_insert_with(|| attacker_intel::new_profile(ip, incident.ts));
        if profile.geo.is_none() || profile.abuseipdb_score.is_none() {
            attacker_intel::enrich_identity(profile, ip_geo, ip_reputation, crowdsec_listed);
        }
    }
}

/// Background enrichment backfill — retries GeoIP and AbuseIPDB lookups for
/// profiles that are still missing data.  Called from the slow tick (every 5 min).
///
/// Processes a small batch per call to stay well within rate limits:
/// - ip-api.com free tier: 45 req/min  → 5 per call is safe
/// - AbuseIPDB free tier: 1000/day     → 5 per call is safe
pub(crate) async fn backfill_enrichment(state: &mut AgentState) {
    const BATCH_SIZE: usize = 5;

    if state.geoip_client.is_none() && state.abuseipdb.is_none() {
        return;
    }

    // Collect IPs that need enrichment (missing geo OR abuseipdb).
    // Skip private/loopback — they'll never resolve externally.
    let candidates: Vec<(String, bool, bool)> = state
        .attacker_profiles
        .iter()
        .filter(|(ip, p)| {
            let missing = p.geo.is_none() || p.abuseipdb_score.is_none();
            if !missing {
                return false;
            }
            match ip.parse::<std::net::IpAddr>() {
                Ok(addr) => !addr.is_loopback() && !crate::ai::is_private_ip(addr),
                Err(_) => false,
            }
        })
        .map(|(ip, p)| (ip.clone(), p.geo.is_none(), p.abuseipdb_score.is_none()))
        .take(BATCH_SIZE)
        .collect();

    if candidates.is_empty() {
        return;
    }

    // Perform lookups — borrow clients immutably, then apply results.
    let mut results: Vec<(String, Option<geoip::GeoInfo>, Option<abuseipdb::IpReputation>)> =
        Vec::with_capacity(candidates.len());

    for (ip, needs_geo, needs_abuse) in &candidates {
        let geo = if *needs_geo {
            if let Some(client) = &state.geoip_client {
                client.lookup(ip).await
            } else {
                None
            }
        } else {
            None
        };

        let abuse = if *needs_abuse {
            if let Some(client) = &state.abuseipdb {
                client.check(ip).await
            } else {
                None
            }
        } else {
            None
        };

        if geo.is_some() || abuse.is_some() {
            results.push((ip.clone(), geo, abuse));
        }
    }

    if results.is_empty() {
        debug!(
            candidates = candidates.len(),
            "enrichment backfill: no new data from APIs"
        );
        return;
    }

    // Apply results — now we can borrow profiles mutably.
    let mut enriched = 0usize;
    for (ip, geo, abuse) in &results {
        let crowdsec_listed = state
            .crowdsec
            .as_ref()
            .is_some_and(|cs| cs.is_known_threat(ip));
        if let Some(profile) = state.attacker_profiles.get_mut(ip.as_str()) {
            attacker_intel::enrich_identity(profile, geo.as_ref(), abuse.as_ref(), crowdsec_listed);
            enriched += 1;
        }
    }

    info!(
        enriched,
        candidates = candidates.len(),
        "enrichment backfill: updated profiles with missing data"
    );
}
