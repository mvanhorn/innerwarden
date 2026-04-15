use tracing::{debug, info};

use crate::{abuseipdb, attacker_intel, geoip, AgentState};

/// Namespace for cached GeoIP results.
const GEOIP_CACHE_NS: &str = "geoip_cache";
/// Namespace for cached AbuseIPDB reputation results.
const ABUSEIPDB_CACHE_NS: &str = "abuseipdb_cache";
/// Namespace for daily API call counters.
const ABUSEIPDB_LIMITS_NS: &str = "abuseipdb_limits";
/// Max API calls per day (free tier = 1000; reserve 200 for ad-hoc checks).
const ABUSEIPDB_DAILY_LIMIT: u32 = 800;
/// Cache TTL: 24 hours.
const CACHE_TTL_HOURS: i64 = 24;

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
/// - ip-api.com free tier: 45 req/min  → 3 per call is safe
/// - AbuseIPDB free tier: 1000/day     → 3 per call × 288 ticks = 864 max
///
/// Additionally uses a SQLite cache (24h TTL) and a daily counter (max 800)
/// to avoid exhausting the AbuseIPDB free-tier quota across restarts.
pub(crate) async fn backfill_enrichment(state: &mut AgentState) {
    const BATCH_SIZE: usize = 3;

    if state.geoip_client.is_none() && state.abuseipdb.is_none() {
        return;
    }

    // --- Global daily rate limiter (AbuseIPDB) ---
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();
    let daily_key = format!("abuseipdb_daily_{today}");
    let mut daily_count: u32 = state
        .sqlite_store
        .as_ref()
        .and_then(|sq| {
            sq.kv_get_str(ABUSEIPDB_LIMITS_NS, &daily_key)
                .ok()
                .flatten()
        })
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let abuse_budget_exhausted = daily_count >= ABUSEIPDB_DAILY_LIMIT;

    if abuse_budget_exhausted && state.geoip_client.is_none() {
        // Nothing useful to do — both sources exhausted/disabled.
        debug!(
            daily_count,
            "enrichment backfill: AbuseIPDB daily limit reached, skipping"
        );
        return;
    }

    // Collect IPs that need enrichment (missing geo OR abuseipdb).
    // Skip private/loopback — they'll never resolve externally.
    // Skip IPs already cached in SQLite (survives restarts).
    let candidates: Vec<(String, bool, bool)> = state
        .attacker_profiles
        .iter()
        .filter(|(ip, p)| {
            let needs_geo = p.geo.is_none();
            let needs_abuse = p.abuseipdb_score.is_none();
            if !needs_geo && !needs_abuse {
                return false;
            }
            if !is_ip_eligible_for_external_enrichment(ip) {
                return false;
            }
            true
        })
        .filter(|(ip, _p)| {
            // If abuse score is missing, check SQLite cache — the score may
            // already be cached from a previous agent lifetime.
            if _p.abuseipdb_score.is_none() {
                let cached = state
                    .sqlite_store
                    .as_ref()
                    .and_then(|sq| sq.kv_get(ABUSEIPDB_CACHE_NS, ip).ok().flatten());
                if cached.is_some() {
                    // Will be applied below in the "restore from cache" pass.
                    return true;
                }
            }
            true
        })
        .map(|(ip, p)| (ip.clone(), p.geo.is_none(), p.abuseipdb_score.is_none()))
        .take(BATCH_SIZE)
        .collect();

    if candidates.is_empty() {
        return;
    }

    // Perform lookups — borrow clients immutably, then apply results.
    let mut results: Vec<(
        String,
        Option<geoip::GeoInfo>,
        Option<abuseipdb::IpReputation>,
    )> = Vec::with_capacity(candidates.len());

    for (ip, needs_geo, needs_abuse) in &candidates {
        let geo = if *needs_geo {
            // Try SQLite cache first (survives restarts).
            let cached_geo = state
                .sqlite_store
                .as_ref()
                .and_then(|sq| sq.kv_get_str(GEOIP_CACHE_NS, ip).ok().flatten())
                .and_then(|json| serde_json::from_str::<geoip::GeoInfo>(&json).ok());

            if let Some(info) = cached_geo {
                debug!(ip, "geoip: using cached result");
                Some(info)
            } else if let Some(client) = &state.geoip_client {
                let result = client.lookup(ip).await;
                // Cache successful result with 7-day TTL (geo rarely changes).
                if let Some(ref info) = result {
                    if let Some(ref sq) = state.sqlite_store {
                        let expiry = (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339();
                        if let Ok(json) = serde_json::to_string(info) {
                            let _ = sq.kv_set_with_expiry(
                                GEOIP_CACHE_NS,
                                ip,
                                json.as_bytes(),
                                Some(&expiry),
                            );
                        }
                    }
                }
                result
            } else {
                None
            }
        } else {
            None
        };

        let abuse = if *needs_abuse {
            // Try SQLite cache first (survives restarts).
            let cached_abuse = state
                .sqlite_store
                .as_ref()
                .and_then(|sq| sq.kv_get_str(ABUSEIPDB_CACHE_NS, ip).ok().flatten())
                .and_then(|json| serde_json::from_str::<abuseipdb::IpReputation>(&json).ok());

            if let Some(reputation) = cached_abuse {
                debug!(ip, "abuseipdb: using cached reputation");
                Some(reputation)
            } else if !abuse_budget_exhausted {
                // Cache miss — call API.
                let result = if let Some(client) = &state.abuseipdb {
                    client.check(ip).await
                } else {
                    None
                };

                // Cache successful result in SQLite with 24h TTL.
                if let Some(ref reputation) = result {
                    if let Some(ref sq) = state.sqlite_store {
                        let expiry = (chrono::Utc::now()
                            + chrono::Duration::hours(CACHE_TTL_HOURS))
                        .to_rfc3339();
                        if let Ok(json) = serde_json::to_string(reputation) {
                            let _ = sq.kv_set_with_expiry(
                                ABUSEIPDB_CACHE_NS,
                                ip,
                                json.as_bytes(),
                                Some(&expiry),
                            );
                        }
                    }
                    // Increment daily counter.
                    daily_count += 1;
                    if let Some(ref sq) = state.sqlite_store {
                        let _ = sq.kv_set(
                            ABUSEIPDB_LIMITS_NS,
                            &daily_key,
                            daily_count.to_string().as_bytes(),
                        );
                    }
                }

                result
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
        daily_abuseipdb_calls = daily_count,
        "enrichment backfill: updated profiles with missing data"
    );
}

// Extracted pure logic for testing
pub(crate) fn is_ip_eligible_for_external_enrichment(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(addr) => !addr.is_loopback() && !crate::ai::is_private_ip(addr),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ip_eligible_for_external_enrichment() {
        // Valid external IPs
        assert!(is_ip_eligible_for_external_enrichment("8.8.8.8"));
        assert!(is_ip_eligible_for_external_enrichment("104.21.5.1"));
        assert!(is_ip_eligible_for_external_enrichment(
            "2001:4860:4860::8888"
        )); // External IPv6

        // Loopback
        assert!(!is_ip_eligible_for_external_enrichment("127.0.0.1"));
        assert!(!is_ip_eligible_for_external_enrichment("::1"));

        // Private IPs (assuming crate::ai::is_private_ip covers RFC1918)
        assert!(!is_ip_eligible_for_external_enrichment("10.0.5.5"));
        assert!(!is_ip_eligible_for_external_enrichment("172.16.0.1"));
        assert!(!is_ip_eligible_for_external_enrichment("192.168.1.100"));

        // Invalid format
        assert!(!is_ip_eligible_for_external_enrichment("not_an_ip"));
        assert!(!is_ip_eligible_for_external_enrichment(""));
        assert!(!is_ip_eligible_for_external_enrichment("256.256.256.256"));
    }
}
