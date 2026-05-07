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
    use tempfile::TempDir;

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

    #[test]
    fn enrich_attacker_identity_creates_missing_profile() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let incident = crate::tests::test_incident("203.0.113.55");
        let geo = geoip::GeoInfo {
            country: "United Kingdom".to_string(),
            country_code: "GB".to_string(),
            city: "London".to_string(),
            isp: "Example ISP".to_string(),
            asn: "AS64500 Example".to_string(),
        };
        let reputation = abuseipdb::IpReputation {
            confidence_score: 88,
            total_reports: 17,
            distinct_users: 9,
            country_code: Some("GB".to_string()),
            isp: Some("Example ISP".to_string()),
            is_tor: false,
        };

        enrich_attacker_identity(&incident, &mut state, Some(&geo), Some(&reputation));

        let profile = state
            .attacker_profiles
            .get("203.0.113.55")
            .expect("profile should exist");
        assert!(profile.geo.is_some());
        assert_eq!(profile.abuseipdb_score, Some(88));
    }

    #[tokio::test]
    async fn backfill_enrichment_uses_cached_geo_and_abuse_entries() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let store = crate::tests::test_sqlite_store(dir.path());
        state.sqlite_store = Some(store.clone());
        state.abuseipdb = Some(abuseipdb::AbuseIpDbClient::new(String::new(), 30));
        let ip = "8.8.8.8";
        state.attacker_profiles.insert(
            ip.to_string(),
            attacker_intel::new_profile(ip, chrono::Utc::now()),
        );

        let cached_geo = geoip::GeoInfo {
            country: "Brazil".to_string(),
            country_code: "BR".to_string(),
            city: "Sao Paulo".to_string(),
            isp: "Unit Test ISP".to_string(),
            asn: "AS64510 UnitTest".to_string(),
        };
        let cached_abuse = abuseipdb::IpReputation {
            confidence_score: 64,
            total_reports: 12,
            distinct_users: 4,
            country_code: Some("BR".to_string()),
            isp: Some("Unit Test ISP".to_string()),
            is_tor: false,
        };
        let geo_json = serde_json::to_string(&cached_geo).expect("geo json");
        let abuse_json = serde_json::to_string(&cached_abuse).expect("abuse json");
        store
            .kv_set_with_expiry(
                GEOIP_CACHE_NS,
                ip,
                geo_json.as_bytes(),
                Some(&(chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339()),
            )
            .expect("set geo cache");
        store
            .kv_set_with_expiry(
                ABUSEIPDB_CACHE_NS,
                ip,
                abuse_json.as_bytes(),
                Some(&(chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339()),
            )
            .expect("set abuse cache");

        backfill_enrichment(&mut state).await;

        let profile = state.attacker_profiles.get(ip).expect("profile updated");
        assert!(profile.geo.is_some());
        assert_eq!(profile.abuseipdb_score, Some(64));
    }

    /// Coverage anchor (test/coverage-batch-3 — 2026-05-07): when
    /// `state.threat_feed` is None, `log_threat_feed_match` returns
    /// immediately without panicking. Pins the early-return branch
    /// (`let Some(tf) = state.threat_feed.as_ref() else { return; }`).
    #[test]
    fn log_threat_feed_match_returns_when_threat_feed_disabled() {
        let dir = TempDir::new().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let incident = crate::tests::test_incident("203.0.113.60");
        // No assertion beyond "does not panic" — the contract is no-op.
        log_threat_feed_match(&incident, &state);
    }

    /// Coverage anchor: when `state.geoip_client` is None,
    /// `lookup_incident_geoip` returns None without attempting any
    /// network call. Pins the `?` short-circuit on the client option.
    #[tokio::test]
    async fn lookup_incident_geoip_returns_none_when_client_disabled() {
        let dir = TempDir::new().expect("tempdir");
        let state = crate::tests::triage_test_state(dir.path());
        let incident = crate::tests::test_incident("203.0.113.61");

        let result = lookup_incident_geoip(&incident, &state).await;
        assert!(result.is_none(), "no client must return None");
    }

    /// Coverage anchor: when both `ip_geo` and `ip_reputation` are
    /// None, `enrich_attacker_identity` short-circuits and never
    /// touches `attacker_profiles`. Pins the cheap-exit contract on
    /// the very first line of the function.
    #[test]
    fn enrich_attacker_identity_returns_early_when_no_inputs() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let incident = crate::tests::test_incident("203.0.113.62");

        enrich_attacker_identity(&incident, &mut state, None, None);

        assert!(
            !state.attacker_profiles.contains_key("203.0.113.62"),
            "no enrichment data must not create a profile"
        );
    }

    /// Coverage anchor: when an incident has no IP entity,
    /// `enrich_attacker_identity` walks the entities list, finds
    /// nothing, and skips the mutation block — no profile is
    /// created even with valid GeoIP/AbuseIPDB inputs.
    #[test]
    fn enrich_attacker_identity_skips_when_no_ip_entity() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let mut incident = crate::tests::test_incident("203.0.113.63");
        incident.entities = vec![]; // strip IP entity
        let geo = geoip::GeoInfo {
            country: "Brazil".to_string(),
            country_code: "BR".to_string(),
            city: "Sao Paulo".to_string(),
            isp: "ISP".to_string(),
            asn: "AS1".to_string(),
        };

        enrich_attacker_identity(&incident, &mut state, Some(&geo), None);

        assert!(
            state.attacker_profiles.is_empty(),
            "no IP entity must skip profile mutation"
        );
    }

    /// Coverage anchor: when both `geoip_client` and `abuseipdb` are
    /// None, `backfill_enrichment` returns immediately without
    /// touching `attacker_profiles` or SQLite. Pins the
    /// nothing-to-do early exit at the top of the function.
    #[tokio::test]
    async fn backfill_enrichment_returns_early_when_no_clients() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let ip = "8.8.8.8";
        state.attacker_profiles.insert(
            ip.to_string(),
            attacker_intel::new_profile(ip, chrono::Utc::now()),
        );

        backfill_enrichment(&mut state).await;

        let profile = state.attacker_profiles.get(ip).expect("profile preserved");
        assert!(profile.geo.is_none(), "no client must skip enrichment");
        assert!(profile.abuseipdb_score.is_none());
    }

    #[tokio::test]
    async fn backfill_enrichment_respects_daily_abuseipdb_limit() {
        let dir = TempDir::new().expect("tempdir");
        let mut state = crate::tests::triage_test_state(dir.path());
        let store = crate::tests::test_sqlite_store(dir.path());
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let key = format!("abuseipdb_daily_{today}");
        store
            .kv_set(
                ABUSEIPDB_LIMITS_NS,
                &key,
                ABUSEIPDB_DAILY_LIMIT.to_string().as_bytes(),
            )
            .expect("set daily counter");
        state.sqlite_store = Some(store);
        state.abuseipdb = Some(abuseipdb::AbuseIpDbClient::new(String::new(), 30));
        let ip = "203.0.113.80";
        state.attacker_profiles.insert(
            ip.to_string(),
            attacker_intel::new_profile(ip, chrono::Utc::now()),
        );

        backfill_enrichment(&mut state).await;

        let profile = state.attacker_profiles.get(ip).expect("profile exists");
        assert!(profile.geo.is_none());
        assert!(profile.abuseipdb_score.is_none());
    }
}
