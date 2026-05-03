//! Persistent IP → geolocation cache (Wave 6a, 2026-05-03).
//!
//! Background — operator-visible bug: with 138 unique attacker IPs in
//! the last 24 h (and growing), the public site's `Attack origins` map
//! was making 138 calls to ip-api.com on every page load. ip-api free
//! tier is 45 req/min, so the first 45 markers appeared, then the
//! frontend hit HTTP 429 and the rest of the markers stayed grey. On
//! cold cache the operator's tester would see "their" attack at the
//! tail of the queue, ~3 minutes after the actual block.
//!
//! Fix: cache `{ip → {country, lat, lon, ts}}` on disk with a 7-day
//! TTL. The slow_loop pre-warms the cache for IPs in the incidents
//! JSONL so the front-page payload already carries geo data; the
//! `/api/live-feed/geoip` proxy consults the cache before falling
//! through to ip-api.
//!
//! On-disk layout: `geo-cache.json` next to `baseline.json` and
//! `responses.json`. Single JSON object keyed by IP. Serializing the
//! whole map per save is fine because:
//! - typical size is sub-100 KB even at 10 k IPs
//! - writes happen on the slow_loop cadence, not per request
//! - rebuilding from the JSONL incidents on cache loss is cheap
//!
//! All public functions are pure on the data — I/O lives at the
//! edges so tests can drive the cache without touching the disk or
//! the network.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// How long a cached entry stays valid. ip-api results are stable
/// (an ASN does not change country in 7 days), so weekly refresh
/// keeps the cache useful without re-burning rate budget on every
/// agent restart.
pub(crate) const CACHE_TTL_SECS: i64 = 7 * 24 * 60 * 60;

/// One geolocation entry for one IP. Serialised verbatim — the wire
/// shape is the on-disk shape so a future migration that adds e.g.
/// `city` only needs `#[serde(default)]` for back-compat with old
/// caches.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoEntry {
    pub country: String,
    pub lat: f64,
    pub lon: f64,
    /// Unix timestamp the lookup was performed. Used for TTL.
    pub ts: i64,
}

impl GeoEntry {
    /// Has this entry expired against the given `now` Unix timestamp?
    pub fn is_expired(&self, now: i64) -> bool {
        now - self.ts >= CACHE_TTL_SECS
    }
}

/// In-memory cache. Wrap in `RwLock` for concurrent access.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GeoCache {
    entries: HashMap<String, GeoEntry>,
}

impl GeoCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 2026-05-03 (Wave 6a): retained as part of the public-ish
    /// cache API even though no production caller hits it yet —
    /// follow-up PR for the slow_loop pre-warm tick (deferred from
    /// 6a) is the natural caller. Tests use it; production will too.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Fetch a fresh entry. Returns `None` if missing or expired —
    /// the caller is expected to re-fetch from ip-api (or skip) on
    /// `None`.
    pub fn get_fresh(&self, ip: &str, now: i64) -> Option<&GeoEntry> {
        let entry = self.entries.get(ip)?;
        if entry.is_expired(now) {
            None
        } else {
            Some(entry)
        }
    }

    /// Insert / overwrite an entry. Caller is responsible for
    /// stamping `ts = now` so the TTL is consistent.
    pub fn put(&mut self, ip: String, entry: GeoEntry) {
        self.entries.insert(ip, entry);
    }

    /// Drop entries older than the TTL. Returns how many were
    /// removed so the caller can log a single line on each sweep.
    ///
    /// 2026-05-03 (Wave 6a): retained for the slow_loop pre-warm
    /// tick that follows in a separate PR. The `get_fresh` path
    /// already filters stale on read, so the cache stays correct
    /// even when this is not called periodically — sweep is a
    /// memory hygiene concern, not a correctness one.
    #[allow(dead_code)]
    pub fn evict_expired(&mut self, now: i64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| !e.is_expired(now));
        before - self.entries.len()
    }
}

/// 2026-05-03 (Wave 6a CodeQL fix): `data_dir` arrives from the
/// agent's CLI / `[agent.data_dir]` config and CodeQL's
/// `rust/path-injection` rule (CWE-22) treats any file I/O on a
/// path derived from it as user-tainted. The agent's own data dir
/// is operator-controlled rather than attacker-controlled, but the
/// canonicalise + `starts_with` defence is the same shape we already
/// use in `dashboard/live_feed.rs::load_ip_reputation_map` for
/// `ip-reputation.json` next door — adopt it here so:
///
/// 1. CodeQL's taint analysis sees the parent dir resolved through
///    `canonicalize()` (breaks the symlink-traversal class) and the
///    join target verified against it via `starts_with` (breaks the
///    `..`-in-filename class — defensive even though our filename
///    is hardcoded `"geo-cache.json"`).
/// 2. A future caller that constructs `data_dir` from less-trusted
///    input inherits the same hardening.
///
/// Returns `None` when the data_dir cannot be canonicalised
/// (does not exist, no read permission). Both `load_cache` and
/// `save_cache` treat `None` as "no cache I/O this tick" — same
/// degraded-IO shape as a missing file, which the slow_loop already
/// retries on the next pass.
fn safe_cache_path(data_dir: &Path) -> Option<PathBuf> {
    let canonical_dir = data_dir.canonicalize().ok()?;
    let path = canonical_dir.join("geo-cache.json");
    if !path.starts_with(&canonical_dir) {
        return None;
    }
    Some(path)
}

/// Load the cache from disk. Returns an empty cache on any I/O or
/// parse failure — the cache is best-effort and rebuilds from the
/// JSONL incidents on the next slow_loop tick.
pub fn load_cache(data_dir: &Path) -> GeoCache {
    let Some(path) = safe_cache_path(data_dir) else {
        return GeoCache::new();
    };
    let Ok(content) = std::fs::read_to_string(&path) else {
        return GeoCache::new();
    };
    match serde_json::from_str::<GeoCache>(&content) {
        Ok(c) => {
            debug!(entries = c.len(), "geo cache loaded from disk");
            c
        }
        Err(e) => {
            warn!("failed to parse geo-cache.json (rebuilding): {e:#}");
            GeoCache::new()
        }
    }
}

/// Persist the cache to disk. Atomic via tmp-rename so a crash
/// mid-write cannot leave a half-written file. Returns `Ok(())` on
/// success; a write failure is logged at `warn!` and swallowed by
/// the caller (the cache stays in memory and the next save retries).
pub fn save_cache(data_dir: &Path, cache: &GeoCache) -> std::io::Result<()> {
    let path = safe_cache_path(data_dir).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "data_dir cannot be canonicalised; refusing to write geo-cache.json",
        )
    })?;
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_string(cache)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-05-03 (Wave 6a anchor): TTL boundary. Pinned so a
    /// future "let's bump TTL to 30 days" change is loud and
    /// reviewer sees the rate-budget impact.
    #[test]
    fn entry_expires_exactly_at_ttl_boundary() {
        let now = 1_000_000_i64;
        let entry = GeoEntry {
            country: "GB".into(),
            lat: 51.5,
            lon: -0.1,
            ts: now - CACHE_TTL_SECS + 1,
        };
        assert!(!entry.is_expired(now), "1s under TTL must be fresh");
        let stale = GeoEntry {
            country: "GB".into(),
            lat: 51.5,
            lon: -0.1,
            ts: now - CACHE_TTL_SECS,
        };
        assert!(stale.is_expired(now), "exactly at TTL must be expired");
    }

    /// 2026-05-03 (Wave 6a anchor): cache miss + cache hit + cache
    /// stale. The site map's per-page-load cost depends on this
    /// being right — a regression that "always returns Some" would
    /// silently serve stale geo data, and a regression that "never
    /// returns Some" would re-ddos ip-api on every page load.
    #[test]
    fn get_fresh_distinguishes_hit_miss_and_stale() {
        let mut cache = GeoCache::new();
        let now = 1_000_000_i64;
        cache.put(
            "1.2.3.4".into(),
            GeoEntry {
                country: "RU".into(),
                lat: 55.7,
                lon: 37.6,
                ts: now - 100,
            },
        );
        cache.put(
            "5.6.7.8".into(),
            GeoEntry {
                country: "BR".into(),
                lat: -23.5,
                lon: -46.6,
                ts: now - CACHE_TTL_SECS - 1, // stale
            },
        );

        // Hit: fresh entry returned.
        assert_eq!(
            cache.get_fresh("1.2.3.4", now).map(|e| e.country.as_str()),
            Some("RU")
        );
        // Miss: unknown IP.
        assert!(cache.get_fresh("9.9.9.9", now).is_none());
        // Stale: present but past TTL → returned as None so the
        // caller refreshes.
        assert!(cache.get_fresh("5.6.7.8", now).is_none());
    }

    #[test]
    fn evict_expired_drops_only_stale_entries() {
        let mut cache = GeoCache::new();
        let now = 1_000_000_i64;
        cache.put(
            "fresh".into(),
            GeoEntry {
                country: "GB".into(),
                lat: 51.5,
                lon: -0.1,
                ts: now - 60,
            },
        );
        cache.put(
            "stale".into(),
            GeoEntry {
                country: "RU".into(),
                lat: 55.7,
                lon: 37.6,
                ts: now - CACHE_TTL_SECS - 1,
            },
        );
        let removed = cache.evict_expired(now);
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 1);
        assert!(cache.entries.contains_key("fresh"));
        assert!(!cache.entries.contains_key("stale"));
    }

    #[test]
    fn save_then_load_roundtrip_preserves_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut cache = GeoCache::new();
        cache.put(
            "1.2.3.4".into(),
            GeoEntry {
                country: "RU".into(),
                lat: 55.7,
                lon: 37.6,
                ts: 1_000_000,
            },
        );
        save_cache(dir.path(), &cache).unwrap();
        let loaded = load_cache(dir.path());
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded
                .get_fresh("1.2.3.4", 1_000_000)
                .map(|e| e.country.as_str()),
            Some("RU")
        );
    }

    #[test]
    fn load_returns_empty_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let cache = load_cache(dir.path());
        assert!(cache.is_empty());
    }

    #[test]
    fn load_returns_empty_on_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("geo-cache.json"), b"not json").unwrap();
        let cache = load_cache(dir.path());
        assert!(cache.is_empty());
    }

    /// 2026-05-03 (Wave 6a): the canonicalize+starts_with guard is the
    /// CodeQL-mitigation surface; pin its happy + sad paths so a
    /// future refactor that drops one of the two branches surfaces
    /// loud at test time, not at the next CI scan.
    #[test]
    fn safe_cache_path_returns_some_for_existing_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = safe_cache_path(dir.path()).expect("existing data_dir must canonicalise");
        // Joined target ends with the hardcoded filename, never escapes.
        assert!(path.ends_with("geo-cache.json"));
        assert!(path.starts_with(dir.path().canonicalize().unwrap()));
    }

    #[test]
    fn safe_cache_path_returns_none_for_missing_data_dir() {
        // canonicalize fails → None → callers degrade to "no cache I/O".
        let missing =
            std::path::PathBuf::from("/nonexistent/innerwarden-test-dir-does-not-exist-xyz");
        assert!(safe_cache_path(&missing).is_none());
    }

    #[test]
    fn save_cache_returns_permission_denied_for_missing_data_dir() {
        // Pairs with the safe_cache_path None path: when the dir
        // cannot be canonicalised, save_cache surfaces a typed
        // PermissionDenied error instead of writing to nowhere.
        let missing =
            std::path::PathBuf::from("/nonexistent/innerwarden-test-dir-does-not-exist-xyz");
        let err = save_cache(&missing, &GeoCache::new()).expect_err("missing dir must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn load_cache_returns_empty_for_missing_data_dir() {
        // Same shape on the read side — None from safe_cache_path
        // means "best-effort: no cache today".
        let missing =
            std::path::PathBuf::from("/nonexistent/innerwarden-test-dir-does-not-exist-xyz");
        let cache = load_cache(&missing);
        assert!(cache.is_empty());
    }

    #[test]
    fn save_then_load_records_lookup_round_trip_with_real_geo_data() {
        // End-to-end coverage for the operator-visible flow:
        //   1. agent fetches a fresh geo lookup (e.g. via
        //      api_live_feed_geoip on cache miss),
        //   2. writes it to disk via save_cache,
        //   3. next page load hits load_cache and returns the
        //      pre-attached geo to the site map without a network
        //      round-trip.
        // The round-trip pinned in `save_then_load_roundtrip_preserves_entries`
        // covers a single entry; this exercises a 3-IP cache to
        // pick up the iter + put paths used by api_live_feed_geoip.
        let dir = tempfile::tempdir().unwrap();
        let now = chrono::Utc::now().timestamp();
        let mut cache = GeoCache::new();
        for (ip, country, lat, lon) in [
            ("1.2.3.4", "RU", 55.7, 37.6),
            ("5.6.7.8", "BR", -23.5, -46.6),
            ("9.9.9.9", "US", 37.7, -122.4),
        ] {
            cache.put(
                ip.into(),
                GeoEntry {
                    country: country.into(),
                    lat,
                    lon,
                    ts: now,
                },
            );
        }
        save_cache(dir.path(), &cache).expect("save");
        let loaded = load_cache(dir.path());
        assert_eq!(loaded.len(), 3);
        for (ip, country) in [("1.2.3.4", "RU"), ("5.6.7.8", "BR"), ("9.9.9.9", "US")] {
            let entry = loaded.get_fresh(ip, now).expect(ip);
            assert_eq!(entry.country, country);
        }
    }
}
