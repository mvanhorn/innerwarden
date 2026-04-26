//! Persistent state store backed by SQLite (via `innerwarden_store`).
//!
//! Replaces the previous redb implementation. Data lives in the unified
//! `innerwarden.db` SQLite database using KV namespaces.
//!
//! Namespaces:
//!   - ip_reputations:          IP → JSON (LocalIpReputation)
//!   - decision_cooldowns:      key → timestamp_ms (i64 LE bytes)
//!   - notification_cooldowns:  key → timestamp_ms (i64 LE bytes)
//!   - block_counts:            IP → count (u32 LE bytes)
//!   - xdp_block_times:         IP → JSON { blocked_at_ms, ttl_secs }
//!   - recent_blocks:           timestamp_ms_str → [1u8] (rate-limiter window)
//!   - trust_rules:             "detector:action" → [1u8]
//!   - attacker_profiles:       IP → JSON (AttackerProfile)

use anyhow::{Context, Result};
use innerwarden_store::Store;
use std::path::Path;
use tracing::{info, warn};

/// Namespace constants
const NS_IP_REPUTATIONS: &str = "ip_reputations";
const NS_DECISION_COOLDOWNS: &str = "decision_cooldowns";
const NS_NOTIFICATION_COOLDOWNS: &str = "notification_cooldowns";
const NS_BLOCK_COUNTS: &str = "block_counts";
const NS_XDP_BLOCK_TIMES: &str = "xdp_block_times";
const NS_RECENT_BLOCKS: &str = "recent_blocks";
const NS_TRUST_RULES: &str = "trust_rules";
const NS_ATTACKER_PROFILES: &str = "attacker_profiles";

/// Persistent state store for the agent.
pub struct StateStore {
    store: Store,
}

#[allow(dead_code)]
impl StateStore {
    /// Open or create the state database at `data_dir/innerwarden.db`.
    pub fn open(data_dir: &Path) -> Result<Self> {
        let store = Store::open(data_dir)
            .with_context(|| format!("failed to open state store: {}", data_dir.display()))?;

        info!(path = %data_dir.display(), "state store opened (sqlite)");
        Ok(Self { store })
    }

    // ── IP Reputations ──────────────────────────────────────────────

    pub fn get_ip_reputation(&self, ip: &str) -> Option<serde_json::Value> {
        match self.store.kv_get(NS_IP_REPUTATIONS, ip) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
            Ok(None) => None,
            Err(e) => {
                warn!(error = %e, "get_ip_reputation failed");
                None
            }
        }
    }

    pub fn set_ip_reputation(&self, ip: &str, value: &serde_json::Value) {
        let data = serde_json::to_vec(value).unwrap_or_default();
        if let Err(e) = self.store.kv_set(NS_IP_REPUTATIONS, ip, &data) {
            warn!(error = %e, "set_ip_reputation failed");
        }
    }

    pub fn all_ip_reputations(&self) -> Vec<(String, serde_json::Value)> {
        match self.store.kv_list(NS_IP_REPUTATIONS) {
            Ok(entries) => entries
                .into_iter()
                .filter_map(|(k, v)| {
                    serde_json::from_slice::<serde_json::Value>(&v)
                        .ok()
                        .map(|val| (k, val))
                })
                .collect(),
            Err(e) => {
                warn!(error = %e, "all_ip_reputations failed");
                Vec::new()
            }
        }
    }

    pub fn ip_reputations_len(&self) -> usize {
        self.store.kv_count(NS_IP_REPUTATIONS).unwrap_or(0)
    }

    /// Remove entries beyond `max` by keeping the most recently seen.
    /// Called during slow-loop cleanup.
    pub fn trim_ip_reputations(&self, max: usize) {
        let len = self.ip_reputations_len();
        if len <= max {
            return;
        }
        // Collect all, sort by last_seen, keep top `max`
        let mut all = self.all_ip_reputations();
        all.sort_by(|a, b| {
            let ts_a = a.1["last_seen"].as_str().unwrap_or("");
            let ts_b = b.1["last_seen"].as_str().unwrap_or("");
            ts_b.cmp(ts_a) // newest first
        });
        let to_remove: Vec<String> = all.into_iter().skip(max).map(|(k, _)| k).collect();
        for ip in &to_remove {
            if let Err(e) = self.store.kv_delete(NS_IP_REPUTATIONS, ip) {
                warn!(error = %e, ip = %ip, "trim_ip_reputations delete failed");
            }
        }
    }

    // ── Cooldowns (decision + notification) ─────────────────────────

    pub fn get_cooldown(
        &self,
        table_def: CooldownTable,
        key: &str,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        let ns = table_def.namespace();
        match self.store.kv_get(ns, key) {
            Ok(Some(bytes)) => {
                if bytes.len() == 8 {
                    let ms = i64::from_le_bytes(bytes.try_into().ok()?);
                    chrono::DateTime::from_timestamp_millis(ms)
                } else {
                    None
                }
            }
            Ok(None) => None,
            Err(e) => {
                warn!(error = %e, "get_cooldown failed");
                None
            }
        }
    }

    pub fn set_cooldown(
        &self,
        table_def: CooldownTable,
        key: &str,
        ts: chrono::DateTime<chrono::Utc>,
    ) {
        let ns = table_def.namespace();
        let bytes = ts.timestamp_millis().to_le_bytes();
        if let Err(e) = self.store.kv_set(ns, key, &bytes) {
            warn!(error = %e, "set_cooldown failed");
        }
    }

    pub fn has_cooldown(&self, table_def: CooldownTable, key: &str) -> bool {
        self.get_cooldown(table_def, key).is_some()
    }

    /// Remove entries older than `cutoff`.
    pub fn retain_cooldowns(
        &self,
        table_def: CooldownTable,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) {
        let ns = table_def.namespace();
        let cutoff_ms = cutoff.timestamp_millis();
        let entries = match self.store.kv_list(ns) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "retain_cooldowns list failed");
                return;
            }
        };
        for (key, bytes) in entries {
            if bytes.len() == 8 {
                let ms = i64::from_le_bytes(bytes.try_into().unwrap());
                if ms <= cutoff_ms {
                    if let Err(e) = self.store.kv_delete(ns, &key) {
                        warn!(error = %e, key = %key, "retain_cooldowns delete failed");
                    }
                }
            }
        }
    }

    // ── Block Counts ────────────────────────────────────────────────

    pub fn get_block_count(&self, ip: &str) -> u32 {
        match self.store.kv_get(NS_BLOCK_COUNTS, ip) {
            Ok(Some(bytes)) if bytes.len() == 4 => u32::from_le_bytes(bytes.try_into().unwrap()),
            Ok(_) => 0,
            Err(e) => {
                warn!(error = %e, "get_block_count failed");
                0
            }
        }
    }

    pub fn increment_block_count(&self, ip: &str) -> u32 {
        let current = self.get_block_count(ip);
        let new_count = current + 1;
        let bytes = new_count.to_le_bytes();
        if let Err(e) = self.store.kv_set(NS_BLOCK_COUNTS, ip, &bytes) {
            warn!(error = %e, "increment_block_count failed");
        }
        new_count
    }

    pub fn clear_block_counts(&self) {
        if let Err(e) = self.store.kv_clear(NS_BLOCK_COUNTS) {
            warn!(error = %e, "clear_block_counts failed");
        }
    }

    pub fn block_counts_len(&self) -> usize {
        self.store.kv_count(NS_BLOCK_COUNTS).unwrap_or(0)
    }

    // ── XDP Block Times ─────────────────────────────────────────────

    pub fn get_xdp_block_time(&self, ip: &str) -> Option<(chrono::DateTime<chrono::Utc>, i64)> {
        match self.store.kv_get(NS_XDP_BLOCK_TIMES, ip) {
            Ok(Some(bytes)) => {
                let val: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
                let blocked_at = val["blocked_at_ms"].as_i64()?;
                let ttl = val["ttl_secs"].as_i64().unwrap_or(0);
                Some((chrono::DateTime::from_timestamp_millis(blocked_at)?, ttl))
            }
            Ok(None) => None,
            Err(e) => {
                warn!(error = %e, "get_xdp_block_time failed");
                None
            }
        }
    }

    pub fn set_xdp_block_time(
        &self,
        ip: &str,
        blocked_at: chrono::DateTime<chrono::Utc>,
        ttl_secs: i64,
    ) {
        let val = serde_json::json!({
            "blocked_at_ms": blocked_at.timestamp_millis(),
            "ttl_secs": ttl_secs,
        });
        let data = serde_json::to_vec(&val).unwrap_or_default();
        if let Err(e) = self.store.kv_set(NS_XDP_BLOCK_TIMES, ip, &data) {
            warn!(error = %e, "set_xdp_block_time failed");
        }
    }

    pub fn remove_xdp_block_time(&self, ip: &str) {
        if let Err(e) = self.store.kv_delete(NS_XDP_BLOCK_TIMES, ip) {
            warn!(error = %e, "remove_xdp_block_time failed");
        }
    }

    pub fn all_xdp_block_times(&self) -> Vec<(String, chrono::DateTime<chrono::Utc>, i64)> {
        match self.store.kv_list(NS_XDP_BLOCK_TIMES) {
            Ok(entries) => entries
                .into_iter()
                .filter_map(|(k, v)| {
                    let val: serde_json::Value = serde_json::from_slice(&v).ok()?;
                    let ms = val["blocked_at_ms"].as_i64()?;
                    let ttl = val["ttl_secs"].as_i64()?;
                    let dt = chrono::DateTime::from_timestamp_millis(ms)?;
                    Some((k, dt, ttl))
                })
                .collect(),
            Err(e) => {
                warn!(error = %e, "all_xdp_block_times failed");
                Vec::new()
            }
        }
    }

    /// Warm-cache loader for `AgentState::xdp_block_times`.
    ///
    /// Spec 037 PR-1 (I-02 slice 1): SQLite `xdp_block_times` namespace
    /// becomes the canonical persisted store. The in-memory HashMap
    /// reverts to a runtime view rebuilt at boot from this method. A
    /// failed read (corrupted row, KV backend unavailable) is already
    /// swallowed by `all_xdp_block_times` with a `warn!` — this method
    /// inherits that behaviour and returns an empty map in the
    /// degraded case. Same semantic as pre-I-02 boot: no TTL
    /// accounting, cleanup loop is a no-op, kernel rules continue
    /// blocking until reinserted.
    pub fn load_xdp_block_times(
        &self,
    ) -> std::collections::HashMap<String, (chrono::DateTime<chrono::Utc>, i64)> {
        self.all_xdp_block_times()
            .into_iter()
            .map(|(ip, ts, ttl)| (ip, (ts, ttl)))
            .collect()
    }

    // ── Recent Blocks (rate-limiter warm cache) ─────────────────────
    //
    // Spec 037 I-07 slice 2: persists the rolling-window block-rate
    // counter so a restart does not reset it to zero. Pre-PR the
    // `AgentState::recent_blocks` `VecDeque` reset on every boot,
    // letting a burst of `MAX_BLOCKS_PER_MINUTE` blocks land in the
    // first second after a crash before the window refilled. The
    // canonical store is now this namespace; the in-memory `VecDeque`
    // is rebuilt at boot via `load_recent_blocks_within`.
    //
    // Storage shape: key = `timestamp_millis().to_string()`, value =
    // sentinel `[1u8]`. Only the timestamp matters; the value is
    // present so the row exists. Same semantic the audit recommends
    // ("each cache rebuilt from SQLite at boot") and the same shape
    // as XDP PR-1 minus the per-IP TTL (recent_blocks tracks events,
    // not entities).

    /// Append one block timestamp to the persisted rate-limit window.
    /// Failure is logged at `warn!` and degrades to pre-PR behaviour
    /// (the in-memory `VecDeque` still gets the entry; only the
    /// restart-survival property is lost).
    pub fn set_recent_block(&self, ts: chrono::DateTime<chrono::Utc>) {
        let key = ts.timestamp_millis().to_string();
        if let Err(e) = self.store.kv_set(NS_RECENT_BLOCKS, &key, &[1u8]) {
            warn!(error = %e, "set_recent_block failed");
        }
    }

    /// Delete every persisted block timestamp older than `cutoff_ms`.
    /// Mirrors the in-memory `retain` so the namespace does not grow
    /// without bound. Iterates `kv_list` and per-row deletes — fine
    /// for the low-volume namespace (≤ MAX_BLOCKS_PER_MINUTE entries
    /// in steady state).
    pub fn prune_recent_blocks_before(&self, cutoff_ms: i64) {
        let entries = match self.store.kv_list(NS_RECENT_BLOCKS) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "prune_recent_blocks: kv_list failed");
                return;
            }
        };
        for (key, _) in entries {
            let Ok(ts_ms) = key.parse::<i64>() else {
                continue;
            };
            if ts_ms < cutoff_ms {
                if let Err(e) = self.store.kv_delete(NS_RECENT_BLOCKS, &key) {
                    warn!(error = %e, key, "prune_recent_blocks: kv_delete failed");
                }
            }
        }
    }

    /// Warm-cache loader for `AgentState::recent_blocks`. Returns the
    /// timestamps inside `window_secs` of `now`, sorted oldest-first
    /// to match the `VecDeque` semantics of the rate-limiter (which
    /// `push_back`s newest and reads `len()` to compare against
    /// `MAX_BLOCKS_PER_MINUTE`). Entries OUTSIDE the window are
    /// dropped from SQLite during this call so a long agent uptime
    /// does not accumulate stale rows in the namespace.
    pub fn load_recent_blocks_within(
        &self,
        window_secs: i64,
    ) -> std::collections::VecDeque<chrono::DateTime<chrono::Utc>> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let cutoff_ms = now_ms - window_secs * 1000;

        let entries = match self.store.kv_list(NS_RECENT_BLOCKS) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "load_recent_blocks_within: kv_list failed");
                return std::collections::VecDeque::new();
            }
        };

        // Two passes: first prune stale rows, then collect surviving
        // ones. `kv_list` already returns rows ordered by key (the
        // millis-timestamp string), which is monotonic for keys of
        // the same width — sufficient for VecDeque oldest-first
        // ordering in practice (in-memory `push_back` would only see
        // newer entries from this point on).
        let mut out = std::collections::VecDeque::new();
        for (key, _) in entries {
            let Ok(ts_ms) = key.parse::<i64>() else {
                // Malformed key — drop it; it cannot participate in
                // the rate-limit window.
                let _ = self.store.kv_delete(NS_RECENT_BLOCKS, &key);
                continue;
            };
            if ts_ms < cutoff_ms {
                if let Err(e) = self.store.kv_delete(NS_RECENT_BLOCKS, &key) {
                    warn!(error = %e, key, "load_recent_blocks_within: prune kv_delete failed");
                }
                continue;
            }
            if let Some(dt) = chrono::DateTime::from_timestamp_millis(ts_ms) {
                out.push_back(dt);
            }
        }
        out
    }

    // ── Trust Rules ─────────────────────────────────────────────────

    pub fn has_trust_rule(&self, key: &str) -> bool {
        match self.store.kv_get(NS_TRUST_RULES, key) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                warn!(error = %e, "has_trust_rule failed");
                false
            }
        }
    }

    pub fn add_trust_rule(&self, key: &str) {
        if let Err(e) = self.store.kv_set(NS_TRUST_RULES, key, &[1u8]) {
            warn!(error = %e, "add_trust_rule failed");
        }
    }

    // ── Attacker Profiles ────────────────────────────────────────────

    pub fn get_attacker_profile(&self, ip: &str) -> Option<serde_json::Value> {
        match self.store.kv_get(NS_ATTACKER_PROFILES, ip) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
            Ok(None) => None,
            Err(e) => {
                warn!(error = %e, "get_attacker_profile failed");
                None
            }
        }
    }

    pub fn set_attacker_profile(&self, ip: &str, value: &serde_json::Value) {
        let data = serde_json::to_vec(value).unwrap_or_default();
        if let Err(e) = self.store.kv_set(NS_ATTACKER_PROFILES, ip, &data) {
            warn!(error = %e, "set_attacker_profile failed");
        }
    }

    pub fn all_attacker_profiles(&self) -> Vec<(String, serde_json::Value)> {
        match self.store.kv_list(NS_ATTACKER_PROFILES) {
            Ok(entries) => entries
                .into_iter()
                .filter_map(|(k, v)| {
                    serde_json::from_slice::<serde_json::Value>(&v)
                        .ok()
                        .map(|val| (k, val))
                })
                .collect(),
            Err(e) => {
                warn!(error = %e, "all_attacker_profiles failed");
                Vec::new()
            }
        }
    }

    pub fn remove_attacker_profile(&self, ip: &str) {
        if let Err(e) = self.store.kv_delete(NS_ATTACKER_PROFILES, ip) {
            warn!(error = %e, "remove_attacker_profile failed");
        }
    }

    pub fn attacker_profiles_len(&self) -> usize {
        self.store.kv_count(NS_ATTACKER_PROFILES).unwrap_or(0)
    }

    /// Remove entries beyond `max` by keeping those with the highest risk_score.
    pub fn trim_attacker_profiles(&self, max: usize) {
        let len = self.attacker_profiles_len();
        if len <= max {
            return;
        }
        let mut all = self.all_attacker_profiles();
        // Sort by risk_score descending, then last_seen descending
        all.sort_by(|a, b| {
            let score_a = a.1["risk_score"].as_u64().unwrap_or(0);
            let score_b = b.1["risk_score"].as_u64().unwrap_or(0);
            score_b.cmp(&score_a).then_with(|| {
                let ts_a = a.1["last_seen"].as_str().unwrap_or("");
                let ts_b = b.1["last_seen"].as_str().unwrap_or("");
                ts_b.cmp(ts_a)
            })
        });
        let to_remove: Vec<String> = all.into_iter().skip(max).map(|(k, _)| k).collect();
        for ip in &to_remove {
            if let Err(e) = self.store.kv_delete(NS_ATTACKER_PROFILES, ip) {
                warn!(error = %e, ip = %ip, "trim_attacker_profiles delete failed");
            }
        }
    }

    /// Checkpoint the WAL (replaces redb compact).
    pub fn compact(&mut self) {
        if let Err(e) = self.store.wal_checkpoint() {
            warn!(error = %e, "state store WAL checkpoint failed");
        }
    }
}

/// Which cooldown table to operate on.
#[derive(Clone, Copy)]
pub enum CooldownTable {
    Decision,
    Notification,
}

impl CooldownTable {
    fn namespace(&self) -> &'static str {
        match self {
            CooldownTable::Decision => NS_DECISION_COOLDOWNS,
            CooldownTable::Notification => NS_NOTIFICATION_COOLDOWNS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store() -> (TempDir, StateStore) {
        let dir = TempDir::new().unwrap();
        let store = StateStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn cooldown_insert_and_get() {
        let (_dir, store) = make_store();
        let now = chrono::Utc::now();
        store.set_cooldown(CooldownTable::Decision, "test:key", now);
        assert!(store.has_cooldown(CooldownTable::Decision, "test:key"));
        assert!(!store.has_cooldown(CooldownTable::Decision, "other:key"));
    }

    #[test]
    fn block_count_increment() {
        let (_dir, store) = make_store();
        assert_eq!(store.get_block_count("1.2.3.4"), 0);
        store.increment_block_count("1.2.3.4");
        assert_eq!(store.get_block_count("1.2.3.4"), 1);
        store.increment_block_count("1.2.3.4");
        assert_eq!(store.get_block_count("1.2.3.4"), 2);
    }

    #[test]
    fn ip_reputation_roundtrip() {
        let (_dir, store) = make_store();
        let val = serde_json::json!({"score": 42, "last_seen": "2026-01-01T00:00:00Z"});
        store.set_ip_reputation("10.0.0.1", &val);
        let got = store.get_ip_reputation("10.0.0.1").unwrap();
        assert_eq!(got["score"], 42);
        assert_eq!(store.ip_reputations_len(), 1);
    }

    #[test]
    fn trust_rule_add_and_check() {
        let (_dir, store) = make_store();
        assert!(!store.has_trust_rule("ssh:block"));
        store.add_trust_rule("ssh:block");
        assert!(store.has_trust_rule("ssh:block"));
    }

    #[test]
    fn xdp_block_time_roundtrip() {
        let (_dir, store) = make_store();
        let now = chrono::Utc::now();
        store.set_xdp_block_time("5.6.7.8", now, 3600);
        let (dt, ttl) = store.get_xdp_block_time("5.6.7.8").unwrap();
        assert_eq!(ttl, 3600);
        assert!((dt - now).num_seconds().abs() < 1);
    }

    // ─────────────────────────────────────────────────────────────────
    // Spec 037 PR-1 — `load_xdp_block_times` warm-cache anchors
    // ─────────────────────────────────────────────────────────────────
    //
    // PR-1 of I-02 promotes SQLite `xdp_block_times` to the canonical
    // persisted store and rebuilds `AgentState::xdp_block_times` as a
    // warm-cache at boot via `load_xdp_block_times`. These tests pin
    // the behaviours the boot path depends on:
    //
    //   1. Empty store → empty map (safe fallback; pre-PR behaviour).
    //   2. Round-trip: persisted entries load back with matching TTL +
    //      timestamp (modulo sub-second drift from ms precision).
    //   3. Remove mirror: after a remove, the load result no longer
    //      contains that IP. Guards the "resurrect-expired-block"
    //      regression the operator flagged explicitly.
    //   4. Corrupt row: a malformed payload is skipped, valid siblings
    //      still load. The store never panics on boot.

    #[test]
    fn load_xdp_block_times_is_empty_on_fresh_store() {
        let (_dir, store) = make_store();
        let loaded = store.load_xdp_block_times();
        assert!(
            loaded.is_empty(),
            "fresh store MUST return an empty warm-cache — pre-PR boot behaviour"
        );
    }

    #[test]
    fn load_xdp_block_times_returns_inserted_entries() {
        let (_dir, store) = make_store();
        let now = chrono::Utc::now();
        store.set_xdp_block_time("10.0.0.1", now, 3600);
        store.set_xdp_block_time("10.0.0.2", now, 900);
        store.set_xdp_block_time("10.0.0.3", now, 60);

        let loaded = store.load_xdp_block_times();
        assert_eq!(
            loaded.len(),
            3,
            "all persisted entries must appear in the warm-cache"
        );

        let (ts1, ttl1) = loaded.get("10.0.0.1").expect("10.0.0.1 must be in the map");
        assert_eq!(*ttl1, 3600);
        assert!(
            (*ts1 - now).num_seconds().abs() < 1,
            "round-tripped timestamp must be within sub-second drift (ms precision)"
        );
        assert_eq!(loaded.get("10.0.0.2").map(|(_, ttl)| *ttl), Some(900));
        assert_eq!(loaded.get("10.0.0.3").map(|(_, ttl)| *ttl), Some(60));
    }

    #[test]
    fn load_xdp_block_times_reflects_remove_mirror() {
        // Anchors the "resurrect-expired-block" regression the
        // operator flagged: if `boot.rs` cleanup removes an entry
        // from `state.xdp_block_times` but NOT from SQLite, the
        // warm-cache on the next restart puts it back.
        let (_dir, store) = make_store();
        let now = chrono::Utc::now();
        store.set_xdp_block_time("192.0.2.10", now, 3600);
        store.set_xdp_block_time("192.0.2.11", now, 3600);

        // Simulate the `boot.rs` cleanup mirror: the live runtime
        // path calls both the HashMap remove and `remove_xdp_block_time`.
        store.remove_xdp_block_time("192.0.2.10");

        let loaded = store.load_xdp_block_times();
        assert_eq!(loaded.len(), 1);
        assert!(
            !loaded.contains_key("192.0.2.10"),
            "a removed entry MUST NOT resurface in the warm-cache"
        );
        assert!(
            loaded.contains_key("192.0.2.11"),
            "sibling entries must remain available"
        );
    }

    #[test]
    fn load_xdp_block_times_skips_corrupt_rows() {
        // Guards against a panic-on-boot regression: if a previous
        // agent version wrote a row with a missing/typed field, the
        // reader must skip it with no log-spam-at-boot (`all_xdp_block_times`
        // already does this) and return the remaining valid entries.
        let (_dir, store) = make_store();
        let now = chrono::Utc::now();
        store.set_xdp_block_time("198.51.100.5", now, 3600);

        // Write a corrupt row via the raw KV API.
        store
            .store
            .kv_set(NS_XDP_BLOCK_TIMES, "198.51.100.6", b"not-json")
            .expect("raw kv_set");

        let loaded = store.load_xdp_block_times();
        assert_eq!(
            loaded.len(),
            1,
            "corrupt row must be skipped, valid sibling must still load"
        );
        assert!(loaded.contains_key("198.51.100.5"));
    }

    // ─────────────────────────────────────────────────────────────────
    // Spec 037 I-07 slice 2 — `load_recent_blocks_within` warm-cache anchors
    // ─────────────────────────────────────────────────────────────────
    //
    // I-07 slice 2 promotes SQLite `recent_blocks` to the canonical
    // persisted store for the rate-limiter window and rebuilds
    // `AgentState::recent_blocks` as a warm-cache at boot via
    // `load_recent_blocks_within(60)`. Tests pin the boot-path
    // contract:
    //
    //   1. Empty store → empty deque (degraded fallback; pre-PR
    //      behaviour).
    //   2. Round-trip: timestamps inside the window load back.
    //   3. Stale entries (> window) are filtered AND deleted from
    //      SQLite during the load — the regression anchor for the
    //      audit's "burst can pass right after a crash" finding,
    //      generalised to "stale rows from old uptimes do not
    //      resurrect into the new window".
    //   4. `prune_recent_blocks_before` is the runtime-side mirror of
    //      the in-memory `retain`; deleting old entries must NOT
    //      touch entries inside the window.

    #[test]
    fn load_recent_blocks_is_empty_on_fresh_store() {
        let (_dir, store) = make_store();
        let loaded = store.load_recent_blocks_within(60);
        assert!(
            loaded.is_empty(),
            "fresh store MUST return an empty rate-limit window — pre-PR boot behaviour"
        );
    }

    #[test]
    fn load_recent_blocks_returns_inserted_entries_within_window() {
        let (_dir, store) = make_store();
        let now = chrono::Utc::now();
        // Three timestamps inside the 60s window: 1s, 10s, 30s ago.
        store.set_recent_block(now - chrono::Duration::seconds(1));
        store.set_recent_block(now - chrono::Duration::seconds(10));
        store.set_recent_block(now - chrono::Duration::seconds(30));

        let loaded = store.load_recent_blocks_within(60);
        assert_eq!(
            loaded.len(),
            3,
            "all three persisted entries must appear in the warm-cache"
        );
    }

    #[test]
    fn load_recent_blocks_filters_entries_older_than_60s() {
        // Regression anchor for the audit's "burst can pass right
        // after a crash" finding. If a previous uptime left
        // 60-second-old rows in SQLite, the warm-cache MUST drop
        // them so the rate-limit count reflects only the current
        // window.
        let (_dir, store) = make_store();
        let now = chrono::Utc::now();
        store.set_recent_block(now - chrono::Duration::seconds(5)); // in window
        store.set_recent_block(now - chrono::Duration::seconds(120)); // 2 min ago
        store.set_recent_block(now - chrono::Duration::seconds(3600)); // 1 h ago

        let loaded = store.load_recent_blocks_within(60);
        assert_eq!(
            loaded.len(),
            1,
            "only the in-window entry must survive the warm-cache load"
        );

        // The stale rows must ALSO be deleted from SQLite during the
        // load so the namespace does not grow without bound across
        // restarts.
        let remaining = store
            .store
            .kv_count(NS_RECENT_BLOCKS)
            .expect("kv_count after load");
        assert_eq!(
            remaining, 1,
            "load_recent_blocks_within must prune stale rows from SQLite, not just filter them in memory"
        );
    }

    #[test]
    fn prune_recent_blocks_before_deletes_only_old_entries() {
        // The runtime path calls `prune_recent_blocks_before` from
        // every block decision so the namespace tracks the same
        // window the in-memory `retain` enforces. Deletes must be
        // bounded to entries strictly older than the cutoff.
        let (_dir, store) = make_store();
        let now = chrono::Utc::now();
        store.set_recent_block(now - chrono::Duration::seconds(5)); // keep
        store.set_recent_block(now - chrono::Duration::seconds(45)); // keep
        store.set_recent_block(now - chrono::Duration::seconds(90)); // drop
        store.set_recent_block(now - chrono::Duration::seconds(3600)); // drop

        let cutoff_ms = (now - chrono::Duration::seconds(60)).timestamp_millis();
        store.prune_recent_blocks_before(cutoff_ms);

        // load_recent_blocks_within(60) confirms the keep/drop split
        // by reading what survived.
        let loaded = store.load_recent_blocks_within(60);
        assert_eq!(
            loaded.len(),
            2,
            "prune must delete entries older than cutoff and leave in-window entries intact"
        );
    }

    #[test]
    fn load_recent_blocks_skips_malformed_keys() {
        // Mirrors the `load_xdp_block_times` corrupt-row anchor —
        // a row written by a previous agent version with a
        // non-millis-string key must not panic the boot loader.
        let (_dir, store) = make_store();
        let now = chrono::Utc::now();
        store.set_recent_block(now - chrono::Duration::seconds(5));

        // Inject a malformed key via the raw KV API.
        store
            .store
            .kv_set(NS_RECENT_BLOCKS, "not-a-timestamp", &[1u8])
            .expect("raw kv_set");

        let loaded = store.load_recent_blocks_within(60);
        assert_eq!(
            loaded.len(),
            1,
            "malformed key must be skipped, valid sibling must still load"
        );
    }

    #[test]
    fn retain_cooldowns_removes_old() {
        let (_dir, store) = make_store();
        let old = chrono::Utc::now() - chrono::Duration::hours(3);
        let recent = chrono::Utc::now();
        store.set_cooldown(CooldownTable::Decision, "old:key", old);
        store.set_cooldown(CooldownTable::Decision, "new:key", recent);
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(2);
        store.retain_cooldowns(CooldownTable::Decision, cutoff);
        assert!(!store.has_cooldown(CooldownTable::Decision, "old:key"));
        assert!(store.has_cooldown(CooldownTable::Decision, "new:key"));
    }

    #[test]
    fn attacker_profile_roundtrip() {
        let (_dir, store) = make_store();
        let val = serde_json::json!({"ip": "10.0.0.1", "risk_score": 75, "last_seen": "2026-03-29T00:00:00Z"});
        store.set_attacker_profile("10.0.0.1", &val);
        let got = store.get_attacker_profile("10.0.0.1").unwrap();
        assert_eq!(got["risk_score"], 75);
        assert_eq!(store.attacker_profiles_len(), 1);
    }

    #[test]
    fn trim_attacker_profiles_keeps_highest_risk() {
        let (_dir, store) = make_store();
        for i in 0..5u64 {
            let val =
                serde_json::json!({"risk_score": i * 10, "last_seen": "2026-01-01T00:00:00Z"});
            store.set_attacker_profile(&format!("10.0.0.{i}"), &val);
        }
        assert_eq!(store.attacker_profiles_len(), 5);
        store.trim_attacker_profiles(3);
        assert_eq!(store.attacker_profiles_len(), 3);
        // Lowest risk (0, 10) should be removed
        assert!(store.get_attacker_profile("10.0.0.4").is_some()); // risk 40
        assert!(store.get_attacker_profile("10.0.0.0").is_none()); // risk 0
    }

    #[test]
    fn trim_ip_reputations_keeps_newest() {
        let (_dir, store) = make_store();
        for i in 0..5 {
            let val = serde_json::json!({"last_seen": format!("2026-01-0{}T00:00:00Z", i + 1)});
            store.set_ip_reputation(&format!("10.0.0.{i}"), &val);
        }
        assert_eq!(store.ip_reputations_len(), 5);
        store.trim_ip_reputations(3);
        assert_eq!(store.ip_reputations_len(), 3);
    }
}
