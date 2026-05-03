//! XDP firewall availability gate (Wave 5b PR-2, 2026-05-03).
//!
//! Background — operator-visible bug: production hosts where the
//! sensor never finished mounting `bpffs` at `/sys/fs/bpf/innerwarden`
//! were emitting `bpftool map update failed for X.X.X.X: Error: bpf
//! obj get (/sys/fs/bpf/innerwarden): directory not in bpf file
//! system (bpffs)` followed by `XDP blocklist map not found - XDP
//! firewall not loaded` on EVERY block decision. Three blocks per
//! hour produced six log lines per hour of pure noise that masked
//! real warnings (SQLite lock contention, KG dangling edges, etc.).
//! The fallback to UFW worked silently, so the operator only saw
//! the WARNs and was led to think blocks were failing — they were
//! not, just slower.
//!
//! This module gates both XDP call sites in `decision_block_ip` so:
//!
//! 1. After one observed failure, XDP attempts are SKIPPED for
//!    `RECHECK_INTERVAL` (5 min). The fallback path runs directly,
//!    no syscall wasted, no log line emitted.
//! 2. Exactly one operator-facing WARN with actionable instructions
//!    is logged per `WARN_INTERVAL` (5 min) — the operator sees the
//!    problem ONCE per dashboard refresh window with a recovery
//!    recipe, not on every block.
//! 3. After `RECHECK_INTERVAL`, the next block tries XDP again so
//!    that mounting bpffs auto-recovers without an agent restart.
//!
//! The state is two atomics, no locking, safe to call from any
//! tokio worker. Pure logic; the actual filesystem check lives in
//! the caller (`std::path::Path::new(BLOCKLIST_PIN).exists()`).

use std::sync::atomic::{AtomicI64, Ordering};

use tracing::warn;

/// Seconds to skip XDP attempts after a failure. After this many
/// seconds, the next block tries XDP again so auto-recovery works
/// when the operator finally mounts bpffs.
pub const RECHECK_INTERVAL_SECS: i64 = 300;

/// Seconds between operator-facing WARN messages. Same value as the
/// recheck interval — keeps the WARN-to-attempt ratio at 1:1 in the
/// degraded state.
const WARN_INTERVAL_SECS: i64 = 300;

/// Unix timestamp at which the next XDP attempt is permitted.
/// 0 = "no failure observed, attempt freely".
static SKIP_UNTIL_TS: AtomicI64 = AtomicI64::new(0);

/// Unix timestamp of the last operator-facing WARN. Separate from
/// SKIP_UNTIL_TS so the WARN can fire at the moment of failure
/// without artificially extending the skip window.
static LAST_WARN_TS: AtomicI64 = AtomicI64::new(0);

/// Should the caller attempt XDP right now? Returns `false` while
/// inside the skip window after a recent failure.
///
/// Cheap — one atomic load + one timestamp read.
pub fn should_attempt_xdp() -> bool {
    let now = chrono::Utc::now().timestamp();
    let skip_until = SKIP_UNTIL_TS.load(Ordering::Relaxed);
    now >= skip_until
}

/// Record an XDP failure. Sets the skip window for the next
/// `RECHECK_INTERVAL_SECS` seconds, and emits exactly one
/// operator-facing WARN per `WARN_INTERVAL_SECS` window.
///
/// `context` is a one-line string carried into the WARN
/// (e.g. `"shield xdp_manager"` or `"block-ip-xdp skill"`) so the
/// log makes the failure surface obvious. `details` is the underlying
/// error string (typically the bpftool stderr or filesystem
/// description) — included once per WARN, not on every attempt.
pub fn mark_failed(context: &str, details: &str) {
    let now = chrono::Utc::now().timestamp();
    SKIP_UNTIL_TS.store(now + RECHECK_INTERVAL_SECS, Ordering::Relaxed);

    let last_warn = LAST_WARN_TS.load(Ordering::Relaxed);
    if now - last_warn >= WARN_INTERVAL_SECS
        && LAST_WARN_TS
            .compare_exchange(last_warn, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        // Operator-actionable single-line WARN. Includes the
        // recovery recipe so the operator does not have to remember
        // it. Falls back to UFW/iptables silently in the meantime —
        // blocks still happen, just at firewall speed instead of
        // wire speed.
        warn!(
            context,
            details,
            "XDP firewall unavailable — falling back to UFW/iptables for the next {RECHECK_INTERVAL_SECS}s. \
             To enable wire-speed blocks: `sudo mount -t bpf bpffs /sys/fs/bpf && sudo systemctl restart innerwarden-sensor`. \
             Subsequent failures within this window will be silent until the next recheck."
        );
    }
}

/// Reset the skip window. Called after an XDP success so a transient
/// glitch (e.g. one-off bpftool race) does not leave subsequent
/// successful blocks running through the skip path.
pub fn mark_succeeded() {
    SKIP_UNTIL_TS.store(0, Ordering::Relaxed);
}

/// Test-only: clear the global state so tests don't leak into each
/// other. The atomics are `static`, so a previous test that called
/// `mark_failed` would otherwise poison the next test's view.
#[cfg(test)]
pub(crate) fn reset_for_test() {
    SKIP_UNTIL_TS.store(0, Ordering::Relaxed);
    LAST_WARN_TS.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-05-03 (Wave 5b PR-2 anchor): the gate must (a) skip XDP
    /// attempts for the configured window after a failure and (b)
    /// rate-limit the operator-facing WARN to one per window.
    ///
    /// Combined into a single test because the gate state lives in
    /// `static` atomics shared across the test binary; running the
    /// two scenarios in parallel races on `SKIP_UNTIL_TS` /
    /// `LAST_WARN_TS` even with `reset_for_test` at the start.
    /// The whole-flow assertion is the contract anyway — the
    /// operator-visible behaviour is "after failure, no more
    /// attempts AND no more WARNs for 5 min, then both auto-recover
    /// on the next attempt".
    ///
    /// The bug this pins: prod was burning a bpftool subprocess per
    /// block decision (3+ per hour) AND emitting 2 WARN lines each
    /// time, swamping the journal. The skip path replaces both with
    /// a single atomic load.
    #[test]
    fn xdp_availability_gate_skips_attempts_and_rate_limits_warns() {
        reset_for_test();

        // Cold path: never failed → attempt allowed.
        assert!(should_attempt_xdp(), "cold start must allow XDP attempt");

        // First failure records the WARN timestamp and opens the skip window.
        mark_failed("test", "first");
        let after_first = LAST_WARN_TS.load(Ordering::Relaxed);
        assert!(after_first > 0, "first failure must record warn timestamp");
        assert!(
            !should_attempt_xdp(),
            "attempt must be skipped immediately after failure"
        );

        // Second failure within the window must NOT re-record the WARN.
        // (The skip window stays open; the gate is idempotent.)
        mark_failed("test", "second");
        let after_second = LAST_WARN_TS.load(Ordering::Relaxed);
        assert_eq!(
            after_first, after_second,
            "second failure within WARN_INTERVAL must not re-record warn timestamp"
        );
        assert!(
            !should_attempt_xdp(),
            "second failure must keep skip window open"
        );

        // Success resets the gate (covers the transient-glitch case
        // where one bpftool call fails but the next succeeds).
        mark_succeeded();
        assert!(
            should_attempt_xdp(),
            "success must re-enable attempts after a transient failure"
        );
    }
}
