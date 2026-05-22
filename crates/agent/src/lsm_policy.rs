//! Agent-side control plane for the kernel LSM block (Spec 052 Phase 1b).
//!
//! Opens the `BLOCKED_PIDS` LRU map that the sensor pinned at
//! `/sys/fs/bpf/innerwarden/blocked_pids` (see
//! `crates/sensor/src/collectors/ebpf_syscall.rs`) and exposes
//! `register_blocked_pid` / `unregister_blocked_pid` for the kill chain
//! detector and process-exit GC to call.
//!
//! INV-LSM-03: every map write goes through this module's
//! `register_blocked_pid` — no other code in the agent or sensor pokes
//! the map directly.
//!
//! INV-LSM-07: `register_blocked_pid` writes BOTH the PID (thread id)
//! and the TGID (process id, looked up via `/proc/<pid>/status:Tgid:`)
//! so a chain that matched on a non-main thread still gets blocked at
//! exec time on the main thread of the same process.
//!
//! The map is opened lazily on first use. If the sensor isn't running
//! or BLOCKED_PIDS isn't pinned (e.g. operator built without LSM
//! support), every register/unregister becomes a no-op + warn — the
//! kernel-block path goes inert without disturbing the agent's normal
//! detection pipeline.
//!
//! Aya is Linux-only — non-Linux builds compile to pure no-op stubs
//! that log a single "kernel-block path unavailable" warn the first
//! time the agent tries to register a PID.

#[cfg(target_os = "linux")]
use std::sync::{Mutex, OnceLock};

#[cfg(target_os = "linux")]
use aya::maps::{HashMap as AyaHashMap, Map, MapData};
#[cfg(target_os = "linux")]
use tracing::{info, warn};

#[cfg(not(target_os = "linux"))]
use std::sync::OnceLock;
#[cfg(not(target_os = "linux"))]
use tracing::warn;

/// Pin path the sensor uses for the LRU map. Kept as a string constant
/// so this crate doesn't have to depend on `innerwarden-sensor` (the
/// sensor crate isn't a dependency of the agent today and we want to
/// avoid that coupling for the kernel-block control plane).
#[cfg(target_os = "linux")]
const BLOCKED_PIDS_PIN: &str = "/sys/fs/bpf/innerwarden/blocked_pids";

/// Lazy global handle to the opened map. `None` if the pin didn't exist
/// or `MapData::from_pin` failed — every public function in this module
/// short-circuits to a logged no-op in that case.
#[cfg(target_os = "linux")]
static MAP_HANDLE: OnceLock<Mutex<Option<AyaHashMap<MapData, u32, u8>>>> = OnceLock::new();

#[cfg(target_os = "linux")]
fn map_handle() -> &'static Mutex<Option<AyaHashMap<MapData, u32, u8>>> {
    MAP_HANDLE.get_or_init(|| {
        let opened = match MapData::from_pin(BLOCKED_PIDS_PIN) {
            Ok(md) => {
                // The kernel side declared BLOCKED_PIDS as LruHashMap
                // (see crates/sensor-ebpf/src/main.rs). Aya's typed
                // `HashMap<MapData, K, V>` wrapper accepts both regular
                // HashMap and LruHashMap variants of the Map enum
                // (see aya 0.13 maps/mod.rs:504 macro), so we wrap
                // explicitly in Map::LruHashMap before TryFrom.
                let map = Map::LruHashMap(md);
                match AyaHashMap::<MapData, u32, u8>::try_from(map) {
                    Ok(typed) => {
                        info!(
                            pin = BLOCKED_PIDS_PIN,
                            "lsm_policy: BLOCKED_PIDS opened — kernel-block path live"
                        );
                        Some(typed)
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            pin = BLOCKED_PIDS_PIN,
                            "lsm_policy: BLOCKED_PIDS pin exists but is not a u32→u8 LRU map — \
                             kernel-block path INERT"
                        );
                        None
                    }
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    pin = BLOCKED_PIDS_PIN,
                    "lsm_policy: BLOCKED_PIDS pin not found — kernel-block path INERT \
                     (sensor not running, built without LSM, or kernel lacks BPF LSM)"
                );
                None
            }
        };
        Mutex::new(opened)
    })
}

/// Read `/proc/<pid>/status` and return the `Tgid:` value. Returns
/// `None` if the process has already exited (ENOENT) or status parsing
/// fails — the caller treats that as "couldn't dual-register" and
/// proceeds with the PID-only registration.
//
// dead_code allow on non-Linux: this helper is only called by the Linux
// register_blocked_pid path and the macOS-gated unit test, neither of
// which the workspace clippy run sees on the macOS build cfg.
#[allow(dead_code)]
fn read_tgid_from_proc(pid: u32) -> Option<u32> {
    let path = format!("/proc/{pid}/status");
    let content = std::fs::read_to_string(&path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

/// Mark a PID (and its TGID, when distinct) as denied at the next
/// `bprm_check_security` LSM hook firing. Idempotent — duplicate calls
/// just refresh the entry's LRU position.
///
/// `reason` is logged but not persisted to the kernel map (the map
/// value is a single byte). Operator-side audit of why a PID was
/// registered lives in the agent's events JSONL via this function's
/// `info!` log line.
#[cfg(target_os = "linux")]
pub fn register_blocked_pid(pid: u32, reason: &str) {
    let mut guard = match map_handle().lock() {
        Ok(g) => g,
        Err(_) => {
            warn!("lsm_policy: register_blocked_pid: map mutex poisoned");
            return;
        }
    };
    let map = match guard.as_mut() {
        Some(m) => m,
        None => return,
    };

    if let Err(e) = map.insert(pid, 1u8, 0) {
        warn!(pid, error = %e, "lsm_policy: failed to insert PID into BLOCKED_PIDS");
        return;
    }

    let tgid = read_tgid_from_proc(pid);
    if let Some(tgid_val) = tgid {
        if tgid_val != pid {
            if let Err(e) = map.insert(tgid_val, 1u8, 0) {
                warn!(
                    tgid = tgid_val,
                    pid,
                    error = %e,
                    "lsm_policy: failed to dual-register TGID into BLOCKED_PIDS \
                     (PID-only block remains in effect)"
                );
            }
        }
    }

    info!(
        pid,
        tgid = ?tgid,
        reason,
        "lsm_policy: registered PID for kernel-block"
    );
}

/// Drop a PID's registration. Called from the process-exit consumer
/// (Phase 1b follow-up) so dead PIDs don't sit in the map forever.
/// LRU eviction handles the leak risk if this is never called, so this
/// is best-effort cleanup, not load-bearing.
//
// dead_code allow: this function is the documented entry point for the
// sched_process_exit GC wiring that comes in the next Phase 1b sub-PR.
// Without `#[allow]` clippy `-D warnings` rejects the PR.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn unregister_blocked_pid(pid: u32) {
    let mut guard = match map_handle().lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    let map = match guard.as_mut() {
        Some(m) => m,
        None => return,
    };
    let _ = map.remove(&pid);
}

// ── Non-Linux stubs ──────────────────────────────────────────────────
// On macOS / Windows there's no BPF map and aya doesn't compile, so the
// kernel-block path is fundamentally unavailable. Both functions become
// no-ops with a single warn on first registration attempt so the operator
// knows kernel enforcement is dormant (rather than silently disabled).

#[cfg(not(target_os = "linux"))]
static WARNED_ONCE: OnceLock<()> = OnceLock::new();

#[cfg(not(target_os = "linux"))]
pub fn register_blocked_pid(pid: u32, reason: &str) {
    WARNED_ONCE.get_or_init(|| {
        warn!(
            "lsm_policy: register_blocked_pid called on non-Linux host \
             (pid={pid}, reason={reason}) — kernel-block path unavailable; \
             userspace skill pipeline still applies"
        );
    });
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn unregister_blocked_pid(_pid: u32) {
    // no-op on non-Linux
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `read_tgid_from_proc` against the test process itself — pid and
    /// tgid will match (test runs as a single-threaded worker as far
    /// as cargo test is concerned, so `pid == tgid` is expected).
    #[test]
    #[cfg(target_os = "linux")]
    fn read_tgid_from_proc_works_on_self() {
        let pid = std::process::id();
        let tgid = read_tgid_from_proc(pid).expect("self /proc/<pid>/status should be readable");
        // The test process's pid equals its tgid because the main thread
        // is what cargo executes the test in.
        assert_eq!(tgid, pid);
    }

    /// On macOS (no /proc) the helper must return None, not panic.
    #[test]
    #[cfg(target_os = "macos")]
    fn read_tgid_from_proc_returns_none_on_macos() {
        assert!(read_tgid_from_proc(std::process::id()).is_none());
    }

    /// `register_blocked_pid` on a host without the BPF map pinned must
    /// not panic and must not write anywhere; it should log a warn and
    /// return cleanly. We can't verify the map state here (no map), but
    /// we can verify the call completes without panic.
    #[test]
    fn register_blocked_pid_no_pin_is_noop() {
        // The first call to map_handle() on a host without the pin will
        // initialize the OnceLock with None. Subsequent calls are no-ops.
        register_blocked_pid(99999, "test:no_pin");
        unregister_blocked_pid(99999);
    }
}
