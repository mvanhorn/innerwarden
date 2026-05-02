//! String interning for the knowledge graph.
//!
//! Property keys on `Edge` ("event_source", "event_kind", "summary",
//! "severity", etc.) repeat across hundreds of thousands of edges. The
//! pre-intern world allocated a fresh `String` per insert, so a graph
//! with 145k edges paid 145k * (~24 bytes header + heap chars) just for
//! the same handful of repeated keys. The interner deduplicates: each
//! distinct string is stored once and shared via `Arc<str>`.
//!
//! Per heap profile (jeprof 2026-05-02), KG live state was ~85 MB on
//! prod with `Edge.properties` as the dominant call site. Interning
//! the keys is the smallest viable change that targets that line.
//!
//! ## API surface
//!
//! - [`intern`] returns the canonical `Arc<str>` for a string slice.
//!   Multiple calls with the same content return clones of the same
//!   underlying allocation.
//! - The global pool uses a `RwLock<HashMap<...>>` so reads are
//!   contention-free in steady state. Inserts (rare — only on first
//!   sight of a key) take a write lock for ~microseconds.
//! - The pool grows monotonically. The KG never sees enough distinct
//!   property keys for the pool to become a memory concern (estimated
//!   <50 distinct keys in steady state); a periodic GC is left for a
//!   follow-up if profiling ever shows a need.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

fn pool() -> &'static RwLock<HashMap<Box<str>, Arc<str>>> {
    static POOL: OnceLock<RwLock<HashMap<Box<str>, Arc<str>>>> = OnceLock::new();
    POOL.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Return the canonical `Arc<str>` for `s`. Subsequent calls with the
/// same content return clones of the same `Arc`, so the underlying
/// heap allocation is shared across every call site.
pub fn intern(s: &str) -> Arc<str> {
    // Fast path: read lock + lookup. The interner is read-mostly in
    // steady state because the same keys repeat.
    {
        let pool = pool().read().expect("intern pool poisoned");
        if let Some(arc) = pool.get(s) {
            return Arc::clone(arc);
        }
    }
    // Slow path: not present, take a write lock. Re-check under the
    // write lock so two concurrent first-sight callers do not both
    // insert (the second observes the first's entry).
    let mut pool = pool().write().expect("intern pool poisoned");
    if let Some(arc) = pool.get(s) {
        return Arc::clone(arc);
    }
    let arc: Arc<str> = Arc::from(s);
    pool.insert(arc.as_ref().into(), Arc::clone(&arc));
    arc
}

/// Number of distinct strings currently held by the pool. Useful for
/// observability and tests; not exposed on a hot path.
#[cfg(test)]
pub fn pool_len() -> usize {
    pool().read().expect("intern pool poisoned").len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_returns_same_arc_for_same_string() {
        let a = intern("event_source");
        let b = intern("event_source");
        // Pointer equality on Arc proves the underlying allocation
        // is shared — that's the whole point of the interner.
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(&*a, "event_source");
    }

    #[test]
    fn intern_distinct_strings_get_distinct_arcs() {
        let a = intern("event_source");
        let b = intern("event_kind");
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(&*a, "event_source");
        assert_eq!(&*b, "event_kind");
    }

    #[test]
    fn intern_pool_dedupes_high_volume() {
        // Sanity: 1000 calls for 5 distinct keys produce a pool of 5.
        let len_before = pool_len();
        for _ in 0..1000 {
            for k in ["a-key", "b-key", "c-key", "d-key", "e-key"] {
                let _ = intern(k);
            }
        }
        let len_after = pool_len();
        assert!(
            len_after - len_before <= 5,
            "pool grew by more than the 5 distinct keys: {} -> {}",
            len_before,
            len_after
        );
    }
}
