#![no_main]
//! Fuzz the TLS ClientHello parser + JA3/JA4 fingerprint computer.
//!
//! Input: arbitrary bytes (what an attacker on the wire can send).
//! Invariants under fuzz:
//!   - `parse_packet` must return `None` or `Some(hello)`. It must never
//!     panic on any byte sequence, regardless of length or content.
//!   - When `parse_packet` succeeds, `compute_fingerprints` must
//!     terminate in bounded time and must not panic. The resulting
//!     JA3 / JA4 strings are not asserted (we only care about crashes,
//!     OOM, and hangs).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(hello) = innerwarden_sensor::collectors::tls_fingerprint::parse_packet(data) {
        let _ = innerwarden_sensor::collectors::tls_fingerprint::compute_fingerprints(&hello);
    }
});
