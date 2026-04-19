#![no_main]
//! Fuzz serde_json deserialisation of the `Incident` type.
//!
//! The agent reads incident JSONL on startup to rebuild in-memory state,
//! and via replay/scenario-qa to validate detector output. A malformed
//! line must produce `Err`, never a panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<innerwarden_core::incident::Incident>(data);
});
