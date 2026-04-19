#![no_main]
//! Fuzz serde_json deserialisation of the `Event` type.
//!
//! Every piece of the pipeline that replays JSONL or reads events from
//! external sinks passes strings through `serde_json::from_slice::<Event>`
//! or `::from_str`. Adversarial JSON bodies with unexpected types, deep
//! nesting, or giant fields must not crash the agent; either the parse
//! returns Err or produces a well-formed Event.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<innerwarden_core::event::Event>(data);
});
