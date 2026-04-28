//! Test-only utilities for capturing `tracing` events deterministically.
//!
//! ## Why this exists
//!
//! Spec 037 I-13 follow-up #3 (PR #310) tried to fix tracing-capture
//! flakiness by serializing tests via a crate-level `Mutex<()>` and
//! installing per-test subscribers via
//! `tracing::subscriber::with_default(...)`. Local repro went from
//! ~33 % failure to "5 clean runs in a row", but CI still hit the
//! same `dashboard::auth::tests::write_admin_audit_or_warn_emits_warn_with_context_on_failure`
//! failure with an empty captured buffer (the warn fired but the
//! per-test subscriber never observed it). Local re-test after the
//! lock landed on main: 2 failures in 8 `make test` runs (~25 %).
//!
//! Root cause we never fully pinned down, but the symptom is
//! reliable: even with the Mutex serialising the tests, the
//! thread-local dispatcher set by `with_default` occasionally fails
//! to receive an event fired on the same thread. Hypothesis:
//! interaction with the `#[tokio::test]` runtimes that other tests
//! in the same binary spin up; or a tracing-internal quirk around
//! `with_default`'s save/restore semantics under pressure.
//!
//! ## How this module fixes it
//!
//! Instead of per-test thread-local dispatchers, install **one**
//! global default subscriber once per process via `OnceLock` and
//! `tracing::subscriber::set_global_default`. The subscriber writes
//! every WARN-or-above event into a **thread-local** buffer. Tests
//! call [`arm_capture`] at the top to clear their thread's buffer
//! and take the cross-test serialisation lock; they call
//! [`drain_capture`] at the assertion site to read what landed.
//!
//! The lock is preserved (any concurrent capture test would scribble
//! into different thread-local buffers, but draining and asserting
//! while another test is mid-write makes the assertion racy in a
//! different way). The lock buys determinism around clear-and-arm.
//!
//! ## What gets captured
//!
//! - `WARN` and `ERROR` events on the calling thread.
//! - The textual message (the `"..."` argument to `warn!()` /
//!   `error!()`).
//! - Each structured field as `name=value`. Strings get `Display`
//!   via [`std::fmt::Debug`]; numbers/bools get their native repr.
//!
//! Existing assertion patterns like `contains("audit trail write
//! failed")`, `contains("operator=\"alice\"")`, `contains("error=")`
//! all work against the rendered line because the rendering is
//! `<message> <field>=<debug-of-value> <field>=<debug-of-value>`.
//! Strings render as `"alice"` (quoted) so both `operator="alice"`
//! and `operator=alice` substrings can be tested for if the test
//! wants to be tolerant of formatting changes.
//!
//! ## Why not just use `tracing-test`
//!
//! `tracing-test` is the obvious off-the-shelf solution but adds a
//! dev-dependency. Per the operator's repo convention, dependency
//! bumps go through a consolidated `chore(deps)` PR (see PR #230
//! pattern); folding a new dev-dep into a flakiness fix muddies the
//! change. This module is ~120 LOC and self-contained.

#![cfg(test)]
#![allow(dead_code)]

use std::cell::RefCell;
use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard, OnceLock};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

thread_local! {
    static CAPTURE: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Cross-test serialisation lock. Tests that capture warns must
/// hold this for the whole test body so concurrent tests cannot
/// interleave clear / read on each other's thread-local buffers.
static CAPTURE_LOCK: Mutex<()> = Mutex::new(());

/// Install the global capture subscriber if not yet installed.
/// Safe to call from multiple tests; only the first call wins.
static GLOBAL_INIT: OnceLock<()> = OnceLock::new();

fn install_global_subscriber() {
    GLOBAL_INIT.get_or_init(|| {
        // `set_global_default` is one-shot; if anything else (a
        // production-binary main path, a different test util) has
        // already set it, we silently lose. In test mode that
        // shouldn't happen — `cargo test` does not run main.
        let _ = tracing::subscriber::set_global_default(TestCaptureSubscriber);
    });
}

/// Take the cross-test capture lock, ensure the global subscriber
/// is installed, and clear the calling thread's capture buffer.
/// Returns the lock guard so the caller's scope keeps the lock
/// held for the whole test body.
///
/// Usage:
///
/// ```ignore
/// let _guard = crate::test_util::arm_capture();
/// // run code that fires `warn!`
/// let captured = crate::test_util::drain_capture();
/// assert!(captured.contains("expected message"));
/// ```
pub(crate) fn arm_capture() -> MutexGuard<'static, ()> {
    install_global_subscriber();
    let guard = CAPTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    CAPTURE.with(|c| c.borrow_mut().clear());
    guard
}

/// Drain and return the calling thread's captured warns since the
/// most recent [`arm_capture`]. Each captured event is one line
/// of the form `<message> <field>=<value> <field>=<value>\n`.
pub(crate) fn drain_capture() -> String {
    CAPTURE.with(|c| c.borrow_mut().split_off(0))
}

/// `tracing::Subscriber` that writes every WARN-or-above event
/// fired on the current thread into the thread-local [`CAPTURE`]
/// buffer. Spans are no-op stubs; we only care about events.
struct TestCaptureSubscriber;

impl Subscriber for TestCaptureSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        // Capture WARN and ERROR; ignore INFO / DEBUG / TRACE so
        // production info-level logs do not flood the buffer.
        metadata.level() <= &Level::WARN
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        // Tests do not assert on span structure; return a constant
        // ID. `Id` cannot be zero per the tracing contract.
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut visitor = LineVisitor::default();
        event.record(&mut visitor);

        let mut line = String::new();
        if !visitor.message.is_empty() {
            line.push_str(&visitor.message);
        }
        for (k, v) in &visitor.fields {
            if !line.is_empty() {
                line.push(' ');
            }
            let _ = write!(&mut line, "{k}={v}");
        }
        line.push('\n');

        CAPTURE.with(|c| c.borrow_mut().push_str(&line));
    }

    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

#[derive(Default)]
struct LineVisitor {
    message: String,
    fields: Vec<(String, String)>,
}

impl Visit for LineVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // The default catch-all. Used for `?value` (Debug) AND for
        // `%value` (Display) — `tracing` wraps Display in a Debug
        // adapter so the same visitor entry point receives both.
        let formatted = format!("{value:?}");
        if field.name() == "message" {
            // The message arrives as `"the message string"` (with
            // outer quotes from Debug formatting). Strip the outer
            // quotes for human-readable assertions while leaving
            // any embedded escaping intact.
            self.message = strip_outer_quotes(&formatted).to_string();
        } else {
            self.fields.push((field.name().to_string(), formatted));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            // Keep the quoted form so existing assertions like
            // `contains("operator=\"alice\"")` continue to match.
            self.fields
                .push((field.name().to_string(), format!("{value:?}")));
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }
}

fn strip_outer_quotes(s: &str) -> &str {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod self_tests {
    use super::*;

    #[test]
    fn captures_warn_message_and_fields() {
        let _g = arm_capture();
        tracing::warn!(
            operator = "alice",
            count = 42_u64,
            dry_run = true,
            "audit trail write failed"
        );
        let out = drain_capture();
        assert!(
            out.contains("audit trail write failed"),
            "message missing — got: {out}"
        );
        assert!(
            out.contains("operator=\"alice\""),
            "operator missing — got: {out}"
        );
        assert!(out.contains("count=42"), "count missing — got: {out}");
        assert!(out.contains("dry_run=true"), "dry_run missing — got: {out}");
    }

    #[test]
    fn drains_independently_per_thread() {
        let _g = arm_capture();
        tracing::warn!("first event");
        let first = drain_capture();
        assert!(first.contains("first event"));

        // After draining, the next warn lands fresh.
        tracing::warn!("second event");
        let second = drain_capture();
        assert!(second.contains("second event"));
        assert!(
            !second.contains("first event"),
            "drain must consume; second drain saw first event: {second}"
        );
    }

    #[test]
    fn ignores_info_level() {
        let _g = arm_capture();
        tracing::info!("should not be captured");
        tracing::warn!("should be captured");
        let out = drain_capture();
        assert!(
            !out.contains("should not be captured"),
            "info events leaked into capture: {out}"
        );
        assert!(out.contains("should be captured"));
    }
}
