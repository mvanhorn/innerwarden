//! Sensor boot-time helpers, split out of `async fn main` on 2026-05-25
//! as PR5b of the main.rs decomposition (see SESSION_LOG.md).
//!
//! ## Structure
//!
//! The boot phase splits into three logical units, one sub-module each:
//!
//! - [`build_detectors`] — synchronous DetectorSet construction
//!   (PR5b1 — landed).
//! - `spawn_collectors` — tokio task spawn for each enabled collector
//!   (PR5b2 — planned).
//! - `event_loop` — the consumer-side `while rx.recv()` loop +
//!   shutdown sequence (PR5b3 — planned).
//!
//! `async fn main` keeps the top-level orchestration (CLI parse, config
//! load, sink construction, dataset reload, seccomp gate) and just
//! calls into these helpers.

pub(crate) mod build_detectors;
pub(crate) mod event_loop;
pub(crate) mod spawn_collectors;
