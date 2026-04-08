// Migrated from standalone repo — suppress cosmetic clippy lints.
#![allow(clippy::all)]

//! innerwarden-shield — DDoS protection module.
//!
//! Adaptive rate limiting, SYN flood detection, auto-escalation state machine,
//! attack classification, and Cloudflare failover.
//!
//! # Usage as library (inline in agent)
//!
//! ```rust,ignore
//! use innerwarden_shield::{ShieldEngine, ShieldConfig};
//!
//! let mut engine = ShieldEngine::new(config);
//! let result = engine.process_events(&events);
//! ```

pub mod attack_classifier;
pub mod cloudflare_failover;
pub mod escalation;
pub mod ingest;
pub mod origin_lockdown;
pub mod rate_limiter;
pub mod store;
pub mod syn_tracker;
pub mod tcp_fingerprint;
pub mod telegram_notify;
pub mod xdp_manager;

// These modules require tokio (daemon feature)
#[cfg(feature = "daemon")]
pub mod api;
#[cfg(feature = "daemon")]
pub mod bgp_monitor;
