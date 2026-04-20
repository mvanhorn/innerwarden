// Spec 029 PR-B: the types are now consumed transitively via
// `AgentState.ai_router`, but individual `provider_for` call sites
// do not yet reach the enum variants. PR-C migrates the ~30 call
// sites and removes this allow.
#![allow(dead_code)]

//! AI capability types (spec 029).
//!
//! Replaces the single-method-fits-all surface of the old `AiProvider`
//! trait. Each provider declares which roles it can serve, and the
//! `AiRouter` (in `router.rs`) picks the right provider for each call
//! site based on the role it requests.
//!
//! ## Design rationale
//!
//! Pre-029, eight call sites all invoked `provider.chat(system, user)`.
//! Two of them are classification tasks disguised as chat (the output
//! is a short label); four are free-form generation (briefings,
//! operator Q&A); two are explanations (incident → natural-language
//! summary); one simulates a shell for honeypot deception. A single
//! provider cannot be the right answer for all of them — a distilled
//! ONNX classifier is great at classify/decide but can't generate
//! text; an LLM is the reverse cost story.
//!
//! The router splits providers by role so an operator can, for
//! example, run a local classifier for decide() and an Azure-hosted
//! LLM for briefings, with neither aware of the other.
//!
//! Capabilities are a small enumerable set (not a free-form string)
//! because the call sites are known at compile time. Adding a new
//! capability is a deliberate trait-extension act, not ad-hoc.

use serde::{Deserialize, Serialize};

/// A single capability an AI provider can declare it supports.
///
/// Each call site in the agent requests a capability (not a specific
/// provider). The router resolves the request to a concrete provider
/// or returns `None` when the role is unavailable (operator chose a
/// Falco-like deployment with no LLM, for example).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    /// Incident triage: take a `DecisionContext` and return an
    /// `AiDecision` with an action (block_ip, monitor, ignore, etc.).
    /// This is the high-volume fast path in production.
    Decide,

    /// Structured classification: short structured input → short
    /// structured label. No free-form text. Used today by
    /// `notification_pipeline::batch_triage` and
    /// `narrative_observation_verify::ai_verify_ambiguous`.
    Classify,

    /// Free-form text generation: system + user prompt → natural-
    /// language reply. Used today by the dashboard briefing endpoint
    /// and the Telegram `/ask` operator bot.
    Generate,

    /// Structured context → natural-language explanation. Used today
    /// by the dashboard interactive chat, honeypot session summaries,
    /// and post-session attacker profile helpers.
    Explain,

    /// Defensive deception: attacker prompt → realistic shell-like
    /// response. Used by the honeypot SSH interact skill to stall an
    /// attacker with plausible-looking output.
    SimulateShell,
}

impl Capability {
    /// Iterate every variant, used by tests and CLI diagnostics.
    pub fn all() -> &'static [Capability] {
        &[
            Capability::Decide,
            Capability::Classify,
            Capability::Generate,
            Capability::Explain,
            Capability::SimulateShell,
        ]
    }

    /// Short lowercase tag suitable for logs and config dumps.
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::Decide => "decide",
            Capability::Classify => "classify",
            Capability::Generate => "generate",
            Capability::Explain => "explain",
            Capability::SimulateShell => "simulate_shell",
        }
    }

    /// Bit position in `AiCapabilities`. Contract with the bitset
    /// implementation: every capability maps to a distinct bit.
    fn bit(self) -> u8 {
        match self {
            Capability::Decide => 0b0000_0001,
            Capability::Classify => 0b0000_0010,
            Capability::Generate => 0b0000_0100,
            Capability::Explain => 0b0000_1000,
            Capability::SimulateShell => 0b0001_0000,
        }
    }
}

/// Bitset of capabilities a provider declares it supports. Small
/// (single byte) and Copy so it can live inline on providers without
/// allocation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AiCapabilities(u8);

impl AiCapabilities {
    /// An empty capability set. Providers that are still under
    /// development can start here without getting routed to for any
    /// role.
    pub const NONE: AiCapabilities = AiCapabilities(0);

    /// Every capability set, for providers that fulfil every role
    /// (general-purpose LLMs). Equivalent to `Capability::all()` OR'd
    /// together.
    pub const ALL: AiCapabilities = AiCapabilities(0b0001_1111);

    /// Build from a list of capabilities.
    pub fn from_slice(caps: &[Capability]) -> Self {
        let mut bits = 0u8;
        for c in caps {
            bits |= c.bit();
        }
        AiCapabilities(bits)
    }

    /// Does the provider support `cap`?
    pub fn has(&self, cap: Capability) -> bool {
        self.0 & cap.bit() != 0
    }

    /// Number of capabilities declared. For diagnostics.
    pub fn count(&self) -> usize {
        self.0.count_ones() as usize
    }

    /// Every capability currently declared, in enum order. Useful for
    /// logs and the `/api/diagnostics/ai` endpoint.
    pub fn enumerate(&self) -> Vec<Capability> {
        Capability::all()
            .iter()
            .filter(|c| self.has(**c))
            .copied()
            .collect()
    }
}

impl std::fmt::Display for AiCapabilities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&'static str> = self.enumerate().iter().map(|c| c.as_str()).collect();
        if names.is_empty() {
            write!(f, "none")
        } else {
            write!(f, "{}", names.join(","))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_capability_has_unique_bit() {
        // Contract: no two capabilities share the same bit. Violating
        // this would silently merge roles.
        let mut seen = 0u8;
        for c in Capability::all() {
            assert_eq!(
                seen & c.bit(),
                0,
                "capability {c:?} reuses a bit already claimed"
            );
            seen |= c.bit();
        }
    }

    #[test]
    fn none_is_empty() {
        let caps = AiCapabilities::NONE;
        for c in Capability::all() {
            assert!(!caps.has(*c));
        }
        assert_eq!(caps.count(), 0);
        assert_eq!(format!("{caps}"), "none");
    }

    #[test]
    fn all_includes_every_variant() {
        let caps = AiCapabilities::ALL;
        for c in Capability::all() {
            assert!(
                caps.has(*c),
                "ALL is missing {c:?} — when a new capability is added to the enum, update ALL too"
            );
        }
        assert_eq!(caps.count(), Capability::all().len());
    }

    #[test]
    fn from_slice_sets_only_listed_bits() {
        let caps = AiCapabilities::from_slice(&[Capability::Decide, Capability::Classify]);
        assert!(caps.has(Capability::Decide));
        assert!(caps.has(Capability::Classify));
        assert!(!caps.has(Capability::Generate));
        assert!(!caps.has(Capability::Explain));
        assert!(!caps.has(Capability::SimulateShell));
        assert_eq!(caps.count(), 2);
    }

    #[test]
    fn enumerate_preserves_enum_order() {
        let caps = AiCapabilities::from_slice(&[
            Capability::SimulateShell,
            Capability::Decide,
            Capability::Generate,
        ]);
        // enum-definition order, not insertion order.
        assert_eq!(
            caps.enumerate(),
            vec![
                Capability::Decide,
                Capability::Generate,
                Capability::SimulateShell,
            ]
        );
    }

    #[test]
    fn display_joins_with_comma() {
        let caps = AiCapabilities::from_slice(&[Capability::Decide, Capability::Generate]);
        assert_eq!(format!("{caps}"), "decide,generate");
    }

    #[test]
    fn as_str_distinct_per_variant() {
        use std::collections::HashSet;
        let tags: HashSet<_> = Capability::all().iter().map(|c| c.as_str()).collect();
        assert_eq!(tags.len(), Capability::all().len());
    }

    #[test]
    fn capability_serde_round_trip() {
        for c in Capability::all() {
            let json = serde_json::to_string(c).unwrap();
            let back: Capability = serde_json::from_str(&json).unwrap();
            assert_eq!(back, *c);
        }
    }
}
