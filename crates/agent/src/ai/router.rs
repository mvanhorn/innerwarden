// Spec 029 PR-B: `AiRouter` is now a field on `AgentState` and
// constructed in `loops/boot.rs`. The router itself is reachable
// but its per-capability resolver is not called from any pre-PR-C
// call site, so `provider_for`, `any_llm`, `describe` etc. still
// appear unused to clippy. PR-C migrates the call sites and removes
// this allow.
#![allow(dead_code)]

//! AI capability router (spec 029).
//!
//! Replaces `state.ai_provider: Option<Arc<dyn AiProvider>>` with a
//! router that holds a provider per **role** (classifier, llm) and
//! resolves each call site's `Capability` request to the right one.
//!
//! ## Why
//!
//! The old design had a single provider serve every AI call in the
//! agent, which is fine when the provider is a full LLM but breaks
//! when you want a cheap-fast classifier for triage decisions and a
//! big LLM only for briefings / operator chat. The router is the
//! small piece of plumbing that lets both coexist.
//!
//! ## Current roles
//!
//! - `classifier`: serves `Capability::Decide` and `Capability::Classify`.
//!   Typically the local ONNX-distilled SecureBERT model, or an LLM
//!   used in classifier mode.
//! - `llm`: serves `Capability::Generate`, `Capability::Explain`,
//!   `Capability::SimulateShell`. Typically Azure-hosted GPT-5.4-mini.
//!
//! Either slot may be `None`. The router reports "no provider for X"
//! as a typed error; call sites already handle this path gracefully
//! (the pre-029 code pattern `if let Some(ai) = state.ai_provider`
//! becomes `if let Some(p) = state.ai_router.provider_for(cap)`).
//!
//! ## Back-compat
//!
//! If the operator's `agent.toml` contains only the legacy `[ai]`
//! block (no `[ai.classifier]` / `[ai.llm]` sections), the resulting
//! router puts the same provider in both slots. Behaviour is
//! identical to pre-029.
//!
//! ## Shadow
//!
//! The `[ai.shadow]` infrastructure from PR #196 lives **inside**
//! the classifier slot: `build_provider` still returns a
//! `ShadowProvider` wrapper when enabled. The router does not need
//! to know about shadow; it just sees a single classifier provider.

use std::sync::Arc;

use super::capability::{AiCapabilities, Capability};
use super::AiProvider;

/// A resolver from capability → provider. Typically stored in
/// `state.ai_router`. Constructed once at agent boot and immutable
/// from there on.
#[derive(Clone)]
pub struct AiRouter {
    classifier: Option<Arc<dyn AiProvider>>,
    llm: Option<Arc<dyn AiProvider>>,
}

/// Why a router build failed. Separate from the generic `anyhow` used
/// elsewhere so tests can assert on precise variants. Implemented by
/// hand rather than `thiserror` to avoid adding a new dependency for
/// a single variant.
#[derive(Debug, PartialEq, Eq)]
pub enum RouterBuildError {
    EmptyRouter,
}

impl std::fmt::Display for RouterBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouterBuildError::EmptyRouter => write!(
                f,
                "both ai.classifier and ai.llm are unconfigured - router would serve no capabilities"
            ),
        }
    }
}

impl std::error::Error for RouterBuildError {}

impl AiRouter {
    /// Build a router from two optional provider slots. Returns an
    /// error when both slots are empty; operators who want that
    /// should set `[ai] enabled = false` explicitly rather than
    /// accidentally starting the agent with a dead router.
    pub fn new(
        classifier: Option<Arc<dyn AiProvider>>,
        llm: Option<Arc<dyn AiProvider>>,
    ) -> Result<Self, RouterBuildError> {
        if classifier.is_none() && llm.is_none() {
            return Err(RouterBuildError::EmptyRouter);
        }
        Ok(Self { classifier, llm })
    }

    /// Falco-mode factory: a router that serves no capabilities. Used
    /// by the agent when `[ai] enabled = false` so code paths that
    /// hold a router handle still compile but every `provider_for`
    /// call returns `None`.
    ///
    /// Prefer `new` when at least one slot is populated — this
    /// constructor is a deliberate "AI is off" declaration.
    pub fn disabled() -> Self {
        Self {
            classifier: None,
            llm: None,
        }
    }

    /// Resolve a capability to a concrete provider.
    ///
    /// Routing rules:
    /// - `Decide`, `Classify`: prefer classifier slot; if unset, fall
    ///   back to llm (an LLM can classify).
    /// - `Generate`, `Explain`, `SimulateShell`: prefer llm slot; if
    ///   unset, fall back to classifier **only if** it explicitly
    ///   declares the capability (unusual, but future-proof).
    ///
    /// When no provider serves the capability, returns `None`. Call
    /// sites already handle this via the existing `is_some()` check
    /// pattern.
    pub fn provider_for(&self, cap: Capability) -> Option<Arc<dyn AiProvider>> {
        match cap {
            Capability::Decide | Capability::Classify => {
                if let Some(c) = &self.classifier {
                    if c.capabilities().has(cap) {
                        return Some(Arc::clone(c));
                    }
                }
                if let Some(l) = &self.llm {
                    if l.capabilities().has(cap) {
                        return Some(Arc::clone(l));
                    }
                }
                None
            }
            Capability::Generate | Capability::Explain | Capability::SimulateShell => {
                if let Some(l) = &self.llm {
                    if l.capabilities().has(cap) {
                        return Some(Arc::clone(l));
                    }
                }
                if let Some(c) = &self.classifier {
                    if c.capabilities().has(cap) {
                        return Some(Arc::clone(c));
                    }
                }
                None
            }
        }
    }

    /// Convenience: provider for `Decide`. Replaces the old
    /// `state.ai_provider` single-getter.
    pub fn decider(&self) -> Option<Arc<dyn AiProvider>> {
        self.provider_for(Capability::Decide)
    }

    /// Convenience: provider for any of the free-form text roles.
    /// Returns the first populated among Generate, Explain,
    /// SimulateShell. Useful for telemetry and health checks.
    pub fn any_llm(&self) -> Option<Arc<dyn AiProvider>> {
        self.provider_for(Capability::Generate)
            .or_else(|| self.provider_for(Capability::Explain))
            .or_else(|| self.provider_for(Capability::SimulateShell))
    }

    /// Union of all capabilities this router can serve. For startup
    /// telemetry and the `/api/diagnostics/ai` endpoint (future).
    pub fn capabilities(&self) -> AiCapabilities {
        let mut bits = AiCapabilities::NONE;
        if let Some(c) = &self.classifier {
            bits = merge(bits, c.capabilities());
        }
        if let Some(l) = &self.llm {
            bits = merge(bits, l.capabilities());
        }
        bits
    }

    /// Is the router effectively "Falco mode" (no capabilities)?
    pub fn is_disabled(&self) -> bool {
        self.classifier.is_none() && self.llm.is_none()
    }

    /// Describe both slots for logs. Formatted as
    /// `classifier=<name>|<caps>, llm=<name>|<caps>` with `none` for
    /// empty slots.
    pub fn describe(&self) -> String {
        let c = self
            .classifier
            .as_ref()
            .map(|p| format!("{}|{}", p.name(), p.capabilities()))
            .unwrap_or_else(|| "none".to_string());
        let l = self
            .llm
            .as_ref()
            .map(|p| format!("{}|{}", p.name(), p.capabilities()))
            .unwrap_or_else(|| "none".to_string());
        format!("classifier={c}, llm={l}")
    }
}

/// Merge two capability sets. Small helper kept module-local because
/// it is only used by the router; `AiCapabilities` itself does not
/// need a public `|` impl yet.
fn merge(a: AiCapabilities, b: AiCapabilities) -> AiCapabilities {
    let mut caps = AiCapabilities::NONE;
    for c in Capability::all() {
        if a.has(*c) || b.has(*c) {
            caps = AiCapabilities::from_slice(
                &caps
                    .enumerate()
                    .into_iter()
                    .chain(std::iter::once(*c))
                    .collect::<Vec<_>>(),
            );
        }
    }
    caps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::{AiAction, AiDecision, DecisionContext};
    use anyhow::Result;
    use async_trait::async_trait;

    /// Test provider that declares a configurable capability set and
    /// records the name its caller would see.
    struct FakeProvider {
        tag: &'static str,
        caps: AiCapabilities,
    }

    #[async_trait]
    impl AiProvider for FakeProvider {
        fn name(&self) -> &'static str {
            self.tag
        }
        fn capabilities(&self) -> AiCapabilities {
            self.caps
        }
        async fn decide(&self, _ctx: &DecisionContext<'_>) -> Result<AiDecision> {
            Ok(AiDecision {
                action: AiAction::Ignore {
                    reason: self.tag.to_string(),
                },
                confidence: 0.5,
                auto_execute: false,
                reason: String::new(),
                alternatives: vec![],
                estimated_threat: "low".into(),
            })
        }
        async fn chat(&self, _s: &str, _u: &str) -> Result<String> {
            Ok(self.tag.to_string())
        }
    }

    fn arc(tag: &'static str, caps: AiCapabilities) -> Arc<dyn AiProvider> {
        Arc::new(FakeProvider { tag, caps }) as Arc<dyn AiProvider>
    }

    #[test]
    fn empty_router_errors() {
        // AiRouter does not impl Debug (Arc<dyn AiProvider> has no
        // Debug), so the .err().unwrap() pattern is used in place of
        // .unwrap_err().
        let err = AiRouter::new(None, None).err().unwrap();
        assert_eq!(err, RouterBuildError::EmptyRouter);
    }

    #[test]
    fn disabled_router_serves_nothing() {
        let r = AiRouter::disabled();
        for c in Capability::all() {
            assert!(r.provider_for(*c).is_none());
        }
        assert!(r.is_disabled());
        assert_eq!(r.capabilities().count(), 0);
    }

    #[test]
    fn classifier_only_serves_decide_and_classify() {
        let c = arc(
            "clf",
            AiCapabilities::from_slice(&[Capability::Decide, Capability::Classify]),
        );
        let r = AiRouter::new(Some(c), None).unwrap();
        assert_eq!(r.provider_for(Capability::Decide).unwrap().name(), "clf");
        assert_eq!(r.provider_for(Capability::Classify).unwrap().name(), "clf");
        assert!(r.provider_for(Capability::Generate).is_none());
        assert!(r.provider_for(Capability::Explain).is_none());
        assert!(r.provider_for(Capability::SimulateShell).is_none());
    }

    #[test]
    fn llm_only_serves_everything_it_declares() {
        let l = arc("llm", AiCapabilities::ALL);
        let r = AiRouter::new(None, Some(l)).unwrap();
        for c in Capability::all() {
            assert_eq!(
                r.provider_for(*c).unwrap().name(),
                "llm",
                "LLM slot should serve {c:?}"
            );
        }
    }

    #[test]
    fn classifier_preferred_for_decide_when_both_present() {
        let c = arc("clf", AiCapabilities::ALL);
        let l = arc("llm", AiCapabilities::ALL);
        let r = AiRouter::new(Some(c), Some(l)).unwrap();
        // Classifier wins the Decide / Classify roles.
        assert_eq!(r.provider_for(Capability::Decide).unwrap().name(), "clf");
        assert_eq!(r.provider_for(Capability::Classify).unwrap().name(), "clf");
        // LLM wins the Generate / Explain / SimulateShell roles.
        assert_eq!(r.provider_for(Capability::Generate).unwrap().name(), "llm");
        assert_eq!(r.provider_for(Capability::Explain).unwrap().name(), "llm");
        assert_eq!(
            r.provider_for(Capability::SimulateShell).unwrap().name(),
            "llm"
        );
    }

    #[test]
    fn decide_falls_back_to_llm_when_classifier_absent() {
        let l = arc("llm", AiCapabilities::ALL);
        let r = AiRouter::new(None, Some(l)).unwrap();
        assert_eq!(r.provider_for(Capability::Decide).unwrap().name(), "llm");
    }

    #[test]
    fn generate_falls_back_to_classifier_only_when_classifier_declares_it() {
        // Unusual but future-proof: a classifier that declares Generate
        // wins when no LLM is configured.
        let c = arc(
            "clf-with-gen",
            AiCapabilities::from_slice(&[Capability::Decide, Capability::Generate]),
        );
        let r = AiRouter::new(Some(c), None).unwrap();
        assert_eq!(
            r.provider_for(Capability::Generate).unwrap().name(),
            "clf-with-gen"
        );
    }

    #[test]
    fn generate_returns_none_when_classifier_does_not_declare_it() {
        // Production common case: classifier declares only Decide +
        // Classify; no LLM. Generate must return None so call sites
        // degrade gracefully.
        let c = arc(
            "clf",
            AiCapabilities::from_slice(&[Capability::Decide, Capability::Classify]),
        );
        let r = AiRouter::new(Some(c), None).unwrap();
        assert!(r.provider_for(Capability::Generate).is_none());
    }

    #[test]
    fn decider_returns_the_decide_provider() {
        let c = arc(
            "clf",
            AiCapabilities::from_slice(&[Capability::Decide, Capability::Classify]),
        );
        let l = arc("llm", AiCapabilities::ALL);
        let r = AiRouter::new(Some(c), Some(l)).unwrap();
        assert_eq!(r.decider().unwrap().name(), "clf");
    }

    #[test]
    fn any_llm_returns_first_free_form_provider() {
        let l = arc("azure", AiCapabilities::ALL);
        let r = AiRouter::new(None, Some(l)).unwrap();
        assert_eq!(r.any_llm().unwrap().name(), "azure");
    }

    #[test]
    fn any_llm_returns_none_when_only_classifier_configured() {
        let c = arc(
            "clf",
            AiCapabilities::from_slice(&[Capability::Decide, Capability::Classify]),
        );
        let r = AiRouter::new(Some(c), None).unwrap();
        assert!(r.any_llm().is_none());
    }

    #[test]
    fn capabilities_is_union_of_both_slots() {
        let c = arc(
            "clf",
            AiCapabilities::from_slice(&[Capability::Decide, Capability::Classify]),
        );
        let l = arc(
            "llm",
            AiCapabilities::from_slice(&[Capability::Generate, Capability::Explain]),
        );
        let r = AiRouter::new(Some(c), Some(l)).unwrap();
        let caps = r.capabilities();
        assert!(caps.has(Capability::Decide));
        assert!(caps.has(Capability::Classify));
        assert!(caps.has(Capability::Generate));
        assert!(caps.has(Capability::Explain));
        assert!(!caps.has(Capability::SimulateShell));
    }

    #[test]
    fn describe_formats_slots_with_caps() {
        let c = arc(
            "clf",
            AiCapabilities::from_slice(&[Capability::Decide, Capability::Classify]),
        );
        let r = AiRouter::new(Some(c), None).unwrap();
        let d = r.describe();
        assert!(d.contains("classifier=clf|"));
        assert!(d.contains("decide"));
        assert!(d.contains("classify"));
        assert!(d.contains("llm=none"));
    }

    #[test]
    fn describe_handles_both_empty() {
        let r = AiRouter::disabled();
        let d = r.describe();
        assert_eq!(d, "classifier=none, llm=none");
    }

    // Spec 029 PR-B back-compat guarantee: the agent's boot path
    // populates both slots with the same provider (because pre-029
    // config only has one `[ai]` block). The router must resolve
    // every capability to that same provider. Breaking this would
    // silently change production behaviour when PR-B lands.
    #[test]
    fn back_compat_same_provider_in_both_slots_resolves_every_capability() {
        let single = arc("legacy-single", AiCapabilities::ALL);
        let r = AiRouter::new(Some(Arc::clone(&single)), Some(Arc::clone(&single))).unwrap();
        for c in Capability::all() {
            assert_eq!(
                r.provider_for(*c).expect("every cap resolves").name(),
                "legacy-single",
                "back-compat break: capability {c:?} did not resolve to the legacy provider"
            );
        }
        // describe() must show the same provider name in both slots.
        let d = r.describe();
        assert!(d.contains("classifier=legacy-single|"));
        assert!(d.contains("llm=legacy-single|"));
    }

    // Spec 029 PR-B: when the legacy provider declares narrow caps
    // (LocalClassifier scenario), the router resolves only the caps
    // the provider actually supports and returns None for the rest.
    // This is the graceful-degradation path the agent's no-AI code
    // already handles.
    #[test]
    fn back_compat_narrow_provider_returns_none_for_unsupported() {
        let narrow = arc(
            "classifier-only",
            AiCapabilities::from_slice(&[Capability::Decide, Capability::Classify]),
        );
        let r = AiRouter::new(Some(Arc::clone(&narrow)), Some(Arc::clone(&narrow))).unwrap();
        assert!(r.provider_for(Capability::Decide).is_some());
        assert!(r.provider_for(Capability::Classify).is_some());
        assert!(r.provider_for(Capability::Generate).is_none());
        assert!(r.provider_for(Capability::Explain).is_none());
        assert!(r.provider_for(Capability::SimulateShell).is_none());
    }
}
