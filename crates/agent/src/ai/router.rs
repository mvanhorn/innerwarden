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

    /// Convenience: provider for `Decide`. Kept as a public shorthand
    /// and exercised by router back-compat tests. Production code
    /// calls `provider_for(Capability::Decide)` directly.
    #[allow(dead_code)]
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

    /// Spec 029 PR-C.2: honeypot always-on and other "nice-to-have"
    /// explain callers want an Explain-capable provider but will
    /// accept any free-form LLM if Explain is not configured
    /// separately. Prefer Explain, fall back to any LLM. Extracted
    /// here so boot.rs can spawn the honeypot task without an inline
    /// `.or_else()` chain that codecov cannot reach from unit tests.
    pub fn explain_or_any_llm(&self) -> Option<Arc<dyn AiProvider>> {
        self.provider_for(Capability::Explain)
            .or_else(|| self.any_llm())
    }

    /// Union of all capabilities this router can serve. Consumed by
    /// router tests and reserved for a future `/api/diagnostics/ai`
    /// endpoint.
    #[allow(dead_code)]
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
    /// Used by test helpers (`dashboard::state::test_dashboard_state`)
    /// and router unit tests to assert on construction results.
    #[allow(dead_code)]
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

/// Spec 029 PR-C.1: build an `AiRouter` from the primary provider
/// plus optional per-role config sections. Extracted from
/// `loops/boot.rs` so the branch logic (per-role build failure
/// fallback, legacy-only back-compat path, Falco-mode empty config)
/// is unit-testable without spinning up the whole agent.
///
/// Contract:
/// - If `role_cfg.enabled` is true, build a fresh provider from that
///   config and put it in the slot. If the build fails, fall back to
///   `primary` and call `on_slot_fallback` so the caller can log.
/// - If `role_cfg.enabled` is false, use `primary` for the slot
///   (back-compat with pre-029 configs).
/// - Same logic for both classifier and llm roles.
/// - If both resulting slots are empty, return `AiRouter::disabled()`
///   instead of the `EmptyRouter` error so the agent can run in
///   Falco-mode (rules-only detection, no LLM cost).
///
/// Side-effect callbacks keep tracing concerns in the caller; this
/// helper stays pure enough to unit-test without mocking a logger.
pub fn build_from_config(
    primary: Option<Arc<dyn AiProvider>>,
    classifier_cfg: &crate::config::RoleProviderConfig,
    llm_cfg: &crate::config::RoleProviderConfig,
    shadow_cfg: Option<&crate::config::ShadowConfig>,
    confidence_threshold: f32,
    mut on_slot_configured: impl FnMut(&'static str, &str),
    mut on_slot_fallback: impl FnMut(&'static str, &str, &anyhow::Error),
) -> AiRouter {
    // Shadow wraps the Decide-serving slot. When a dedicated
    // classifier is configured it takes Decide (router rules in
    // `provider_for`); otherwise Decide falls back to the llm slot.
    // Pass the shadow config to whichever slot will answer Decide so
    // the `differs from` guard compares against the right provider.
    let classifier_shadow = if classifier_cfg.enabled {
        shadow_cfg
    } else {
        None
    };
    let llm_shadow = if !classifier_cfg.enabled && llm_cfg.enabled {
        shadow_cfg
    } else {
        None
    };

    let classifier_slot = resolve_slot(
        "classifier",
        &primary,
        classifier_cfg,
        classifier_shadow,
        confidence_threshold,
        &mut on_slot_configured,
        &mut on_slot_fallback,
    );
    let llm_slot = resolve_slot(
        "llm",
        &primary,
        llm_cfg,
        llm_shadow,
        confidence_threshold,
        &mut on_slot_configured,
        &mut on_slot_fallback,
    );

    match AiRouter::new(classifier_slot, llm_slot) {
        Ok(r) => r,
        Err(_) => AiRouter::disabled(),
    }
}

/// Convenience wrapper over `build_from_config` that emits the
/// dashboard-flavoured tracing lines. Called twice at boot (once for
/// the agent loop, once for the dashboard spawn) so the callbacks
/// live here, not inline in `loops/boot.rs`, which keeps the boot
/// path flat and makes the tracing covered by a router unit test.
pub fn build_for_dashboard(
    primary: Option<Arc<dyn AiProvider>>,
    classifier_cfg: &crate::config::RoleProviderConfig,
    llm_cfg: &crate::config::RoleProviderConfig,
    shadow_cfg: Option<&crate::config::ShadowConfig>,
    confidence_threshold: f32,
) -> AiRouter {
    build_from_config(
        primary,
        classifier_cfg,
        llm_cfg,
        shadow_cfg,
        confidence_threshold,
        |slot, provider_name| {
            tracing::info!(
                slot,
                provider = provider_name,
                "dashboard router: per-role slot configured"
            );
        },
        |slot, provider_name, err| {
            tracing::warn!(
                slot,
                provider = provider_name,
                "dashboard router: per-role provider build failed, falling back to primary: {err:#}"
            );
        },
    )
}

fn resolve_slot(
    slot_name: &'static str,
    primary: &Option<Arc<dyn AiProvider>>,
    role_cfg: &crate::config::RoleProviderConfig,
    shadow_cfg: Option<&crate::config::ShadowConfig>,
    confidence_threshold: f32,
    on_configured: &mut impl FnMut(&'static str, &str),
    on_fallback: &mut impl FnMut(&'static str, &str, &anyhow::Error),
) -> Option<Arc<dyn AiProvider>> {
    if !role_cfg.enabled {
        return primary.as_ref().map(Arc::clone);
    }
    let ai_cfg = role_cfg.to_ai_config();
    match crate::ai::build_provider(&ai_cfg) {
        Ok(primary_box) => {
            on_configured(slot_name, &ai_cfg.provider);
            let wrapped_box = match shadow_cfg {
                Some(scfg) if scfg.enabled => {
                    match crate::ai::build_shadow_observer(
                        scfg,
                        &ai_cfg.provider,
                        &ai_cfg.base_url,
                        &ai_cfg.model,
                        confidence_threshold,
                    ) {
                        Ok(shadow_opt) => {
                            crate::ai::wrap_with_shadow(primary_box, shadow_opt, &scfg.log_path)
                        }
                        Err(e) => {
                            on_fallback(slot_name, &scfg.provider, &e);
                            primary_box
                        }
                    }
                }
                _ => primary_box,
            };
            Some(Arc::from(wrapped_box))
        }
        Err(e) => {
            on_fallback(slot_name, &ai_cfg.provider, &e);
            primary.as_ref().map(Arc::clone)
        }
    }
}

/// Merge two capability sets. Small helper kept module-local because
/// it is only used by the router; `AiCapabilities` itself does not
/// need a public `|` impl yet. Reachable via `capabilities()` which
/// is currently test-only.
#[allow(dead_code)]
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
    fn explain_or_any_llm_prefers_explain_slot() {
        let l = arc(
            "llm",
            AiCapabilities::from_slice(&[Capability::Generate, Capability::Explain]),
        );
        let r = AiRouter::new(None, Some(l)).unwrap();
        assert_eq!(r.explain_or_any_llm().unwrap().name(), "llm");
    }

    #[test]
    fn explain_or_any_llm_falls_back_to_generate_when_no_explain() {
        // Provider only claims Generate. explain_or_any_llm must still
        // return it via the any_llm fallback.
        let l = arc(
            "gen-only",
            AiCapabilities::from_slice(&[Capability::Generate]),
        );
        let r = AiRouter::new(None, Some(l)).unwrap();
        assert_eq!(r.explain_or_any_llm().unwrap().name(), "gen-only");
    }

    #[test]
    fn explain_or_any_llm_returns_none_when_classifier_only() {
        let c = arc(
            "clf",
            AiCapabilities::from_slice(&[Capability::Decide, Capability::Classify]),
        );
        let r = AiRouter::new(Some(c), None).unwrap();
        assert!(r.explain_or_any_llm().is_none());
    }

    #[test]
    fn explain_or_any_llm_returns_none_when_router_disabled() {
        let r = AiRouter::disabled();
        assert!(r.explain_or_any_llm().is_none());
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

    // ── build_from_config ───────────────────────────────────────────

    use crate::config::RoleProviderConfig;

    fn record_callbacks() -> (
        std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
        std::sync::Arc<std::sync::Mutex<Vec<(String, String, String)>>>,
    ) {
        (
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        )
    }

    // Spec 029 PR-C.1: legacy config (per-role blocks both disabled).
    // Primary provider fills both slots; no callback fires because no
    // per-role provider was constructed.
    #[test]
    fn build_from_config_legacy_primary_fills_both_slots() {
        let primary = arc("legacy", AiCapabilities::ALL);
        let (configured, fallbacks) = record_callbacks();
        let cfg_configured = configured.clone();
        let cfg_fallbacks = fallbacks.clone();

        let r = build_from_config(
            Some(Arc::clone(&primary)),
            &RoleProviderConfig::default(),
            &RoleProviderConfig::default(),
            None,
            0.85_f32,
            move |slot, p| {
                cfg_configured
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string()))
            },
            move |slot, p, e| {
                cfg_fallbacks
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string(), e.to_string()))
            },
        );

        assert_eq!(r.decider().unwrap().name(), "legacy");
        assert_eq!(r.any_llm().unwrap().name(), "legacy");
        assert!(configured.lock().unwrap().is_empty());
        assert!(fallbacks.lock().unwrap().is_empty());
    }

    // Spec 029 PR-C.1: classifier enabled + successful build. A
    // dedicated provider goes in the classifier slot; llm slot still
    // uses primary because its role_cfg is disabled.
    #[test]
    fn build_from_config_classifier_enabled_builds_dedicated_provider() {
        let primary = arc("primary-llm", AiCapabilities::ALL);
        let classifier_cfg = RoleProviderConfig {
            enabled: true,
            provider: "stub".into(),
            ..Default::default()
        };
        let llm_cfg = RoleProviderConfig::default();
        let (configured, fallbacks) = record_callbacks();
        let cfg_configured = configured.clone();
        let cfg_fallbacks = fallbacks.clone();

        let r = build_from_config(
            Some(Arc::clone(&primary)),
            &classifier_cfg,
            &llm_cfg,
            None,
            0.85_f32,
            move |slot, p| {
                cfg_configured
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string()))
            },
            move |slot, p, e| {
                cfg_fallbacks
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string(), e.to_string()))
            },
        );

        // Classifier slot now the stub; llm slot still primary.
        assert_eq!(r.decider().unwrap().name(), "stub");
        assert_eq!(r.any_llm().unwrap().name(), "primary-llm");

        let configured = configured.lock().unwrap().clone();
        assert_eq!(configured.len(), 1);
        assert_eq!(configured[0].0, "classifier");
        assert_eq!(configured[0].1, "stub");
        assert!(fallbacks.lock().unwrap().is_empty());
    }

    // Spec 029 PR-C.1: llm enabled + successful build. Dedicated
    // provider in the llm slot; classifier slot still primary.
    #[test]
    fn build_from_config_llm_enabled_builds_dedicated_provider() {
        let primary = arc("primary-classifier", AiCapabilities::ALL);
        let classifier_cfg = RoleProviderConfig::default();
        let llm_cfg = RoleProviderConfig {
            enabled: true,
            provider: "stub".into(),
            ..Default::default()
        };
        let (configured, fallbacks) = record_callbacks();
        let cfg_configured = configured.clone();
        let cfg_fallbacks = fallbacks.clone();

        let r = build_from_config(
            Some(Arc::clone(&primary)),
            &classifier_cfg,
            &llm_cfg,
            None,
            0.85_f32,
            move |slot, p| {
                cfg_configured
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string()))
            },
            move |slot, p, e| {
                cfg_fallbacks
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string(), e.to_string()))
            },
        );

        assert_eq!(r.decider().unwrap().name(), "primary-classifier");
        assert_eq!(r.any_llm().unwrap().name(), "stub");

        let configured = configured.lock().unwrap().clone();
        assert_eq!(configured.len(), 1);
        assert_eq!(configured[0].0, "llm");
        assert_eq!(configured[0].1, "stub");
    }

    // Spec 029 PR-C.1: both roles enabled + successful build. Two
    // distinct providers populate the router.
    #[test]
    fn build_from_config_both_roles_enabled() {
        let primary = arc("primary", AiCapabilities::ALL);
        let classifier_cfg = RoleProviderConfig {
            enabled: true,
            provider: "stub".into(),
            model: "classifier-model".into(),
            ..Default::default()
        };
        let llm_cfg = RoleProviderConfig {
            enabled: true,
            provider: "stub".into(),
            model: "llm-model".into(),
            ..Default::default()
        };
        let (configured, fallbacks) = record_callbacks();
        let cfg_configured = configured.clone();
        let cfg_fallbacks = fallbacks.clone();

        let r = build_from_config(
            Some(Arc::clone(&primary)),
            &classifier_cfg,
            &llm_cfg,
            None,
            0.85_f32,
            move |slot, p| {
                cfg_configured
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string()))
            },
            move |slot, p, e| {
                cfg_fallbacks
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string(), e.to_string()))
            },
        );

        assert_eq!(r.decider().unwrap().name(), "stub");
        assert_eq!(r.any_llm().unwrap().name(), "stub");
        let configured = configured.lock().unwrap().clone();
        assert_eq!(configured.len(), 2);
        let slots: std::collections::HashSet<_> =
            configured.iter().map(|(s, _)| s.clone()).collect();
        assert!(slots.contains("classifier"));
        assert!(slots.contains("llm"));
        assert!(fallbacks.lock().unwrap().is_empty());
    }

    // Spec 029 PR-C.1: per-role enabled but build fails (unknown
    // provider + no base_url, which build_provider rejects per SEC-017).
    // The slot falls back to the primary and on_fallback fires so
    // operators see a warn line.
    #[test]
    fn build_from_config_per_role_build_failure_falls_back() {
        let primary = arc("primary", AiCapabilities::ALL);
        let classifier_cfg = RoleProviderConfig {
            enabled: true,
            provider: "nonexistent-provider".into(),
            // base_url empty — unknown providers without base_url fail
            // per SEC-017.
            ..Default::default()
        };
        let (configured, fallbacks) = record_callbacks();
        let cfg_configured = configured.clone();
        let cfg_fallbacks = fallbacks.clone();

        let r = build_from_config(
            Some(Arc::clone(&primary)),
            &classifier_cfg,
            &RoleProviderConfig::default(),
            None,
            0.85_f32,
            move |slot, p| {
                cfg_configured
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string()))
            },
            move |slot, p, e| {
                cfg_fallbacks
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string(), e.to_string()))
            },
        );

        // Fallback: both slots end up with primary.
        assert_eq!(r.decider().unwrap().name(), "primary");
        assert_eq!(r.any_llm().unwrap().name(), "primary");
        // on_configured never fired because no per-role build succeeded.
        assert!(configured.lock().unwrap().is_empty());
        // on_fallback fired for the classifier slot.
        let fallbacks = fallbacks.lock().unwrap().clone();
        assert_eq!(fallbacks.len(), 1);
        assert_eq!(fallbacks[0].0, "classifier");
        assert_eq!(fallbacks[0].1, "nonexistent-provider");
        assert!(fallbacks[0].2.contains("unknown AI provider"));
    }

    // Spec 029 PR-C.1: no primary provider + both per-role blocks
    // disabled. Router goes into Falco-mode (disabled) instead of
    // erroring. The agent is explicitly allowed to run without AI.
    #[test]
    fn build_from_config_no_primary_and_no_per_role_is_falco_mode() {
        let (configured, fallbacks) = record_callbacks();
        let cfg_configured = configured.clone();
        let cfg_fallbacks = fallbacks.clone();

        let r = build_from_config(
            None,
            &RoleProviderConfig::default(),
            &RoleProviderConfig::default(),
            None,
            0.85_f32,
            move |slot, p| {
                cfg_configured
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string()))
            },
            move |slot, p, e| {
                cfg_fallbacks
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string(), e.to_string()))
            },
        );

        assert!(r.is_disabled());
        for c in Capability::all() {
            assert!(r.provider_for(*c).is_none());
        }
    }

    // Spec 029 PR-C.1: per-role build fails AND no primary. The
    // fallback path returns None for the slot; router has only the
    // other slot (or disabled).
    #[test]
    fn build_from_config_failure_with_no_primary_leaves_slot_empty() {
        let classifier_cfg = RoleProviderConfig {
            enabled: true,
            provider: "nonexistent-provider".into(),
            ..Default::default()
        };
        let (configured, fallbacks) = record_callbacks();
        let cfg_configured = configured.clone();
        let cfg_fallbacks = fallbacks.clone();

        let r = build_from_config(
            None, // no primary
            &classifier_cfg,
            &RoleProviderConfig::default(),
            None,
            0.85_f32,
            move |slot, p| {
                cfg_configured
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string()))
            },
            move |slot, p, e| {
                cfg_fallbacks
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string(), e.to_string()))
            },
        );

        assert!(r.is_disabled());
        // Fallback callback fired even though the fallback itself
        // yielded None. Operators still see "we tried and failed".
        assert_eq!(fallbacks.lock().unwrap().len(), 1);
    }

    // ── build_for_dashboard ─────────────────────────────────────────

    #[test]
    fn build_for_dashboard_legacy_primary_fills_both_slots() {
        let primary = arc("legacy", AiCapabilities::ALL);
        let r = build_for_dashboard(
            Some(Arc::clone(&primary)),
            &RoleProviderConfig::default(),
            &RoleProviderConfig::default(),
            None,
            0.85_f32,
        );
        assert_eq!(r.decider().unwrap().name(), "legacy");
        assert_eq!(r.any_llm().unwrap().name(), "legacy");
    }

    #[test]
    fn build_for_dashboard_no_primary_no_per_role_is_disabled() {
        let r = build_for_dashboard(
            None,
            &RoleProviderConfig::default(),
            &RoleProviderConfig::default(),
            None,
            0.85_f32,
        );
        assert!(r.is_disabled());
    }

    #[test]
    fn build_for_dashboard_per_role_build_failure_falls_back_to_primary() {
        let primary = arc("primary", AiCapabilities::ALL);
        let classifier_cfg = RoleProviderConfig {
            enabled: true,
            provider: "nonexistent-provider".into(),
            ..Default::default()
        };
        let r = build_for_dashboard(
            Some(Arc::clone(&primary)),
            &classifier_cfg,
            &RoleProviderConfig::default(),
            None,
            0.85_f32,
        );
        assert_eq!(r.decider().unwrap().name(), "primary");
        assert_eq!(r.any_llm().unwrap().name(), "primary");
    }

    // ── shadow routing ──────────────────────────────────────────────
    //
    // Spec 029: `[ai.shadow]` wraps the Decide-serving slot. When a
    // dedicated classifier is configured, shadow wraps that.

    #[test]
    fn shadow_wraps_classifier_when_classifier_is_configured() {
        use crate::config::ShadowConfig;
        // Stub classifier + stub shadow with a different model. The
        // router should wrap the classifier slot with a ShadowProvider.
        let classifier_cfg = RoleProviderConfig {
            enabled: true,
            provider: "stub".into(),
            model: "clf-model".into(),
            ..Default::default()
        };
        let shadow_cfg = ShadowConfig {
            enabled: true,
            provider: "stub".into(),
            model: "shadow-model".into(),
            ..Default::default()
        };
        let (configured, fallbacks) = record_callbacks();
        let cfg_configured = configured.clone();
        let cfg_fallbacks = fallbacks.clone();
        let r = build_from_config(
            None,
            &classifier_cfg,
            &RoleProviderConfig::default(),
            Some(&shadow_cfg),
            0.85,
            move |slot, p| {
                cfg_configured
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string()))
            },
            move |slot, p, e| {
                cfg_fallbacks
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string(), e.to_string()))
            },
        );
        // Decide routes to the classifier slot which is now a
        // ShadowProvider wrapper. ShadowProvider delegates `name()` to
        // the primary, so the stub name surfaces through the wrapper.
        assert_eq!(r.decider().unwrap().name(), "stub");
        assert!(fallbacks.lock().unwrap().is_empty());
    }

    #[test]
    fn shadow_rejects_identical_target_config() {
        use crate::config::ShadowConfig;
        // Classifier config == shadow config. Router must log a fallback
        // (shadow build rejected) but keep the classifier slot usable.
        let classifier_cfg = RoleProviderConfig {
            enabled: true,
            provider: "stub".into(),
            ..Default::default()
        };
        let shadow_cfg = ShadowConfig {
            enabled: true,
            provider: "stub".into(),
            ..Default::default()
        };
        let (configured, fallbacks) = record_callbacks();
        let cfg_configured = configured.clone();
        let cfg_fallbacks = fallbacks.clone();
        let r = build_from_config(
            None,
            &classifier_cfg,
            &RoleProviderConfig::default(),
            Some(&shadow_cfg),
            0.85,
            move |slot, p| {
                cfg_configured
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string()))
            },
            move |slot, p, e| {
                cfg_fallbacks
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string(), e.to_string()))
            },
        );
        let fbs = fallbacks.lock().unwrap().clone();
        assert_eq!(fbs.len(), 1, "expected shadow differs-from fallback");
        assert!(
            fbs[0].2.contains("must differ"),
            "expected 'must differ' in error, got {}",
            fbs[0].2
        );
        // Classifier slot still built successfully without the shadow wrap.
        assert_eq!(r.decider().unwrap().name(), "stub");
    }

    #[test]
    fn shadow_wraps_llm_when_no_classifier_configured() {
        use crate::config::ShadowConfig;
        // No classifier, only llm. Decide falls back to llm, so shadow
        // attaches there.
        let llm_cfg = RoleProviderConfig {
            enabled: true,
            provider: "stub".into(),
            model: "llm-model".into(),
            ..Default::default()
        };
        let shadow_cfg = ShadowConfig {
            enabled: true,
            provider: "stub".into(),
            model: "shadow-model".into(),
            ..Default::default()
        };
        let (configured, fallbacks) = record_callbacks();
        let cfg_configured = configured.clone();
        let cfg_fallbacks = fallbacks.clone();
        let r = build_from_config(
            None,
            &RoleProviderConfig::default(),
            &llm_cfg,
            Some(&shadow_cfg),
            0.85,
            move |slot, p| {
                cfg_configured
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string()))
            },
            move |slot, p, e| {
                cfg_fallbacks
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string(), e.to_string()))
            },
        );
        assert!(fallbacks.lock().unwrap().is_empty());
        // Decide and any_llm both reach llm, which is shadow-wrapped.
        assert_eq!(r.decider().unwrap().name(), "stub");
        assert_eq!(r.any_llm().unwrap().name(), "stub");
    }

    #[test]
    fn shadow_disabled_does_not_wrap() {
        use crate::config::ShadowConfig;
        let classifier_cfg = RoleProviderConfig {
            enabled: true,
            provider: "stub".into(),
            ..Default::default()
        };
        let shadow_cfg = ShadowConfig::default(); // enabled = false
        let (configured, fallbacks) = record_callbacks();
        let cfg_configured = configured.clone();
        let cfg_fallbacks = fallbacks.clone();
        let r = build_from_config(
            None,
            &classifier_cfg,
            &RoleProviderConfig::default(),
            Some(&shadow_cfg),
            0.85,
            move |slot, p| {
                cfg_configured
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string()))
            },
            move |slot, p, e| {
                cfg_fallbacks
                    .lock()
                    .unwrap()
                    .push((slot.to_string(), p.to_string(), e.to_string()))
            },
        );
        assert!(fallbacks.lock().unwrap().is_empty());
        assert_eq!(r.decider().unwrap().name(), "stub");
    }
}
