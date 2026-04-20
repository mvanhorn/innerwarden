# Feature Specification: AI Capability Router

**Feature Branch**: `029-ai-capability-router`
**Created**: 2026-04-20
**Status**: Draft
**Input**: Production deployment of the local classifier (PR #196) + autonomy gap closure (spec 028) exposed a structural issue with the single-provider AI surface. A distilled classifier is great for `decide()` but cannot do `chat()`; an LLM is the reverse story for cost/latency. The current design picks one and uses it everywhere, so mixing them requires error-string fallbacks or explicit special-case logic in the shadow wrapper.

## Origin

Spec 028 landed `[ai.shadow]` which was a first attempt at multi-provider, but its model assumes "one primary, one observer". In practice the agent now needs:

- A **classifier** (SecureBERT-distilled ONNX) for triage decisions on incidents. Cheap, fast, deterministic-ish.
- An **LLM** (Azure GPT-5.4-mini today, potentially GPT-5.4-cyber or Claude later) for briefings, operator chat, ambiguous-batch verification, honeypot shell simulation, future active-defense policy synthesis.
- Graceful degradation when either is missing (Falco-like operator usage: rules-only, no AI at all).

The single-provider surface is already tacked over with `[ai.shadow]`, a `supports_chat()` guard we considered adding, and per-call-site `state.ai_provider.is_some()` checks. Each workaround adds a coupling that blocks clean evolution.

## Problem statement

1. `AiProvider::chat()` is called from eight places in `crates/agent/` but the eight tasks are not the same kind of task. Two are classification disguised as chat (batch triage, observation-verify ambiguous batch), four are generation (briefing, /ask, explanations), two are deception (honeypot shell simulation). A single method on a single provider cannot be the right abstraction for all of them.

2. Promoting `local_classifier` to primary breaks seven of the eight chat sites because the classifier can't generate text. Without routing, the only fix is a runtime error string match.

3. Future roles (active-defense orchestration, policy synthesis, multi-agent AI per spec 027) add more task shapes. A bigger bag of `.xxx()` methods on one trait becomes a grab-bag.

4. Operators want Falco-like minimal deployments with no LLM cost. Today the code handles it (all sites check `.is_some()`) but the UX is opaque (silent failures, API 500s for briefing endpoint). A typed-capability model makes the degradation visible in config.

## Proposal

### Capability enum

```rust
pub enum Capability {
    Decide,           // incident → AiDecision
    Classify,         // structured input → label (short, no free-form text)
    Generate,         // free-form text generation
    Explain,          // structured context → natural-language explanation
    SimulateShell,    // attacker prompt → realistic shell response (deception)
}
```

Providers self-report:

```rust
pub struct AiCapabilities {
    bits: u8, // bit per Capability
}

trait AiProvider {
    fn capabilities(&self) -> AiCapabilities;
    // existing: decide, chat, name
    // new with default impls that bail:
    async fn classify(&self, task: &ClassifyTask) -> Result<ClassifyResult>;
    async fn generate(&self, req: &GenerateRequest) -> Result<String>;
    async fn explain(&self, ctx: &ExplainContext) -> Result<String>;
    async fn simulate_shell(&self, ctx: &ShellSimContext) -> Result<String>;
}
```

### Router

`AiRouter` replaces `state.ai_provider: Option<Arc<dyn AiProvider>>` with:

```rust
pub struct AiRouter {
    // Each role holds zero or one provider. None means the role is unavailable
    // and calls to it return a typed "no provider for role" error that call sites
    // already handle via `Option` / graceful degradation.
    pub decider: Option<Arc<dyn AiProvider>>,
    pub classifier: Option<Arc<dyn AiProvider>>,
    pub llm: Option<Arc<dyn AiProvider>>,
    pub shadow: Option<Arc<dyn AiProvider>>, // still parallels the decider
    pub shadow_log_path: Option<PathBuf>,
}

impl AiRouter {
    pub fn provider_for(&self, cap: Capability) -> Option<&Arc<dyn AiProvider>> {
        match cap {
            Capability::Decide | Capability::Classify => self.classifier.as_ref().or(self.llm.as_ref()),
            Capability::Generate | Capability::Explain | Capability::SimulateShell => {
                self.llm.as_ref().or_else(|| self.classifier.as_ref().filter(|p| p.capabilities().has(cap)))
            }
        }
    }
}
```

Call sites request by capability, not by provider:

```rust
// Before:
if let Some(ai) = &state.ai_provider { ai.chat(sys, user).await?; }

// After:
if let Some(p) = state.ai_router.provider_for(Capability::Generate) {
    p.generate(&req).await?;
}
```

### Config

New explicit roles, back-compat with the old `[ai]` block:

```toml
[ai.classifier]
provider = "local_classifier"
base_url = "/var/lib/innerwarden/models/classifier"
confidence_threshold = 0.85

[ai.llm]
provider = "azure_openai"
model = "gpt-5.4-mini"
base_url = "https://<resource>.openai.azure.com"
api_version = "2024-12-01-preview"
# api_key via AZURE_OPENAI_API_KEY env

[ai.shadow]      # unchanged from PR #196
enabled = true
provider = "local_classifier"
log_path = "/var/lib/innerwarden/shadow-decisions.jsonl"
```

Legacy single-provider config is still parsed. When present, it populates both `classifier` and `llm` slots with the same provider (current behaviour).

### Call-site migration

Map each of the 9 sites to the right capability:

| File:line | Current | Capability |
|---|---|---|
| `process/incidents.rs:539` | `provider.decide()` | Decide |
| `ai/shadow.rs:104` | `primary.decide()` | Decide (same; shadow wraps) |
| `notification_pipeline.rs:857` | `provider.chat()` | Classify |
| `narrative_observation_verify.rs:437` | `provider.chat()` | Classify |
| `dashboard/data_api.rs:406` | `provider.chat()` | Generate |
| `dashboard/data_api.rs:551` | `provider.chat()` | Explain |
| `bot_commands.rs:644` | `provider.chat()` | Generate |
| `honeypot_always_on.rs:146` | `provider.chat()` | Explain |
| `honeypot_post_session.rs:177` | `provider.chat()` | Explain |
| `skills/builtin/honeypot/ssh_interact.rs:310` | `provider.chat()` | SimulateShell |

When a site requests a capability no provider supports, the return is `Err(NoProviderFor(Capability::X))`. Existing graceful-degradation paths (which already handle `ai_provider.is_none()`) swallow it identically.

### Falco-like mode

Documented operator UX:

| Config | Behaviour |
|---|---|
| `[ai.classifier]` + `[ai.llm]` both set | Full Inner Warden experience (today's default). |
| `[ai.classifier]` only | Triage decisions via classifier, briefings/explanations fall back to templated strings, operator `/ask` returns "AI not configured". |
| `[ai.llm]` only | LLM does everything, including triage (costly but works). |
| Both absent | Pure Falco-mode. Rules-based detection only. Obvious-gate auto-blocks. No LLM cost. Dashboard briefing endpoint returns 404 instead of 500. |

## Non-goals

- Does **not** introduce RL/training loops. Those live in innerwarden-gym.
- Does **not** touch the shadow infrastructure. PR #196 semantics preserved.
- Does **not** add the "orchestrate" / "synthesize_policy" capabilities for active defence. That is spec-030 follow-up once the router proves stable.
- Does **not** remove the legacy `AiProvider::chat()` method in this PR; it stays for transition, deprecated in docstrings.

## Risks

- **Large blast radius**: nine call sites, four trait methods, new router, new config. Mitigated by exhaustive unit tests per call site and keeping legacy chat() as fallthrough during transition.
- **Config churn**: operator-visible TOML change. Mitigated by keeping `[ai]` block working (auto-expanded into classifier + llm slots) + CHANGELOG callout.
- **Performance**: per-call capability lookup is `O(1)` (enum match). No allocation. Negligible.

## Acceptance criteria

1. `cargo test --workspace` passes with 100+ new tests across `ai_router`, `capability`, per-site migration smoke tests.
2. `make check` (clippy `-D warnings` + fmt) clean.
3. Deploying with legacy `[ai]` config produces **zero observable behaviour change** (back-compat check: same decisions for same inputs in scenario-qa).
4. Deploying with new `[ai.classifier]` + `[ai.llm]` config produces:
   - Classifier handles `decide()` and `classify()` call sites
   - LLM handles `generate()`, `explain()`, `simulate_shell()` call sites
   - `NoProviderFor(Capability::X)` error at sites where no provider matches
5. Falco-mode deploy (both roles absent) starts without error, runs rules-only, dashboard briefing endpoint returns 404 with clear body, all incidents still flow through detection/rules/honeypot.
6. Scenario-qa replay suite unchanged (all scenarios still produce the same envelope).

## Sequencing

Split into three PRs because the mechanical churn of migrating 30+
`state.ai_provider` references in one commit would be unreviewable.
Each PR lands on `development`; together they constitute the full
spec-029 delivery.

### PR A: infrastructure (this PR)
- `Capability` enum + `AiCapabilities` bitset (`ai/capability.rs`)
- `AiRouter` + `RouterBuildError` (`ai/router.rs`)
- `AiProvider::capabilities()` trait method with `ALL` default
- `LocalClassifier` overrides to declare only `Decide` + `Classify`
- 26 unit tests across both new modules
- Zero behavioural change. The router is not yet wired into
  `AgentState`; call sites still go through `state.ai_provider`.

### PR B: wiring
- Add `ai_router: AiRouter` field to `AgentState` next to
  `ai_provider`
- Populate router in boot / test constructors from the same provider
  stack build step that produces `ai_provider` today
- Router exposes `decider()`, `any_llm()` helpers that return the
  same provider today (transparent shim)
- Integration test: router built from legacy `[ai]` config serves
  every capability identically to pre-029
- Still no behavioural change

### PR C: call-site migration
- Migrate each chat/decide call site to `state.ai_router.provider_for(...)`
- Runtime wrapper (`bot_actions`, `decision_honeypot`, etc.) switches
  to holding an `AiRouter` clone instead of `Option<Arc<dyn AiProvider>>`
- `[ai.classifier]` / `[ai.llm]` TOML sections added, back-compat
  with `[ai]`
- Remove `state.ai_provider` field
- Release v0.13.0 after Oracle observation (treat as major because
  config shape changes and trait gained a method).

## References

- Spec 028-b (autonomy gap 2.0 follow-up) — exposes the `supports_chat` limitation of the current surface.
- PR #196 — shadow infrastructure that this spec preserves.
- `ideias/active-defence/active-defence-root-zero-dano.md` — future consumers of additional capabilities (policy synthesis, orchestration).
- `docs/internal/bug-hunt-2026-04-18.md` — spec 027 multi-agent AI idea, compatible with this router.
