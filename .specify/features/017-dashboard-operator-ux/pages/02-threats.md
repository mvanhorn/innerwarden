# Spec 02 — Threats Tab (AI Audit Trail)

**Parent**: `../spec.md`
**Phase**: 1
**Depends on**: `00-shared.md`, `01-home.md`
**Status**: Implementation

## Product philosophy

**Threats is not a triage queue. Threats is an audit trail.**

The operator installed an AI agent to handle security autonomously. The AI decides and acts. There is no human in the decision loop except in extreme cases (0-5 times per year). Therefore:

- There is no "OPEN" status. Every threat has a decided state.
- The operator reads outcomes, not work items.
- The primary grouping is by OUTCOME (what the AI did), not by detector (what was found).
- "Needs your attention" exists but should ideally always show 0.

## Outcome model

| Outcome | Meaning | Operator action | Frequency |
|---------|---------|-----------------|-----------|
| **Blocked** | AI blocked with high confidence | None. See that it worked. | Several/day |
| **Honeypot** | AI redirected to honeypot for intel | None. Can inspect sessions. | Some/day |
| **Observing** | AI collecting more data before deciding | None. AI decides on its own. | Some/day |
| **Dismissed** | AI evaluated and discarded (noise, FP, low risk) | None. Audit trail only. | Majority |
| **Needs attention** | AI genuinely needs human input | Only case requiring action. | 0-5/year |

The old statuses `open` and `active` map to **Observing** — the AI is processing, not demanding operator action.

## Scope

**In scope**:
- Regroup entity list by outcome instead of by detector
- Outcome-first KPIs: "Blocked" / "Observing" / "Needs attention" with temporal labels
- Hero state aligned with 01-home 3-state system
- Badge rename: OPEN → removed, ACTIVE → OBSERVING
- Home → Threats navigation pre-selects highest-priority item
- Section title: "Defense Activity" → "AI Defense Log"
- Guidance summary at top of journey: "What happened / What the AI did"

**Out of scope**:
- Backend changes to outcome computation
- Mobile layout (separate PR)
- "Needs attention" escalation logic (requires AI confidence threshold — future work)
- Full journey rewrite
- Internationalization
