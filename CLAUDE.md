# InnerWarden — Main Repo

Sensor (eBPF) + Agent (AI triage) + CTL (CLI). Open source (Apache-2.0).

## O que vive aqui

```
crates/
  sensor/       49 detectors, 40 eBPF hooks, 22 collectors
  agent/        AI pipeline, dashboard, skills, correlation, notifications, knowledge graph
  ctl/          CLI: setup, configure, scan, harden, upgrade
  agent-guard/  AI agent protection (ATR rules, MCP inspection)
  smm/          Ring -2 firmware/UEFI/SMM security audit (migrated from standalone repo)
  hypervisor/   Ring -1 hypervisor security — VM detection, KVM monitoring (migrated from standalone repo)
  killchain/    Kill chain detection — 8 attack patterns via bitmask tracking (migrated from standalone repo)
  dna/          Threat DNA — behavioral fingerprinting, anomaly detection, MITRE chain tracking (migrated from standalone repo)
  core/         Shared types: Event, Incident, Severity
  sensor-ebpf/  eBPF bytecode (no_std, bpfel target)
  sensor-ebpf-types/  Shared eBPF ↔ userspace types
rules/
  sigma/        208 community Sigma rules (SigmaHQ)
  yara/         8 malware scanning rules
  atr/          71 AI agent threat rules (vendored)
modules/        Vertical security modules (manifests)
integrations/   Declarative integration recipes
```

## Comandos

```bash
make test         # todos os testes (workspace)
make build        # debug build
make check        # clippy -D warnings + fmt --check
make replay-qa    # validacao E2E multi-source
```

## Estado (2026-04-17)

- 49 sensor detectors + 27 graph detectors, 40 eBPF hooks, 65 MITRE IDs, 47 correlation rules (CL-001..CL-047 incl. 5 AlphaZero V4 discoveries + 3 hypervisor + 3 cross-module) + 10 graph correlation rules
- Knowledge graph e unica fonte de verdade para dashboard/bot/reports. In-memory directed graph (11 node types, 50 relations, 60 event kinds mapped). Snapshots diarios dated + 7d retention + 3-backup rotation + integrity check. FP tracking in graph. decision_cooldown/report/neural_lifecycle/threat_report leem do graph (JSONL fallback). Dashboard "Graph" tab removido — stats migrados pra Health.
- 3102 tests passing workspace
- Coverage: ~45% overall (2026-04-17 baseline). Codecov configurado com 12 components per-crate + patch gate 70% em PRs (spec 023).
- Server producao: Oracle Cloud London (ver config local, nao expor no repo publico)
- Branches: main = stable, develop = bleeding edge
- CI: `make check` + `make test` + `make spec-check` + coverage via tarpaulin 0.33
- Licenca: Apache-2.0 (migrado de BUSL-1.1 em 2026-04-03)
- Release atual: v0.11.1
- CTL reestruturado: 8 grupos (get, stream, action, trust, config, system, module, agent)

## Convencoes

- Commits em ingles
- Sensor: deterministico, zero HTTP/AI
- Agent: pode chamar APIs externas
- I/O errors em sinks: `warn!`, nao `?`
- `spawn_blocking` pra I/O sincrono em tasks Tokio

## Signal quality principle (spec 015)

**Every node in the knowledge graph must earn its place by being useful for operator experience OR AI research and training. Noise that is useful for neither is waste.**

This is a hard rule. A detector that produces high-volume false positives is worse than a detector that produces nothing: the false positives pollute correlation chains, feed wrong signals to the neural model, consume memory, and erode trust in the dashboard.

Concrete checks when adding or reviewing a `detect_*` function in `crates/agent/src/knowledge_graph/detectors.rs`:

- **Prefer baseline diff or event-driven emission over presence scans.** If the semantic is "something new happened", do not iterate `nodes_of_type` unconditionally — filter by a time window (`edges_in_window`, `active_nodes_since`, `now - start_ts < W`) or move the emission into the ingestion path where the event first arrives.
- **A cooldown is not a fix for a presence scan.** It just slows the noise down. A stale node matching a static predicate will still keep firing once per cooldown window forever.
- **Parser robustness at the ingestion boundary.** Bad data at ingestion pollutes everything downstream. Fix it at the source, not at the display layer. `ensure_user`, `ensure_ip`, `ensure_file` call sites must be reviewed any time they touch attacker-controlled input.
- **Research data and operator data can coexist, but should be structurally distinct.** Different node types, or a tag/flag, so the operator view can filter noise out without losing training signal.

Spec 015 (`/.specify/features/015-graph-signal-quality/spec.md`) caught 3,954 false-positive `graph_user_creation` incidents from a single presence-scan detector on permanent (non-expiring) User nodes. The spec contains the full audit table of all 27 graph detectors and the rationale for each pass/fail verdict.

## Fonte De Verdade

- `CLAUDE.md` e o unico arquivo de navegacao e governanca do repo
- Nao criar `AGENTS.md` neste repo
- Specs de features vivem em `.specify/features/`
- Decisoes arquiteturais vivem em `docs/internal/adr/`

## Fluxo De Mudanca

Toda mudanca relevante para produto, arquitetura ou operacao:

1. Spec primeiro: criar ou atualizar em `.specify/features/<id>-<tema>/`
2. ADR se criar regra, conceito ou trade-off permanente
3. Atualizar `CLAUDE.md` se alterar mapa do repo, workflow, deploy ou convencoes
4. `make check` e `make test` antes de commit
5. Nao misturar reorganizacao com mudanca de comportamento no mesmo commit

## Taxonomia

- `command`: interface exposta no CLI
- `capability`: toggle operacional (habilitada pelo CTL)
- `module`: pacote vertical declarativo em `modules/`
- `integration`: conexao com sistema externo ou provider
- `rule`: logica declarativa de deteccao/correlacao/playbook
- `skill`: acao permitida ao agent/responder

ADR: `docs/internal/adr/0001-project-taxonomy.md`

## Features — Status

Ordenado por numero. ✅ merged, 🚧 in-progress, 📝 draft/planned, ⏸ deferred.

| ID | Feature | Status |
|----|---------|--------|
| 001 | Telegram Interactive Triage | ✅ |
| 002 | Telegram Triage v2 (2FA + Undo + Auto-Learn) | ✅ Auto-Learn, Undo, 2FA Telegram. Pendente: dashboard 2FA endpoints (GET/POST `/api/2fa/*`) |
| 003 | Setup Ready To Use | ✅ |
| 004 | Setup Zero Friction | ✅ |
| 005 | Intelligent Notifications | ✅ Phases 1-8 shipped (US1-US7). Grouping + channel filter + digest + bootstrap profile + periodic census + operator feedback loop + AI batch triage (opt-in). Integrated into spec 024 via scenario 07 + tightened alert thresholds. |
| 010 | Detector Migration (Phase 3) | ✅ Phases 3A-3C. 27 graph detectors + 10 correlation rules + dedup + config flag. Phase 3D metrics diferida. |
| 012 | Eliminate JSONL Dependency (Phase 6) | ✅ Phases 6A-6F. Graph primary for dashboard/bot/reports. |
| 013 | Graph Single Source of Truth (Phase 7) | ✅ Gaps 1/2/4/5 done. Daily dated snapshots, FP tracking in graph, monthly report from snapshots, 6h window from event_timeline. Gap 3 (telemetry JSONL) por design. |
| 014 | Graph Full Connectivity | ✅ Phases A-D. 8→18 active relations. Edges 12K→33K, Process nodes 411→4470. |
| 015 | Graph Signal Quality | ✅ Auditoria dos 27 graph detectors + 3,954 FP `graph_user_creation` caçados. Ver [Signal quality principle](#signal-quality-principle-spec-015). |
| 016 | Unified SQLite Store | ✅ v0.11.0. Single `innerwarden.db` substitui 15 storage artifacts. redb removido, JSONL removido, 14 maintenance tasks, migration legada. |
| 017 | Dashboard Operator UX | 🚧 Phase 1 merged (Home + Threats tabs AI-first, 16 detector FP fixes). Demais fases em backlog. |
| 018 | Autonomous Response | ✅ Phases A-D. Layer 2 correlation-driven escalation + trusted_processes filter. Graduated enforcement state machine (Phase F) parcial no spec 020. |
| 019 | Test Coverage Gaps | ✅ Closed. Batch 1 merged (PR #110). Batches 2-7 subsumed by spec 023 Coverage Closeout (PR #125, 11 batches) + spec 026 decomposition phases. |
| 020 | Zero-Trust MDR | 🚧 Phases C + D merged (continuous trust scoring + AI SOC daily checks com 11 system parsers). Phase F-partial (graduated enforcement state machine) merged. |
| 021 | Observation Verification | ✅ Phases A-D. Score engine + integracao no agent loop + AI batch verification + dashboard score display. Active FP clearing funcional. |
| 022 | Dashboard Test Coverage | ✅ 6 batches merged + 2 expansoes. Cobertura do dashboard de 0% pra ~30%+. HTML escape, auth, investigation, sensors, actions — tudo testado. |
| 023 | Coverage Closeout (project-wide) | **In progress** — Batches 1..11 done, awaiting codecov refresh |
| 024 | Regression Safety Net | ✅ Phases A+B+C done. `make scenario-qa` (7 scenarios — 01/02 ready, 03-07 wip/scaffold), 18 contract tests across 5 boundary subsystems, `/metrics` surfaces all 10 drift metrics, `docs/prometheus-alerts.yaml` tightened to 10/h warn + 50/h crit now that spec 005 grouping shipped, Health tab drift section. |
| 025 | Structured AI Prompt | 📝 Draft P1. Bench mostrou qwen2.5:3b: 53%→73% accuracy (prose→JSON subgraph). Implementacao: 2 AI sessions. Bench em `innerwarden-test/ai-grounding/`. |
| 026 | Decomposition for Testability | ✅ Phases A-C. main.rs split, honeypot split, telegram split. Agent crate +10.98pp coverage. replay-qa diff zero. |

## Divida tecnica

- **2FA dashboard endpoints**: TOTP funciona no Telegram. Falta `GET /api/2fa/pending` + `POST /api/2fa/approve` + `POST /api/2fa/deny` pro metodo "dashboard".
- **Agent main.rs**: 5610 linhas (cresceu de 4396). `process_incidents` e `process_telegram_approval` ainda concentram orquestracao. Proximos candidatos pra extrair: Telegram bot commands/status, integracoes.
- **CTL main.rs**: 2936 linhas (cresceu de 2201). Aceitavel; tende a crescer com novos subcomandos. Extracao ainda nao urgente.
- **Coverage ~45%**: spec 023 em andamento ataca. Codecov.yml configurado pra visibilidade.
- **Spec 005 (Intelligent Notifications) nao implementada**: agent ainda manda 1 Telegram por incident. Grouping + batch triage seria melhoria de UX significativa.
- **Spec 017 fases > 1**: apenas Phase 1 merged. 15 FRs do spec ainda na fila.

## Docs detalhados

Handbook completo: `.claude/CLAUDE.md`
Wiki: `innerwarden.wiki/` no monorepo
