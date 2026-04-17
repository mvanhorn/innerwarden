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
make test         # todos os testes (~1900)
make build        # debug build
make check        # clippy + fmt
make replay-qa    # validacao E2E
```

## Estado (2026-04-11)

- 49 sensor detectors + 27 graph detectors (Phase 3A-C complete), 40 eBPF hooks, 65 MITRE IDs, 47 correlation rules (CL-001 to CL-047, includes 5 AlphaZero V4 discoveries + 3 hypervisor rules + 3 cross-module integration rules) + 10 graph correlation rules
- Knowledge graph: in-memory directed graph (11 node types, 50 relation types, 60 event kinds mapped). Dashboard tab + AI triage integration + 58-feature autoencoder (10 graph structural features). **Phase 6 + Phase 7 complete**: graph is single source of truth. Daily dated snapshots (`graph-snapshot-YYYY-MM-DD.json`), 7-day retention. FP tracking in graph (false_positive, fp_reporter, fp_reported_at on Incident nodes). decision_cooldown, report, neural_lifecycle, threat_report all read from graph snapshots (JSONL fallback). ~30+ JSONL reads eliminated. Snapshot rotation (3 backups) + integrity check + corruption fallback.
- 2475 tests passing
- Server producao: ver config local (nao expor no repo publico)
- Branches: main = stable, develop = bleeding edge
- CI: `make check` + `make test` + `make spec-check`
- Licenca: Apache-2.0 (migrado de BUSL-1.1 em 2026-04-03)
- Release atual: v0.11.0
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

| ID | Feature | Status |
|----|---------|--------|
| 001 | Telegram Interactive Triage | Concluida |
| 002 | Telegram Triage v2 (2FA + Undo + Auto-Learn) | Auto-Learn, Undo e 2FA Telegram concluidos. Pendente: dashboard 2FA endpoints (A5) |
| 003 | Setup Ready To Use | Concluida |
| 004 | Setup Zero Friction | Concluida |
| 005 | Intelligent Notifications | Spec pronto. Grouping + channel filter + env calibration + AI batch triage |
| 012 | Eliminate JSONL Dependency (Phase 6) | **Concluida**. 6A-6F done. Graph primary for dashboard/bot/reports. Deferred: FP tracking, multi-day snapshots, telemetry (spec 013) |
| 010 | Detector Migration (Phase 3) | **3A-3C Done**: 27 graph detectors + 10 correlation rules + dedup + config flag. 3D partial (metrics deferred). 29 tests. |
| 013 | Graph Single Source of Truth (Phase 7) | **COMPLETE** (Gaps 1,2,4,5 done). Daily dated snapshots, FP tracking in graph, monthly report from snapshots, 6h window from event_timeline. Gap 3 deferred (telemetry stays JSONL by design). |
| 014 | Graph Full Connectivity | **COMPLETE** (Phases A-D + leftover). 8 → 18 active relations. tcp_stream/eBPF/memory/cgroup/incident-PID all ingested. Bug fixes: missing `--features ebpf` flag, filename/path field mismatch, 200MB JSONL cap dropping events. Edges 12K → 33K, Process nodes 411 → 4470. |
| 016 | Unified SQLite Store | **COMPLETE** (v0.11.0). Single `innerwarden.db` replaces 15 storage artifacts. 8 phases + cleanup. redb removed, JSONL removed, 14 maintenance tasks, legacy migration. |
| 017 | Dashboard Operator UX | **Draft** P1. Two personas (primary operator + technical fallback). 15 FRs covering state consistency, non-alarmist tone, mobile legibility, stale-data indicators. Spec validated, no plan yet. |
| 019 | Test Coverage Gaps (Batches 2–7) | **In progress** (Gemini-owned). Batch 1 landed in PR #110. Batches 2–7 outstanding: agent + ctl pure-logic extraction. Target 42.85% → 50%. |
| 022 | Dashboard Test Coverage | **Draft** P0. 6 batches covering 16 dashboard files (9,709 lines, 24 tests total). HTML escaping, auth, investigation journeys, sensors status bugs, actions validation. Target 0% → 30%+ on dashboard. |
| 023 | Coverage Closeout (project-wide) | **Draft** P1. 11 batches, 56 files, ~335 tests across ctl/sensor/agent/hypervisor/smm/shield. Picks up what 019 and 022 don't cover. Target 45% → 65% (stretch 70%). Coordination rules + lint traps documented. |
| 024 | Regression Safety Net | **Draft** P0. Three layers: canonical scenario volume tests (`make scenario-qa`), `/metrics` endpoint + drift alerts, contract tests at subsystem boundaries. Kills the whack-a-mole pattern (fix A, break B). Unblocks spec 005 as Phase 3. ~7 AI sessions for Phases A+B. |

## Divida tecnica

- **2FA dashboard endpoints (A5)**: TOTP funciona no Telegram. Falta implementar `GET /api/2fa/pending`, `POST /api/2fa/approve`, `POST /api/2fa/deny` para o metodo "dashboard".
- **Agent main.rs**: 4396 linhas. Modularizacao avancou muito mas `process_incidents` e `process_telegram_approval` ainda concentram orquestracao. Proximos candidatos: Telegram bot commands/status, integracoes.
- **CTL main.rs**: 2201 linhas. Aceitavel. Ponto de manutencao atingido.

## Docs detalhados

Handbook completo: `.claude/CLAUDE.md`
Wiki: `innerwarden.wiki/` no monorepo
