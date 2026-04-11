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

## Estado (2026-04-04)

- 49 sensor detectors + 27 graph detectors (Phase 3A-C complete), 40 eBPF hooks, 65 MITRE IDs, 43 correlation rules + 10 graph correlation rules
- Knowledge graph: in-memory directed graph (11 node types, 50 relation types, 60 event kinds mapped). Dashboard tab + AI triage integration + 58-feature autoencoder (10 graph structural features). **Phase 6 + Phase 7 complete**: graph is single source of truth. Daily dated snapshots (`graph-snapshot-YYYY-MM-DD.json`), 7-day retention. FP tracking in graph (false_positive, fp_reporter, fp_reported_at on Incident nodes). decision_cooldown, report, neural_lifecycle, threat_report all read from graph snapshots (JSONL fallback). ~30+ JSONL reads eliminated. Snapshot rotation (3 backups) + integrity check + corruption fallback.
- Server producao: ver config local (nao expor no repo publico)
- Branches: main = stable, develop = bleeding edge
- CI: `make check` + `make test` + `make spec-check`
- Licenca: Apache-2.0 (migrado de BUSL-1.1 em 2026-04-03)
- Release atual: v0.9.2

## Convencoes

- Commits em ingles
- Sensor: deterministico, zero HTTP/AI
- Agent: pode chamar APIs externas
- I/O errors em sinks: `warn!`, nao `?`
- `spawn_blocking` pra I/O sincrono em tasks Tokio

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

## Divida tecnica

- **2FA dashboard endpoints (A5)**: TOTP funciona no Telegram. Falta implementar `GET /api/2fa/pending`, `POST /api/2fa/approve`, `POST /api/2fa/deny` para o metodo "dashboard".
- **Agent main.rs**: 4396 linhas. Modularizacao avancou muito mas `process_incidents` e `process_telegram_approval` ainda concentram orquestracao. Proximos candidatos: Telegram bot commands/status, integracoes.
- **CTL main.rs**: 2201 linhas. Aceitavel. Ponto de manutencao atingido.

## Docs detalhados

Handbook completo: `.claude/CLAUDE.md`
Wiki: `innerwarden.wiki/` no monorepo
