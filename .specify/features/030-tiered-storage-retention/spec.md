# Feature Specification: Tiered Storage Retention

**Feature Branch**: `030-tiered-storage-retention`
**Created**: 2026-04-21
**Status**: Draft
**Input**: Oracle production deploy of spec 029 surfaced that `innerwarden.db` grew to 1.36 GB in 9 days with no pruning. The sqlite store is treated as permanent state, but most of its content is ephemeral processing data that already has a durable home in the per-day JSONL files. Agent RSS is 432 MB (sqlite page cache accounts for ~40% of that) and trending up.

## Origin

Spec 013 Phase 6 (2026-04-10) moved read paths from JSONL scans to sqlite for speed. That landed correctly — queries went from ~200ms to ~5ms — but the retention side of the swap never landed. Today:

- JSONL retention is configured and working (`events-*.jsonl`, `incidents-*.jsonl`, `decisions-*.jsonl` pruned after `[data]` retention days).
- Sqlite retention is absent. Events/incidents/decisions/graph_snapshots tables grow forever.
- `graph-snapshot-YYYY-MM-DD.json` files on disk also never expire (9 daily snapshots at ~40 MB each on Oracle).
- WAL checkpoint is implicit (sqlite default every ~1000 pages) and `VACUUM` is never called, so freed pages stay.

The system accidentally became tiered: the JSONL files are a perfectly good append-only log of truth, sqlite is the hot index. The missing piece is explicit retention on the hot tier so only the processing window lives there.

## Problem statement

1. Sqlite db on Oracle: 1.36 GB. Breakdown: `graph_snapshots=282MB` (1 row/day × 9d), `events=151MB` (176k rows / 2d — not 9d because something is pruning events but not in a controlled way), `incidents=7MB` (5479 rows / 9d), `decisions=2MB` (2143 rows / 9d). All other tables under 5 MB combined.

2. Graph snapshot files on disk: 360 MB (9 daily snapshots averaging ~40MB).

3. Agent RSS: 432 MB. Sqlite page cache dominates (~150-200 MB estimated). ONNX classifier adds 87 MB. Knowledge graph in memory adds ~25 MB. Rust allocator + jemalloc overhead ~50-100 MB. Tokenizer, threat feeds, buffers: small.

4. No operator-facing knob to trade "queryable history depth" for "memory footprint". An operator running on a small VM has to choose between accepting 500 MB+ RSS or hand-editing sqlite.

5. Dashboard drift risk: if retention is applied naively and the dashboard tries to query pruned incidents, the UI breaks. Any retention spec must define what happens to old queries.

## Proposal

### Three-tier model

```
┌────────────────────────────────────────────────────────────┐
│ Hot: sqlite innerwarden.db                                 │
│   - processing window: last 7d events, 30d incidents,      │
│     90d decisions, 3 most-recent graph snapshots           │
│   - served at ~5 ms query latency                          │
│   - dashboard live paths read here                         │
└────────────────────┬───────────────────────────────────────┘
                     │ age > hot_days: DELETE FROM ...
                     ▼
┌────────────────────────────────────────────────────────────┐
│ Warm: JSONL append-only log                                │
│   - events-YYYY-MM-DD.jsonl, incidents-*, decisions-*,     │
│     graph-snapshot-*.json                                  │
│   - already written as source of truth                     │
│   - kept 30-90d (per-kind via existing [data] config)      │
│   - dashboard drill-down of old periods reads here on      │
│     demand (seconds, acceptable for rare queries)          │
└────────────────────┬───────────────────────────────────────┘
                     │ age > warm_days: gzip in place
                     ▼
┌────────────────────────────────────────────────────────────┐
│ Cold: gzipped archive                                      │
│   - events-2026-02-15.jsonl.gz etc.                        │
│   - forensic / compliance reads only                       │
│   - compression ~85% for event JSONL                       │
│   - after cold_days: delete (operator compliance config)   │
└────────────────────────────────────────────────────────────┘
```

### Retention defaults

| Data kind | Hot (sqlite) | Warm (JSONL on disk) | Cold (gzipped) | Notes |
|---|---|---|---|---|
| events | 7d | 30d | never | AI context uses last 50k rows, not a time window. Dashboard "live" tab shows last 72h. |
| incidents | 30d | 90d | never | Dashboard drill-down + knowledge graph training data |
| decisions | 90d | 365d | never | Audit / compliance trail. Small table, ~20 MB/90d |
| graph_snapshots (sqlite) | 3 most-recent | - | - | Only the latest is loaded on restart |
| graph-snapshot-*.json files | 3d | - | - | Written daily; recovery uses the latest |
| telemetry | already handled | - | - | No change |
| reports | already handled | - | - | No change |

All values configurable in `[data]` block of `agent.toml`, defaults above. An operator running a compliance profile can bump decisions to 7 years, or a lab operator can tighten events to 24h.

### Cold tier scope

Opt-in per kind. Default `cold_enabled = false` because gzip on small JSONL is pointless and operators who need archival usually ship to S3 / SIEM anyway. When `cold_enabled = true`, the warm → cold transition is in-place gzip; a follow-up `cold_days` trigger deletes the `.gz` if set.

### Dashboard fallback to warm tier

The dashboard and CLI query paths currently hit sqlite exclusively. When sqlite is pruned past the hot window, old-incident drill-down would return "not found". The fix:

1. Query sqlite first (~5 ms, covers the common case: recent period).
2. On miss, check if the requested timestamp falls within the warm window.
3. If yes, scan the matching `incidents-YYYY-MM-DD.jsonl` (possibly `.gz`) for the id.
4. Return the row; UI shows a small "loaded from archive" indicator so operators see why the response was ~500 ms instead of ~5 ms.

The fallback path is read-only. Writes always land in both sqlite (hot) and JSONL (warm) as today, so nothing new in the write path.

### VACUUM and WAL checkpoint

Pruning alone does not reclaim disk. Sqlite marks pages free; the file stays the same size. Two housekeeping operations needed:

1. **WAL checkpoint (passive)** — hourly. Keeps `innerwarden.db-wal` bounded under ~10 MB. Current WAL on Oracle is 28 MB because passive checkpoints rely on sqlite's default trigger (every ~1000 pages) which under-fires on a mostly-idle DB.

2. **VACUUM** — weekly or when free space exceeds 20% of file size. `VACUUM INTO` avoids locking (rebuilds into a temp file, atomic swap). Runs at 03:00 local to avoid colliding with the autoencoder retrain (also 03:00 but different lock scope).

Both run from the slow loop (already ticks once per 30 s), gated by a "last run" timestamp in `kv_state`.

### Graph snapshot file pruning

Already wrote `data_retention.rs::cleanup`. Extend the pattern list with `graph-snapshot-` and a separate retention key `graph_snapshot_keep_days` (default 3). No new code path, just a table entry.

## Scope

**In**:
- sqlite row-level pruning for events, incidents, decisions, graph_snapshots
- `graph-snapshot-*.json` file pruning via existing data_retention helper
- WAL checkpoint loop (hourly)
- VACUUM loop (weekly, or on free-space threshold)
- Dashboard fallback: on sqlite miss for an incident in the warm window, read JSONL
- Optional gzip compression for warm-tier JSONL older than `warm_days`
- Config surface under `[data]` with sane defaults
- Metrics: `retention_rows_deleted_total{kind}`, `retention_bytes_reclaimed_total`, `retention_last_run_ts`

**Out**:
- S3 / remote cold storage — operators wanting this today can run an rsync cron. Adding S3 support is a separate spec.
- Per-tenant retention (multi-tenant is not a thing in the product today)
- Live streaming to SIEM (already an option via webhook; not retention's problem)
- Changing the sqlite schema itself (new indexes, partitioning, etc.) — keep the schema stable, just prune

## Rollout

PR-A: **sqlite pruning primitives**
- `store::prune_events_older_than(days: u32) -> usize`
- `store::prune_incidents_older_than(days: u32) -> usize`
- `store::prune_decisions_older_than(days: u32) -> usize`
- `store::prune_graph_snapshots_keep_latest(n: usize) -> usize`
- Pure sqlite tests (in-memory): insert old + new rows, prune, assert count.

PR-B: **retention loop wiring**
- `data_retention::run_sqlite_retention(store, cfg)` invoked from slow loop.
- Runs at most once per `retention_interval_hours` (default 24).
- Emits metrics + logs.
- Backfill the graph-snapshot file pattern into the existing JSONL sweep.
- Integration test: run loop twice in ≤ interval, assert second is no-op.

PR-C: **housekeeping (WAL + VACUUM)**
- `store::wal_checkpoint_passive()` — hourly.
- `store::vacuum_if_free_space_ratio_exceeds(ratio: f32)` — weekly.
- Tests: insert/delete then assert file size shrinks after vacuum.

PR-D: **dashboard fallback**
- `read_incident_from_warm_tier(data_dir, incident_id, ts) -> Option<Incident>` in reader module.
- Dashboard `/api/incidents/:id` checks sqlite, then warm on miss.
- Log + metric when falling back. UI hint (small "archive" badge).
- Test: prune an incident from sqlite, assert the dashboard still returns it with the archive-source flag.

PR-E (optional, deferred if rollout is running long): **cold-tier gzip**
- `data_retention::gzip_warm_files_older_than(days)`.
- Reader opens both `.jsonl` and `.jsonl.gz` transparently.
- Config: `cold_enabled = false` default.

Each PR ships with tests above the patch coverage floor (70% with 15pp slack per the project codecov config). PR-D is the only one with user-facing behavior change (dashboard badge) — everything else is operationally silent.

## Success criteria

**Production measurements after PR-A + PR-B + PR-C land (on the Oracle London box, roughly one week of data accumulation):**

- `innerwarden.db` size: < 500 MB (from 1.36 GB)
- `innerwarden.db-wal`: < 15 MB (from 28 MB)
- `graph-snapshot-*.json` total: < 120 MB (from 360 MB)
- Agent RSS: < 300 MB steady-state (from 432 MB)
- Retention loop runtime: < 5 s end to end
- Zero regressions in dashboard live queries (p99 < 50 ms for the last 24h window, unchanged)

**Dashboard fallback correctness (after PR-D):**

- Operator queries a 45-day-old incident (outside hot window, inside warm window). Dashboard returns the record within 2 s and displays the archive indicator. Logged.
- Operator queries a 400-day-old incident (outside warm window). Dashboard returns a typed 404 with "beyond retention window; configure [data] for longer retention" — never a crash or silent empty response.

## Non-goals

- Changing the source-of-truth ordering. JSONL is authoritative for write ordering; sqlite is the fast index. Retention never deletes JSONL ahead of sqlite.
- Replacing sqlite. Out of scope — the cost is retention, not the engine.
- Distributed retention coordination (fleet-wide). Each agent prunes its own store.

## Risks

1. **Dashboard drift** — an existing dashboard view implicitly assumes sqlite has all history. We will audit the dashboard query surface before shipping PR-A; if a view relies on > hot window, either extend the hot window or add the warm fallback first (reorder PR-D before PR-A for that specific table).

2. **VACUUM lock** — `VACUUM INTO` is non-blocking but requires roughly 2× disk space during the rebuild. On a 1.36 GB db that's 2.7 GB free. The Oracle box has 900 GB free so this is fine, but the doc will note the requirement.

3. **Retention sweeping deletion of rows the knowledge graph later needs** — the neural training pipeline (gym) reads historical incidents. Coordinate with `neural_lifecycle::training_retention_days` (currently 7). If retention spec sets incidents hot window shorter than that, training gets starved. Align defaults: incidents hot window ≥ training_retention_days.

4. **Operator surprise** — an operator hand-inspecting sqlite ("select * from events") expecting to see last month's data will see last 7 days only after this lands. Call out in CHANGELOG + release notes. Make the warm-tier fallback discoverable (`innerwarden query events --since 30d` CLI command lands with PR-D).

## Timeline

- PR-A, PR-B, PR-C: shipped together in one release window. Roughly 1 day of coding + review.
- PR-D: follow-up in the same release or next, depending on dashboard audit findings.
- PR-E (cold tier): optional, shipped only if operators ask for it.

Target: merge all PR-A..PR-D by end of week, bundle into v0.13 release alongside spec 029 observation results.
