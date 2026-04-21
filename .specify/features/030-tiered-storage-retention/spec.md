# Feature Specification: Tiered Storage Retention

**Feature Branch**: `030-tiered-storage-retention`
**Created**: 2026-04-21
**Status**: Draft
**Input**: Oracle production deploy of spec 029 surfaced that `innerwarden.db` grew to 1.36 GB in 9 days. On inspection, spec 016 already ships a `MaintenanceScheduler` (WAL checkpoint every 5 min, incremental_vacuum hourly, `run_retention(events=2d, incidents=30d, decisions=90d, graph_snapshots=7d)` daily). The file is big despite retention because (a) `incremental_vacuum` does not shrink the file, only marks pages free; (b) `graph-snapshot-*.json` files on disk are outside the sqlite table and not in the retention sweep; (c) warm-tier JSONL is kept uncompressed. Agent RSS is 432 MB.

## Origin

Spec 013 Phase 6 (2026-04-10) moved read paths from JSONL scans to sqlite. Spec 016 added the `MaintenanceScheduler`. Both landed, but the gap between "mark pages free" and "file shrinks on disk" was never closed, and cold-tier compression was deferred. Today:

- Sqlite row-level retention **is running** (daily tick, aggressive defaults).
- `wal_checkpoint` **is running** (5-min tick, TRUNCATE mode).
- `incremental_vacuum(1000)` **is running** hourly, `incremental_vacuum(5000)` daily if DB > 500 MB. Reclaims free pages to the freelist but the sqlite file size stays roughly constant — the freelist is in-file.
- **No full `VACUUM`** ever runs. That is the only operation that rebuilds the file and actually shrinks it.
- **No `graph-snapshot-*.json` file pruning**: `data_retention::cleanup` knows about `events-*.jsonl`, `incidents-*.jsonl`, `decisions-*.jsonl`, `telemetry-*`, `admin-actions-*`, `agent-guard-events-*`, `trial-report-*`, `summary-*`, `monthly-report-*`. Graph snapshots are not in the pattern list, so they accumulate at ~40 MB/day.
- **No warm-tier compression**: older JSONL sits uncompressed. `gzip -9` on event JSONL compresses ~85% in practice, so a 30-day warm window currently costing 300 MB on disk becomes ~45 MB compressed.
- **Transparent `.gz` reads** do not exist. If we compress old JSONL, the reader module needs to handle both extensions.

The system accidentally became tiered: JSONL files are the append-only log of truth, sqlite is the hot index. Spec 016 closed hot-tier retention; this spec closes the disk-shrink, graph-snapshot-file, and warm-tier compression gaps.

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

Since spec 016 already covers the sqlite row-pruning + WAL + incremental_vacuum path, this spec only closes the three remaining gaps. Everything ships in one PR (#225):

**Gap 1: full VACUUM**
- `Store::vacuum_full_into_tempfile()` — runs `VACUUM INTO '<tmp>'`, fsyncs, atomically swaps over `innerwarden.db`. Non-blocking for readers during the rebuild.
- Scheduler: weekly, gated on `free_page_ratio > 0.20` (avoid rebuild when the file is already dense).
- Tests: insert rows, delete half, assert post-vacuum file size < pre-vacuum.

**Gap 2: graph-snapshot file pruning**
- Extend `data_retention::cleanup` patterns with `graph-snapshot-` prefix.
- Add `graph_snapshot_keep_days: u32` to `[data]` config (default 3).
- Test: write five fake snapshot files, run cleanup, assert oldest two removed.

**Gap 3: warm-tier gzip + transparent reads**
- `data_retention::gzip_warm_files_older_than(data_dir, days, prefixes)` — compresses matching files older than N days with gzip, atomic rename to `.gz`, deletes original.
- Add `warm_gzip_days: u32` to `[data]` (default 7). `0` disables.
- Reader module: open helper tries `path.jsonl`, falls back to `path.jsonl.gz` via `flate2::read::GzDecoder`. Existing call sites keep their signature; the helper is transparent.
- Pre-existing `innerwarden query` / `innerwarden report` CLI paths inherit the transparent read. No call-site audit needed.
- Tests:
  - Compress sample JSONL, decode back, assert content match.
  - Reader opens `.jsonl` when present, falls back to `.jsonl.gz` when original deleted.
  - `data_retention` sweep compresses files past threshold, leaves recent files untouched.

**Gap 4: sqlite per-connection tuning**

Low-risk PRAGMA retuning to trade a small amount of in-process cache
for large RSS savings (100 - 150 MB headroom on Oracle). The OS page
cache still serves hot pages, so the miss cost is negligible for our
workload.

- `cache_size = -2000` (2 MB per connection, down from 8 MB).
- `mmap_size = 0` (disable sqlite internal memory-mapped IO; reads
  go through `read()` and land in the OS page cache instead of the
  agent's address space).
- `temp_store = 1` (FILE - temporary tables on disk rather than RAM;
  agent queries rarely touch temp tables so the disk cost is
  invisible).
- Applied via `SqliteConnectionManager::with_init` so every pooled
  connection (not just the first fetched) receives the configuration.
  The pre-030 path configured only the first connection and relied
  on the pool returning the same one, which broke as soon as a
  second connection was created on demand.
- Tests: assert each PRAGMA value after `pool.get()` for memory and
  file-backed stores, and across repeated fetches on the file pool.

**Gap 5: jemalloc runtime tuning**

The agent already uses jemalloc on Linux (`tikv-jemallocator` as
global allocator) but ships without an explicit `MALLOC_CONF`, so
jemalloc uses its generic defaults. The security agent has spiky
allocation patterns (JSON parsing, graph rebuilds, tokenizer
batches) that leave RSS close to the recent peak instead of the
working set.

Embed a `malloc_conf` static string in the binary so operators get
production-ready memory behaviour without touching env vars:

- `background_thread:true` purges off the hot path.
- `dirty_decay_ms:1000` returns dirty pages to the OS after 1 s of
  idleness (jemalloc default is 10 s).
- `muzzy_decay_ms:1000` matches the dirty interval so there is a
  single predictable decay window.

Compile-time only (Linux, non-test builds); macOS uses the system
allocator. No runtime tests because `#[export_name = "malloc_conf"]`
is a symbol the jemalloc runtime reads at startup; behavioural
verification is possible via `jemalloc-ctl` but the dependency bloat
is not worth the marginal signal.

Expected: additional ~50 MB RSS reduction beyond the sqlite tuning,
with no latency regression for our workload.

**Out of this PR (separate follow-up)**:
- Dashboard warm-tier fallback for old incidents — keep in spec but ship in its own PR after dashboard query surface audit. Shipping the compress helper first means sqlite-prune + file-compress is independently valuable, and the dashboard change gets its own focused review.

Patch coverage ≥ 70% (project floor with 15pp slack).

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
