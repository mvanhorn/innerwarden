# Event Pipeline Rules

Declarative YAML rules that control which events the InnerWarden sensor
persists to disk. Rules are evaluated in priority order (highest first).
Detectors still process all events in memory regardless of pipeline
decisions.

## Quick Start

Drop a `.yml` file in this directory. The sensor hot-reloads every 60
seconds. No restart needed.

```yaml
version: 1
metadata:
  description: Drop noisy batch job reads
rules:
  - id: drop-etl-batch
    priority: 75
    match:
      source: ebpf
      kind: file.read_access
      comm: etl-batch
      path_prefix: ["/var/lib/data/"]
    action: drop
    drop_reason: etl-noise
```

## Rule File Format

```yaml
version: 1                    # Required. Schema version (currently 1).
metadata:                     # Optional. Informational only.
  author: string
  description: string
  last_reviewed: "YYYY-MM-DD"

rules:
  - id: unique-snake-case-id  # Required. Must be unique across all files.
    priority: 0-1000           # Optional (default 50). Higher fires first.
    match:                     # Required. ALL set fields must match (AND).
      <predicates>
    action: <action>           # Required. See Actions below.
    tags: [string]             # Optional. Appended to event tags.
    drop_reason: string        # Optional. Shown in per-rule counters.
    disabled: true             # Optional. Skips rule without deleting file.
    expires_at: "YYYY-MM-DD"   # Optional. Auto-disables after this date.
    sample: 0.0-1.0            # Required when action is "sample".
```

## Match Predicates

All set fields combine with AND. For OR, write two rules with the
same action.

| Field           | Type         | Match shape        | Example                        |
|-----------------|--------------|--------------------|--------------------------------|
| `source`        | string       | exact              | `ebpf`                         |
| `source_in`     | list[string] | any-of             | `[ebpf, auditd]`              |
| `kind`          | string       | exact or glob      | `file.read_access` or `file.*` |
| `kind_in`       | list[string] | any-of             | `[file.read_access, file.write_access]` |
| `comm`          | string       | exact              | `apache2`                      |
| `comm_in`       | list[string] | any-of             | `[nginx, php-fpm, mysqld]`    |
| `comm_glob`     | list[string] | any-of (glob)      | `[innerwarden-*, php-fpm*]`   |
| `path_in`       | list[string] | exact              | `[/etc/shadow]`               |
| `path_glob`     | list[string] | any-of (glob)      | `[/etc/ssh/*, /home/*/.ssh/*]`|
| `path_prefix`   | list[string] | starts-with any    | `[/var/log/, /tmp/]`          |
| `severity_min`  | string       | gte rank           | `medium`                       |
| `uid_in`        | list[int]    | any-of             | `[0]`                          |
| `dst_port_in`   | list[int]    | any-of             | `[4444, 1337]`                |
| `parent_comm_in`| list[string] | any-of             | `[apache2, nginx]`            |

Fields are extracted from `event.details` JSON: `comm`, `filename`/`path`,
`pid`, `uid`, `dst_port`, `parent_comm`.

## Actions

| Action          | Terminal? | Effect |
|-----------------|-----------|--------|
| `emit`          | No        | Persist event. Continue evaluating rules. |
| `force_emit`    | Yes       | Persist event. Stop evaluation. No downstream rule can drop it. |
| `drop`          | Yes       | Discard event from disk. Still seen by detectors in memory. |
| `sample`        | Yes       | Persist with probability `sample` (0.0-1.0). |
| `score_increment`| No       | (Phase 5) Bump per-PID score. Continue evaluating. |

## Built-in Rules

Five packs ship embedded in the sensor binary. They are always loaded
and act as baseline. To override a built-in, create a file in this
directory with a rule that has the same `id`.

| File | Rules | Purpose |
|------|-------|---------|
| `00-defensive-allowlist.yml` | `always-emit-credential-paths` | Credential/config paths ALWAYS persisted (force_emit, priority 1000) |
| `01-self-traffic-suppression.yml` | `drop-innerwarden-self-reads` | Drop innerwarden's own file access |
| `02-service-daemon-suppression.yml` | `drop-service-daemon-file-ops` | Drop web/db/auth daemon file access |
| `03-package-manager-suppression.yml` | `drop-package-manager-file-ops` | Drop apt/dpkg/snap/pip/npm/cargo file access |
| `99-default-sample.yml` | `sample-remainder-file-ops` | 1% sample of remaining file access events |

## File Naming Convention

- `00-09`: reserved for built-in packs
- `10-89`: operator rules (loaded in lexicographic order)
- `90-99`: reserved for catch-all/sampling rules

## Validation

- Unknown fields in YAML are rejected (`deny_unknown_fields`).
- Invalid glob patterns are rejected per-rule (other rules still load).
- Invalid files are skipped with a warning in `journalctl`.
- Missing or empty directory = only built-in rules apply.

## Testing a Rule (Coming Soon)

```
sudo innerwarden rule test <file.yml>
sudo innerwarden rule list
sudo innerwarden rule disable <rule-id>
```

Phase 4 of the event pipeline spec will add CLI tooling for dry-run
testing against the last hour of events.
