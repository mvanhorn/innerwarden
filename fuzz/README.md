# InnerWarden fuzz harnesses

Three cargo-fuzz harnesses for the parsers that see attacker-controlled
input on a live deployment:

- **tls_client_hello** — raw TLS ClientHello bytes. Exercises
  `sensor::collectors::tls_fingerprint::parse_packet` and the JA3/JA4
  fingerprint computer.
- **core_event_json** — JSON → `innerwarden_core::event::Event`. The
  deserialisation boundary for JSONL replay, redis-stream ingestion, and
  external sinks.
- **core_incident_json** — JSON → `innerwarden_core::incident::Incident`.
  Loaded on startup to rebuild in-memory state; must never panic on a
  corrupted line.

## Running locally

Requires nightly Rust + cargo-fuzz:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

Run one target for 60 seconds:

```bash
cd fuzz
cargo +nightly fuzz run tls_client_hello -- -max_total_time=60
```

Or run every target through the Makefile:

```bash
make fuzz-quick               # 60s per target
FUZZ_DURATION=300 make fuzz-quick  # 5min per target
```

## CI

`.github/workflows/fuzz.yml` runs each target for 5 minutes every night
and on manual dispatch. It does not block PRs. Crashes are uploaded as
workflow artifacts under `fuzz-crash-<target>/` and kept for 14 days so
the operator can reproduce:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```

## Adding a target

1. Create `fuzz_targets/<name>.rs` with a `fuzz_target!` entry point.
2. Add a matching `[[bin]]` section to `fuzz/Cargo.toml`.
3. Add the target name to `Makefile` `fuzz-quick` and to the workflow
   matrix in `.github/workflows/fuzz.yml`.
4. Fuzz harnesses must not panic on any input. Surface deliberate
   invariants with `assert!` only when the assertion is load-bearing.
