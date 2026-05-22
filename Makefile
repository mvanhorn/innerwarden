TARGET_LINUX := aarch64-unknown-linux-gnu
SENSOR_DIR   := crates/sensor
AGENT_DIR    := crates/agent
RELEASE_DIR  := target/$(TARGET_LINUX)/release
CARGO        := $(HOME)/.cargo/bin/cargo

# Detect whether eBPF can be built on this host. On Linux with bpf-linker
# installed we ALWAYS embed the BPF bytecode into the sensor binary so a
# single artefact ships everything needed to load the eBPF subsystem at
# runtime — no separate .o file deployed beside the binary, no host-time
# clang+libbpf dependency. On macOS or any host without bpf-linker we
# silently fall back to building the sensor with `--features ebpf` and
# rely on the runtime `EBPF_OBJ_PATH` lookup, which keeps the macOS dev
# loop fast and unblocks contributors who haven't set up the BPF
# toolchain yet.
HOST_OS         := $(shell uname -s)
HAS_BPF_LINKER  := $(shell command -v bpf-linker 2>/dev/null)
ifeq ($(HOST_OS),Linux)
ifneq ($(HAS_BPF_LINKER),)
  SENSOR_FEATURES := ebpf-embedded
else
  SENSOR_FEATURES := ebpf
endif
else
  SENSOR_FEATURES := ebpf
endif

# ─── Local dev ───────────────────────────────────────────────────────────────

# Build the eBPF bytecode (Linux only, requires bpf-linker + nightly Rust).
# Pre-requisite for `build-sensor` / `build` when on a host that supports
# bpf-linker. On macOS or hosts without bpf-linker this becomes a no-op
# so the dev loop stays fast.
.PHONY: build-ebpf
build-ebpf:
ifeq ($(HOST_OS),Linux)
ifneq ($(HAS_BPF_LINKER),)
	@echo "[build-ebpf] cd crates/sensor-ebpf && cargo +nightly build --target bpfel-unknown-none …"
	@cd crates/sensor-ebpf && RUSTFLAGS="" \
		cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
	@ls -la crates/sensor-ebpf/target/bpfel-unknown-none/release/innerwarden-ebpf
else
	@echo "[build-ebpf] bpf-linker not on PATH — skipping bytecode build (sensor will use runtime .o lookup)"
	@echo "             Install: cargo +nightly install bpf-linker --locked"
endif
else
	@echo "[build-ebpf] host is $(HOST_OS), not Linux — skipping (sensor on macOS dev does not load eBPF)"
endif

.PHONY: build
build: build-ebpf
	$(CARGO) build -p innerwarden-sensor --features $(SENSOR_FEATURES)
	$(CARGO) build -p innerwarden-agent -p innerwarden-ctl

.PHONY: build-sensor
build-sensor: build-ebpf
	$(CARGO) build -p innerwarden-sensor --features $(SENSOR_FEATURES)

.PHONY: build-agent
build-agent:
	$(CARGO) build -p innerwarden-agent

.PHONY: build-ctl
build-ctl:
	$(CARGO) build -p innerwarden-ctl

.PHONY: test
test:
	$(CARGO) test --workspace

.PHONY: run-sensor
run-sensor:
	$(CARGO) run -p innerwarden-sensor -- --config config.test.toml

.PHONY: run-agent
run-agent:
	$(CARGO) run -p innerwarden-agent -- --data-dir ./data

.PHONY: run-dashboard
run-dashboard:
	$(CARGO) run -p innerwarden-agent -- --data-dir ./data --dashboard

# Test the enable flow without applying changes (safe to run locally)
.PHONY: test-enable-dry-run
test-enable-dry-run: build-ctl
	$(CARGO) run -p innerwarden-ctl -- \
		--sensor-config config.test.toml \
		--agent-config agent-test.toml \
		--dry-run \
		enable block-ip

.PHONY: replay-qa
replay-qa:
	./scripts/replay_qa.sh

.PHONY: scenario-qa
scenario-qa:
	./scripts/scenario_qa.sh

.PHONY: ops-check
ops-check:
	./scripts/ops-check.sh $(DATA_DIR)

# Requires nightly Rust + cargo-fuzz (`cargo install cargo-fuzz`).
# `fuzz-quick` runs each harness for 60s, enough to catch regressions
# on a developer machine without burning a build slot. For real
# coverage, point OSS-Fuzz or a dedicated runner at the targets.
FUZZ_DURATION ?= 60
.PHONY: fuzz-quick
fuzz-quick:
	@command -v cargo-fuzz >/dev/null 2>&1 || { echo "cargo-fuzz not installed; run: cargo install cargo-fuzz"; exit 1; }
	@for target in tls_client_hello core_event_json core_incident_json; do \
		echo "[fuzz] $$target — $(FUZZ_DURATION)s"; \
		(cd fuzz && cargo +nightly fuzz run $$target -- -max_total_time=$(FUZZ_DURATION)) || exit 1; \
	done

# Spec 035 PR-A2: heap-budget regression gate via DHAT-instrumented
# allocator. Runs the three anchors in
#   crates/agent/src/knowledge_graph/persistence.rs (save_to_store)
#   crates/agent/src/loops/slow_loop.rs           (narrative tick)
#   crates/agent/src/loops/boot.rs                (run_agent once-mode)
# Each asserts cumulative allocation churn (DHAT total_bytes) stays
# under a baseline-derived budget. `--test-threads=1` is MANDATORY —
# DHAT's counter is process-global and concurrent tests contaminate
# the delta (see module-level comments in each file for detail).
.PHONY: heap-budget
heap-budget:
	cargo test -p innerwarden-agent --features dhat-heap heap_budget -- --test-threads=1

# ─── Cross-compile for Linux arm64 ───────────────────────────────────────────

.PHONY: build-linux
build-linux:
	@$(dir $(CARGO))cargo-zigbuild --version >/dev/null 2>&1 || \
		{ echo "cargo-zigbuild not found - install with: cargo install cargo-zigbuild"; exit 1; }
	@rustup target add $(TARGET_LINUX) 2>/dev/null || true
	$(CARGO) zigbuild -p innerwarden-sensor --features $(SENSOR_FEATURES) \
		--target $(TARGET_LINUX) --release
	$(CARGO) zigbuild -p innerwarden-agent -p innerwarden-ctl \
		--target $(TARGET_LINUX) --release
	@echo "Sensor: $(RELEASE_DIR)/innerwarden-sensor"
	@echo "Agent:  $(RELEASE_DIR)/innerwarden-agent"
	@echo "Ctl:    $(RELEASE_DIR)/innerwarden-ctl"

# ─── Deploy ──────────────────────────────────────────────────────────────────

# Override on the command line: make update HOST=user@myserver
HOST ?= user@your-server

# ── Full update pipeline: test → build → deploy → restart → verify ────────────
# Usage: make update HOST=ubuntu@1.2.3.4
#
# Steps:
#   1. make test      - all tests must pass (fails fast if any break)
#   2. make build-linux - cross-compile release binaries for arm64 Linux
#   3. Stop agent + sensor gracefully (sensor last so no events are lost)
#   4. SCP both binaries to /tmp, install to /usr/local/bin atomically
#   5. Restart sensor → agent (sensor first so agent finds fresh data)
#   6. Wait 3s, show status of both services + tail last 20 log lines
.PHONY: update
update: test build-linux
	@echo "══════════════════════════════════════════════════"
	@echo "  Deploying to $(HOST)"
	@echo "══════════════════════════════════════════════════"
	@echo "→ Stopping services..."
	ssh $(HOST) "sudo systemctl stop innerwarden-agent  2>/dev/null || true"
	ssh $(HOST) "sudo systemctl stop innerwarden-sensor 2>/dev/null || true"
	@echo "→ Uploading binaries..."
	scp $(RELEASE_DIR)/innerwarden-sensor $(HOST):/tmp/innerwarden-sensor
	scp $(RELEASE_DIR)/innerwarden-agent  $(HOST):/tmp/innerwarden-agent
	scp $(RELEASE_DIR)/innerwarden-ctl    $(HOST):/tmp/innerwarden-ctl
	@echo "→ Installing binaries..."
	ssh $(HOST) "sudo install -o root -g root -m 755 /tmp/innerwarden-sensor /usr/local/bin/innerwarden-sensor"
	ssh $(HOST) "sudo install -o root -g root -m 755 /tmp/innerwarden-agent  /usr/local/bin/innerwarden-agent"
	ssh $(HOST) "sudo install -o root -g root -m 755 /tmp/innerwarden-ctl    /usr/local/bin/innerwarden-ctl"
	ssh $(HOST) "sudo ln -sf /usr/local/bin/innerwarden-ctl /usr/local/bin/innerwarden"
	@echo "→ Restarting services..."
	ssh $(HOST) "sudo systemctl daemon-reload && sudo systemctl start innerwarden-sensor"
	ssh $(HOST) "sudo systemctl start innerwarden-agent 2>/dev/null || true"
	@echo "→ Waiting for services to settle..."
	@sleep 3
	@echo "══════════════════════════════════════════════════"
	@echo "  Status"
	@echo "══════════════════════════════════════════════════"
	ssh $(HOST) "sudo systemctl status innerwarden-sensor innerwarden-agent --no-pager -l"
	@echo "══════════════════════════════════════════════════"
	@echo "  Recent logs (sensor)"
	@echo "══════════════════════════════════════════════════"
	ssh $(HOST) "sudo journalctl -u innerwarden-sensor -n 20 --no-pager"
	@echo "══════════════════════════════════════════════════"
	@echo "  Recent logs (agent)"
	@echo "══════════════════════════════════════════════════"
	ssh $(HOST) "sudo journalctl -u innerwarden-agent  -n 20 --no-pager"
	@echo ""
	@echo "✓ Update complete."

# ── deploy: binaries only, no test run (faster, use when tests already passed) ─
.PHONY: deploy
deploy: build-linux
	@echo "Deploying to $(HOST) (no test run - use 'make update' for full pipeline)..."
	ssh $(HOST) "sudo systemctl stop innerwarden-agent  2>/dev/null || true"
	ssh $(HOST) "sudo systemctl stop innerwarden-sensor 2>/dev/null || true"
	scp $(RELEASE_DIR)/innerwarden-sensor $(HOST):/tmp/innerwarden-sensor
	scp $(RELEASE_DIR)/innerwarden-agent  $(HOST):/tmp/innerwarden-agent
	scp $(RELEASE_DIR)/innerwarden-ctl    $(HOST):/tmp/innerwarden-ctl
	ssh $(HOST) "sudo install -o root -g root -m 755 /tmp/innerwarden-sensor /usr/local/bin/innerwarden-sensor"
	ssh $(HOST) "sudo install -o root -g root -m 755 /tmp/innerwarden-agent  /usr/local/bin/innerwarden-agent"
	ssh $(HOST) "sudo install -o root -g root -m 755 /tmp/innerwarden-ctl    /usr/local/bin/innerwarden-ctl"
	ssh $(HOST) "sudo ln -sf /usr/local/bin/innerwarden-ctl /usr/local/bin/innerwarden"
	ssh $(HOST) "sudo systemctl daemon-reload && sudo systemctl start innerwarden-sensor"
	ssh $(HOST) "sudo systemctl start innerwarden-agent 2>/dev/null || true"
	@echo "Deploy complete - checking status:"
	ssh $(HOST) "sudo systemctl status innerwarden-sensor innerwarden-agent --no-pager"

.PHONY: deploy-config
deploy-config:
	@[ -f config.prod.toml ] || { echo "config.prod.toml not found"; exit 1; }
	ssh $(HOST) "sudo mkdir -p /etc/innerwarden"
	scp config.prod.toml $(HOST):/tmp/innerwarden-config.toml
	ssh $(HOST) "sudo install -o root -g root -m 640 /tmp/innerwarden-config.toml /etc/innerwarden/config.toml"

.PHONY: deploy-service
deploy-service:
	scp examples/systemd/innerwarden-sensor.service $(HOST):/tmp/innerwarden-sensor.service
	scp examples/systemd/innerwarden-agent.service  $(HOST):/tmp/innerwarden-agent.service
	ssh $(HOST) "sudo install -o root -g root -m 644 /tmp/innerwarden-sensor.service /etc/systemd/system/innerwarden-sensor.service"
	ssh $(HOST) "sudo install -o root -g root -m 644 /tmp/innerwarden-agent.service  /etc/systemd/system/innerwarden-agent.service"
	ssh $(HOST) "sudo systemctl daemon-reload && sudo systemctl enable innerwarden-sensor innerwarden-agent"

.PHONY: rollout-precheck
rollout-precheck:
	ssh $(HOST) 'bash -s -- pre' < scripts/rollout_smoke.sh

.PHONY: rollout-postcheck
rollout-postcheck:
	ssh $(HOST) 'bash -s -- post' < scripts/rollout_smoke.sh

.PHONY: rollout-rollback
rollout-rollback:
	ssh $(HOST) 'bash -s -- rollback' < scripts/rollout_smoke.sh

.PHONY: rollout-stop-agent
rollout-stop-agent:
	ssh $(HOST) "sudo systemctl stop innerwarden-agent && sudo systemctl status innerwarden-agent --no-pager || true"

# ─── Remote ops ──────────────────────────────────────────────────────────────

.PHONY: logs
logs:
	ssh $(HOST) "sudo journalctl -u innerwarden-sensor -u innerwarden-agent -f --no-pager"

.PHONY: logs-sensor
logs-sensor:
	ssh $(HOST) "sudo journalctl -u innerwarden-sensor -f --no-pager"

.PHONY: logs-agent
logs-agent:
	ssh $(HOST) "sudo journalctl -u innerwarden-agent -f --no-pager"

.PHONY: status
status:
	ssh $(HOST) "sudo systemctl status innerwarden-sensor innerwarden-agent --no-pager"

# ─── Helpers ─────────────────────────────────────────────────────────────────

.PHONY: clean
clean:
	$(CARGO) clean

.PHONY: check
check:
	$(CARGO) clippy --workspace -- -D warnings
	$(CARGO) fmt --all --check

.PHONY: spec-check
spec-check:
	$(CARGO) test -p innerwarden-sensor -- spec_ --test-threads=1
