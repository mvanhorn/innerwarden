#!/usr/bin/env bash
# Deploy InnerWarden components to production server.
# Usage: ./scripts/deploy-prod.sh [sensor|agent|ctl|all]

set -euo pipefail

SERVER="ubuntu@130.162.171.105"
SSH_PORT=49222
SSH_KEY="$HOME/.ssh/id_oracle_ed25519"
SSH="ssh -p $SSH_PORT -i $SSH_KEY $SERVER"
REMOTE_DIR="/home/ubuntu/innerwarden"
BIN_DIR="/usr/local/bin"

component="${1:-all}"

die() { echo "ERROR: $1" >&2; exit 1; }

# Validate argument
case "$component" in
  sensor|agent|ctl|all) ;;
  *) die "Usage: $0 [sensor|agent|ctl|all]" ;;
esac

echo "=== Deploy $component to production ==="

# Step -1: Source-state guard (Wave 9d, 2026-05-04).
#
# Guards against the failure mode that produced the 2026-05-04 prod
# incident: a fix had been merged to main for hours but the binary on
# prod was built from a stale checkout (HEAD on a feature branch from 2
# days earlier). cargo build succeeded, the agent restarted "clean",
# and the operator believed the fix was live - 1000+ false-positive
# correlation chains continued firing for two days.
#
# Refuses to proceed when:
#   - remote /home/ubuntu/innerwarden HEAD is not on the `main` branch
#   - HEAD is behind origin/main (would silently miss merged commits)
#   - working tree has uncommitted changes (cargo build would pick them
#     up but the resulting binary would not match any commit)
#
# Operator can still ship a feature-branch experiment by skipping the
# guard explicitly: DEPLOY_SKIP_SOURCE_GUARD=1 ./scripts/deploy-prod.sh
# (use sparingly; the guard exists for a reason).
echo "[-1/4] Source-state guard..."
if [ "${DEPLOY_SKIP_SOURCE_GUARD:-0}" = "1" ]; then
  echo "  WARN: DEPLOY_SKIP_SOURCE_GUARD=1 set - skipping branch/sync check."
else
  branch=$($SSH "cd $REMOTE_DIR && git rev-parse --abbrev-ref HEAD" 2>/dev/null || echo "?")
  if [ "$branch" != "main" ]; then
    die "remote $REMOTE_DIR is on branch '$branch', not 'main'. Either:
  - SSH in and \`git checkout main\` first, or
  - Re-run with DEPLOY_SKIP_SOURCE_GUARD=1 to deploy this branch anyway."
  fi
  $SSH "cd $REMOTE_DIR && git fetch origin main --quiet" || die "git fetch failed"
  ahead_behind=$($SSH "cd $REMOTE_DIR && git rev-list --left-right --count HEAD...origin/main" 2>/dev/null || echo "? ?")
  ahead=$(echo "$ahead_behind" | awk '{print $1}')
  behind=$(echo "$ahead_behind" | awk '{print $2}')
  if [ "$behind" != "0" ]; then
    head=$($SSH "cd $REMOTE_DIR && git rev-parse --short=12 HEAD")
    main=$($SSH "cd $REMOTE_DIR && git rev-parse --short=12 origin/main")
    die "remote $REMOTE_DIR HEAD is $behind commit(s) behind origin/main:
  HEAD:        $head
  origin/main: $main
The build would silently miss those commits. Step [1/4] will pull, but
this guard fires first so the operator sees the gap."
  fi
  if [ "$ahead" != "0" ]; then
    head=$($SSH "cd $REMOTE_DIR && git rev-parse --short=12 HEAD")
    echo "  WARN: HEAD is $ahead commit(s) AHEAD of origin/main ($head). Local-only commits will be in the binary."
  fi
  dirty=$($SSH "cd $REMOTE_DIR && git status --porcelain | head -1")
  if [ -n "$dirty" ]; then
    die "remote $REMOTE_DIR has uncommitted changes (sample: '$dirty'). Stash or revert before deploying so the build matches a real commit."
  fi
  echo "  OK: on main, in sync with origin, clean working tree."
fi

# Step -0.5: Config schema gate (Wave 9e, 2026-05-04).
#
# Anchors AUDIT-002 ("agent.toml [data_retention] silently ignored"). The
# agent now has #[serde(deny_unknown_fields)] on every nested config struct,
# so an unknown / typo'd key is a LOUD startup error. Catching it here
# (before the build + restart) means the operator sees the typo in the
# deploy log instead of finding their agent in a crashloop after the
# `systemctl start`.
#
# Skipped when source guard is skipped (matching the bypass-everything
# semantics). To intentionally skip just this gate set
# DEPLOY_SKIP_CONFIG_VALIDATE=1 (e.g. when validating against an in-flight
# config that you know has known-warning legacy keys).
echo "[-0.5/4] Config schema gate (validates /etc/innerwarden/agent.toml)..."
if [ "${DEPLOY_SKIP_CONFIG_VALIDATE:-0}" = "1" ] || [ "${DEPLOY_SKIP_SOURCE_GUARD:-0}" = "1" ]; then
  echo "  WARN: DEPLOY_SKIP_CONFIG_VALIDATE=1 set - skipping schema validation."
else
  # `sudo` because /etc/innerwarden/agent.toml is mode 640 (root:innerwarden)
  # on prod hosts that ran `innerwarden setup` — the SSH user (ubuntu) is
  # neither root nor in the `innerwarden` group, so the validator would
  # fail with "config file not found" without sudo. The validator runs
  # the agent binary with --validate-config-only; it does not start any
  # service, so sudo only grants read access to the config file.
  $SSH "sudo $BIN_DIR/innerwarden config validate --path /etc/innerwarden/agent.toml" || die "agent.toml failed strict-schema validation; refusing deploy until the operator fixes the unknown/typo'd keys reported above. To intentionally bypass: DEPLOY_SKIP_CONFIG_VALIDATE=1 ./scripts/deploy-prod.sh"
fi


# Step 0: Pre-deploy cleanup (free disk before pulling/building).
#
# Production deploys have hit "Out of diskspace" during git pull when
# the rootfs creeps to 100% — the agent binary keeps running on whatever
# is in /usr/local/bin, but `cargo build --release` and `git pull`
# both fail. Targets here are CACHE / DEV / OBSOLETE files that the
# running services do not depend on.
#
# Targets and rationale:
#   - jeprof/                 jemalloc heap profiles. Preserved across
#                             deploys (the directory itself is recreated
#                             with proper ownership so jemalloc can keep
#                             writing); dumps older than 7 days are
#                             pruned. Wholesale wipe lost the operator's
#                             pre-deploy baseline during memory work
#                             2026-05-02.
#   - target/release/incremental
#                             cargo's incremental compile cache. Safe
#                             to drop; release builds rebuild it.
#   - graph-snapshot-*.json*  >5 days old (canonical store is SQLite
#                             post-PR-258; JSON snapshots are
#                             redundant). Keep recent ones for the
#                             threats Date picker fallback.
#   - pcap/                   >3 days old. Operator pulls hot pcaps
#                             same-day; older are forensic archive
#                             material that should live elsewhere.
#   - events-*.jsonl*         >7 days old. Canonical events live in
#                             SQLite events table.
#   - incidents-*.jsonl*      >14 days old. Canonical incidents live
#                             in SQLite incidents table; JSONL is the
#                             legacy compat path kept for replay
#                             tooling.
#   - journalctl --vacuum-time=3d
#                             OS-level journald retention.
#   - /tmp                    files >1 day. Build tmp + ad-hoc dumps.
#   - sqlite WAL checkpoint   merge WAL into main DB so big WAL files
#                             do not accumulate during agent uptime.
echo "[0/4] Pre-deploy cleanup (free disk before pulling/building)..."
$SSH 'set -e
  before=$(df -h / | awk "NR==2 {print \$4}")
  echo "  before: $before free on /"
  # Preserve the jeprof directory across deploys so the operator
  # can compare heap profiles pre- and post-binary-update. Recreate
  # with the right ownership in case it disappeared (e.g. fresh box,
  # manual cleanup) and prune dumps older than 7 days.
  sudo mkdir -p /var/lib/innerwarden/jeprof 2>/dev/null || true
  sudo chown innerwarden:innerwarden /var/lib/innerwarden/jeprof 2>/dev/null || true
  sudo chmod 750 /var/lib/innerwarden/jeprof 2>/dev/null || true
  sudo find /var/lib/innerwarden/jeprof -type f -mtime +7 -delete 2>/dev/null || true
  sudo rm -rf /home/ubuntu/innerwarden/target/release/incremental 2>/dev/null || true
  sudo find /var/lib/innerwarden -maxdepth 1 -name "graph-snapshot-*.json*" -mtime +5 -delete 2>/dev/null || true
  if [ -d /var/lib/innerwarden/pcap ]; then
    sudo find /var/lib/innerwarden/pcap -type f -mtime +3 -delete 2>/dev/null || true
  fi
  sudo find /var/lib/innerwarden -maxdepth 1 -name "events-*.jsonl*" -mtime +7 -delete 2>/dev/null || true
  sudo find /var/lib/innerwarden -maxdepth 1 -name "incidents-*.jsonl*" -mtime +14 -delete 2>/dev/null || true
  sudo find /var/lib/innerwarden -maxdepth 1 -name "decisions-*.jsonl*" -mtime +14 -delete 2>/dev/null || true
  sudo find /tmp -type f -mtime +1 -delete 2>/dev/null || true
  sudo journalctl --vacuum-time=3d 2>&1 | tail -1 || true
  sudo sqlite3 /var/lib/innerwarden/innerwarden.db "PRAGMA wal_checkpoint(TRUNCATE);" 2>/dev/null || true
  after=$(df -h / | awk "NR==2 {print \$4}")
  echo "  after:  $after free on /"
'

# Step 1: Pull latest code
echo "[1/4] Pulling latest code..."
$SSH "cd $REMOTE_DIR && git stash -q 2>/dev/null; git pull origin main --ff-only" || die "git pull failed"

# Step 2: Build
build_one() {
  local pkg="$1"
  local features=""
  [ "$pkg" = "innerwarden-sensor" ] && features="--features ebpf"
  [ "$pkg" = "innerwarden-agent" ] && features="--features local-classifier"
  echo "[2/4] Building $pkg..."
  $SSH "source ~/.cargo/env && cd $REMOTE_DIR && cargo build --release -p $pkg $features 2>&1 | tail -1"
}

if [ "$component" = "all" ]; then
  build_one innerwarden-sensor
  build_one innerwarden-agent
  build_one innerwarden-ctl
elif [ "$component" = "ctl" ]; then
  build_one innerwarden-ctl
else
  build_one "innerwarden-$component"
fi

# Step 3: Install + restart
install_one() {
  local pkg="$1"
  local bin="$2"
  local svc="$3"
  echo "[3/4] Installing $bin..."
  if [ -n "$svc" ]; then
    $SSH "sudo systemctl stop $svc 2>/dev/null; sleep 1"
  fi
  $SSH "sudo cp $REMOTE_DIR/target/release/$bin $BIN_DIR/$bin"
  if [ -n "$svc" ]; then
    $SSH "sudo systemctl start $svc && sleep 2 && sudo systemctl is-active $svc"
  fi
}

if [ "$component" = "all" ]; then
  install_one innerwarden-sensor innerwarden-sensor innerwarden-sensor
  install_one innerwarden-agent innerwarden-agent innerwarden-agent
  # CTL binary is innerwarden-ctl in target/ but installed as both names
  $SSH "sudo cp $REMOTE_DIR/target/release/innerwarden-ctl $BIN_DIR/innerwarden-ctl && sudo ln -sf $BIN_DIR/innerwarden-ctl $BIN_DIR/innerwarden" 2>/dev/null
elif [ "$component" = "sensor" ]; then
  install_one innerwarden-sensor innerwarden-sensor innerwarden-sensor
elif [ "$component" = "agent" ]; then
  install_one innerwarden-agent innerwarden-agent innerwarden-agent
elif [ "$component" = "ctl" ]; then
  # CTL binary is innerwarden-ctl in target/ but installed as both names
  $SSH "sudo cp $REMOTE_DIR/target/release/innerwarden-ctl $BIN_DIR/innerwarden-ctl && sudo ln -sf $BIN_DIR/innerwarden-ctl $BIN_DIR/innerwarden" 2>/dev/null
fi

# Step 4: Copy sigma rules if deploying sensor
if [ "$component" = "sensor" ] || [ "$component" = "all" ]; then
  echo "[3/4] Copying Sigma rules..."
  $SSH "sudo mkdir -p /etc/innerwarden/rules && sudo cp -r $REMOTE_DIR/rules/sigma /etc/innerwarden/rules/"
fi

# Verify
echo "[4/4] Verifying..."
if [ "$component" = "ctl" ]; then
  echo "  innerwarden-ctl: installed"
else
  for svc in $([ "$component" = "all" ] && echo "innerwarden-sensor innerwarden-agent" || echo "innerwarden-$component"); do
    status=$($SSH "sudo systemctl is-active $svc" 2>/dev/null || echo "unknown")
    version=$($SSH "$BIN_DIR/$svc --version 2>/dev/null" || echo "?")
    echo "  $svc: $status ($version)"
  done
fi

echo "=== Done ==="
