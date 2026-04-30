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

# Step 0: Pre-deploy cleanup (free disk before pulling/building).
#
# Production deploys have hit "Out of diskspace" during git pull when
# the rootfs creeps to 100% — the agent binary keeps running on whatever
# is in /usr/local/bin, but `cargo build --release` and `git pull`
# both fail. Targets here are CACHE / DEV / OBSOLETE files that the
# running services do not depend on.
#
# Targets and rationale:
#   - jeprof/                 jemalloc heap profiles, dev-only.
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
  sudo rm -rf /var/lib/innerwarden/jeprof 2>/dev/null || true
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
