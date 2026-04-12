// ── D3 - action state ─────────────────────────────────────────────────
let actionCfg = null;
let pendingAction = null; // { type: 'block_ip'|'suspend_user', ip, user }
// Sentinel set to true only after /api/action/config has been loaded
// at boot. Diagnostic for spec 017 — distinguishes "allowlist loaded
// and genuinely empty" from "allowlist never loaded" (both show
// length === 0 but mean very different things).
var _allowlistLoaded = false;

async function loadActionConfig() {
  try {
    actionCfg = await loadJson('/api/action/config');
    _trustedIps = actionCfg.trusted_ips || [];
    _trustedUsers = actionCfg.trusted_users || [];
    _allowlistLoaded = true;
    const badge = document.getElementById('modeBadge');
    const aiBadge = document.getElementById('aiBadge');
    // Mode badge
    if (badge) {
      if (actionCfg.enabled) {
        if (actionCfg.dry_run) {
          badge.textContent = '👁 WATCHING';
          badge.className = 'status-badge status-badge-watch';
        } else {
          badge.textContent = '🛡 PROTECTED';
          badge.className = 'status-badge status-badge-guard';
        }
      } else {
        badge.textContent = '📖 MONITOR';
        badge.className = 'status-badge status-badge-read';
      }
    }
    // AI badge
    if (aiBadge) {
      if (actionCfg.ai_enabled) {
        const label = actionCfg.ai_provider === 'anthropic' ? 'claude' :
                      actionCfg.ai_provider === 'ollama'    ? 'ollama' : 'openai';
        aiBadge.textContent = '🤖 ' + label;
        aiBadge.className = 'status-badge status-badge-ai-on';
      } else {
        aiBadge.textContent = 'AI: off';
        aiBadge.className = 'status-badge status-badge-ai-off';
      }
    }
    // Version badge
    const vBadge = document.getElementById('versionBadge');
    if (vBadge && actionCfg.version) {
      vBadge.textContent = 'v' + actionCfg.version;
    }
  } catch (_) {
    actionCfg = null;
  }
}

function showActionModal(type, ip, user) {
  if (!actionCfg || !actionCfg.enabled) return;
  pendingAction = { type, ip, user };
  const modal = document.getElementById('actionModal');
  const drLabel = actionCfg.dry_run
    ? '<span class="dry-run-badge on">DRY RUN</span>'
    : '<span class="dry-run-badge off">LIVE</span>';

  if (type === 'block_ip') {
    document.getElementById('modalTitle').innerHTML =
      'Block IP: <span style="font-family:\'JetBrains Mono\',monospace">' + esc(ip) + '</span>' + drLabel;
    document.getElementById('modalSubtitle').textContent =
      'Executes ' + esc(actionCfg.block_backend) + ' deny rule. Logged to the audit trail.';
    document.getElementById('modalDurationField').style.display = 'none';
    document.getElementById('modalConfirm').textContent = actionCfg.dry_run ? 'Simulate Block' : 'Block IP';
  } else {
    document.getElementById('modalTitle').innerHTML =
      'Suspend sudo: <span style="font-family:\'JetBrains Mono\',monospace">' + esc(user) + '</span>' + drLabel;
    document.getElementById('modalSubtitle').textContent =
      'Temporarily revokes sudo access for the specified duration. Logged to the audit trail.';
    document.getElementById('modalDurationField').style.display = 'block';
    document.getElementById('modalConfirm').textContent = actionCfg.dry_run ? 'Simulate Suspend' : 'Suspend User';
  }

  document.getElementById('modalReason').value = '';
  document.getElementById('modalReason').style.borderColor = '';
  modal.classList.add('open');
  setTimeout(() => document.getElementById('modalReason').focus(), 60);
}

function closeActionModal() {
  document.getElementById('actionModal').classList.remove('open');
  pendingAction = null;
}

function handleModalBg(ev) {
  if (ev.target === document.getElementById('actionModal')) closeActionModal();
}

async function submitAction() {
  if (!pendingAction) return;
  const reason = document.getElementById('modalReason').value.trim();
  if (!reason) {
    document.getElementById('modalReason').style.borderColor = 'var(--danger)';
    document.getElementById('modalReason').focus();
    return;
  }
  document.getElementById('modalReason').style.borderColor = '';
  const confirmBtn = document.getElementById('modalConfirm');
  confirmBtn.disabled = true;
  confirmBtn.textContent = 'Working…';
  try {
    let url, body;
    if (pendingAction.type === 'block_ip') {
      url = '/api/action/block-ip';
      body = JSON.stringify({ ip: pendingAction.ip, reason });
    } else {
      const duration_secs = parseInt(
        document.getElementById('modalDuration').value || '3600', 10
      );
      url = '/api/action/suspend-user';
      body = JSON.stringify({ user: pendingAction.user, reason, duration_secs });
    }
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      cache: 'no-store',
    });
    const data = await resp.json();
    closeActionModal();
    if (data.success) {
      showToast((data.dry_run ? '[DRY RUN] ' : '') + data.message, 'ok');
      await refreshLeft(state.selected.value !== null);
    } else {
      showToast('Error: ' + data.message, 'err');
    }
  } catch (e) {
    showToast('Request failed: ' + e.message, 'err');
  } finally {
    confirmBtn.disabled = false;
  }
}

function showToast(msg, type) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.className = 'toast ' + (type || 'ok') + ' visible';
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => toast.classList.remove('visible'), 4500);
}

function copyCmd(cmd) {
  navigator.clipboard.writeText(cmd).then(() => {
    showToast('Copied: ' + cmd, 'ok');
  }).catch(() => {
    showToast('Command: ' + cmd, 'ok');
  });
}
