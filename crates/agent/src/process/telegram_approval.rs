use std::path::Path;

use crate::{
    bot_actions::{handle_pending_confirmation, handle_telegram_action_callback},
    bot_commands::handle_telegram_bot_command,
    bot_helpers, config, telegram, AgentState,
};

// ---------------------------------------------------------------------------
// Telegram T.2 approval handler
// ---------------------------------------------------------------------------

/// Process a single operator approval result received from the Telegram polling task.
/// Resolves and executes (or discards) the pending confirmation, writes an audit entry,
/// and informs the operator via Telegram of the outcome.
pub(crate) async fn process_telegram_approval(
    result: telegram::ApprovalResult,
    data_dir: &Path,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) {
    // 2FA: intercept TOTP code responses before any other handler
    if bot_helpers::handle_totp_response(&result, data_dir, cfg, state) {
        return;
    }

    if handle_telegram_bot_command(&result, data_dir, cfg, state).await {
        return;
    }

    if bot_helpers::handle_telegram_triage_action(&result, data_dir, cfg, state) {
        return;
    }

    if handle_telegram_action_callback(&result, data_dir, cfg, state).await {
        return;
    }

    let _ = handle_pending_confirmation(&result, data_dir, cfg, state).await;
}
