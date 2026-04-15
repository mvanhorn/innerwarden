#!/usr/bin/env bash
set -euo pipefail

trap 'printf "\nCanceled by user.\n"; exit 130' INT TERM

if ! command -v gum >/dev/null 2>&1; then
  echo "gum is not installed. Run: brew install gum"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAN_DIR="$ROOT_DIR/docs/internal/setup"
mkdir -p "$PLAN_DIR"

TS="$(date +%Y%m%d-%H%M%S)"
PLAN_FILE="$PLAN_DIR/plan-$TS.md"

WIZARD_SIMULATE="${IW_WIZARD_SIMULATE:-0}"
AGENT_CONFIG_PATH="${IW_AGENT_CONFIG_PATH:-/etc/innerwarden/agent.toml}"
AGENT_ENV_PATH="${IW_AGENT_ENV_PATH:-/etc/innerwarden/agent.env}"

CHANNEL_TELEGRAM="Telegram alerts"
CHANNEL_SLACK="Slack alerts"
CHANNEL_WEBHOOK="Webhook alerts"
CHANNEL_DASHBOARD="Dashboard access"

detect_theme() {
  local mode="${IW_WIZARD_THEME:-auto}"
  local bg=""

  if [[ "$mode" == "auto" && -n "${COLORFGBG:-}" ]]; then
    bg="${COLORFGBG##*;}"
    if [[ "$bg" =~ ^[0-9]+$ ]]; then
      if (( bg >= 7 )); then
        mode="light"
      else
        mode="dark"
      fi
    fi
  fi

  if [[ "$mode" != "light" && "$mode" != "dark" ]]; then
    mode="dark"
  fi

  echo "$mode"
}

THEME="$(detect_theme)"
USE_COLOR=1
if [[ -n "${NO_COLOR:-}" ]]; then
  USE_COLOR=0
fi

if [[ "$THEME" == "light" ]]; then
  FG_MAIN=16
  FG_MUTED=238
  FG_ACCENT=20
  FG_OK=22
  FG_WARN=124
  FG_BORDER=20
else
  FG_MAIN=255
  FG_MUTED=250
  FG_ACCENT=81
  FG_OK=84
  FG_WARN=214
  FG_BORDER=81
fi

style_line() {
  local text="$1"
  local color="${2:-}"
  local extra="${3:-}"

  if (( USE_COLOR == 1 )) && [[ -n "$color" ]]; then
    if [[ -n "$extra" ]]; then
      gum style --foreground "$color" "$extra" "$text"
    else
      gum style --foreground "$color" "$text"
    fi
  else
    if [[ -n "$extra" ]]; then
      gum style "$extra" "$text"
    else
      gum style "$text"
    fi
  fi
}

render_header() {
  clear

  if (( USE_COLOR == 1 )); then
    gum style --border rounded --margin "1 2" --padding "1 2" \
      --border-foreground "$FG_BORDER" --foreground "$FG_MAIN" --bold \
$'INNERWARDEN SETUP WIZARD\nInteractive setup configurator (applies system settings).'
  else
    gum style --border rounded --margin "1 2" --padding "1 2" --bold \
$'INNERWARDEN SETUP WIZARD\nInteractive setup configurator (applies system settings).'
  fi
}

trim() {
  printf '%s' "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

read_env_key() {
  local key="$1"
  if [[ ! -f "$AGENT_ENV_PATH" ]]; then
    return 1
  fi

  local raw
  raw="$(awk -v key="$key" -F '=' '$1==key {sub(/^[^=]*=/, "", $0); val=$0} END {if (val != "") print val}' "$AGENT_ENV_PATH")"
  if [[ -z "$raw" ]]; then
    return 1
  fi

  raw="$(trim "$raw")"
  raw="${raw#\"}"
  raw="${raw%\"}"
  printf '%s' "$raw"
}

read_toml_value() {
  local section="$1"
  local key="$2"

  if [[ ! -f "$AGENT_CONFIG_PATH" ]]; then
    return 1
  fi

  awk -v section="$section" -v key="$key" '
    BEGIN { in_section=0 }
    $0 ~ "^[[:space:]]*\\[" section "\\][[:space:]]*$" { in_section=1; next }
    in_section && $0 ~ "^[[:space:]]*\\[" { in_section=0 }
    in_section && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
      line=$0
      sub(/^[^=]*=[[:space:]]*/, "", line)
      sub(/[[:space:]]*#.*/, "", line)
      gsub(/^\"|\"$/, "", line)
      print line
      exit
    }
  ' "$AGENT_CONFIG_PATH"
}

read_toml_bool() {
  local section="$1"
  local key="$2"
  local value

  value="$(read_toml_value "$section" "$key" 2>/dev/null || true)"
  value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  if [[ "$value" == "true" || "$value" == "false" ]]; then
    printf '%s' "$value"
  fi
}

mask_secret() {
  local value="$1"
  local len=${#value}
  if (( len <= 6 )); then
    printf '***'
  else
    printf '%s***%s' "${value:0:3}" "${value: -3}"
  fi
}

selection_has() {
  local option="$1"
  printf '%s\n' "$PROTECTIONS" | grep -Fxq "$option"
}

append_selection() {
  local option="$1"
  if [[ -z "${PROTECTIONS//[$'\n\r\t ']/}" ]]; then
    PROTECTIONS="$option"
  else
    PROTECTIONS+=$'\n'
    PROTECTIONS+="$option"
  fi
}

prompt_required_input() {
  local header="$1"
  local placeholder="$2"
  local password_mode="${3:-false}"
  local value=""
  local trimmed=""

  while true; do
    if [[ "$password_mode" == "true" ]]; then
      if ! value="$(gum input --password --header "$header" --placeholder "$placeholder")"; then
        printf "\nCanceled by user.\n"
        exit 130
      fi
    else
      if ! value="$(gum input --header "$header" --placeholder "$placeholder")"; then
        printf "\nCanceled by user.\n"
        exit 130
      fi
    fi

    trimmed="$(trim "$value")"

    if [[ "$trimmed" == "back" ]]; then
      printf '%s' "__BACK__"
      return 0
    fi

    if [[ -n "$trimmed" ]]; then
      printf '%s' "$trimmed"
      return 0
    fi

    style_line "This field is required. Type a value or 'back' to return." "$FG_WARN"
  done
}

prompt_dashboard_password() {
  local first
  local second

  while true; do
    first="$(prompt_required_input "Dashboard password (min 8 chars)" "Type password" true)"
    if [[ "$first" == "__BACK__" ]]; then
      printf '%s' "__BACK__"
      return 0
    fi

    second="$(prompt_required_input "Confirm dashboard password" "Repeat password" true)"
    if [[ "$second" == "__BACK__" ]]; then
      printf '%s' "__BACK__"
      return 0
    fi

    if (( ${#first} < 8 )); then
      style_line "Dashboard password must have at least 8 characters." "$FG_WARN"
      continue
    fi

    if [[ "$first" != "$second" ]]; then
      style_line "Passwords do not match. Try again." "$FG_WARN"
      continue
    fi

    printf '%s' "$first"
    return 0
  done
}

run_innerwarden_cmd() {
  if [[ "$(id -u)" -eq 0 ]]; then
    innerwarden "$@"
  else
    sudo innerwarden "$@"
  fi
}

apply_step() {
  local label="$1"
  shift

  style_line "\nApplying: ${label}" "$FG_ACCENT"
  if run_innerwarden_cmd "$@"; then
    style_line "[ok] ${label}" "$FG_OK"
    return 0
  fi

  style_line "[fail] ${label}" "$FG_WARN"
  return 1
}

apply_selected_configuration() {
  if [[ "$WIZARD_SIMULATE" == "1" ]]; then
    style_line "\n[SIMULATION] Apply requested, but no system changes were made." "$FG_WARN"
    return 0
  fi

  if ! command -v innerwarden >/dev/null 2>&1; then
    style_line "innerwarden binary not found in PATH." "$FG_WARN"
    return 1
  fi

  if [[ "$(id -u)" -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
    style_line "sudo not found. Cannot apply system configuration." "$FG_WARN"
    return 1
  fi

  if [[ "$(id -u)" -ne 0 ]]; then
    style_line "Sudo may ask for your password to apply configuration." "$FG_MUTED"
    if ! sudo -v; then
      style_line "Unable to acquire sudo credentials." "$FG_WARN"
      return 1
    fi
  fi

  local failures=0

  apply_step "Set notification sensitivity to normal (High + Critical)" configure sensitivity normal || ((failures+=1))
  apply_step "Enable block-ip capability" enable block-ip --yes || ((failures+=1))
  apply_step "Set responder to watch mode (enabled + dry-run)" configure responder --enable --dry-run true || ((failures+=1))

  if [[ "$TELEGRAM_SELECTED" == "true" ]]; then
    apply_step "Configure Telegram channel" notify telegram \
      --token "$TELEGRAM_BOT_TOKEN" \
      --chat-id "$TELEGRAM_CHAT_ID" \
      --no-test || ((failures+=1))
  fi

  if [[ "$SLACK_SELECTED" == "true" ]]; then
    apply_step "Configure Slack channel" notify slack \
      --webhook-url "$SLACK_WEBHOOK_URL" \
      --min-severity high \
      --no-test || ((failures+=1))
  fi

  if [[ "$WEBHOOK_SELECTED" == "true" ]]; then
    apply_step "Configure Webhook channel" notify webhook \
      --url "$WEBHOOK_URL" \
      --min-severity high \
      --no-test || ((failures+=1))
  fi

  if [[ "$DASHBOARD_SELECTED" == "true" ]]; then
    if [[ "$DASHBOARD_ACTION" == "kept existing" ]]; then
      style_line "\nDashboard: existing credentials kept." "$FG_MAIN"
    else
      apply_step "Configure Dashboard credentials" notify dashboard \
        --user "$DASHBOARD_USER" \
        --password "$DASHBOARD_PASSWORD" || ((failures+=1))
    fi
  fi

  if (( failures > 0 )); then
    style_line "\nApplied with ${failures} issue(s). Review errors above." "$FG_WARN"
    return 1
  fi

  style_line "\nConfiguration applied successfully." "$FG_OK" "--bold"
  return 0
}

configure_telegram_channel() {
  local has_existing="false"
  local choice=""

  if [[ -n "$EXISTING_TELEGRAM_BOT_TOKEN" && -n "$EXISTING_TELEGRAM_CHAT_ID" ]]; then
    has_existing="true"
    render_header
    style_line "[1/2] Channels" "$FG_MUTED"
    style_line "Telegram is already configured." "$FG_MUTED"
    style_line "  - Bot token: $(mask_secret "$EXISTING_TELEGRAM_BOT_TOKEN")" "$FG_MUTED"
    style_line "  - Chat ID: ${EXISTING_TELEGRAM_CHAT_ID}" "$FG_MUTED"
    echo ""

    choice="$(gum choose "Keep existing" "Update now" "Back" --header "Telegram configuration")"
    case "$choice" in
      "Keep existing")
        TELEGRAM_BOT_TOKEN="$EXISTING_TELEGRAM_BOT_TOKEN"
        TELEGRAM_CHAT_ID="$EXISTING_TELEGRAM_CHAT_ID"
        TELEGRAM_ACTION="kept existing"
        return 0
        ;;
      "Back")
        return 1
        ;;
    esac
  fi

  TELEGRAM_BOT_TOKEN="$(prompt_required_input "Telegram bot token (from @BotFather)" "123456789:ABC...")"
  if [[ "$TELEGRAM_BOT_TOKEN" == "__BACK__" ]]; then
    return 1
  fi

  while true; do
    TELEGRAM_CHAT_ID="$(prompt_required_input "Telegram chat ID (user: 123..., group: -100...)" "-1001234567890")"
    if [[ "$TELEGRAM_CHAT_ID" == "__BACK__" ]]; then
      return 1
    fi
    if [[ "${TELEGRAM_CHAT_ID#-}" =~ ^[0-9]+$ ]]; then
      break
    fi
    style_line "Telegram chat ID must be numeric (optionally starting with '-')." "$FG_WARN"
  done

  if [[ "$has_existing" == "true" ]]; then
    TELEGRAM_ACTION="updated"
  else
    TELEGRAM_ACTION="configured"
  fi
  return 0
}

configure_slack_channel() {
  local has_existing="false"
  local choice=""

  if [[ -n "$EXISTING_SLACK_WEBHOOK_URL" ]]; then
    has_existing="true"
    render_header
    style_line "[1/2] Channels" "$FG_MUTED"
    style_line "Slack is already configured." "$FG_MUTED"
    style_line "  - Webhook: $(mask_secret "$EXISTING_SLACK_WEBHOOK_URL")" "$FG_MUTED"
    echo ""

    choice="$(gum choose "Keep existing" "Update now" "Back" --header "Slack configuration")"
    case "$choice" in
      "Keep existing")
        SLACK_WEBHOOK_URL="$EXISTING_SLACK_WEBHOOK_URL"
        SLACK_ACTION="kept existing"
        return 0
        ;;
      "Back")
        return 1
        ;;
    esac
  fi

  while true; do
    SLACK_WEBHOOK_URL="$(prompt_required_input "Slack Incoming Webhook URL" "Paste full Slack webhook URL")"
    if [[ "$SLACK_WEBHOOK_URL" == "__BACK__" ]]; then
      return 1
    fi
    if [[ "$SLACK_WEBHOOK_URL" =~ ^https://hooks\.slack\.com/services/ ]]; then
      break
    fi
    style_line "Slack webhook must start with https://hooks.slack.com/services/." "$FG_WARN"
  done

  if [[ "$has_existing" == "true" ]]; then
    SLACK_ACTION="updated"
  else
    SLACK_ACTION="configured"
  fi
  return 0
}

configure_webhook_channel() {
  local has_existing="false"
  local choice=""

  if [[ -n "$EXISTING_WEBHOOK_URL" ]]; then
    has_existing="true"
    render_header
    style_line "[1/2] Channels" "$FG_MUTED"
    style_line "Webhook is already configured." "$FG_MUTED"
    style_line "  - Endpoint: $(mask_secret "$EXISTING_WEBHOOK_URL")" "$FG_MUTED"
    echo ""

    choice="$(gum choose "Keep existing" "Update now" "Back" --header "Webhook configuration")"
    case "$choice" in
      "Keep existing")
        WEBHOOK_URL="$EXISTING_WEBHOOK_URL"
        WEBHOOK_ACTION="kept existing"
        return 0
        ;;
      "Back")
        return 1
        ;;
    esac
  fi

  while true; do
    WEBHOOK_URL="$(prompt_required_input "Webhook URL (required)" "Paste full webhook URL")"
    if [[ "$WEBHOOK_URL" == "__BACK__" ]]; then
      return 1
    fi
    if [[ "$WEBHOOK_URL" =~ ^https?:// ]]; then
      break
    fi
    style_line "Webhook URL must start with http:// or https://." "$FG_WARN"
  done

  if [[ "$has_existing" == "true" ]]; then
    WEBHOOK_ACTION="updated"
  else
    WEBHOOK_ACTION="configured"
  fi
  return 0
}

configure_dashboard_channel() {
  local has_existing="false"
  local choice=""

  if [[ -n "$EXISTING_DASHBOARD_USER" && -n "$EXISTING_DASHBOARD_HASH" ]]; then
    has_existing="true"
    render_header
    style_line "[1/2] Channels" "$FG_MUTED"
    style_line "Dashboard credentials already exist." "$FG_MUTED"
    style_line "  - User: $EXISTING_DASHBOARD_USER" "$FG_MUTED"
    echo ""

    choice="$(gum choose "Keep existing" "Update now" "Back" --header "Dashboard configuration")"
    case "$choice" in
      "Keep existing")
        DASHBOARD_USER="$EXISTING_DASHBOARD_USER"
        DASHBOARD_PASSWORD=""
        DASHBOARD_ACTION="kept existing"
        return 0
        ;;
      "Back")
        return 1
        ;;
    esac
  fi

  local suggested_user="admin"
  if [[ -n "$EXISTING_DASHBOARD_USER" ]]; then
    suggested_user="$EXISTING_DASHBOARD_USER"
  fi

  DASHBOARD_USER="$(prompt_required_input "Dashboard username" "$suggested_user")"
  if [[ "$DASHBOARD_USER" == "__BACK__" ]]; then
    return 1
  fi

  DASHBOARD_PASSWORD="$(prompt_dashboard_password)"
  if [[ "$DASHBOARD_PASSWORD" == "__BACK__" ]]; then
    return 1
  fi

  if [[ "$has_existing" == "true" ]]; then
    DASHBOARD_ACTION="updated"
  else
    DASHBOARD_ACTION="configured"
  fi
  return 0
}

# Existing configuration snapshot (used for keep/update decisions)
EXISTING_TELEGRAM_BOT_TOKEN="$(read_env_key "TELEGRAM_BOT_TOKEN" 2>/dev/null || true)"
EXISTING_TELEGRAM_CHAT_ID="$(read_env_key "TELEGRAM_CHAT_ID" 2>/dev/null || true)"
EXISTING_SLACK_WEBHOOK_URL="$(read_env_key "SLACK_WEBHOOK_URL" 2>/dev/null || true)"
EXISTING_DASHBOARD_USER="$(read_env_key "INNERWARDEN_DASHBOARD_USER" 2>/dev/null || true)"
EXISTING_DASHBOARD_HASH="$(read_env_key "INNERWARDEN_DASHBOARD_PASSWORD_HASH" 2>/dev/null || true)"
EXISTING_WEBHOOK_URL="$(read_toml_value "webhook" "url" 2>/dev/null || true)"

EXISTING_TELEGRAM_ENABLED="$(read_toml_bool "telegram" "enabled" 2>/dev/null || true)"
EXISTING_SLACK_ENABLED="$(read_toml_bool "slack" "enabled" 2>/dev/null || true)"
EXISTING_WEBHOOK_ENABLED="$(read_toml_bool "webhook" "enabled" 2>/dev/null || true)"

EXPERIENCE="Simple"
PROTECTIONS=""
SEVERITY="High + Critical (system default)"
APPLY_MODE=""

TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
SLACK_WEBHOOK_URL=""
WEBHOOK_URL=""
DASHBOARD_USER="$EXISTING_DASHBOARD_USER"
DASHBOARD_PASSWORD=""

TELEGRAM_SELECTED="false"
SLACK_SELECTED="false"
WEBHOOK_SELECTED="false"
DASHBOARD_SELECTED="false"

TELEGRAM_ACTION="not selected"
SLACK_ACTION="not selected"
WEBHOOK_ACTION="not selected"
DASHBOARD_ACTION="not selected"

if [[ -n "$EXISTING_TELEGRAM_BOT_TOKEN" && -n "$EXISTING_TELEGRAM_CHAT_ID" ]] || [[ "$EXISTING_TELEGRAM_ENABLED" == "true" ]]; then
  append_selection "$CHANNEL_TELEGRAM"
fi
if [[ -n "$EXISTING_SLACK_WEBHOOK_URL" ]] || [[ "$EXISTING_SLACK_ENABLED" == "true" ]]; then
  append_selection "$CHANNEL_SLACK"
fi
if [[ -n "$EXISTING_WEBHOOK_URL" ]] || [[ "$EXISTING_WEBHOOK_ENABLED" == "true" ]]; then
  append_selection "$CHANNEL_WEBHOOK"
fi
if [[ -n "$EXISTING_DASHBOARD_USER" && -n "$EXISTING_DASHBOARD_HASH" ]]; then
  append_selection "$CHANNEL_DASHBOARD"
fi

WIZARD_STEP=1

while true; do
  while (( WIZARD_STEP <= 2 )); do
    case "$WIZARD_STEP" in
      1)
        PROTECTIONS_ERROR=""
        while true; do
          render_header
          style_line "[1/2] Interaction Channels" "$FG_MUTED"
          style_line "Progress: step 1 of 2" "$FG_MUTED"
          style_line "Use space to toggle [x]. Enter opens confirmation." "$FG_MUTED"
          style_line "Defaults applied automatically: Block-IP + High/Critical alerts + Watch mode." "$FG_MUTED"
          style_line "Choose where you want to interact with InnerWarden:" "$FG_MUTED"
          style_line "  - Telegram alerts: real-time notifications on your phone." "$FG_MUTED"
          style_line "  - Slack alerts: notifications in your team channel." "$FG_MUTED"
          style_line "  - Webhook alerts: PagerDuty/Opsgenie/custom integrations." "$FG_MUTED"
          style_line "  - Dashboard access: browser UI for status and actions." "$FG_MUTED"
          style_line "If already configured, you'll be able to keep existing values." "$FG_MUTED"
          echo ""

          if [[ -n "$PROTECTIONS_ERROR" ]]; then
            style_line "$PROTECTIONS_ERROR" "$FG_WARN"
          fi

          local_selected_csv=""
          if [[ -n "${PROTECTIONS//[$'\n\r\t ']/}" ]]; then
            local_selected_csv="$(printf '%s\n' "$PROTECTIONS" | sed '/^[[:space:]]*$/d' | paste -sd, -)"
          fi

          CHOOSE_ARGS=(
            --no-limit
            --show-help
            --selected-prefix "[x] "
            --unselected-prefix "[ ] "
            --header "Select interaction channels"
          )
          if [[ -n "$local_selected_csv" ]]; then
            CHOOSE_ARGS+=(--selected="$local_selected_csv")
          fi

          PROTECTIONS="$(gum choose "${CHOOSE_ARGS[@]}" \
            "$CHANNEL_TELEGRAM" \
            "$CHANNEL_SLACK" \
            "$CHANNEL_WEBHOOK" \
            "$CHANNEL_DASHBOARD")"

          if [[ -z "${PROTECTIONS//[$'\n\r\t ']/}" ]]; then
            PROTECTIONS_LIST="  - none"
          else
            PROTECTIONS_LIST="$(printf '%s\n' "$PROTECTIONS" | sed '/^[[:space:]]*$/d' | sed 's/^/  - /')"
          fi

          render_header
          style_line "[1/2] Interaction Channels" "$FG_MUTED"
          style_line "Progress: step 1 of 2" "$FG_MUTED"
          style_line "Selected channels:" "$FG_ACCENT"
          printf "%s\n" "$PROTECTIONS_LIST"
          echo ""

          STEP1_ACTION="$(gum choose "Continue" "Edit selections" --header "Confirm channel selections")"
          if [[ "$STEP1_ACTION" != "Continue" ]]; then
            PROTECTIONS_ERROR="Selection not confirmed. Review and confirm to continue."
            continue
          fi

          if selection_has "$CHANNEL_TELEGRAM"; then
            TELEGRAM_SELECTED="true"
            if ! configure_telegram_channel; then
              PROTECTIONS_ERROR="Telegram setup canceled. Review selections and continue."
              continue
            fi
          else
            TELEGRAM_SELECTED="false"
            TELEGRAM_BOT_TOKEN=""
            TELEGRAM_CHAT_ID=""
            if [[ -n "$EXISTING_TELEGRAM_BOT_TOKEN" && -n "$EXISTING_TELEGRAM_CHAT_ID" ]]; then
              TELEGRAM_ACTION="not selected (kept existing)"
            else
              TELEGRAM_ACTION="not selected"
            fi
          fi

          if selection_has "$CHANNEL_SLACK"; then
            SLACK_SELECTED="true"
            if ! configure_slack_channel; then
              PROTECTIONS_ERROR="Slack setup canceled. Review selections and continue."
              continue
            fi
          else
            SLACK_SELECTED="false"
            SLACK_WEBHOOK_URL=""
            if [[ -n "$EXISTING_SLACK_WEBHOOK_URL" ]]; then
              SLACK_ACTION="not selected (kept existing)"
            else
              SLACK_ACTION="not selected"
            fi
          fi

          if selection_has "$CHANNEL_WEBHOOK"; then
            WEBHOOK_SELECTED="true"
            if ! configure_webhook_channel; then
              PROTECTIONS_ERROR="Webhook setup canceled. Review selections and continue."
              continue
            fi
          else
            WEBHOOK_SELECTED="false"
            WEBHOOK_URL=""
            if [[ -n "$EXISTING_WEBHOOK_URL" ]]; then
              WEBHOOK_ACTION="not selected (kept existing)"
            else
              WEBHOOK_ACTION="not selected"
            fi
          fi

          if selection_has "$CHANNEL_DASHBOARD"; then
            DASHBOARD_SELECTED="true"
            if ! configure_dashboard_channel; then
              PROTECTIONS_ERROR="Dashboard setup canceled. Review selections and continue."
              continue
            fi
          else
            DASHBOARD_SELECTED="false"
            DASHBOARD_PASSWORD=""
            if [[ -n "$EXISTING_DASHBOARD_USER" && -n "$EXISTING_DASHBOARD_HASH" ]]; then
              DASHBOARD_ACTION="not selected (kept existing)"
            else
              DASHBOARD_ACTION="not selected"
            fi
          fi

          WIZARD_STEP=2
          break
        done
        ;;
      2)
        render_header
        style_line "[2/2] Finish" "$FG_MUTED"
        style_line "Progress: step 2 of 2" "$FG_MUTED"
        style_line "The wizard will apply required defaults automatically." "$FG_MUTED"
        style_line "  - Alert threshold: High + Critical" "$FG_MUTED"
        style_line "  - Block-IP: enabled" "$FG_MUTED"
        style_line "  - Responder: watch mode (dry-run)" "$FG_MUTED"
        if [[ "$WIZARD_SIMULATE" == "1" ]]; then
          style_line "Simulation mode: no files/services will be changed." "$FG_MUTED"
        fi
        echo ""

        APPLY_CHOICE="$(gum choose \
          "Review first (recommended)" \
          "Apply immediately" \
          "Back" \
          --header "How do you want to finish?")"

        if [[ "$APPLY_CHOICE" == "Back" ]]; then
          WIZARD_STEP=1
        else
          APPLY_MODE="$APPLY_CHOICE"
          WIZARD_STEP=3
        fi
        ;;
    esac
  done

  PROTECTIONS_CSV="$(printf '%s' "$PROTECTIONS" | tr '\n' ',' | sed 's/,$//')"

  render_header
  style_line "Final review" "$FG_ACCENT" "--bold"
  style_line "Progress: review" "$FG_MUTED"
  style_line "Block-IP: enabled (default)" "$FG_MAIN"
  style_line "Channels: ${PROTECTIONS_CSV:-none}" "$FG_MAIN"
  style_line "Alert threshold: $SEVERITY" "$FG_MAIN"
  style_line "Telegram: $TELEGRAM_ACTION" "$FG_MAIN"
  style_line "Slack: $SLACK_ACTION" "$FG_MAIN"
  style_line "Webhook: $WEBHOOK_ACTION" "$FG_MAIN"
  style_line "Dashboard: $DASHBOARD_ACTION" "$FG_MAIN"
  style_line "Mode: $APPLY_MODE" "$FG_MAIN"
  echo ""

  REVIEW_ACTION="$(gum choose \
    "Save and finish" \
    "Back to finish step" \
    "Back to channels" \
    --header "Confirm setup plan")"

  case "$REVIEW_ACTION" in
    "Save and finish")
      break
      ;;
    "Back to finish step")
      WIZARD_STEP=2
      ;;
    "Back to channels")
      WIZARD_STEP=1
      ;;
  esac
done

style_line "\nSaving plan to: $PLAN_FILE" "$FG_MUTED"

cat > "$PLAN_FILE" <<PLAN
# Setup Session ($TS)

## Context
- Agent config: $AGENT_CONFIG_PATH
- Agent env: $AGENT_ENV_PATH
- Simulation mode: $WIZARD_SIMULATE

## Choices
- Block-IP: enabled (default)
- Channels: ${PROTECTIONS_CSV:-none}
- Alert threshold: $SEVERITY
- Telegram: $TELEGRAM_ACTION
- Slack: $SLACK_ACTION
- Webhook: $WEBHOOK_ACTION
- Dashboard: $DASHBOARD_ACTION
- Mode: $APPLY_MODE

## Next actions
- Validate with: \`innerwarden doctor\`
PLAN

if [[ "$APPLY_MODE" == "Apply immediately" ]]; then
  if apply_selected_configuration; then
    style_line "Plan saved at $PLAN_FILE" "$FG_OK"
  else
    style_line "Plan saved at $PLAN_FILE" "$FG_WARN"
    exit 1
  fi
else
  style_line "Done. Review complete." "$FG_OK"
fi
