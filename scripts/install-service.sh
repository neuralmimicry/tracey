#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: install-service.sh [options]

Install Tracey as a background systemd service on Linux.
The service entrypoint is `tracey-loader`, which supervises and updates the
mutable `tracey` core from the service state directory.
By default, `--scope auto` prefers a boot-time system service and will use
`sudo` for privileged install steps when needed.

Options:
  --scope auto|system|user     `auto` prefers a system service; `user` is opt-in.
  --service-name NAME          Base service name. Default: tracey
  --binary PATH                Alias for --core-binary PATH.
  --core-binary PATH           Source Tracey core binary to install.
  --loader-binary PATH         Source Tracey loader binary to install.
  --install-path PATH          Alias for --loader-install-path PATH.
  --loader-install-path PATH   Destination path for the installed loader binary.
  --core-install-path PATH     Destination path for the installed core binary.
  --config PATH                Config file path to reference from the service.
  --state-dir PATH             Working/state directory for Tracey runtime files.
  --unit-path PATH             Explicit systemd unit path.
  --env-file PATH              Optional EnvironmentFile path for extra overrides.
  --agent-id ID                Stable Tracey agent_id to write when creating config.
  --core-channel MODE          production or development. Auto-detected by default.
  --bootstrap-version VERSION  Optional fallback version for first loader bootstrap.
  --skip-build                 Do not build release binaries when they are missing.
  --skip-start                 Install/enable the service but do not start it.
  --no-supervisor              Deprecated; ignored because tracey-loader always supervises the core.
  --force-config               Overwrite an existing config file.
  --dry-run                    Show planned actions without changing the system.
  -h, --help                   Show this help text.

Examples:
  ./scripts/install-service.sh
  sudo ./scripts/install-service.sh
  ./scripts/install-service.sh --scope user --core-channel development --dry-run
USAGE
}

log() {
  printf '%s\n' "$*"
}

warn() {
  printf 'warning: %s\n' "$*" >&2
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

run() {
  if ((DRY_RUN)); then
    printf '+'
    for arg in "${RUN_PREFIX[@]}" "$@"; do
      printf ' %q' "$arg"
    done
    printf '\n'
    return 0
  fi
  if ((${#RUN_PREFIX[@]})); then
    "${RUN_PREFIX[@]}" "$@"
  else
    "$@"
  fi
}

write_file() {
  local path="$1"
  local mode="$2"
  local content="$3"

  if ((DRY_RUN)); then
    printf '\n>>> %s (mode %s)\n%s\n' "$path" "$mode" "$content"
    return 0
  fi

  local tmp
  local status=0
  tmp=$(mktemp)
  printf '%s\n' "$content" >"$tmp"
  run install -D -m "$mode" "$tmp" "$path" || status=$?
  rm -f "$tmp"
  return "$status"
}

default_agent_id() {
  local host
  host=$(hostname -s 2>/dev/null || hostname 2>/dev/null || printf 'node')
  host=$(printf '%s' "$host" | tr -cs 'A-Za-z0-9._-' '-')
  host=${host#-}
  host=${host%-}
  printf 'tracey-%s' "${host:-node}"
}

require_linux_systemd() {
  [[ "$(uname -s)" == "Linux" ]] || die "this installer currently supports Linux systems only"
  command -v systemctl >/dev/null 2>&1 || die "systemctl is required"
  [[ -d /run/systemd/system ]] || die "systemd runtime was not detected on this host"
}

validate_name() {
  [[ "$UNIT_BASE" =~ ^[A-Za-z0-9_.@-]+$ ]] || die "service name '$UNIT_BASE' contains unsupported characters"
}

validate_path() {
  local label="$1"
  local path="$2"
  [[ "$path" != *$'\n'* ]] || die "$label must not contain newlines"
  [[ "$path" != *[[:space:]]* ]] || die "$label must not contain whitespace: $path"
}

build_release_binaries() {
  log "building release Tracey binaries"
  if ((DRY_RUN)); then
    printf '+ (cd %q && cargo build --release --bin tracey --bin tracey-loader)\n' "$REPO_ROOT"
    return 0
  fi
  (
    cd "$REPO_ROOT"
    cargo build --release --bin tracey --bin tracey-loader
  )
}

ensure_binary_sources() {
  if [[ -n "$CORE_BINARY_SOURCE" ]]; then
    [[ -x "$CORE_BINARY_SOURCE" ]] || die "core binary is not executable: $CORE_BINARY_SOURCE"
  fi
  if [[ -n "$LOADER_BINARY_SOURCE" ]]; then
    [[ -x "$LOADER_BINARY_SOURCE" ]] || die "loader binary is not executable: $LOADER_BINARY_SOURCE"
  fi

  if { [[ -z "$CORE_BINARY_SOURCE" ]] || [[ -z "$LOADER_BINARY_SOURCE" ]]; } \
    && ((BUILD_IF_MISSING)) \
    && command -v cargo >/dev/null 2>&1 \
    && [[ -f "$REPO_ROOT/Cargo.toml" ]] \
    && { [[ ! -x "$REPO_ROOT/target/release/tracey" ]] || [[ ! -x "$REPO_ROOT/target/release/tracey-loader" ]]; }
  then
    build_release_binaries
  fi

  if [[ -z "$CORE_BINARY_SOURCE" ]]; then
    if [[ -x "$REPO_ROOT/target/release/tracey" ]]; then
      CORE_BINARY_SOURCE="$REPO_ROOT/target/release/tracey"
    elif [[ -x "$REPO_ROOT/target/debug/tracey" ]]; then
      CORE_BINARY_SOURCE="$REPO_ROOT/target/debug/tracey"
    elif command -v tracey >/dev/null 2>&1; then
      CORE_BINARY_SOURCE=$(command -v tracey)
    else
      die "could not find a Tracey core binary; pass --core-binary PATH or run from the repo with cargo installed"
    fi
  fi

  if [[ -z "$LOADER_BINARY_SOURCE" ]]; then
    if [[ -x "$REPO_ROOT/target/release/tracey-loader" ]]; then
      LOADER_BINARY_SOURCE="$REPO_ROOT/target/release/tracey-loader"
    elif [[ -x "$REPO_ROOT/target/debug/tracey-loader" ]]; then
      LOADER_BINARY_SOURCE="$REPO_ROOT/target/debug/tracey-loader"
    elif command -v tracey-loader >/dev/null 2>&1; then
      LOADER_BINARY_SOURCE=$(command -v tracey-loader)
    else
      die "could not find a Tracey loader binary; pass --loader-binary PATH or run from the repo with cargo installed"
    fi
  fi

  [[ -x "$CORE_BINARY_SOURCE" ]] || die "core binary is not executable: $CORE_BINARY_SOURCE"
  [[ -x "$LOADER_BINARY_SOURCE" ]] || die "loader binary is not executable: $LOADER_BINARY_SOURCE"
}

resolve_scope() {
  case "$SCOPE" in
    auto)
      SCOPE=system
      ;;
    system|user)
      ;;
    *)
      die "unsupported scope: $SCOPE"
      ;;
  esac

  if [[ "$SCOPE" == "user" ]]; then
    if ! systemctl --user show-environment >/dev/null 2>&1; then
      if ((DRY_RUN)); then
        warn "systemctl --user is not currently available; dry-run continuing"
      else
        die "systemctl --user is not available for this session; use a user login session or install with sudo --scope system"
      fi
    fi
  fi
}

ensure_privileged_access() {
  RUN_PREFIX=()
  if [[ "$SCOPE" != "system" ]] || [[ $(id -u) -eq 0 ]]; then
    return 0
  fi

  command -v sudo >/dev/null 2>&1 || die "system scope requires root or sudo; rerun with sudo or use --scope user"
  RUN_PREFIX=(sudo)

  if ((DRY_RUN)); then
    warn "dry-run assuming sudo for system-scope writes"
    return 0
  fi

  log "system scope selected; requesting sudo for privileged install steps"
  sudo -v || die "sudo authentication failed"
}

service_is_active() {
  local scope="$1"
  local unit="$2"
  if [[ "$scope" == "system" ]]; then
    systemctl is-active --quiet "$unit"
  else
    user_systemctl is-active --quiet "$unit"
  fi
}

service_is_enabled() {
  local scope="$1"
  local unit="$2"
  if [[ "$scope" == "system" ]]; then
    systemctl is-enabled --quiet "$unit"
  else
    user_systemctl is-enabled --quiet "$unit"
  fi
}

user_manager_owner() {
  if [[ $(id -u) -eq 0 ]]; then
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
      printf '%s\n' "$SUDO_USER"
      return 0
    fi
    return 1
  fi

  printf '%s\n' "${USER:-$(id -un)}"
}

user_systemctl() {
  local owner uid runtime_dir bus_addr
  owner=$(user_manager_owner) || return 1
  if [[ $(id -u) -eq 0 ]]; then
    uid=$(id -u "$owner")
    runtime_dir="/run/user/$uid"
    bus_addr="unix:path=${runtime_dir}/bus"
    if command -v runuser >/dev/null 2>&1; then
      env XDG_RUNTIME_DIR="$runtime_dir" DBUS_SESSION_BUS_ADDRESS="$bus_addr" \
        runuser -u "$owner" -- systemctl --user "$@"
    elif command -v sudo >/dev/null 2>&1; then
      env XDG_RUNTIME_DIR="$runtime_dir" DBUS_SESSION_BUS_ADDRESS="$bus_addr" \
        sudo -u "$owner" systemctl --user "$@"
    else
      return 1
    fi
  else
    systemctl --user "$@"
  fi
}

run_user_systemctl() {
  local owner
  local -a cmd
  owner=$(user_manager_owner) || return 1

  if ((DRY_RUN)); then
    if [[ $(id -u) -eq 0 ]]; then
      cmd=(
        env
        "XDG_RUNTIME_DIR=/run/user/$(id -u "$owner")"
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u "$owner")/bus"
        runuser -u "$owner" -- systemctl --user
      )
    else
      cmd=(systemctl --user)
    fi
    printf '+'
    for arg in "${cmd[@]}" "$@"; do
      printf ' %q' "$arg"
    done
    printf '\n'
    return 0
  fi

  user_systemctl "$@"
}

resolve_scope_conflicts() {
  if [[ "$SCOPE" == "system" ]]; then
    if ! user_systemctl show-environment >/dev/null 2>&1; then
      return 0
    fi
    if service_is_active user "$UNIT_NAME" || service_is_enabled user "$UNIT_NAME"; then
      warn "disabling conflicting user service $UNIT_NAME before enabling the system service"
      run_user_systemctl disable --now "$UNIT_NAME"
      run_user_systemctl daemon-reload
    fi
    return 0
  fi

  if service_is_active system "$UNIT_NAME" || service_is_enabled system "$UNIT_NAME"; then
    die "system service '$UNIT_NAME' is already active or enabled; stop it with sudo systemctl disable --now $UNIT_NAME before installing the user service"
  fi
}

resolve_core_channel() {
  if [[ -z "$CORE_CHANNEL" ]]; then
    case "$CORE_BINARY_SOURCE" in
      */target/debug/*|*/debug/tracey)
        CORE_CHANNEL=development
        ;;
      *)
        CORE_CHANNEL=production
        ;;
    esac
  fi

  case "$CORE_CHANNEL" in
    production|development)
      ;;
    *)
      die "unsupported core channel: $CORE_CHANNEL"
      ;;
  esac
}

maybe_detect_bootstrap_version() {
  if [[ -n "$BOOTSTRAP_VERSION" ]] || ((DRY_RUN)); then
    return 0
  fi
  local version
  if version=$("$CORE_BINARY_SOURCE" --version 2>/dev/null); then
    version=${version%%$'\n'*}
    BOOTSTRAP_VERSION=${version//$'\r'/}
  fi
}

resolve_paths() {
  local config_home state_home
  config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
  state_home="${XDG_STATE_HOME:-$HOME/.local/state}"

  case "$SCOPE" in
    system)
      LOADER_INSTALL_PATH="${LOADER_INSTALL_PATH:-/usr/local/bin/tracey-loader}"
      CONFIG_PATH="${CONFIG_PATH:-/etc/tracey/tracey.json}"
      STATE_DIR="${STATE_DIR:-/var/lib/tracey}"
      UNIT_PATH="${UNIT_PATH:-/etc/systemd/system/${UNIT_NAME}}"
      ENV_FILE="${ENV_FILE:-/etc/default/${UNIT_BASE}}"
      WANTED_BY="multi-user.target"
      ;;
    user)
      LOADER_INSTALL_PATH="${LOADER_INSTALL_PATH:-$HOME/.local/bin/tracey-loader}"
      CONFIG_PATH="${CONFIG_PATH:-$config_home/tracey/tracey.json}"
      STATE_DIR="${STATE_DIR:-$state_home/tracey}"
      UNIT_PATH="${UNIT_PATH:-$config_home/systemd/user/${UNIT_NAME}}"
      ENV_FILE="${ENV_FILE:-$config_home/tracey/tracey.env}"
      WANTED_BY="default.target"
      ;;
  esac

  CORE_INSTALL_PATH="${CORE_INSTALL_PATH:-$STATE_DIR/loader/current/tracey-core}"

  validate_path "core binary source" "$CORE_BINARY_SOURCE"
  validate_path "loader binary source" "$LOADER_BINARY_SOURCE"
  validate_path "loader install path" "$LOADER_INSTALL_PATH"
  validate_path "core install path" "$CORE_INSTALL_PATH"
  validate_path "config path" "$CONFIG_PATH"
  validate_path "state dir" "$STATE_DIR"
  validate_path "unit path" "$UNIT_PATH"
  validate_path "env file" "$ENV_FILE"
}

render_config() {
  local bootstrap_block
  bootstrap_block=
  if [[ -n "$BOOTSTRAP_VERSION" ]]; then
    bootstrap_block=$(cat <<CFG
,
    "bootstrap_version": "${BOOTSTRAP_VERSION}"
CFG
)
  fi

  cat <<CFG
{
  "agent_id": "${AGENT_ID}",
  "storage": {
    "log_path": "tracey.log.jsonl"
  },
  "update": {
    "update_dir": "updates",
    "local_channel": "${CORE_CHANNEL}"
  },
  "loader": {
    "enabled": true,
    "state_dir": "loader"${bootstrap_block}
  },
  "prometheus_log_export": {
    "server_url": "http://prometheus.neuralmimicry.ai"
  }
}
CFG
}

render_env_file() {
  cat <<CFG
# Optional environment overrides for ${UNIT_NAME}.
# TRACEY_CONFIG is set in the unit file to ${CONFIG_PATH}
# RUST_LOG=info
# TRACEY_DISCOVERY_SHARED_KEY=rotate-this-key
# TRACEY_UPDATE_SHARED_KEY=rotate-this-key
# TRACEY_UPDATE_LOCAL_CHANNEL=development
CFG
}

render_unit() {
  cat <<CFG
[Unit]
Description=Tracey loader and autonomous anomaly/fault detection core
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
Environment=TRACEY_CONFIG=${CONFIG_PATH}
EnvironmentFile=-${ENV_FILE}
WorkingDirectory=${STATE_DIR}
ExecStart=${LOADER_INSTALL_PATH}
Restart=always
RestartSec=2
LimitNOFILE=65536
NoNewPrivileges=true

[Install]
WantedBy=${WANTED_BY}
CFG
}

install_loader_binary() {
  run mkdir -p "$(dirname "$LOADER_INSTALL_PATH")"
  if [[ "$LOADER_BINARY_SOURCE" == "$LOADER_INSTALL_PATH" ]]; then
    log "loader binary already installed at $LOADER_INSTALL_PATH"
    return
  fi
  run install -D -m 0755 "$LOADER_BINARY_SOURCE" "$LOADER_INSTALL_PATH"
}

install_core_binary() {
  run mkdir -p "$(dirname "$CORE_INSTALL_PATH")"
  if [[ "$CORE_BINARY_SOURCE" == "$CORE_INSTALL_PATH" ]]; then
    log "core binary already installed at $CORE_INSTALL_PATH"
    return
  fi
  run install -D -m 0755 "$CORE_BINARY_SOURCE" "$CORE_INSTALL_PATH"
}

maybe_write_config() {
  local content
  content=$(render_config)
  if [[ -e "$CONFIG_PATH" && "$FORCE_CONFIG" -eq 0 ]]; then
    log "keeping existing config: $CONFIG_PATH"
    return
  fi
  write_file "$CONFIG_PATH" 0644 "$content"
}

maybe_write_env_file() {
  local content
  content=$(render_env_file)
  if [[ -e "$ENV_FILE" ]]; then
    log "keeping existing environment file: $ENV_FILE"
    return
  fi
  write_file "$ENV_FILE" 0644 "$content"
}

write_unit() {
  local content
  content=$(render_unit)
  write_file "$UNIT_PATH" 0644 "$content"
}

enable_service() {
  if [[ "$SCOPE" == "system" ]]; then
    run systemctl daemon-reload
    run systemctl enable "$UNIT_NAME"
    if ((START_SERVICE)); then
      run systemctl restart "$UNIT_NAME"
    fi
  else
    run systemctl --user daemon-reload
    run systemctl --user enable "$UNIT_NAME"
    if ((START_SERVICE)); then
      run systemctl --user restart "$UNIT_NAME"
    fi
  fi
}

print_summary() {
  log
  log "Tracey service installation plan:"
  log "  scope:          $SCOPE"
  log "  service:        $UNIT_NAME"
  log "  loader source:  $LOADER_BINARY_SOURCE"
  log "  core source:    $CORE_BINARY_SOURCE"
  log "  loader path:    $LOADER_INSTALL_PATH"
  log "  core path:      $CORE_INSTALL_PATH"
  log "  config:         $CONFIG_PATH"
  log "  state dir:      $STATE_DIR"
  log "  unit:           $UNIT_PATH"
  log "  env file:       $ENV_FILE"
  log "  agent_id:       $AGENT_ID"
  log "  core channel:   $CORE_CHANNEL"
  if [[ -n "$BOOTSTRAP_VERSION" ]]; then
    log "  core version:   $BOOTSTRAP_VERSION"
  fi
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

SCOPE=auto
SERVICE_NAME=tracey
CORE_BINARY_SOURCE=
LOADER_BINARY_SOURCE=
LOADER_INSTALL_PATH=
CORE_INSTALL_PATH=
CONFIG_PATH=
STATE_DIR=
UNIT_PATH=
ENV_FILE=
AGENT_ID=
CORE_CHANNEL=
BOOTSTRAP_VERSION=
BUILD_IF_MISSING=1
START_SERVICE=1
FORCE_CONFIG=0
DRY_RUN=0
WANTED_BY=
SUPERVISOR_REQUESTED=1
RUN_PREFIX=()

while (($#)); do
  case "$1" in
    --scope)
      shift
      (($#)) || die "--scope requires a value"
      SCOPE="$1"
      ;;
    --service-name)
      shift
      (($#)) || die "--service-name requires a value"
      SERVICE_NAME="$1"
      ;;
    --binary|--core-binary)
      shift
      (($#)) || die "--core-binary requires a value"
      CORE_BINARY_SOURCE="$1"
      ;;
    --loader-binary)
      shift
      (($#)) || die "--loader-binary requires a value"
      LOADER_BINARY_SOURCE="$1"
      ;;
    --install-path|--loader-install-path)
      shift
      (($#)) || die "--loader-install-path requires a value"
      LOADER_INSTALL_PATH="$1"
      ;;
    --core-install-path)
      shift
      (($#)) || die "--core-install-path requires a value"
      CORE_INSTALL_PATH="$1"
      ;;
    --config)
      shift
      (($#)) || die "--config requires a value"
      CONFIG_PATH="$1"
      ;;
    --state-dir)
      shift
      (($#)) || die "--state-dir requires a value"
      STATE_DIR="$1"
      ;;
    --unit-path)
      shift
      (($#)) || die "--unit-path requires a value"
      UNIT_PATH="$1"
      ;;
    --env-file)
      shift
      (($#)) || die "--env-file requires a value"
      ENV_FILE="$1"
      ;;
    --agent-id)
      shift
      (($#)) || die "--agent-id requires a value"
      AGENT_ID="$1"
      ;;
    --core-channel)
      shift
      (($#)) || die "--core-channel requires a value"
      CORE_CHANNEL="$1"
      ;;
    --bootstrap-version)
      shift
      (($#)) || die "--bootstrap-version requires a value"
      BOOTSTRAP_VERSION="$1"
      ;;
    --skip-build)
      BUILD_IF_MISSING=0
      ;;
    --skip-start)
      START_SERVICE=0
      ;;
    --no-supervisor)
      SUPERVISOR_REQUESTED=0
      ;;
    --force-config)
      FORCE_CONFIG=1
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
    --system)
      SCOPE=system
      ;;
    --user)
      SCOPE=user
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
  shift
done

UNIT_BASE="${SERVICE_NAME%.service}"
UNIT_NAME="${UNIT_BASE}.service"

validate_name
require_linux_systemd
resolve_scope

if [[ -z "$AGENT_ID" ]]; then
  AGENT_ID=$(default_agent_id)
fi

ensure_binary_sources
resolve_core_channel
maybe_detect_bootstrap_version
resolve_paths
print_summary
ensure_privileged_access
resolve_scope_conflicts

run mkdir -p "$STATE_DIR"
install_loader_binary
install_core_binary
maybe_write_config
maybe_write_env_file
write_unit
enable_service

if (( ! SUPERVISOR_REQUESTED )); then
  warn "--no-supervisor is ignored; tracey-loader is always the supervising service entrypoint"
fi

if [[ "$SCOPE" == "user" ]]; then
  if command -v loginctl >/dev/null 2>&1; then
    linger=$(loginctl show-user "$USER" -p Linger --value 2>/dev/null || true)
    if [[ "$linger" != "yes" ]]; then
      warn "user lingering is disabled; enable it with: sudo loginctl enable-linger $USER"
    fi
  fi
fi

log
if ((DRY_RUN)); then
  log "dry-run complete"
else
  log "service installed: $UNIT_NAME"
  if ((START_SERVICE)); then
    if [[ "$SCOPE" == "system" ]]; then
      log "check status with: systemctl status $UNIT_NAME"
    else
      log "check status with: systemctl --user status $UNIT_NAME"
    fi
  fi
fi
