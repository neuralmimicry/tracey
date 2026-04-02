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
  --cli-install-path PATH      Destination path for the user-invocable `tracey` command.
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
  --skip-build                 Do not build release binaries when missing or older than source version.
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

run_capture() {
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

read_loader_state_dir_from_config() {
  local path="$1"
  [[ -r "$path" ]] || return 0
  sed -n 's/.*"state_dir"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$path" | head -n 1
}

extract_host_from_socket_addr() {
  local addr="$1"
  if [[ "$addr" =~ ^\[([^]]+)\]:[0-9]+$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
  elif [[ "$addr" == *:* ]]; then
    printf '%s\n' "${addr%:*}"
  else
    printf '%s\n' "$addr"
  fi
}

extract_port_from_socket_addr() {
  local addr="$1"
  local port
  if [[ "$addr" =~ ^\[[^]]+\]:([0-9]+)$ ]]; then
    port="${BASH_REMATCH[1]}"
  elif [[ "$addr" =~ :([0-9]+)$ ]]; then
    port="${BASH_REMATCH[1]}"
  else
    return 1
  fi
  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  ((port >= 1 && port <= 65535)) || return 1
  printf '%s\n' "$port"
}

is_loopback_socket_addr() {
  local host
  host=$(extract_host_from_socket_addr "$1")
  case "${host,,}" in
    127.*|localhost|::1|0:0:0:0:0:0:0:1|::ffff:127.*)
      return 0
      ;;
  esac
  return 1
}

can_manage_firewall() {
  [[ $(id -u) -eq 0 || ${#RUN_PREFIX[@]} -gt 0 ]]
}

read_status_settings_from_config() {
  local path="$1"
  [[ -r "$path" ]] || return 0

  if command -v python3 >/dev/null 2>&1; then
    local line key value
    while IFS= read -r line; do
      key="${line%%=*}"
      value="${line#*=}"
      case "$key" in
        enabled)
          if [[ "$value" == "false" ]]; then
            STATUS_ENABLED=0
          else
            STATUS_ENABLED=1
          fi
          ;;
        listen_addr)
          STATUS_LISTEN_ADDR="$value"
          ;;
      esac
    done < <(
      python3 - "$path" <<'PY'
import json
import sys

path = sys.argv[1]
data = json.load(open(path, "r", encoding="utf-8"))
status = data.get("status")
enabled = True
listen_addr = "0.0.0.0:48000"

if isinstance(status, dict):
    if "enabled" in status:
        enabled = bool(status["enabled"])
    if isinstance(status.get("listen_addr"), str):
        listen_addr = status["listen_addr"].strip()

print(f"enabled={'true' if enabled else 'false'}")
print(f"listen_addr={listen_addr}")
PY
    )
    return 0
  fi

  local status_block listen_addr
  status_block=$(sed -n '/"status"[[:space:]]*:[[:space:]]*{/,/^[[:space:]]*}/p' "$path" || true)
  [[ -n "$status_block" ]] || return 0

  if printf '%s\n' "$status_block" | grep -Eq '"enabled"[[:space:]]*:[[:space:]]*false'; then
    STATUS_ENABLED=0
  fi
  listen_addr=$(printf '%s\n' "$status_block" \
    | sed -n 's/.*"listen_addr"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n 1)
  if [[ -n "$listen_addr" ]]; then
    STATUS_LISTEN_ADDR="$listen_addr"
  fi
}

resolve_status_firewall_target() {
  STATUS_ENABLED=1
  STATUS_LISTEN_ADDR="0.0.0.0:48000"
  STATUS_FIREWALL_PORT=
  FIREWALL_MANAGER=
  FIREWALL_STATUS="not required"

  if [[ -e "$CONFIG_PATH" && "$FORCE_CONFIG" -eq 0 ]]; then
    read_status_settings_from_config "$CONFIG_PATH"
  fi

  if (( ! STATUS_ENABLED )) || [[ -z "$STATUS_LISTEN_ADDR" ]]; then
    FIREWALL_STATUS="not required (status API disabled)"
    return 0
  fi

  if is_loopback_socket_addr "$STATUS_LISTEN_ADDR"; then
    FIREWALL_STATUS="not required (status API bound to $STATUS_LISTEN_ADDR)"
    return 0
  fi

  if ! STATUS_FIREWALL_PORT=$(extract_port_from_socket_addr "$STATUS_LISTEN_ADDR"); then
    FIREWALL_STATUS="manual check required (unable to parse $STATUS_LISTEN_ADDR)"
    warn "could not determine a firewall port from status.listen_addr=$STATUS_LISTEN_ADDR"
    return 0
  fi

  FIREWALL_STATUS="pending tcp/$STATUS_FIREWALL_PORT"
}

ensure_status_firewall_access() {
  [[ -n "$STATUS_FIREWALL_PORT" ]] || return 0

  if ((DRY_RUN)); then
    FIREWALL_STATUS="dry-run (would ensure tcp/$STATUS_FIREWALL_PORT is allowed)"
    return 0
  fi

  if command -v ufw >/dev/null 2>&1; then
    local ufw_status
    ufw_status=$(run_capture ufw status 2>/dev/null || true)
    if [[ "$ufw_status" == "Status: active"* ]]; then
      FIREWALL_MANAGER="ufw"
      if ! can_manage_firewall; then
        FIREWALL_STATUS="manual action required for ufw (tcp/$STATUS_FIREWALL_PORT)"
        warn "ufw is active but this install is not running with privileges to open tcp/$STATUS_FIREWALL_PORT"
        return 0
      fi
      if printf '%s\n' "$ufw_status" | grep -Eq "(^|[[:space:]])${STATUS_FIREWALL_PORT}/tcp([[:space:]]|$)"; then
        FIREWALL_STATUS="allowed via ufw (already present)"
        return 0
      fi
      log "opening ufw for Tracey status API on tcp/$STATUS_FIREWALL_PORT"
      if run ufw allow "${STATUS_FIREWALL_PORT}/tcp" comment "Tracey status API"; then
        FIREWALL_STATUS="allowed via ufw"
      else
        FIREWALL_STATUS="manual action required for ufw (tcp/$STATUS_FIREWALL_PORT)"
        warn "failed to open ufw for tcp/$STATUS_FIREWALL_PORT; allow it manually"
      fi
      return 0
    fi
  fi

  if command -v firewall-cmd >/dev/null 2>&1 \
    && run_capture firewall-cmd --state >/dev/null 2>&1
  then
    local runtime_allowed=0
    local permanent_allowed=0
    local firewalld_failed=0

    FIREWALL_MANAGER="firewalld"
    if ! can_manage_firewall; then
      FIREWALL_STATUS="manual action required for firewalld (tcp/$STATUS_FIREWALL_PORT)"
      warn "firewalld is active but this install is not running with privileges to open tcp/$STATUS_FIREWALL_PORT"
      return 0
    fi
    if run_capture firewall-cmd --quiet --query-port="${STATUS_FIREWALL_PORT}/tcp"; then
      runtime_allowed=1
    fi
    if run_capture firewall-cmd --quiet --permanent --query-port="${STATUS_FIREWALL_PORT}/tcp"; then
      permanent_allowed=1
    fi
    if ((runtime_allowed && permanent_allowed)); then
      FIREWALL_STATUS="allowed via firewalld (already present)"
      return 0
    fi

    log "opening firewalld for Tracey status API on tcp/$STATUS_FIREWALL_PORT"
    if (( ! runtime_allowed )) \
      && ! run firewall-cmd --add-port="${STATUS_FIREWALL_PORT}/tcp"
    then
      firewalld_failed=1
    fi
    if (( ! permanent_allowed )) \
      && ! run firewall-cmd --permanent --add-port="${STATUS_FIREWALL_PORT}/tcp"
    then
      firewalld_failed=1
    fi

    if (( firewalld_failed )); then
      FIREWALL_STATUS="manual action required for firewalld (tcp/$STATUS_FIREWALL_PORT)"
      warn "failed to open firewalld for tcp/$STATUS_FIREWALL_PORT; allow it manually"
    else
      FIREWALL_STATUS="allowed via firewalld"
    fi
    return 0
  fi

  if systemctl is-active --quiet nftables 2>/dev/null; then
    FIREWALL_MANAGER="nftables"
    FIREWALL_STATUS="manual action required for nftables (tcp/$STATUS_FIREWALL_PORT)"
    warn "nftables appears active; allow tcp/$STATUS_FIREWALL_PORT manually for status.listen_addr=$STATUS_LISTEN_ADDR"
    return 0
  fi

  FIREWALL_MANAGER="none"
  FIREWALL_STATUS="no active supported firewall detected for tcp/$STATUS_FIREWALL_PORT"
}

build_release_binaries() {
  log "building release Tracey binaries"
  RELEASE_BUILD_PLANNED=1
  local build_cmd
  printf -v build_cmd 'cd %q && cargo build --release --bin tracey --bin tracey-loader' "$REPO_ROOT"
  if ((DRY_RUN)); then
    if [[ -n "$BUILD_AS_USER" ]]; then
      printf '+ sudo -u %q -H bash -lc %q\n' "$BUILD_AS_USER" "$build_cmd"
    else
      printf '+ bash -lc %q\n' "$build_cmd"
    fi
    return 0
  fi
  if [[ -n "$BUILD_AS_USER" ]]; then
    sudo -u "$BUILD_AS_USER" -H bash -lc "$build_cmd"
  else
    (
      cd "$REPO_ROOT"
      cargo build --release --bin tracey --bin tracey-loader
    )
  fi
}

resolve_build_user() {
  if [[ $(id -u) -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    printf '%s\n' "$SUDO_USER"
  fi
}

read_source_release_version() {
  local cargo_toml="$REPO_ROOT/Cargo.toml"
  [[ -r "$cargo_toml" ]] || return 1
  sed -n '/^\[package\]/,/^\[/ s/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
    "$cargo_toml" \
    | head -n 1
}

version_component_or_default() {
  local value="$1"
  local fallback="$2"
  if [[ "$value" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$value"
  else
    printf '%s\n' "$fallback"
  fi
}

read_binary_version() {
  local path="$1"
  [[ -x "$path" ]] || return 1
  local version
  version=$("$path" --version 2>/dev/null) || return 1
  version=${version%%$'\n'*}
  version=${version//$'\r'/}
  [[ -n "$version" ]] || return 1
  printf '%s\n' "$version"
}

version_numbers() {
  printf '%s\n' "$1" | tr -cs '0-9' ' '
}

env_first() {
  local name value
  for name in "$@"; do
    value="${!name:-}"
    value=${value//$'\r'/}
    value=${value#"${value%%[![:space:]]*}"}
    value=${value%"${value##*[![:space:]]}"}
    if [[ -n "$value" ]]; then
      printf '%s\n' "$value"
      return 0
    fi
  done
  return 1
}

read_source_build_version() {
  local explicit_version release_version numbers
  local major minor build_number
  local -a parts=()

  if explicit_version=$(env_first TRACEY_VERSION); then
    if [[ "$explicit_version" =~ ^[0-9]+\.[0-9]+\.[0-9]{4,}$ ]]; then
      printf '%s\n' "$explicit_version"
      return 0
    fi
  fi

  release_version=$(read_source_release_version || true)
  read -r -a parts <<<"$(version_numbers "$release_version")"
  major=$(version_component_or_default "${TRACEY_VERSION_MAJOR:-${parts[0]:-}}" 0)
  minor=$(version_component_or_default "${TRACEY_VERSION_MINOR:-${parts[1]:-}}" 1)

  if build_number=$(env_first TRACEY_BUILD_NUMBER BUILD_NUMBER); then
    build_number=$(version_component_or_default "$build_number" 0)
  elif build_number=$(git -C "$REPO_ROOT" rev-list --count HEAD 2>/dev/null); then
    build_number=$(version_component_or_default "$build_number" 0)
  else
    build_number=0
  fi

  printf '%s.%s.%04d\n' "$major" "$minor" "$((10#$build_number))"
}

compare_versions() {
  local left="$1"
  local right="$2"
  local -a left_nums=()
  local -a right_nums=()
  local max_len=0
  local idx left_part right_part

  read -r -a left_nums <<<"$(version_numbers "$left")"
  read -r -a right_nums <<<"$(version_numbers "$right")"

  max_len=${#left_nums[@]}
  if ((${#right_nums[@]} > max_len)); then
    max_len=${#right_nums[@]}
  fi

  if ((max_len > 0)); then
    for ((idx = 0; idx < max_len; idx++)); do
      left_part=${left_nums[idx]:-0}
      right_part=${right_nums[idx]:-0}
      if ((10#$left_part > 10#$right_part)); then
        printf '1\n'
        return 0
      fi
      if ((10#$left_part < 10#$right_part)); then
        printf '%s\n' '-1'
        return 0
      fi
    done
  fi

  if [[ "$left" > "$right" ]]; then
    printf '1\n'
  elif [[ "$left" < "$right" ]]; then
    printf '%s\n' '-1'
  else
    printf '0\n'
  fi
}

release_rebuild_reason_for_source_version() {
  local source_version="$1"
  local release_core="$REPO_ROOT/target/release/tracey"
  local release_loader="$REPO_ROOT/target/release/tracey-loader"
  local core_version loader_version cmp
  local -a reasons=()
  local joined

  [[ -n "$source_version" ]] || return 1
  [[ -x "$release_core" && -x "$release_loader" ]] || return 1

  if ! core_version=$(read_binary_version "$release_core"); then
    reasons+=("could not read release core version from $release_core")
  else
    cmp=$(compare_versions "$source_version" "$core_version")
    if ((cmp > 0)); then
      reasons+=("source version $source_version is newer than release core $core_version")
    fi
  fi

  if ! loader_version=$(read_binary_version "$release_loader"); then
    reasons+=("could not read release loader version from $release_loader")
  else
    cmp=$(compare_versions "$source_version" "$loader_version")
    if ((cmp > 0)); then
      reasons+=("source version $source_version is newer than release loader $loader_version")
    fi
  fi

  ((${#reasons[@]})) || return 1
  joined=$(printf '%s; ' "${reasons[@]}")
  joined=${joined%; }
  printf '%s\n' "$joined"
}

ensure_binary_sources() {
  local release_core="$REPO_ROOT/target/release/tracey"
  local release_loader="$REPO_ROOT/target/release/tracey-loader"
  local rebuild_reason=

  if [[ -n "$CORE_BINARY_SOURCE" ]]; then
    [[ -x "$CORE_BINARY_SOURCE" ]] || die "core binary is not executable: $CORE_BINARY_SOURCE"
  fi
  if [[ -n "$LOADER_BINARY_SOURCE" ]]; then
    [[ -x "$LOADER_BINARY_SOURCE" ]] || die "loader binary is not executable: $LOADER_BINARY_SOURCE"
  fi

  if { [[ -z "$CORE_BINARY_SOURCE" ]] || [[ -z "$LOADER_BINARY_SOURCE" ]]; } \
    && [[ -f "$REPO_ROOT/Cargo.toml" ]]
  then
    SOURCE_VERSION=$(read_source_build_version || true)
    rebuild_reason=$(release_rebuild_reason_for_source_version "$SOURCE_VERSION" || true)
    if [[ -n "$rebuild_reason" ]]; then
      if ((BUILD_IF_MISSING)); then
        command -v cargo >/dev/null 2>&1 \
          || die "$rebuild_reason but cargo is unavailable; install Cargo, pass explicit binaries, or use --skip-build to override"
        RELEASE_BUILD_STATUS="rebuilding release binaries ($rebuild_reason)"
        build_release_binaries
      else
        RELEASE_BUILD_STATUS="skipped release rebuild ($rebuild_reason)"
        warn "$RELEASE_BUILD_STATUS"
      fi
    fi
  fi

  if { [[ -z "$CORE_BINARY_SOURCE" ]] || [[ -z "$LOADER_BINARY_SOURCE" ]]; } \
    && ((BUILD_IF_MISSING)) \
    && command -v cargo >/dev/null 2>&1 \
    && [[ -f "$REPO_ROOT/Cargo.toml" ]] \
    && { [[ ! -x "$release_core" ]] || [[ ! -x "$release_loader" ]]; }
  then
    if [[ -z "$RELEASE_BUILD_STATUS" ]]; then
      RELEASE_BUILD_STATUS="rebuilding release binaries (missing release artifacts)"
    fi
    build_release_binaries
  fi

  if [[ -z "$CORE_BINARY_SOURCE" ]]; then
    if [[ -x "$release_core" || "$RELEASE_BUILD_PLANNED" -eq 1 ]]; then
      CORE_BINARY_SOURCE="$release_core"
    elif [[ -x "$REPO_ROOT/target/debug/tracey" ]]; then
      CORE_BINARY_SOURCE="$REPO_ROOT/target/debug/tracey"
    elif command -v tracey >/dev/null 2>&1; then
      CORE_BINARY_SOURCE=$(command -v tracey)
    else
      die "could not find a Tracey core binary; pass --core-binary PATH or run from the repo with cargo installed"
    fi
  fi

  if [[ -z "$LOADER_BINARY_SOURCE" ]]; then
    if [[ -x "$release_loader" || "$RELEASE_BUILD_PLANNED" -eq 1 ]]; then
      LOADER_BINARY_SOURCE="$release_loader"
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
      CLI_INSTALL_PATH="${CLI_INSTALL_PATH:-/usr/local/bin/tracey}"
      LOADER_INSTALL_PATH="${LOADER_INSTALL_PATH:-/usr/local/bin/tracey-loader}"
      CONFIG_PATH="${CONFIG_PATH:-/etc/tracey/tracey.json}"
      STATE_DIR="${STATE_DIR:-/var/lib/tracey}"
      UNIT_PATH="${UNIT_PATH:-/etc/systemd/system/${UNIT_NAME}}"
      ENV_FILE="${ENV_FILE:-/etc/default/${UNIT_BASE}}"
      WANTED_BY="multi-user.target"
      ;;
    user)
      CLI_INSTALL_PATH="${CLI_INSTALL_PATH:-$HOME/.local/bin/tracey}"
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
  validate_path "cli install path" "$CLI_INSTALL_PATH"
  validate_path "loader install path" "$LOADER_INSTALL_PATH"
  validate_path "core install path" "$CORE_INSTALL_PATH"
  validate_path "config path" "$CONFIG_PATH"
  validate_path "state dir" "$STATE_DIR"
  validate_path "unit path" "$UNIT_PATH"
  validate_path "env file" "$ENV_FILE"

  [[ "$CLI_INSTALL_PATH" != "$LOADER_INSTALL_PATH" ]] || die "cli install path must differ from loader install path"
  [[ "$CLI_INSTALL_PATH" != "$CORE_INSTALL_PATH" ]] || die "cli install path must differ from core install path"
}

resolve_loader_paths() {
  local loader_manifest_name
  local loader_state_dir
  loader_manifest_name="tracey-loader.manifest.json"
  loader_state_dir="loader"

  if [[ -e "$CONFIG_PATH" && "$FORCE_CONFIG" -eq 0 ]]; then
    loader_state_dir=$(read_loader_state_dir_from_config "$CONFIG_PATH")
    loader_state_dir="${loader_state_dir:-loader}"
  fi

  if [[ "$loader_state_dir" = /* ]]; then
    LOADER_ROOT_PATH="$loader_state_dir"
  else
    LOADER_ROOT_PATH="$STATE_DIR/$loader_state_dir"
  fi
  LOADER_MANIFEST_PATH="$LOADER_ROOT_PATH/$loader_manifest_name"
  LOADER_CURRENT_METADATA_PATH="$LOADER_ROOT_PATH/current/tracey-core.meta.json"
  LOADER_CURRENT_SIGNATURE_PATH="$LOADER_ROOT_PATH/current/tracey-core.sig"

  validate_path "loader root path" "$LOADER_ROOT_PATH"
  validate_path "loader manifest path" "$LOADER_MANIFEST_PATH"
  validate_path "loader current metadata path" "$LOADER_CURRENT_METADATA_PATH"
  validate_path "loader current signature path" "$LOADER_CURRENT_SIGNATURE_PATH"
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

render_cli_wrapper() {
  local config_q state_q core_q
  printf -v config_q '%q' "$CONFIG_PATH"
  printf -v state_q '%q' "$STATE_DIR"
  printf -v core_q '%q' "$CORE_INSTALL_PATH"

  cat <<CFG
#!/usr/bin/env bash
set -euo pipefail

# tracey-service-wrapper: keeps CLI invocations pinned to the installed service state.
export TRACEY_CONFIG=${config_q}
cd ${state_q}
exec ${core_q} "\$@"
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

install_cli_wrapper() {
  local content
  content=$(render_cli_wrapper)
  write_file "$CLI_INSTALL_PATH" 0755 "$content"
}

refresh_loader_integrity_manifest() {
  if [[ -e "$LOADER_MANIFEST_PATH" ]]; then
    run rm -f "$LOADER_MANIFEST_PATH"
  fi
}

refresh_core_bootstrap_artifacts() {
  if [[ -e "$LOADER_CURRENT_METADATA_PATH" ]]; then
    run rm -f "$LOADER_CURRENT_METADATA_PATH"
  fi
  if [[ -e "$LOADER_CURRENT_SIGNATURE_PATH" ]]; then
    run rm -f "$LOADER_CURRENT_SIGNATURE_PATH"
  fi
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
  if [[ -n "$BUILD_AS_USER" ]]; then
    log "  build user:     $BUILD_AS_USER"
  fi
  if [[ -n "$SOURCE_VERSION" ]]; then
    log "  source version: $SOURCE_VERSION"
  fi
  if [[ -n "$RELEASE_BUILD_STATUS" ]]; then
    log "  build action:   $RELEASE_BUILD_STATUS"
  fi
  log "  cli path:       $CLI_INSTALL_PATH"
  log "  loader path:    $LOADER_INSTALL_PATH"
  log "  core path:      $CORE_INSTALL_PATH"
  log "  loader root:    $LOADER_ROOT_PATH"
  log "  config:         $CONFIG_PATH"
  log "  state dir:      $STATE_DIR"
  log "  unit:           $UNIT_PATH"
  log "  env file:       $ENV_FILE"
  if (( STATUS_ENABLED )); then
    log "  status bind:    $STATUS_LISTEN_ADDR"
  else
    log "  status bind:    disabled"
  fi
  log "  firewall:       $FIREWALL_STATUS"
  log "  agent_id:       $AGENT_ID"
  log "  core channel:   $CORE_CHANNEL"
  if [[ -n "$BOOTSTRAP_VERSION" ]]; then
    log "  core version:   $BOOTSTRAP_VERSION"
  fi
}

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)

SCOPE=auto
SERVICE_NAME=tracey
CORE_BINARY_SOURCE=
LOADER_BINARY_SOURCE=
CLI_INSTALL_PATH=
LOADER_INSTALL_PATH=
CORE_INSTALL_PATH=
LOADER_ROOT_PATH=
LOADER_MANIFEST_PATH=
LOADER_CURRENT_METADATA_PATH=
LOADER_CURRENT_SIGNATURE_PATH=
CONFIG_PATH=
STATE_DIR=
UNIT_PATH=
ENV_FILE=
STATUS_ENABLED=1
STATUS_LISTEN_ADDR=
STATUS_FIREWALL_PORT=
FIREWALL_MANAGER=
FIREWALL_STATUS=
AGENT_ID=
CORE_CHANNEL=
BOOTSTRAP_VERSION=
BUILD_IF_MISSING=1
START_SERVICE=1
FORCE_CONFIG=0
DRY_RUN=0
WANTED_BY=
SUPERVISOR_REQUESTED=1
SOURCE_VERSION=
RELEASE_BUILD_STATUS=
RELEASE_BUILD_PLANNED=0
BUILD_AS_USER=
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
    --cli-install-path)
      shift
      (($#)) || die "--cli-install-path requires a value"
      CLI_INSTALL_PATH="$1"
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

BUILD_AS_USER=$(resolve_build_user || true)

ensure_binary_sources
resolve_core_channel
maybe_detect_bootstrap_version
resolve_paths
resolve_loader_paths
resolve_status_firewall_target
print_summary
ensure_privileged_access
resolve_scope_conflicts

run mkdir -p "$STATE_DIR"
install_loader_binary
install_core_binary
install_cli_wrapper
refresh_loader_integrity_manifest
refresh_core_bootstrap_artifacts
maybe_write_config
maybe_write_env_file
ensure_status_firewall_access
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
if [[ -n "$FIREWALL_MANAGER" ]]; then
  log "firewall manager: $FIREWALL_MANAGER"
fi
log "firewall status: $FIREWALL_STATUS"
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
