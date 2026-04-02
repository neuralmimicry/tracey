#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: package-release.sh [options]

Build and package Tracey release artifacts.

Options:
  --version VERSION           Version label for the packaged artifacts.
  --output-dir DIR            Directory to receive the packaged artifacts.
  --target-triple TRIPLE      Optional cargo target triple.
  --platform NAME             Platform suffix in output names. Default: derived from host.
  --skip-build                Reuse existing release binaries instead of building them.
  --sign-update               Generate tracey.update(.meta.json/.sig) with TRACEY_UPDATE_KEY.
  -h, --help                  Show this help text.

Examples:
  ./scripts/package-release.sh --version 0.1.0 --output-dir ./dist
  TRACEY_UPDATE_KEY=shared ./scripts/package-release.sh --version 0.1.0 --output-dir ./dist --sign-update
USAGE
}

log() {
  printf '%s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

default_platform() {
  local os arch
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)
  case "$arch" in
    amd64) arch="x86_64" ;;
    arm64) arch="aarch64" ;;
  esac
  printf '%s-%s\n' "$os" "$arch"
}

sha256_tool() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf 'sha256sum\n'
  elif command -v shasum >/dev/null 2>&1; then
    printf 'shasum -a 256\n'
  else
    die "sha256sum or shasum is required"
  fi
}

binary_dir() {
  if [[ -n "$TARGET_TRIPLE" ]]; then
    printf '%s/target/%s/release\n' "$REPO_ROOT" "$TARGET_TRIPLE"
  else
    printf '%s/target/release\n' "$REPO_ROOT"
  fi
}

resolve_build_user() {
  if [[ $(id -u) -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    printf '%s\n' "$SUDO_USER"
  fi
}

build_binaries() {
  local args
  local cmd
  args=(cargo build --locked --release --bin tracey --bin tracey-loader)
  if [[ -n "$TARGET_TRIPLE" ]]; then
    args+=(--target "$TARGET_TRIPLE")
  fi
  printf -v cmd '%q ' "${args[@]}"
  cmd=${cmd% }
  if [[ -n "$BUILD_AS_USER" ]]; then
    log "building release binaries as ${BUILD_AS_USER}"
    sudo -u "$BUILD_AS_USER" -H bash -lc "cd $(printf '%q' "$REPO_ROOT") && ${cmd}"
  else
    log "building release binaries"
    (
      cd "$REPO_ROOT"
      "${args[@]}"
    )
  fi
}

VERSION=
OUTPUT_DIR=
TARGET_TRIPLE=
PLATFORM=
SKIP_BUILD=0
SIGN_UPDATE=0
BUILD_AS_USER=

while (($#)); do
  case "$1" in
    --version)
      shift
      (($#)) || die "--version requires a value"
      VERSION="$1"
      ;;
    --output-dir)
      shift
      (($#)) || die "--output-dir requires a value"
      OUTPUT_DIR="$1"
      ;;
    --target-triple)
      shift
      (($#)) || die "--target-triple requires a value"
      TARGET_TRIPLE="$1"
      ;;
    --platform)
      shift
      (($#)) || die "--platform requires a value"
      PLATFORM="$1"
      ;;
    --skip-build)
      SKIP_BUILD=1
      ;;
    --sign-update)
      SIGN_UPDATE=1
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

[[ -n "$VERSION" ]] || die "--version is required"
[[ -n "$OUTPUT_DIR" ]] || die "--output-dir is required"

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
PLATFORM="${PLATFORM:-$(default_platform)}"
BUILD_AS_USER=$(resolve_build_user || true)

BIN_DIR=$(binary_dir)
TRACEY_BIN="$BIN_DIR/tracey"
LOADER_BIN="$BIN_DIR/tracey-loader"

if (( ! SKIP_BUILD )) || [[ ! -x "$TRACEY_BIN" || ! -x "$LOADER_BIN" ]]; then
  build_binaries
fi

[[ -x "$TRACEY_BIN" ]] || die "missing tracey binary: $TRACEY_BIN"
[[ -x "$LOADER_BIN" ]] || die "missing tracey-loader binary: $LOADER_BIN"

if (( SIGN_UPDATE )) && [[ -z "${TRACEY_UPDATE_KEY:-}" ]]; then
  die "TRACEY_UPDATE_KEY must be set when --sign-update is used"
fi

ARCHIVE_BASENAME="tracey-${VERSION}-${PLATFORM}"
OUTPUT_DIR=$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)
STAGE_ROOT="$OUTPUT_DIR/.stage"
PAYLOAD_DIR="$STAGE_ROOT/$ARCHIVE_BASENAME"
ARCHIVE_PATH="$OUTPUT_DIR/${ARCHIVE_BASENAME}.tar.gz"
CHECKSUM_PATH="$OUTPUT_DIR/${ARCHIVE_BASENAME}.sha256.txt"

rm -rf "$STAGE_ROOT"
mkdir -p "$PAYLOAD_DIR"
mkdir -p "$PAYLOAD_DIR/docs"

install -m 0755 "$TRACEY_BIN" "$PAYLOAD_DIR/tracey"
install -m 0755 "$LOADER_BIN" "$PAYLOAD_DIR/tracey-loader"
install -m 0755 "$REPO_ROOT/scripts/install-service.sh" "$PAYLOAD_DIR/install-service.sh"
install -m 0644 "$REPO_ROOT/README.md" "$PAYLOAD_DIR/README.md"
install -m 0644 "$REPO_ROOT/docs/OPERATIONS.md" "$PAYLOAD_DIR/docs/OPERATIONS.md"

tar -C "$STAGE_ROOT" -czf "$ARCHIVE_PATH" "$ARCHIVE_BASENAME"

artifacts=("$ARCHIVE_PATH")

if (( SIGN_UPDATE )); then
  SIGN_DIR="$OUTPUT_DIR/.sign"
  rm -rf "$SIGN_DIR"
  mkdir -p "$SIGN_DIR"
  (
    cd "$REPO_ROOT"
    TRACEY_UPDATE_KEY="$TRACEY_UPDATE_KEY" "$TRACEY_BIN" \
      sign-update \
      --bundle "$TRACEY_BIN" \
      --version "$VERSION" \
      --channel production \
      --out "$SIGN_DIR"
  )

  mv "$SIGN_DIR/tracey.update" "$OUTPUT_DIR/${ARCHIVE_BASENAME}.update"
  mv "$SIGN_DIR/tracey.update.meta.json" "$OUTPUT_DIR/${ARCHIVE_BASENAME}.update.meta.json"
  mv "$SIGN_DIR/tracey.update.sig" "$OUTPUT_DIR/${ARCHIVE_BASENAME}.update.sig"
  artifacts+=(
    "$OUTPUT_DIR/${ARCHIVE_BASENAME}.update"
    "$OUTPUT_DIR/${ARCHIVE_BASENAME}.update.meta.json"
    "$OUTPUT_DIR/${ARCHIVE_BASENAME}.update.sig"
  )
  rm -rf "$SIGN_DIR"
fi

checksum_cmd=$(sha256_tool)
(
  cd "$OUTPUT_DIR"
  relative_artifacts=()
  for artifact in "${artifacts[@]}"; do
    relative_artifacts+=("$(basename "$artifact")")
  done
  $checksum_cmd "${relative_artifacts[@]}" >"$(basename "$CHECKSUM_PATH")"
)

log
log "packaged Tracey release artifacts:"
for artifact in "${artifacts[@]}" "$CHECKSUM_PATH"; do
  log "  $artifact"
done

rm -rf "$STAGE_ROOT"
