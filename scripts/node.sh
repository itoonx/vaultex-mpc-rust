#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────
# scripts/node.sh — one-command wrapper to run a standalone MPC boot node.
#
#   scripts/node.sh init --party 1            # scaffold node.env + mint secrets
#   scripts/node.sh up                        # docker compose up (+ bundled NATS)
#   scripts/node.sh logs | status | down
#
# Flags (init): --party N (required)
#               --external-nats <url>   connect to an existing NATS (default: bundled)
#               --bundle-nats           co-locate a NATS container (default)
#               --keys <hostpath>       bind-mount existing key shares (default: named volume)
#               --env <file>            env-file path (default: infra/node/node.env)
#               --force                 overwrite an existing node.env
# ─────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
NODE_DIR="$REPO_ROOT/infra/node"
COMPOSE_FILE="$NODE_DIR/docker-compose.node.yml"
EXAMPLE_ENV="$NODE_DIR/node.env.example"
STATE_FILE="$NODE_DIR/.boot-node.state"
GATEWAY_KEY_FILE="$NODE_DIR/gateway.key"
CLI_BIN="${MPC_WALLET_BIN:-$REPO_ROOT/target/release/mpc-wallet}"
ENV_FILE="$NODE_DIR/node.env"

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*" >&2; }

# Compose wrapper: always pass --env-file so ${HEALTH_PORT}/${KEYS_MOUNT} interpolate.
dc() { docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"; }

# set_env KEY VALUE — idempotently upsert KEY=VALUE in the env-file.
set_env() {
  local key="$1" val="$2"
  if grep -qE "^${key}=" "$ENV_FILE" 2>/dev/null; then
    # portable in-place edit (BSD + GNU sed)
    local tmp; tmp="$(mktemp)"
    sed "s|^${key}=.*|${key}=${val}|" "$ENV_FILE" > "$tmp" && mv "$tmp" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$val" >> "$ENV_FILE"
  fi
}

get_env() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2-; }

require_cli() {
  [[ -x "$CLI_BIN" ]] || die "mpc-wallet binary not found at $CLI_BIN — run: cargo build -p mpc-wallet-cli --release (or set MPC_WALLET_BIN)"
}

# Active profile args for `up`/`down`, derived from saved NATS mode.
profile_args() {
  local NATS_MODE="bundled"
  [[ -f "$STATE_FILE" ]] && . "$STATE_FILE"
  [[ "${NATS_MODE:-bundled}" == "bundled" ]] && echo "--profile bundled-nats"
}

cmd_init() {
  local party="" nats_mode="bundled" nats_url="nats://nats:4222" keys="" force=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --party)         party="$2"; shift 2 ;;
      --external-nats) nats_mode="external"; nats_url="$2"; shift 2 ;;
      --bundle-nats)   nats_mode="bundled"; nats_url="nats://nats:4222"; shift 1 ;;
      --keys)          keys="$2"; shift 2 ;;
      --env)           ENV_FILE="$2"; shift 2 ;;
      --force)         force=1; shift 1 ;;
      *) die "unknown init flag: $1" ;;
    esac
  done
  [[ -n "$party" ]] || die "init requires --party N"
  require_cli

  if [[ -f "$ENV_FILE" && "$force" -ne 1 ]]; then
    warn "$ENV_FILE exists — keeping existing secrets (use --force to regenerate)"
  else
    cp "$EXAMPLE_ENV" "$ENV_FILE"
    info "scaffolded $ENV_FILE from template"
  fi

  set_env PARTY_ID "$party"
  set_env NATS_URL "$nats_url"

  # KEY_STORE_PASSWORD — random if still the placeholder/empty.
  local pw; pw="$(get_env KEY_STORE_PASSWORD)"
  if [[ -z "$pw" || "$pw" == "change-me" ]]; then
    set_env KEY_STORE_PASSWORD "$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 32)"
    info "generated random KEY_STORE_PASSWORD"
  fi

  # NODE_SIGNING_KEY — mint if absent.
  if [[ -z "$(get_env NODE_SIGNING_KEY)" ]]; then
    local node_json; node_json="$("$CLI_BIN" --format json gen-identity --label node 2>/dev/null)"
    set_env NODE_SIGNING_KEY "$(printf '%s' "$node_json" | sed -n 's/.*"signing_key_hex": *"\([0-9a-f]*\)".*/\1/p')"
    info "minted NODE_SIGNING_KEY"
  fi

  # GATEWAY keypair — mint a gateway identity; node needs the PUBLIC half.
  if [[ -z "$(get_env GATEWAY_PUBKEY)" ]]; then
    local gw_json; gw_json="$("$CLI_BIN" --format json gen-identity --label gateway 2>/dev/null)"
    local gw_sk gw_pk
    gw_sk="$(printf '%s' "$gw_json" | sed -n 's/.*"signing_key_hex": *"\([0-9a-f]*\)".*/\1/p')"
    gw_pk="$(printf '%s' "$gw_json" | sed -n 's/.*"verifying_key_hex": *"\([0-9a-f]*\)".*/\1/p')"
    set_env GATEWAY_PUBKEY "$gw_pk"
    umask 077; printf '%s\n' "$gw_sk" > "$GATEWAY_KEY_FILE"
    info "minted GATEWAY keypair (pubkey → env, private → $GATEWAY_KEY_FILE)"
  fi

  # Persist run-mode state for `up`/`down`.
  local keys_mount="boot-node-keys"
  if [[ -n "$keys" ]]; then
    [[ -d "$keys" ]] || die "--keys path does not exist: $keys"
    keys_mount="$(cd "$keys" && pwd)"   # absolute → bind mount
    info "will bind-mount existing shares from $keys_mount"
  fi
  { echo "NATS_MODE=$nats_mode"; echo "KEYS_MOUNT=$keys_mount"; } > "$STATE_FILE"

  info "init complete — review $ENV_FILE, then: scripts/node.sh up"
}

preflight() {
  [[ -f "$ENV_FILE" ]] || die "no env-file at $ENV_FILE — run: scripts/node.sh init --party N"
  local missing=()
  for v in PARTY_ID KEY_STORE_PASSWORD NODE_SIGNING_KEY GATEWAY_PUBKEY; do
    [[ -n "$(get_env "$v")" ]] || missing+=("$v")
  done
  [[ ${#missing[@]} -eq 0 ]] || die "missing mandatory vars in $ENV_FILE: ${missing[*]}"
  # External NATS reachability probe (best-effort).
  if [[ -f "$STATE_FILE" ]]; then
    local NATS_MODE="bundled"; . "$STATE_FILE"
    if [[ "${NATS_MODE:-bundled}" == "external" ]]; then
      local hp; hp="$(get_env NATS_URL | sed -E 's#^nats://##; s#/.*##')"
      local host="${hp%%:*}" port="${hp##*:}"
      if command -v nc >/dev/null 2>&1 && ! nc -z -w2 "$host" "$port" 2>/dev/null; then
        warn "external NATS $host:$port not reachable yet — node will retry after start"
      fi
    fi
  fi
}

cmd_up() {
  preflight
  local NATS_MODE="bundled" KEYS_MOUNT="boot-node-keys"
  [[ -f "$STATE_FILE" ]] && . "$STATE_FILE"
  info "building + starting boot node (party $(get_env PARTY_ID), NATS=${NATS_MODE:-bundled})"
  KEYS_MOUNT="${KEYS_MOUNT:-boot-node-keys}" dc $(profile_args) up -d --build
  info "started — check: scripts/node.sh status"
}

cmd_down() {
  local purge=""
  [[ "${1:-}" == "--purge" ]] && purge="-v"
  dc $(profile_args) down $purge
  info "stopped${purge:+ (volumes purged)}"
}

cmd_logs()   { dc logs -f mpc-node; }

cmd_status() {
  dc $(profile_args) ps
  local port; port="$(get_env HEALTH_PORT)"; port="${port:-9090}"
  echo "── GET http://localhost:$port/health ──"
  curl -fsS "http://localhost:$port/health" 2>/dev/null && echo || warn "health endpoint not responding (node may still be starting)"
}

usage() {
  sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

main() {
  local sub="${1:-help}"; shift || true
  case "$sub" in
    init)   cmd_init "$@" ;;
    up)     cmd_up "$@" ;;
    down)   cmd_down "$@" ;;
    logs)   cmd_logs "$@" ;;
    status) cmd_status "$@" ;;
    help|-h|--help) usage ;;
    *) die "unknown command: $sub (try: init | up | down | logs | status)" ;;
  esac
}

main "$@"
