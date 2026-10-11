#!/usr/bin/env bash
# Regression check: the boot-node wrapper never mounts a host (multi-party CLI) keystore.
# Runs scripts/node.sh in a throwaway copy with stub `docker` and stub CLI (dummy values only);
# needs nothing but bash. Usage: infra/node/test-node-wrapper.sh
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
R="$T/repo"; mkdir -p "$R/scripts" "$R/infra/node" "$T/bin"
cp "$REPO/scripts/node.sh" "$R/scripts/"
cp "$REPO/infra/node/docker-compose.node.yml" "$REPO/infra/node/node.env.example" "$R/infra/node/"
cat > "$T/bin/docker" <<'STUB'
#!/usr/bin/env bash
echo "docker $* | KEYS_MOUNT=${KEYS_MOUNT-unset}" >> "$DOCKER_LOG"
STUB
cat > "$T/bin/mpc-wallet" <<'STUB'
#!/usr/bin/env bash
echo '{"signing_key_hex": "1111111111111111111111111111111111111111111111111111111111111111", "verifying_key_hex": "2222222222222222222222222222222222222222222222222222222222222222"}'
STUB
chmod +x "$T/bin/docker" "$T/bin/mpc-wallet"
unset KEYS_MOUNT
export PATH="$T/bin:$PATH" MPC_WALLET_BIN="$T/bin/mpc-wallet" DOCKER_LOG="$T/docker.log"
N="$R/scripts/node.sh"; ST="$R/infra/node/.boot-node.state"; EF="$R/infra/node/node.env"
COMPOSE="$R/infra/node/docker-compose.node.yml"
fails=0
# check NAME — records the exit status of the condition run just before it.
check() { local st=$?; if [[ $st -eq 0 ]]; then echo "ok   $1"; else echo "FAIL $1"; fails=$((fails + 1)); fi; }

# Static: the compose file pins the named volume; no variable and no host path for /data/keys.
grep -qE '^ +- boot-node-keys:/data/keys$' "$COMPOSE" && ! grep -q KEYS_MOUNT "$COMPOSE"
check "compose pins the named volume"

out="$(bash "$N" init --party 1 --keys "$T" 2>&1)"; rc=$?
[[ $rc -ne 0 && "$out" == *"--keys was removed"* && ! -e "$ST" && ! -e "$EF" ]]
check "init --keys is refused and writes nothing"

bash "$N" init --party 2 >/dev/null 2>&1; rc=$?
[[ $rc -eq 0 && "$(cat "$ST")" == "NATS_MODE=bundled" ]]
check "init records no keystore mount"

: > "$DOCKER_LOG"; bash "$N" up >/dev/null 2>&1; rc=$?
[[ $rc -eq 0 && "$(cat "$DOCKER_LOG")" == *" up -d --build | KEYS_MOUNT=unset"* ]]
check "up starts compose with no KEYS_MOUNT"

printf 'NATS_MODE=bundled\nKEYS_MOUNT=%s\n' "$T" > "$ST"; : > "$DOCKER_LOG"
out="$(bash "$N" up 2>&1)"; rc=$?
[[ $rc -ne 0 && "$out" == *"no longer supported"* && ! -s "$DOCKER_LOG" ]]
check "up refuses legacy host-keystore state before docker runs"

bash "$N" init --party 2 >/dev/null 2>&1
[[ "$(cat "$ST")" == "NATS_MODE=bundled" ]]
check "re-running init clears the legacy mount"

if [[ $fails -ne 0 ]]; then echo "$fails check(s) failed"; exit 1; fi
echo "all checks passed"
