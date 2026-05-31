# Standalone MPC Boot Node

Run a single `mpc-node` separately, via Docker, with two commands — no hand-setting
env vars one at a time.

```bash
# 1. build the CLI once (used to mint identity keys)
cargo build -p mpc-wallet-cli --release

# 2. scaffold config + auto-generate the 4 mandatory secrets
scripts/node.sh init --party 1

# 3. start the node (bundles a NATS container by default)
scripts/node.sh up

# inspect / stop
scripts/node.sh status
scripts/node.sh logs
scripts/node.sh down            # add --purge to also drop the key volume
```

## Why this exists

`mpc-node` is 100% env-driven and needs **4 mandatory** vars — `PARTY_ID`,
`KEY_STORE_PASSWORD`, `NODE_SIGNING_KEY` (Ed25519 private seed, hex) and
`GATEWAY_PUBKEY` (Ed25519 public key, hex) — plus a reachable NATS. `init` fills all
of them into `node.env` (gitignored) so you set things up **once**. The gateway
public key must be a real curve point, so `init` mints it in audited Rust via
`mpc-wallet gen-identity` (the gateway private half is saved to `gateway.key`,
0600) rather than a fragile `openssl rand`.

## Files

| File | Purpose |
|------|---------|
| `node.env.example` | Template / single source of truth for every env var |
| `node.env` | Your filled config (gitignored) — created by `init` |
| `gateway.key` | Generated gateway Ed25519 private key (gitignored, 0600) |
| `.boot-node.state` | Run-mode state (`NATS_MODE`, `KEYS_MOUNT`) for `up`/`down` |
| `docker-compose.node.yml` | One node + optional `bundled-nats` profile |

## NATS modes

- **Bundled (default):** `init --party 1` → a co-located `nats:2.10-alpine` starts
  alongside the node (compose profile `bundled-nats`). Self-contained boot node.
- **External:** `init --party 1 --external-nats nats://<host>:4222` → no NATS
  container; the node connects to your broker. `up` probes reachability and warns
  early. The node has `restart: unless-stopped`, so it retries until NATS is up.

## Key-share modes

- **Default (named volume):** the node starts with an empty docker-managed
  `/data/keys`. This is the right state for a node that will receive its share via
  **DKG over NATS** (keygen is a multi-party operation — a lone node cannot keygen
  itself). The volume is owned by the container's `mpc` user, so shares written
  during DKG persist with correct permissions.
- **Mount existing shares:** `init --party 1 --keys /path/to/keys` bind-mounts an
  existing EncryptedFileStore directory (e.g. a previously-funded keystore). Use the
  **same `KEY_STORE_PASSWORD`** that encrypted those shares.

## Multiple nodes

This wrapper targets **one separate boot node** (state is kept in a single
`.boot-node.state`). To run the canonical local **3-node + gateway** stack on one
host, use `infra/docker/docker-compose.yml` instead. To run several independent boot
nodes, give each its own checkout/working copy, or run them on separate hosts.

## Notes

- On Docker Desktop (macOS), bind-mounting a host keystore generally works despite
  the container running as non-root; on Linux ensure the dir is readable by the
  container `mpc` user.
- `MPC_WALLET_BIN=/path/to/mpc-wallet scripts/node.sh init ...` overrides which CLI
  binary mints the identity keys.
