> **ARCHIVED — SUPERSEDED (2026-10-11).** Kept for history only; it does not describe Vaultex today.
> Current status: [README](../../../README.md), [SECURITY_STATUS.md](../../../SECURITY_STATUS.md), [CLAIMS.md](../../../CLAIMS.md).
> Superseded by: nothing. In the proposed v1 scope the caller builds and broadcasts transactions ([ROADMAP §2.1](../../ROADMAP.md#21-declared-v1-scope-and-boundary)).

# RPC Providers

The MPC wallet broadcasts transactions through public RPC endpoints. Both the
CLI (`mpc-wallet send`) and the API gateway (`POST /v1/wallets/:id/transactions`)
resolve a URL via the same precedence chain.

## Fallback chain

```
1. --rpc-url <override>            (CLI only — always wins)
2. DWELLIR_API_KEY                 (preferred, ~43 chains)
3. INFURA_API_KEY                  (legacy, EVM only)
4. Public endpoint                 (Solana, Bitcoin Esplora)
5. Error                           ("set DWELLIR_API_KEY or pass --rpc-url")
```

## Dwellir

Set `DWELLIR_API_KEY` to your account key:

```bash
export DWELLIR_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

URL pattern: `https://{slug}-rpc.dwellir.com/{key}` — see
`crates/mpc-wallet-chains/src/rpc/providers/dwellir.rs` for the full slug map.

Known coverage gaps in the current provider:
- `Chain::BitcoinTestnet` — Dwellir has Bitcoin mainnet only; testnet routes via Blockstream.
- `Chain::Solana` devnet/testnet — slug map has only `solana` (mainnet); devnet falls back to public RPC.
- `Chain::Litecoin / Dogecoin / Zcash / Monero` — not in the Dwellir slug table.

## Infura (legacy)

Set `INFURA_API_KEY` to keep Infura as a fallback for EVM (Ethereum, Polygon,
Arbitrum, Optimism, Base, Avalanche, Linea):

```bash
export INFURA_API_KEY=<project_id>
```

Infura is consulted only when Dwellir is unset or doesn't cover the chain.

## Public endpoints (no key)

- **Solana**: `https://api.{mainnet-beta|devnet|testnet}.solana.com`
- **Bitcoin**: `https://blockstream.info/{mainnet,testnet}/api`

## Override per-call

```bash
mpc-wallet send --rpc-url https://my-node.example.com/rpc \
  --chain ethereum --network testnet ...
```
