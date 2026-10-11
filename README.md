<div align="center">

```
          ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗███████╗██╗  ██╗
          ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██╔════╝╚██╗██╔╝
          ██║   ██║███████║██║   ██║██║     ██║   █████╗   ╚███╔╝
          ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ██╔══╝   ██╔██╗
           ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ███████╗██╔╝ ██╗
            ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝
```

**Threshold-MPC wallet research prototype in Rust**

[![CI](https://github.com/itoonx/vaultex-mpc-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/itoonx/vaultex-mpc-rust/actions/workflows/ci.yml)

[English](README.md) | [中文](README.zh-CN.md)

</div>

> [!CAUTION]
> UNAUDITED PRE-ALPHA RESEARCH SOFTWARE · TESTNET ONLY · DO NOT USE WITH REAL FUNDS. Known critical limitations (by category): (1) affected scheme classes — the hand-rolled threshold-ECDSA engines are unsound, and Sr25519/BLS signing is not threshold; (2) transport confidentiality during key generation; (3) control-plane freshness; (4) unenforced signing policy — signers do not independently verify what they sign; (5) unsafe deposit addresses: addresses exported by pre-cut versions for unimplemented chains, and P2WPKH addresses shown for FROST-TR wallets, may be unspendable; do not send funds to them.

---

## What is Vaultex?

Vaultex is a Rust workspace that explores a self-hosted threshold multi-party computation (MPC) wallet. Each signer node holds one key share, a gateway coordinates the nodes over NATS, and the chain crates build and encode transactions.

The design goal is that no single party ever holds a complete private key. **The code at HEAD does not meet that goal for every scheme, and it cannot safely hold value.** Read the banner above and the support matrix below before you use anything here.

- **What works:** the chain transaction encoders. For six chains they are pinned to official SDK output where a reference exists, and they have produced confirmed transactions on public testnets.
- **What does not:** the integrated custody system. The banner lists its known limitations by category. No independent security audit or external review has taken place.
- **Where it is going:** [docs/ROADMAP.md](docs/ROADMAP.md) (proposed, awaiting owner decisions) and [docs/TASKS.md](docs/TASKS.md). The proposed first supported scope is a TRON (TRX + TRC-20) signer on an adopted, pinned threshold-ECDSA library, in which every node verifies what it signs. The banner changes only when a roadmap milestone closes on public evidence.

---

## Support matrix

This matrix describes the code at HEAD.

| Status | Meaning |
|---|---|
| **Supported** | Fit for real funds under a published support policy. **Nothing is supported today.** |
| **Staged** | Implemented and exercised end to end on a public testnet. Testnet only. A candidate for support once the limitations that affect it are fixed. |
| **Experimental** | Present in the code, but unverified, unsound or incomplete. Do not rely on it, and do not send funds to any address it shows. |

### Chains

No mainnet network is supported on any chain.

| Chain | Network tested | Assets | Encoder evidence | Signing used for that evidence | Status |
|---|---|---|---|---|---|
| TRON | Shasta testnet | TRX, TRC-20 | tronweb reference vectors; confirmed testnet transactions | Hand-rolled ECDSA (experimental, limitation 1) | Staged |
| Ethereum | Sepolia testnet | ETH, ERC-20 | viem reference vector; confirmed testnet transactions | Hand-rolled ECDSA (experimental, limitation 1) | Staged |
| Bitcoin | Testnet, P2WPKH | BTC | Confirmed testnet transaction | Hand-rolled ECDSA (experimental, limitation 1) | Staged. ⚠ Unsafe deposit addresses (5): P2WPKH addresses shown for FROST-TR wallets may be unspendable; do not send funds to them |
| Solana | Devnet | SOL, SPL tokens | `@solana/spl-token` reference vector; confirmed devnet transactions | FROST Ed25519 | Staged |
| Sui | Testnet | SUI, `Coin<T>` | `@mysten/sui` reference vectors; confirmed testnet transactions | FROST Ed25519 | Staged |
| Aptos | Testnet | APT, coins, fungible assets | `@aptos-labs/ts-sdk` reference vectors; confirmed testnet transactions | FROST Ed25519 | Staged |

The code also names 44 other chains. None of them has end-to-end evidence.

| Chains | Status |
|---|---|
| EVM networks other than Ethereum (25): Polygon, BSC, Arbitrum, Optimism, Base, Avalanche, Linea, zkSync Era, Scroll, Mantle, Blast, Zora, Fantom, Gnosis, Cronos, Celo, Moonbeam, Ronin, opBNB, Immutable, Manta Pacific, Hyperliquid, Berachain, MegaETH, Monad | Experimental. ⚠ Unsafe deposit addresses (5): addresses exported for these chains may be unspendable; do not send funds to them |
| Bitcoin mainnet, Litecoin, Dogecoin, Zcash | Experimental. ⚠ Unsafe deposit addresses (5): addresses exported for these chains may be unspendable; do not send funds to them |
| Polkadot, Kusama, Astar, Acala, Phala, Interlay | Experimental. ⚠ Unsafe deposit addresses (5): addresses exported for these chains may be unspendable; do not send funds to them |
| Cosmos Hub, Osmosis, Celestia, Injective, Sei | Experimental. ⚠ Unsafe deposit addresses (5): addresses exported for these chains may be unspendable; do not send funds to them |
| Movement, TON, Monero, Starknet | Experimental. ⚠ Unsafe deposit addresses (5): addresses exported for these chains may be unspendable; do not send funds to them |

### Signing schemes

| Scheme | Source | Status | Notes |
|---|---|---|---|
| GG20 threshold ECDSA (secp256k1) | Hand-rolled in this repo | Experimental | Unsound (limitation 1). To be deleted or quarantined ([ROADMAP §3.5](docs/ROADMAP.md#35-scope-cuts)) |
| CGGMP21 threshold ECDSA (secp256k1) | Hand-rolled in this repo | Experimental | Unsound (limitation 1). To be deleted or quarantined |
| Stark-curve threshold ECDSA | Hand-rolled in this repo | Experimental | Unsound (limitation 1). To be deleted or quarantined |
| Sr25519 | Uses `schnorrkel` | Experimental | **Not threshold signing** (limitation 1). To be deleted or quarantined |
| BLS12-381 | Uses `blst` | Experimental | **Not threshold signing** (limitation 1). To be deleted or quarantined |
| FROST Ed25519 | Wraps the ZF `frost-ed25519` crate | Staged | Affected by limitations 2–4 |
| FROST secp256k1 Taproot | Wraps the ZF `frost-secp256k1-tr` crate | Experimental | ⚠ Unsafe deposit addresses (5): P2WPKH addresses shown for FROST-TR wallets may be unspendable; do not send funds to them |
| `cggmp24` (LFDT-Lockness, pinned) | Upstream library | Not integrated | Proposed replacement for the hand-rolled ECDSA engines; decision pending (ROADMAP ADR-07) |

### Components

| Component | Status | Notes |
|---|---|---|
| Chain transaction encoders (the six staged chains) | Staged | Evidence as in the chain table |
| MPC node and gateway (`services/`) | Experimental | Limitations 2–4. No working multi-host deployment; the gateway's wallet registry is held in memory |
| Policy engine, approvals, velocity limits, RBAC/ABAC/MFA, audit ledger | Experimental (library code) | Not enforced by the signers (limitation 4) |
| Gateway authentication (key-exchange handshake, session JWT, mTLS via a TLS terminator, bearer JWT) | Experimental | Replacement under review (ROADMAP ADR-09) |
| Encrypted key store (Argon2id + AES-256-GCM) | Experimental | No backup or restore tooling yet |
| Key refresh and reshare | Experimental | Built on the hand-rolled engines (limitation 1) |
| KMS, HSM, SGX/TEE | Not implemented | Interfaces, stubs and a mock only |
| Transaction simulation and risk scoring | Experimental | — |
| CLI (`mpc-wallet-cli`) | Experimental | Single-process demo that runs every party in one process. Never use it with real funds |
| Deployment: Docker Compose, Kubernetes manifests, Helm, Terraform | Experimental | None of them starts a working multi-host cluster |

---

## Quickstart (development and testnet only)

```bash
git clone https://github.com/itoonx/vaultex-mpc-rust.git
cd vaultex-mpc-rust

# Unit and integration tests (single process, no infrastructure)
cargo test --workspace --features local-transport

# Single-host dev stack: Vault, Redis, NATS, three MPC nodes and the gateway
./scripts/local-infra.sh up
./scripts/local-infra.sh test    # E2E keygen and sign over NATS
./scripts/local-infra.sh down

# Single-process CLI demo
./scripts/demo.sh
```

The tests use test-size cryptographic parameters. Passing tests do not show that anything works at production parameters or across hosts.

---

## Documentation

| Document | What it is |
|---|---|
| [Roadmap](docs/ROADMAP.md) | Production roadmap (proposed) and an honest account of the current state |
| [Task backlog](docs/TASKS.md) | Tasks that execute the roadmap |
| [Security policy](SECURITY.md) | How to report a vulnerability |
| [CLI guide](docs/CLI_GUIDE.md) | Commands of the single-process demo CLI |
| [API reference](docs/API_REFERENCE.md) | Gateway REST API (experimental) |
| [Architecture](specs/ARCHITECTURE.md) | Architecture notes. They predate the roadmap and may overstate maturity |
| [Auth spec](specs/AUTH_SPEC.md) | Gateway key-exchange handshake (experimental) |
| [Standards](specs/STANDARDS.md) | Standards and references cited by the code |
| [Contributing](docs/CONTRIBUTING.md) | Contribution guide |
| [Changelog](CHANGELOG.md) | Change history |

Older documents predate the roadmap. They include the internal security notes in [docs/SECURITY_FINDINGS.md](docs/SECURITY_FINDINGS.md) and [docs/SECURITY_AUDIT_AUTH.md](docs/SECURITY_AUDIT_AUTH.md) and the chain plan in [specs/CHAIN_ROADMAP.md](specs/CHAIN_ROADMAP.md). The security notes were written by AI agents during development. They are not independent audits, and their "resolved" statuses do not cover the limitations in the banner. Stale documents are being archived (ROADMAP M5 #10).

---

## Project structure

```
crates/
  mpc-wallet-core/     ← MPC protocols, transport, key store, policy, identity, RPC messages
  mpc-wallet-chains/   ← Chain providers and transaction encoders (see the support matrix)
  mpc-wallet-cli/      ← Single-process demo CLI
services/
  api-gateway/         ← REST gateway and orchestrator (holds no key shares)
  mpc-node/            ← Standalone MPC node (one party, one share)
infra/                 ← Docker, local dev stack, Kubernetes, Helm, Terraform (experimental)
scripts/               ← local-infra.sh, demo.sh and helpers
specs/, docs/, retro/  ← Specifications, documentation, decision records and lessons
```

---

## Security

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md). Do not open public issues for security problems.

---

## Licence

This repository does not contain a licence file yet, so this README grants no licence. Licensing is being finalised (ROADMAP M5 #2). The `license` field in the Cargo manifests predates this and will be corrected together with the licence files.

---

<p align="center">
  <sub>
    Built with <a href="https://claude.com/claude-code">Claude Code</a> by a team of AI agents.
  </sub>
</p>
