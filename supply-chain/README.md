# supply-chain/: cargo-vet

[cargo-vet](https://mozilla.github.io/cargo-vet/) records who reviewed each third-party crate we build, and against which criteria. This directory is its store. ROADMAP M5 #7 asks for it, and M7 #6 makes it a gate for crypto crates. Licence, advisory, source and ban policy lives in `../deny.toml`.

| File | Contents | Edited by |
|---|---|---|
| `config.toml` | imports, first-party policy, exemptions | `cargo vet`; hand edits are fine if `cargo vet fmt` leaves them unchanged |
| `audits.toml` | our criteria and our own audits | `cargo vet certify` |
| `imports.lock` | the imported audits we actually use | `cargo vet` only |

The three files have no comments. `cargo vet` rewrites them in a canonical layout, and `cargo vet --locked` (the mode for CI) rejects any file that differs from that layout. Put rationale in an entry's `notes` field, or in this README.

## Imports

| Import | Why |
|---|---|
| `google` | broad coverage; its `crypto-safe` maps to our `crypto-reviewed` |
| `zcash` | crypto-heavy Rust ecosystem; its `crypto-reviewed` maps to ours |
| `mozilla`, `bytecode-alliance`, `isrg` | broad coverage, including hashes, TLS and AEAD crates |

URLs and names come from cargo-vet's registry. Each import's `safe-to-run` and `safe-to-deploy` map onto ours automatically. Other criteria are dropped unless they are mapped. Run in CI as `cargo vet --locked`, the check trusts only the audits copied into `imports.lock` in a reviewed commit, never the live upstream files.

## The `crypto-reviewed` criterion

It is defined in `audits.toml`. It means that any cryptographic code in the crate was reviewed by a qualified cryptography reviewer. A crate that implements no cryptography meets it: google's `does-not-implement-crypto` implies `crypto-safe`, which is mapped onto it. That lets non-crypto helper crates satisfy it without a crypto audit.

On purpose, it does **not** imply `safe-to-deploy`. If it did, every imported "no crypto here" audit would count as a deployment approval. A policy that wants both asks for both.

## State today (M5 bootstrap)

- Every crates.io crate in `Cargo.lock` has an exemption at its exact version, as `cargo vet init` would write it: `safe-to-deploy`, or `safe-to-run` for crates reached only through dev-dependencies. An exemption means **not yet audited**. It is never a review.
- No exemption claims `crypto-reviewed`. Only imports and our own audits can grant it.
- `imports.lock` lists the five imports but holds no audits yet. The first networked `cargo vet prune` fetches them, drops every exemption an import now covers, and leaves the rest. Review that diff like code.
- Every workspace crate has `audit-as-crates-io = false`: it is first-party, even if a crates.io crate takes the same name.
- A new or upgraded crate fails `cargo vet` until an import, an audit (`cargo vet certify`) or a reviewed exemption covers that exact version. The check stays report-only, not a required status check, until M7.

## Crypto crates and the M7 gate

The kernel and Guard crypto set is `k256`, `ecdsa`, `elliptic-curve`, `crypto-bigint`, `ed25519-dalek`, `curve25519-dalek`, `sha2` and `sha3`. `deny.toml` allows exactly one version of each. As of 2026-10, searched by crate name, no import has audits for `k256`, `crypto-bigint` or `ed25519-dalek`, nor for `bcs` (the kernel's encoding). Those need our own audits by a cryptography reviewer. For `k256`, the public 2023 NCC Group review is the basis for a delta audit.

At M7, the Guard's crypto dependencies must be `crypto-reviewed` with **no exemption**. Then the vet job becomes a required check. The policy goes into `config.toml`, with one `dependency-criteria` entry per crate in the set (run `cargo vet fmt` afterwards):

```toml
[policy.vaultex-guard]
audit-as-crates-io = false
dependency-criteria = { k256 = ["crypto-reviewed", "safe-to-deploy"] }
```

## Commands

Local runs need the tools installed (Decision Inbox Q-RUN-2); otherwise CI runs them.

```sh
cargo vet --locked          # the CI check: committed files only, no import fetch
cargo vet prune             # fetch imports, drop exemptions they cover (then review + commit)
cargo vet suggest           # audits that would retire exemptions, smallest first
cargo vet certify <crate>   # record our own audit in audits.toml
```
