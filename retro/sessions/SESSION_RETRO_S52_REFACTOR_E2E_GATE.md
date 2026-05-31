# Sprint 52 Retro — Chain Registry Refactor E2E Gate (Live on All 6 Chains)

- **Window:** 2026-06-01 (single session)
- **Branch:** `dev` (doc-only commit `d90cd52a`; zero production code changed)
- **Outcome:** Sprint 51's deferred E2E gate **passed** — live MPC re-broadcast on all 6 funded testnet wallets, all confirmed on-chain. The CHAIN_METADATA / provider-owned `fetch_presign_extras` refactor is proven not to have regressed any live signing path.

---

## Goal

> "ตอนนี้เราต้องทำอะไรต่อ" → what's next? → chose **Sprint 52: E2E live re-broadcast**
> "ยิงสดเลยทั้ง 6 chain" → fire live on all 6, no dry-run.

**Hard goal:** a real, on-chain-confirmed tx per chain, signed by distributed MPC parties through the *refactored* CLI dispatch path (CLI has zero chain-conditional presign branches post-Sprint-51).

This closes a follow-up logged in the S38/S39 retro: *"Refactor `merge_extras` + per-chain `fetch_presign_extras` into a `PresignBuilder` per chain."* Sprint 51 did exactly that; Sprint 52 validates it under live fire.

## Outcome

| Chain | Protocol | TX | On-chain |
|-------|----------|----|----------|
| Sepolia | GG20 ECDSA | `0x299e31bf…2a40c00f` | block 10963455 |
| Solana devnet | FROST-Ed25519 | `4BSvgaFy…iR3cNsHn` | finalized |
| Bitcoin testnet | GG20 ECDSA (P2WPKH) | `2084bef0…1aeaaba1` | accepted to mempool (testnet block lag) |
| Sui testnet | FROST-Ed25519 | `FtVMnEvo…Gv6zGtWF` | success |
| Aptos testnet | FROST-Ed25519 | `0x9773f20e…6a47dafb` | Executed (seq 5) |
| TRON Shasta | GG20 ECDSA | `5821dd9d…07204b404` | SUCCESS |

All 6 wallets were still funded from Sprints 38–50 (verified read-only before any signing). No re-keygen, no re-funding needed.

## Process — what worked

- **Read-only funding check first.** Before touching a keystore, queried each chain's public RPC for the sender balance. All 6 were still funded → the whole sprint was unblocked in one batch of `curl`s, no faucet round-trips. Aptos's `CoinStore<AptosCoin>` returned `resource_not_found` (APT migrated to the FA standard); the `0x1::coin::balance` view function still reported ~9.99 APT — confirmed live, not drained.
- **The diagnostic ladder from S38/S39 paid off again.** Every send printed balance → presign summary → encoded-tx fields → recover/verify-against-sender *before* broadcast. On all 6 chains the local invariants passed, so the only surprise came from the remote validator (TRON), not from our encoding.
- **Refactor held under fire.** The Sprint 51 claim "adding/maintaining a chain = one CHAIN_METADATA entry + one provider impl, zero CLI edits" is now backed by 6 live txs: default RPC, explorer URLs, and the entire presign RPC dance resolved through metadata/provider for every chain with no CLI special-casing.

## Process — what didn't / surprises

- **TRON rejects self-transfer.** `CONTRACT_VALIDATE_ERROR: Cannot transfer TRX to yourself.` The MPC sign + encode succeeded (raw_len=132, sig recovered to sender) — the rejection is a TRON node rule, surfaced only at broadcast. Worked around by deriving a second controlled TRON address (`export-address --chain tron` on the Sepolia GG20 group → `TE8xGvXfuYQijhYKDoFizRWQXjNv3u11CS`) and sending there. The other 5 chains all accept self-transfer, which is why the pattern had never bitten before.
- **`funded-wallets.local.json` was missing the TRON `group_id`.** The tron-shasta entry had a `sender` but no `group_id`, so the wallet had to be recovered by reading `metadata.json` across all 14 keystores. Filled in `16be267f-…` so the next run is a straight lookup.
- **Toolchain moved under us.** rustc bumped to 1.93.1 / alloy 1.7.3 (the two Docker base-bump commits that preceded this session). Re-ran `cargo test --workspace --lib` first → 624/624 green, so the live run started from a known-good build.

## Lessons filed

- **L-020** — TRON `TransferContract` rejects self-transfer at the validator (`Cannot transfer TRX to yourself`); native-coin self-sends are not a universal testnet smoke-test primitive. EVM/Solana/BTC/Sui/Aptos all allow it.

## Decisions captured

- None new. Reinforces **DEC-019** (persistent funded testnet wallets reused across sessions) and the Sprint 51 metadata-driven provider architecture.

## Open follow-ups

- Promote this into a `LIVE_TESTNET=1`-gated integration test that loops the 6 wallets and asserts broadcast success (the S38/S39 follow-up is still open and now has a concrete 6-chain harness to model).
- Record the Sprint 52 verified tx hashes into `funded-wallets.local.json` per-chain `verified_tx` history (currently only Sprint 38–50 hashes are stored).
- Bitcoin confirmation was still pending at session close — re-check the block inclusion of `2084bef0…` on next session for a fully-confirmed 6/6.
