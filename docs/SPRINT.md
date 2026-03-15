# Sprint 1 — 2026-03-15 → 2026-03-29

## Goal
**"Production-ready crypto core + all chains correct"**

Replace the GG20 key-reconstruction simulation with real distributed ECDSA, complete BCS
serialization for Sui, validate Solana wire-format against the real SDK, and add proactive
key refresh — so the codebase is no longer blocked on fundamental correctness issues.

**Sprint owner:** R7 PM Agent

---

## Gate Status

| Task | Agent | Branch | PM Approved | Implementation | R6 Verdict | Merged |
|------|-------|--------|-------------|----------------|------------|--------|
| T-01 | R1 | `agent/r1-zeroize` | ✓ | pending | pending | ✗ |
| T-02 | R1 | `agent/r1-zeroize` | ✓ | pending | pending | ✗ |
| T-05 | R0 | `agent/r0-interface` | ✓ | pending | pending | ✗ |
| T-06 | R3d | `agent/r3d-sui-followup` | ✓ | pending | pending | ✗ |
| T-07 | R3c | `agent/r3c-sol` | ✓ | pending | pending | ✗ |

---

## Task Specs

### Task Spec: T-01
- **Agent:** R1
- **Branch:** `agent/r1-zeroize`
- **Epic:** Epic J (Production Hardening)
- **Title:** Gate GG20 simulation behind `gg20-simulation` feature flag
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-core/src/protocol/gg20.rs`
  - `crates/mpc-wallet-core/Cargo.toml`
- **Acceptance Criteria:**
  - [ ] `Cargo.toml` declares `[features] gg20-simulation = []` and the feature is **off by default**
  - [ ] All code in `gg20.rs` that calls `lagrange_interpolate` (line 232) is wrapped in `#[cfg(feature = "gg20-simulation")]`
  - [ ] A `compile_error!` or prominent doc comment at the top of the `gg20-simulation`-gated block warns: `"SECURITY: SIMULATION ONLY — reconstructs full private key — NOT FOR PRODUCTION"`
  - [ ] When the feature is **disabled** (default), `cargo test -p mpc-wallet-core` still passes (the simulation code is absent; tests that test Shamir/Lagrange must also be gated or updated to be feature-gated)
  - [ ] When the feature is **enabled** (`cargo test -p mpc-wallet-core --features gg20-simulation`), all existing tests still pass
  - [ ] `cargo check -p mpc-wallet-core` passes without the feature (default)
- **Dependencies:** None — can start immediately
- **Complexity:** S

#### Security Checklist for R6
- [ ] Feature flag is **off by default** — verify in `Cargo.toml` that `gg20-simulation` is NOT listed under `default = [...]`
- [ ] The `lagrange_interpolate` function and its call site in `sign()` are entirely absent from the non-simulation build — confirm via `cargo check -p mpc-wallet-core` (no feature) that `lagrange_interpolate` does not appear
- [ ] The `#[cfg(feature = "gg20-simulation")]` gate wraps the entire reconstruction path — no partial gating that leaves the scalar accessible
- [ ] The simulation warning comment is prominent (top of gated block) and accurately describes the risk (full key reconstruction)
- [ ] `cargo audit` clean — no new advisories; no new dependencies added

---

### Task Spec: T-02
- **Agent:** R1
- **Branch:** `agent/r1-zeroize`
- **Epic:** Epic H (Key Lifecycle)
- **Title:** Add `EncryptedFileStore::touch(group_id)` for key refresh metadata tracking
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-core/src/key_store/encrypted.rs`
- **Acceptance Criteria:**
  - [ ] `EncryptedFileStore` has a new concrete method `pub async fn touch(&self, group_id: &KeyGroupId) -> Result<(), CoreError>`
  - [ ] `touch()` reads the existing `metadata.json` for the group, updates a `last_refreshed` field (unix timestamp as `u64`, obtained via `std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()`), and writes it back atomically (overwrite)
  - [ ] `KeyMetadata` in `key_store/types.rs` gains a new field `last_refreshed: Option<u64>` with `#[serde(default)]` so existing JSON files (without the field) continue to deserialize correctly — **NOTE: `types.rs` is owned by R0; R1 must NOT modify it. Instead R1 should write the `last_refreshed` value as a standalone JSON key alongside the `KeyMetadata` JSON, by reading the raw JSON as `serde_json::Value`, inserting the key, and writing back. This avoids touching R0-owned types.**
  - [ ] Alternative (preferred since it avoids R0 files): `touch()` writes a separate file `touch.json` containing `{"last_refreshed": <unix_u64>}` in the group directory — keeps all R0 types untouched
  - [ ] A unit test `test_touch_updates_timestamp` verifies: create a group (via `save()`), call `touch()`, read `touch.json`, verify `last_refreshed` is a non-zero u64 and is >= the `created_at` timestamp
  - [ ] No key material is read or decrypted during `touch()` — only metadata files are accessed
  - [ ] `cargo test -p mpc-wallet-core` passes
- **Dependencies:** None — `encrypted.rs` is R1's file; no trait change required
- **Complexity:** S

#### Security Checklist for R6
- [ ] `touch()` does **not** call `decrypt()` or access the `.enc` share file — verified by code inspection
- [ ] No key material (share bytes, password, derived key) is present in any variable created during `touch()`
- [ ] The timestamp written is obtained from `std::time::SystemTime` (not user-supplied input) — no injection risk
- [ ] `touch.json` does not contain any sensitive fields — only the `last_refreshed` timestamp
- [ ] `cargo audit` clean — no new dependencies added

---

### Task Spec: T-05
- **Agent:** R0
- **Branch:** `agent/r0-interface`
- **Epic:** Epic H (Key Lifecycle)
- **Title:** Add `freeze` / `unfreeze` to `KeyStore` trait + `CoreError::KeyFrozen`
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-core/src/key_store/mod.rs`
  - `crates/mpc-wallet-core/src/error.rs`
  - `crates/mpc-wallet-core/src/key_store/encrypted.rs`
- **Acceptance Criteria:**
  - [ ] `KeyStore` trait in `key_store/mod.rs` has two new async methods:
    ```rust
    async fn freeze(&self, group_id: &KeyGroupId) -> Result<(), CoreError>;
    async fn unfreeze(&self, group_id: &KeyGroupId) -> Result<(), CoreError>;
    ```
  - [ ] `CoreError::KeyFrozen(String)` variant added to `error.rs` with `#[error("key frozen: {0}")]`
  - [ ] `EncryptedFileStore` in `key_store/encrypted.rs` gets stub implementations: both `freeze` and `unfreeze` return `Ok(())` (no-op stubs; full implementation is deferred to a later sprint)
  - [ ] `cargo check --workspace` passes — all crates compile
  - [ ] `cargo test -p mpc-wallet-core` passes — no existing tests broken
- **Dependencies:** None — highest-priority interface change, must complete Day 1–2 to unblock dependent tasks
- **Complexity:** S

#### Security Checklist for R6
- [ ] Trait method signatures use `&self` (not `&mut self`) — consistent with the existing `KeyStore` API (`save`, `load`, `list`, `delete` all use `&self`)
- [ ] `CoreError::KeyFrozen(String)` error message does NOT include key share bytes, derived keys, or password material — only the `group_id` string or a safe descriptive message
- [ ] No implementation logic beyond `Ok(())` stubs in the trait-level default impls (if any) — logic belongs in `EncryptedFileStore`, not in trait defaults
- [ ] The `KeyFrozen` variant is additive — no existing `CoreError` variants are renamed, removed, or reordered (non-breaking change)
- [ ] `cargo audit` clean — no new dependencies added

---

### Task Spec: T-06
- **Agent:** R3d
- **Branch:** `agent/r3d-sui-followup`
- **Epic:** Epic J (Production Hardening)
- **Title:** Sui — add `build_transaction_with_sender` helper and sender address validation
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-chains/src/sui/tx.rs`
  - `crates/mpc-wallet-chains/src/sui/mod.rs`
- **Acceptance Criteria:**
  - [ ] `SuiProvider` gains a new `pub fn build_transaction_with_sender<'a>(&'a self, params: TransactionParams, sender: &str) -> impl Future<Output = Result<UnsignedTransaction, CoreError>> + 'a` method in `mod.rs` that takes the sender address explicitly (bypassing `extra["sender"]` lookup)
  - [ ] The `sender` parameter is validated: must start with `"0x"` and the hex portion (after `0x`) must decode to exactly 32 bytes (64 hex chars). Return `CoreError::InvalidInput` if validation fails.
  - [ ] The existing `build_transaction` (which reads `extra["sender"]`) continues to work unchanged — no regression
  - [ ] A unit test `test_build_transaction_with_sender_valid` verifies a valid 0x-prefixed 32-byte hex sender succeeds and the resulting `sign_payload` is 32 bytes (Blake2b-256)
  - [ ] A unit test `test_build_transaction_with_sender_rejects_invalid` verifies that a sender missing `"0x"` prefix returns `Err(CoreError::InvalidInput(...))`
  - [ ] A unit test `test_build_transaction_with_sender_rejects_wrong_length` verifies that a sender with `"0x"` prefix but incorrect hex length (not 64 hex chars) returns `Err(CoreError::InvalidInput(...))`
  - [ ] `cargo test -p mpc-wallet-chains` passes
- **Dependencies:** None — `sui/tx.rs` and `sui/mod.rs` are R3d's files; no R0-owned files touched
- **Complexity:** S

#### Security Checklist for R6
- [ ] Sender address validation rejects: missing `0x` prefix, hex decode failure, decoded length ≠ 32 bytes — all three cases tested
- [ ] Validation occurs **before** any transaction data is constructed — fail-fast, no partial state built with invalid sender
- [ ] The `extra["sender"]` path in the existing `build_transaction` is unchanged — no regression in the existing API
- [ ] No secret material (private key, share bytes) present in error messages or returned values
- [ ] `cargo audit` clean — no new dependencies added

---

### Task Spec: T-07
- **Agent:** R3c
- **Branch:** `agent/r3c-sol`
- **Epic:** Epic J (Production Hardening)
- **Title:** Solana — binary message round-trip validation test + fix `tx_hash` to full base58 signature
- **Files owned (agent may only touch these):**
  - `crates/mpc-wallet-chains/tests/chain_integration.rs`
  - `crates/mpc-wallet-chains/src/solana/tx.rs`
- **Source change (tx.rs — one line fix):**
  - [ ] Line 183: replace `let tx_hash = hex::encode(&signature[..8]);` with `let tx_hash = bs58::encode(signature).into_string();` — fixes SEC-010 (truncated tx hash)
- **New tests to add in `chain_integration.rs`:**
  - [ ] `test_solana_message_structure_num_required_sigs`: build a transaction, assert `sign_payload[0] == 1` (num_required_sigs header byte)
  - [ ] `test_solana_message_structure_account_keys_offset`: build a transaction, assert that bytes at offset 4 (after header 3 bytes + compact-u16(3)=1 byte) match the `from` public key bytes (32 bytes starting at index 4)
  - [ ] `test_solana_message_structure_three_accounts_present`: build a transaction, assert sign_payload length >= 3 (header) + 1 (compact-u16) + 96 (3×32 account keys) + 32 (blockhash) = 132 bytes minimum
  - [ ] `test_solana_encode_compact_u16_boundary_values`: test the compact-u16 encoding for values 0, 1, 127, 128, 16383 — assert correct byte sequences (`[0]`, `[1]`, `[0x7f]`, `[0x80, 0x01]`, `[0xff, 0x7f]`)
  - [ ] `test_solana_tx_hash_is_base58_full_signature`: build+finalize a transaction with a known 64-byte signature, assert `tx_hash` decodes from base58 to exactly 64 bytes matching the signature
  - [ ] `test_solana_zero_lamports_transaction`: build a transaction with `value: "0"`, assert it succeeds (zero lamports is valid)
  - [ ] `test_solana_same_from_to_address`: build a transaction where from == to (same 32-byte address), assert it succeeds (network-level restriction, not SDK-level)
- **Acceptance Criteria:**
  - [ ] All 7 new tests pass
  - [ ] `finalize_solana_transaction` `tx_hash` is now `bs58::encode(signature).into_string()` (full 64-byte signature base58-encoded)
  - [ ] All pre-existing Solana tests in `chain_integration.rs` still pass
  - [ ] `cargo test -p mpc-wallet-chains` passes
- **Dependencies:** None — `chain_integration.rs` and `solana/tx.rs` are in R3c's scope
- **Complexity:** S

#### Security Checklist for R6
- [ ] `tx_hash` in `SignedTransaction` is the **full** base58-encoded 64-byte signature — NOT the previous truncated 8-byte hex. Verify the fix resolves SEC-010: `hex::encode(&signature[..8])` must no longer appear anywhere in `tx.rs`
- [ ] `encode_compact_u16` boundary test covers value 128 (two-byte encoding threshold) — verifies no off-by-one that could corrupt message structure
- [ ] Zero-lamports test: verify no integer underflow or panic on `u64` value of 0
- [ ] Same from/to test: verify no panic or assertion failure when sender == recipient (array aliasing non-issue in Rust, but must confirm no validation incorrectly rejects it)
- [ ] No secret material present in `SignedTransaction` output — `tx_hash` is the public signature, `raw_tx` is the serialized transaction; no private key bytes
- [ ] `cargo audit` clean — no new dependencies added (bs58 is already in workspace)

---

## Blocked Tasks

| Task | Blocker | Owner | Resolution |
|------|---------|-------|------------|
| (none) | — | — | All 5 tasks are independent and can start in parallel. T-05 (R0) should be prioritized to unblock any future freeze/unfreeze implementation work. |

---

## Done (pre-Sprint 1, already on main)

The following tasks were completed and merged to `main` before Sprint 1 began.
They are tracked here for completeness. **No R6 gate re-audit required** (merged pre-gate-model).

| Agent | Task | Branch (merged) | Description |
|-------|------|-----------------|-------------|
| R1 | Pre-sprint zeroize | `agent/r1-zeroize` (pre-merge) | `ZeroizeOnDrop` on `Gg20ShareData`, `FrostEd25519ShareData`, `FrostSecp256k1ShareData` |
| R2 | NatsTransport stub | `agent/r2-nats` (pre-merge) | `NatsTransport` struct and `todo!()` stubs committed (full impl is T-TODO Sprint 2+) |
| R3a | EVM multi-network | `agent/r3a-evm` (pre-merge) | Polygon, BSC, Arbitrum, Base chain IDs added to `EvmProvider` |
| R3b | Bitcoin testnet | `agent/r3b-btc` (pre-merge) | Testnet/signet support added to `BitcoinProvider` |
| R3c | Solana binary serialization | `agent/r3c-sol` (pre-merge) | Manual wire-format serialization replacing JSON stub |
| R3d | Sui cleanup | `agent/r3d-sui-followup` (pre-merge) | Initial Sui provider scaffolding |

---

## Sprint Notes

- **T-01 and T-02 both assigned to R1** on the same branch `agent/r1-zeroize`. R1 should do T-01 first (feature flag), then T-02 (touch method), then commit each separately per checkpoint protocol.
- **T-05 (R0) has no blockers** and should be completed first — it unblocks any future freeze/unfreeze work and is the smallest task in the sprint.
- **T-06 (R3d) and T-07 (R3c)** can work in parallel — no shared files.
- **R6 gate:** R6 must issue APPROVED verdict for each task branch before it can merge to main.
- **No branch merges without R6 APPROVED** — enforced per the Sprint Gate Model in AGENTS.md.
- **No new crate dependencies** are required for any Sprint 1 task. `bs58` is already in the workspace (used in `solana/tx.rs`).

---

## Execution Order

All 5 tasks are independent and can run in parallel. Recommended priority:

```
Day 1:  R0 → T-05 (small, unblocks future work)
Day 1:  R1 → T-01 (feature flag — preparatory for Sprint 2 real GG20)
Day 1:  R3d → T-06 (Sui sender validation helper)
Day 1:  R3c → T-07 (Solana round-trip test + tx_hash fix)

Day 2:  R1 → T-02 (touch method, after T-01 lands on same branch)

Day 3+: R6 audits each branch as agents report complete
```

---

# Sprint 2 — 2026-03-30 → 2026-04-13

## Goal
**"Distributed signing without key reconstruction + password security + Sui BCS + CI"**

Resolve SEC-001 CRITICAL by implementing additive-share-based distributed ECDSA signing
(the full private key is never assembled on any party). Also resolve SEC-002 (demo-password),
advance Sui BCS serialization (SEC-011), and wire up the CI pipeline.

**Sprint owner:** R7 PM Agent  
**Sprint dates:** 2026-03-30 → 2026-04-13

---

## Why These Are Hard Goals

| Finding | Severity | Why It Blocks |
|---------|----------|---------------|
| SEC-001 | CRITICAL | GG20 sign() reconstructs full private key — negates MPC guarantee entirely |
| SEC-002 | CRITICAL | Hardcoded "demo-password" fallback silently encrypts key shares with a known string |
| SEC-011 | MEDIUM   | Sui tx uses JSON instead of BCS — rejected by all Sui nodes |

---

## Execution Order

```
Wave 1 (first — blocks Wave 2):
  T-S2-00  R0   agent/r0-s2-prep       (add bcs + rpassword deps, PasswordRequired error)

Wave 2 (after T-S2-00 merges — all parallel):
  T-S2-01  R1   agent/r1-real-gg20     (distributed signing, resolves SEC-001)
  T-S2-03  R4   agent/r4-cli-password  (remove demo-password, resolves SEC-002)
  T-S2-04  R3d  agent/r3d-sui-bcs      (Sui BCS encoding, advances SEC-011)
  T-S2-05  R5   agent/r5-ci            (CI pipeline — no code deps, can run in parallel with Wave 1)
```

**T-S2-05 (R5) has no source-code dependency** and may be started immediately in parallel with
T-S2-00. All other Wave 2 tasks must wait for T-S2-00 to be merged first.

---

## Gate Status (Sprint 2)

| Task | Agent | Branch | PM Approved | R6 Verdict | Merged | Resolves |
|------|-------|--------|-------------|------------|--------|----------|
| T-S2-00 | R0 | `agent/r0-s2-prep` | ✓ | pending | ✗ | Unblocks T-S2-01, T-S2-03, T-S2-04 |
| T-S2-01 | R1 | `agent/r1-real-gg20` | ✓ | pending | ✗ | SEC-001 CRITICAL |
| T-S2-03 | R4 | `agent/r4-cli-password` | ✓ | pending | ✗ | SEC-002 CRITICAL |
| T-S2-04 | R3d | `agent/r3d-sui-bcs` | ✓ | pending | ✗ | SEC-011 MEDIUM |
| T-S2-05 | R5 | `agent/r5-ci` | ✓ | pending | ✗ | CI infrastructure |

---

## Task Specs

---

### Task Spec: T-S2-00
- **Agent:** R0 (Architect)
- **Branch:** `agent/r0-s2-prep`
- **Epic:** Epic J (Production Hardening)
- **Title:** Add `bcs` + `rpassword` workspace deps and `CoreError::PasswordRequired` variant
- **Complexity:** S
- **Must complete before:** T-S2-01, T-S2-03, T-S2-04

#### Files owned (agent may ONLY modify these — nothing else)
```
Cargo.toml                                               ← workspace [workspace.dependencies]
crates/mpc-wallet-core/Cargo.toml                        ← add rpassword to [dependencies]
crates/mpc-wallet-core/src/error.rs                      ← add PasswordRequired variant
```

#### Context
- `bcs = "0.1"` is needed by T-S2-04 (R3d Sui BCS encoding)
- `rpassword = "7"` is needed by T-S2-03 (R4 CLI password prompt) — add to workspace deps
  so R4 can opt-in in `mpc-wallet-cli/Cargo.toml`. R0 does NOT add it to core's deps (CLI only).
- `CoreError::PasswordRequired` is a new error variant needed by T-S2-03
- `bcs` should be added to workspace deps AND to `mpc-wallet-chains/Cargo.toml`
  (R3d will use it in that crate)

#### Acceptance Criteria
- [ ] `Cargo.toml` `[workspace.dependencies]` gains:
  ```toml
  bcs = "0.1"
  rpassword = "7"
  ```
- [ ] `crates/mpc-wallet-chains/Cargo.toml` gains `bcs = { workspace = true }` in `[dependencies]`
- [ ] `crates/mpc-wallet-core/src/error.rs` gains:
  ```rust
  #[error("password required: {0}")]
  PasswordRequired(String),
  ```
  as a new variant (additive — no existing variants modified or reordered)
- [ ] `cargo check --workspace` passes after all three changes
- [ ] `cargo test --workspace` still passes (no regressions)
- [ ] `cargo audit` run and output reviewed — no new CRITICAL/HIGH advisories from `bcs` or `rpassword`

#### Security Checklist for R6
- [ ] `bcs = "0.1"` license check: verify Apache-2.0 or MIT compatible with workspace MIT license
- [ ] `rpassword = "7"` license check: same
- [ ] `cargo audit` output after adding both crates: zero new CRITICAL or HIGH advisories
- [ ] `CoreError::PasswordRequired(String)` message template does NOT include the password value itself — only a descriptive hint like `"--password flag is required"`. Verify the string in the variant is a message, not the password.
- [ ] `PasswordRequired` is additive — no existing `CoreError` variants renamed, removed, or reordered (non-breaking)
- [ ] No existing tests broken by the new variant — `cargo test --workspace` green

---

### Task Spec: T-S2-01
- **Agent:** R1 (Crypto)
- **Branch:** `agent/r1-real-gg20`
- **Epic:** Epic J (Production Hardening)
- **Title:** Distributed ECDSA signing — no key reconstruction (resolves SEC-001)
- **Complexity:** L
- **Depends on:** T-S2-00 merged (for new feature flag; no new crate dep needed — `k256` already present)

#### Files owned (agent may ONLY modify these — nothing else)
```
crates/mpc-wallet-core/src/protocol/gg20.rs              ← primary impl file
crates/mpc-wallet-core/Cargo.toml                        ← add gg20-distributed feature
```

#### Context: What the current code does (the problem)

The existing `sign()` under `#[cfg(feature = "gg20-simulation")]` (lines 227–306 of `gg20.rs`):
1. Every party broadcasts their Shamir share `(x_i, y_i)` to all others
2. Every party collects all shares
3. Every party calls `lagrange_interpolate(&collected_shares)` → reconstructs **full private key** `x`
4. Every party signs directly with `x`

This is the simulation — every signer learns the full key. This is what SEC-001 prohibits.

#### What T-S2-01 must implement: Additive-share distributed signing

**Key insight:** Convert Shamir shares to additive shares, then use partial signing.

**Keygen changes (trusted dealer — Party 1):**

Party 1 currently generates Shamir shares `(i, f(i))` where `f(0) = x` (the secret).
Party 1 must now **convert to additive shares** before distributing:

```
For each party i with Shamir share (i, y_i):
  lambda_i = lagrange_coefficient(i, all_party_indices, x=0)
           = product_{j ≠ i} (-j) / (i - j)   [evaluated at 0]
  additive_share_i = lambda_i * y_i   (scalar multiplication mod curve order)
```

Party `i` receives `x_i_add = lambda_i * y_i`. These are additive shares:
```
sum_i(x_i_add) = sum_i(lambda_i * y_i) = x   (the secret)
```

But we will **never compute this sum during signing**.

Party 1 sends each party their `x_i_add` (a 32-byte scalar). Party 1 keeps its own `x_1_add`.

Store `x_i_add` as the `share_data` for each party (replaces old `Gg20ShareData { x, y }`):

```rust
#[cfg(feature = "gg20-distributed")]
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
struct Gg20DistributedShareData {
    /// Additive share scalar: lambda_i * y_i (32 bytes, big-endian)
    additive_share: Vec<u8>,
}
```

**Sign changes — the distributed protocol:**

Given: each party `i` holds `x_i_add` (their additive share, a `k256::Scalar`).
Goal: produce ECDSA signature `(r, s)` where `s = k^{-1}(hash + x*r) mod n`
without any party computing `x`.

Step 1 — Each party generates a per-session nonce `k_i`:
```rust
let k_i: Scalar = Scalar::random(&mut rand::thread_rng());
```

Step 2 — Each party computes and broadcasts `R_i = k_i * G` (a curve point, 33 bytes compressed):
```rust
let R_i: ProjectivePoint = ProjectivePoint::GENERATOR * k_i;
// serialize to 33 bytes compressed and broadcast via transport.send(...)
```

Step 3 — Each party collects all `R_j` points. The aggregated nonce point is:
```rust
let R: ProjectivePoint = R_i_values.iter().fold(ProjectivePoint::IDENTITY, |acc, p| acc + p);
let r_affine = R.to_affine();
// r = x-coordinate of R mod n
let r: Scalar = r_from_affine_x(&r_affine);  // see helper below
```

Step 4 — Each party computes their partial signature `s_i`:
```rust
// hash = keccak256 or sha256 of message, as Scalar
let hash_scalar: Scalar = scalar_from_hash(message);
// k_i_inv = modular inverse of k_i
let k_i_inv: Scalar = k_i.invert().expect("nonce cannot be zero");
// s_i = k_i^{-1} * (hash + x_i_add * r)
let s_i: Scalar = k_i_inv * (hash_scalar + x_i_add * r);
// broadcast s_i (32 bytes) to aggregator via transport.send(...)
```

Step 5 — Aggregator (any party, or the first party) collects all `s_j` and sums:
```rust
// s = sum_i(s_i)
// Note: x = sum(x_i_add), so x*r = sum(x_i_add)*r
// and sum(s_i) = sum(k_i^{-1}) * hash + sum(k_i^{-1} * x_i_add * r)
// BUT: sum(s_i) ≠ k^{-1}(hash + x*r) in general unless k = 1/sum(k_i^{-1})
```

**⚠️ IMPORTANT — Mathematical correctness note:**

The naive sum `s = sum(s_i)` does NOT equal `k^{-1}(hash + x*r)` because
`1/sum(k_i) ≠ sum(1/k_i)` in general.

**The correct approach is multiplicative nonce sharing:**

Instead of summing nonces, use the following two-round nonce protocol:

**Round 1 (nonce commitment):**
- Each party `i` samples `k_i` and `gamma_i` (two random scalars)
- Broadcasts `Gamma_i = gamma_i * G`

**Round 2 (nonce aggregation):**
- Compute `Gamma = sum(Gamma_i)`, get `r = x_coord(Gamma) mod n`
- Each party computes `delta_i = k_i * gamma_i` and broadcasts it
- Aggregator computes `delta = sum(delta_i)` and `delta_inv = delta^{-1}`
- Note: `delta = sum(k_i * gamma_i)` and the combined nonce is `k = sum(k_i) * delta_inv`

This becomes complex. **Use the simpler correct approach for Sprint 2:**

**Simplified correct approach — single aggregator model:**

Since keygen already uses a trusted dealer (Party 1 generates `x`), we can use a
**semi-honest aggregator** model for signing as well, which avoids the nonce-inversion problem:

The aggregator (Party 1) handles nonce coordination:

1. Aggregator samples a single session nonce `k` (random scalar)
2. Aggregator computes `R = k * G`, broadcasts `R` and `r = x_coord(R) mod n` to all parties
3. Each party `i` computes partial signature:
   ```
   s_i = k^{-1} * (hash + x_i_add * r)
   ```
   using the `k^{-1}` value broadcast by the aggregator (or each party can compute it from `k` if
   the aggregator broadcasts `k` — but this leaks `k`).

**The cleanest implementation for Sprint 2:**

Use the fact that additive shares let us split the signing equation linearly:
```
s = k^{-1} * (hash + x * r)
  = k^{-1} * hash + k^{-1} * x * r
  = k^{-1} * hash + k^{-1} * r * sum_i(x_i_add)
  = k^{-1} * hash + sum_i(k^{-1} * r * x_i_add)
```

Protocol:
1. Aggregator (Party 1) generates `k`, computes `R = k*G`, `r = x_coord(R) mod n`, `k_inv = k^{-1}`
2. Aggregator broadcasts `(r, k_inv)` to all parties (NOTE: broadcasting `k_inv` is safe — it's
   a per-session ephemeral value, not the private key; knowledge of `k_inv` alone doesn't reveal `x`)
3. Each party `i` computes:
   ```rust
   // hash_scalar = sha256(message) interpreted as Scalar
   let s_i = k_inv * (hash_scalar + x_i_add * r);
   // send s_i to aggregator
   ```
4. Aggregator sums: `s = sum_i(s_i) = k_inv * (n_parties * hash + x * r)`

**⚠️ This is STILL WRONG** because summing partial sigs with the same `k_inv` and `hash` gives:
`sum(s_i) = k_inv * sum(hash + x_i_add * r) = k_inv * (n*hash + x*r)` which ≠ `k_inv*(hash + x*r)`.

**FINAL CORRECT APPROACH for Sprint 2 — "Additive shares, one-shot keygen, aggregator signs":**

The mathematically sound implementation that avoids key reconstruction:

- During keygen: Party 1 generates `x` and distributes additive shares `x_i_add` such that `sum(x_i_add) = x`.
  The simplest split: randomly generate `x_1, x_2, ..., x_{n-1}` and set `x_n = x - sum(x_1..x_{n-1})`.
  This is truly additive (NOT Shamir-based).

- During sign: Use the MtA (Multiplicative-to-Additive) conversion pattern. BUT for Sprint 2,
  use the **centralized nonce** approach that is provably correct:

  1. All parties send their additive share `x_i_add` as `s_i_partial = x_i_add * r * k_inv`
     where `k_inv` is provided by the aggregator (Party 1).
     Each `s_i_partial` is: `x_i_add * r * k_inv`
  2. The hash contribution is handled by ONE party (aggregator):
     `s_hash = hash_scalar * k_inv`
  3. Final: `s = s_hash + sum_i(s_i_partial) = k_inv * hash + k_inv * r * sum_i(x_i_add) = k_inv * (hash + x*r)`
     This is exactly the ECDSA equation. ✓

  The full `x = sum(x_i_add)` is **never computed**. The aggregator computes:
  - `s_hash = hash * k_inv` using no key material
  - `s = s_hash + sum_i(s_i_partial)` — just scalar addition

  The per-party computation `x_i_add * r * k_inv` uses only the party's own additive share.
  No party ever sees another party's additive share.

#### Concrete Implementation Spec

**Data structures:**
```rust
#[cfg(feature = "gg20-distributed")]
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
struct Gg20DistributedShareData {
    /// This party's additive share of the private key x (32-byte BE scalar).
    /// All parties' shares sum to x: sum_i(additive_share_i) = x.
    /// x is never reconstructed during signing.
    additive_share: Vec<u8>,
    /// Total number of parties (needed to know how many partial sigs to collect)
    total_parties: u16,
    /// This party's index (1-indexed)
    party_index: u16,
}
```

**Keygen (trusted dealer — Party 1 only):**
```rust
// Party 1:
let x: Scalar = Scalar::random(&mut rng);
let pub_point = ProjectivePoint::GENERATOR * x;
// ... derive group_pubkey from pub_point ...

// Generate additive shares: random split
let n = config.total_parties as usize;
let mut shares: Vec<Scalar> = (0..n-1).map(|_| Scalar::random(&mut rng)).collect();
let last_share = x - shares.iter().fold(Scalar::ZERO, |acc, s| acc + s);
shares.push(last_share);
// shares[i] is the additive share for party (i+1)
// sum(shares) == x  ← this sum is NEVER computed after this point

// Distribute: send shares[i] to party (i+1), keep shares[0] for party 1
for (i, share) in shares.iter().enumerate() {
    let target = PartyId(i as u16 + 1);
    if target == party_id { continue; }
    // serialize and send via transport
}
```

**Sign:**
```rust
// All parties receive: (r, k_inv) from aggregator (Party 1)
// Step 1: Party 1 generates k, computes R, r, k_inv and broadcasts to all
// Step 2: Each party i computes:
//   s_i_partial = x_i_add * r * k_inv   (no hash involvement — only key contribution)
// Step 3: Each party broadcasts s_i_partial to Party 1 (aggregator)
// Step 4: Party 1 computes:
//   s_hash = hash_scalar * k_inv
//   s = s_hash + sum_i(s_i_partial)
//   return (r, s)
```

**Transport rounds:**
- Round 1: Party 1 → all: broadcast `(r_bytes: [u8;32], k_inv_bytes: [u8;32])`
- Round 2: All parties → Party 1: send `s_i_partial_bytes: [u8;32]`
- Party 1 aggregates and returns final `(r, s)`

**Feature flag:**
- New feature: `gg20-distributed = []` in `mpc-wallet-core/Cargo.toml`
- `default = ["gg20-distributed"]` — distributed signing is ON by default
- `gg20-simulation` remains available as opt-in for comparison tests
- When `gg20-distributed` feature is active, the `#[cfg(not(feature = "gg20-simulation"))]`
  production stub is replaced by the real distributed impl

Specifically: Add a third cfg branch:
```
#[cfg(feature = "gg20-simulation")]          → simulation (unchanged)
#[cfg(feature = "gg20-distributed")]          → new distributed impl (this task)
#[cfg(not(any(feature = "gg20-simulation", feature = "gg20-distributed")))]
                                              → error stub (returns Err)
```

#### Acceptance Criteria
- [ ] New feature `gg20-distributed` declared in `mpc-wallet-core/Cargo.toml` under `[features]`
- [ ] `default = ["gg20-distributed"]` set in `mpc-wallet-core/Cargo.toml`
- [ ] `gg20-simulation` remains as a separate non-default feature (no regression)
- [ ] `gg20.rs`: `sign()` under `gg20-distributed` feature NEVER calls `lagrange_interpolate` and NEVER assembles the sum `sum(additive_shares)` — full private key `x` does not exist as a variable anywhere in the distributed sign path
- [ ] `keygen()` under `gg20-distributed` generates proper additive shares (random split summing to `x`); the secret scalar `x` is zeroized (wrapped in `Zeroizing<Scalar>`) immediately after shares are generated and sent
- [ ] 2-of-2 signing test: two parties each hold an additive share; signing produces a valid secp256k1 ECDSA signature verifiable with `k256::ecdsa::VerifyingKey::verify`
- [ ] 3-party signing test: three parties each hold an additive share; signing produces valid ECDSA signature
- [ ] `k_inv` broadcast by aggregator: document in code comments that `k_inv` is an ephemeral per-session value. Confirm it is NOT the private key or any derivation of it.
- [ ] All existing tests pass: `cargo test -p mpc-wallet-core` (default features = gg20-distributed)
- [ ] `cargo test -p mpc-wallet-core --features gg20-simulation` still passes
- [ ] `cargo test -p mpc-wallet-core --no-default-features` compiles (error stub path)

#### Security Checklist for R6
- [ ] **SEC-001 resolved:** Full private key scalar `x` MUST NOT appear as a named variable in the `gg20-distributed` sign path. Search `gg20.rs` for any call to `lagrange_interpolate` in the distributed path — must be zero.
- [ ] **Additive share sum never computed during signing:** verify no code in the sign path computes `sum(additive_share_i)` or any equivalent reconstruction. The only place additive shares are summed is conceptually at keygen (Party 1 knows `x`); after share distribution, `x` is zeroized.
- [ ] **Secret `x` zeroized at keygen:** confirm `x: Scalar` in Party 1's keygen path is wrapped in `Zeroizing<Scalar>` or explicitly zeroized after shares are generated and before any `.await`
- [ ] **`k_inv` is ephemeral:** confirm `k_inv` is generated fresh per signing session (not reused). Each call to `sign()` generates a new `k`.
- [ ] **Nonce `k` not zero:** confirm code has `assert!(!bool::from(k.is_zero()))` or equivalent before computing `k_inv` to prevent panic on invert
- [ ] **Partial sig `s_i_partial` does not leak additive share:** `s_i_partial = x_i_add * r * k_inv`. Confirm `x_i_add` itself is NOT broadcast — only the product is sent. Code inspection required.
- [ ] **`ZeroizeOnDrop` on `Gg20DistributedShareData`:** verify the `ZeroizeOnDrop` derive is present on the new share data struct
- [ ] **`gg20-distributed` default ON, simulation OFF:** verify `Cargo.toml` `default = ["gg20-distributed"]` and `gg20-simulation` is NOT in default
- [ ] **Tests verify cryptographic correctness:** at least one test calls `k256::ecdsa::VerifyingKey::verify` on the output signature against the group public key
- [ ] `cargo audit` clean — no new dependencies added (k256, rand already present)

---

### Task Spec: T-S2-03
- **Agent:** R4 (Service)
- **Branch:** `agent/r4-cli-password`
- **Epic:** Epic J (Production Hardening)
- **Title:** Remove hardcoded "demo-password" fallback from all CLI commands (resolves SEC-002)
- **Complexity:** S
- **Depends on:** T-S2-00 merged (for `rpassword` workspace dep and `CoreError::PasswordRequired`)

#### Files owned (agent may ONLY modify these — nothing else)
```
crates/mpc-wallet-cli/src/commands/keygen.rs
crates/mpc-wallet-cli/src/commands/sign.rs
crates/mpc-wallet-cli/src/commands/address.rs
crates/mpc-wallet-cli/src/commands/keys.rs
crates/mpc-wallet-cli/Cargo.toml                         ← add rpassword = { workspace = true }
```

#### Context: What to replace

All four files currently contain:
```rust
let password = args.password.clone().unwrap_or_else(|| "demo-password".into());
```
(or a close variant). This must be entirely removed.

#### What to implement

Make `--password` a **required** clap argument by changing the `Option<String>` type in the
`Args` struct to `String` (removing `Option`). This is the simplest, safest approach:
- No new `rpassword` dep needed if prompt isn't required (but add it as a dep anyway per T-S2-00 so it's available for future interactive use)
- No `unwrap_or_else` possible when the type is `String` not `Option<String>`
- If `--password` is omitted, clap will print an error and exit — fail-fast, user-visible

Alternatively (if the Args struct uses `Option<String>` for other reasons), change to:
```rust
let password = args.password.clone().ok_or_else(|| {
    CoreError::PasswordRequired("--password flag is required".into())
})?;
```
using the new `CoreError::PasswordRequired` variant from T-S2-00.

**Do NOT use `rpassword` for interactive prompting in this sprint** — the simpler required-arg
approach is sufficient for SEC-002 resolution and avoids the complexity of interactive TTY handling.
Interactive prompting is tracked for a future sprint.

#### Acceptance Criteria
- [ ] `keygen.rs`: no `unwrap_or_else(|| "demo-password"...)` or `unwrap_or("demo-password"...)` anywhere
- [ ] `sign.rs`: same — zero occurrences of the hardcoded string
- [ ] `address.rs`: same
- [ ] `keys.rs`: same
- [ ] `crates/mpc-wallet-cli/Cargo.toml` adds `rpassword = { workspace = true }` to `[dependencies]`
- [ ] When `--password` is omitted, the CLI exits with a clear error (clap error if required arg, or `CoreError::PasswordRequired` if option-based) — NOT silently using "demo-password"
- [ ] `cargo test -p mpc-wallet-cli` passes (update any tests that used the implicit "demo-password" to pass `--password test-password` explicitly)
- [ ] `cargo build -p mpc-wallet-cli` succeeds
- [ ] `grep -r "demo-password" crates/mpc-wallet-cli/` returns zero results

#### Security Checklist for R6
- [ ] **SEC-002 resolved:** `grep -r "demo-password" crates/mpc-wallet-cli/src/` MUST return zero results. Check all 4 command files exhaustively.
- [ ] **No new fallback introduced:** confirm no other `unwrap_or_else`, `unwrap_or`, or `if password.is_empty()` blocks introduce a different default password
- [ ] **`--password` arg is either `String` (required) or handled with `CoreError::PasswordRequired`:** verify `Option<String>` is not silently `.unwrap()`ed anywhere in the new code
- [ ] **Test passwords use a clearly named constant:** if any test file uses a password string, it must be a named constant (e.g., `const TEST_PASSWORD: &str = "test-only-not-for-prod";`) not an inline `"demo-password"` or similar
- [ ] **`rpassword` added but not yet used for prompting:** confirm `rpassword` is in `Cargo.toml` but no live code calls `rpassword::prompt_password` yet (that's a future task) — this avoids accidental broken interactive paths
- [ ] `cargo audit` clean — `rpassword` and its deps have no CRITICAL advisories

---

### Task Spec: T-S2-04
- **Agent:** R3d (Sui Chain)
- **Branch:** `agent/r3d-sui-bcs`
- **Epic:** Epic J (Production Hardening)
- **Title:** Replace JSON tx_data with BCS-encoded TransactionData for Sui (advances SEC-011)
- **Complexity:** M
- **Depends on:** T-S2-00 merged (for `bcs` workspace dep in `mpc-wallet-chains/Cargo.toml`)

#### Files owned (agent may ONLY modify these — nothing else)
```
crates/mpc-wallet-chains/src/sui/tx.rs
crates/mpc-wallet-chains/src/sui/mod.rs
crates/mpc-wallet-chains/Cargo.toml                      ← bcs added by T-S2-00, just use it
```

#### Context: What exists today

`build_sui_transaction` in `sui/tx.rs` (lines 85–113) currently builds a canonical JSON blob
as `tx_data`. The sign_payload computation (Blake2b-256 of intent_prefix || tx_data) is
correct per the Sui spec — only the serialization of `tx_data` needs to change from JSON to BCS.

The `finalize_sui_transaction` (lines 124–183) currently:
1. Parses `tx_data` as JSON to recover the embedded pubkey hex
2. Builds the 97-byte Sui signature `[0x00 || sig(64) || pubkey(32)]`

Both functions must be updated when the serialization format changes.

#### Sui BCS TransactionData format (minimal implementation)

Sui's `TransactionData` is complex in full production. For Sprint 2, implement a
**minimal BCS-encoded transfer** sufficient to produce a valid Sui transfer transaction.

The Sui TransactionData for a simple SUI coin transfer (programmable transaction) has this structure:
```
TransactionData::V1 {
    kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
        inputs: [CallArg::Pure(bcs(amount_u64)), CallArg::Pure(bcs(recipient_address))],
        commands: [Command::TransferObjects(vec![Argument::Result(0)], Argument::Input(1))]
        // NOTE: this is a simplification; full SUI transfer uses SplitCoins + TransferObjects
    }),
    sender: SuiAddress (32 bytes),
    gas_data: GasData { ... },
    expiration: TransactionExpiration::None,
}
```

This is quite involved. **For Sprint 2, implement the following pragmatic approach:**

Since BCS is a simple format (see spec below), implement a **minimal BCS serializer** for
the exact Sui transfer transaction structure, rather than a full generic BCS library.

**BCS encoding rules (sufficient subset):**
- `u64`: 8 bytes little-endian
- `u8`: 1 byte
- `[u8; 32]` (address): 32 bytes as-is
- `Vec<T>` / sequence: ULEB128 length prefix, then each element
- `enum` variant: ULEB128 variant index, then payload
- `bool`: 1 byte (0 or 1)
- `Option<T>`: `0u8` for None, `1u8` followed by T for Some

**Minimal Sui ProgrammableTransaction for SUI transfer:**

The following byte layout is sufficient for a valid SUI coin transfer payload
that Sui nodes will accept (modulo gas object, which is a known limitation):

```rust
// Instead of implementing full TransactionData BCS, implement:
// A "SuiTransferPayload" struct that BCS-encodes the essential fields
// and can be used as tx_data for signing and broadcasting.

// Use the `bcs` crate: bcs::to_bytes(&value) for any Serde-serializable struct
// The bcs crate handles ULEB128, LE integers, etc. automatically.

#[derive(Serialize)]
struct SuiTransferTxData {
    sender: [u8; 32],
    recipient: [u8; 32],
    amount: u64,
    // Gas budget placeholder — required by Sui protocol
    gas_budget: u64,
    // Gas price placeholder
    gas_price: u64,
}
```

Use `bcs::to_bytes(&tx_data_struct)` to produce the BCS bytes.

NOTE: This is still a simplification of full Sui TransactionData, but it:
1. Uses real BCS encoding (not JSON)
2. Will sign correct bytes
3. Moves towards SEC-011 resolution

The `finalize_sui_transaction` must be updated to NOT parse JSON for the pubkey.
Instead: embed the pubkey as the LAST 32 bytes of `tx_data` (or store it separately
in a new struct), so finalize can recover it without JSON parsing.

Recommended approach:
```rust
// tx_data layout: BCS(SuiTransferTxData) || pubkey(32 bytes)
// finalize recovers pubkey as: &tx_data[tx_data.len()-32..]
// This avoids any JSON dependency in tx_data
```

Document this layout clearly in the code with a comment:
```rust
// tx_data layout: [BCS-encoded SuiTransferTxData][pubkey: 32 bytes]
// The pubkey suffix is NOT part of the Sui protocol tx_data —
// it is an SDK-internal convention for key recovery in finalize().
// TODO(production): Replace with proper Sui TransactionData BCS once
// full gas coin management is implemented.
```

#### Acceptance Criteria
- [ ] `build_sui_transaction` no longer uses `serde_json::json!()` for `tx_data` construction
- [ ] `tx_data` bytes are produced by `bcs::to_bytes()` (or manual BCS if `bcs` crate has compatibility issues)
- [ ] `sign_payload` computation is unchanged: `Blake2b-256(SUI_INTENT_PREFIX || tx_data_without_pubkey_suffix)` — the 32-byte pubkey suffix is NOT included in the bytes that are hashed for signing (it's appended AFTER hashing, for internal recovery use only)
- [ ] `finalize_sui_transaction` does NOT call `serde_json::from_slice` on `tx_data` — pubkey is recovered via the 32-byte suffix convention
- [ ] All existing Sui tests in `chain_integration.rs` pass
- [ ] New test `test_sui_tx_data_is_not_json`: assert that `tx_data[..1]` is NOT `b'{'` (i.e., not JSON)
- [ ] New test `test_sui_sign_payload_is_32_bytes`: assert `sign_payload.len() == 32`
- [ ] New test `test_sui_finalize_produces_97_byte_sig`: assert `raw_tx` decodes to a Sui sig of exactly 97 bytes, with `raw_tx["signature"]` hex decoding to `[0x00, sig(64), pubkey(32)]`
- [ ] `cargo test -p mpc-wallet-chains` passes
- [ ] `cargo build -p mpc-wallet-chains` with BCS dep passes

#### Security Checklist for R6
- [ ] **SEC-011 advanced:** `tx_data` must not be JSON — verify `serde_json::json!()` no longer appears in `build_sui_transaction`. `grep` for `serde_json::json` in `sui/tx.rs` must return zero results after this task.
- [ ] **sign_payload hashes only the transaction bytes, not the pubkey suffix:** confirm the 32-byte pubkey is appended to `tx_data` AFTER the hashing step. The `Blake2b-256(intent_prefix || tx_data_bcs_only)` call must NOT include the pubkey suffix bytes.
- [ ] **Pubkey recovery from suffix is bounds-checked:** confirm `finalize_sui_transaction` validates `unsigned.tx_data.len() >= 32` before slicing `[len-32..]` — prevents panic on malformed input
- [ ] **BCS encoding of address bytes:** confirm sender/recipient `[u8; 32]` are encoded as raw bytes (no ULEB128 length prefix for fixed-size arrays in BCS) — verify against BCS spec
- [ ] **No secret material in `tx_data`:** pubkey (32 bytes) is public; `tx_data` contains only sender address (public), recipient (public), amount (public), gas params (public). No private key bytes.
- [ ] Existing 97-byte signature format test still passes — `[0x00 || sig(64) || pubkey(32)]`
- [ ] `cargo audit` clean — `bcs` crate has no CRITICAL advisories

---

### Task Spec: T-S2-05
- **Agent:** R5 (QA)
- **Branch:** `agent/r5-ci`
- **Epic:** Epic I (Multi-cloud Ops) / Infrastructure
- **Title:** Set up GitHub Actions CI pipeline
- **Complexity:** S
- **Depends on:** Nothing — can start immediately, no source-code dependencies

#### Files owned (agent may ONLY modify/create these — nothing else)
```
.github/workflows/ci.yml                                 ← new file (create)
```

#### Context

There is currently no CI. Every merge is unverified by automation. The CI must run:
1. `cargo fmt --check` — enforces formatting
2. `cargo clippy -- -D warnings` — enforces lint cleanliness
3. `cargo test --workspace` — runs all 42+ tests
4. `cargo audit` — catches known CVEs in dependencies

The pipeline must pass on `main` after Sprint 2 merges, and must gate all future PRs.

#### Acceptance Criteria
- [ ] `.github/workflows/ci.yml` exists with a job named `ci` (or similar)
- [ ] Job triggers on: `push` to `main`, `pull_request` targeting `main`
- [ ] Runs on: `ubuntu-latest`
- [ ] Uses Rust toolchain: `stable` via `dtolnay/rust-toolchain@stable`
- [ ] Uses `Swatinem/rust-cache@v2` for dependency caching (reduces CI time significantly)
- [ ] Step 1: `cargo fmt --check` — fails if code is not formatted
- [ ] Step 2: `cargo clippy --workspace -- -D warnings` — fails on any warning
- [ ] Step 3: `cargo test --workspace` — must pass all tests
- [ ] Step 4: `cargo audit` — install via `cargo install cargo-audit --locked` (cached), then run
- [ ] All steps use the same `ubuntu-latest` runner
- [ ] `cargo test --workspace` step does NOT enable `gg20-simulation` feature (default features only — distributed signing must work without it)
- [ ] The workflow file is valid YAML (verified by `yamllint` or similar, or just careful review)

#### Example structure (adapt as needed)
```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  ci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - name: fmt
        run: cargo fmt --check
      - name: clippy
        run: cargo clippy --workspace -- -D warnings
      - name: test
        run: cargo test --workspace
      - name: audit
        run: |
          cargo install cargo-audit --locked
          cargo audit
```

#### Security Checklist for R6
- [ ] `cargo audit` step is present and runs AFTER test — confirms dependency vulnerability scanning is part of every CI run
- [ ] `gg20-simulation` feature is NOT enabled in the `cargo test` step — the dangerous simulation path is not the default test target
- [ ] No secrets, tokens, or credentials present in the workflow file
- [ ] `actions/checkout@v4` pinned to a major version tag (v4), not `@main` or `@latest` — avoids supply-chain risk from unpinned action refs
- [ ] `cargo clippy -- -D warnings` treats all warnings as errors — prevents lint debt accumulation
- [ ] No `continue-on-error: true` on the audit step — a new CRITICAL advisory must fail the build

---

## Blocked Tasks

| Task | Blocker | Resolution |
|------|---------|------------|
| T-S2-01 | T-S2-00 must merge first | R0 completes Wave 1; Wave 2 agents start after |
| T-S2-03 | T-S2-00 must merge first | same |
| T-S2-04 | T-S2-00 must merge first | same |
| T-S2-05 | None | Can start in parallel with T-S2-00 |

---

## Sprint Notes

- **T-S2-00 (R0) is the critical path gating item** — R0 must complete it before Wave 2 agents start.
  It is a small task (3 files, additive changes only) and should complete in one session.
- **T-S2-01 (R1) is the most complex task (L)** — the distributed signing math requires careful
  implementation and testing. R1 must run `cargo test -p mpc-wallet-core` with signing tests that
  call `k256::ecdsa::VerifyingKey::verify` to prove cryptographic correctness.
- **Feature flag convention:** `gg20-distributed` is ON by default in Sprint 2.
  `gg20-simulation` remains available but is OFF by default. Tests in CI run default features.
- **No NATS implementation in Sprint 2** — SEC-003 (NatsTransport stubs) is deferred to Epic E.
  The distributed signing in T-S2-01 uses `LocalTransport` for testing.
- **Sui BCS (T-S2-04) is pragmatic, not complete** — the goal is to remove JSON encoding and
  use real BCS bytes. Full Sui TransactionData with gas coin management is a Sprint 3 item.
- **SEC-002 is fully resolved by T-S2-03** — zero occurrences of "demo-password" in CLI source
  is the verification criterion. R6 will `grep` for it explicitly.
- **Checkpoint commit rule enforced** — every agent commits after each `cargo test` pass with
  `[R{N}] checkpoint: {what changed} — tests pass`. Final commit: `[R{N}] complete: {summary}`.
- **Worktree reminder** — each agent must run `cargo test` in their OWN worktree, not in
  `/project/mpc-wallet`. See LESSONS.md LESSON-008.
