# Known-answer test (KAT) plan

| | |
|---|---|
| **Version** | 1.0-draft, 2026-10-11 |
| **Status** | **PROPOSED.** Drafted by R6 (advisory) with R7. WS-05 and WS-13 review it with each RFC. Part B is **Gated** (G-MPC, ADR-07) and is not built before that gate opens. |
| **Covers** | Part A (§3): the verifier kernel and its contracts (M6, plus the Guard's operator-signature check in M7). Part B (§4): the future MPC engine and its transport and key store (M8). The rules (§1), the file format (§2) and Part C (§5: CI, evidence and upkeep) apply to both. |
| **Sources** | [ROADMAP](../ROADMAP.md) M6 #2–#8, M7 #1, M8 #1–#7, PC-02–PC-04; [threat model v2](THREAT_MODEL_V2.md); the RFC process in [`docs/rfcs/README.md`](../rfcs/README.md); [known issues](KNOWN_ISSUES.md). |
| **Public safety** | Category level. Vectors name the rule they check. No exploit mechanics. |
| **Owner** | WS-14 maintains the plan. WS-05 writes the kernel vectors, WS-13 checks them independently, and WS-08/09/10 write the engine vectors once G-MPC opens. |

---

## 0. What a KAT is here

A **known-answer test** is a fixed input together with the exact expected outcome: either "accept", with the exact output bytes or digest, or "refuse", with the exact refusal code. The expected outcome comes from a source **other than the code under test**.

There are three kinds, and every vector file says which kind it holds:

| Kind | Where the expected outcome comes from | Counts as evidence of correctness? |
|---|---|---|
| **Reference** | A published standard or an independent reference: an RFC, a NIST CAVP file, a Wycheproof set, or an SDK such as tronweb | Yes |
| **Cross-implementation** | An independent implementation written from the RFC text alone by a different author or agent (the WS-13 JS oracle, M6 #7) that agrees byte for byte | Yes, once the oracle exists |
| **Regression** | Our own code's output, pinned so that any change shows up | **No.** It detects change only, and its file is labelled "regression" |

**Not in this plan:** property tests, fuzzing, the mutation check, the tronweb differential and live testnet runs. Those are separate M6 #8 and M8 evidence. KATs feed them: vectors seed the fuzz corpora, and the mutation check maps each removed check to the vectors that must then fail (§1, R3).

---

## 1. Rules for every vector

| # | Rule |
|---|---|
| R1 | **An independent expected value.** Every expected value has a source other than the Rust code under test. A vector whose only source is that code is a regression vector and is labelled so |
| R2 | **Every rule has a vector** ([RFC rule 2](../rfcs/README.md#rules)). Each validation rule has at least one refuse vector with its refusal code, and each accepted shape has at least one accept vector |
| R3 | **Minimal pairs.** A refuse vector differs from a named accept vector (its `base`) in one property only, so that it exercises exactly one check |
| R4 | **Exact expectations.** Accept vectors pin the output bytes: digests, re-encodings, receipt bytes. Refuse vectors pin the exact refusal code, not just "refused". If an input could break several rules, either the RFC defines which code wins or the vector breaks only one (R3) |
| R5 | **Boundaries both ways.** Every numeric bound (caps, expiry, validity windows, size caps, tier edges, velocity limits) has a vector at the bound and one past it. The RFC says whether the bound is inclusive |
| R6 | **Test material only.** Keys come from public test seeds, as the contracts v0 vectors already do, and never control value on any network. Cryptographic parameters are production-size. Reduced parameters are never used, even for speed ([ROADMAP](../ROADMAP.md) §3.6) |
| R7 | **Provenance in every file.** Each file names its generator and exact version (or the RFC section, or the dataset and its commit), the date, and the RFC version it targets. Reference-vector tooling is version-locked with exact versions and a lockfile |
| R8 | **Data, not code.** Vectors are data files. The Rust tests and the JS oracle read **the same files** (M6 #7 vector job) |
| R9 | **Frozen with the RFC.** Vectors may change only while their RFC is `DRAFT` or `COMMENT`. Once it is `ACCEPTED`, a change to any expected value needs a new RFC version ([`docs/rfcs/README.md`](../rfcs/README.md#versioning)) |
| R10 | **No vacuous pass.** The harness fails if a file holds zero vectors, if a vector has an unknown field or kind, or if an expected refusal code is not in the registry |
| R11 | **Category-level descriptions.** A vector states the rule it checks. Vectors derived from incidents name the incident class, never the incident's mechanics |

---

## 2. Vector file format (a proposal for WS-05 and WS-13)

Plain JSON with hex strings. Rust already has `serde_json` and `hex` in `Cargo.lock`, and JavaScript reads JSON natively, so no new dependency is needed.

<!-- ponytail: plain JSON, no schema language. The harness rejects unknown fields instead (R10). Add a JSON Schema only if a third implementation appears. -->

```json
{
  "rfc": "INTENT_V1",
  "rfc_version": "DRAFT 2026-10-..",
  "kind": "cross-implementation",
  "generated_by": [{ "tool": "tronweb", "version": "<exact>" }],
  "vectors": [
    {
      "id": "INTENT_V1-A-001",
      "rule": "§4.2",
      "base": null,
      "description": "TRC-20 transfer at the fee-limit bound",
      "input": { "raw_tx": "<hex>" },
      "expect": { "accept": { "tx_hash": "<hex>", "intent_digest": "<hex>" } }
    },
    {
      "id": "INTENT_V1-R-001",
      "rule": "§4.3",
      "base": "INTENT_V1-A-001",
      "description": "One field outside the grammar",
      "input": { "raw_tx": "<hex>" },
      "expect": { "refuse": { "code": "0x0203", "name": "TX_UNKNOWN_FIELD" } }
    }
  ]
}
```

- **Location:** next to the implementation, as [`docs/rfcs/README.md`](../rfcs/README.md#where-rfcs-live) asks: `crates/vaultex-verify/vectors/<RFC>/` (WS-05). External datasets go under a `third_party/` subfolder of that location, unmodified, with their licence. Their attribution is handled together with the licence decision (ADR-02).
- **Refusal codes** are written as both the stable `u16` code and its name. The harness checks that the two agree with the registry in `vaultex-types`.
- **Sequence vectors** (velocity, breaker, receipt chains) hold a starting state and an ordered list of steps. Each step has its input, the caller-supplied time and its expected outcome. The vector ends with the expected final state digest.

---

## 3. Part A: the kernel (M6)

The decoder and policy KATs are the acceptance spec for M6 #2–#6. The JS oracle (T13-2) makes them cross-implementation KATs (M6 #7).

### A.1 Primitives the kernel relies on

The libraries below are already in `Cargo.lock`. The KATs check that Vaultex calls them with the right variant and the right rule, not that the libraries are correct.

| ID | Primitive | Used for | Expected values from | Notes | Lands in |
|---|---|---|---|---|---|
| KAT-01 | SHA-256 | Recomputing the TRON txid; tagged digests; the receipt chain | FIPS 180-4 examples; NIST CAVP SHAVS byte-oriented message files | — | M6 #2, #6 |
| KAT-02 | Ed25519 verification, strict | Approvals, initiator statements, bundle signatures, receipts, freeze and unpause orders | RFC 8032 §7.1; Wycheproof `ed25519_test.json`; the edge-case set from "Taming the many EdDSAs" (IACR ePrint 2020/1244, `ed25519-speccheck`) | Libraries disagree on edge cases (KI-27), so each RFC must name one rule. Recommended (§6): reject non-canonical encodings of S and of points, and reject small-order public keys and R. The edge-case vectors pin that rule's accept or refuse result for both the kernel and the oracle | M6 #3, #4, #6 |
| KAT-03 | Keccak-256 | The allowlisted TRC-20 selector; EVM later | The published Keccak-256 digest of the empty input, `c5d24601…5d85a470`, which differs from the SHA3-256 (FIPS 202) digest, `a7ffc6f8…80f8434a`; the derivation `transfer(address,uint256)` → `a9059cbb` and `approve(address,uint256)` → `095ea7b3` | This catches the Keccak-versus-SHA3 padding confusion. The selector is a constant in the kernel, and this KAT proves the constant | M6 #2 |
| KAT-04 | TRON address forms | Owner, recipient and token checks (21-byte form); rendering in the approver CLI (base58check) | tronweb output for hex ↔ base58check pairs; the double-SHA-256 checksum | The kernel compares 21-byte forms only. Base58 appears only when rendering. A refuse vector covers a wrong address prefix | M6 #2, #9 |
| KAT-05 | secp256k1 ECDSA with public-key recovery | The Guard's recovery of the operator signature (M7 #1); later the checks on engine output (KAT-31) | Wycheproof `ecdsa_secp256k1_sha256_test.json` and `ecdsa_secp256k1_sha256_bitcoin_test.json` (the low-S variant); transactions signed by tronweb | Whether TRON nodes require low S is a **HYPOTHESIS** until the Nile spike or the testnet job records it. The vector records the observed rule | M7 #1 |
| KAT-06 | U256 arithmetic | Amounts, caps, tiers; the calibration L = ⌈t·G/n⌉ | A hand-derived boundary table (0, 1, 2^64, 2^128, 2^256 − 1; rounding up; overflow), cross-checked by the oracle with JavaScript `BigInt` | Overflow refuses; it never wraps or saturates | M6 #3, #5 |

### A.2 Contracts and canonical encoding (`vaultex-types`)

The contracts v0 vectors already exist: V-00 to V-10 (accept) and N-01 to N-08 (refuse). Two independent encoders, a minimal Python BCS encoder and `@mysten/bcs`, produced the expected bytes, and the Rust tests reproduce them. **Gap:** those generators are not in the repository, so the vectors cannot be regenerated from it. The JS oracle (T13-2), written from the RFC text, becomes the reproducible second implementation. Until it exists, these count as cross-implementation KATs whose provenance is recorded only in the test file.

| ID | What | Vectors | Lands in |
|---|---|---|---|
| KAT-07 | BCS canonical encoding and strict decoding: length prefixes, minimal ULEB128, no trailing bytes, byte-equal re-encoding, size caps checked before decoding | V-01, N-01 to N-08; one more refuse vector per strict-decoding rule that has none yet | M5 #11; M6 #7 |
| KAT-08 | Tagged digests and signatures: `SHA-256(BCS(tag) ‖ BCS(value))` with prefix-free tags; one key, one purpose | V-02 to V-08, plus refuse vectors that present the same bytes under another tag or another key purpose (`ISSUER_NOT_AUTHORIZED`) | M6 #4, #6 |

### A.3 TRON strict decoder (M6 #2)

| ID | What | Expected values from | Lands in |
|---|---|---|---|
| KAT-09 | **Accept the two shapes**: `TransferContract`, and `TriggerSmartContract` calling `transfer(address,uint256)` on an allowlisted token with zero call value. Each vector pins the txid (`sha256(raw_data)`), the decoded intent fields and the byte-equal re-encoding. Boundary values per R5: smallest and largest amount, fee limit at the bound, expiry at the bound | The tronweb reference vectors already pinned by the chain encoder tests (native transfer and TRC-20), new vectors from a version-locked tronweb, and the oracle | M6 #2 |
| KAT-10 | **One refusal per decoder rule**, each a minimal pair against a KAT-09 base: `TX_MALFORMED`, `TX_TRAILING_BYTES`, `TX_UNKNOWN_FIELD`, `TX_DUPLICATE_FIELD`, `TX_NON_CANONICAL` (a non-minimal varint, and a re-encoding that differs), `TX_SHAPE_NOT_ALLOWED` (memo or data, a second contract, another contract type including a permission update), `TX_SELECTOR_NOT_ALLOWED` (`approve`, `transferFrom`, any other selector), `TX_VALUE_NOT_ALLOWED`, `TX_PERMISSION_NOT_ALLOWED`, `TX_SENDER_MISMATCH`, `TX_EXPIRY_OUT_OF_BOUNDS` (expired, and too long), `TX_FEE_OVER_BOUND`, `TX_DIGEST_MISMATCH` | Built by mutating the accept bytes. The oracle must agree on the refusal and its code | M6 #2, #7 |
| KAT-11 | **Incident replay**: each incident class in the WS-13 catalogue (T13-3) maps to a refuse vector with its expected code. 100% must be refused (M6 #8). The catalogue holds the cases; the kernel vector files reference them by ID and do not copy them | WS-13 (a different agent from the kernel author) | M6 #8 |

### A.4 Policy bundle (M6 #3; distribution: ADR-11)

| ID | What | Lands in |
|---|---|---|
| KAT-12 | **Bundle validity.** Accept: an M-of-N quorum. Refuse: `BUNDLE_INVALID` (M−1 signatures, an unknown admin key, a duplicate admin signature, the wrong tag), `BUNDLE_ROLLBACK` (the same or a lower version, or a fork with the wrong parent digest), `BUNDLE_NOT_EFFECTIVE` (a loosening before its time-lock ends, at the boundary and just before it), `NO_POLICY` | M6 #3 |
| KAT-13 | **Rule evaluation**, deny by default: `ASSET_NOT_ALLOWED`, `RECIPIENT_NOT_ALLOWED`, `AMOUNT_OVER_TX_CAP` (at the cap and at cap + 1), `FEE_OVER_CAP`, `VALIDITY_OVER_CAP`. A zero-approval tier is accepted only when the bundle states it explicitly | M6 #3 |
| KAT-14 | **The loosening or tightening classifier**: pairs of bundles with their expected class. A pair that is not provably tighter counts as a loosening. Property tests cover the general case; these vectors pin the RFC's worked examples | M6 #3 |

### A.5 Initiator and approvals (M6 #4)

| ID | What | Lands in |
|---|---|---|
| KAT-15 | Accept: k-of-n approvals for each amount tier, at and just above each tier edge. Refuse, once each: `INITIATOR_INVALID`, `APPROVALS_INSUFFICIENT`, `APPROVAL_INVALID`, `APPROVER_UNKNOWN`, `APPROVER_DUPLICATE` (refused, not deduplicated), `SOD_VIOLATION` (the initiator's principal also approves), `APPROVAL_EXPIRED` (at the boundary), `APPROVAL_INTENT_MISMATCH` (an approval over a different intent, including the same intent with another txid) | M6 #4 |

### A.6 Velocity, breaker and clock (M6 #5)

These are sequence vectors (§2). Crash behaviour under `kill -9` is tested separately and is not a KAT.

| ID | What | Lands in |
|---|---|---|
| KAT-16 | Velocity windows for amount, count and fees: `VELOCITY_EXCEEDED` at L and at L + 1; a window rolling over exactly at its boundary; the calibration table for L = ⌈t·G/n⌉ (KAT-06) | M6 #5 |
| KAT-17 | Breaker and freeze: `BREAKER_TRIPPED`, `FROZEN`; an unpause short of quorum (`ADMIN_QUORUM_INSUFFICIENT`); an unpause with a stale nonce or an expired order, refused with the code the RFC defines | M6 #5 |
| KAT-18 | Clock: `CLOCK_UNTRUSTED` for a time below the high-water mark and for skew beyond the bound | M6 #5 |

### A.7 Receipts and the offline verifier (M6 #6)

| ID | What | Lands in |
|---|---|---|
| KAT-19 | Receipt bytes, digest and signature for an accept and for a refusal; the link to the previous receipt's digest; the first receipt of a chain. V-08 is the starting point | M6 #6 |
| KAT-20 | Offline-verifier refusals: a broken link, a reordered chain, an altered body, the wrong key, the wrong tag, a duplicated sequence number. A truncated chain cannot be detected offline without an anchor (KI-16), so its vector pins the result "valid prefix" | M6 #6 |

### A.8 Request envelope and local state (M6; Guard API in M7)

| ID | What | Lands in |
|---|---|---|
| KAT-21 | One refusal for each `0x01xx` code the Phase-1 path can return: `MALFORMED`, `UNSUPPORTED_VERSION`, `REQUEST_EXPIRED`, `REQUEST_WINDOW_TOO_LONG`, `REPLAY`, `UNKNOWN_WALLET`, `NETWORK_MISMATCH`, `POLICY_VERSION_MISMATCH`, `PAYLOAD_TOO_LARGE`, `PAYLOAD_MISSING` (empty bytes, or a digest only), `ISSUER_NOT_AUTHORIZED`. An oversize input is refused before any parsing. The v2-only codes belong to Part B | M6; M7 #1 |
| KAT-22 | **Fail closed on local state** (fault-injection vectors: a storage or key-custody test double that fails on cue). A failed durable write gives `STATE_WRITE_FAILED` and no signature; a key that fails to load gives `KEY_UNAVAILABLE`. Each vector also checks that no receipt claims an accept and no velocity is left reserved | M6 #5–#6; M7 #1 |

### A.9 Coverage check

A test in `vaultex-verify` (WS-05) lists the refusal-code registry and requires at least one refuse vector for every code that the Phase-1 path can return. Codes exempt from that rule are listed by name, each with its reason: the v2 codes (Part B); `TX_CHAIN_ID_MISMATCH` (EVM only, until EVM enters scope); `INTERNAL` (an invariant violation that no valid or invalid input should reach; it is covered by review and by fuzzing, which must never trigger it); and the retryable `0xF0xx` class. A new code without either a vector or an exemption fails the test. This makes RFC rule 2 mechanical.

---

## 4. Part B: the engine (M8; Gated)

Nothing here starts before G-MPC passes (ADR-07). Part B IDs start at KAT-30; KAT-23 to KAT-29 are kept free for Part A additions, so that IDs never change. No engine crate is in `Cargo.lock` today. Adding the engine triplet is the M8 dependency change, and it goes through R0, the owner, and `cargo deny` / `cargo vet` ([ROADMAP](../ROADMAP.md) §5.0).

Threshold key generation and signing are randomised and interactive, so the protocol itself has no single known answer. The plan therefore pins what does have one: the pin, the outputs, the encodings, the parameters and the refusals.

| ID | What | Expected values from | Lands in |
|---|---|---|---|
| KAT-30 | **The pin and its advisories.** The exact triplet is pinned. At pin time, it is checked against RUSTSEC and GHSA (KI-28). The upstream test suite runs at the pinned version in CI as the library's own KATs, if upstream ships them (**HYPOTHESIS**; cheapest test: read the upstream test directory at G-MPC) | Upstream; advisory databases | M8 #1 |
| KAT-31 | **Output verification.** Every engine signature in tests is checked by at least two independent verifiers: `k256` verification against the group key, and public-key recovery that must return the group key. Chain-form signatures (r, s, v) are also checked with tronweb for TRON and viem for EVM. The verifiers themselves are pinned by KAT-05 | `k256`, tronweb, viem | M8 #3; PC-02; PC-04 |
| KAT-32 | **S normalisation and the recovery id.** A high-S signature is normalised to low S, with the recovery id flipped, wherever the chain requires it: EIP-2 for EVM. TRON's rule is recorded by the testnet job (**HYPOTHESIS** until then) | EIP-2; testnet | M8 #3 |
| KAT-33 | **Address derivation.** The group public key must give the same TRON and EVM addresses as tronweb and viem | tronweb, viem | M8 #3 |
| KAT-34 | **Typed sign input.** For `SignInput::EcdsaPreimage { hash, bytes }`, the node recomputes the hash from the bytes with the chain's rule (SHA-256 of `raw_data` for TRON, Keccak-256 for EVM) and refuses a mismatch with `TX_DIGEST_MISMATCH`. No untyped 32-byte input exists (TH43). This extends contracts v0 V-04 to v2 | KAT-01, KAT-03 | M8 #1 |
| KAT-35 | **Parameter sizes.** Production-size parameters are asserted on cached fixtures (M8 #7). A reduced-parameter fixture must fail the assertion (a negative KAT). Parameters are never shrunk for speed | The engine's documented production level | M8 #7 |
| KAT-36 | **Transcript regression vectors** (regression only, §0). With a fixed, test-only RNG seed and the pinned engine version, the hashes of the key-generation, auxiliary-material and signing transcripts and outputs are pinned. Bumping the engine changes them on purpose, and the change states why, as input to the AL3 delta review. The seeded RNG exists only in test builds, and the shipped-build guard (M5 #8) fails if it is linked. Needs an engine API that accepts an injected RNG (**HYPOTHESIS**; cheapest test: read the public API at G-MPC) | Our own code | M8 #1, #7 |
| KAT-37 | **Negative protocol vectors.** Recorded honest messages for each round, each with one mutation: the wrong party index, the wrong execution id, a replay from another session, truncated, oversize, or flipped proof bytes. The expected result is an abort (`ENGINE_ABORT`, which is retryable) or a transport refusal, and never a signature. Shared with the PC-03 adversarial suite | Mutations of recorded transcripts | M8 #4–#5; PC-03 |
| KAT-38 | **HD derivation, only if a use case needs it** (M8 #1). Non-hardened public derivation against the BIP-32 and SLIP-10 (secp256k1) test vectors. Otherwise, a test asserts that no HD path is reachable | BIP-32; SLIP-10 | M8 #1 |
| KAT-39 | **Key store v2.** AES-256-GCM against NIST CAVP GCM (SP 800-38D) vectors and Wycheproof `aes_gcm_test.json`; Argon2id against RFC 9106 §5.3; AAD binding (a share encrypted for one wallet and party fails to decrypt for another); a refused overwrite | NIST; Wycheproof; RFC 9106 | M8 #6; PC-09 |
| KAT-40 | **Transport and control plane v2** (WS-09 chooses the primitives). X25519 against RFC 7748 §5.2 and §6.1 and Wycheproof `x25519_test.json`; HKDF-SHA256 against RFC 5869 Appendix A and Wycheproof `hkdf_sha256_test.json`; ChaCha20-Poly1305 against RFC 8439 §2.8.2 and Appendix A.5 and Wycheproof `chacha20_poly1305_test.json` (or KAT-39, if AES-GCM is chosen). Signed-envelope vectors: one accept, then refusals for a spoofed sender, the wrong execution id, a replay, oversize input before parsing, `SIGNER_SET_INVALID` and `SUBJECT_MISMATCH`. Control-plane refusals: `GROUP_EXISTS`, `KEYGEN_INTENT_INVALID`, `AUX_EPOCH_UNKNOWN` | RFCs; Wycheproof; the oracle | M8 #4–#6; PC-03; PC-04 |

The AEAD, key-exchange, KDF and password-hashing crates that KAT-39 and KAT-40 exercise are already in `Cargo.lock`. Those KATs need only vendored data files, not new crates.

---

## 5. Part C: CI, evidence and upkeep

- **The vector job** (M6 #7; a required check per [ROADMAP](../ROADMAP.md) §9.2). The Rust tests and the JS oracle read the same files. They must agree on every accept or refuse result, every code and every output byte. The job runs on every PR that touches the kernel, the contract types or the vectors. WS-02 wires it into CI.
- **Coverage report.** Each review package (the M6 limited evaluation, M10-K, and the M10-F decoder line AL4) gets a table of rule → vector IDs → result in Rust and in the oracle.
- **Mutation link** (M6 #8). Every refuse vector names the check it exercises. The mutation report shows that removing each check makes at least one vector fail.
- **Fuzz seeds** (M6 #8). The accept and refuse vectors seed the fuzz corpora, so fuzzing starts from valid structure.
- **Cost.** KATs are fast unit tests. No fuzzing or long-running job is part of the default test run.
- **Upkeep.** The plan is reviewed with each RFC (DRAFT → COMMENT → ACCEPTED), at the M6 freeze, and at G-MPC for Part B.

### Ownership and timing

| Part | Writes the vectors | Independent check | When |
|---|---|---|---|
| A.1 primitives | WS-05 | Published datasets | With T05-2 and T05-6 |
| A.2 contracts | WS-03 (v0 exists) | The JS oracle (T13-2) | T13-2 |
| A.3 decoder | WS-05 (T05-2) | tronweb and the oracle; WS-13 incident cases (T13-3) | M6 |
| A.4–A.5 policy and approvals | WS-05 (T05-3, T05-4; ADR-11) | The oracle (T05-7b, T13-2) | M6 |
| A.6–A.7 velocity and receipts | WS-05 (T05-5, T05-6) | The oracle | M6 |
| A.8 envelope and local state | WS-05; WS-06 for the Guard API | The oracle | M6–M7 |
| Part B | WS-08, WS-09, WS-10 | tronweb, viem, `k256`, published datasets; the contract cryptographer | M8 (Gated) |

---

## 6. Open points

| Point | Who decides | Recommendation |
|---|---|---|
| The exact Ed25519 verification rule written into each RFC (KAT-02) | WS-03 and WS-05 | Strict verification, as stated in KAT-02, pinned by the edge-case vectors |
| Vendoring external datasets (Wycheproof, NIST CAVP): licence and attribution | Owner, with ADR-02 | Vendor the files unmodified, with their licence; record each dataset's licence before vendoring [check per dataset] |
| Version-locking the reference-vector tooling (R7) | WS-13 | Exact versions plus a lockfile for the oracle and vector scripts. Today's vector scripts use version ranges and have no lockfile |
| Where the incident-replay cases live | WS-13 and WS-05 | In the WS-13 catalogue; kernel vector files reference them by ID (KAT-11) |
| Upstream engine vectors and RNG injection (KAT-30, KAT-36) | WS-08 at G-MPC | Check both before the engine work is planned |

---

## 7. Facts this plan relies on

| Fact | Status | Evidence, or the cheapest test |
|---|---|---|
| The contracts v0 vectors V-00–V-10 and N-01–N-08 exist and are reproduced in Rust | VERIFIED | `crates/vaultex-types/tests/vectors_v0.rs` |
| The generators of those vectors are not in the repository | VERIFIED | A repository search finds them named only in that test file's header |
| The chain encoder tests pin tronweb reference vectors for a native TRON transfer and a TRC-20 transfer | VERIFIED | `proto_matches_tronweb_reference` and `proto_matches_tronweb_trc20_reference` in the chains crate |
| `serde_json`, `hex`, `sha2`, `sha3`, `ed25519-dalek`, `k256`, `bs58`, `aes-gcm`, `chacha20poly1305`, `x25519-dalek`, `hkdf` and `argon2` are in `Cargo.lock`, and no engine crate is | VERIFIED | `Cargo.lock` at this plan's commit |
| Keccak-256 of the empty input is `c5d2…a470`, SHA3-256 of it is `a7ff…434a`, and the selectors are `a9059cbb` and `095ea7b3` | VERIFIED | Python `hashlib.sha3_256`, and a stdlib Keccak-f[1600] checked against it |
| Wycheproof ships `ed25519_test.json`, `ecdsa_secp256k1_sha256_test.json`, `ecdsa_secp256k1_sha256_bitcoin_test.json`, `aes_gcm_test.json`, `chacha20_poly1305_test.json`, `x25519_test.json` and `hkdf_sha256_test.json` | VERIFIED | The `testvectors_v1` listing of `github.com/C2SP/wycheproof`, 2026-10-11 |
| RFC 9106 §5.3 holds the Argon2id vectors; RFC 8439 §2.8.2 and Appendix A.5 hold the ChaCha20-Poly1305 AEAD vectors | VERIFIED | rfc-editor.org, 2026-10-11 |
| One advisory database lists a cryptographic issue in `cggmp24` releases before `0.7.0-alpha.2` | VERIFIED | [security.snyk.io/package/cargo/cggmp24](https://security.snyk.io/package/cargo/cggmp24), 2026-10-11 |
| TRON nodes require low-S signatures | HYPOTHESIS | Submit a high-S variant of a signed testnet transaction in the testnet job |
| The engine ships its own KATs and accepts an injected RNG | HYPOTHESIS | Read the upstream test directory and public API at G-MPC |
