# RECEIPT_V1: Signed, hash-chained decision receipts

- RFC: RECEIPT_V1
- Status: DRAFT
- Writer: WS-05 (R3, R6 adversarial vectors; R1 reviews encodings and signatures)
- Implementation: `crates/vaultex-verify` (module `receipt` and the `vaultex-receipts` binary); types in `crates/vaultex-types` (`ReceiptBodyV1`, `ReceiptV1`, `Decision`, `RefusalCode`)
- Vectors: `crates/vaultex-verify/vectors/RECEIPT_V1/receipt_v1.json`
- Comment window: not yet open
- Discussion: none yet (the owner opens it with the comment window)
- Supersedes: none
- Related ADRs: ADR-11 (policy distribution: what `policy_digest` names)

## 1. Summary

Every decision a signer makes, accept or refuse, leaves a receipt: what was decided, about which transaction, under which policy, by which verifier build. Each receipt is signed with the signer's Ed25519 receipt key and names the digest of the previous one, so a signer's receipts form a hash chain, its receipt log, that anyone holding the public receipt key can verify offline. This RFC specifies the receipt, its encoding and signature, the log format, the rules a writer follows and the rules a verifier checks.

## 2. Scope

**In scope:**

- The `ReceiptBodyV1` and `ReceiptV1` data model, the BCS encoding, the receipt digest and the signature (§4–§6).
- The receipt log: framing, writer rules, and offline verification of a whole log or of a segment that starts at a checkpoint (§5.3, §7).

**Out of scope:**

- What `intent_digest` and `policy_digest` digest. They are defined by `INTENT_V1` §6.1 and by `POLICY_BUNDLE_V1` (T05-7b).
- The request format and the refusal-code semantics. They belong to contracts v0; the registry is reproduced in Appendix A.
- Anchoring heads in another failure domain, and exporting logs as evidence packs. The outflow monitor compares heads (WS-07).
- Custody of the receipt key, and retention.

**Boundary.** A receipt holds digests and the decision, not the request. The transaction bytes, the statements and the policy bundle live in the evidence pack.

## 3. Terminology

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

| Term | Meaning |
|---|---|
| **Receipt** | A `ReceiptV1`: a body and its signature. |
| **Receipt key** | The signer's Ed25519 key used only to sign receipts. Its public half is published, so that verifiers can pin it. |
| **Log** | A signer's receipts in order, as a sequence of frames (§5.3). |
| **Head** | The last receipt of a log: its `seq` and digest. |
| **Checkpoint** | A `seq` and digest that a verifier already trusts, for example an anchored head. |
| **Segment** | The receipts after a checkpoint. |
| **Prefix** | The first n receipts of a log. |
| **Check** | One verification rule of §7.2, named in upper snake case, such as `PREV`. |

Hex is written in lower case. Integers in the vector file are decimal strings.

## 4. Data model

### 4.1 `ReceiptBodyV1`

| # | Field | Type | Meaning |
|---|---|---|---|
| 1 | `signer_key` | 32 bytes | This signer's Ed25519 receipt public key |
| 2 | `seq` | `u64` | Position in this key's chain, from 0 |
| 3 | `prev` | 32 bytes | The digest (§6.1) of receipt `seq − 1`; 32 zero bytes when `seq` is 0 |
| 4 | `time_s` | `u64` | Decision time, in seconds since the Unix epoch (W4) |
| 5 | `request_id` | 16 bytes | The request decided on |
| 6 | `wallet_id` | `WalletId` | The wallet: ASCII `[a-z0-9-]{1,64}` |
| 7 | `chain` | `ChainId` (`u16`) | The chain (`INTENT_V1` §4.2) |
| 8 | `network` | `NetworkId` | The network, a CAIP-2 id from the allowlist (`INTENT_V1` §4.2) |
| 9 | `tx_hash` | 32 bytes | SHA-256 of the unsigned transaction bytes |
| 10 | `intent_digest` | optional 32 bytes | The decoded intent's digest (`INTENT_V1` §6.1); absent when decoding itself refused |
| 11 | `policy_version` | `u64` | Version of the installed policy bundle |
| 12 | `policy_digest` | 32 bytes | Digest of the installed policy bundle (`POLICY_BUNDLE_V1`) |
| 13 | `verifier_version` | 3 × `u16` | The verifier build that decided: major, minor, patch |
| 14 | `decision` | `Decision` | Accept, or refuse with a code (§4.2) |

### 4.2 `Decision`

`Decision` is an enum:

- variant 0, `Accept`: every check passed;
- variant 1, `Refuse(Refusal)`: a check failed, and nothing is signed.

`Refusal` is a struct of `code: u16`, a refusal code (Appendix A), and `rule_index: optional u32`, the index of the policy rule that fired, when one did. There is no free-text reason.

A code that a verifier does not know still decodes and is counted by its number. Appendix A gives the registry's classes.

### 4.3 `ReceiptV1`

A body followed by `signature`: 64 bytes, the Ed25519 signature `R ‖ S` by `signer_key` over the body's digest (§6).

## 5. Canonical encoding

### 5.1 BCS encoding of a body

BCS as in `INTENT_V1` §5.1: fixed-width little-endian integers, shortest-form ULEB128 lengths and enum indexes, `ULEB128(length) ‖ bytes` for strings, raw bytes for fixed-size arrays, and fields concatenated in the order of §4.1. An optional value is `00`, or `01 ‖ value`.

| # | Field | Bytes |
|---|---|---|
| 1 | `signer_key` | 32 |
| 2 | `seq` | `u64` LE |
| 3 | `prev` | 32 |
| 4 | `time_s` | `u64` LE |
| 5 | `request_id` | 16 |
| 6 | `wallet_id` | `ULEB128(len) ‖ ASCII` |
| 7 | `chain` | `u16` LE |
| 8 | `network` | `ULEB128(len) ‖ ASCII` |
| 9 | `tx_hash` | 32 |
| 10 | `intent_digest` | `00`, or `01 ‖ 32 bytes` |
| 11 | `policy_version` | `u64` LE |
| 12 | `policy_digest` | 32 |
| 13 | `verifier_version` | `u16` LE ×3 (major, minor, patch) |
| 14 | `decision` | `00` (accept), or `01 ‖ code (u16 LE) ‖ rule_index` |

`rule_index` is `00` when absent, or `01 ‖ u32 LE`. For example, `Refuse(TX_SELECTOR_NOT_ALLOWED, none)` is `01 07 02 00`, and `Refuse(VELOCITY_EXCEEDED, 3)` is `01 01 05 01 03000000` (contracts v0 vector V-07).

**Worked example.** The first receipt of vector `RECEIPT_V1-A-001` (identical to contracts v0 vector V-08) has a 263-byte body:

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 32 | `signer_key` | `ed4928c6…8737d1` (test seed `03`×32) |
| 32 | 8 | `seq` | 0 |
| 40 | 32 | `prev` | 32 zero bytes |
| 72 | 8 | `time_s` | 1,700,000,010 |
| 80 | 16 | `request_id` | `000102…0e0f` |
| 96 | 37 | `wallet_id` | `24` ‖ `00000000-0000-4000-8000-000000000001` |
| 133 | 2 | `chain` | `0100` (TRON) |
| 135 | 16 | `network` | `0f` ‖ `tron:2494104990` |
| 151 | 32 | `tx_hash` | `4145dae0…8ecbf99e` |
| 183 | 33 | `intent_digest` | `01` ‖ `71eda63f…5614820d` (`INTENT_V1-A-002`) |
| 216 | 8 | `policy_version` | 1 |
| 224 | 32 | `policy_digest` | `3d400d56…720f587d` (a placeholder) |
| 256 | 6 | `verifier_version` | 0.1.0 |
| 262 | 1 | `decision` | `00` (accept) |

With the current network allowlist, a body is at most 298 bytes and a receipt at most 362 bytes, well under the 1024-byte frame cap.

### 5.2 BCS encoding of a receipt

`BCS(ReceiptV1) = BCS(body) ‖ signature`. The signature is exactly 64 raw bytes, with no length prefix.

### 5.3 Log frames

A log is a sequence of frames and nothing else:

```text
frame := len (u32 little-endian) ‖ BCS(ReceiptV1)      with 1 ≤ len ≤ 1024
log   := frame*
```

An empty log (zero bytes) is valid and has no head.

### 5.4 Strict decoding

A frame's receipt bytes MUST be exactly one canonical `BCS(ReceiptV1)`. A decoder refuses trailing bytes, non-minimal ULEB128, an option tag other than `00` or `01`, a `Decision` variant other than 0 or 1, a `wallet_id` outside its character set or length, and a `network` that is not on the allowlist. It then re-encodes the receipt and requires the same bytes. Any failure is the check `MALFORMED` (§7.2).

## 6. Digests and signatures

### 6.1 Receipt digest

```text
ReceiptDigest = SHA-256( BCS("VAULTEX/RECEIPT/v1") ‖ BCS(body) )
BCS("VAULTEX/RECEIPT/v1") = 12 5641554c5445582f524543454950542f7631
```

The digest is what the receipt key signs, and what the next receipt names as `prev`.

### 6.2 Signature

The signature is pure Ed25519 (RFC 8032 §5.1) by the receipt key. The signed message is the 32-byte receipt digest, not the body. Ed25519 signing is deterministic, so a given key and body always give the same signature; the writer vector pins signatures.

### 6.3 Verification rule (strict)

Ed25519 libraries disagree on edge cases (non-canonical encodings, small-order points, cofactored or cofactorless equations), so this RFC names one rule. Given the public key bytes `A`, the signature bytes `R ‖ S` and the message `M` (the digest), a verifier MUST:

1. Refuse unless `S`, read as a little-endian integer, is below `L = 2²⁵² + 27742317777372353535851937790883648493`.
2. Refuse unless `R` and `A` each decode to a curve point (RFC 8032 §5.1.3; for an unreduced y-coordinate, see the note below).
3. Refuse if `R` or `A` is a point of small order (its order divides 8).
4. Compute `k = SHA-512(R ‖ A ‖ M)` as a little-endian integer mod `L`, over the bytes as received.
5. Accept only if the encoding of `[S]B − [k]A` equals `R` byte for byte. This is the cofactorless equation, compared on encodings, so a non-canonical encoding of `R` never verifies.

This is the rule of `ed25519-dalek` 2.x `verify_strict`. **Note:** that library reduces an unreduced y-coordinate (y ≥ p) instead of refusing it. For `R` this makes no difference, because step 5 compares encodings. For `A`, whether to refuse it at step 2 is not fixed yet (§11). A receipt key is pinned and published in its canonical encoding, so the question affects only keys nobody publishes.

### 6.4 One key, one purpose

The receipt key signs nothing but receipt digests. A signature by the same key over a digest made under another tag, for example `VAULTEX/APPROVAL/v1`, does not verify as a receipt (vector `R-008`). The receipt key MUST NOT be the signer's transaction key or any other purpose's key.

## 7. Validation and refusal

### 7.1 Writer rules

A signer that writes receipts MUST follow these rules.

- **W1. One receipt per decision.** Every decision on a request that names its request id, wallet, chain, network and transaction bytes gets exactly one receipt, accept or refuse. A refusal by the decoder has no `intent_digest`.
- **W2. An accept names its intent.** An accept MUST carry `intent_digest`.
- **W3. Durable before release.** The receipt is written and synced to stable storage **before** the signer releases a signature or returns the decision. If the write fails, the signer refuses (`STATE_WRITE_FAILED`, `0x0601`) and releases nothing. After a failed write, the writer appends nothing more until the log has been reopened and verified (W7).
- **W4. Chain fields.** `signer_key` is the receipt key's public half. `seq` is the previous receipt's `seq + 1`, or 0 for the first receipt. `prev` is the previous receipt's digest, or 32 zero bytes. `time_s` is `max(⌊now_ms / 1000⌋, previous time_s)`, so a clock that runs behind never puts the log out of order. `verifier_version` is the deciding build.
- **W5. Check before writing.** The writer checks each new receipt against rules `SIGNER_KEY` to `POLICY_ROLLBACK` of §7.2 with the log's current state. A receipt that would break a rule is not written, and the decision fails closed. So every log a conforming writer produces verifies.
- **W6. One writer.** One process at a time holds the log, for example under an exclusive file lock. The log file holds frames only.
- **W7. Open.** On open, the writer verifies the whole log against its own key before appending. Suppose verification fails at a frame that is cut short (`TRUNCATED`), does not decode (`MALFORMED`) or does not verify (`SIGNATURE`). That frame is a torn append, one that never completed and so was never acknowledged (W3), when it is the last thing in the log: its declared length ends exactly at, or runs past, the end of the log (or, if its header is unusable, what remains fits in one frame), and the receipt key's 32 bytes occur in what remains only at the start of the frame's own body, followed by the expected `seq` (as much of it as is present). The writer then truncates the log at that frame. Any other failure means the log MUST NOT be appended to: it is restored from a copy, never repaired.

### 7.2 Verification

**Inputs.** The log bytes; optionally a **pinned key** (the signer's published receipt key); optionally a **checkpoint** (`seq`, digest) to start after.

**Initial state.** The expected key is the pinned key, or none. The next `seq` is 0, or the checkpoint's `seq + 1`. The previous digest is 32 zero bytes, or the checkpoint's digest. The previous time is 0. The previous policy is none.

**Per receipt.** For each frame in order, the verifier applies these checks and stops at the first failure. It reports the check, the receipt's index in the log (from 0, whatever its `seq`), and the frame's byte offset.

| # | Check | The receipt fails it when |
|---|---|---|
| 1 | `TRUNCATED` | Fewer than 4 bytes remain for the frame header, or the receipt runs past the end of the log |
| 2 | `MALFORMED` | The frame length is 0 or above 1024, or the frame is not exactly one canonical `BCS(ReceiptV1)` (§5.4) |
| 3 | `SIGNER_KEY` | `signer_key` differs from the expected key. With no pinned key, the first receipt's key becomes the expected key |
| 4 | `SIGNATURE` | The signature does not verify under §6.3 over the digest of §6.1 |
| 5 | `SEQ` | `seq` is not the next `seq` |
| 6 | `PREV` | `prev` is not the previous digest |
| 7 | `TIME` | `time_s` is below the previous receipt's (equal is allowed) |
| 8 | `NETWORK` | `network` does not belong to `chain` |
| 9 | `ACCEPT_WITHOUT_INTENT` | The decision is an accept and `intent_digest` is absent |
| 10 | `POLICY_ROLLBACK` | `policy_version` is below the previous receipt's, or equal to it with a different `policy_digest` |

Checks 1 and 2 read the frame in this order: a header shorter than 4 bytes is `TRUNCATED`; then a length of 0 or above 1024 is `MALFORMED`; then a receipt that runs past the end of the log is `TRUNCATED`; then a receipt that is not one canonical `BCS(ReceiptV1)` is `MALFORMED`.

After a receipt passes, it becomes the head: the next `seq` is its `seq + 1`, and the previous digest, time and policy are its own.

**Result.** Either `INVALID` with the check, index and offset of the first failure, or `VALID` with a summary: the key, whether it was pinned, the number of receipts, the number of accepts, the number of refusals per code, the head (`seq` and digest, or none for an empty log) and the first and last `time_s`.

The offline verifier reads only the log and its inputs. It needs no network access.

### 7.3 What a valid log shows

- Every receipt in it was signed by the expected key, in an unbroken chain, in time order, with no policy rollback.
- **Pin the key.** Without a pinned key, a valid log shows only that one key signed all of it.
- **A valid log may be a prefix.** A log cut at a frame boundary verifies (vector `A-006`). Dropped receipts at the end, or a log rewritten by a host that holds the receipt key, show only against a head anchored in another failure domain. Verify a segment from an anchored checkpoint, and compare the head with the latest anchor.
- A receipt shows what was decided, not why in full. The request, the statements and the bundle are in the evidence pack, and the receipt's digests tie them together.

## 8. Versioning and compatibility

- The layout version is carried in the digest tag (`VAULTEX/RECEIPT/v1`). Once this RFC is `ACCEPTED`, the bytes of `ReceiptBodyV1` are frozen. A new layout is a new type with tag `VAULTEX/RECEIPT/v2` and a new RFC.
- Verifiers keep a decoder for every receipt version ever released, so old evidence verifies forever.
- A v1 frame carries no version marker. How a later version is told apart in a log is open (§11) and MUST be settled before this RFC is `ACCEPTED`.
- `verifier_version` records the build, not the receipt version.
- Registries grow by appending. A receipt that names a network the verifier does not know fails `MALFORMED`, so readers upgrade before writers. A refusal code the verifier does not know still decodes and is counted by number.

## 9. Test vectors

**File:** `crates/vaultex-verify/vectors/RECEIPT_V1/receipt_v1.json` (JSON, hex strings, integers as decimal strings).

**Top level:** `rfc`, `rfc_version`, `kind`, `generated_by`; `keys` (the test receipt key and a second key, as seeds and public keys); `frame` (the framing of §5.3); `checks` (the ten checks of §7.2, in order, each with its rule); `vectors`.

**One vector:** `id`, `rule`, `base`, `description`, `input`, `expect`.

- **Writer vector** (`rule` = `WRITER`, `RECEIPT_V1-A-001`). `input`: `signer_seed`, `verifier_version` and `steps`, each with `now_ms`, `record` (the decision fields of §4.1 that the caller supplies: `request_id`, `wallet_id`, `chain`, `network`, `tx_hash`, `intent_digest`, `policy_version`, `policy_digest`, `decision`) and a `note`. `expect`: for each step the full `body` (adding `signer_key`, `seq`, `prev`, `time_s` and `verifier_version` per W4), `body_bcs`, `digest`, `signature` and `receipt_bcs`; then the whole `log` and its `head`. A `decision` is `{"kind": "accept"}` or `{"kind": "refuse", "code", "name", "rule_index"}`.
- **Verify vectors** (`rule` = `VALID_LOG` or a check name). `input`: `log`, `key` (hex or `null`) and `after` (`{seq, digest}` or `null`). `expect`: either `valid` (`receipts`, `accepts`, `refusals` by code, `head`, `key`, `key_pinned`) or `invalid` (`check`, and `index`, the receipt's position in the log).

**Coverage.** 27 vectors. One writer vector covers an accept that starts a chain, a decoder refusal without an intent, and a policy refusal with a rule index whose caller clock ran behind (W4). Five valid-log vectors cover a pinned key, no pinned key, a segment from a checkpoint, an empty log and a prefix. Twenty-one invalid-log vectors cover every check of §7.2 at least once. Among them, `R-009` (S + L), `R-010` (a small-order R) and `R-011` (a small-order key) pin the strict rule of §6.3, and `R-008` pins the tag separation of §6.4.

**Links to other vectors.** The first receipt of `A-001` is contracts v0 vector V-08. Its first and third receipts name the intent digests of `INTENT_V1-A-002` and `INTENT_V1-A-001`. Its second receipt records the decoder's refusal of `INTENT_V1-A-002` with a memo added (`TX_SHAPE_NOT_ALLOWED`).

**Provenance.** The expected values come from a separate Python standard-library implementation (BCS, SHA-256 and RFC 8032 Ed25519 written from scratch, self-tested against RFC 8032 §7.1 and contracts vector V-08). It was written by the same author as the Rust code, without sharing code with it. The independent oracle (T13-2) has not reproduced the vectors yet. The test keys are public test seeds and control nothing on any network.

**CI.** The Rust kernel and the independent oracle MUST read this same file and agree on every result, check, index and byte (KAT plan §5).

## 10. Security considerations

- **Receipts detect a rewritten log; they do not prevent it.** A host that holds the receipt key can rewrite its own log while it is compromised. Detection needs heads anchored in another failure domain, compared regularly, and an offline verification of the evidence pack.
- **Truncation.** A log cut at a frame boundary looks like a shorter log. Only an anchored head shows the cut.
- **Pinning.** A verifier that does not pin the published receipt key learns only that one key signed the whole log.
- **Receipt-key compromise.** It allows forged receipts, but not signatures on transactions: the receipt key is separate from the signing key (§6.4).
- **No signature without a receipt.** W3 makes the receipt durable before any signature leaves the signer. A crash between the two leaves a receipt for a signature that was never released, which errs on the safe side.
- **Torn writes.** Only an unacknowledged last frame may be truncated (W7). Any other damage stops the writer, so a damaged log is never silently repaired.
- **Policy rollback.** `POLICY_ROLLBACK` shows a signer that went back to an older bundle, or that used two bundles under one version.
- **Signature edge cases.** A single strict verification rule (§6.3) and its edge-case vectors keep two implementations from disagreeing about the same receipt.
- **Resource use.** The frame length is checked before decoding, and a receipt is at most 1024 bytes.
- **Time.** `time_s` comes from the signer's clock. It is ordered within a log, but it is not a trusted timestamp; anchoring bounds it externally.
- **Confidentiality.** A receipt carries no amounts or addresses, but `tx_hash` and the wallet id link it to on-chain activity. Treat receipt logs as confidential operational records.

## 11. Open questions

1. **Version marker.** A v1 frame carries no version. Should a later version use a new log file, or a framed version tag?
2. **Receipt-key rotation.** A key change inside a log fails `SIGNER_KEY`. Is rotation a new log, anchored with the old log's head?
3. **Non-canonical public keys.** Should a public key whose y-coordinate encoding is not reduced be refused at §6.3 step 2? Then add the published Ed25519 edge-case set (KAT plan KAT-02).
4. **Before the first bundle.** What do `policy_version` and `policy_digest` hold before any bundle is installed? The proposal is 0 and 32 zero bytes. The digest itself is defined by `POLICY_BUNDLE_V1`.
5. **Requests that name nothing.** A request that fails before it names a wallet, network or transaction gets no receipt under W1. Should such refusals be logged elsewhere?
6. **Richer checkpoints.** A checkpoint holds only `seq` and digest, so a segment's first receipt is not checked for `TIME` or `POLICY_ROLLBACK` across the boundary. Should a checkpoint also carry the time and the policy?
7. **Evidence packs.** Their export format and retention.

## 12. Changelog

- 2026-10-11: First draft (T05-7a). The 27 vectors were drafted with the receipts implementation (T05-6).

## Appendix A. Refusal-code registry (contracts v0)

Codes are `u16`, append-only and never reused. The high byte is the class:

- `0x01`–`0x07` are **refusals**, final for that request. A relay MUST NOT retry a refusal on another signer subset, since that would let it shop for a signer that agrees; it alerts instead.
- `0xF0` is **unavailable**, which may be retried as a fresh attempt.
- A code a verifier does not know is a refusal.

"(v2)" marks codes reserved for the MPC phase.

| Code | Name | Meaning |
|---|---|---|
| `0x0101` | `MALFORMED` | The request failed strict decoding, or a size cap was exceeded before decoding |
| `0x0102` | `UNSUPPORTED_VERSION` | A message or tag version this verifier does not accept |
| `0x0103` | `REQUEST_EXPIRED` | The request's expiry has passed |
| `0x0104` | `REQUEST_WINDOW_TOO_LONG` | The request's validity window is longer than the maximum |
| `0x0105` | `REPLAY` | The request id or envelope nonce was already seen |
| `0x0106` | `UNKNOWN_WALLET` | No registry entry for the wallet |
| `0x0107` | `NETWORK_MISMATCH` | Chain or network differ from the wallet's entry, or do not match each other |
| `0x0108` | `POLICY_VERSION_MISMATCH` | The request's policy version differs from the installed one |
| `0x0109` | `PAYLOAD_TOO_LARGE` | A field cap was exceeded |
| `0x010A` | `PAYLOAD_MISSING` | The transaction bytes are empty, or only a digest was supplied |
| `0x010B` | `SIGNER_SET_INVALID` | (v2) The signer set is invalid or omits this signer |
| `0x010C` | `ISSUER_NOT_AUTHORIZED` | The key is not pinned for that purpose or tag |
| `0x010D` | `SUBJECT_MISMATCH` | (v2) The envelope subject differs from the one it arrived on |
| `0x0201` | `TX_MALFORMED` | The transaction does not parse |
| `0x0202` | `TX_TRAILING_BYTES` | Input continues after the transaction |
| `0x0203` | `TX_UNKNOWN_FIELD` | A field outside the grammar |
| `0x0204` | `TX_DUPLICATE_FIELD` | A field appears more than once |
| `0x0205` | `TX_NON_CANONICAL` | A non-minimal encoding, or a re-encoding that differs from the input |
| `0x0206` | `TX_SHAPE_NOT_ALLOWED` | A contract type, count, memo or other shape outside the allowlist |
| `0x0207` | `TX_SELECTOR_NOT_ALLOWED` | A call selector other than the allowlisted transfer |
| `0x0208` | `TX_VALUE_NOT_ALLOWED` | A call value, token fields on a token call, or a zero token amount |
| `0x0209` | `TX_PERMISSION_NOT_ALLOWED` | The transaction's permission is not configured for the wallet |
| `0x020A` | `TX_SENDER_MISMATCH` | The transaction's owner is not the wallet's address |
| `0x020B` | `TX_EXPIRY_OUT_OF_BOUNDS` | Expired, or valid for too long |
| `0x020C` | `TX_FEE_OVER_BOUND` | The fee limit is above the decoder bound |
| `0x020D` | `TX_DIGEST_MISMATCH` | A digest claimed by the caller differs from the recomputed one |
| `0x020E` | `TX_CHAIN_ID_MISMATCH` | (EVM) The transaction's chain id differs from the network |
| `0x0301` | `NO_POLICY` | No policy bundle is installed (deny by default) |
| `0x0302` | `BUNDLE_INVALID` | The bundle's signatures or quorum do not verify |
| `0x0303` | `BUNDLE_ROLLBACK` | The bundle's version is not newer than the installed one |
| `0x0304` | `BUNDLE_NOT_EFFECTIVE` | A loosening bundle's time-lock is still running |
| `0x0305` | `ASSET_NOT_ALLOWED` | No rule for the asset, or a token that is not allowlisted |
| `0x0306` | `RECIPIENT_NOT_ALLOWED` | The recipient is not on the allowlist |
| `0x0307` | `AMOUNT_OVER_TX_CAP` | The amount is above the per-transaction cap |
| `0x0308` | `FEE_OVER_CAP` | The fee is above the policy fee cap |
| `0x0309` | `VALIDITY_OVER_CAP` | The validity window is above the policy maximum |
| `0x0401` | `INITIATOR_INVALID` | The initiator statement has a bad signature, an unknown key or the wrong role |
| `0x0402` | `APPROVALS_INSUFFICIENT` | Fewer valid approvals than the amount tier requires |
| `0x0403` | `APPROVAL_INVALID` | An approval signature does not verify |
| `0x0404` | `APPROVER_UNKNOWN` | An approval key is not in the approver set |
| `0x0405` | `APPROVER_DUPLICATE` | The same approver key appears more than once |
| `0x0406` | `SOD_VIOLATION` | The initiator key is also an approver key |
| `0x0407` | `APPROVAL_EXPIRED` | An approval statement has expired |
| `0x0408` | `APPROVAL_INTENT_MISMATCH` | An approval's intent digest differs from the recomputed one |
| `0x0501` | `VELOCITY_EXCEEDED` | The spend reservation would exceed this signer's velocity cap |
| `0x0502` | `FROZEN` | The wallet is frozen |
| `0x0503` | `BREAKER_TRIPPED` | An auto-pause trigger fired |
| `0x0504` | `CLOCK_UNTRUSTED` | The clock went backwards past its high-water mark, or is out of the skew bound |
| `0x0601` | `STATE_WRITE_FAILED` | A durable write (velocity, replay or receipt log) failed |
| `0x0602` | `KEY_UNAVAILABLE` | The signing key or share failed to load |
| `0x0603` | `INTERNAL` | An internal invariant was violated |
| `0x0701` | `GROUP_EXISTS` | (v2) Key generation over an existing group |
| `0x0702` | `KEYGEN_INTENT_INVALID` | (v2) The key-generation intent is invalid |
| `0x0703` | `AUX_EPOCH_UNKNOWN` | (v2) No auxiliary material for the node set and epoch |
| `0x0704` | `ADMIN_QUORUM_INSUFFICIENT` | An M-of-N admin action is short of its quorum |
| `0xF001` | `BUSY` | The signer's queue is full |
| `0xF002` | `TIMEOUT` | A deadline passed |
| `0xF003` | `PEER_UNREACHABLE` | A peer or the message bus is unreachable |
| `0xF004` | `ENGINE_ABORT` | (v2) The signing protocol aborted |
