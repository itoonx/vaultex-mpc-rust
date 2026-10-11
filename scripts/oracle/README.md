# Independent vector oracle (T13-2)

A second implementation of the kernel RFCs, written from the RFC text alone, that must reproduce their test vectors byte for byte (ROADMAP M6 #7; KAT plan §5).

| RFC | What the oracle implements |
|---|---|
| [`INTENT_V1`](../../specs/INTENT_V1.md) | The strict TRON decoder (§7: reader rules V1–V3 and R1–R9, the ordered checks of §7.3, the canonical re-encoding), `BCS(IntentV1)`, `IntentDigest` and `BCS(SignInput)` |
| [`RECEIPT_V1`](../../specs/RECEIPT_V1.md) | Receipt BCS with strict decoding (§5), the receipt digest, strict Ed25519 verification (§6.3), the writer rules W4/W5 and the offline log verifier (§7.2) |

**Independence.** A different agent from the WS-05 implementer wrote it, from `specs/INTENT_V1.md` and `specs/RECEIPT_V1.md` only (including the registry in `RECEIPT_V1` Appendix A). It never read the Rust kernel's source, its tests or the generator behind the vectors. It reads the same vector files as the Rust tests (`crates/vaultex-verify/vectors/`).

**Dependencies.** Only the Node standard library (Node ≥ 20). There is nothing to `npm install`.
- `node:crypto` provides SHA-256, SHA-512 and Ed25519 signing.
- Ed25519 verification follows `RECEIPT_V1` §6.3 step by step, with RFC 8032 §5.1 arithmetic written out in `BigInt`. A library call alone is not the RFC's rule: `node:crypto` verification accepts the small-order cases of vectors `R-010` and `R-011`, which §6.3 refuses. A self-test pins that difference.

## Run

```sh
node scripts/oracle/run.mjs            # every vector + cross-file links; --verbose lists each one
node --test scripts/oracle/            # self-tests of the oracle
```

`run.mjs` exits `0` when every vector agrees, `1` on any disagreement, and `2` when a vector file is malformed. It accepts `--intent FILE` and `--receipt FILE` to point at other copies.

## What a pass means

- **Each vector:**
  - An accept matches every intent field, `intent_bcs`, `intent_digest` and `sign_input_bcs`.
  - A refusal matches the first failing check, its code and its registry name.
  - A receipt log matches the written bodies, digests, signatures, log and head, or the verifier's result, check and index.
- **The files themselves (KAT plan R10):**
  - The harness fails on zero vectors, any unknown key, a code whose name disagrees with the registry, or a check table that differs from the RFC's.
  - It also fails when a check other than `NON_CANONICAL_ENCODING` has no vector.
- **Cross-file links** (§9 of both RFCs): the writer vector's receipts name the intent digests of `INTENT_V1-A-002` and `A-001`. Its decoder refusal is the memo refusal of `A-002`.
- **Self-tests:**
  - RFC 8032 §7.1 TEST 1 and TEST 2.
  - The worked examples of both RFCs, offset by offset.
  - The strict-rule edge cases.
  - 38,000 deterministic mutants of the accept vectors, none of which may crash the decoder or reach `NON_CANONICAL_ENCODING` (§7.3 step 7).
  - Mutated vector files, which must fail.

## Choices where the RFC text is open

- An Ed25519 key or `R` whose y-coordinate is not reduced is refused, as RFC 8032 §5.1.3 says. `RECEIPT_V1` §11 Q3 leaves this open for keys. No vector covers it.
- A decode context whose `network` is not on the allowlist is refused as `NETWORK_NOT_TRON`, since an unknown network has no chain.
- Neither RFC gives the transaction bytes behind the writer vector's second receipt ("`A-002` with a memo added"). The oracle rebuilds them as `A-002` with the memo field of `INTENT_V1-R-039` placed in field order. That reproduces the receipt's `tx_hash`.
