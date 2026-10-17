# INTENT_V1: Transfer intents decoded from unsigned transactions

- RFC: INTENT_V1
- Status: DRAFT
- Writer: WS-05 (R3 TRON decoding, R6 adversarial vectors; R1 reviews encodings)
- Implementation: `crates/vaultex-verify` (module `tron`); types in `crates/vaultex-types` (`IntentV1`, `IntentDigest`, `SignInput`)
- Vectors: `crates/vaultex-verify/vectors/INTENT_V1/intent_v1.json`
- Comment window: not yet open
- Discussion: none yet (the owner opens it with the comment window)
- Supersedes: none
- Related ADRs: ADR-04 (v1 support matrix), ADR-11 (policy distribution), ADR-15 (decoder diversity)

## 1. Summary

An intent states what a transaction does: which wallet pays whom, in which asset, how much, at most what fee, until when, and on which network. A Vaultex signer never takes an intent from a caller. It decodes the exact unsigned transaction it is asked to sign and either derives the intent from those bytes or refuses with a registered code. This RFC specifies the intent, its canonical encoding and its digest (what initiators and approvers sign statements about), and, for TRON, the strict decoding of an unsigned transaction into an intent.

## 2. Scope

**In scope:**

- The `IntentV1` data model, its BCS encoding and its digest, `IntentDigest` (§4–§6).
- `SignInput`: what a signer's key or engine signs after an accept (§4.3).
- The TRON decoder: the two accepted transaction shapes, the decode context, every check in order with its refusal code, and the canonical form (§5.2, §7).

**Out of scope:**

- Policy evaluation, approvals, velocity and receipts. They are specified by `POLICY_BUNDLE_V1` (T05-7b), the approvals design (T05-4) and `RECEIPT_V1`. §6.3 notes, informatively, how statements bind to the intent digest.
- Where the decode context comes from. Apart from the wallet id, the clock and the optional txid claim, every context value is a fact of the verified policy bundle (`POLICY_BUNDLE_V1`). This RFC fixes what the decoder does with the values.
- Chains other than TRON. Their chain codes are reserved (§4.2); each chain gets its own decoder section in a later version.
- Whether a transaction's reference block belongs to the network. That needs a view of the chain (§10).
- Broadcasting, and the chain's signature format.

**Boundary.** The caller supplies the unsigned bytes and the wallet id, and may claim a txid. Everything else the decoder reads comes from state the signer has verified itself.

## 3. Terminology

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

| Term | Meaning |
|---|---|
| **raw** | The unsigned, protobuf-encoded TRON `Transaction.raw` (the `raw_data` that the chain hashes and the owner signs). |
| **Intent** | An `IntentV1` value (§4.1). |
| **Decode context** | The inputs of the decoder other than raw (§4.4). |
| **Check** | One validation rule of §7. Each has a stable name in upper snake case, such as `MEMO_PRESENT`, and maps to exactly one wire refusal code. |
| **Refusal** | The first check that fails, in the order of §7.3. The wire result is its refusal code; implementations SHOULD also record the check name locally. |
| **Wire code** | A `u16` from the refusal-code registry of contracts v0 (`RECEIPT_V1` Appendix A). |
| **sun** | 10⁻⁶ TRX. |
| **Base unit** | A token's smallest unit. This RFC never applies decimals. |
| **varint, field number, wire type** | Protobuf wire-format terms. Wire type 0 is a varint; wire type 2 is length-delimited. |
| **int64 range** | `1 ..= 2⁶³ − 1`. A zero value is never encoded (§7.2 R9), and `2⁶³` and above are negative `int64` values on the wire. |
| `x[a..b]` | Bytes `a` (inclusive) to `b` (exclusive) of `x`, counted from 0. |
| `‖` | Concatenation. |

Hex is written in lower case. Integers in the vector file are decimal strings.

## 4. Data model

### 4.1 `IntentV1`

| # | Field | Type | Meaning | TRON value (§7.5) |
|---|---|---|---|---|
| 1 | `wallet_id` | `WalletId` | The wallet (key group) that would sign | context `wallet_id` |
| 2 | `chain` | `ChainId` | The chain | `1` (TRON) |
| 3 | `network` | `NetworkId` | The network the wallet's key is pinned to | context `network` |
| 4 | `sender` | `Address` | The paying address, decoded | `owner_address` |
| 5 | `recipient` | `Address` | The receiving address, decoded | `to_address`, or `0x41 ‖` the calldata recipient |
| 6 | `asset` | `AssetId` | What moves | `Native`, or `Contract(contract_address)` |
| 7 | `amount` | `U256` | The amount, in base units | `amount`, or the calldata amount |
| 8 | `fee_cap` | `U256` | The chain-native fee bound | `0`, or `fee_limit` in sun |
| 9 | `not_after_ms` | `u64` | The transaction's own expiry, in milliseconds since the Unix epoch | `expiration` |
| 10 | `tx_hash` | `TxHash` | SHA-256 of the unsigned transaction bytes | `SHA-256(raw)` |

All fields are required. An intent has no free-text field.

### 4.2 Field types

| Type | Definition |
|---|---|
| `WalletId` | ASCII string matching `[a-z0-9-]{1,64}`. |
| `ChainId` | `u16` registry code, append-only, never reused. `0x0001` TRON (the only chain with a decoder in this version); `0x0002` EVM, `0x0003` Bitcoin, `0x0004` Solana, `0x0005` Sui and `0x0006` Aptos are reserved. |
| `NetworkId` | A CAIP-2 id from a closed allowlist. Its namespace fixes its chain. TRON ids are decimal; the hexadecimal alias form is not on the list. |
| `Address` | A byte string. On TRON, 21 bytes: `0x41 ‖ 20 bytes`. |
| `AssetId` | An enum: variant 0 `Native` (the chain's coin, TRX on TRON); variant 1 `Contract(Address)` (a token contract, TRC-20 on TRON). |
| `U256` | An unsigned 256-bit integer. It compares numerically. |
| `TxHash` | 32 bytes. |

The network allowlist in this version:

| `NetworkId` | Chain | Network |
|---|---|---|
| `tron:728126428` | TRON | Mainnet |
| `tron:2494104990` | TRON | Shasta testnet |
| `tron:3448148188` | TRON | Nile testnet |
| `eip155:1` | EVM | Ethereum mainnet |
| `eip155:11155111` | EVM | Sepolia testnet |

### 4.3 `SignInput`

What the signer's key or MPC engine signs after an accept. It is produced only by the signer's own decode.

| Variant | Index | Fields | Meaning |
|---|---|---|---|
| `EcdsaPreimage` | 0 | `hash: EcdsaHash`, `bytes: bytes` | ECDSA over `hash(bytes)`; `bytes` is the chain's signing preimage |
| `Ed25519Message` | 1 | `bytes` | Ed25519 over the exact message the chain verifies |

`EcdsaHash` is an enum: 0 `Sha256` (TRON), 1 `Keccak256` (EVM), 2 `Sha256d` (Bitcoin).

For a TRON accept, `SignInput` is `EcdsaPreimage { hash: Sha256, bytes: raw }`. There is deliberately no variant that carries a ready-made digest. The signer hashes the preimage itself, so it knows what it signs.

### 4.4 TRON decode context

| Field | Type | Meaning | Source |
|---|---|---|---|
| `wallet_id` | `WalletId` | The wallet the decision is for | The request, checked against the signer's registry |
| `network` | `NetworkId` | The network the wallet's key is pinned to | Bundle |
| `wallet_address` | 21 bytes | The wallet's TRON address | Bundle |
| `permission_id` | `u8` | The permission the wallet signs under: `0` (owner) or an active permission id | Bundle |
| `trc20_allowlist` | list of 21-byte addresses | The token contracts `transfer` may be called on | Bundle |
| `now_ms` | `u64` | The signer's clock, in milliseconds since the Unix epoch | The signer; never the request |
| `max_validity_ms` | `u64` | The longest accepted `expiration − now_ms` | Bundle |
| `max_fee_limit_sun` | `u64` | The largest accepted `fee_limit` | Bundle |
| `max_clock_skew_ms` | `u64` | How far `timestamp` may run ahead of `now_ms` | Bundle |
| `claimed_txid` | optional 32 bytes | A txid the caller claims for raw | The request (optional) |

Constants of this RFC:

| Constant | Value | Use |
|---|---|---|
| `MAX_RAW_BYTES` | 512 | Inputs longer than this are refused before parsing. Both accepted shapes are under 256 bytes |
| `MAX_VALIDITY_MS` | 86,400,000 (24 h) | Hard ceiling on `max_validity_ms` |
| `MAX_FEE_LIMIT_SUN` | 15,000,000,000 (15,000 TRX) | Hard ceiling on `max_fee_limit_sun` |
| `MAX_NATIVE_AMOUNT_SUN` | 9,007,199,254,740,991 (`2⁵³ − 1`, about 9.0 billion TRX) | Hard ceiling on a native `amount`. It is JavaScript's `Number.MAX_SAFE_INTEGER`: tronweb reads `int64` fields as JS numbers, which are exact only up to this value, so above it JS tooling (tronweb, approver tools, the independent oracle) would show a rounded amount while the decoder and the chain read the exact one. TRC-20 amounts are 32-byte words that JS tooling reads exactly, and are not bounded |

A bundle can lower the validity and fee ceilings and can never raise them: a larger configured value is clamped to the ceiling (§7.3 step 6). `MAX_NATIVE_AMOUNT_SUN` has no context value; per-transaction amount caps belong to the policy bundle (`POLICY_BUNDLE_V1`).

## 5. Canonical encoding

### 5.1 BCS encoding of an intent

Everything this RFC hashes is encoded with BCS (Binary Canonical Serialization). The rules used here:

- Unsigned integers are fixed width and little-endian: `u16` 2 bytes, `u64` 8 bytes.
- Lengths and enum variant indexes are ULEB128, in their shortest form.
- A byte string or ASCII string is `ULEB128(length) ‖ bytes`.
- A fixed-size array, `U256` and `TxHash` are their raw bytes, with no length prefix. `U256` is 32 bytes, **little-endian**.
- A struct is the concatenation of its fields in the order of §4.1.
- `WalletId` and `NetworkId` encode as strings.

`BCS(IntentV1)`:

| # | Field | Bytes |
|---|---|---|
| 1 | `wallet_id` | `ULEB128(len) ‖ ASCII` |
| 2 | `chain` | `u16` LE |
| 3 | `network` | `ULEB128(len) ‖ ASCII` |
| 4 | `sender` | `ULEB128(len) ‖ bytes` |
| 5 | `recipient` | `ULEB128(len) ‖ bytes` |
| 6 | `asset` | `00` for `Native`; `01 ‖ ULEB128(len) ‖ bytes` for `Contract` |
| 7 | `amount` | 32 bytes LE |
| 8 | `fee_cap` | 32 bytes LE |
| 9 | `not_after_ms` | `u64` LE |
| 10 | `tx_hash` | 32 bytes |

**Worked example** (vector `INTENT_V1-A-002`, 226 bytes, identical to contracts v0 vector V-02):

| Offset | Bytes (hex) | Field |
|---|---|---|
| 0 | `24` ‖ `30303030…3031` | `wallet_id`, 36 bytes: `00000000-0000-4000-8000-000000000001` |
| 37 | `0100` | `chain` = 1 |
| 39 | `0f` ‖ `74726f6e3a32343934313034393930` | `network` = `tron:2494104990` |
| 55 | `15` ‖ `41` ‖ `11`×20 | `sender` |
| 77 | `15` ‖ `41` ‖ `22`×20 | `recipient` |
| 99 | `01` ‖ `15` ‖ `41` ‖ `99`×20 | `asset` = `Contract(0x41 99…99)` |
| 122 | `40420f00` ‖ `00`×28 | `amount` = 1,000,000 |
| 154 | `00e1f505` ‖ `00`×28 | `fee_cap` = 100,000,000 |
| 186 | `6052e6cf8b010000` | `not_after_ms` = 1,700,000,060,000 |
| 194 | `4145dae0…8ecbf99e` | `tx_hash` |

A verifier never decodes an intent it was sent: it derives the intent (§7). A tool that does read an encoded intent, for example to display it, MUST decode strictly: refuse input over 128 KiB before decoding, trailing bytes, non-minimal ULEB128, unknown enum variants, a `WalletId` outside its character set and length, and a `NetworkId` that is not on the allowlist, and it MUST require that re-encoding gives back the input byte for byte. Contracts v0 vectors N-07 and N-08 cover the identifier rules.

### 5.2 Canonical TRON raw

The decoder accepts only one encoding of each transaction: the one below. java-tron computes the txid over its own re-serialisation of raw, so only canonical bytes have `SHA-256(raw)` equal to the chain's txid (§6.2).

- Fields appear in ascending field-number order, each at most once, with the wire type of §7.1.
- Every varint (tag, value, length) is in its shortest form.
- Default values (0, empty) are never written. `Permission_id` is omitted when it is 0 (owner); `fee_limit` is omitted when absent.
- Nothing else is present.

The two accepted shapes, byte by byte (`<v>` is a varint, `<n>` a length varint):

```text
raw       := 0a 02 <ref_block_bytes:2>  22 08 <ref_block_hash:8>  40 <expiration>
             5a <n> <Contract>  70 <timestamp>  [90 01 <fee_limit>]
Contract  := 08 <type>  12 <n> <Any>  [28 <Permission_id>]
Any       := 0a <n> <type_url>  12 <n> <value>
Transfer  := 0a 15 <owner_address:21>  12 15 <to_address:21>  18 <amount>          (type 1)
Trigger   := 0a 15 <owner_address:21>  12 15 <contract_address:21>  22 44 <data:68>  (type 31)
data      := a9 05 9c bb ‖ 00×12 ‖ recipient[20] ‖ amount[32, big-endian]
```

`type_url` is the ASCII string `type.googleapis.com/protocol.TransferContract` (45 bytes) for type 1 and `type.googleapis.com/protocol.TriggerSmartContract` (49 bytes) for type 31.

### 5.3 BCS encoding of `SignInput`

`BCS(SignInput::EcdsaPreimage { Sha256, raw }) = 00 ‖ 00 ‖ ULEB128(len(raw)) ‖ raw`. For `INTENT_V1-A-002` (211 bytes) it starts `00 00 d3 01`.

## 6. Digests and signatures

### 6.1 Intent digest

```text
IntentDigest = SHA-256( BCS("VAULTEX/INTENT/v1") ‖ BCS(intent) )
BCS("VAULTEX/INTENT/v1") = 11 5641554c5445582f494e54454e542f7631
```

The tag is length-prefixed, so no tag is a prefix of another. Tags are protocol constants and do not follow product renames. Only this tag makes an intent digest.

### 6.2 Transaction hash and what the key signs

- `tx_hash = SHA-256(raw)`. For canonical raw (§5.2) it is the TRON transaction id.
- The TRON signature is secp256k1 ECDSA over `SHA-256(raw)`. The signer computes that hash from `SignInput.bytes` itself, and never signs a digest it did not compute.

### 6.3 Statements over an intent (informative)

Initiator and approver statements (contracts v0 `ApprovalStatementV1`) are Ed25519 signatures over `SHA-256(BCS("VAULTEX/APPROVAL/v1") ‖ BCS({intent_digest, role, not_after_s}))`. The verifier compares `intent_digest` with the digest of its **own** decode. Because the intent includes the wallet, the network and `tx_hash`, a statement binds to one exact transaction on one network. Which keys may sign, the k-of-n tiers, separation of duties and expiry belong to the approvals design and `POLICY_BUNDLE_V1`.

## 7. Validation and refusal (TRON)

### 7.1 Grammar

```text
raw      := 1 ref_block_bytes  4 ref_block_hash  8 expiration  11 contract  14 timestamp  [18 fee_limit]
Contract := 1 type  2 parameter:Any  [5 Permission_id]
Any      := 1 type_url  2 value
Transfer := 1 owner_address  2 to_address  3 amount                (type 1, TransferContract)
Trigger  := 1 owner_address  2 contract_address  4 data            (type 31, TriggerSmartContract)
```

Each message is read under a schema. A schema lists, for each allowed field number, either the wire type its value must have or the check that refuses it. Any other field number is refused.

| Message | Field | Rule |
|---|---|---|
| raw | 1 `ref_block_bytes` | bytes |
| | 4 `ref_block_hash` | bytes |
| | 8 `expiration` | varint |
| | 10 `data` (memo) | refuse: `MEMO_PRESENT` |
| | 11 `contract` | bytes (the field is `repeated` upstream; here it occurs once) |
| | 14 `timestamp` | varint |
| | 18 `fee_limit` | varint |
| Contract | 1 `type` | varint |
| | 2 `parameter` | bytes |
| | 5 `Permission_id` | varint |
| Any | 1 `type_url` | bytes |
| | 2 `value` | bytes |
| Transfer | 1 `owner_address` | bytes |
| | 2 `to_address` | bytes |
| | 3 `amount` | varint |
| Trigger | 1 `owner_address` | bytes |
| | 2 `contract_address` | bytes |
| | 3 `call_value` | refuse: `CALL_VALUE_PRESENT` |
| | 4 `data` | bytes |
| | 5 `call_token_value` | refuse: `TRC10_FIELDS_PRESENT` |
| | 6 `token_id` | refuse: `TRC10_FIELDS_PRESENT` |

Fields left out on purpose include raw `ref_block_num` (3), `auths` (9) and `scripts` (12), and Contract `provider` (3) and `ContractName` (4). They are refused by `FIELD_NOT_ALLOWED`.

### 7.2 Reading one message

A message's bytes are the whole input (for raw) or the value bytes of the field that holds it. A message has no end marker, so bytes after the last field are read as further fields; the TRON decoder therefore never returns `TX_TRAILING_BYTES`.

**Varints.** A varint is read in 7-bit groups, least significant first, at most 10 bytes:

- V1. The input ends before a byte without the continuation bit: `PB_MALFORMED`.
- V2. The 10th byte is greater than 1 (more than 64 bits; checked as soon as that byte is read): `PB_MALFORMED`.
- V3. A varint of two or more bytes whose last byte is `00` (not the shortest form): `PB_NON_CANONICAL_VARINT`.

**Fields.** Until the message's bytes are used up, for each field, in this order:

- R1. Read the key as a varint (V1–V3).
- R2. Field number = key >> 3; wire type = key & 7. Field number 0: `PB_MALFORMED`.
- R3. A field number the schema does not list: `FIELD_NOT_ALLOWED`.
- R4. A field the schema refuses: that field's check (`MEMO_PRESENT`, `CALL_VALUE_PRESENT` or `TRC10_FIELDS_PRESENT`), whatever its wire type and value.
- R5. A wire type other than the schema's (0 for a varint field, 2 for a bytes field): `PB_WIRE_TYPE`.
- R6. A field already read in this message: `PB_DUPLICATE_FIELD`. A second contract is refused here.
- R7. A field number lower than the previous field's: `PB_FIELD_ORDER`.
- R8. Read the value: a varint (V1–V3), or a length varint (V1–V3) followed by that many bytes. A length beyond the remaining bytes: `PB_MALFORMED`.
- R9. A varint value of 0, or an empty bytes value: `PB_DEFAULT_VALUE`.

### 7.3 Decoding procedure

An implementation MUST apply the steps below in order and report the **first** check that fails. Checks inside one step apply in the order written. Arithmetic is exact: a sum or difference is computed without overflow, and `now_ms − V` below 0 is taken as 0.

1. **Context and size.**
   1. The chain of `network` is not TRON: `NETWORK_NOT_TRON`.
   2. raw is empty: `EMPTY`.
   3. raw is longer than `MAX_RAW_BYTES`: `TOO_LARGE`.
2. **raw.** Read raw under its schema (§7.2). Then:
   1. If any of `ref_block_bytes`, `ref_block_hash`, `expiration`, `contract` or `timestamp` is absent: `MISSING_FIELD`.
   2. If `expiration`, then `timestamp`, then `fee_limit` (when present) is above `2⁶³ − 1`: `INT_RANGE`.
3. **Contract, then Any.** Read `contract` under the Contract schema. If `type` or `parameter` is absent: `MISSING_FIELD`. An absent `Permission_id` means 0. Read `parameter` under the Any schema. If `type_url` or `value` is absent: `MISSING_FIELD`.
4. **Contract type.**
   - **Type 1:** `type_url` other than the TransferContract URL (§5.2): `TYPE_URL_MISMATCH`. Read `value` under the Transfer schema. If `owner_address`, `to_address` or `amount` is absent: `MISSING_FIELD`. If `amount` is above `2⁶³ − 1`: `INT_RANGE`.
   - **Type 31:** `type_url` other than the TriggerSmartContract URL: `TYPE_URL_MISMATCH`. Read `value` under the Trigger schema. If `owner_address`, `contract_address` or `data` is absent: `MISSING_FIELD`.
   - **Type 46** (`AccountPermissionUpdateContract`): `ACCOUNT_PERMISSION_UPDATE`.
   - **Any other type:** `CONTRACT_TYPE_NOT_ALLOWED`.
5. **Transaction facts.**
   1. `claimed_txid` is present and differs from `SHA-256(raw)`: `DIGEST_MISMATCH`.
   2. `ref_block_bytes` is not 2 bytes, or `ref_block_hash` is not 8 bytes: `REF_BLOCK_SHAPE`.
   3. `Permission_id` is 1 (witness), or differs from the context's `permission_id`: `PERMISSION_ID_MISMATCH`.
   4. `owner_address`, then the counterparty (`to_address` for type 1, `contract_address` for type 31), is not 21 bytes starting with `0x41`: `ADDRESS_SHAPE`.
   5. `owner_address` differs from `wallet_address`: `OWNER_NOT_WALLET`.
6. **Shape.**
   - **Type 1:** `to_address` equals `owner_address`: `SELF_TRANSFER`. `fee_limit` is present: `FEE_LIMIT_ON_NATIVE`. `amount` is above `MAX_NATIVE_AMOUNT_SUN` (`2⁵³ − 1`): `NATIVE_AMOUNT_OVER_BOUND`.
   - **Type 31**, in this order:
     1. `data` is shorter than 4 bytes: `CALLDATA_LENGTH`.
     2. `data[0..4]` is not `a9059cbb` (`transfer(address,uint256)`): `SELECTOR_NOT_TRANSFER`.
     3. `data` is not exactly 68 bytes: `CALLDATA_LENGTH`.
     4. Any byte of `data[4..16]` is not zero: `CALLDATA_ADDRESS_PADDING`.
     5. `data[16..36]` is all zero: `RECIPIENT_ZERO`.
     6. `data[36..68]` is all zero: `AMOUNT_ZERO`.
     7. `contract_address` is not in `trc20_allowlist`: `TOKEN_NOT_ALLOWLISTED`.
     8. `fee_limit` is absent: `FEE_LIMIT_MISSING`.
     9. `fee_limit` is above `min(max_fee_limit_sun, MAX_FEE_LIMIT_SUN)`: `FEE_LIMIT_OVER_BOUND`.
   - Then, with `V = min(max_validity_ms, MAX_VALIDITY_MS)`:
     1. `expiration ≤ now_ms`, or `expiration > now_ms + V`: `EXPIRATION_WINDOW`.
     2. `timestamp > expiration`, or `timestamp > now_ms + max_clock_skew_ms`, or `timestamp < now_ms − V`: `TIMESTAMP_INVALID`.
7. **Canonical form.** Encode the decoded fields as in §5.2. If the result differs from raw: `NON_CANONICAL_ENCODING`.

A reader that applies §7.2 exactly refuses every non-canonical form before step 7, so step 7 never fires in a conforming implementation. It MUST still be implemented: it is the backstop for a reader that misses a form, and it ties the accepted bytes to the chain's txid (§5.2).

### 7.4 Checks and refusal codes

Several checks share one wire code. The registry is coarse on purpose; the check name stays in local logs and vectors.

| Check | Where | Refused when | Code | Code name |
|---|---|---|---|---|
| `NETWORK_NOT_TRON` | 1.1 | The context network is not a TRON network | `0x0107` | `NETWORK_MISMATCH` |
| `EMPTY` | 1.2 | raw is empty | `0x010A` | `PAYLOAD_MISSING` |
| `TOO_LARGE` | 1.3 | raw exceeds 512 bytes | `0x0109` | `PAYLOAD_TOO_LARGE` |
| `PB_MALFORMED` | V1, V2, R2, R8 | Truncated input, a length past the end, a varint over 64 bits, field number 0 | `0x0201` | `TX_MALFORMED` |
| `PB_NON_CANONICAL_VARINT` | V3 | A varint not in its shortest form | `0x0205` | `TX_NON_CANONICAL` |
| `FIELD_NOT_ALLOWED` | R3 | A field outside the schema | `0x0203` | `TX_UNKNOWN_FIELD` |
| `MEMO_PRESENT` | R4 | raw carries `data` (a memo) | `0x0206` | `TX_SHAPE_NOT_ALLOWED` |
| `CALL_VALUE_PRESENT` | R4 | The call carries `call_value` | `0x0208` | `TX_VALUE_NOT_ALLOWED` |
| `TRC10_FIELDS_PRESENT` | R4 | The call carries `call_token_value` or `token_id` | `0x0208` | `TX_VALUE_NOT_ALLOWED` |
| `PB_WIRE_TYPE` | R5 | A wire type other than the schema's | `0x0201` | `TX_MALFORMED` |
| `PB_DUPLICATE_FIELD` | R6 | A field occurs twice (including a second contract) | `0x0204` | `TX_DUPLICATE_FIELD` |
| `PB_FIELD_ORDER` | R7 | Fields out of ascending order | `0x0205` | `TX_NON_CANONICAL` |
| `PB_DEFAULT_VALUE` | R9 | A 0 or empty value written out | `0x0205` | `TX_NON_CANONICAL` |
| `MISSING_FIELD` | 2.1, 3, 4 | A required field is absent | `0x0201` | `TX_MALFORMED` |
| `INT_RANGE` | 2.2, 4 | An `int64` value above `2⁶³ − 1` | `0x0201` | `TX_MALFORMED` |
| `TYPE_URL_MISMATCH` | 4 | `type_url` does not match the contract type | `0x0206` | `TX_SHAPE_NOT_ALLOWED` |
| `ACCOUNT_PERMISSION_UPDATE` | 4 | A permission change (type 46) | `0x0206` | `TX_SHAPE_NOT_ALLOWED` |
| `CONTRACT_TYPE_NOT_ALLOWED` | 4 | Any contract type other than 1 and 31 | `0x0206` | `TX_SHAPE_NOT_ALLOWED` |
| `DIGEST_MISMATCH` | 5.1 | The claimed txid differs from `SHA-256(raw)` | `0x020D` | `TX_DIGEST_MISMATCH` |
| `REF_BLOCK_SHAPE` | 5.2 | Reference-block fields of the wrong length | `0x0201` | `TX_MALFORMED` |
| `PERMISSION_ID_MISMATCH` | 5.3 | The witness permission, or not the configured permission | `0x0209` | `TX_PERMISSION_NOT_ALLOWED` |
| `ADDRESS_SHAPE` | 5.4 | An address that is not `0x41 ‖ 20 bytes` | `0x0201` | `TX_MALFORMED` |
| `OWNER_NOT_WALLET` | 5.5 | The owner is not the wallet's address | `0x020A` | `TX_SENDER_MISMATCH` |
| `SELF_TRANSFER` | 6 | A native transfer to the sender | `0x0206` | `TX_SHAPE_NOT_ALLOWED` |
| `FEE_LIMIT_ON_NATIVE` | 6 | A native transfer with `fee_limit` | `0x0206` | `TX_SHAPE_NOT_ALLOWED` |
| `NATIVE_AMOUNT_OVER_BOUND` | 6 | A native amount above `2⁵³ − 1` sun | `0x0208` | `TX_VALUE_NOT_ALLOWED` |
| `CALLDATA_LENGTH` | 6.1, 6.3 | Call data shorter than a selector, or not 68 bytes | `0x0207` | `TX_SELECTOR_NOT_ALLOWED` |
| `SELECTOR_NOT_TRANSFER` | 6.2 | Any selector other than `a9059cbb` | `0x0207` | `TX_SELECTOR_NOT_ALLOWED` |
| `CALLDATA_ADDRESS_PADDING` | 6.4 | Non-zero padding in the recipient word | `0x0205` | `TX_NON_CANONICAL` |
| `RECIPIENT_ZERO` | 6.5 | A token transfer to the zero address | `0x0206` | `TX_SHAPE_NOT_ALLOWED` |
| `AMOUNT_ZERO` | 6.6 | A token transfer of 0 | `0x0208` | `TX_VALUE_NOT_ALLOWED` |
| `TOKEN_NOT_ALLOWLISTED` | 6.7 | A token not on the allowlist | `0x0305` | `ASSET_NOT_ALLOWED` |
| `FEE_LIMIT_MISSING` | 6.8 | A token transfer without `fee_limit` | `0x0206` | `TX_SHAPE_NOT_ALLOWED` |
| `FEE_LIMIT_OVER_BOUND` | 6.9 | `fee_limit` above the bound | `0x020C` | `TX_FEE_OVER_BOUND` |
| `EXPIRATION_WINDOW` | 6 | Expired, or valid for longer than the bound | `0x020B` | `TX_EXPIRY_OUT_OF_BOUNDS` |
| `TIMESTAMP_INVALID` | 6 | `timestamp` after expiry, too far ahead, or too old | `0x020B` | `TX_EXPIRY_OUT_OF_BOUNDS` |
| `NON_CANONICAL_ENCODING` | 7 | Re-encoding differs from raw | `0x0205` | `TX_NON_CANONICAL` |

### 7.5 Accept

If no check fails, the decoder returns the intent and the sign input:

| Field | Type 1 (native TRX) | Type 31 (TRC-20) |
|---|---|---|
| `wallet_id`, `network` | From the context | From the context |
| `chain` | `1` | `1` |
| `sender` | `owner_address` | `owner_address` |
| `recipient` | `to_address` | `0x41 ‖ data[16..36]` |
| `asset` | `Native` | `Contract(contract_address)` |
| `amount` | `amount` | `data[36..68]` read as a big-endian unsigned integer |
| `fee_cap` | `0` | `fee_limit` |
| `not_after_ms` | `expiration` | `expiration` |
| `tx_hash` | `SHA-256(raw)` | `SHA-256(raw)` |

`SignInput` is `EcdsaPreimage { hash: Sha256, bytes: raw }`.

## 8. Versioning and compatibility

- The layout version is carried in the digest tag (`VAULTEX/INTENT/v1`). Once this RFC is `ACCEPTED`, the bytes of `IntentV1` are frozen. A new field or a changed meaning is a new type with tag `VAULTEX/INTENT/v2` and a new RFC.
- The decoder's results are part of this RFC. After `ACCEPTED`, accepting a new shape, or changing a check, its order or its code, needs a new RFC version, even when the intent bytes do not change. Receipts record the verifier build that decided (`RECEIPT_V1`).
- Registries grow by appending: chain codes, networks and refusal codes are never reused. A network a verifier does not know cannot be decoded, so it fails closed. Readers upgrade before writers.
- Decoders for other chains arrive as new sections in a later version. They do not change any TRON result.
- Signers and approver tools MUST implement the same version. A digest computed under another version never matches, because the tag differs.

## 9. Test vectors

**File:** `crates/vaultex-verify/vectors/INTENT_V1/intent_v1.json` (JSON, hex strings, integers as decimal strings).

**Top level:**

| Key | Content |
|---|---|
| `rfc`, `rfc_version`, `kind` | `INTENT_V1`, the RFC version targeted, and the vector kind of the KAT plan |
| `generated_by` | Generators and versions (provenance) |
| `constants` | `MAX_RAW_BYTES`, `MAX_VALIDITY_MS`, `MAX_FEE_LIMIT_SUN` and the intent tag |
| `checks` | Every check of §7.4 with its code and code name, in table order |
| `untested_checks` | Checks with no vector, each with its reason (only `NON_CANONICAL_ENCODING`, §7.3 step 7) |
| `vectors` | The vectors |

**One vector:** `id`, `rule`, `base`, `description`, `input`, `expect`.

- `id`: `INTENT_V1-A-nnn` (accept) or `INTENT_V1-R-nnn` (refuse).
- `rule`: `ACCEPT_NATIVE`, `ACCEPT_TRC20`, or the check name the vector exercises.
- `base`: the accept vector this one differs from, or `null`.
- `input.raw_tx`: raw, in hex. `input.ctx`: the full decode context (§4.4): `wallet_id`, `network`, `wallet_address`, `permission_id`, `trc20_allowlist`, `now_ms`, `max_validity_ms`, `max_fee_limit_sun`, `max_clock_skew_ms`, `claimed_txid` (hex or `null`).
- `expect.accept`: `tx_hash`, the decoded `intent` (each field of §4.1; `asset` is `{"kind": "native"}` or `{"kind": "contract", "address": …}`), `intent_bcs`, `intent_digest` and `sign_input_bcs`.
- `expect.refuse`: `check`, `code` (as `0x…`) and `name` (the registry name).

**Running a vector.** Decode `raw_tx` under `ctx`. An accept vector passes when every field, `BCS(intent)`, the intent digest and `BCS(SignInput)` match. A refuse vector passes when the first failing check, its code and its code name match. A harness MUST fail when the file holds no vectors, when a vector has an unknown key, or when a code and its name disagree with the registry (KAT plan R10).

**Coverage.** 146 vectors: 19 accept, 127 refuse. Every check except `NON_CANONICAL_ENCODING` and `NATIVE_AMOUNT_OVER_BOUND` has at least one refuse vector. Each refuse vector with a `base` changes one property of it (KAT plan R3): one field, one encoding detail, the call data, or one context value. The precedence vectors below change two on purpose.

**Boundaries** (KAT plan R5; each pair is at the bound and one past it):

| Bound | Accepted at the bound | Refused past it |
|---|---|---|
| Input size, 512 bytes (inclusive) | `R-004` (passes the size check, then refused for its padding field) | `R-003` |
| Native amount, `1 ..= 2⁵³ − 1` | `A-005` (1); `2⁵³ − 1`: no vector yet | `R-026` (0); `2⁵³`: no vector yet |
| Native `int64` range, `2⁶³ − 1` | — | `R-062` (`2⁶³`, `INT_RANGE`) |
| Token amount, `1 ..= 2²⁵⁶ − 1` | `A-007`, `A-008` | `R-107` (0) |
| Configured `fee_limit` bound (inclusive) | `A-010` | `R-111` |
| `fee_limit` ceiling, 15,000 TRX | `A-011` | `R-112` |
| Configured validity (inclusive) | `A-010` | `R-115` |
| Validity ceiling, 24 h | `A-012` | `R-116` |
| Expiry after `now_ms` (exclusive) | `A-013` | `R-113` |
| `timestamp ≤ expiration` | `A-014` | `R-117` |
| `timestamp ≤ now_ms + max_clock_skew_ms` | `A-015` | `R-118` |
| `timestamp ≥ now_ms − V` | `A-016` | `R-119` |

**Vector file behind this draft.** The file was generated from the draft of 2026-10-11, before `NATIVE_AMOUNT_OVER_BOUND` (§7.3 step 6). Its `checks` table does not list that check, it has no vector at that bound, and `A-006` (a native amount of `2⁶³ − 1` sun) still expects an accept that this draft refuses. The file is regenerated once the independent oracle implements the check; until then the oracle checks the file against the 2026-10-11 draft, and the decoder's own tests pin the bound.

**Precedence** (two properties changed; the order of §7.3 decides): `R-120` to `R-127`, plus `R-039` (a memo after the last field: R4 before R7) and `R-041` (an explicit zero `call_value`: R4 before R9).

**Links to other vectors.** `A-002`'s intent is contracts v0 vector V-02, and its digest is V-03. The intent digests of `A-001` and `A-002` appear in the `RECEIPT_V1-A-001` receipts.

**Provenance.** The raw bytes of `A-001` and `A-002` are tronweb output, the reference vectors that the chains crate's encoder tests also pin. Every other input is derived from them. The expected values come from a separate Python standard-library generator: a protobuf writer, a decoder written from §7 of this RFC, BCS and SHA-256. It shares no code with the Rust kernel, and it must agree with the check each vector was built to hit. The generator was written by the author of this RFC; the independent oracle (T13-2), written from this text by a different author, has not reproduced the vectors yet. `A-003` and `A-019` (with `Permission_id`) are constructed, not captured from tronweb (§11).

**CI.** The Rust kernel and the independent oracle MUST read this same file and agree on every result, code and byte (KAT plan §5).

## 10. Security considerations

- **Substituted intent.** The signer derives the intent from the bytes it signs, so a caller cannot show approvers one transfer and have the signer sign another. Approvals bind to the digest of the signer's own decode (§6.3).
- **Parser differentials.** Two parsers that read the same bytes differently are a classic way to slip a payload past a check. The decoder accepts exactly one encoding per transaction (§5.2), refuses every field it does not understand, and requires the re-encoding to be byte-equal, so the bytes it judged are the bytes the chain hashes. A defect shared by every signer (common mode) is not prevented by having many signers. It is bounded by the independent oracle, differential tests against the chain SDK, fuzzing, velocity caps and auto-pause, and optionally by a second, independently written decoder at one or more signers (ADR-15).
- **Allowance-class calls.** Only `transfer(address,uint256)` is accepted. `approve`, `increaseAllowance`, `transferFrom` and every other selector are refused, because an approval leaves a standing allowance that can be drained without another signature.
- **Permission changes.** Permission updates are refused outright, the witness permission is never accepted, and `Permission_id` must equal the configured permission.
- **Hidden payloads.** Memos, call value and TRC-10 token fields are refused, as are fields outside the grammar.
- **Network context.** TRON bytes carry no network id, and every TRON network uses the same address prefix. The network comes from the bundle, so a wallet key MUST be pinned to one network (one key per network). The intent and its digest include the network, so a statement for one network does not verify for another.
- **Reference block.** The decoder checks only the reference block's shape. It does not rely on the chain's own reference-block check to bind a transaction to a network; the per-network key above does that.
- **Time.** `now_ms` is the signer's own clock. Expiry is bounded (24 h at most), so a signed transaction does not stay valid indefinitely. Clock attacks are handled outside the decoder (the breaker's clock checks).
- **Fees.** `fee_limit` is bounded for token calls and refused on native transfers.
- **Amounts.** Amounts are base units; decimals come from the bundle. `U256` keeps all 256 bits and is never truncated. A native amount above `2⁵³ − 1` sun is refused, so JS tooling, which reads `int64` fields as JS numbers, shows an approver the same amount the decoder decided on.
- **Zero recipient.** A token transfer to the zero address is refused. A native transfer to the zero address is left to the policy's recipient allowlist (§11).
- **Resource use.** The size cap is checked before parsing. Parsing is a single pass over at most 512 bytes.
- **Refusals reveal only a class.** A refusal carries a code, never input bytes.

## 11. Open questions

1. **Native zero-address recipient.** Should the decoder refuse it, as it does for tokens, or leave it to the policy recipient allowlist?
2. **`Permission_id` reference capture.** `A-003` and `A-019` are constructed bytes. They become reference vectors once a tronweb capture confirms where `Permission_id` is written.
3. **Finer wire codes.** Several checks share a code (§7.4). Should the registry gain finer codes, appended, so that receipts name the exact check? `NATIVE_AMOUNT_OVER_BOUND` uses `TX_VALUE_NOT_ALLOWED` because the registry has no amount-bound code (the fee analogue is `TX_FEE_OVER_BOUND`); a dedicated code is still to be requested.
4. **A ceiling for `max_clock_skew_ms`.** It is bounded in effect by `timestamp ≤ expiration ≤ now_ms + V`. Is a separate ceiling wanted?
5. **Reference-block freshness.** Should a signer that holds a view of the chain also bound the reference block's age? That needs chain data, which the kernel does not read.
6. **Where the statement format lives.** §6.3 is informative. Should the approval statement be specified here, or with the approvals design and `POLICY_BUNDLE_V1`?
7. **Decoder diversity.** Should at least one signer decode with an independently written decoder (ADR-15)?

## 12. Changelog

- 2026-10-11: First draft (T05-7a), with 146 vectors.
- 2026-10-16: `NATIVE_AMOUNT_OVER_BOUND`: native amounts above `2⁵³ − 1` sun are refused (owner decision, T05-2b). The vector file is not regenerated yet (§9).
