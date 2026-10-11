//! Strict TRON decoder (ROADMAP M6 #2): from the exact unsigned `Transaction.raw` bytes a signer is
//! asked to sign, to the intent those bytes would authorise, or a refusal.
//!
//! # Accepted shapes (everything else is refused)
//!
//! - **Native TRX transfer:** one `TransferContract` (type 1) from the wallet to another address,
//!   with no `fee_limit`.
//! - **TRC-20 transfer:** one `TriggerSmartContract` (type 31) calling `transfer(address,uint256)`
//!   on an allowlisted token contract, with no call value, no TRC-10 token fields, a non-zero
//!   recipient and amount, and a `fee_limit`.
//!
//! ```text
//! raw      := 1 ref_block_bytes[2]  4 ref_block_hash[8]  8 expiration  11 contract  14 timestamp
//!             [18 fee_limit]
//! Contract := 1 type  2 parameter:Any  [5 Permission_id]
//! Any      := 1 type_url  2 value
//! Transfer := 1 owner_address[21]  2 to_address[21]  3 amount
//! Trigger  := 1 owner_address[21]  2 contract_address[21]  4 data[68]
//! data     := a9059cbb ‖ 00×12 ‖ recipient[20] ‖ amount[32, big-endian]
//! ```
//!
//! # Checks, in refusal order (the first failure is reported)
//!
//! 1. **Context and size:** the network is a TRON network; the input is 1 to [`MAX_RAW_BYTES`].
//! 2. **Strict protobuf, then grammar, message by message from the outside in** (raw, Contract,
//!    Any, value):
//!    - the profile in `pb.rs`: allowlisted fields only, each once and in ascending order,
//!      matching wire types, minimal varints, no encoded defaults, no trailing bytes. Memo/data,
//!      `call_value` and TRC-10 fields get their own refusals;
//!    - required fields present; `int64` values in `1..=2^63−1`; contract type 1 or 31 with the
//!      matching `type_url` (`AccountPermissionUpdate`, type 46, has its own refusal).
//! 3. **Semantics:** a claimed txid equals `sha256(raw)`; reference-block shape; `Permission_id`
//!    equals the wallet's (absent means 0, owner; 1, witness, is never accepted); address shape
//!    `0x41 ‖ 20`; owner is the wallet; native: not to itself, no `fee_limit`; TRC-20: selector,
//!    length, zero padding, recipient and amount non-zero, allowlisted token, `fee_limit` present
//!    and within bound; `now < expiration ≤ now + validity bound`; `timestamp ≤ expiration` and
//!    within `[now − validity bound, now + skew]`.
//! 4. **Canonical form:** re-encoding the decoded fields with an encoder written apart from the
//!    reader must give back the input byte for byte. java-tron computes the txid over its own
//!    re-serialisation of `raw`, so only canonical bytes have `sha256(raw)` equal to the chain txid.
//!
//! # Limits
//!
//! - TRON bytes carry no network id, and every TRON network uses the `0x41` prefix. The network is
//!   a fact of the policy bundle, so a wallet key must be pinned to one network.
//! - Whether the reference block belongs to that network is not checked here: it needs a view of
//!   the chain.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod encode;
mod pb;

use vaultex_types::{
    Address, AssetId, ChainId, EcdsaHash, IntentV1, NetworkId, Refusal, RefusalCode, SignInput,
    TxHash, WalletId, U256,
};

use encode::Call;
use pb::{Rule, Value};

/// Largest `Transaction.raw` the decoder reads. The two accepted shapes are 133 to 213 bytes.
pub const MAX_RAW_BYTES: usize = 512;
/// Hard ceiling on `expiration − now`: 24 hours, the chain's own maximum.
pub const MAX_VALIDITY_MS: u64 = 86_400_000;
/// Hard ceiling on `fee_limit`: 15,000 TRX in sun, the mainnet maximum.
pub const MAX_FEE_LIMIT_SUN: u64 = 15_000_000_000;

/// What the decoder needs besides the bytes. Every field except `claimed_txid` comes from the
/// verified policy bundle or the caller's own clock, never from the request being decided.
#[derive(Clone, Debug)]
pub struct TronDecodeCtx<'a> {
    /// The wallet the decision is for.
    pub wallet_id: &'a WalletId,
    /// The network the wallet's key is pinned to.
    pub network: NetworkId,
    /// The wallet's TRON address, `0x41 ‖ 20 bytes`.
    pub wallet_address: [u8; 21],
    /// The permission the wallet signs under: 0 (owner, sent as an absent `Permission_id`) or an
    /// active permission id.
    pub permission_id: u8,
    /// The TRC-20 token contracts the wallet may call `transfer` on.
    pub trc20_allowlist: &'a [[u8; 21]],
    /// The caller's clock, in milliseconds since the Unix epoch.
    pub now_ms: u64,
    /// Longest accepted `expiration − now`. Values above [`MAX_VALIDITY_MS`] are clamped to it.
    pub max_validity_ms: u64,
    /// Largest accepted `fee_limit`, in sun. Values above [`MAX_FEE_LIMIT_SUN`] are clamped to it.
    pub max_fee_limit_sun: u64,
    /// How far the transaction's `timestamp` may run ahead of `now_ms`.
    pub max_clock_skew_ms: u64,
    /// A txid the caller claims for the bytes. If present, it must equal `sha256(raw)`.
    pub claimed_txid: Option<TxHash>,
}

/// Why the decoder refused: one variant per check, so a test can tell which check fired.
///
/// [`code`](Self::code) maps each to the wire refusal-code registry, which is coarser. The variant
/// carries no input bytes.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TronRefusal {
    /// The context's network is not a TRON network.
    NetworkNotTron,
    /// The input is empty.
    Empty,
    /// The input is longer than [`MAX_RAW_BYTES`].
    TooLarge,
    /// Truncated input, a length beyond the input, a varint over 64 bits, or field number 0.
    PbMalformed,
    /// A varint (tag, value or length) is not in its minimal encoding.
    PbNonCanonicalVarint,
    /// A field's wire type is not the one its schema names.
    PbWireType,
    /// A field occurs more than once (including a second contract).
    PbDuplicateField,
    /// Fields are not in ascending field-number order.
    PbFieldOrder,
    /// A proto3 default value (0 or empty) is encoded explicitly.
    PbDefaultValue,
    /// A field outside the message's allowlist (e.g. `ref_block_num`, `auths`, `scripts`,
    /// `provider`, `ContractName`, or an unknown field).
    FieldNotAllowed,
    /// The transaction carries a memo (`raw.data`).
    MemoPresent,
    /// The contract call carries a `call_value`.
    CallValuePresent,
    /// The contract call carries TRC-10 `call_token_value` or `token_id`.
    Trc10FieldsPresent,
    /// A required field is absent.
    MissingField,
    /// An `int64` value is outside `1..=2^63−1`.
    IntRange,
    /// A contract type other than `TransferContract` or `TriggerSmartContract`.
    ContractTypeNotAllowed,
    /// An `AccountPermissionUpdateContract` (a permission change).
    AccountPermissionUpdate,
    /// The parameter's `type_url` does not match the contract type.
    TypeUrlMismatch,
    /// `sha256(raw)` differs from the txid the caller claimed.
    DigestMismatch,
    /// `ref_block_bytes` is not 2 bytes, or `ref_block_hash` is not 8 bytes.
    RefBlockShape,
    /// `Permission_id` differs from the wallet's, or is the witness permission.
    PermissionIdMismatch,
    /// An address is not `0x41 ‖ 20 bytes`.
    AddressShape,
    /// The owner address is not the wallet's address.
    OwnerNotWallet,
    /// A native transfer to the sender itself.
    SelfTransfer,
    /// A token transfer of zero.
    AmountZero,
    /// Contract-call data shorter than a selector, or not 68 bytes.
    CalldataLength,
    /// A call selector other than `transfer(address,uint256)` (`a9059cbb`).
    SelectorNotTransfer,
    /// Non-zero high bytes in the recipient word of the calldata.
    CalldataAddressPadding,
    /// A token transfer to the zero address.
    RecipientZero,
    /// The token contract is not on the wallet's allowlist.
    TokenNotAllowlisted,
    /// A token transfer without `fee_limit`.
    FeeLimitMissing,
    /// A native transfer with a `fee_limit`.
    FeeLimitOnNative,
    /// `fee_limit` is above the bound.
    FeeLimitOverBound,
    /// The transaction has expired, or expires later than the validity bound allows.
    ExpirationWindow,
    /// `timestamp` is after `expiration`, or outside `[now − validity bound, now + skew]`.
    TimestampInvalid,
    /// Re-encoding the decoded fields does not give back the input.
    NonCanonicalEncoding,
}

impl TronRefusal {
    /// The wire refusal code (registry in `vaultex-types`).
    pub fn code(self) -> RefusalCode {
        // ponytail: the wire registry is coarse by design; the variant keeps the exact check for
        // tests and local logs. A finer wire code would be an append to the registry (WS-03).
        use TronRefusal as R;
        match self {
            R::NetworkNotTron => RefusalCode::NETWORK_MISMATCH,
            R::Empty => RefusalCode::PAYLOAD_MISSING,
            R::TooLarge => RefusalCode::PAYLOAD_TOO_LARGE,
            R::PbMalformed
            | R::PbWireType
            | R::MissingField
            | R::IntRange
            | R::RefBlockShape
            | R::AddressShape => RefusalCode::TX_MALFORMED,
            R::PbNonCanonicalVarint
            | R::PbFieldOrder
            | R::PbDefaultValue
            | R::CalldataAddressPadding
            | R::NonCanonicalEncoding => RefusalCode::TX_NON_CANONICAL,
            R::PbDuplicateField => RefusalCode::TX_DUPLICATE_FIELD,
            R::FieldNotAllowed => RefusalCode::TX_UNKNOWN_FIELD,
            R::MemoPresent
            | R::ContractTypeNotAllowed
            | R::AccountPermissionUpdate
            | R::TypeUrlMismatch
            | R::SelfTransfer
            | R::RecipientZero
            | R::FeeLimitMissing
            | R::FeeLimitOnNative => RefusalCode::TX_SHAPE_NOT_ALLOWED,
            R::CallValuePresent | R::Trc10FieldsPresent | R::AmountZero => {
                RefusalCode::TX_VALUE_NOT_ALLOWED
            }
            R::CalldataLength | R::SelectorNotTransfer => RefusalCode::TX_SELECTOR_NOT_ALLOWED,
            R::TokenNotAllowlisted => RefusalCode::ASSET_NOT_ALLOWED,
            R::DigestMismatch => RefusalCode::TX_DIGEST_MISMATCH,
            R::PermissionIdMismatch => RefusalCode::TX_PERMISSION_NOT_ALLOWED,
            R::OwnerNotWallet => RefusalCode::TX_SENDER_MISMATCH,
            R::FeeLimitOverBound => RefusalCode::TX_FEE_OVER_BOUND,
            R::ExpirationWindow | R::TimestampInvalid => RefusalCode::TX_EXPIRY_OUT_OF_BOUNDS,
        }
    }

    /// The wire refusal (no policy rule is involved).
    pub fn refusal(self) -> Refusal {
        Refusal {
            code: self.code(),
            rule_index: None,
        }
    }
}

const RAW: [(u64, Rule); 7] = [
    (1, Rule::Bytes),  // ref_block_bytes
    (4, Rule::Bytes),  // ref_block_hash
    (8, Rule::Varint), // expiration
    (10, Rule::Refuse(TronRefusal::MemoPresent)),
    (11, Rule::Bytes),  // contract (repeated upstream; exactly once here)
    (14, Rule::Varint), // timestamp
    (18, Rule::Varint), // fee_limit
];
const CONTRACT: [(u64, Rule); 3] = [
    (1, Rule::Varint), // type
    (2, Rule::Bytes),  // parameter
    (5, Rule::Varint), // Permission_id
];
const ANY: [(u64, Rule); 2] = [(1, Rule::Bytes), (2, Rule::Bytes)];
const TRANSFER: [(u64, Rule); 3] = [
    (1, Rule::Bytes),  // owner_address
    (2, Rule::Bytes),  // to_address
    (3, Rule::Varint), // amount
];
const TRIGGER: [(u64, Rule); 6] = [
    (1, Rule::Bytes), // owner_address
    (2, Rule::Bytes), // contract_address
    (3, Rule::Refuse(TronRefusal::CallValuePresent)),
    (4, Rule::Bytes),                                   // data
    (5, Rule::Refuse(TronRefusal::Trc10FieldsPresent)), // call_token_value
    (6, Rule::Refuse(TronRefusal::Trc10FieldsPresent)), // token_id
];

const ACCOUNT_PERMISSION_UPDATE_TYPE: u64 = 46;
const WITNESS_PERMISSION_ID: u64 = 1;
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const I64_MAX: u64 = i64::MAX as u64;

/// Decodes `raw` (the unsigned `Transaction.raw` bytes) into the intent it authorises and the
/// exact input the signer signs, or refuses. See the module docs for the grammar and check order.
pub fn decode(raw: &[u8], ctx: &TronDecodeCtx<'_>) -> Result<(IntentV1, SignInput), TronRefusal> {
    use TronRefusal as R;

    // 1. Context and size.
    if ctx.network.chain() != ChainId::TRON {
        return Err(R::NetworkNotTron);
    }
    if raw.is_empty() {
        return Err(R::Empty);
    }
    if raw.len() > MAX_RAW_BYTES {
        return Err(R::TooLarge);
    }

    // 2. Strict protobuf and grammar, from the outside in.
    let [ref_block_bytes, ref_block_hash, expiration, _memo, contract, timestamp, fee_limit] =
        pb::read(raw, &RAW)?;
    let ref_block_bytes = bytes(ref_block_bytes)?;
    let ref_block_hash = bytes(ref_block_hash)?;
    let expiration = varint(expiration)?;
    let contract = bytes(contract)?;
    let timestamp = varint(timestamp)?;
    let expiration = int64(expiration)?;
    let timestamp = int64(timestamp)?;
    let fee_limit = opt_varint(fee_limit).map(int64).transpose()?;

    let [contract_type, parameter, permission_id] = pb::read(contract, &CONTRACT)?;
    let contract_type = varint(contract_type)?;
    let parameter = bytes(parameter)?;
    // Absent means 0 (owner); an explicit 0 was refused as an encoded default.
    let permission_id = opt_varint(permission_id).unwrap_or(0);

    let [type_url, value] = pb::read(parameter, &ANY)?;
    let type_url = bytes(type_url)?;
    let value = bytes(value)?;

    let call = match contract_type {
        encode::TRANSFER_TYPE => {
            if type_url != encode::TRANSFER_URL.as_bytes() {
                return Err(R::TypeUrlMismatch);
            }
            let [owner, to, amount] = pb::read(value, &TRANSFER)?;
            Call::Transfer {
                owner: bytes(owner)?,
                to: bytes(to)?,
                amount: int64(varint(amount)?)?,
            }
        }
        encode::TRIGGER_TYPE => {
            if type_url != encode::TRIGGER_URL.as_bytes() {
                return Err(R::TypeUrlMismatch);
            }
            let [owner, contract, _call_value, data, _call_token_value, _token_id] =
                pb::read(value, &TRIGGER)?;
            Call::Trigger {
                owner: bytes(owner)?,
                contract: bytes(contract)?,
                data: bytes(data)?,
            }
        }
        ACCOUNT_PERMISSION_UPDATE_TYPE => return Err(R::AccountPermissionUpdate),
        _ => return Err(R::ContractTypeNotAllowed),
    };

    // 3. Semantics.
    let tx_hash = TxHash::of(raw);
    if ctx.claimed_txid.is_some_and(|claimed| claimed != tx_hash) {
        return Err(R::DigestMismatch);
    }
    if ref_block_bytes.len() != 2 || ref_block_hash.len() != 8 {
        return Err(R::RefBlockShape);
    }
    if permission_id == WITNESS_PERMISSION_ID || permission_id != u64::from(ctx.permission_id) {
        return Err(R::PermissionIdMismatch);
    }
    let (owner, counterparty) = match call {
        Call::Transfer { owner, to, .. } => (owner, to),
        Call::Trigger {
            owner, contract, ..
        } => (owner, contract),
    };
    let (owner, counterparty) = (address(owner)?, address(counterparty)?);
    if owner != ctx.wallet_address {
        return Err(R::OwnerNotWallet);
    }
    let (recipient, asset, amount, fee_cap) = match call {
        Call::Transfer { amount, .. } => {
            if counterparty == owner {
                return Err(R::SelfTransfer);
            }
            if fee_limit.is_some() {
                return Err(R::FeeLimitOnNative);
            }
            (counterparty, AssetId::Native, U256::from(amount), 0)
        }
        Call::Trigger { data, .. } => {
            let (recipient, amount) = trc20_transfer(data)?;
            if !ctx.trc20_allowlist.contains(&counterparty) {
                return Err(R::TokenNotAllowlisted);
            }
            let fee_limit = fee_limit.ok_or(R::FeeLimitMissing)?;
            if fee_limit > ctx.max_fee_limit_sun.min(MAX_FEE_LIMIT_SUN) {
                return Err(R::FeeLimitOverBound);
            }
            let token = AssetId::Contract(Address(counterparty.to_vec()));
            (recipient, token, amount, fee_limit)
        }
    };
    let validity = ctx.max_validity_ms.min(MAX_VALIDITY_MS);
    if expiration <= ctx.now_ms || expiration > ctx.now_ms.saturating_add(validity) {
        return Err(R::ExpirationWindow);
    }
    if timestamp > expiration
        || timestamp > ctx.now_ms.saturating_add(ctx.max_clock_skew_ms)
        || timestamp < ctx.now_ms.saturating_sub(validity)
    {
        return Err(R::TimestampInvalid);
    }

    // 4. Canonical form.
    ensure_canonical(
        raw,
        &encode::Tx {
            ref_block_bytes,
            ref_block_hash,
            expiration,
            call,
            permission_id,
            timestamp,
            fee_limit,
        },
    )?;

    let intent = IntentV1 {
        wallet_id: ctx.wallet_id.clone(),
        chain: ChainId::TRON,
        network: ctx.network,
        sender: Address(owner.to_vec()),
        recipient: Address(recipient.to_vec()),
        asset,
        amount,
        fee_cap: U256::from(fee_cap),
        not_after_ms: expiration,
        tx_hash,
    };
    let sign_input = SignInput::EcdsaPreimage {
        hash: EcdsaHash::Sha256,
        bytes: raw.to_vec(),
    };
    Ok((intent, sign_input))
}

/// Check 4. Through [`decode`] it cannot fail while the reader and the encoder agree: the reader
/// already refuses every non-canonical form it knows. It is the backstop for one they miss.
fn ensure_canonical(raw: &[u8], tx: &encode::Tx<'_>) -> Result<(), TronRefusal> {
    if encode::encode(tx) == raw {
        Ok(())
    } else {
        Err(TronRefusal::NonCanonicalEncoding)
    }
}

/// `transfer(address,uint256)` calldata → (recipient, amount).
fn trc20_transfer(data: &[u8]) -> Result<([u8; 21], U256), TronRefusal> {
    use TronRefusal as R;
    let (selector, args) = data.split_first_chunk::<4>().ok_or(R::CalldataLength)?;
    if *selector != TRANSFER_SELECTOR {
        return Err(R::SelectorNotTransfer);
    }
    if args.len() != 64 {
        return Err(R::CalldataLength);
    }
    let (padding, rest) = args.split_first_chunk::<12>().ok_or(R::CalldataLength)?;
    let (recipient, amount) = rest.split_first_chunk::<20>().ok_or(R::CalldataLength)?;
    let mut amount: [u8; 32] = amount.try_into().map_err(|_| R::CalldataLength)?;
    if padding.iter().any(|b| *b != 0) {
        return Err(R::CalldataAddressPadding);
    }
    if recipient.iter().all(|b| *b == 0) {
        return Err(R::RecipientZero);
    }
    if amount.iter().all(|b| *b == 0) {
        return Err(R::AmountZero);
    }
    let recipient: [u8; 21] = [[0x41].as_slice(), recipient]
        .concat()
        .try_into()
        .map_err(|_| R::CalldataLength)?;
    amount.reverse(); // ABI words are big-endian; `U256` is little-endian
    Ok((recipient, U256(amount)))
}

fn address(bytes: &[u8]) -> Result<[u8; 21], TronRefusal> {
    match <[u8; 21]>::try_from(bytes) {
        Ok(address @ [0x41, ..]) => Ok(address),
        _ => Err(TronRefusal::AddressShape),
    }
}

fn bytes(value: Option<Value<'_>>) -> Result<&[u8], TronRefusal> {
    match value {
        Some(Value::Bytes(b)) => Ok(b),
        _ => Err(TronRefusal::MissingField),
    }
}

fn varint(value: Option<Value<'_>>) -> Result<u64, TronRefusal> {
    opt_varint(value).ok_or(TronRefusal::MissingField)
}

fn opt_varint(value: Option<Value<'_>>) -> Option<u64> {
    match value {
        Some(Value::Varint(v)) => Some(v),
        _ => None,
    }
}

/// A positive `int64`. Zero never reaches here (an encoded 0 is refused as a default value).
fn int64(v: u64) -> Result<u64, TronRefusal> {
    if v > I64_MAX {
        Err(TronRefusal::IntRange)
    } else {
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Check 4 cannot be reached through `decode` (see `ensure_canonical`), so its negative test
    /// drives the check directly with fields that do not match the input.
    #[test]
    fn refuses_noncanonical_reencode() {
        let (owner, to) = ([0x41; 21], [0x42; 21]);
        let tx = |timestamp| encode::Tx {
            ref_block_bytes: &[0, 1],
            ref_block_hash: &[1, 2, 3, 4, 5, 6, 7, 8],
            expiration: 1_700_000_060_000,
            call: Call::Transfer {
                owner: &owner,
                to: &to,
                amount: 1_000_000,
            },
            permission_id: 0,
            timestamp,
            fee_limit: None,
        };
        let raw = encode::encode(&tx(1_700_000_000_000));
        assert_eq!(ensure_canonical(&raw, &tx(1_700_000_000_000)), Ok(()));
        assert_eq!(
            ensure_canonical(&raw, &tx(1_700_000_000_001)),
            Err(TronRefusal::NonCanonicalEncoding)
        );
    }
}
