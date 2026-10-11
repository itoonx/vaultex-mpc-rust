//! Strict TRON decoder: the accepted vectors, and one named negative test per refusal
//! (`TronRefusal` variant). `NonCanonicalEncoding` cannot be reached through `decode`; its negative
//! test is the unit test `tron::tests::refuses_noncanonical_reencode`.
//!
//! Every negative input changes one thing in an accepted vector, so the refusal under test is the
//! first check that fails. Inputs are built with a small protobuf writer that is independent of the
//! kernel's encoder; `test_builder_reproduces_the_vectors` pins it to the vectors.

use vaultex_types::{
    Address, AssetId, ChainId, EcdsaHash, IntentV1, NetworkId, RefusalCode, SignInput, TxHash,
    WalletId, U256,
};
use vaultex_verify::tron::{
    decode, TronDecodeCtx, TronRefusal, MAX_FEE_LIMIT_SUN, MAX_RAW_BYTES, MAX_VALIDITY_MS,
};

// ───────────────────────────── vectors (synthetic addresses) ─────────────────────────────

/// tronweb `TransferContract`, 1 TRX from 0x41 11… to 0x41 22… (also pinned in the chains crate).
const NATIVE_HEX: &str = "0a0200012208010203040506070840e0a499ffbc315a67080112630a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412320a15411111111111111111111111111111111111111111121541222222222222222222222222222222222222222218c0843d7080d095ffbc31";
const NATIVE_TXID: &str = "e0139655d946fbdeeff8a8a0bfe82453354b97245fab8c13fb3ba39016a494e2";
/// tronweb TRC-20 `transfer` of 1,000,000 base units of token 0x41 99… to 0x41 22….
const TRC20_HEX: &str = "0a0200012208010203040506070840e0a499ffbc315aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a1541111111111111111111111111111111111111111112154199999999999999999999999999999999999999992244a9059cbb000000000000000000000000222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000f42407080d095ffbc31900180c2d72f";
const TRC20_TXID: &str = "4145dae04fdc27be8a6e585f2596591ef861bc06ea2d6c31c3eac1348ecbf99e";
/// The TRC-20 vector with `Permission_id = 2` (an active permission). Constructed by an
/// independent script, not yet captured from tronweb: it becomes a reference vector once a tronweb
/// capture confirms where `Permission_id` goes.
const TRC20_PERM2_HEX: &str = "0a0200012208010203040506070840e0a499ffbc315ab001081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a1541111111111111111111111111111111111111111112154199999999999999999999999999999999999999992244a9059cbb000000000000000000000000222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000f424028027080d095ffbc31900180c2d72f";
const TRC20_PERM2_TXID: &str = "01c6144118e25c4a0900a6592aaea9fd0c3fea26245ce56158adb47cb67f0809";

const OWNER: [u8; 21] = addr(0x11);
const RCPT: [u8; 21] = addr(0x22);
const OTHER: [u8; 21] = addr(0x33);
const TOKEN: [u8; 21] = addr(0x99);
const TIMESTAMP: u64 = 1_700_000_000_000;
const EXPIRATION: u64 = 1_700_000_060_000;
/// Inside both vectors' validity windows.
const NOW: u64 = 1_700_000_010_000;
const FEE_LIMIT: u64 = 100_000_000;
const ALLOWLIST: [[u8; 21]; 1] = [TOKEN];

const TRANSFER_URL: &[u8] = b"type.googleapis.com/protocol.TransferContract";
const TRIGGER_URL: &[u8] = b"type.googleapis.com/protocol.TriggerSmartContract";
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

const fn addr(fill: u8) -> [u8; 21] {
    let mut a = [fill; 21];
    a[0] = 0x41;
    a
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ───────────────────────────── decoding helpers ─────────────────────────────

fn with_ctx<T>(
    edit: impl FnOnce(&mut TronDecodeCtx<'_>),
    run: impl FnOnce(&TronDecodeCtx<'_>) -> T,
) -> T {
    let wallet_id = WalletId::new("test-wallet").unwrap();
    let mut ctx = TronDecodeCtx {
        wallet_id: &wallet_id,
        network: NetworkId::new("tron:3448148188").unwrap(),
        wallet_address: OWNER,
        permission_id: 0,
        trc20_allowlist: &ALLOWLIST,
        now_ms: NOW,
        max_validity_ms: MAX_VALIDITY_MS,
        max_fee_limit_sun: MAX_FEE_LIMIT_SUN,
        max_clock_skew_ms: 120_000,
        claimed_txid: None,
    };
    edit(&mut ctx);
    run(&ctx)
}

fn accept_with(raw: &[u8], edit: impl FnOnce(&mut TronDecodeCtx<'_>)) -> (IntentV1, SignInput) {
    with_ctx(edit, |ctx| decode(raw, ctx)).unwrap_or_else(|r| panic!("refused with {r:?}"))
}

fn accept(raw: &[u8]) -> (IntentV1, SignInput) {
    accept_with(raw, |_| {})
}

fn refuse_with(raw: &[u8], edit: impl FnOnce(&mut TronDecodeCtx<'_>)) -> TronRefusal {
    match with_ctx(edit, |ctx| decode(raw, ctx)) {
        Ok(_) => panic!("accepted {}", to_hex(raw)),
        Err(refusal) => refusal,
    }
}

fn refuse(raw: &[u8]) -> TronRefusal {
    refuse_with(raw, |_| {})
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ───────────────────────────── independent protobuf writer ─────────────────────────────

fn varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
    out
}

/// A length-delimited field.
fn len(field: u64, bytes: &[u8]) -> Vec<u8> {
    [
        varint(field << 3 | 2),
        varint(bytes.len() as u64),
        bytes.to_vec(),
    ]
    .concat()
}

/// A varint field.
fn int(field: u64, v: u64) -> Vec<u8> {
    [varint(field << 3), varint(v)].concat()
}

/// Concatenates `(field number, encoded field)` parts in field order. The sort is stable, so an
/// extra part with the same number lands right after the base part (a duplicate).
fn join(mut parts: Vec<(u64, Vec<u8>)>) -> Vec<u8> {
    parts.sort_by_key(|(field, _)| *field);
    parts.into_iter().flat_map(|(_, bytes)| bytes).collect()
}

fn transfer_value(owner: &[u8], to: &[u8], amount: u64) -> Vec<u8> {
    [len(1, owner), len(2, to), int(3, amount)].concat()
}

fn trigger_value(owner: &[u8], contract: &[u8], data: &[u8]) -> Vec<u8> {
    [len(1, owner), len(2, contract), len(4, data)].concat()
}

fn calldata(selector: [u8; 4], padding: [u8; 12], recipient: &[u8], amount: [u8; 32]) -> Vec<u8> {
    [&selector[..], &padding, recipient, &amount].concat()
}

fn amount_word(amount: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&amount.to_be_bytes());
    word
}

/// One transaction as parts, so a test can change exactly one thing.
#[derive(Clone)]
struct Tx {
    ref_block_bytes: Vec<u8>,
    ref_block_hash: Vec<u8>,
    expiration: u64,
    contract_type: u64,
    type_url: Vec<u8>,
    value: Vec<u8>,
    permission_id: Option<u64>,
    timestamp: u64,
    fee_limit: Option<u64>,
    raw_extra: Vec<(u64, Vec<u8>)>,
    contract_extra: Vec<(u64, Vec<u8>)>,
    any_extra: Vec<(u64, Vec<u8>)>,
}

impl Tx {
    fn native() -> Self {
        Self {
            ref_block_bytes: vec![0x00, 0x01],
            ref_block_hash: vec![1, 2, 3, 4, 5, 6, 7, 8],
            expiration: EXPIRATION,
            contract_type: 1,
            type_url: TRANSFER_URL.to_vec(),
            value: transfer_value(&OWNER, &RCPT, 1_000_000),
            permission_id: None,
            timestamp: TIMESTAMP,
            fee_limit: None,
            raw_extra: vec![],
            contract_extra: vec![],
            any_extra: vec![],
        }
    }

    fn trc20() -> Self {
        Self {
            contract_type: 31,
            type_url: TRIGGER_URL.to_vec(),
            value: trigger_value(
                &OWNER,
                &TOKEN,
                &Self::transfer_calldata(&RCPT[1..], 1_000_000),
            ),
            fee_limit: Some(FEE_LIMIT),
            ..Self::native()
        }
    }

    fn transfer_calldata(recipient20: &[u8], amount: u64) -> Vec<u8> {
        calldata(TRANSFER_SELECTOR, [0; 12], recipient20, amount_word(amount))
    }

    fn trc20_with_data(data: &[u8]) -> Self {
        Self {
            value: trigger_value(&OWNER, &TOKEN, data),
            ..Self::trc20()
        }
    }

    fn any(&self) -> Vec<u8> {
        let mut parts = vec![(1, len(1, &self.type_url)), (2, len(2, &self.value))];
        parts.extend(self.any_extra.iter().cloned());
        join(parts)
    }

    fn contract(&self) -> Vec<u8> {
        let mut parts = vec![(1, int(1, self.contract_type)), (2, len(2, &self.any()))];
        parts.extend(self.permission_id.map(|p| (5, int(5, p))));
        parts.extend(self.contract_extra.iter().cloned());
        join(parts)
    }

    fn raw_parts(&self) -> Vec<(u64, Vec<u8>)> {
        let mut parts = vec![
            (1, len(1, &self.ref_block_bytes)),
            (4, len(4, &self.ref_block_hash)),
            (8, int(8, self.expiration)),
            (11, len(11, &self.contract())),
            (14, int(14, self.timestamp)),
        ];
        parts.extend(self.fee_limit.map(|f| (18, int(18, f))));
        parts.extend(self.raw_extra.iter().cloned());
        parts.sort_by_key(|(field, _)| *field);
        parts
    }

    fn raw(&self) -> Vec<u8> {
        join(self.raw_parts())
    }

    /// The raw transaction without field `field`.
    fn raw_without(&self, field: u64) -> Vec<u8> {
        join(
            self.raw_parts()
                .into_iter()
                .filter(|(f, _)| *f != field)
                .collect(),
        )
    }
}

// ───────────────────────────── accepted ─────────────────────────────

#[test]
fn test_builder_reproduces_the_vectors() {
    assert_eq!(to_hex(&Tx::native().raw()), NATIVE_HEX);
    assert_eq!(to_hex(&Tx::trc20().raw()), TRC20_HEX);
    let perm2 = Tx {
        permission_id: Some(2),
        ..Tx::trc20()
    };
    assert_eq!(to_hex(&perm2.raw()), TRC20_PERM2_HEX);
}

#[test]
fn accepts_tronweb_native_transfer() {
    let raw = hex(NATIVE_HEX);
    let (intent, sign_input) = accept(&raw);
    assert_eq!(to_hex(&intent.tx_hash.0), NATIVE_TXID);
    assert_eq!(intent.wallet_id.as_str(), "test-wallet");
    assert_eq!(intent.chain, ChainId::TRON);
    assert_eq!(intent.network.as_str(), "tron:3448148188");
    assert_eq!(intent.sender, Address(OWNER.to_vec()));
    assert_eq!(intent.recipient, Address(RCPT.to_vec()));
    assert_eq!(intent.asset, AssetId::Native);
    assert_eq!(intent.amount, U256::from(1_000_000));
    assert_eq!(intent.fee_cap, U256::from(0));
    assert_eq!(intent.not_after_ms, EXPIRATION);
    assert_eq!(
        sign_input,
        SignInput::EcdsaPreimage {
            hash: EcdsaHash::Sha256,
            bytes: raw
        }
    );
}

#[test]
fn accepts_tronweb_trc20_transfer() {
    let raw = hex(TRC20_HEX);
    let (intent, sign_input) = accept(&raw);
    assert_eq!(to_hex(&intent.tx_hash.0), TRC20_TXID);
    assert_eq!(intent.sender, Address(OWNER.to_vec()));
    assert_eq!(intent.recipient, Address(RCPT.to_vec()));
    assert_eq!(intent.asset, AssetId::Contract(Address(TOKEN.to_vec())));
    assert_eq!(intent.amount, U256::from(1_000_000));
    assert_eq!(intent.fee_cap, U256::from(FEE_LIMIT));
    assert_eq!(intent.not_after_ms, EXPIRATION);
    assert_eq!(
        sign_input,
        SignInput::EcdsaPreimage {
            hash: EcdsaHash::Sha256,
            bytes: raw
        }
    );
}

#[test]
fn accepts_active_permission_when_configured() {
    let raw = hex(TRC20_PERM2_HEX);
    let (intent, _) = accept_with(&raw, |c| c.permission_id = 2);
    assert_eq!(to_hex(&intent.tx_hash.0), TRC20_PERM2_TXID);
}

#[test]
fn accepts_a_matching_claimed_txid() {
    let raw = hex(NATIVE_HEX);
    accept_with(&raw, |c| c.claimed_txid = Some(TxHash::of(&raw)));
}

#[test]
fn token_amount_keeps_all_256_bits() {
    let mut word = [0u8; 32];
    word[0] = 0x01; // 2^248
    word[31] = 0x02;
    let raw = Tx::trc20_with_data(&calldata(TRANSFER_SELECTOR, [0; 12], &RCPT[1..], word)).raw();
    let (intent, _) = accept(&raw);
    let mut le = [0u8; 32];
    le[31] = 0x01;
    le[0] = 0x02;
    assert_eq!(intent.amount, U256(le));
    assert!(intent.amount > U256::from(u64::MAX));
}

#[test]
fn accepts_bounds_exactly() {
    // `expiration == now + validity bound` and `fee_limit == bound` are inside.
    let raw = hex(TRC20_HEX);
    accept_with(&raw, |c| {
        c.max_validity_ms = EXPIRATION - NOW;
        c.max_fee_limit_sun = FEE_LIMIT;
    });
    // A token transfer to the sender itself is a valid chain transaction (only native TRX refuses it).
    accept(&Tx::trc20_with_data(&Tx::transfer_calldata(&OWNER[1..], 1)).raw());
}

#[test]
fn every_refusal_has_a_registered_wire_code() {
    use TronRefusal as R;
    let all = [
        R::NetworkNotTron,
        R::Empty,
        R::TooLarge,
        R::PbMalformed,
        R::PbNonCanonicalVarint,
        R::PbWireType,
        R::PbDuplicateField,
        R::PbFieldOrder,
        R::PbDefaultValue,
        R::FieldNotAllowed,
        R::MemoPresent,
        R::CallValuePresent,
        R::Trc10FieldsPresent,
        R::MissingField,
        R::IntRange,
        R::ContractTypeNotAllowed,
        R::AccountPermissionUpdate,
        R::TypeUrlMismatch,
        R::DigestMismatch,
        R::RefBlockShape,
        R::PermissionIdMismatch,
        R::AddressShape,
        R::OwnerNotWallet,
        R::SelfTransfer,
        R::AmountZero,
        R::CalldataLength,
        R::SelectorNotTransfer,
        R::CalldataAddressPadding,
        R::RecipientZero,
        R::TokenNotAllowlisted,
        R::FeeLimitMissing,
        R::FeeLimitOnNative,
        R::FeeLimitOverBound,
        R::ExpirationWindow,
        R::TimestampInvalid,
        R::NonCanonicalEncoding,
    ];
    for r in all {
        let code = r.code();
        assert!(code.name().is_some(), "{r:?} maps to an unregistered code");
        assert!(!code.is_retryable(), "{r:?} must be a final refusal");
        assert_eq!(r.refusal().code, code);
        assert_eq!(r.refusal().rule_index, None);
    }
    assert_eq!(R::OwnerNotWallet.code(), RefusalCode::TX_SENDER_MISMATCH);
    assert_eq!(
        R::SelectorNotTransfer.code(),
        RefusalCode::TX_SELECTOR_NOT_ALLOWED
    );
}

// ───────────────────────────── refused: context and size ─────────────────────────────

#[test]
fn refuses_network_not_tron() {
    let r = refuse_with(&hex(NATIVE_HEX), |c| {
        c.network = NetworkId::new("eip155:11155111").unwrap()
    });
    assert_eq!(r, TronRefusal::NetworkNotTron);
}

#[test]
fn refuses_empty() {
    assert_eq!(refuse(&[]), TronRefusal::Empty);
}

#[test]
fn refuses_raw_too_large() {
    assert_eq!(refuse(&[0x0a; MAX_RAW_BYTES + 1]), TronRefusal::TooLarge);
}

// ───────────────────────────── refused: strict protobuf ─────────────────────────────

#[test]
fn refuses_pb_malformed() {
    let native = hex(NATIVE_HEX);
    // Truncated inside the last varint (timestamp).
    assert_eq!(
        refuse(&native[..native.len() - 1]),
        TronRefusal::PbMalformed
    );
    // Truncated inside a length-delimited value.
    assert_eq!(refuse(&native[..10]), TronRefusal::PbMalformed);
    // A length beyond the input.
    assert_eq!(refuse(&[0x0a, 0x05, 0x00, 0x01]), TronRefusal::PbMalformed);
    // Field number 0.
    assert_eq!(
        refuse(&[[0x00].as_slice(), &native].concat()),
        TronRefusal::PbMalformed
    );
    // A varint over 64 bits (10th byte > 1), and an 11-byte varint.
    let mut tx = Tx::native().raw_parts();
    tx[2].1 = [vec![0x40], vec![0xff; 9], vec![0x02]].concat();
    assert_eq!(refuse(&join(tx.clone())), TronRefusal::PbMalformed);
    tx[2].1 = [vec![0x40], vec![0xff; 10], vec![0x01]].concat();
    assert_eq!(refuse(&join(tx)), TronRefusal::PbMalformed);
}

#[test]
fn refuses_overlong_varint() {
    let native = hex(NATIVE_HEX);
    // The same expiration value with a redundant trailing zero group.
    let overlong = NATIVE_HEX.replace("40e0a499ffbc31", "40e0a499ffbcb100");
    assert_eq!(refuse(&hex(&overlong)), TronRefusal::PbNonCanonicalVarint);
    // An overlong tag (field 1, wire type 2 as `8a 00`).
    let tag = [&[0x8a, 0x00][..], &native[1..]].concat();
    assert_eq!(refuse(&tag), TronRefusal::PbNonCanonicalVarint);
    // An overlong length prefix (`82 00` for 2).
    let length = [&[0x0a, 0x82, 0x00][..], &native[2..]].concat();
    assert_eq!(refuse(&length), TronRefusal::PbNonCanonicalVarint);
}

#[test]
fn refuses_wrong_wiretype() {
    let swap = |index: usize, part: Vec<u8>| {
        let mut parts = Tx::native().raw_parts();
        parts[index].1 = part;
        refuse(&join(parts))
    };
    // expiration as bytes; ref_block_bytes as a varint; timestamp as fixed64 (wire type 1).
    assert_eq!(swap(2, len(8, b"x")), TronRefusal::PbWireType);
    assert_eq!(swap(0, int(1, 1)), TronRefusal::PbWireType);
    let fixed64 = [vec![14 << 3 | 1], TIMESTAMP.to_le_bytes().to_vec()].concat();
    assert_eq!(swap(4, fixed64), TronRefusal::PbWireType);
    // Contract.type as fixed32 (wire type 5), inside the contract message.
    let tx = Tx::native();
    let contract = [vec![1 << 3 | 5, 1, 0, 0, 0], len(2, &tx.any())].concat();
    let mut parts = tx.raw_parts();
    parts[3].1 = len(11, &contract);
    assert_eq!(refuse(&join(parts)), TronRefusal::PbWireType);
}

#[test]
fn refuses_second_contract() {
    let mut tx = Tx::trc20();
    tx.raw_extra = vec![(11, len(11, &tx.contract()))];
    assert_eq!(refuse(&tx.raw()), TronRefusal::PbDuplicateField);
}

#[test]
fn refuses_duplicate_scalar() {
    let mut tx = Tx::native();
    tx.raw_extra = vec![(8, int(8, EXPIRATION))];
    assert_eq!(refuse(&tx.raw()), TronRefusal::PbDuplicateField);
    let mut tx = Tx::native();
    tx.any_extra = vec![(2, len(2, &tx.value))];
    assert_eq!(refuse(&tx.raw()), TronRefusal::PbDuplicateField);
}

#[test]
fn refuses_field_reorder() {
    let mut parts = Tx::native().raw_parts();
    parts.swap(0, 1); // ref_block_hash before ref_block_bytes
    let raw: Vec<u8> = parts.into_iter().flat_map(|(_, b)| b).collect();
    assert_eq!(refuse(&raw), TronRefusal::PbFieldOrder);
    // to_address before owner_address.
    let value = [len(2, &RCPT), len(1, &OWNER), int(3, 1_000_000)].concat();
    let tx = Tx {
        value,
        ..Tx::native()
    };
    assert_eq!(refuse(&tx.raw()), TronRefusal::PbFieldOrder);
}

#[test]
fn refuses_explicit_default() {
    // Permission_id = 0 written out (absent is the canonical form of the owner permission).
    let tx = Tx {
        permission_id: Some(0),
        ..Tx::native()
    };
    assert_eq!(refuse(&tx.raw()), TronRefusal::PbDefaultValue);
    let tx = Tx {
        fee_limit: Some(0),
        ..Tx::trc20()
    };
    assert_eq!(refuse(&tx.raw()), TronRefusal::PbDefaultValue);
    let tx = Tx {
        ref_block_bytes: vec![],
        ..Tx::native()
    };
    assert_eq!(refuse(&tx.raw()), TronRefusal::PbDefaultValue);
    let tx = Tx {
        value: transfer_value(&OWNER, &RCPT, 0),
        ..Tx::native()
    };
    assert_eq!(refuse(&tx.raw()), TronRefusal::PbDefaultValue);
}

// ───────────────────────────── refused: grammar ─────────────────────────────

#[test]
fn refuses_hidden_fields() {
    let with_raw = |field, part| {
        let mut tx = Tx::native();
        tx.raw_extra = vec![(field, part)];
        refuse(&tx.raw())
    };
    assert_eq!(with_raw(3, int(3, 1)), TronRefusal::FieldNotAllowed); // ref_block_num
    assert_eq!(with_raw(9, len(9, b"a")), TronRefusal::FieldNotAllowed); // auths
    assert_eq!(with_raw(12, len(12, b"s")), TronRefusal::FieldNotAllowed); // scripts
    assert_eq!(with_raw(2, int(2, 1)), TronRefusal::FieldNotAllowed); // unknown
    assert_eq!(with_raw(99, int(99, 1)), TronRefusal::FieldNotAllowed); // unknown

    let mut tx = Tx::native();
    tx.contract_extra = vec![(3, len(3, b"p"))]; // provider
    assert_eq!(refuse(&tx.raw()), TronRefusal::FieldNotAllowed);
    tx.contract_extra = vec![(4, len(4, b"n"))]; // ContractName
    assert_eq!(refuse(&tx.raw()), TronRefusal::FieldNotAllowed);

    let mut tx = Tx::native();
    tx.any_extra = vec![(3, int(3, 1))];
    assert_eq!(refuse(&tx.raw()), TronRefusal::FieldNotAllowed);

    let tx = Tx {
        value: [transfer_value(&OWNER, &RCPT, 1), int(4, 1)].concat(),
        ..Tx::native()
    };
    assert_eq!(refuse(&tx.raw()), TronRefusal::FieldNotAllowed);
    let data = Tx::transfer_calldata(&RCPT[1..], 1);
    let tx = Tx {
        value: [trigger_value(&OWNER, &TOKEN, &data), int(7, 1)].concat(),
        ..Tx::trc20()
    };
    assert_eq!(refuse(&tx.raw()), TronRefusal::FieldNotAllowed);
}

#[test]
fn refuses_memo() {
    let mut tx = Tx::native();
    tx.raw_extra = vec![(10, len(10, b"hi!"))];
    assert_eq!(refuse(&tx.raw()), TronRefusal::MemoPresent);
    // Also when appended after the last field.
    let appended = [hex(TRC20_HEX), len(10, b"hi!")].concat();
    assert_eq!(refuse(&appended), TronRefusal::MemoPresent);
}

#[test]
fn refuses_call_value() {
    let data = Tx::transfer_calldata(&RCPT[1..], 1);
    for call_value in [1, 0] {
        let value = [
            len(1, &OWNER),
            len(2, &TOKEN),
            int(3, call_value),
            len(4, &data),
        ]
        .concat();
        let tx = Tx {
            value,
            ..Tx::trc20()
        };
        assert_eq!(refuse(&tx.raw()), TronRefusal::CallValuePresent);
    }
}

#[test]
fn refuses_trc10_smuggling() {
    let data = Tx::transfer_calldata(&RCPT[1..], 1);
    for extra in [int(5, 1), int(6, 1_000_001)] {
        let tx = Tx {
            value: [trigger_value(&OWNER, &TOKEN, &data), extra].concat(),
            ..Tx::trc20()
        };
        assert_eq!(refuse(&tx.raw()), TronRefusal::Trc10FieldsPresent);
    }
}

#[test]
fn refuses_missing_fields() {
    for field in [1, 4, 8, 11, 14] {
        assert_eq!(
            refuse(&Tx::native().raw_without(field)),
            TronRefusal::MissingField,
            "raw field {field}"
        );
    }
    let tx = Tx::native();
    for contract in [int(1, 1), len(2, &tx.any())] {
        let mut parts = tx.raw_parts();
        parts[3].1 = len(11, &contract);
        assert_eq!(refuse(&join(parts)), TronRefusal::MissingField);
    }
    for any in [len(1, TRANSFER_URL), len(2, &tx.value)] {
        let contract = [int(1, 1), len(2, &any)].concat();
        let mut parts = tx.raw_parts();
        parts[3].1 = len(11, &contract);
        assert_eq!(refuse(&join(parts)), TronRefusal::MissingField);
    }
    for value in [
        [len(2, &RCPT), int(3, 1)].concat(),
        [len(1, &OWNER), int(3, 1)].concat(),
        [len(1, &OWNER), len(2, &RCPT)].concat(),
    ] {
        let tx = Tx {
            value,
            ..Tx::native()
        };
        assert_eq!(refuse(&tx.raw()), TronRefusal::MissingField);
    }
    let data = Tx::transfer_calldata(&RCPT[1..], 1);
    for value in [
        [len(2, &TOKEN), len(4, &data)].concat(),
        [len(1, &OWNER), len(4, &data)].concat(),
        [len(1, &OWNER), len(2, &TOKEN)].concat(),
    ] {
        let tx = Tx {
            value,
            ..Tx::trc20()
        };
        assert_eq!(refuse(&tx.raw()), TronRefusal::MissingField);
    }
}

#[test]
fn refuses_negative_int() {
    // 2^63 and above are negative `int64`s on the wire.
    for v in [1 << 63, u64::MAX] {
        let tx = Tx {
            expiration: v,
            ..Tx::native()
        };
        assert_eq!(refuse(&tx.raw()), TronRefusal::IntRange);
        let tx = Tx {
            timestamp: v,
            ..Tx::native()
        };
        assert_eq!(refuse(&tx.raw()), TronRefusal::IntRange);
        let tx = Tx {
            fee_limit: Some(v),
            ..Tx::trc20()
        };
        assert_eq!(refuse(&tx.raw()), TronRefusal::IntRange);
        let tx = Tx {
            value: transfer_value(&OWNER, &RCPT, v),
            ..Tx::native()
        };
        assert_eq!(refuse(&tx.raw()), TronRefusal::IntRange);
    }
}

#[test]
fn refuses_contract_types_table() {
    // Every type other than TransferContract (1), TriggerSmartContract (31) and
    // AccountPermissionUpdateContract (46, its own refusal), e.g. TRC-10 transfer (2), account
    // update (10), contract creation (30), staking and resource delegation (54-58).
    let types = (2..=100)
        .filter(|t| ![31, 46].contains(t))
        .chain([1 << 20, i64::MAX as u64]);
    for contract_type in types {
        let tx = Tx {
            contract_type,
            ..Tx::native()
        };
        assert_eq!(
            refuse(&tx.raw()),
            TronRefusal::ContractTypeNotAllowed,
            "type {contract_type}"
        );
    }
}

#[test]
fn refuses_account_permission_update() {
    let tx = Tx {
        contract_type: 46,
        type_url: b"type.googleapis.com/protocol.AccountPermissionUpdateContract".to_vec(),
        value: len(1, &OWNER),
        ..Tx::native()
    };
    assert_eq!(refuse(&tx.raw()), TronRefusal::AccountPermissionUpdate);
}

#[test]
fn refuses_type_url_mismatch() {
    let cases = [
        Tx {
            type_url: TRIGGER_URL.to_vec(),
            ..Tx::native()
        },
        Tx {
            type_url: TRANSFER_URL.to_vec(),
            ..Tx::trc20()
        },
        Tx {
            type_url: [TRANSFER_URL, b"X"].concat(),
            ..Tx::native()
        },
        Tx {
            type_url: b"type.googleapis.com/protocol.TransferAssetContract".to_vec(),
            ..Tx::native()
        },
    ];
    for tx in cases {
        assert_eq!(refuse(&tx.raw()), TronRefusal::TypeUrlMismatch);
    }
}

// ───────────────────────────── refused: semantics ─────────────────────────────

#[test]
fn refuses_claimed_txid_mismatch() {
    let r = refuse_with(&hex(NATIVE_HEX), |c| c.claimed_txid = Some(TxHash([0; 32])));
    assert_eq!(r, TronRefusal::DigestMismatch);
    let r = refuse_with(&hex(NATIVE_HEX), |c| {
        c.claimed_txid = Some(TxHash::of(&hex(TRC20_HEX)))
    });
    assert_eq!(r, TronRefusal::DigestMismatch);
}

#[test]
fn refuses_ref_block_shape() {
    for (bytes, hash) in [(3, 8), (1, 8), (2, 7), (2, 9), (2, 32)] {
        let tx = Tx {
            ref_block_bytes: vec![1; bytes],
            ref_block_hash: vec![1; hash],
            ..Tx::native()
        };
        assert_eq!(refuse(&tx.raw()), TronRefusal::RefBlockShape);
    }
}

#[test]
fn refuses_permission_id_mismatch() {
    // (transaction's Permission_id, wallet's): owner vs active either way, another active id,
    // and the witness permission even when configured.
    for (tx_perm, wallet_perm) in [(Some(2), 0), (None, 2), (Some(3), 2), (Some(1), 1)] {
        let tx = Tx {
            permission_id: tx_perm,
            ..Tx::trc20()
        };
        let r = refuse_with(&tx.raw(), |c| c.permission_id = wallet_perm);
        assert_eq!(
            r,
            TronRefusal::PermissionIdMismatch,
            "{tx_perm:?} vs {wallet_perm}"
        );
    }
}

#[test]
fn refuses_bad_address() {
    let short = &OWNER[..20];
    let mut wrong_prefix = OWNER;
    wrong_prefix[0] = 0x42;
    let long = [&OWNER[..], &[0x11]].concat();
    let data = Tx::transfer_calldata(&RCPT[1..], 1);
    let cases = [
        transfer_value(short, &RCPT, 1),
        transfer_value(&wrong_prefix, &RCPT, 1),
        transfer_value(&OWNER, &long, 1),
    ];
    for value in cases {
        let tx = Tx {
            value,
            ..Tx::native()
        };
        assert_eq!(refuse(&tx.raw()), TronRefusal::AddressShape);
    }
    let mut zero_prefix = TOKEN;
    zero_prefix[0] = 0x00;
    let tx = Tx {
        value: trigger_value(&OWNER, &zero_prefix, &data),
        ..Tx::trc20()
    };
    assert_eq!(refuse(&tx.raw()), TronRefusal::AddressShape);
}

#[test]
fn refuses_owner_mismatch() {
    for raw in [hex(NATIVE_HEX), hex(TRC20_HEX)] {
        let r = refuse_with(&raw, |c| c.wallet_address = OTHER);
        assert_eq!(r, TronRefusal::OwnerNotWallet);
    }
}

#[test]
fn refuses_self_transfer() {
    let tx = Tx {
        value: transfer_value(&OWNER, &OWNER, 1_000_000),
        ..Tx::native()
    };
    assert_eq!(refuse(&tx.raw()), TronRefusal::SelfTransfer);
}

#[test]
fn refuses_zero_amount() {
    let tx = Tx::trc20_with_data(&Tx::transfer_calldata(&RCPT[1..], 0));
    assert_eq!(refuse(&tx.raw()), TronRefusal::AmountZero);
}

#[test]
fn refuses_calldata_length() {
    let good = Tx::transfer_calldata(&RCPT[1..], 1);
    let cases = [
        good[..67].to_vec(),
        [&good[..], &[0]].concat(),
        good[..4].to_vec(),
        good[..3].to_vec(),
        [&good[..], &[0; 32]].concat(),
    ];
    for data in cases {
        assert_eq!(
            refuse(&Tx::trc20_with_data(&data).raw()),
            TronRefusal::CalldataLength,
            "{} bytes",
            data.len()
        );
    }
}

#[test]
fn refuses_selector_table() {
    let word = |fill: u8| [[0u8; 12].as_slice(), &[fill; 20]].concat();
    let cases = [
        // approve(spender, max)
        [&[0x09, 0x5e, 0xa7, 0xb3][..], &word(0x77), &[0xff; 32]].concat(),
        // increaseAllowance(spender, x)
        [&[0x39, 0x50, 0x93, 0x51][..], &word(0x77), &amount_word(1)].concat(),
        // decreaseAllowance(spender, x)
        [&[0xa4, 0x57, 0xc2, 0xd7][..], &word(0x77), &amount_word(1)].concat(),
        // transferFrom(from, to, x): 100 bytes
        [
            &[0x23, 0xb8, 0x72, 0xdd][..],
            &word(0x55),
            &word(0x77),
            &amount_word(1),
        ]
        .concat(),
        // near misses of the transfer selector
        calldata(
            [0xa9, 0x05, 0x9c, 0xbc],
            [0; 12],
            &RCPT[1..],
            amount_word(1),
        ),
        calldata([0, 0, 0, 0], [0; 12], &RCPT[1..], amount_word(1)),
    ];
    for data in cases {
        assert_eq!(
            refuse(&Tx::trc20_with_data(&data).raw()),
            TronRefusal::SelectorNotTransfer
        );
    }
}

#[test]
fn refuses_dirty_padding() {
    for i in 0..12 {
        let mut padding = [0u8; 12];
        padding[i] = 0x01;
        let data = calldata(TRANSFER_SELECTOR, padding, &RCPT[1..], amount_word(1));
        assert_eq!(
            refuse(&Tx::trc20_with_data(&data).raw()),
            TronRefusal::CalldataAddressPadding
        );
    }
}

#[test]
fn refuses_zero_recipient() {
    let tx = Tx::trc20_with_data(&Tx::transfer_calldata(&[0; 20], 1));
    assert_eq!(refuse(&tx.raw()), TronRefusal::RecipientZero);
}

#[test]
fn refuses_token_not_allowlisted() {
    let raw = hex(TRC20_HEX);
    assert_eq!(
        refuse_with(&raw, |c| c.trc20_allowlist = &[]),
        TronRefusal::TokenNotAllowlisted
    );
    assert_eq!(
        refuse_with(&raw, |c| c.trc20_allowlist = &[OTHER, RCPT]),
        TronRefusal::TokenNotAllowlisted
    );
}

#[test]
fn refuses_trc20_without_fee_limit() {
    let tx = Tx {
        fee_limit: None,
        ..Tx::trc20()
    };
    assert_eq!(refuse(&tx.raw()), TronRefusal::FeeLimitMissing);
}

#[test]
fn refuses_native_with_fee_limit() {
    let tx = Tx {
        fee_limit: Some(1),
        ..Tx::native()
    };
    assert_eq!(refuse(&tx.raw()), TronRefusal::FeeLimitOnNative);
}

#[test]
fn refuses_fee_limit_over_bound() {
    let raw = hex(TRC20_HEX); // fee_limit 100 TRX
    assert_eq!(
        refuse_with(&raw, |c| c.max_fee_limit_sun = 30_000_000),
        TronRefusal::FeeLimitOverBound
    );
    assert_eq!(
        refuse_with(&raw, |c| c.max_fee_limit_sun = FEE_LIMIT - 1),
        TronRefusal::FeeLimitOverBound
    );
    // The hard ceiling holds whatever the configured bound.
    let tx = Tx {
        fee_limit: Some(MAX_FEE_LIMIT_SUN + 1),
        ..Tx::trc20()
    };
    assert_eq!(
        refuse_with(&tx.raw(), |c| c.max_fee_limit_sun = u64::MAX),
        TronRefusal::FeeLimitOverBound
    );
}

#[test]
fn refuses_expired_or_overlong_validity() {
    let raw = hex(NATIVE_HEX);
    // Expired: now at or after expiration.
    assert_eq!(
        refuse_with(&raw, |c| c.now_ms = EXPIRATION),
        TronRefusal::ExpirationWindow
    );
    assert_eq!(
        refuse_with(&raw, |c| c.now_ms = EXPIRATION + 1),
        TronRefusal::ExpirationWindow
    );
    // Valid for longer than the configured bound.
    let r = refuse_with(&raw, |c| c.max_validity_ms = EXPIRATION - NOW - 1);
    assert_eq!(r, TronRefusal::ExpirationWindow);
    // Over 24 hours, whatever the configured bound.
    let tx = Tx {
        expiration: NOW + MAX_VALIDITY_MS + 1,
        ..Tx::native()
    };
    assert_eq!(
        refuse_with(&tx.raw(), |c| c.max_validity_ms = u64::MAX),
        TronRefusal::ExpirationWindow
    );
}

#[test]
fn refuses_timestamp_invalid() {
    // After expiration.
    let tx = Tx {
        timestamp: EXPIRATION + 1,
        ..Tx::native()
    };
    assert_eq!(refuse(&tx.raw()), TronRefusal::TimestampInvalid);
    // Ahead of now by more than the skew.
    let tx = Tx {
        timestamp: NOW + 1_001,
        ..Tx::native()
    };
    assert_eq!(
        refuse_with(&tx.raw(), |c| c.max_clock_skew_ms = 1_000),
        TronRefusal::TimestampInvalid
    );
    // Older than the validity bound.
    let tx = Tx {
        timestamp: NOW - MAX_VALIDITY_MS - 1,
        ..Tx::native()
    };
    assert_eq!(refuse(&tx.raw()), TronRefusal::TimestampInvalid);
}
