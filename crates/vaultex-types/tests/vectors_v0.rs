//! Contracts v0 test vectors (V-01…V-10 positive, N-01…N-08 negative).
//!
//! The expected bytes and digests were produced by two independent encoders (a minimal Python BCS
//! encoder and `@mysten/bcs`), which agree byte for byte; this test is the Rust reproduction. It is
//! not the independent oracle of ROADMAP M6 #7, which must be written from the RFC text by a
//! different author. The v2 vectors arrive with the v2 types.
//!
//! Test keys are Ed25519 seeds of 32 repeated bytes (0x01 initiator, 0x02 approver, 0x03 receipt).
//! They are public and test-only.

use std::fmt::Debug;

use ed25519_dalek::{Signer, SigningKey};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use vaultex_types::*;

/// V-00: TRON TRC-20 `raw_data` (211 bytes), the tronweb reference vector already pinned in the
/// chains crate: owner 0x41 11…11, token 0x41 99…99, `transfer(0x41 22…22, 1_000_000)`,
/// expiration 1_700_000_060_000, fee_limit 100_000_000.
const RAW_TX: &str = concat!(
    "0a0200012208010203040506070840e0a499ffbc315aae01081f12a9010a31747970652e676f6f676c65617069",
    "732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a15411111111111",
    "11111111111111111111111111111112154199999999999999999999999999999999999999992244a9059cbb00",
    "0000000000000000000000222222222222222222222222222222222222222200000000000000000000000000000",
    "000000000000000000000000000000f42407080d095ffbc31900180c2d72f",
);
const TX_HASH: &str = "4145dae04fdc27be8a6e585f2596591ef861bc06ea2d6c31c3eac1348ecbf99e";

/// V-02: BCS(IntentV1), 226 bytes.
const INTENT_BCS: &str = concat!(
    "2430303030303030302d303030302d343030302d383030302d30303030303030303030303101000f74726f6e3a32",
    "3439343130343939301541111111111111111111111111111111111111111115412222222222222222222222222222",
    "222222222222011541999999999999999999999999999999999999999940420f0000000000000000000000000000",
    "00000000000000000000000000000000e1f50500000000000000000000000000000000000000000000000000000000",
    "6052e6cf8b0100004145dae04fdc27be8a6e585f2596591ef861bc06ea2d6c31c3eac1348ecbf99e",
);

/// V-08: BCS(ReceiptBodyV1), 263 bytes.
const RECEIPT_BODY_BCS: &str = concat!(
    "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d10000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000af1536500000000000102030405060708090a0b",
    "0c0d0e0f2430303030303030302d303030302d343030302d383030302d30303030303030303030303101000f7472",
    "6f6e3a323439343130343939304145dae04fdc27be8a6e585f2596591ef861bc06ea2d6c31c3eac1348ecbf99e01",
    "71eda63fe5e0864f8775542d7cbd2a802f48d3fecb8e271fe76e09605614820d01000000000000003d400d56b0c0",
    "e0028258af15e58568dacaa83c0fe5ce988dfaa0cbe1720f587d00000100000000",
);

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn h32(s: &str) -> [u8; 32] {
    h(s).try_into().unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `value` encodes to exactly `expected`, and strict decoding gives back the same value.
fn assert_canonical<T>(value: &T, expected: &[u8])
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let bytes = to_canonical(value).unwrap();
    assert_eq!(hex::encode(&bytes), hex::encode(expected));
    assert_eq!(&from_canonical_strict::<T>(&bytes).unwrap(), value);
}

/// Strict decoding gives back the value and re-encodes to the same bytes; returns those bytes.
fn round_trip<T>(value: &T) -> Vec<u8>
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let bytes = to_canonical(value).unwrap();
    assert_canonical(value, &bytes);
    bytes
}

fn wallet() -> WalletId {
    WalletId::new("00000000-0000-4000-8000-000000000001").unwrap()
}

fn shasta() -> NetworkId {
    NetworkId::new("tron:2494104990").unwrap()
}

fn tron_address(byte: u8) -> Address {
    let mut a = vec![0x41];
    a.extend([byte; 20]);
    Address(a)
}

fn request_id() -> RequestId {
    RequestId(core::array::from_fn(|i| i as u8))
}

fn intent() -> IntentV1 {
    IntentV1 {
        wallet_id: wallet(),
        chain: ChainId::TRON,
        network: shasta(),
        sender: tron_address(0x11),
        recipient: tron_address(0x22),
        asset: AssetId::Contract(tron_address(0x99)),
        amount: U256::from(1_000_000),
        fee_cap: U256::from(100_000_000),
        not_after_ms: 1_700_000_060_000,
        tx_hash: TxHash::of(&h(RAW_TX)),
    }
}

fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sign(key: &SigningKey, digest: [u8; 32]) -> Sig64 {
    Sig64(key.sign(&digest).to_bytes())
}

fn statement(seed: u8, role: Role) -> SignedStatementV1 {
    let key = test_key(seed);
    let statement = ApprovalStatementV1 {
        intent_digest: intent().digest(),
        role,
        not_after_s: 1_700_000_100,
    };
    SignedStatementV1 {
        key: Ed25519Pub(key.verifying_key().to_bytes()),
        statement,
        signature: sign(&key, statement.digest()),
    }
}

fn verify_request() -> VerifyRequestV1 {
    VerifyRequestV1 {
        request_id: request_id(),
        wallet_id: wallet(),
        chain: ChainId::TRON,
        network: shasta(),
        raw_tx: h(RAW_TX),
        context: TxContextV1::Empty,
        policy_version: 1,
        initiator: statement(0x01, Role::Initiator),
        approvals: vec![statement(0x02, Role::Approver)],
        not_after_s: 1_700_000_100,
    }
}

fn receipt_body() -> ReceiptBodyV1 {
    ReceiptBodyV1 {
        signer_key: Ed25519Pub(test_key(0x03).verifying_key().to_bytes()),
        seq: 0,
        prev: ReceiptDigest([0; 32]),
        time_s: 1_700_000_010,
        request_id: request_id(),
        wallet_id: wallet(),
        chain: ChainId::TRON,
        network: shasta(),
        tx_hash: TxHash::of(&h(RAW_TX)),
        intent_digest: Some(intent().digest()),
        policy_version: 1,
        policy_digest: Sha256::digest(b"example policy bundle (placeholder for vectors)").into(),
        verifier_version: VerifierVersion {
            major: 0,
            minor: 1,
            patch: 0,
        },
        decision: Decision::Accept,
    }
}

#[test]
fn v00_tx_hash_is_sha256_of_raw_tx() {
    assert_eq!(h(RAW_TX).len(), 211);
    assert_eq!(TxHash::of(&h(RAW_TX)), TxHash(h32(TX_HASH)));
}

#[test]
fn v01_tag_is_length_prefixed() {
    assert_eq!(
        hex::encode(to_canonical(tag::INTENT_V1).unwrap()),
        "115641554c5445582f494e54454e542f7631"
    );
}

#[test]
fn v02_v03_intent_bytes_and_digest() {
    assert_canonical(&intent(), &h(INTENT_BCS));
    assert_eq!(h(INTENT_BCS).len(), 226);
    assert_eq!(
        intent().digest(),
        IntentDigest(h32(
            "71eda63fe5e0864f8775542d7cbd2a802f48d3fecb8e271fe76e09605614820d"
        ))
    );
}

#[test]
fn v04_sign_input_carries_the_preimage() {
    let input = SignInput::EcdsaPreimage {
        hash: EcdsaHash::Sha256,
        bytes: h(RAW_TX),
    };
    let bytes = round_trip(&input);
    assert_eq!(bytes.len(), 215);
    assert_eq!(hex::encode(&bytes[..4]), "0000d301"); // variant 0, Sha256, ULEB128(211)
    assert_eq!(
        sha256(&bytes),
        "08a40655f4058a6a917f8d5236e0d499327f7a58652b0b9cdcd3c4ad0d6aeb31"
    );
    // The digest an ECDSA engine signs is SHA-256 of the preimage: the TRON transaction id.
    assert_eq!(sha256(&h(RAW_TX)), TX_HASH);
}

#[test]
fn v05_v06_initiator_and_approver_statements() {
    let initiator = statement(0x01, Role::Initiator);
    assert_eq!(
        hex::encode(to_canonical(&initiator.statement).unwrap()),
        "71eda63fe5e0864f8775542d7cbd2a802f48d3fecb8e271fe76e09605614820d0064f1536500000000"
    );
    let cases = [
        (
            initiator,
            "b74749aec2817dde2061289a4686e9019539df663b839500f923f2acbcee749e",
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
            concat!(
                "0f139e1487e2583c1e92e8bd73f7818fd7218b2c1e76933691f1b5e3fb39d921",
                "2a567f78141e4703297c74a41797cef51a3fa3f60a2405bba78386df9fa4d508"
            ),
        ),
        (
            statement(0x02, Role::Approver),
            "ad917da3470ab5e9c0016177b127d7f72409ad750d83f59c245fcee30f7def0f",
            "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
            concat!(
                "36ebfa35aca2ac8fddd3c820516786d46787618dd323901fbffce16a9dbab147",
                "250abe9c9c8c3a240fc53875387b1da55b13ed7d8922c4741c97f3657397800a"
            ),
        ),
    ];
    for (signed, digest, key, sig) in cases {
        assert_eq!(hex::encode(signed.statement.digest()), digest);
        assert_eq!(hex::encode(signed.key.0), key);
        assert_eq!(hex::encode(signed.signature.0), sig);
        let bytes = round_trip(&signed);
        assert_eq!(bytes.len(), 32 + 41 + 64); // key, statement, signature: no length prefixes
    }
}

#[test]
fn v07_decision_encodings() {
    let refuse = |code, rule_index| Decision::Refuse(Refusal { code, rule_index });
    assert_canonical(&Decision::Accept, &h("00"));
    assert_canonical(
        &refuse(RefusalCode::TX_SELECTOR_NOT_ALLOWED, None),
        &h("01070200"),
    );
    assert_canonical(
        &refuse(RefusalCode::VELOCITY_EXCEEDED, Some(3)),
        &h("0101050103000000"),
    );
}

#[test]
fn v08_receipt_bytes_digest_and_signature() {
    let body = receipt_body();
    assert_canonical(&body, &h(RECEIPT_BODY_BCS));
    assert_eq!(h(RECEIPT_BODY_BCS).len(), 263);
    assert_eq!(
        body.digest(),
        ReceiptDigest(h32(
            "a792d33e55b806ca357b1a33dd5642475bbce2e655769763c9b08cc5fc7ba71a"
        ))
    );
    assert_eq!(
        hex::encode(body.signer_key.0),
        "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1"
    );
    let receipt = ReceiptV1 {
        signature: sign(&test_key(0x03), body.digest().0),
        body,
    };
    assert_eq!(
        hex::encode(receipt.signature.0),
        concat!(
            "21af0c104d717e0293c6d6be782713525f7fed1de2a104dd359bf209200e48d8",
            "16b47f23a77072a6b95de9a82829543580365621cb5602404df0bb5324b38704"
        )
    );
    round_trip(&receipt);
}

#[test]
fn v09_verify_request() {
    let bytes = round_trip(&verify_request());
    assert_eq!(bytes.len(), 576);
    assert_eq!(
        sha256(&bytes),
        "9e839bf607df4ed3cb748e394e3e1c43b00ce285f5870e8ce1973ecfb5ee599b"
    );
}

#[test]
fn v10_guard_request() {
    let request = GuardRequestV1 {
        version: GUARD_API_VERSION,
        mode: GuardMode::CoSign,
        request: verify_request(),
        operator_signature: None,
    };
    let bytes = round_trip(&request);
    assert_eq!(bytes.len(), 580);
    assert_eq!(
        sha256(&bytes),
        "181e97650e79acaa66ddf0a65248361b80a7b6c461c1aa68661740f9e016d0b9"
    );
}

#[test]
fn guard_response_round_trips() {
    // No published vector yet; this pins only that every field survives strict decoding.
    let body = receipt_body();
    let response = GuardResponseV1 {
        version: GUARD_API_VERSION,
        request_id: request_id(),
        decision: Decision::Accept,
        co_signature: Some(SignatureV1::EcdsaSecp256k1 {
            r: [1; 32],
            s: [2; 32],
            recovery_id: 1,
        }),
        receipt: ReceiptV1 {
            signature: sign(&test_key(0x03), body.digest().0),
            body,
        },
    };
    round_trip(&response);
}

#[test]
fn n01_to_n06_malformed_bcs_is_refused() {
    let refused = |r: Result<(), Error>| assert!(matches!(r, Err(Error::Bcs(_))), "{r:?}");
    refused(from_canonical_strict::<Decision>(&h("00ff")).map(drop)); // trailing byte
    refused(from_canonical_strict::<String>(&h("810041")).map(drop)); // non-canonical ULEB128
    refused(from_canonical_strict::<bool>(&h("02")).map(drop)); // invalid bool
    refused(from_canonical_strict::<Option<u8>>(&h("0207")).map(drop)); // invalid option tag
    refused(from_canonical_strict::<Decision>(&h("05")).map(drop)); // unknown variant
    refused(from_canonical_strict::<String>(&h("01ff")).map(drop)); // invalid UTF-8
}

#[test]
fn n07_n08_invalid_identifiers_are_refused() {
    // N-07: the deprecated hex alias of TRON Shasta, the same length as the decimal id.
    let mut deprecated = h(INTENT_BCS);
    let at = deprecated
        .windows(15)
        .position(|w| w == b"tron:2494104990")
        .unwrap();
    deprecated[at..at + 15].copy_from_slice(b"tron:0x94a9059e");
    let refused = from_canonical_strict::<IntentV1>(&deprecated);
    assert!(matches!(refused, Err(Error::Bcs(_))), "{refused:?}");

    // N-08: a wallet id outside the charset.
    let mut traversal = vec![4];
    traversal.extend_from_slice(b"../x");
    traversal.extend_from_slice(&h(INTENT_BCS)[37..]);
    let refused = from_canonical_strict::<IntentV1>(&traversal);
    assert!(matches!(refused, Err(Error::Bcs(_))), "{refused:?}");
}

#[test]
fn unknown_refusal_codes_still_decode() {
    let refusal: Refusal = from_canonical_strict(&h("ff0f00")).unwrap();
    assert_eq!(refusal.code, RefusalCode(0x0FFF));
    assert_eq!(refusal.code.name(), None);
}
