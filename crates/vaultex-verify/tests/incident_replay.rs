//! Incident replay (ROADMAP M6 #8): every case of the T13-3 incident catalogue (`vaultex-redteam`),
//! driven through the real kernel, must be refused with one of its expected codes, and every
//! control must be accepted.
//!
//! # What runs today
//!
//! The kernel has its strict TRON decoder; the policy bundle, the approvals and the request checks
//! do not exist yet (T05-3 and T05-4, which wait on ADR-11). So `decide` is the decoder alone, under
//! the catalogue's test world, and the replay must:
//!
//! - refuse **every** case whose fault is in the transaction bytes with an expected code;
//! - accept every control's bytes;
//! - leave exactly the cases in [`PENDING`] unanswered. Each one's bytes must decode (the fault is
//!   beyond the decoder), and each one must expect only codes the decoder never returns, so a
//!   decoder miss can never hide in the list.
//!
//! When the policy layer lands, `decide` gains the evaluation step and [`PENDING`] must shrink to
//! empty: that is the 100% exit criterion.
//!
//! # Decoder context
//!
//! The decoder's expiry and `fee_limit` bounds are the world's **network** facts. The policy caps
//! (validity, fee) belong to the policy layer, which is the catalogue's "decoder first" convention:
//! a fault that breaks both a network bound and a policy cap expects the decoder's code.

// ponytail: the catalogue is compiled in from its source (so its own unit test runs here too)
// because this crate's manifest does not list `vaultex-redteam` as a dev-dependency yet; that is
// requested. With the dev-dependency this block becomes
// `use vaultex_redteam::{replay, tron, Case, IncidentClass, Scenario};`.
#[allow(dead_code)]
#[path = "../../vaultex-redteam/src/lib.rs"]
mod vaultex_redteam;
// The catalogue's own `crate::` paths resolve through these.
use vaultex_redteam::{
    Case, Control, Evidence, Governance, IncidentClass, Key, Over, Scenario, Statement,
};

use std::collections::BTreeSet;

use vaultex_redteam::tron::{self, world};
use vaultex_types::{Address, AssetId, Decision, NetworkId, RefusalCode as R, WalletId, U256};
use vaultex_verify::tron::{decode, TronDecodeCtx};

/// The kernel layer that refuses a case the decoder cannot see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layer {
    /// Request envelope: freshness bound and window.
    Request,
    /// Policy bundle: install, version, recipient allowlist, fee and validity caps (T05-3).
    Policy,
    /// Initiator and approver statements: signatures, roles, quorum, expiry, intent binding,
    /// separation of duties (T05-4).
    Approvals,
}

/// Cases whose one fault lies beyond the transaction bytes, by the layer that must refuse them.
const PENDING: &[(&str, Layer)] = &[
    ("IR-DEST-1", Layer::Approvals),
    ("IR-DEST-2", Layer::Approvals),
    ("IR-DEST-3", Layer::Approvals),
    ("IR-DEST-4", Layer::Policy),
    ("IR-FEE-2", Layer::Policy),
    ("IR-VALID-4", Layer::Policy),
    ("IR-VALID-5", Layer::Request),
    ("IR-VALID-6", Layer::Request),
    ("IR-VALID-7", Layer::Approvals),
    ("IR-ROLLBACK-1", Layer::Policy),
    ("IR-ROLLBACK-2", Layer::Policy),
    ("IR-ROLLBACK-3", Layer::Policy),
    ("IR-ROLLBACK-4", Layer::Policy),
    ("IR-APPROVAL-1", Layer::Approvals),
    ("IR-APPROVAL-2", Layer::Approvals),
    ("IR-APPROVAL-3", Layer::Approvals),
    ("IR-APPROVAL-4", Layer::Approvals),
    ("IR-APPROVAL-5", Layer::Approvals),
    ("IR-APPROVAL-6", Layer::Approvals),
    ("IR-APPROVAL-7", Layer::Approvals),
    ("IR-APPROVAL-8", Layer::Approvals),
    ("IR-APPROVAL-9", Layer::Approvals),
    ("IR-SOD-1", Layer::Approvals),
    ("IR-SOD-2", Layer::Approvals),
    ("IR-SOD-3", Layer::Approvals),
];

/// Every wire code `TronRefusal::code` can return.
const DECODER_CODES: [R; 16] = [
    R::NETWORK_MISMATCH,
    R::PAYLOAD_MISSING,
    R::PAYLOAD_TOO_LARGE,
    R::TX_MALFORMED,
    R::TX_NON_CANONICAL,
    R::TX_DUPLICATE_FIELD,
    R::TX_UNKNOWN_FIELD,
    R::TX_SHAPE_NOT_ALLOWED,
    R::TX_VALUE_NOT_ALLOWED,
    R::TX_SELECTOR_NOT_ALLOWED,
    R::ASSET_NOT_ALLOWED,
    R::TX_DIGEST_MISMATCH,
    R::TX_PERMISSION_NOT_ALLOWED,
    R::TX_SENDER_MISMATCH,
    R::TX_FEE_OVER_BOUND,
    R::TX_EXPIRY_OUT_OF_BOUNDS,
];

/// The decoder under the catalogue's test world (`tron::world`), at the scenario's clock.
fn decode_world(s: &Scenario) -> Result<vaultex_types::IntentV1, R> {
    let wallet_id = WalletId::new("incident-replay").unwrap();
    let allowlist = [world::TOKEN];
    let ctx = TronDecodeCtx {
        wallet_id: &wallet_id,
        network: NetworkId::new(world::NETWORK).unwrap(),
        wallet_address: world::WALLET,
        permission_id: u8::try_from(world::PERMISSION_ID).unwrap(),
        trc20_allowlist: &allowlist,
        now_ms: s.now_ms,
        max_validity_ms: world::CHAIN_MAX_EXPIRATION_MS,
        max_fee_limit_sun: world::NETWORK_MAX_FEE_LIMIT_SUN,
        max_clock_skew_ms: 120_000,
        claimed_txid: None,
    };
    decode(&s.raw_tx, &ctx)
        .map(|(intent, _)| intent)
        .map_err(|r| r.code())
}

/// The kernel as it stands: the decoder's refusal, or acceptance of the bytes.
fn decide(s: &Scenario) -> Decision {
    match decode_world(s) {
        Ok(_) => Decision::Accept,
        Err(code) => Decision::Refuse(vaultex_types::Refusal {
            code,
            rule_index: None,
        }),
    }
}

#[test]
fn decoder_refuses_every_byte_level_case_and_accepts_every_control() {
    let pending: BTreeSet<&str> = PENDING.iter().map(|(id, _)| *id).collect();
    let mismatches = vaultex_redteam::replay(decide);

    // No control refused, and no byte-level case accepted or refused with an unexpected code.
    let wrong: Vec<_> = mismatches
        .iter()
        .filter(|m| !pending.contains(m.id.as_str()) || m.got != Decision::Accept)
        .collect();
    assert!(wrong.is_empty(), "wrong answers: {wrong:#?}");

    // Every pending case is still unanswered: one the decoder starts refusing must leave the list.
    let unanswered: BTreeSet<&str> = mismatches.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(unanswered, pending);

    // Coverage, per incident class.
    let cases = tron::cases();
    let mut refused_total = 0;
    for class in IncidentClass::ALL {
        let of_class: Vec<&Case> = cases.iter().filter(|c| c.class == class).collect();
        let refused = of_class
            .iter()
            .filter(|c| !pending.contains(c.id.as_str()))
            .count();
        refused_total += refused;
        println!(
            "{class:?}: {refused}/{} refused by the decoder, {} pending",
            of_class.len(),
            of_class.len() - refused
        );
    }
    println!(
        "{refused_total}/{} cases refused; {} pending on the policy layer; {} controls accepted",
        cases.len(),
        pending.len(),
        tron::controls().len()
    );
    // Not vacuous: the byte-level part is most of the catalogue.
    assert!(refused_total >= 60, "{refused_total} cases refused");
}

/// A pending case must carry its fault outside the bytes: it expects no decoder code, and its
/// bytes decode. Otherwise the list could hide a decoder miss.
#[test]
fn pending_cases_are_beyond_the_decoder() {
    let cases = tron::cases();
    for (id, layer) in PENDING {
        let case = cases
            .iter()
            .find(|c| c.id == *id)
            .unwrap_or_else(|| panic!("{id} is not in the catalogue"));
        for code in case.expect {
            assert!(
                !DECODER_CODES.contains(code),
                "{id} ({layer:?}) expects decoder code {code:?}"
            );
        }
        assert!(
            decode_world(&case.scenario).is_ok(),
            "{id}: the bytes do not decode"
        );
    }
}

/// The controls decode to the intent the test world describes, not merely to "accepted".
#[test]
fn controls_decode_to_the_world_intent() {
    let token = AssetId::Contract(Address(world::TOKEN.to_vec()));
    for control in tron::controls() {
        let intent = decode_world(&control.scenario)
            .unwrap_or_else(|code| panic!("{} refused with {code:?}", control.id));
        assert_eq!(
            intent.sender,
            Address(world::WALLET.to_vec()),
            "{}",
            control.id
        );
        assert_eq!(
            intent.recipient,
            Address(world::RECIPIENT.to_vec()),
            "{}",
            control.id
        );
        assert_eq!(intent.amount, U256::from(1_000_000u64), "{}", control.id);
        let expected_asset = if control.id == "CTRL-2" {
            AssetId::Native
        } else {
            token.clone()
        };
        assert_eq!(intent.asset, expected_asset, "{}", control.id);
    }
}
