//! Vaultex adversarial verification harness (WS-13).
//!
//! # Incident catalogue (T13-3)
//!
//! [`tron::cases`] maps the incident classes of ROADMAP M6 #8 ([`IncidentClass`]) onto concrete
//! TRON cases. Each [`Case`] is a [`Scenario`] (the unsigned transaction bytes, plus the clock,
//! the request fields, the approval evidence and the policy-bundle state around them) and the
//! refusal code the verifier kernel must answer with. [`tron::controls`] are well-formed
//! scenarios that must be **accepted**, so a kernel that refuses everything cannot pass.
//!
//! The kernel's incident-replay suite (T05-9) drives every scenario through the real kernel with
//! [`replay`] and requires an empty result: 100% of cases refused with an expected code, and every
//! control accepted. Descriptions stay at category level; the fixtures are negative test vectors,
//! not tooling.
//!
//! # Conventions
//!
//! - **One fault per case.** Every case is a control with exactly one thing wrong, so the expected
//!   code names the check under test. The tests in this crate check that no case equals a control
//!   or another case, so a mutation that silently got lost is caught here, not in the kernel.
//! - **Decoder first.** The kernel evaluates only what it has decoded, so when a fault also breaks
//!   a policy bound (an expiry beyond the chain maximum is also beyond the policy maximum), the
//!   decoder's code is expected.
//! - **Two codes at most.** Where the registry's wording admits two codes for one fault (a second
//!   contract is both a shape and a duplicate-field violation), the case lists both, preferred
//!   first. The kernel's check order stays its own.
//! - **Independent bytes.** Fixtures come from this crate's own minimal protobuf writer, not from
//!   the kernel's encoder, so a shared encoder bug cannot hide a missed refusal. The writer is
//!   anchored to the two tronweb reference vectors.
//!
//! # Instantiating the test world
//!
//! The adapter in the kernel's test suite turns [`tron::world`] into a real policy bundle and keys:
//! one wallet on Nile under active permission [`tron::world::PERMISSION_ID`]; native TRX and one
//! TRC-20 token allowed; a recipient allowlist (deny by default, in every tier); per-transaction,
//! fee and validity caps; [`tron::world::QUORUM`] of [`tron::world::APPROVERS`] approvals for
//! every amount; and installed bundle version [`tron::world::BUNDLE_VERSION`]. Each [`Key`] maps to
//! a distinct fixed Ed25519 test key, and statements are signed at replay time
//! ([`Statement`]).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod tron;

use vaultex_types::{Decision, RefusalCode, Role};

/// The incident classes of ROADMAP M6 #8, at category level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IncidentClass {
    /// A token allowance granted in place of a transfer. An allowance can be drained later
    /// without another signature from the wallet.
    ApproveToAttacker,
    /// The destination differs from the one that was approved, is not allowlisted, or is
    /// ambiguous between decoders.
    DestinationSwap,
    /// The transaction changes who controls an account, signs under a permission the wallet does
    /// not use, acts for another account, or performs a privileged operation.
    PermissionTakeover,
    /// Something beyond the one allowlisted transfer travels in the same transaction: a memo, a
    /// second contract, hidden fields, or value attached to the call.
    MemoOrSecondContractSmuggling,
    /// The fee limit exceeds the network or policy bound, is out of range, or appears where none
    /// belongs.
    FeeLimitAbuse,
    /// The transaction, the request or an approval has expired, or stays valid for longer than
    /// allowed.
    ExpiredOrOverlongValidity,
    /// A policy bundle that is not newer than the installed one, a stale policy version, or lost
    /// policy state.
    RolledBackBundle,
    /// Approval evidence that is forged, from a key without that role, duplicated, short of
    /// quorum, or collected for another transaction.
    ForgedOrDuplicateApprovals,
    /// The initiator approves its own request (separation of duties).
    InitiatorSelfApproval,
}

impl IncidentClass {
    /// Every class, in ROADMAP M6 #8 order.
    pub const ALL: [Self; 9] = [
        Self::ApproveToAttacker,
        Self::DestinationSwap,
        Self::PermissionTakeover,
        Self::MemoOrSecondContractSmuggling,
        Self::FeeLimitAbuse,
        Self::ExpiredOrOverlongValidity,
        Self::RolledBackBundle,
        Self::ForgedOrDuplicateApprovals,
        Self::InitiatorSelfApproval,
    ];
}

/// A key of the test world. The adapter maps each one to a distinct fixed Ed25519 test key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Key {
    /// The key pinned for the initiator role only.
    Initiator,
    /// Approver key `n`, for `n < world::APPROVERS`. Approver 2 is also pinned for the initiator
    /// role (one person who may both initiate and approve, never on the same request).
    Approver(u8),
    /// A well-formed key pinned for no role.
    Outsider,
}

/// What a statement's intent digest is computed over.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Over {
    /// The scenario's own transaction.
    ThisTx,
    /// Another unsigned transaction, decoded into an intent the same way.
    OtherTx(Vec<u8>),
}

/// An initiator or approver statement, described rather than signed: the adapter builds the
/// `ApprovalStatementV1` and signs it with `key` at replay time.
///
/// ponytail: statements stay symbolic because the intent digest needs the kernel's decode and the
/// `INTENT_V1` RFC; T05-9 signs them once both exist.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Statement {
    /// The signing key.
    pub key: Key,
    /// The role written into the signed statement.
    pub role: Role,
    /// The transaction whose intent digest is signed.
    pub over: Over,
    /// Expiry, in seconds since the Unix epoch.
    pub not_after_s: u64,
    /// Flip one bit of the signature after signing.
    pub corrupt_signature: bool,
}

/// The initiator statement and the approver statements of a request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Evidence {
    /// The initiator's statement.
    pub initiator: Statement,
    /// The approver statements, in request order.
    pub approvals: Vec<Statement>,
}

/// The signer's policy-bundle state when the scenario runs.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Governance {
    /// The world bundle (version `world::BUNDLE_VERSION`) is installed.
    Installed,
    /// No bundle is installed: fresh or wiped signer state.
    Missing,
    /// With the world bundle installed, the signer is offered another bundle: the world policy
    /// with `world::OUTSIDER` added to the recipient allowlist (looser), at `version`, validly
    /// signed by the pinned admin quorum. The decision under test is the install's; no request is
    /// evaluated.
    Offered {
        /// The offered bundle's version.
        version: u64,
    },
}

/// Everything around one decision: the bytes, the clock, the request and the signer's state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Scenario {
    /// The unsigned transaction (TRON: `Transaction.raw` bytes).
    pub raw_tx: Vec<u8>,
    /// The verifier's "now", in milliseconds since the Unix epoch.
    pub now_ms: u64,
    /// The request's freshness bound (`VerifyRequestV1::not_after_s`).
    pub request_not_after_s: u64,
    /// The policy version the request names (`VerifyRequestV1::policy_version`).
    pub policy_version: u64,
    /// The initiator and approver statements.
    pub evidence: Evidence,
    /// The bundle state.
    pub governance: Governance,
}

/// One incident case: a scenario the kernel must refuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Case {
    /// Stable id, `IR-<CLASS>-<n>`.
    pub id: String,
    /// The incident class it instantiates.
    pub class: IncidentClass,
    /// Category-level description of the one fault.
    pub summary: &'static str,
    /// Acceptable refusal codes, preferred first (one or two).
    pub expect: &'static [RefusalCode],
    /// The scenario.
    pub scenario: Scenario,
}

/// A well-formed scenario the kernel must accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Control {
    /// Stable id, `CTRL-<n>`.
    pub id: &'static str,
    /// What it is.
    pub summary: &'static str,
    /// The scenario.
    pub scenario: Scenario,
}

/// A case or control the kernel answered wrongly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch {
    /// The case or control id.
    pub id: String,
    /// The codes that would have been right; empty means the scenario had to be accepted.
    pub expected: &'static [RefusalCode],
    /// What the kernel answered.
    pub got: Decision,
}

/// Runs every control and every case through `decide` and returns the wrong answers. The
/// incident-replay suite passes only when this is empty.
pub fn replay(mut decide: impl FnMut(&Scenario) -> Decision) -> Vec<Mismatch> {
    const ACCEPT: &[RefusalCode] = &[];
    let controls = tron::controls()
        .into_iter()
        .map(|c| (c.id.to_string(), ACCEPT, c.scenario));
    let cases = tron::cases()
        .into_iter()
        .map(|c| (c.id, c.expect, c.scenario));
    controls
        .chain(cases)
        .filter_map(|(id, expected, scenario)| {
            let got = decide(&scenario);
            (!answers(expected, got)).then_some(Mismatch { id, expected, got })
        })
        .collect()
}

/// `true` when `got` is an acceptance and nothing was expected, or a refusal with an expected code.
fn answers(expected: &[RefusalCode], got: Decision) -> bool {
    match got {
        Decision::Accept => expected.is_empty(),
        Decision::Refuse(refusal) => expected.contains(&refusal.code),
        _ => false, // a decision kind this harness does not know is never right
    }
}
