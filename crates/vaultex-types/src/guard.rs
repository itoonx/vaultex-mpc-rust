//! The verify request shared by every signer, and the Guard API v1 messages.

use serde::{Deserialize, Serialize};

use crate::{
    ChainId, Decision, NetworkId, ReceiptV1, RequestId, Sig64, SignedStatementV1, WalletId,
};

/// Version carried by [`GuardRequestV1`] and [`GuardResponseV1`].
pub const GUARD_API_VERSION: u16 = 1;

/// Extra chain data a decoder needs besides the transaction bytes. TRON needs none; later
/// variants (Bitcoin previous transactions, Sui object proofs) are appended.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TxContextV1 {
    /// No context.
    Empty,
}

/// Everything a signer needs to decide on one transaction. The Guard receives it now; MPC nodes
/// receive the same bytes in the MPC phase, so one verifier serves both.
///
/// It carries the **unsigned transaction bytes, never a digest**: the verifier decodes them and
/// derives the intent and the [`SignInput`](crate::SignInput) itself.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VerifyRequestV1 {
    /// Idempotency and replay key.
    pub request_id: RequestId,
    /// The wallet asked to sign.
    pub wallet_id: WalletId,
    /// The chain.
    pub chain: ChainId,
    /// The network.
    pub network: NetworkId,
    /// The canonical unsigned transaction (at most [`MAX_RAW_TX_BYTES`](crate::MAX_RAW_TX_BYTES)).
    pub raw_tx: Vec<u8>,
    /// Extra decode context.
    pub context: TxContextV1,
    /// Must equal the verifier's installed policy version.
    pub policy_version: u64,
    /// The initiator's statement (role `Initiator`). Always required.
    pub initiator: SignedStatementV1,
    /// Approver statements (role `Approver`; at most [`MAX_APPROVALS`](crate::MAX_APPROVALS)).
    pub approvals: Vec<SignedStatementV1>,
    /// Request freshness, in seconds since the Unix epoch; separate from the transaction expiry.
    pub not_after_s: u64,
}

/// A signature in chain-ready form.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureV1 {
    /// secp256k1 ECDSA, low-s normalised.
    EcdsaSecp256k1 {
        /// `r`, big-endian.
        r: [u8; 32],
        /// `s`, big-endian, at most n/2.
        s: [u8; 32],
        /// Recovery id, 0 or 1.
        recovery_id: u8,
    },
    /// Ed25519.
    Ed25519(Sig64),
}

/// How the Guard handles a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GuardMode {
    /// Decide and record a receipt, but never co-sign.
    Shadow,
    /// Decide, record a receipt, and co-sign on accept.
    CoSign,
}

/// A request to the Guard (the additive co-signer).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GuardRequestV1 {
    /// [`GUARD_API_VERSION`].
    pub version: u16,
    /// Shadow or co-sign.
    pub mode: GuardMode,
    /// The transaction and its statements.
    pub request: VerifyRequestV1,
    /// The operator's signature over the same transaction, checked by key recovery.
    pub operator_signature: Option<SignatureV1>,
}

/// The Guard's answer. Every request gets a receipt, refusals included.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GuardResponseV1 {
    /// [`GUARD_API_VERSION`].
    pub version: u16,
    /// The request answered.
    pub request_id: RequestId,
    /// The decision.
    pub decision: Decision,
    /// The Guard's co-signature: present only on accept in co-sign mode.
    pub co_signature: Option<SignatureV1>,
    /// The signed receipt for this decision.
    pub receipt: ReceiptV1,
}
