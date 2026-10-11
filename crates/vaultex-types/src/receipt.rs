//! Signed, hash-chained decision receipts.

use serde::{Deserialize, Serialize};

use crate::{
    tag, tagged_digest, ChainId, Decision, Ed25519Pub, IntentDigest, NetworkId, ReceiptDigest,
    RequestId, Sig64, TxHash, VerifierVersion, WalletId,
};

/// One decision, accept or refuse, as a signer records it. Semantics are specified by the
/// `RECEIPT_V1` RFC. Each receipt names the digest of the previous one from the same key, so a
/// signer's receipt log is a hash chain that can be verified offline.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReceiptBodyV1 {
    /// This signer's receipt key.
    pub signer_key: Ed25519Pub,
    /// Position in this key's chain, from 0.
    pub seq: u64,
    /// Digest of receipt `seq − 1`; all zeros for `seq` 0.
    pub prev: ReceiptDigest,
    /// Decision time, in seconds since the Unix epoch.
    pub time_s: u64,
    /// The request decided on.
    pub request_id: RequestId,
    /// The wallet.
    pub wallet_id: WalletId,
    /// The chain.
    pub chain: ChainId,
    /// The network.
    pub network: NetworkId,
    /// SHA-256 of the unsigned transaction bytes.
    pub tx_hash: TxHash,
    /// The decoded intent's digest; `None` when decoding itself refused.
    pub intent_digest: Option<IntentDigest>,
    /// Version of the installed policy bundle.
    pub policy_version: u64,
    /// Digest of the installed policy bundle.
    pub policy_digest: [u8; 32],
    /// The verifier build that decided.
    pub verifier_version: VerifierVersion,
    /// The decision.
    pub decision: Decision,
}

impl ReceiptBodyV1 {
    /// `tagged_digest(RECEIPT_V1, self)`: what the receipt key signs, and what the next receipt
    /// names as `prev`.
    pub fn digest(&self) -> ReceiptDigest {
        ReceiptDigest(tagged_digest(tag::RECEIPT_V1, self))
    }
}

/// A receipt body with the receipt key's Ed25519 signature over [`ReceiptBodyV1::digest`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReceiptV1 {
    /// What was decided.
    pub body: ReceiptBodyV1,
    /// Ed25519 signature by `body.signer_key`.
    pub signature: Sig64,
}
