//! Signed statements: initiator and approver statements, and admin actions.

use serde::{Deserialize, Serialize};

use crate::{tag, tagged_digest, Ed25519Pub, IntentDigest, Sig64, WalletId};

/// Who a statement speaks for. The role is signed, so an initiator statement can never be
/// replayed as an approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// The person or system that asked for the transfer.
    Initiator,
    /// An approver counted towards the policy's k-of-n.
    Approver,
}

/// "I, in `role`, agree to the intent with this digest, until `not_after_s`." Semantics are
/// specified by the approvals v1 design; the kernel recomputes the intent digest itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApprovalStatementV1 {
    /// Digest of the intent the signer agrees to.
    pub intent_digest: IntentDigest,
    /// The role the signer speaks in.
    pub role: Role,
    /// Expiry, in seconds since the Unix epoch.
    pub not_after_s: u64,
}

impl ApprovalStatementV1 {
    /// `tagged_digest(APPROVAL_V1, self)`: the 32 bytes the key signs.
    pub fn digest(&self) -> [u8; 32] {
        tagged_digest(tag::APPROVAL_V1, self)
    }
}

/// An [`ApprovalStatementV1`] with its key and Ed25519 signature over
/// [`ApprovalStatementV1::digest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignedStatementV1 {
    /// The signing key; it must be pinned in the policy bundle for `statement.role`.
    pub key: Ed25519Pub,
    /// What was signed.
    pub statement: ApprovalStatementV1,
    /// Ed25519 signature over the statement digest.
    pub signature: Sig64,
}

/// An administrative action on a wallet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdminAction {
    /// Stop signing. One pinned admin key (or the monitor's freeze-only key) is enough.
    Freeze,
    /// Resume signing. Needs M-of-N pinned admin keys.
    Unfreeze,
}

/// A freeze or unfreeze order, signed under [`tag::ADMIN_ACTION_V1`] by each admin key. The nonce
/// is remembered until expiry, so an order cannot be replayed.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AdminActionV1 {
    /// Freeze or unfreeze.
    pub action: AdminAction,
    /// The wallet it applies to.
    pub scope: WalletId,
    /// A random nonce, unique per order.
    pub nonce: [u8; 16],
    /// Expiry, in seconds since the Unix epoch.
    pub not_after_s: u64,
}

impl AdminActionV1 {
    /// `tagged_digest(ADMIN_ACTION_V1, self)`: the 32 bytes each admin key signs.
    pub fn digest(&self) -> [u8; 32] {
        tagged_digest(tag::ADMIN_ACTION_V1, self)
    }
}
