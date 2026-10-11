//! Decisions and the refusal-code registry.

use serde::{Deserialize, Serialize};

/// Why a signer refused, or could not answer (contract rule 7: `u16`, append-only, never reused).
///
/// Classes, by high byte:
/// - `0x01`–`0x07` are **refusals**: final for that request. A relay must not retry a refusal on
///   another signer subset (that would let it shop for a signer that agrees); it alerts instead.
/// - `0xF0` is **unavailable**: retryable as a fresh attempt ([`RefusalCode::is_retryable`]).
/// - A code this version does not know is treated as a refusal.
///
/// Codes marked "(v2)" are reserved for the MPC phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RefusalCode(pub u16);

macro_rules! refusal_codes {
    ($( $(#[$doc:meta])* $name:ident = $code:literal, )*) => {
        impl RefusalCode {
            $( $(#[$doc])* pub const $name: Self = Self($code); )*

            /// The registry name of a known code; `None` for a code this version does not know.
            pub fn name(self) -> Option<&'static str> {
                match self.0 {
                    $( $code => Some(stringify!($name)), )*
                    _ => None,
                }
            }
        }
    };
}

refusal_codes! {
    // 0x01xx request and envelope
    /// The request failed strict decoding, or a size cap was exceeded before decoding.
    MALFORMED = 0x0101,
    /// The message or tag version is not one this verifier accepts (N or N−1).
    UNSUPPORTED_VERSION = 0x0102,
    /// The request's `not_after_s` has passed.
    REQUEST_EXPIRED = 0x0103,
    /// The request's validity window is longer than the maximum.
    REQUEST_WINDOW_TOO_LONG = 0x0104,
    /// The request id or envelope nonce was already seen.
    REPLAY = 0x0105,
    /// No registry entry for the wallet.
    UNKNOWN_WALLET = 0x0106,
    /// Chain or network differ from the wallet's registry entry, or do not match each other.
    NETWORK_MISMATCH = 0x0107,
    /// The request's policy version differs from the installed one.
    POLICY_VERSION_MISMATCH = 0x0108,
    /// A field cap was exceeded.
    PAYLOAD_TOO_LARGE = 0x0109,
    /// The transaction bytes are empty, or only a digest was supplied.
    PAYLOAD_MISSING = 0x010A,
    /// (v2) The signer set is unsorted, has duplicates, has the wrong size, or omits this signer.
    SIGNER_SET_INVALID = 0x010B,
    /// The envelope or statement key is not pinned for that purpose or tag.
    ISSUER_NOT_AUTHORIZED = 0x010C,
    /// (v2) The envelope subject differs from the subject it arrived on.
    SUBJECT_MISMATCH = 0x010D,

    // 0x02xx transaction decode (TRON first)
    /// The transaction does not parse.
    TX_MALFORMED = 0x0201,
    /// Input continues after the transaction.
    TX_TRAILING_BYTES = 0x0202,
    /// A field outside the grammar.
    TX_UNKNOWN_FIELD = 0x0203,
    /// A field appears more than once.
    TX_DUPLICATE_FIELD = 0x0204,
    /// A non-minimal varint, or re-encoding differs from the input.
    TX_NON_CANONICAL = 0x0205,
    /// Contract type or count, memo or data, or any type outside the allowlist.
    TX_SHAPE_NOT_ALLOWED = 0x0206,
    /// A call selector other than the allowlisted transfer.
    TX_SELECTOR_NOT_ALLOWED = 0x0207,
    /// Non-zero call value, or token fields on a token call.
    TX_VALUE_NOT_ALLOWED = 0x0208,
    /// The transaction's permission id is not configured for this wallet.
    TX_PERMISSION_NOT_ALLOWED = 0x0209,
    /// The transaction's owner is not the wallet's address.
    TX_SENDER_MISMATCH = 0x020A,
    /// The transaction has expired, or its validity is too long.
    TX_EXPIRY_OUT_OF_BOUNDS = 0x020B,
    /// The transaction's fee limit is above the decoder bound.
    TX_FEE_OVER_BOUND = 0x020C,
    /// A digest claimed by the caller differs from the recomputed one.
    TX_DIGEST_MISMATCH = 0x020D,
    /// (EVM) The transaction's chain id differs from the network.
    TX_CHAIN_ID_MISMATCH = 0x020E,

    // 0x03xx policy
    /// No policy bundle is installed (deny by default).
    NO_POLICY = 0x0301,
    /// The bundle's signatures or quorum do not verify.
    BUNDLE_INVALID = 0x0302,
    /// The bundle's version is not newer than the installed one.
    BUNDLE_ROLLBACK = 0x0303,
    /// A loosening bundle's time-lock is still running.
    BUNDLE_NOT_EFFECTIVE = 0x0304,
    /// The policy has no rule for the asset.
    ASSET_NOT_ALLOWED = 0x0305,
    /// The recipient is not on the allowlist.
    RECIPIENT_NOT_ALLOWED = 0x0306,
    /// The amount is above the per-transaction cap.
    AMOUNT_OVER_TX_CAP = 0x0307,
    /// The fee is above the policy fee cap.
    FEE_OVER_CAP = 0x0308,
    /// The validity window is above the policy maximum.
    VALIDITY_OVER_CAP = 0x0309,

    // 0x04xx initiator and approvals
    /// The initiator statement has a bad signature, an unknown key or the wrong role.
    INITIATOR_INVALID = 0x0401,
    /// Fewer valid approvals than the amount tier requires.
    APPROVALS_INSUFFICIENT = 0x0402,
    /// An approval signature does not verify.
    APPROVAL_INVALID = 0x0403,
    /// An approval key is not in the bundle's approver set.
    APPROVER_UNKNOWN = 0x0404,
    /// The same approver key appears more than once.
    APPROVER_DUPLICATE = 0x0405,
    /// The initiator key is also an approver key (separation of duties).
    SOD_VIOLATION = 0x0406,
    /// An approval statement has expired.
    APPROVAL_EXPIRED = 0x0407,
    /// An approval's intent digest differs from the recomputed one.
    APPROVAL_INTENT_MISMATCH = 0x0408,

    // 0x05xx velocity and breaker
    /// The spend reservation would exceed this signer's velocity cap.
    VELOCITY_EXCEEDED = 0x0501,
    /// The wallet is frozen.
    FROZEN = 0x0502,
    /// An auto-pause trigger fired.
    BREAKER_TRIPPED = 0x0503,
    /// The clock went backwards past its high-water mark, or is out of the skew bound.
    CLOCK_UNTRUSTED = 0x0504,

    // 0x06xx local state (fail closed)
    /// A durable write (velocity, replay or receipt log) failed.
    STATE_WRITE_FAILED = 0x0601,
    /// The signing key or share failed to load.
    KEY_UNAVAILABLE = 0x0602,
    /// An internal invariant was violated.
    INTERNAL = 0x0603,

    // 0x07xx keygen and control (v2)
    /// (v2) Key generation over an existing group.
    GROUP_EXISTS = 0x0701,
    /// (v2) The key-generation intent's admin quorum or fields are invalid.
    KEYGEN_INTENT_INVALID = 0x0702,
    /// (v2) No auxiliary info for the node set and epoch.
    AUX_EPOCH_UNKNOWN = 0x0703,
    /// An M-of-N admin action (such as unfreeze) is short of its quorum.
    ADMIN_QUORUM_INSUFFICIENT = 0x0704,

    // 0xF0xx unavailable (retryable; not a refusal)
    /// The signer's queue is full.
    BUSY = 0xF001,
    /// A deadline passed.
    TIMEOUT = 0xF002,
    /// A peer or the message bus is unreachable.
    PEER_UNREACHABLE = 0xF003,
    /// (v2) The signing protocol aborted.
    ENGINE_ABORT = 0xF004,
}

impl RefusalCode {
    /// `true` only for the "unavailable" class (`0xF0xx`), which may be retried as a fresh attempt.
    /// Everything else, including codes this version does not know, is a final refusal.
    pub fn is_retryable(self) -> bool {
        self.0 >> 8 == 0xF0
    }
}

/// A refusal: the code and, for policy refusals, the index of the rule that fired. There is no
/// free-text reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Refusal {
    /// What was refused.
    pub code: RefusalCode,
    /// The policy rule that fired, if any.
    pub rule_index: Option<u32>,
}

/// A signer's decision on one request.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Decision {
    /// Every check passed.
    Accept,
    /// A check failed; nothing is signed.
    Refuse(Refusal),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_names_and_classes() {
        assert_eq!(
            RefusalCode::TX_SELECTOR_NOT_ALLOWED.name(),
            Some("TX_SELECTOR_NOT_ALLOWED")
        );
        assert_eq!(RefusalCode(0x0FFF).name(), None);
        assert!(RefusalCode::BUSY.is_retryable());
        assert!(RefusalCode::ENGINE_ABORT.is_retryable());
        assert!(!RefusalCode::FROZEN.is_retryable());
        assert!(
            !RefusalCode(0x0FFF).is_retryable(),
            "unknown codes are final"
        );
    }
}
