//! Canonical encoding (BCS), strict decoding and domain-separated digests.

use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};

/// Largest encoded message [`from_canonical_strict`] accepts. Checked before decoding.
pub const MAX_MESSAGE_BYTES: usize = 128 * 1024;
/// Largest unsigned transaction a verify request may carry. The verifier enforces it.
pub const MAX_RAW_TX_BYTES: usize = 64 * 1024;
/// Most approvals a verify request may carry. The verifier enforces it.
pub const MAX_APPROVALS: usize = 16;

/// Domain tags (contract rule 2). Each names exactly one type and one layout version.
pub mod tag {
    /// Digest of an [`IntentV1`](crate::IntentV1): the [`IntentDigest`](crate::IntentDigest).
    pub const INTENT_V1: &str = "VAULTEX/INTENT/v1";
    /// An [`ApprovalStatementV1`](crate::ApprovalStatementV1), signed by an initiator or approver key.
    pub const APPROVAL_V1: &str = "VAULTEX/APPROVAL/v1";
    /// A policy bundle body, signed by M-of-N policy-admin keys. The schema belongs to the kernel.
    pub const POLICY_BUNDLE_V1: &str = "VAULTEX/POLICY-BUNDLE/v1";
    /// An [`AdminActionV1`](crate::AdminActionV1) (freeze or unfreeze).
    pub const ADMIN_ACTION_V1: &str = "VAULTEX/ADMIN-ACTION/v1";
    /// A [`ReceiptBodyV1`](crate::ReceiptBodyV1), signed by the signer's receipt key.
    pub const RECEIPT_V1: &str = "VAULTEX/RECEIPT/v1";
}

/// Why a value could not be encoded, decoded or constructed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The input is larger than [`MAX_MESSAGE_BYTES`]; it was not decoded.
    #[error("encoded message is larger than {MAX_MESSAGE_BYTES} bytes")]
    TooLarge,
    /// BCS rejected the input (truncated, trailing bytes, non-canonical, invalid field value…).
    #[error("invalid canonical encoding: {0}")]
    Bcs(#[from] bcs::Error),
    /// The input decoded, but re-encoding it does not give back the same bytes.
    #[error("encoding is not canonical")]
    NonCanonical,
    /// A wallet id outside `[a-z0-9-]{1,64}`.
    #[error("wallet id must match [a-z0-9-]{{1,64}}")]
    InvalidWalletId,
    /// A network id that is not in the allowlist.
    #[error("network id is not in the allowlist")]
    UnknownNetwork,
}

/// Encodes `value` canonically (BCS).
pub fn to_canonical<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    Ok(bcs::to_bytes(value)?)
}

/// Decodes `bytes` as a `T`, refusing anything that is not its one canonical encoding.
///
/// The size cap is checked first. `bcs` rejects trailing input, non-minimal lengths, invalid
/// booleans and option tags, invalid UTF-8 and unknown enum variants; validated fields
/// ([`WalletId`](crate::WalletId), [`NetworkId`](crate::NetworkId)) reject bad values.
pub fn from_canonical_strict<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::TooLarge);
    }
    let value: T = bcs::from_bytes(bytes)?;
    // ponytail: `bcs` already refuses non-canonical input for derived types; this re-encode check
    // (contract rule 10) is the backstop for any hand-written `Deserialize` added later.
    if bcs::to_bytes(&value)? != bytes {
        return Err(Error::NonCanonical);
    }
    Ok(value)
}

/// `SHA-256(BCS(tag) ‖ BCS(value))`: the domain-separated digest of contract rule 2.
///
/// # Panics
///
/// Only if `value` holds a sequence longer than 2^31 − 1 elements, which BCS cannot encode. A
/// value decoded by [`from_canonical_strict`] never does.
pub fn tagged_digest<T: Serialize + ?Sized>(tag: &str, value: &T) -> [u8; 32] {
    // BCS of a pair is the concatenation of the BCS of its parts.
    let bytes = bcs::to_bytes(&(tag, value)).expect("value is BCS-encodable (sequences < 2^31)");
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_digest_is_length_prefixed() {
        let mut expected = vec![tag::INTENT_V1.len() as u8];
        expected.extend_from_slice(tag::INTENT_V1.as_bytes());
        expected.push(7);
        let want: [u8; 32] = Sha256::digest(&expected).into();
        assert_eq!(tagged_digest(tag::INTENT_V1, &7u8), want);
    }

    #[test]
    fn strict_decode_caps_size_before_decoding() {
        let big = vec![0u8; MAX_MESSAGE_BYTES + 1];
        assert_eq!(from_canonical_strict::<Vec<u8>>(&big), Err(Error::TooLarge));
    }
}
