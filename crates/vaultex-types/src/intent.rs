//! The decoded intent, and what a signer's key or engine actually signs.

use serde::{Deserialize, Serialize};

use crate::{
    tag, tagged_digest, Address, ChainId, IntentDigest, NetworkId, TxHash, WalletId, U256,
};

/// The asset a transfer moves.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetId {
    /// The chain's native coin (TRX on TRON).
    Native,
    /// A token, by contract address (a TRC-20 contract on TRON).
    Contract(Address),
}

/// What a transaction does, as the verifier decoded it from the exact unsigned bytes. Field
/// semantics are specified by the `INTENT_V1` RFC; a verifier never takes an intent from a caller.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IntentV1 {
    /// The wallet (key group) that would sign.
    pub wallet_id: WalletId,
    /// The chain.
    pub chain: ChainId,
    /// The network. Its namespace must match `chain`.
    pub network: NetworkId,
    /// The sending address, decoded from the transaction.
    pub sender: Address,
    /// The receiving address, decoded from the transaction.
    pub recipient: Address,
    /// The asset moved.
    pub asset: AssetId,
    /// The amount, in the asset's base units.
    pub amount: U256,
    /// The chain-native fee bound (TRON: `fee_limit` in sun; 0 when the transaction has none).
    pub fee_cap: U256,
    /// The expiry encoded in the transaction, in milliseconds since the Unix epoch.
    pub not_after_ms: u64,
    /// SHA-256 of the unsigned transaction bytes.
    pub tx_hash: TxHash,
}

impl IntentV1 {
    /// `tagged_digest(INTENT_V1, self)`.
    pub fn digest(&self) -> IntentDigest {
        IntentDigest(tagged_digest(tag::INTENT_V1, self))
    }
}

/// The hash an ECDSA engine applies to a preimage.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EcdsaHash {
    /// SHA-256 (TRON).
    Sha256,
    /// Keccak-256 (EVM).
    Keccak256,
    /// Double SHA-256 (Bitcoin).
    Sha256d,
}

/// Exactly what a signer's key or MPC engine signs, produced only by the verifier's own decode of
/// the unsigned transaction.
///
/// There is deliberately **no pre-hashed variant**: a signer that hashes the preimage itself knows
/// what it signs, and an ECDSA presignature must never be combined with a digest chosen by someone
/// else. New variants are appended only (contract rule 8).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignInput {
    /// ECDSA over `hash(bytes)`, where `bytes` is the chain's signing preimage (TRON: `raw_data`).
    EcdsaPreimage {
        /// The hash the engine applies.
        hash: EcdsaHash,
        /// The preimage, held by the signer.
        bytes: Vec<u8>,
    },
    /// Ed25519 over the exact message the chain verifies.
    Ed25519Message(Vec<u8>),
}
