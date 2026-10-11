//! Identifiers and fixed-width primitives.

use std::cmp::Ordering;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::Error;

/// Chain registry code (contract rule 7). Only [`ChainId::TRON`] is accepted in v0; the other
/// codes are reserved now so they never move.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainId(pub u16);

impl ChainId {
    /// TRON (v0, live).
    pub const TRON: Self = Self(0x0001);
    /// EVM chains (reserved; the next chain to graduate).
    pub const EVM: Self = Self(0x0002);
    /// Bitcoin (reserved).
    pub const BITCOIN: Self = Self(0x0003);
    /// Solana (reserved).
    pub const SOLANA: Self = Self(0x0004);
    /// Sui (reserved).
    pub const SUI: Self = Self(0x0005);
    /// Aptos (reserved).
    pub const APTOS: Self = Self(0x0006);
}

/// One allowlisted network.
#[derive(Debug, PartialEq, Eq, Hash)]
struct Network {
    id: &'static str,
    chain: ChainId,
}

/// The closed network allowlist (CAIP-2 ids). A network is added only when its chain graduates.
/// TRON uses the decimal CAIP-2 form; the deprecated hex alias is not accepted.
static NETWORKS: [Network; 5] = [
    net("tron:728126428", ChainId::TRON),  // mainnet
    net("tron:2494104990", ChainId::TRON), // Shasta testnet
    net("tron:3448148188", ChainId::TRON), // Nile testnet
    net("eip155:1", ChainId::EVM),         // Ethereum mainnet
    net("eip155:11155111", ChainId::EVM),  // Sepolia testnet
];

const fn net(id: &'static str, chain: ChainId) -> Network {
    Network { id, chain }
}

/// A network, as a CAIP-2 id from a closed allowlist. Byte-identical transactions on two networks
/// of one chain mean different things, so every intent, request and receipt names its network
/// (one key per network).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetworkId(&'static Network);

impl NetworkId {
    /// Looks `id` up in the allowlist.
    pub fn new(id: &str) -> Result<Self, Error> {
        NETWORKS
            .iter()
            .find(|n| n.id == id)
            .map(Self)
            .ok_or(Error::UnknownNetwork)
    }

    /// The CAIP-2 id, e.g. `tron:2494104990`.
    pub fn as_str(self) -> &'static str {
        self.0.id
    }

    /// The chain this network belongs to (its CAIP-2 namespace).
    pub fn chain(self) -> ChainId {
        self.0.chain
    }
}

impl Serialize for NetworkId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.0.id)
    }
}

impl<'de> Deserialize<'de> for NetworkId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let id = String::deserialize(d)?;
        Self::new(&id).map_err(serde::de::Error::custom)
    }
}

/// A wallet (key group) id: `[a-z0-9-]{1,64}`, checked at construction, so it is safe to use as a
/// storage path or bus subject component.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct WalletId(String);

impl WalletId {
    /// Validates `id`.
    pub fn new(id: &str) -> Result<Self, Error> {
        let valid = (1..=64).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if valid {
            Ok(Self(id.to_owned()))
        } else {
            Err(Error::InvalidWalletId)
        }
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for WalletId {
    type Error = Error;
    fn try_from(id: String) -> Result<Self, Error> {
        Self::new(&id)
    }
}

/// A random 128-bit request id: the idempotency and replay key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(pub [u8; 16]);

/// An unsigned 256-bit integer in base units, stored **little-endian** (the BCS `u256` layout).
///
/// `Ord` compares numerically. Never compare the raw bytes directly: little-endian bytes do not
/// sort in numeric order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct U256(pub [u8; 32]);

impl From<u64> for U256 {
    fn from(n: u64) -> Self {
        let mut le = [0u8; 32];
        le[..8].copy_from_slice(&n.to_le_bytes());
        Self(le)
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A chain-native address as raw bytes (TRON: 21 bytes, `0x41` ‖ 20; EVM: 20 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub Vec<u8>);

/// SHA-256 of the canonical **unsigned** transaction bytes, on every chain. For TRON this is the
/// transaction id. A chain's own signing digest is carried by [`SignInput`](crate::SignInput).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxHash(pub [u8; 32]);

impl TxHash {
    /// Hashes the unsigned transaction bytes.
    pub fn of(raw_tx: &[u8]) -> Self {
        Self(Sha256::digest(raw_tx).into())
    }
}

/// `tagged_digest(INTENT_V1, intent)`: what initiators and approvers sign statements about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IntentDigest(pub [u8; 32]);

/// `tagged_digest(RECEIPT_V1, body)`: links each receipt to the previous one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReceiptDigest(pub [u8; 32]);

/// An Ed25519 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ed25519Pub(pub [u8; 32]);

/// A 64-byte value (an Ed25519 signature) that encodes as exactly 64 raw bytes, with no length
/// prefix (contract rule 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "[[u8; 32]; 2]", into = "[[u8; 32]; 2]")]
pub struct Sig64(pub [u8; 64]);

// ponytail: serde only implements arrays up to 32 elements; two 32-byte halves give the same
// 64 raw bytes under BCS without a hand-written visitor.
impl From<[[u8; 32]; 2]> for Sig64 {
    fn from([lo, hi]: [[u8; 32]; 2]) -> Self {
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&lo);
        sig[32..].copy_from_slice(&hi);
        Self(sig)
    }
}

impl From<Sig64> for [[u8; 32]; 2] {
    fn from(sig: Sig64) -> Self {
        let (mut lo, mut hi) = ([0u8; 32], [0u8; 32]);
        lo.copy_from_slice(&sig.0[..32]);
        hi.copy_from_slice(&sig.0[32..]);
        [lo, hi]
    }
}

/// The verifier build that made a decision, recorded in every receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VerifierVersion {
    /// Major version. A relay refuses to mix majors in one ceremony.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
    /// Patch version.
    pub patch: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_id_charset_and_length() {
        assert!(WalletId::new("00000000-0000-4000-8000-000000000001").is_ok());
        assert!(WalletId::new(&"a".repeat(64)).is_ok());
        for bad in ["", "../x", "A", "a_b", "a b", "a/b", "é", &"a".repeat(65)] {
            assert_eq!(WalletId::new(bad), Err(Error::InvalidWalletId), "{bad:?}");
        }
    }

    #[test]
    fn network_allowlist_and_chain() {
        assert_eq!(
            NetworkId::new("tron:3448148188").unwrap().chain(),
            ChainId::TRON
        );
        assert_eq!(
            NetworkId::new("eip155:11155111").unwrap().chain(),
            ChainId::EVM
        );
        assert_eq!(
            NetworkId::new("tron:2494104990").unwrap().as_str(),
            "tron:2494104990"
        );
        for bad in [
            "tron:0x94a9059e",
            "TRON:728126428",
            "tron:1",
            "eip155:56",
            "",
        ] {
            assert_eq!(NetworkId::new(bad), Err(Error::UnknownNetwork), "{bad:?}");
        }
    }

    #[test]
    fn u256_orders_numerically() {
        assert!(U256::from(256) > U256::from(255));
        let mut two_pow_64 = [0u8; 32];
        two_pow_64[8] = 1;
        assert!(U256::from(u64::MAX) < U256(two_pow_64));
        assert_eq!(U256::from(1_000_000).0[..3], [0x40, 0x42, 0x0f]);
    }

    #[test]
    fn sig64_encodes_as_64_raw_bytes() {
        let sig = Sig64(core::array::from_fn(|i| i as u8));
        let bytes = crate::to_canonical(&sig).unwrap();
        assert_eq!(bytes, sig.0);
        assert_eq!(crate::from_canonical_strict::<Sig64>(&bytes), Ok(sig));
    }
}
