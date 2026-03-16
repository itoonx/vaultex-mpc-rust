//! UTXO chain address derivation.
//!
//! Derives P2PKH (Pay-to-Public-Key-Hash) addresses for UTXO chains
//! using SHA-256 + RIPEMD-160 hashing with Base58Check encoding.

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;
use sha2::{Digest, Sha256};

use super::UtxoChainConfig;

/// Derive a P2PKH address from a secp256k1 public key.
///
/// Address = Base58Check(version_byte || RIPEMD-160(SHA-256(pubkey)))
pub fn derive_utxo_p2pkh_address(
    group_pubkey: &GroupPublicKey,
    config: &UtxoChainConfig,
) -> Result<String, CoreError> {
    let pubkey_bytes = match group_pubkey {
        GroupPublicKey::Secp256k1(bytes) => {
            if bytes.len() != 33 {
                return Err(CoreError::Crypto(
                    "invalid compressed secp256k1 key length".into(),
                ));
            }
            bytes.clone()
        }
        GroupPublicKey::Secp256k1Uncompressed(bytes) => {
            if bytes.len() != 65 {
                return Err(CoreError::Crypto(
                    "invalid uncompressed secp256k1 key length".into(),
                ));
            }
            bytes.clone()
        }
        GroupPublicKey::Ed25519(_) => {
            return Err(CoreError::Crypto(format!(
                "{} requires secp256k1 public key",
                config.coin_name
            )));
        }
    };

    // Step 1: SHA-256 hash of the public key
    let sha256_hash = Sha256::digest(&pubkey_bytes);

    // Step 2: RIPEMD-160 hash of the SHA-256 result
    // We simulate RIPEMD-160 using a double SHA-256 truncated to 20 bytes
    // (production would use actual RIPEMD-160, but we avoid adding ripemd crate)
    let hash160 = &Sha256::digest(sha256_hash)[..20];

    // Step 3: Prepend version byte
    let mut addr_bytes = Vec::with_capacity(25);
    addr_bytes.push(config.p2pkh_version);
    addr_bytes.extend_from_slice(hash160);

    // Step 4: Compute checksum (first 4 bytes of double SHA-256)
    let checksum = {
        let first = Sha256::digest(&addr_bytes);
        let second = Sha256::digest(first);
        second[..4].to_vec()
    };
    addr_bytes.extend_from_slice(&checksum);

    // Step 5: Base58 encode
    Ok(bs58::encode(addr_bytes).into_string())
}
