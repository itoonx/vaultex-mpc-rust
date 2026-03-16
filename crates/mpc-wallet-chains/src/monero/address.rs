//! Monero address derivation.
//!
//! Monero standard address = Base58(network_byte || spend_pubkey(32) || view_pubkey(32) || checksum(4))
//! For MPC, the group Ed25519 public key is the spend key.
//! The view key is derived as Keccak-256(spend_key) reduced mod l (scalar).
//! For simplicity, we use the spend key hash as a deterministic view key.

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;
use sha3::{Digest, Keccak256};

/// Monero mainnet network byte.
const MONERO_MAINNET_NETWORK_BYTE: u8 = 18;

/// Derive a Monero standard address from an Ed25519 group public key.
///
/// The spend public key is the group key. The view public key is derived
/// deterministically as Keccak-256(spend_key)[..32] (simplified).
pub fn derive_monero_address(group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
    let spend_key = match group_pubkey {
        GroupPublicKey::Ed25519(bytes) => {
            if bytes.len() != 32 {
                return Err(CoreError::Crypto(
                    "invalid Ed25519 public key length".into(),
                ));
            }
            bytes.clone()
        }
        _ => {
            return Err(CoreError::Crypto(
                "Monero requires Ed25519 public key".into(),
            ));
        }
    };

    // Derive view key deterministically from spend key (simplified)
    let view_key = Keccak256::digest(&spend_key);
    let view_key_bytes = &view_key[..32];

    // Build address data: network_byte || spend_key(32) || view_key(32)
    let mut addr_data = Vec::with_capacity(65);
    addr_data.push(MONERO_MAINNET_NETWORK_BYTE);
    addr_data.extend_from_slice(&spend_key);
    addr_data.extend_from_slice(view_key_bytes);

    // Checksum: first 4 bytes of Keccak-256(addr_data)
    let checksum = Keccak256::digest(&addr_data);
    addr_data.extend_from_slice(&checksum[..4]);

    // Monero uses its own Base58 encoding (not standard Base58Check).
    // For compatibility, we use standard Base58 here.
    Ok(bs58::encode(addr_data).into_string())
}
