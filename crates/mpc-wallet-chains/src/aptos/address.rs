use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::GroupPublicKey;
use sha3::{Digest, Sha3_256};

/// Derive an Aptos address from an Ed25519 group public key.
/// Aptos address = 0x + hex(SHA3-256(pubkey || 0x00))
/// where 0x00 is the Ed25519 single-key authentication scheme byte.
pub fn derive_aptos_address(group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
    match group_pubkey {
        GroupPublicKey::Ed25519(bytes) => {
            if bytes.len() != 32 {
                return Err(CoreError::Crypto(
                    "invalid Ed25519 public key length".into(),
                ));
            }
            let mut hasher = Sha3_256::new();
            hasher.update(bytes);
            hasher.update([0x00]); // Ed25519 single-key scheme byte
            let hash = hasher.finalize();
            Ok(format!("0x{}", hex::encode(hash)))
        }
        _ => Err(CoreError::Crypto(
            "Aptos requires Ed25519 public key".into(),
        )),
    }
}

/// Validate an Aptos address string.
/// A valid Aptos address is `0x` followed by exactly 64 lowercase hex characters (32 bytes).
pub fn validate_aptos_address(addr: &str) -> Result<[u8; 32], CoreError> {
    let hex_part = addr.strip_prefix("0x").ok_or_else(|| {
        CoreError::InvalidInput(format!("Aptos address must start with '0x', got: {addr}"))
    })?;
    if hex_part.len() != 64 {
        return Err(CoreError::InvalidInput(format!(
            "Aptos address must be 0x + 64 hex chars (32 bytes), got {} hex chars",
            hex_part.len()
        )));
    }
    let bytes = hex::decode(hex_part)
        .map_err(|e| CoreError::InvalidInput(format!("Aptos address contains invalid hex: {e}")))?;
    Ok(bytes.try_into().unwrap()) // safe: we checked len == 64 hex = 32 bytes
}
