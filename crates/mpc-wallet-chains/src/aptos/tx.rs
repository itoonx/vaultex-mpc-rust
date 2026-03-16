// Aptos transaction serialization using BCS encoding.
//
// This module implements:
//   1. `AptosRawTransaction` — BCS-serializable struct for an Aptos transfer.
//   2. `build_aptos_transaction` — encodes the payload with BCS, computes SHA3-256
//      signing payload, and stores `bcs_bytes || pubkey(32)` in `tx_data`.
//   3. `finalize_aptos_transaction` — extracts the pubkey suffix from `tx_data` and builds
//      the Aptos signed transaction bytes.
//
// Aptos signing: SHA3-256(RAW_TRANSACTION_SALT || bcs(raw_tx))
// RAW_TRANSACTION_SALT = SHA3-256(b"APTOS::RawTransaction")

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::aptos::address::validate_aptos_address;
use crate::provider::{Chain, SignedTransaction, TransactionParams, UnsignedTransaction};

/// Aptos transaction payload for a coin transfer.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AptosTransferPayload {
    /// Sender address as 32 bytes.
    pub sender: [u8; 32],
    /// Recipient address as 32 bytes.
    pub recipient: [u8; 32],
    /// Amount in Octas (1 APT = 100_000_000 Octas).
    pub amount: u64,
    /// Sequence number of the sender account.
    pub sequence_number: u64,
    /// Maximum gas amount willing to pay.
    pub max_gas_amount: u64,
    /// Gas unit price in Octas.
    pub gas_unit_price: u64,
    /// Expiration timestamp in seconds.
    pub expiration_timestamp_secs: u64,
    /// Chain ID (1 = mainnet, 2 = testnet).
    pub chain_id: u8,
}

/// Compute the Aptos signing prefix: SHA3-256(b"APTOS::RawTransaction").
fn aptos_signing_prefix() -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"APTOS::RawTransaction");
    hasher.finalize().to_vec()
}

/// Build an unsigned Aptos transaction using BCS encoding.
///
/// Reads `sender`, `sequence_number`, `max_gas_amount`, `gas_unit_price`,
/// `expiration_timestamp_secs`, and `chain_id` from `params.extra`.
///
/// Sign payload = SHA3-256(prefix_hash || bcs_bytes) where
/// prefix_hash = SHA3-256(b"APTOS::RawTransaction").
///
/// Stores `bcs_bytes || pubkey(32)` in `tx_data`.
pub async fn build_aptos_transaction(
    params: TransactionParams,
    group_pubkey: &GroupPublicKey,
) -> Result<UnsignedTransaction, CoreError> {
    build_move_transaction(Chain::Aptos, params, group_pubkey).await
}

/// Build an unsigned Move VM transaction (Aptos or Movement).
pub async fn build_move_transaction(
    chain: Chain,
    params: TransactionParams,
    group_pubkey: &GroupPublicKey,
) -> Result<UnsignedTransaction, CoreError> {
    // 1. Extract and validate sender
    let sender_hex = params
        .extra
        .as_ref()
        .and_then(|e| e["sender"].as_str())
        .ok_or_else(|| CoreError::InvalidInput("Aptos: missing sender in extra".into()))?;
    let sender_bytes = validate_aptos_address(sender_hex)?;

    // 2. Validate and decode recipient
    let recipient_bytes = validate_aptos_address(&params.to)?;

    // 3. Parse amount
    let amount: u64 = params
        .value
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

    // 4. Parse extra params with defaults
    let extra = params.extra.as_ref();
    let sequence_number = extra
        .and_then(|e| e["sequence_number"].as_u64())
        .unwrap_or(0);
    let max_gas_amount = extra
        .and_then(|e| e["max_gas_amount"].as_u64())
        .unwrap_or(2000);
    let gas_unit_price = extra
        .and_then(|e| e["gas_unit_price"].as_u64())
        .unwrap_or(100);
    let expiration_timestamp_secs = extra
        .and_then(|e| e["expiration_timestamp_secs"].as_u64())
        .unwrap_or(u64::MAX);
    let chain_id = extra.and_then(|e| e["chain_id"].as_u64()).unwrap_or(1) as u8;

    // 5. Build payload
    let payload = AptosTransferPayload {
        sender: sender_bytes,
        recipient: recipient_bytes,
        amount,
        sequence_number,
        max_gas_amount,
        gas_unit_price,
        expiration_timestamp_secs,
        chain_id,
    };

    // 6. BCS encode
    let bcs_bytes =
        bcs::to_bytes(&payload).map_err(|e| CoreError::Protocol(format!("BCS failed: {e}")))?;

    // 7. Compute sign_payload: SHA3-256(prefix || bcs_bytes)
    let prefix = aptos_signing_prefix();
    let sign_payload = {
        let mut hasher = Sha3_256::new();
        hasher.update(&prefix);
        hasher.update(&bcs_bytes);
        hasher.finalize().to_vec()
    };

    // 8. Validate Ed25519 key
    let pubkey_bytes = match group_pubkey {
        GroupPublicKey::Ed25519(ref b) => {
            if b.len() != 32 {
                return Err(CoreError::InvalidInput(
                    "Ed25519 pubkey must be 32 bytes".into(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b);
            arr
        }
        _ => return Err(CoreError::InvalidInput("Aptos requires Ed25519 key".into())),
    };

    // 9. Store: tx_data = bcs_bytes || pubkey(32)
    let mut tx_data = bcs_bytes;
    tx_data.extend_from_slice(&pubkey_bytes);

    Ok(UnsignedTransaction {
        chain,
        sign_payload,
        tx_data,
    })
}

/// Finalize an Aptos/Movement transaction with an EdDSA signature.
///
/// Expects `unsigned.tx_data` in the format: `bcs_bytes || pubkey(32)`.
///
/// Builds the signed transaction bytes:
///   `bcs_bytes || [0x00, sig(64), 0x20, pubkey(32)]`
///
/// where `0x00` is the Ed25519 scheme tag and `0x20` is the pubkey length (32).
pub fn finalize_aptos_transaction(
    unsigned: &UnsignedTransaction,
    sig: &MpcSignature,
) -> Result<SignedTransaction, CoreError> {
    let sig_bytes = match sig {
        MpcSignature::EdDsa { signature } => *signature,
        _ => {
            return Err(CoreError::InvalidInput(
                "Aptos requires EdDsa signature".into(),
            ))
        }
    };

    if unsigned.tx_data.len() < 32 {
        return Err(CoreError::Protocol("tx_data too short".into()));
    }
    let (bcs_bytes, pubkey_bytes) = unsigned.tx_data.split_at(unsigned.tx_data.len() - 32);
    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(pubkey_bytes);

    // Build signed tx: bcs_bytes || authenticator
    // Authenticator: [0x00 (Ed25519 tag) | sig(64) | 0x20 (pubkey len) | pubkey(32)]
    let mut raw_tx = Vec::with_capacity(bcs_bytes.len() + 98);
    raw_tx.extend_from_slice(bcs_bytes);
    raw_tx.push(0x00); // Ed25519 scheme
    raw_tx.extend_from_slice(&sig_bytes);
    raw_tx.push(0x20); // pubkey length = 32
    raw_tx.extend_from_slice(&pubkey_arr);

    let tx_hash = hex::encode(&unsigned.sign_payload);

    Ok(SignedTransaction {
        chain: unsigned.chain,
        raw_tx,
        tx_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> GroupPublicKey {
        GroupPublicKey::Ed25519([1u8; 32].to_vec())
    }

    fn test_params() -> TransactionParams {
        TransactionParams {
            to: format!("0x{}", "ab".repeat(32)),
            value: "1000".to_string(),
            data: None,
            chain_id: None,
            extra: Some(serde_json::json!({
                "sender": format!("0x{}", "01".repeat(32)),
                "sequence_number": 0,
                "max_gas_amount": 2000,
                "gas_unit_price": 100,
                "expiration_timestamp_secs": 9999999999u64,
                "chain_id": 1
            })),
        }
    }

    #[tokio::test]
    async fn test_build_aptos_sign_payload_is_32_bytes() {
        let unsigned = build_aptos_transaction(test_params(), &test_pubkey())
            .await
            .unwrap();
        assert_eq!(unsigned.sign_payload.len(), 32);
        assert_ne!(unsigned.sign_payload, vec![0u8; 32]);
    }

    #[tokio::test]
    async fn test_build_aptos_tx_data_contains_pubkey() {
        let pubkey = test_pubkey();
        let unsigned = build_aptos_transaction(test_params(), &pubkey)
            .await
            .unwrap();
        let last_32 = &unsigned.tx_data[unsigned.tx_data.len() - 32..];
        assert_eq!(last_32, &[1u8; 32]);
    }

    #[tokio::test]
    async fn test_build_aptos_rejects_secp256k1() {
        let pubkey = GroupPublicKey::Secp256k1(vec![2; 33]);
        let result = build_aptos_transaction(test_params(), &pubkey).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_finalize_aptos_rejects_ecdsa() {
        let unsigned = UnsignedTransaction {
            chain: Chain::Aptos,
            sign_payload: vec![0u8; 32],
            tx_data: vec![0u8; 64],
        };
        let sig = MpcSignature::Ecdsa {
            r: vec![0u8; 32],
            s: vec![0u8; 32],
            recovery_id: 0,
        };
        assert!(finalize_aptos_transaction(&unsigned, &sig).is_err());
    }

    #[tokio::test]
    async fn test_finalize_aptos_format() {
        let unsigned = build_aptos_transaction(test_params(), &test_pubkey())
            .await
            .unwrap();
        let sig = MpcSignature::EdDsa {
            signature: [0xAA; 64],
        };
        let signed = finalize_aptos_transaction(&unsigned, &sig).unwrap();
        // raw_tx = bcs_bytes + [0x00, sig(64), 0x20, pubkey(32)] = bcs_bytes + 98
        let bcs_len = unsigned.tx_data.len() - 32;
        assert_eq!(signed.raw_tx.len(), bcs_len + 98);
        // Check Ed25519 tag
        assert_eq!(signed.raw_tx[bcs_len], 0x00);
        // Check pubkey length byte
        assert_eq!(signed.raw_tx[bcs_len + 65], 0x20);
    }
}
