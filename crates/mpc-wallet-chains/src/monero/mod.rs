//! Monero (XMR) chain provider.
//!
//! Monero uses the CryptoNote protocol with Ed25519 curve (Curve25519).
//! Addresses are derived from a pair of keys (spend key + view key).
//! For MPC, we use the spend public key to derive the standard address.

pub mod address;

use async_trait::async_trait;

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, SimulationResult, TransactionParams,
    UnsignedTransaction,
};

/// Monero chain provider.
///
/// Uses Ed25519 signing (FROST Ed25519).
/// Monero addresses are derived from spend + view key pairs.
/// For MPC, the group public key serves as the spend public key.
pub struct MoneroProvider;

impl MoneroProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MoneroProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainProvider for MoneroProvider {
    fn chain(&self) -> Chain {
        Chain::Monero
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_monero_address(group_pubkey)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        // Monero tx building requires ring signatures, decoys, and key images.
        // This is a simplified payload hash for the MPC signing flow.
        let value: u64 = params
            .value
            .parse()
            .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

        let mut payload = Vec::new();
        payload.extend_from_slice(params.to.as_bytes());
        payload.extend_from_slice(&value.to_le_bytes());
        if let Some(extra) = &params.extra {
            payload.extend_from_slice(extra.to_string().as_bytes());
        }

        // Keccak-256 hash (Monero uses Keccak, not SHA3)
        use sha3::{Digest, Keccak256};
        let sign_payload = Keccak256::digest(&payload).to_vec();

        Ok(UnsignedTransaction {
            chain: Chain::Monero,
            sign_payload,
            tx_data: payload,
        })
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        let sig_bytes = match sig {
            MpcSignature::EdDsa { signature } => signature.to_vec(),
            _ => {
                return Err(CoreError::InvalidInput(
                    "Monero requires EdDsa signature".into(),
                ))
            }
        };

        let mut raw_tx = unsigned.tx_data.clone();
        raw_tx.extend_from_slice(&sig_bytes);

        let tx_hash = hex::encode(&unsigned.sign_payload);

        Ok(SignedTransaction {
            chain: Chain::Monero,
            raw_tx,
            tx_hash,
        })
    }

    async fn broadcast(
        &self,
        signed: &SignedTransaction,
        rpc_url: &str,
    ) -> Result<String, CoreError> {
        // Monero daemon JSON-RPC: /send_raw_transaction
        let raw_hex = hex::encode(&signed.raw_tx);
        let body = serde_json::json!({
            "tx_as_hex": raw_hex,
            "do_not_relay": false,
        });
        let url = format!("{rpc_url}/send_raw_transaction");
        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| CoreError::Other(format!("broadcast request failed: {e}")))?;
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CoreError::Other(format!("broadcast response parse failed: {e}")))?;
        if json.get("status").and_then(|s| s.as_str()) != Some("OK") {
            let reason = json
                .get("reason")
                .and_then(|r| r.as_str())
                .unwrap_or("unknown");
            return Err(CoreError::Other(format!(
                "Monero broadcast failed: {reason}"
            )));
        }
        Ok(signed.tx_hash.clone())
    }

    async fn simulate_transaction(
        &self,
        params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        let mut risk_flags = Vec::new();
        let mut risk_score: u8 = 0;

        let piconero: u64 = params.value.parse().unwrap_or(0);
        // 1 XMR = 10^12 piconero, flag if > 100 XMR
        if piconero > 100_000_000_000_000 {
            risk_flags.push("high_value".into());
            risk_score = risk_score.saturating_add(50);
        }

        Ok(SimulationResult {
            success: true,
            gas_used: 0,
            return_data: Vec::new(),
            risk_flags,
            risk_score,
        })
    }
}
