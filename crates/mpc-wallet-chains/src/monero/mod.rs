//! Monero (XMR) chain provider.
//!
//! Monero uses the CryptoNote protocol with Ed25519 curve (Curve25519).
//! Addresses are derived from a pair of keys (spend key + view key).
//! For MPC, we use the spend public key to derive the standard address.

pub mod address;
pub mod tx;

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
        tx::build_monero_transaction(params).await
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        tx::finalize_monero_transaction(unsigned, sig)
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
