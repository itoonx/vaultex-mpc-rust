pub mod address;
pub mod signer;
pub mod tx;

pub use address::validate_aptos_address;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, SimulationResult, TransactionParams,
    UnsignedTransaction,
};

/// Configuration for Aptos transaction simulation / risk analysis.
#[derive(Debug, Clone)]
pub struct AptosSimulationConfig {
    /// Maximum Octas (1 APT = 10^8 Octas) per transaction before flagging as high-value.
    pub max_octas_per_tx: u64,
    /// Maximum gas budget before flagging as excessive.
    pub max_gas_amount: u64,
}

impl Default for AptosSimulationConfig {
    fn default() -> Self {
        Self {
            max_octas_per_tx: 1_000_000_000_000, // 10,000 APT
            max_gas_amount: 200_000,
        }
    }
}

/// Aptos chain provider.
///
/// Holds an optional Ed25519 `GroupPublicKey` so that `build_transaction` can
/// embed it inside the serialized `tx_data`, and `finalize_transaction` can
/// later recover it to build the correct Aptos signature format.
pub struct AptosProvider {
    group_pubkey: Option<GroupPublicKey>,
    simulation_config: Option<AptosSimulationConfig>,
}

impl AptosProvider {
    /// Create a provider without a pre-loaded public key (address derivation only).
    pub fn new() -> Self {
        Self {
            group_pubkey: None,
            simulation_config: None,
        }
    }

    /// Create a provider pre-loaded with the group's Ed25519 public key.
    pub fn with_pubkey(group_pubkey: GroupPublicKey) -> Self {
        Self {
            group_pubkey: Some(group_pubkey),
            simulation_config: None,
        }
    }

    /// Attach a simulation configuration for risk analysis.
    pub fn with_simulation(mut self, config: AptosSimulationConfig) -> Self {
        self.simulation_config = Some(config);
        self
    }
}

impl Default for AptosProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainProvider for AptosProvider {
    fn chain(&self) -> Chain {
        Chain::Aptos
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_aptos_address(group_pubkey)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        let pubkey = self.group_pubkey.as_ref().ok_or_else(|| {
            CoreError::InvalidInput(
                "AptosProvider requires a GroupPublicKey — use AptosProvider::with_pubkey".into(),
            )
        })?;
        tx::build_aptos_transaction(params, pubkey).await
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        tx::finalize_aptos_transaction(unsigned, sig)
    }

    async fn broadcast(
        &self,
        signed: &SignedTransaction,
        rpc_url: &str,
    ) -> Result<String, CoreError> {
        // Aptos REST API: POST /v1/transactions with BCS-encoded signed tx
        let url = format!("{rpc_url}/v1/transactions");
        let encoded = BASE64.encode(&signed.raw_tx);
        let body = serde_json::json!({
            "sender": signed.tx_hash,
            "signed_transaction": encoded,
        });
        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| CoreError::Other(format!("broadcast request failed: {e}")))?;
        let status = resp.status();
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CoreError::Other(format!("broadcast response parse failed: {e}")))?;
        if !status.is_success() {
            let msg = json
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            return Err(CoreError::Other(format!("Aptos broadcast failed: {msg}")));
        }
        json.get("hash")
            .and_then(|h| h.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| CoreError::Other("missing hash in Aptos response".into()))
    }

    async fn simulate_transaction(
        &self,
        params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        let config = match &self.simulation_config {
            Some(c) => c,
            None => {
                return Ok(SimulationResult {
                    success: true,
                    gas_used: 0,
                    return_data: vec![],
                    risk_flags: vec![],
                    risk_score: 0,
                });
            }
        };

        let mut risk_flags = Vec::new();
        let mut risk_score: u16 = 0;

        let octas: u64 = params.value.parse().unwrap_or(0);
        if octas > config.max_octas_per_tx {
            risk_flags.push("high_value".to_string());
            risk_score += 50;
        }

        if let Some(extra) = &params.extra {
            if let Some(gas) = extra.get("max_gas_amount").and_then(|v| v.as_u64()) {
                if gas > config.max_gas_amount {
                    risk_flags.push("excessive_gas".to_string());
                    risk_score += 30;
                }
            }
        }

        Ok(SimulationResult {
            success: true,
            gas_used: 0,
            return_data: vec![],
            risk_flags,
            risk_score: risk_score.min(255) as u8,
        })
    }
}
