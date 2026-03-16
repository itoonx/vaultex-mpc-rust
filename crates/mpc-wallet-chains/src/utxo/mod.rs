//! UTXO chain providers — Litecoin, Dogecoin, Zcash.
//!
//! These chains share Bitcoin's UTXO model and use secp256k1 ECDSA signing
//! (reusing GG20 ECDSA). Each has different address formats but similar
//! transaction structure.

pub mod address;

use async_trait::async_trait;

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, SimulationResult, TransactionParams,
    UnsignedTransaction,
};

/// UTXO chain configuration.
#[derive(Debug, Clone, Copy)]
pub struct UtxoChainConfig {
    pub chain: Chain,
    /// P2PKH address version byte.
    pub p2pkh_version: u8,
    /// P2SH address version byte.
    pub p2sh_version: u8,
    /// Human-readable part for bech32 addresses (if supported).
    pub bech32_hrp: Option<&'static str>,
    /// Coin name for display.
    pub coin_name: &'static str,
}

/// Litecoin configuration.
pub const LITECOIN_CONFIG: UtxoChainConfig = UtxoChainConfig {
    chain: Chain::Litecoin,
    p2pkh_version: 0x30, // 'L' prefix
    p2sh_version: 0x32,  // 'M' prefix
    bech32_hrp: Some("ltc"),
    coin_name: "Litecoin",
};

/// Dogecoin configuration.
pub const DOGECOIN_CONFIG: UtxoChainConfig = UtxoChainConfig {
    chain: Chain::Dogecoin,
    p2pkh_version: 0x1E, // 'D' prefix
    p2sh_version: 0x16,  // '9' or 'A' prefix
    bech32_hrp: None,    // Dogecoin doesn't widely use bech32
    coin_name: "Dogecoin",
};

/// Zcash transparent configuration.
pub const ZCASH_CONFIG: UtxoChainConfig = UtxoChainConfig {
    chain: Chain::Zcash,
    p2pkh_version: 0x1C, // t1 prefix (two-byte: 0x1CB8)
    p2sh_version: 0x1C,  // t3 prefix (two-byte: 0x1CBD)
    bech32_hrp: None,    // Zcash uses t-addresses, not bech32
    coin_name: "Zcash",
};

/// Generic UTXO chain provider for Litecoin, Dogecoin, Zcash.
///
/// Uses secp256k1 ECDSA signing (GG20) — same as Bitcoin legacy.
/// Transaction building delegates to a simplified UTXO model.
pub struct UtxoProvider {
    pub config: UtxoChainConfig,
}

impl UtxoProvider {
    pub fn litecoin() -> Self {
        Self {
            config: LITECOIN_CONFIG,
        }
    }

    pub fn dogecoin() -> Self {
        Self {
            config: DOGECOIN_CONFIG,
        }
    }

    pub fn zcash() -> Self {
        Self {
            config: ZCASH_CONFIG,
        }
    }
}

#[async_trait]
impl ChainProvider for UtxoProvider {
    fn chain(&self) -> Chain {
        self.config.chain
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_utxo_p2pkh_address(group_pubkey, &self.config)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        // Simplified UTXO transaction: hash the tx params for signing.
        // Full UTXO tx building (inputs, outputs, scripts) is a future enhancement.
        let chain = self.config.chain;
        let value: u64 = params
            .value
            .parse()
            .map_err(|_| CoreError::InvalidInput(format!("invalid amount: {}", params.value)))?;

        // Build a minimal signing payload from tx params
        let mut payload_data = Vec::new();
        payload_data.extend_from_slice(params.to.as_bytes());
        payload_data.extend_from_slice(&value.to_le_bytes());
        if let Some(extra) = &params.extra {
            payload_data.extend_from_slice(extra.to_string().as_bytes());
        }

        // Double SHA-256 hash (standard for UTXO chains)
        use sha2::{Digest, Sha256};
        let first = Sha256::digest(&payload_data);
        let sign_payload = Sha256::digest(first).to_vec();

        Ok(UnsignedTransaction {
            chain,
            sign_payload,
            tx_data: payload_data,
        })
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        // Extract ECDSA signature
        let (r, s) = match sig {
            MpcSignature::Ecdsa { r, s, .. } => (r.clone(), s.clone()),
            _ => {
                return Err(CoreError::InvalidInput(format!(
                    "{} requires ECDSA signature",
                    self.config.coin_name
                )))
            }
        };

        // Build raw tx: tx_data || DER-encoded signature
        let mut raw_tx = unsigned.tx_data.clone();
        raw_tx.extend_from_slice(&r);
        raw_tx.extend_from_slice(&s);

        let tx_hash = hex::encode(&unsigned.sign_payload);

        Ok(SignedTransaction {
            chain: self.config.chain,
            raw_tx,
            tx_hash,
        })
    }

    async fn broadcast(
        &self,
        signed: &SignedTransaction,
        rpc_url: &str,
    ) -> Result<String, CoreError> {
        // UTXO chains use similar REST broadcast pattern
        let raw_hex = hex::encode(&signed.raw_tx);
        let url = format!("{rpc_url}/tx");
        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .header("Content-Type", "text/plain")
            .body(raw_hex)
            .send()
            .await
            .map_err(|e| CoreError::Other(format!("broadcast request failed: {e}")))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| CoreError::Other(format!("broadcast response read failed: {e}")))?;
        if !status.is_success() {
            return Err(CoreError::Other(format!(
                "broadcast failed ({status}): {body}"
            )));
        }
        Ok(body.trim().to_string())
    }

    async fn simulate_transaction(
        &self,
        params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        // Basic UTXO simulation — dust and fee checks
        let mut risk_flags = Vec::new();
        let mut risk_score: u8 = 0;

        let value: u64 = params.value.parse().unwrap_or(0);
        if value > 0 && value < 546 {
            risk_flags.push("dust_output".into());
            risk_score = risk_score.saturating_add(40);
        }

        if let Some(extra) = &params.extra {
            if let Some(fee) = extra.get("fee_sat").and_then(|v| v.as_u64()) {
                if fee > 1_000_000 {
                    risk_flags.push("excessive_fee".into());
                    risk_score = risk_score.saturating_add(50);
                }
            }
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
