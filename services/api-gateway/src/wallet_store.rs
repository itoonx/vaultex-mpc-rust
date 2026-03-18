//! In-memory wallet store for key shares and wallet metadata.
//!
//! Stores the result of MPC keygen ceremonies. Each wallet contains:
//! - Group public key (shared across all parties)
//! - Key shares for all parties (in single-gateway demo mode)
//! - Metadata (label, scheme, threshold, frozen state)
//!
//! Production: Replace with persistent storage (encrypted DB, HSM-backed).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use mpc_wallet_core::protocol::{GroupPublicKey, KeyShare, MpcProtocol, MpcSignature};
use mpc_wallet_core::transport::local::LocalTransportNetwork;
use mpc_wallet_core::types::{CryptoScheme, PartyId, ThresholdConfig};

/// Wallet record stored in memory.
#[derive(Clone)]
pub struct WalletRecord {
    pub group_id: String,
    pub label: String,
    pub scheme: CryptoScheme,
    pub config: ThresholdConfig,
    pub group_public_key: GroupPublicKey,
    /// Key shares for all parties (demo mode — single gateway holds all shares).
    pub shares: Vec<KeyShare>,
    pub created_at: u64,
    pub frozen: bool,
}

/// In-memory wallet store.
#[derive(Clone, Default)]
pub struct WalletStore {
    wallets: Arc<RwLock<HashMap<String, WalletRecord>>>,
}

impl WalletStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run MPC keygen and store the resulting wallet.
    pub async fn create(
        &self,
        group_id: String,
        label: String,
        scheme: CryptoScheme,
        threshold: u16,
        total_parties: u16,
    ) -> Result<WalletRecord, mpc_wallet_core::error::CoreError> {
        let config = ThresholdConfig::new(threshold, total_parties)
            .map_err(|e| mpc_wallet_core::error::CoreError::InvalidConfig(e.to_string()))?;
        let _validate = Self::protocol_for_scheme(scheme)?;
        let net = LocalTransportNetwork::new(total_parties);

        // Run keygen for all parties concurrently.
        let mut handles = Vec::new();
        for i in 1..=total_parties {
            let pid = PartyId(i);
            let transport = net.get_transport(pid);
            let proto = Self::protocol_for_scheme(scheme)?;
            handles.push(tokio::spawn(async move {
                proto.keygen(config, pid, &*transport).await
            }));
        }

        let mut shares = Vec::new();
        for h in handles {
            shares.push(h.await.map_err(|e| {
                mpc_wallet_core::error::CoreError::Protocol(format!("keygen task panicked: {e}"))
            })??);
        }

        let group_public_key = shares[0].group_public_key.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let record = WalletRecord {
            group_id: group_id.clone(),
            label,
            scheme,
            config,
            group_public_key,
            shares,
            created_at: now,
            frozen: false,
        };

        self.wallets.write().await.insert(group_id, record.clone());
        Ok(record)
    }

    /// Sign a message using a wallet's key shares.
    pub async fn sign(
        &self,
        group_id: &str,
        message: &[u8],
    ) -> Result<MpcSignature, mpc_wallet_core::error::CoreError> {
        let wallets = self.wallets.read().await;
        let wallet = wallets.get(group_id).ok_or_else(|| {
            mpc_wallet_core::error::CoreError::NotFound(format!("wallet {group_id} not found"))
        })?;

        if wallet.frozen {
            return Err(mpc_wallet_core::error::CoreError::KeyFrozen(format!(
                "wallet {group_id} is frozen"
            )));
        }

        let shares = &wallet.shares;
        let config = wallet.config;
        let scheme = wallet.scheme;

        // Use first t parties as signers (coordinator = Party 1).
        let t = config.threshold as usize;
        let signers: Vec<PartyId> = (0..t).map(|i| shares[i].party_id).collect();

        let net = LocalTransportNetwork::new(config.total_parties);
        let mut handles = Vec::new();
        for share in shares.iter().take(t) {
            let share = share.clone();
            let transport = net.get_transport(share.party_id);
            let proto = Self::protocol_for_scheme(scheme)?;
            let s = signers.clone();
            let m = message.to_vec();
            handles.push(tokio::spawn(async move {
                proto.sign(&share, &s, &m, &*transport).await
            }));
        }

        let mut sigs = Vec::new();
        for h in handles {
            sigs.push(h.await.map_err(|e| {
                mpc_wallet_core::error::CoreError::Protocol(format!("sign task panicked: {e}"))
            })??);
        }

        // Return coordinator's signature (index 0).
        Ok(sigs.into_iter().next().unwrap())
    }

    /// Get a wallet by group_id.
    pub async fn get(&self, group_id: &str) -> Option<WalletRecord> {
        self.wallets.read().await.get(group_id).cloned()
    }

    /// List all wallets (metadata only, no shares).
    pub async fn list(&self) -> Vec<WalletRecord> {
        self.wallets.read().await.values().cloned().collect()
    }

    /// Freeze a wallet.
    pub async fn freeze(&self, group_id: &str) -> Result<(), mpc_wallet_core::error::CoreError> {
        let mut wallets = self.wallets.write().await;
        let wallet = wallets.get_mut(group_id).ok_or_else(|| {
            mpc_wallet_core::error::CoreError::NotFound(format!("wallet {group_id} not found"))
        })?;
        wallet.frozen = true;
        Ok(())
    }

    /// Unfreeze a wallet.
    pub async fn unfreeze(&self, group_id: &str) -> Result<(), mpc_wallet_core::error::CoreError> {
        let mut wallets = self.wallets.write().await;
        let wallet = wallets.get_mut(group_id).ok_or_else(|| {
            mpc_wallet_core::error::CoreError::NotFound(format!("wallet {group_id} not found"))
        })?;
        wallet.frozen = false;
        Ok(())
    }

    /// Create the MPC protocol for a given scheme.
    fn protocol_for_scheme(
        scheme: CryptoScheme,
    ) -> Result<Box<dyn MpcProtocol>, mpc_wallet_core::error::CoreError> {
        use mpc_wallet_core::protocol::*;
        match scheme {
            CryptoScheme::Gg20Ecdsa => Ok(Box::new(gg20::Gg20Protocol::new())),
            CryptoScheme::FrostEd25519 => Ok(Box::new(frost_ed25519::FrostEd25519Protocol::new())),
            CryptoScheme::FrostSecp256k1Tr => {
                Ok(Box::new(frost_secp256k1::FrostSecp256k1TrProtocol::new()))
            }
            _ => Err(mpc_wallet_core::error::CoreError::InvalidConfig(format!(
                "unsupported scheme for gateway keygen: {scheme:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_get_wallet() {
        let store = WalletStore::new();
        let record = store
            .create(
                "test-1".into(),
                "test wallet".into(),
                CryptoScheme::Gg20Ecdsa,
                2,
                3,
            )
            .await
            .unwrap();

        assert_eq!(record.shares.len(), 3);
        assert!(!record.frozen);

        let fetched = store.get("test-1").await.unwrap();
        assert_eq!(fetched.label, "test wallet");
    }

    #[tokio::test]
    async fn test_sign_wallet() {
        let store = WalletStore::new();
        store
            .create(
                "sign-test".into(),
                "sign wallet".into(),
                CryptoScheme::Gg20Ecdsa,
                2,
                3,
            )
            .await
            .unwrap();

        let sig = store.sign("sign-test", b"hello world").await.unwrap();
        match sig {
            MpcSignature::Ecdsa { r, s, .. } => {
                assert_eq!(r.len(), 32);
                assert_eq!(s.len(), 32);
            }
            _ => panic!("expected ECDSA"),
        }
    }

    #[tokio::test]
    async fn test_freeze_blocks_signing() {
        let store = WalletStore::new();
        store
            .create(
                "freeze-test".into(),
                "freeze".into(),
                CryptoScheme::Gg20Ecdsa,
                2,
                3,
            )
            .await
            .unwrap();

        store.freeze("freeze-test").await.unwrap();
        let err = store.sign("freeze-test", b"should fail").await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("frozen"));

        store.unfreeze("freeze-test").await.unwrap();
        let sig = store.sign("freeze-test", b"should work now").await;
        assert!(sig.is_ok());
    }

    #[tokio::test]
    async fn test_list_wallets() {
        let store = WalletStore::new();
        assert!(store.list().await.is_empty());

        store
            .create("w1".into(), "one".into(), CryptoScheme::Gg20Ecdsa, 2, 3)
            .await
            .unwrap();
        store
            .create("w2".into(), "two".into(), CryptoScheme::FrostEd25519, 2, 3)
            .await
            .unwrap();

        assert_eq!(store.list().await.len(), 2);
    }
}
