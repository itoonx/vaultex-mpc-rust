//! Chain listing and address derivation endpoints.

use axum::{
    extract::{Path, State},
    Json,
};

use mpc_wallet_chains::provider::Chain;
use mpc_wallet_chains::registry::ChainRegistry;

use crate::errors::{ApiError, ErrorBody, ErrorCode};
use crate::models::response::{ApiResponse, ChainInfo, ChainsListResponse};
use crate::routes::wallets::check_network;
use crate::state::AppState;

/// Categorize a chain for display purposes.
fn chain_category(chain: Chain) -> &'static str {
    match chain {
        Chain::Ethereum
        | Chain::Polygon
        | Chain::Bsc
        | Chain::Arbitrum
        | Chain::Optimism
        | Chain::Base
        | Chain::Avalanche
        | Chain::Linea
        | Chain::ZkSync
        | Chain::Scroll
        | Chain::Mantle
        | Chain::Blast
        | Chain::Zora
        | Chain::Fantom
        | Chain::Gnosis
        | Chain::Cronos
        | Chain::Celo
        | Chain::Moonbeam
        | Chain::Ronin
        | Chain::OpBnb
        | Chain::Immutable
        | Chain::MantaPacific
        | Chain::Hyperliquid
        | Chain::Berachain
        | Chain::MegaEth
        | Chain::Monad => "evm",
        Chain::BitcoinMainnet
        | Chain::BitcoinTestnet
        | Chain::Litecoin
        | Chain::Dogecoin
        | Chain::Zcash => "utxo",
        Chain::Solana => "solana",
        Chain::Sui => "sui",
        Chain::Aptos | Chain::Movement => "move",
        Chain::Polkadot
        | Chain::Kusama
        | Chain::Astar
        | Chain::Acala
        | Chain::Phala
        | Chain::Interlay => "substrate",
        Chain::CosmosHub | Chain::Osmosis | Chain::Celestia | Chain::Injective | Chain::Sei => {
            "cosmos"
        }
        Chain::Starknet => "starknet",
        Chain::Monero => "cryptonote",
        Chain::Ton => "ton",
        Chain::Tron => "tron",
    }
}

/// Display name for a chain.
fn chain_display_name(chain: Chain) -> &'static str {
    match chain {
        Chain::Ethereum => "Ethereum",
        Chain::Polygon => "Polygon",
        Chain::Bsc => "BNB Smart Chain",
        Chain::Arbitrum => "Arbitrum One",
        Chain::Optimism => "Optimism",
        Chain::Base => "Base",
        Chain::Avalanche => "Avalanche C-Chain",
        Chain::Linea => "Linea",
        Chain::ZkSync => "zkSync Era",
        Chain::Scroll => "Scroll",
        Chain::Mantle => "Mantle",
        Chain::Blast => "Blast",
        Chain::Zora => "Zora",
        Chain::Fantom => "Fantom",
        Chain::Gnosis => "Gnosis",
        Chain::Cronos => "Cronos",
        Chain::Celo => "Celo",
        Chain::Moonbeam => "Moonbeam",
        Chain::Ronin => "Ronin",
        Chain::OpBnb => "opBNB",
        Chain::Immutable => "Immutable X",
        Chain::MantaPacific => "Manta Pacific",
        Chain::Hyperliquid => "Hyperliquid",
        Chain::Berachain => "Berachain",
        Chain::MegaEth => "MegaETH",
        Chain::Monad => "Monad",
        Chain::BitcoinMainnet => "Bitcoin",
        Chain::BitcoinTestnet => "Bitcoin Testnet",
        Chain::Litecoin => "Litecoin",
        Chain::Dogecoin => "Dogecoin",
        Chain::Zcash => "Zcash",
        Chain::Solana => "Solana",
        Chain::Sui => "Sui",
        Chain::Aptos => "Aptos",
        Chain::Movement => "Movement",
        Chain::Polkadot => "Polkadot",
        Chain::Kusama => "Kusama",
        Chain::Astar => "Astar",
        Chain::Acala => "Acala",
        Chain::Phala => "Phala",
        Chain::Interlay => "Interlay",
        Chain::CosmosHub => "Cosmos Hub",
        Chain::Osmosis => "Osmosis",
        Chain::Celestia => "Celestia",
        Chain::Injective => "Injective",
        Chain::Sei => "Sei",
        Chain::Starknet => "StarkNet",
        Chain::Monero => "Monero",
        Chain::Ton => "TON",
        Chain::Tron => "TRON",
    }
}

/// `GET /v1/chains` — list all supported chains.
#[utoipa::path(get, path = "/v1/chains", tag = "Chains",
    responses((status = 200, description = "List of supported chains", body = ApiResponse<ChainsListResponse>))
)]
pub async fn list_chains() -> Json<ApiResponse<ChainsListResponse>> {
    let chains: Vec<ChainInfo> = ChainRegistry::supported_chains()
        .into_iter()
        .map(|c| ChainInfo {
            name: c.to_string(),
            display_name: chain_display_name(c).into(),
            category: chain_category(c).into(),
        })
        .collect();
    let total = chains.len();
    Json(ApiResponse::ok(ChainsListResponse { chains, total }))
}

/// `GET /v1/chains/:chain/address/:id` — derive a wallet's address on a chain.
///
/// Chain gating: the address is derived from the wallet's group public key only
/// for a verified chain and a scheme whose signatures can spend from it; any
/// other chain/scheme pair is refused instead of answered with an address. A
/// gateway on a non-test network serves no addresses (release freeze).
#[utoipa::path(get, path = "/v1/chains/{chain}/address/{id}", tag = "Chains",
    params(("chain" = String, Path, description = "Chain name"), ("id" = String, Path, description = "Wallet ID")),
    security(("session_token" = [])),
    responses(
        (status = 200, description = "Derived address"),
        (status = 400, description = "Unknown chain, or no address served for this chain and wallet scheme (chain gating)", body = ErrorBody),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Refused by the release freeze (non-test network)", body = ErrorBody),
        (status = 404, description = "Wallet not found", body = ErrorBody)
    )
)]
pub async fn derive_address(
    State(state): State<AppState>,
    Path((chain_name, wallet_id)): Path<(String, String)>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    check_network(&state.network)?;

    let chain: Chain = chain_name
        .parse()
        .map_err(|e: String| ApiError::bad_request(ErrorCode::InvalidInput, e))?;

    // Load wallet's group public key from orchestrator metadata.
    let wallet = state
        .orchestrator
        .get(&wallet_id)
        .await
        .ok_or_else(|| ApiError::not_found(format!("wallet {wallet_id} not found")))?;

    let address = state
        .chain_registry
        .derive_address(chain, wallet.scheme, &wallet.group_public_key)
        .map_err(ApiError::from)?;

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "wallet_id": wallet_id,
        "chain": chain.to_string(),
        "address": address,
    }))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::wallets::freeze_tests::{assert_frozen, state_on};
    use axum::http::StatusCode;
    use mpc_wallet_core::protocol::GroupPublicKey;
    use mpc_wallet_core::types::CryptoScheme;

    /// secp256k1 generator, compressed: a valid key for every secp256k1 scheme.
    fn secp256k1_key() -> GroupPublicKey {
        GroupPublicKey::Secp256k1(
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        )
    }

    fn assert_gated(result: Result<String, ApiError>, chain: Chain, scheme: CryptoScheme) {
        let Err(err) = result else {
            panic!("{chain} / {scheme}: expected a chain-gating refusal, got an address");
        };
        assert_eq!(err.status, StatusCode::BAD_REQUEST, "{chain} / {scheme}");
        assert!(matches!(err.code, ErrorCode::InvalidInput));
        assert!(
            err.message.contains("chain gating: "),
            "{chain} / {scheme}: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn freeze_refuses_mainnet_network_chain_address() {
        // Refused before the wallet lookup: a mainnet gateway serves no addresses.
        let state = state_on("mainnet").await;
        let result =
            derive_address(State(state), Path(("ethereum".into(), "any-wallet".into()))).await;
        assert_frozen(result, "network 'mainnet'");
    }

    /// The handler's address call, on the gateway's own registry: every chain
    /// without a verified address derivation, and every chain for a
    /// FROST-Secp256k1-TR wallet, is refused with 400 INVALID_INPUT.
    #[tokio::test]
    async fn chain_gating_refuses_unverified_chains_and_frost_tr() {
        let state = state_on("testnet").await;
        let derive = |chain: Chain, scheme: CryptoScheme, key: &GroupPublicKey| {
            state
                .chain_registry
                .derive_address(chain, scheme, key)
                .map_err(ApiError::from)
        };
        let secp = secp256k1_key();
        let ed25519 = GroupPublicKey::Ed25519(vec![0x42; 32]);

        for chain in ChainRegistry::supported_chains() {
            assert_gated(
                derive(chain, CryptoScheme::FrostSecp256k1Tr, &secp),
                chain,
                CryptoScheme::FrostSecp256k1Tr,
            );
            if mpc_wallet_chains::metadata::metadata_for(chain).is_some() {
                continue;
            }
            for scheme in ChainRegistry::compatible_schemes(chain) {
                let key = if scheme == CryptoScheme::FrostEd25519 {
                    &ed25519
                } else {
                    &secp
                };
                assert_gated(derive(chain, scheme, key), chain, scheme);
            }
        }

        // Verified pairs are still served.
        let eth = derive(Chain::Ethereum, CryptoScheme::Gg20Ecdsa, &secp).unwrap();
        assert!(eth.starts_with("0x"), "{eth}");
        let btc = derive(Chain::BitcoinTestnet, CryptoScheme::Gg20Ecdsa, &secp).unwrap();
        assert!(btc.starts_with("tb1q"), "{btc}");
    }
}
