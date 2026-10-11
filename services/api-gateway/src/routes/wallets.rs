//! Wallet management endpoints: create, list, get, sign, freeze, unfreeze, refresh.
//!
//! Production architecture (DEC-015): Gateway delegates to distributed MPC nodes via NATS.
//! Gateway holds ZERO key shares. Each MPC node holds exactly 1 share.
//!
//! Also home of the gateway's release freeze (ROADMAP M5 #5), shared with `transactions.rs`.

use std::fmt::Display;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};

use mpc_wallet_chains::provider::Chain;
use mpc_wallet_core::protocol::sign_authorization::{AuthorizationPayload, SignAuthorization};
use mpc_wallet_core::protocol::MpcSignature;
use mpc_wallet_core::rbac::{ApiRole, AuthContext, Permissions};
use mpc_wallet_core::types::CryptoScheme;
use sha2::{Digest, Sha256};

use crate::errors::{ApiError, ErrorBody, ErrorCode};
use crate::models::request::{CreateWalletRequest, SignRequest};
use crate::models::response::{
    AddressEntry, ApiResponse, SignResponse, WalletDetailResponse, WalletListResponse,
    WalletResponse,
};
use crate::state::AppState;

// ── Release freeze (ROADMAP M5 #5) ─────────────────────────────────
//
// Until the full independent audit (M10-F) closes, the gateway refuses key
// generation, raw-digest signing and every legacy scheme; only a debug build may
// lift those three, with the `dev-unfreeze` feature, for testnet development.
// Any network or chain other than testnet/devnet is refused in every build,
// `dev-unfreeze` included. The MPC nodes enforce the same refusals independently.

/// `true` unless this is a debug build with the `dev-unfreeze` feature.
const FROZEN: bool = !cfg!(feature = "dev-unfreeze");

#[cfg(all(feature = "dev-unfreeze", not(debug_assertions)))]
compile_error!(
    "`dev-unfreeze` is for debug builds only: release builds stay frozen until M10-F (ROADMAP M5 #5)"
);

fn refused(what: impl Display) -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        ErrorCode::PolicyDenied,
        format!("release freeze: {what} is refused in this build"),
    )
}

/// Refuse `what` when the build is frozen.
pub(crate) fn refuse_if_frozen(what: impl Display) -> Result<(), ApiError> {
    if FROZEN {
        return Err(refused(what));
    }
    Ok(())
}

/// Only testnet and devnet are allowed; anything else fails closed in every build.
pub(crate) fn check_network(network: &str) -> Result<(), ApiError> {
    if matches!(network, "testnet" | "devnet") {
        return Ok(());
    }
    Err(refused(format_args!("network '{network}'")))
}

/// Refuse chains that are mainnet whatever the configured network, in every build.
pub(crate) fn check_chain(chain: Chain) -> Result<(), ApiError> {
    if matches!(chain, Chain::BitcoinMainnet) {
        return Err(refused(format_args!("mainnet chain '{chain}'")));
    }
    Ok(())
}

/// Refuse every legacy scheme.
pub(crate) fn check_scheme(scheme: CryptoScheme) -> Result<(), ApiError> {
    // Exhaustive on purpose: a new scheme does not compile until it is classified here.
    // ponytail: same table as mpc-node's freeze.rs; one copy once WS-03 lands shared types.
    let legacy = match scheme {
        CryptoScheme::Gg20Ecdsa
        | CryptoScheme::Cggmp21Secp256k1
        | CryptoScheme::FrostEd25519
        | CryptoScheme::FrostSecp256k1Tr
        | CryptoScheme::Sr25519Threshold
        | CryptoScheme::StarkThreshold
        | CryptoScheme::Bls12_381Threshold => true,
    };
    if legacy {
        return refuse_if_frozen(format_args!("legacy scheme '{scheme}'"));
    }
    Ok(())
}

fn require_roles(ctx: &AuthContext, roles: &[ApiRole]) -> Result<(), ApiError> {
    Permissions::require_role(ctx, roles).map_err(|e| {
        tracing::warn!(user_id = %ctx.user_id, required = ?roles, actual = ?ctx.roles, "RBAC denied: {e}");
        ApiError::forbidden("insufficient permissions")
    })
}

fn require_admin_mfa(ctx: &AuthContext) -> Result<(), ApiError> {
    Permissions::can_freeze_key_mfa(ctx).map_err(|e| {
        tracing::warn!(user_id = %ctx.user_id, mfa = ctx.mfa_verified, "RBAC denied (admin+MFA): {e}");
        ApiError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::MfaRequired,
            "insufficient permissions",
        )
    })
}

/// `POST /v1/wallets` — create a new MPC wallet (distributed keygen).
#[utoipa::path(post, path = "/v1/wallets", tag = "Wallets",
    request_body = CreateWalletRequest,
    security(("session_token" = [])),
    responses(
        (status = 201, description = "Wallet created", body = ApiResponse<WalletResponse>),
        (status = 401, description = "Unauthorized", body = ErrorBody),
        (status = 403, description = "Admin+MFA required, or refused by the release freeze", body = ErrorBody)
    )
)]
pub async fn create_wallet(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<CreateWalletRequest>,
) -> Result<(StatusCode, Json<ApiResponse<WalletResponse>>), ApiError> {
    require_admin_mfa(&ctx)?;
    check_network(&state.network)?;
    refuse_if_frozen("key generation")?;

    let scheme: mpc_wallet_core::types::CryptoScheme = req
        .scheme
        .parse()
        .map_err(|e: String| ApiError::bad_request(ErrorCode::InvalidInput, e))?;

    mpc_wallet_core::types::ThresholdConfig::new(req.threshold, req.total_parties)
        .map_err(|e| ApiError::bad_request(ErrorCode::InvalidConfig, e.to_string()))?;

    state.metrics.keygen_total.inc();
    let group_id = uuid::Uuid::new_v4().to_string();

    let metadata = state
        .orchestrator
        .keygen(
            group_id,
            req.label,
            scheme,
            req.threshold,
            req.total_parties,
        )
        .await
        .map_err(ApiError::from)?;

    tracing::info!(
        group_id = %metadata.group_id,
        scheme = %metadata.scheme,
        "wallet created via distributed MPC keygen (no shares in gateway)"
    );

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::ok(WalletResponse {
            id: metadata.group_id,
            label: metadata.label,
            scheme: metadata.scheme.to_string(),
            threshold: metadata.config.threshold,
            total_parties: metadata.config.total_parties,
            created_at: metadata.created_at,
        })),
    ))
}

/// `GET /v1/wallets` — list all wallets.
#[utoipa::path(get, path = "/v1/wallets", tag = "Wallets",
    security(("session_token" = [])),
    responses(
        (status = 200, description = "Wallet list", body = ApiResponse<WalletListResponse>),
        (status = 401, description = "Unauthorized", body = ErrorBody)
    )
)]
pub async fn list_wallets(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<ApiResponse<WalletListResponse>>, ApiError> {
    require_roles(
        &ctx,
        &[
            ApiRole::Viewer,
            ApiRole::Initiator,
            ApiRole::Approver,
            ApiRole::Admin,
        ],
    )?;

    let wallets = state
        .orchestrator
        .list()
        .await
        .into_iter()
        .map(|m| WalletResponse {
            id: m.group_id,
            label: m.label,
            scheme: m.scheme.to_string(),
            threshold: m.config.threshold,
            total_parties: m.config.total_parties,
            created_at: m.created_at,
        })
        .collect();

    Ok(Json(ApiResponse::ok(WalletListResponse { wallets })))
}

/// `GET /v1/wallets/:id` — get wallet details with derived addresses.
#[utoipa::path(get, path = "/v1/wallets/{id}", tag = "Wallets",
    params(("id" = String, Path, description = "Wallet ID")),
    security(("session_token" = [])),
    responses(
        (status = 200, description = "Wallet details", body = ApiResponse<WalletDetailResponse>),
        (status = 403, description = "Refused by the release freeze (non-test network)", body = ErrorBody),
        (status = 404, description = "Wallet not found", body = ErrorBody)
    )
)]
pub async fn get_wallet(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<WalletDetailResponse>>, ApiError> {
    require_roles(
        &ctx,
        &[
            ApiRole::Viewer,
            ApiRole::Initiator,
            ApiRole::Approver,
            ApiRole::Admin,
        ],
    )?;
    // Addresses below are derived for the configured network.
    check_network(&state.network)?;

    let m = state
        .orchestrator
        .get(&wallet_id)
        .await
        .ok_or_else(|| ApiError::not_found(format!("wallet {wallet_id} not found")))?;

    let mut addresses = Vec::new();
    for chain in address_chains(m.scheme) {
        if let Ok(provider) = state.chain_registry.provider(chain) {
            if let Ok(addr) = provider.derive_address(&m.group_public_key) {
                addresses.push(AddressEntry {
                    chain: chain.to_string(),
                    address: addr,
                });
            }
        }
    }

    Ok(Json(ApiResponse::ok(WalletDetailResponse {
        id: m.group_id,
        label: m.label,
        scheme: m.scheme.to_string(),
        threshold: m.config.threshold,
        total_parties: m.config.total_parties,
        created_at: m.created_at,
        addresses,
    })))
}

/// Chains to derive display addresses for, given the wallet's signing scheme.
/// Never a mainnet-only chain (see `check_chain`).
fn address_chains(scheme: CryptoScheme) -> Vec<Chain> {
    match scheme {
        CryptoScheme::Gg20Ecdsa | CryptoScheme::Cggmp21Secp256k1 => {
            vec![Chain::Ethereum, Chain::Polygon, Chain::Bsc, Chain::Arbitrum]
        }
        CryptoScheme::FrostEd25519 => vec![Chain::Solana, Chain::Sui, Chain::Aptos],
        CryptoScheme::FrostSecp256k1Tr => vec![Chain::BitcoinTestnet],
        _ => vec![],
    }
}

/// `POST /v1/wallets/:id/sign` — distributed MPC sign.
#[utoipa::path(post, path = "/v1/wallets/{id}/sign", tag = "Wallets",
    params(("id" = String, Path, description = "Wallet ID")),
    request_body = SignRequest,
    security(("session_token" = [])),
    responses(
        (status = 200, description = "Signature result", body = ApiResponse<SignResponse>),
        (status = 403, description = "Refused by the release freeze", body = ErrorBody),
        (status = 404, description = "Wallet not found", body = ErrorBody)
    )
)]
pub async fn sign_message(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
    Json(req): Json<SignRequest>,
) -> Result<Json<ApiResponse<SignResponse>>, ApiError> {
    require_roles(&ctx, &[ApiRole::Initiator, ApiRole::Admin])?;
    Permissions::check_risk_tier_for_signing(&ctx)
        .map_err(|e| ApiError::forbidden(e.to_string()))?;
    check_network(&state.network)?;
    // The caller supplies an opaque digest with no transaction context.
    refuse_if_frozen("raw-digest signing")?;

    let message_bytes = hex::decode(&req.message).map_err(|e| {
        ApiError::bad_request(ErrorCode::InvalidInput, format!("invalid hex message: {e}"))
    })?;

    state.metrics.sign_total.inc();

    // Build SignAuthorization proof for MPC nodes to independently verify (DEC-012).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let message_hash = hex::encode(Sha256::digest(&message_bytes));
    let policy_hash = hex::encode(Sha256::digest(b""));

    let payload = AuthorizationPayload {
        authorization_id: uuid::Uuid::new_v4().to_string(),
        requester_id: ctx.user_id.clone(),
        wallet_id: wallet_id.clone(),
        message_hash,
        policy_hash,
        policy_passed: true, // TODO: wire real policy engine check
        approval_count: 0,   // TODO: wire approval workflow
        approval_required: 0,
        approvers: vec![],
        timestamp: now,
        session_id: uuid::Uuid::new_v4().to_string(),
        encrypted_context: None,
    };

    let sign_auth = SignAuthorization::create(payload, &state.server_signing_key);
    let sign_auth_json = serde_json::to_string(&sign_auth)
        .map_err(|e| ApiError::internal(format!("failed to serialize sign authorization: {e}")))?;

    let sig = state
        .orchestrator
        .sign(&wallet_id, &message_bytes, &sign_auth_json)
        .await
        .map_err(ApiError::from)?;

    let (sig_json, scheme_name) = match &sig {
        MpcSignature::Ecdsa { r, s, recovery_id } => (
            serde_json::json!({"r": hex::encode(r), "s": hex::encode(s), "recovery_id": recovery_id}),
            "gg20-ecdsa",
        ),
        MpcSignature::EdDsa { signature } => (
            serde_json::json!({"signature": hex::encode(signature)}),
            "frost-ed25519",
        ),
        MpcSignature::Schnorr { signature } => (
            serde_json::json!({"signature": hex::encode(signature)}),
            "frost-secp256k1-tr",
        ),
        _ => (serde_json::json!({"raw": "unsupported"}), "unknown"),
    };

    tracing::info!(wallet_id = %wallet_id, scheme = scheme_name, user = %ctx.user_id, "message signed via distributed MPC");

    Ok(Json(ApiResponse::ok(SignResponse {
        signature: sig_json,
        scheme: scheme_name.to_string(),
    })))
}

/// `POST /v1/wallets/:id/refresh` — proactive key refresh (distributed).
#[utoipa::path(post, path = "/v1/wallets/{id}/refresh", tag = "Wallets",
    params(("id" = String, Path, description = "Wallet ID")),
    security(("session_token" = [])),
    responses(
        (status = 501, description = "Not yet implemented"),
        (status = 403, description = "Admin+MFA required", body = ErrorBody)
    )
)]
pub async fn refresh_wallet(
    State(_state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_admin_mfa(&ctx)?;
    Err(ApiError::new(
        StatusCode::NOT_IMPLEMENTED,
        ErrorCode::InternalError,
        format!("wallet {wallet_id}: key refresh via NATS not yet implemented"),
    ))
}

/// `POST /v1/wallets/:id/freeze` — freeze wallet (gateway + all nodes).
#[utoipa::path(post, path = "/v1/wallets/{id}/freeze", tag = "Wallets",
    params(("id" = String, Path, description = "Wallet ID")),
    security(("session_token" = [])),
    responses(
        (status = 200, description = "Wallet frozen"),
        (status = 403, description = "Admin+MFA required", body = ErrorBody),
        (status = 404, description = "Wallet not found", body = ErrorBody)
    )
)]
pub async fn freeze_wallet(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_admin_mfa(&ctx)?;
    state
        .orchestrator
        .freeze(&wallet_id, true)
        .await
        .map_err(ApiError::from)?;

    tracing::info!(wallet_id = %wallet_id, user = %ctx.user_id, "wallet frozen");
    Ok(Json(ApiResponse::ok(
        serde_json::json!({"wallet_id": wallet_id, "status": "frozen"}),
    )))
}

/// `POST /v1/wallets/:id/unfreeze` — unfreeze wallet (gateway + all nodes).
#[utoipa::path(post, path = "/v1/wallets/{id}/unfreeze", tag = "Wallets",
    params(("id" = String, Path, description = "Wallet ID")),
    security(("session_token" = [])),
    responses(
        (status = 200, description = "Wallet unfrozen"),
        (status = 403, description = "Admin+MFA required", body = ErrorBody),
        (status = 404, description = "Wallet not found", body = ErrorBody)
    )
)]
pub async fn unfreeze_wallet(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_admin_mfa(&ctx)?;
    state
        .orchestrator
        .freeze(&wallet_id, false)
        .await
        .map_err(ApiError::from)?;

    tracing::info!(wallet_id = %wallet_id, user = %ctx.user_id, "wallet unfrozen");
    Ok(Json(ApiResponse::ok(
        serde_json::json!({"wallet_id": wallet_id, "status": "active"}),
    )))
}

/// Release-freeze tests. The network and chain refusals hold in every build, so
/// only the keygen, raw-sign and legacy-scheme tests are skipped under `dev-unfreeze`.
#[cfg(test)]
pub(crate) mod freeze_tests {
    use super::*;

    pub(crate) async fn state_on(network: &str) -> AppState {
        let mut config = crate::config::AppConfig::for_test();
        config.network = network.into();
        AppState::from_config(&config).await
    }

    /// Admin with MFA and Initiator: passes every RBAC check on these routes.
    pub(crate) fn privileged_ctx() -> AuthContext {
        let mut ctx = AuthContext::new("freeze-test", vec![ApiRole::Admin, ApiRole::Initiator]);
        ctx.mfa_verified = true;
        ctx
    }

    pub(crate) fn assert_frozen<T>(result: Result<T, ApiError>, what: &str) {
        let Err(err) = result else {
            panic!("expected a release-freeze refusal of {what}, got Ok");
        };
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert!(matches!(err.code, ErrorCode::PolicyDenied));
        assert!(
            err.message.starts_with("release freeze: ") && err.message.contains(what),
            "expected a release-freeze refusal of {what}, got: {}",
            err.message
        );
    }

    #[cfg(not(feature = "dev-unfreeze"))]
    #[tokio::test]
    async fn freeze_refuses_keygen() {
        let state = state_on("testnet").await;
        let req = CreateWalletRequest {
            label: "freeze".into(),
            scheme: "frost-ed25519".into(),
            threshold: 2,
            total_parties: 3,
        };
        let result = create_wallet(State(state), Extension(privileged_ctx()), Json(req)).await;
        assert_frozen(result, "key generation");
    }

    #[cfg(not(feature = "dev-unfreeze"))]
    #[tokio::test]
    async fn freeze_refuses_raw_sign() {
        let state = state_on("testnet").await;
        let req = SignRequest {
            message: "deadbeef".into(),
        };
        let result = sign_message(
            State(state),
            Extension(privileged_ctx()),
            Path("any-wallet".into()),
            Json(req),
        )
        .await;
        assert_frozen(result, "raw-digest signing");
    }

    #[cfg(not(feature = "dev-unfreeze"))]
    #[test]
    fn freeze_refuses_legacy_schemes() {
        for scheme in [
            CryptoScheme::Gg20Ecdsa,
            CryptoScheme::Cggmp21Secp256k1,
            CryptoScheme::FrostEd25519,
            CryptoScheme::FrostSecp256k1Tr,
            CryptoScheme::Sr25519Threshold,
            CryptoScheme::StarkThreshold,
            CryptoScheme::Bls12_381Threshold,
        ] {
            assert_frozen(check_scheme(scheme), "legacy scheme");
        }
    }

    /// Holds under `dev-unfreeze` too: a mainnet gateway never starts a keygen
    /// or a raw signing round.
    #[tokio::test]
    async fn freeze_refuses_mainnet_network_keygen_and_raw_sign() {
        let state = state_on("mainnet").await;
        let req = CreateWalletRequest {
            label: "freeze".into(),
            scheme: "frost-ed25519".into(),
            threshold: 2,
            total_parties: 3,
        };
        let result =
            create_wallet(State(state.clone()), Extension(privileged_ctx()), Json(req)).await;
        assert_frozen(result, "network 'mainnet'");

        let req = SignRequest {
            message: "deadbeef".into(),
        };
        let result = sign_message(
            State(state),
            Extension(privileged_ctx()),
            Path("any-wallet".into()),
            Json(req),
        )
        .await;
        assert_frozen(result, "network 'mainnet'");
    }

    #[tokio::test]
    async fn freeze_refuses_mainnet_network_wallet_addresses() {
        // Refused before the wallet lookup: a mainnet gateway serves no addresses.
        let state = state_on("mainnet").await;
        let result = get_wallet(
            State(state),
            Extension(privileged_ctx()),
            Path("any-wallet".into()),
        )
        .await;
        assert_frozen(result, "network 'mainnet'");
    }

    #[test]
    fn freeze_refuses_mainnet_chain_addresses() {
        assert_frozen(check_chain(Chain::BitcoinMainnet), "mainnet chain");
        for scheme in [
            CryptoScheme::Gg20Ecdsa,
            CryptoScheme::Cggmp21Secp256k1,
            CryptoScheme::FrostEd25519,
            CryptoScheme::FrostSecp256k1Tr,
        ] {
            let chains = address_chains(scheme);
            assert!(
                !chains.contains(&Chain::BitcoinMainnet),
                "{scheme} must not derive a mainnet-only address: {chains:?}"
            );
        }
        assert_eq!(
            address_chains(CryptoScheme::FrostSecp256k1Tr),
            vec![Chain::BitcoinTestnet]
        );
    }

    #[test]
    fn freeze_refuses_unknown_network_but_allows_test_networks() {
        assert_frozen(check_network(""), "network");
        assert_frozen(check_network("Mainnet"), "network");
        assert!(check_network("testnet").is_ok());
        assert!(check_network("devnet").is_ok());
    }
}
