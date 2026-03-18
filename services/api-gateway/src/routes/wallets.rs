//! Wallet management endpoints: create, list, get, sign, freeze, unfreeze, refresh.
//!
//! Every handler extracts `AuthContext` from request extensions and enforces
//! RBAC permissions before processing the request.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};

use mpc_wallet_core::protocol::MpcSignature;
use mpc_wallet_core::rbac::{ApiRole, AuthContext, Permissions};

use crate::errors::{ApiError, ErrorCode};
use crate::models::request::{CreateWalletRequest, SignRequest};
use crate::models::response::{
    AddressEntry, ApiResponse, SignResponse, WalletDetailResponse, WalletListResponse,
    WalletResponse,
};
use crate::state::AppState;

/// Helper: extract AuthContext and check required roles.
fn require_roles(ctx: &AuthContext, roles: &[ApiRole]) -> Result<(), ApiError> {
    Permissions::require_role(ctx, roles).map_err(|e| {
        tracing::warn!(
            user_id = %ctx.user_id,
            required = ?roles,
            actual = ?ctx.roles,
            "RBAC denied: {e}"
        );
        ApiError::forbidden("insufficient permissions")
    })
}

/// Helper: require Admin + MFA.
fn require_admin_mfa(ctx: &AuthContext) -> Result<(), ApiError> {
    Permissions::can_freeze_key_mfa(ctx).map_err(|e| {
        tracing::warn!(
            user_id = %ctx.user_id,
            mfa = ctx.mfa_verified,
            "RBAC denied (admin+MFA): {e}"
        );
        ApiError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::MfaRequired,
            "insufficient permissions",
        )
    })
}

/// `POST /v1/wallets` — create a new MPC wallet (keygen).
/// Requires: Admin + MFA
pub async fn create_wallet(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(req): Json<CreateWalletRequest>,
) -> Result<(StatusCode, Json<ApiResponse<WalletResponse>>), ApiError> {
    require_admin_mfa(&ctx)?;

    // Validate scheme.
    let scheme: mpc_wallet_core::types::CryptoScheme = req
        .scheme
        .parse()
        .map_err(|e: String| ApiError::bad_request(ErrorCode::InvalidInput, e))?;

    // Validate threshold config.
    mpc_wallet_core::types::ThresholdConfig::new(req.threshold, req.total_parties)
        .map_err(|e| ApiError::bad_request(ErrorCode::InvalidConfig, e.to_string()))?;

    state.metrics.keygen_total.inc();

    let group_id = uuid::Uuid::new_v4().to_string();

    // Run MPC keygen via LocalTransport.
    let record = state
        .wallet_store
        .create(
            group_id,
            req.label,
            scheme,
            req.threshold,
            req.total_parties,
        )
        .await
        .map_err(ApiError::from)?;

    tracing::info!(
        group_id = %record.group_id,
        scheme = ?record.scheme,
        threshold = record.config.threshold,
        total = record.config.total_parties,
        "wallet created via MPC keygen"
    );

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::ok(WalletResponse {
            id: record.group_id,
            label: record.label,
            scheme: format!("{:?}", record.scheme),
            threshold: record.config.threshold,
            total_parties: record.config.total_parties,
            created_at: record.created_at,
        })),
    ))
}

/// `GET /v1/wallets` — list all wallets.
/// Requires: Viewer+
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

    let records = state.wallet_store.list().await;
    let wallets = records
        .into_iter()
        .map(|r| WalletResponse {
            id: r.group_id,
            label: r.label,
            scheme: format!("{:?}", r.scheme),
            threshold: r.config.threshold,
            total_parties: r.config.total_parties,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(ApiResponse::ok(WalletListResponse { wallets })))
}

/// `GET /v1/wallets/:id` — get wallet details.
/// Requires: Viewer+
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

    let record = state
        .wallet_store
        .get(&wallet_id)
        .await
        .ok_or_else(|| ApiError::not_found(format!("wallet {wallet_id} not found")))?;

    // Derive addresses for common chains.
    let mut addresses = Vec::new();
    let chains_to_derive = match record.scheme {
        mpc_wallet_core::types::CryptoScheme::Gg20Ecdsa => {
            vec!["ethereum", "polygon", "bsc", "arbitrum"]
        }
        mpc_wallet_core::types::CryptoScheme::FrostEd25519 => {
            vec!["solana", "sui", "aptos"]
        }
        mpc_wallet_core::types::CryptoScheme::FrostSecp256k1Tr => {
            vec!["bitcoin-testnet", "bitcoin-mainnet"]
        }
        _ => vec![],
    };

    for chain_name in chains_to_derive {
        if let Ok(chain) = chain_name.parse::<mpc_wallet_chains::provider::Chain>() {
            if let Ok(provider) = state.chain_registry.provider(chain) {
                if let Ok(addr) = provider.derive_address(&record.group_public_key) {
                    addresses.push(AddressEntry {
                        chain: chain_name.to_string(),
                        address: addr,
                    });
                }
            }
        }
    }

    Ok(Json(ApiResponse::ok(WalletDetailResponse {
        id: record.group_id,
        label: record.label,
        scheme: format!("{:?}", record.scheme),
        threshold: record.config.threshold,
        total_parties: record.config.total_parties,
        created_at: record.created_at,
        addresses,
    })))
}

/// `POST /v1/wallets/:id/sign` — sign a message.
/// Requires: Initiator or Admin + risk tier check
pub async fn sign_message(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
    Json(req): Json<SignRequest>,
) -> Result<Json<ApiResponse<SignResponse>>, ApiError> {
    require_roles(&ctx, &[ApiRole::Initiator, ApiRole::Admin])?;
    Permissions::check_risk_tier_for_signing(&ctx)
        .map_err(|e| ApiError::forbidden(e.to_string()))?;

    let message_bytes = hex::decode(&req.message).map_err(|e| {
        ApiError::bad_request(ErrorCode::InvalidInput, format!("invalid hex message: {e}"))
    })?;

    state.metrics.sign_total.inc();

    // Sign via MPC protocol.
    let sig = state
        .wallet_store
        .sign(&wallet_id, &message_bytes)
        .await
        .map_err(ApiError::from)?;

    let (sig_json, scheme_name) = match &sig {
        MpcSignature::Ecdsa { r, s, recovery_id } => (
            serde_json::json!({
                "r": hex::encode(r),
                "s": hex::encode(s),
                "recovery_id": recovery_id,
            }),
            "gg20-ecdsa",
        ),
        MpcSignature::EdDsa { signature } => (
            serde_json::json!({
                "signature": hex::encode(signature),
            }),
            "frost-ed25519",
        ),
        MpcSignature::Schnorr { signature } => (
            serde_json::json!({
                "signature": hex::encode(signature),
            }),
            "frost-secp256k1-tr",
        ),
        _ => (serde_json::json!({"raw": "unsupported"}), "unknown"),
    };

    tracing::info!(
        wallet_id = %wallet_id,
        scheme = scheme_name,
        user = %ctx.user_id,
        "message signed via MPC"
    );

    Ok(Json(ApiResponse::ok(SignResponse {
        signature: sig_json,
        scheme: scheme_name.to_string(),
    })))
}

/// `POST /v1/wallets/:id/refresh` — proactive key refresh.
/// Requires: Admin + MFA
pub async fn refresh_wallet(
    State(_state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_admin_mfa(&ctx)?;
    // Key refresh requires NATS transport to coordinate with remote parties.
    // For single-gateway demo, this is a placeholder.
    Err(ApiError::new(
        StatusCode::NOT_IMPLEMENTED,
        ErrorCode::InternalError,
        format!("wallet {wallet_id}: key refresh requires distributed MPC transport (NATS)"),
    ))
}

/// `POST /v1/wallets/:id/freeze` — freeze wallet.
/// Requires: Admin + MFA
pub async fn freeze_wallet(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_admin_mfa(&ctx)?;
    state
        .wallet_store
        .freeze(&wallet_id)
        .await
        .map_err(ApiError::from)?;

    tracing::info!(wallet_id = %wallet_id, user = %ctx.user_id, "wallet frozen");

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "wallet_id": wallet_id,
        "status": "frozen"
    }))))
}

/// `POST /v1/wallets/:id/unfreeze` — unfreeze wallet.
/// Requires: Admin + MFA
pub async fn unfreeze_wallet(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(wallet_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    require_admin_mfa(&ctx)?;
    state
        .wallet_store
        .unfreeze(&wallet_id)
        .await
        .map_err(ApiError::from)?;

    tracing::info!(wallet_id = %wallet_id, user = %ctx.user_id, "wallet unfrozen");

    Ok(Json(ApiResponse::ok(serde_json::json!({
        "wallet_id": wallet_id,
        "status": "active"
    }))))
}
