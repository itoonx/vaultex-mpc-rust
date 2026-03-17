//! Authentication middleware: session JWT, API key, and external JWT validation.
//!
//! Priority order: X-Session-Token (JWT) → X-API-Key → Authorization: Bearer.
//! If a header is PRESENT but invalid, auth fails immediately — no fall-through.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};

use mpc_wallet_core::rbac::{AbacAttributes, ApiRole, AuthContext};

use crate::auth::session_jwt::{verify_session_jwt, ActualRequestMeta};
use crate::auth::types::auth_failed;
use crate::state::AppState;

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();

    // Path 1: X-Session-Token (JWT signed with handshake-derived key).
    // Contains session_id + request context (IP, device, fingerprint).
    if headers.contains_key("x-session-token") {
        let token = headers
            .get("x-session-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if token.is_empty() {
            state.metrics.auth_failures.inc();
            tracing::warn!("session token auth failed: empty or non-UTF8 header");
            return auth_failed().into_response();
        }

        // Check if token looks like a JWT (has dots) or is a legacy opaque session_id.
        if token.contains('.') {
            // Extract actual request metadata for cross-verification.
            let real_ip = headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
                .or_else(|| {
                    headers
                        .get("x-real-ip")
                        .and_then(|v| v.to_str().ok())
                        .map(String::from)
                });
            let real_user_agent = headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            let actual_meta = ActualRequestMeta {
                real_ip,
                real_user_agent,
            };

            // JWT path: verify signature + cross-check context.
            let session_store = state.session_store.clone();
            let result = verify_session_jwt(
                token,
                |sid| {
                    let rt = tokio::runtime::Handle::current();
                    rt.block_on(async { session_store.get(sid).await.map(|s| s.client_write_key) })
                },
                &actual_meta,
                false, // log mismatch but don't reject (configurable per deployment)
            );

            match result {
                Ok((session_id, req_ctx)) => {
                    // Warn on context mismatch (possible spoofing).
                    if req_ctx.context_mismatch {
                        tracing::warn!(
                            session_id = %session_id,
                            claimed_ip = ?req_ctx.client_ip,
                            actual_ip = ?actual_meta.real_ip,
                            ip_verified = req_ctx.ip_verified,
                            claimed_ua = ?req_ctx.user_agent,
                            actual_ua = ?actual_meta.real_user_agent,
                            ua_verified = req_ctx.ua_verified,
                            "session JWT context mismatch — possible spoofing"
                        );
                    }

                    // Look up full session for role assignment.
                    match state.session_store.get(&session_id).await {
                        Some(session) => {
                            tracing::debug!(
                                session_id = %session.session_id,
                                client_key_id = %session.client_key_id,
                                client_ip = ?req_ctx.client_ip,
                                ip_verified = req_ctx.ip_verified,
                                device_fp = ?req_ctx.device_fingerprint,
                                "session JWT auth success"
                            );
                            let role = state
                                .client_registry
                                .keys
                                .get(&session.client_key_id)
                                .map(|e| e.api_role())
                                .unwrap_or(ApiRole::Viewer);
                            let ctx = AuthContext::with_attributes(
                                format!("session:{}", session.client_key_id),
                                vec![role],
                                AbacAttributes::default(),
                                false,
                            );
                            request.extensions_mut().insert(ctx);
                            request.extensions_mut().insert(req_ctx);
                            return next.run(request).await;
                        }
                        None => {
                            state.metrics.auth_failures.inc();
                            tracing::warn!(
                                "session JWT: session expired between verify and lookup"
                            );
                            return auth_failed().into_response();
                        }
                    }
                }
                Err(e) => {
                    state.metrics.auth_failures.inc();
                    tracing::warn!("session JWT auth failed: {e}");
                    return auth_failed().into_response();
                }
            }
        } else {
            // Legacy opaque session_id (backward compatible).
            match state.session_store.get(token).await {
                Some(session) => {
                    tracing::debug!(
                        session_id = %session.session_id,
                        client_key_id = %session.client_key_id,
                        "session token auth success (legacy opaque)"
                    );
                    let role = state
                        .client_registry
                        .keys
                        .get(&session.client_key_id)
                        .map(|e| e.api_role())
                        .unwrap_or(ApiRole::Viewer);
                    let ctx = AuthContext::with_attributes(
                        format!("session:{}", session.client_key_id),
                        vec![role],
                        AbacAttributes::default(),
                        false,
                    );
                    request.extensions_mut().insert(ctx);
                    return next.run(request).await;
                }
                None => {
                    state.metrics.auth_failures.inc();
                    tracing::warn!("session token auth failed: invalid or expired");
                    return auth_failed().into_response();
                }
            }
        }
    }

    // Path 2: X-API-Key (service-to-service or user-created).
    if let Some(api_key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        match state.api_key_store.verify(api_key).await {
            Some(meta) => {
                tracing::debug!(
                    key_label = %meta.label,
                    key_id = %meta.key_id,
                    role = ?meta.role,
                    origin = ?meta.origin,
                    "API key auth success"
                );
                let ctx = meta.auth_context();
                request.extensions_mut().insert(ctx);
                return next.run(request).await;
            }
            None => {
                state.metrics.auth_failures.inc();
                tracing::warn!(
                    key_prefix = &api_key[..api_key.len().min(8)],
                    "API key auth failed"
                );
                return auth_failed().into_response();
            }
        }
    }

    // Path 3: Authorization: Bearer <jwt>.
    if let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            match state.jwt_validator.validate(token) {
                Ok(ctx) => {
                    tracing::debug!(user_id = %ctx.user_id, "JWT auth success");
                    request.extensions_mut().insert(ctx);
                    return next.run(request).await;
                }
                Err(e) => {
                    state.metrics.auth_failures.inc();
                    tracing::warn!("JWT auth failed: {e}");
                    return auth_failed().into_response();
                }
            }
        }
    }

    state.metrics.auth_failures.inc();
    auth_failed().into_response()
}
