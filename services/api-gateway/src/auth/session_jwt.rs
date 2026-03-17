//! Session JWT — request context signed with handshake-derived key.
//!
//! After key exchange, the client uses `client_write_key` (32 bytes) to sign
//! a JWT for each request. The JWT carries:
//! - `session_id` — links to the authenticated session
//! - Request context (IP, device fingerprint, user agent) — self-reported by client
//! - Timestamp + expiry (short-lived, per-request)
//!
//! **Gateway verifies only the HS256 signature** — proving the JWT was signed by
//! the holder of the correct `client_write_key` from the key exchange.
//! Payload claims are trusted as client-reported metadata for audit/tracing.

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::auth::types::unix_now;

/// JWT claims embedded in the session token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionJwtClaims {
    /// Session ID (from handshake).
    pub sid: String,
    /// Client IP address (self-reported).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Device fingerprint (self-reported).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    /// User-Agent (self-reported).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ua: Option<String>,
    /// Request ID (unique per request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rid: Option<String>,
    /// Issued at (UNIX seconds).
    pub iat: u64,
    /// Expires at (UNIX seconds).
    pub exp: u64,
}

/// Request context extracted from a verified session JWT.
#[derive(Debug, Clone)]
pub struct VerifiedRequestContext {
    /// Session ID.
    pub session_id: String,
    /// Client IP (self-reported by client).
    pub client_ip: Option<String>,
    /// Device fingerprint (self-reported by client).
    pub device_fingerprint: Option<String>,
    /// User-Agent (self-reported by client).
    pub user_agent: Option<String>,
    /// Request ID.
    pub request_id: Option<String>,
}

/// Maximum age of a session JWT (seconds).
const MAX_JWT_AGE_SECS: u64 = 120;

/// Create a session JWT (client-side).
pub fn create_session_jwt(
    session_id: &str,
    client_write_key: &[u8; 32],
    client_ip: Option<&str>,
    device_fingerprint: Option<&str>,
    user_agent: Option<&str>,
    request_id: Option<&str>,
) -> Result<String, String> {
    let now = unix_now();
    let claims = SessionJwtClaims {
        sid: session_id.to_string(),
        ip: client_ip.map(String::from),
        fp: device_fingerprint.map(String::from),
        ua: user_agent.map(String::from),
        rid: request_id.map(String::from),
        iat: now,
        exp: now + MAX_JWT_AGE_SECS,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(client_write_key),
    )
    .map_err(|e| format!("session JWT encode: {e}"))
}

/// Extract session_id from a JWT WITHOUT verifying the signature.
/// This is the first step — caller uses the session_id to look up the key,
/// then calls `verify_session_jwt_with_key()` with the actual key.
pub fn extract_session_id(token: &str) -> Result<String, String> {
    let mut no_verify = Validation::default();
    no_verify.insecure_disable_signature_validation();
    no_verify.validate_exp = false;
    no_verify.required_spec_claims.clear();

    let unverified = decode::<SessionJwtClaims>(token, &DecodingKey::from_secret(&[]), &no_verify)
        .map_err(|e| format!("session JWT decode: {e}"))?;

    Ok(unverified.claims.sid)
}

/// Verify a session JWT with a known key (gateway-side, step 2).
/// Called AFTER the caller has looked up the session and obtained the `client_write_key`.
pub fn verify_session_jwt_with_key(
    token: &str,
    client_write_key: &[u8; 32],
) -> Result<VerifiedRequestContext, String> {
    let mut validation = Validation::default();
    validation.required_spec_claims.clear();

    let verified = decode::<SessionJwtClaims>(
        token,
        &DecodingKey::from_secret(client_write_key),
        &validation,
    )
    .map_err(|e| format!("session JWT verify: {e}"))?;

    let claims = verified.claims;

    let now = unix_now();
    if now.abs_diff(claims.iat) > MAX_JWT_AGE_SECS {
        return Err("session JWT: token too old".into());
    }

    Ok(VerifiedRequestContext {
        session_id: claims.sid,
        client_ip: claims.ip,
        device_fingerprint: claims.fp,
        user_agent: claims.ua,
        request_id: claims.rid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = 42;
        key[31] = 99;
        key
    }

    #[test]
    fn test_create_and_verify_roundtrip() {
        let key = test_key();
        let jwt = create_session_jwt(
            "sess_123",
            &key,
            Some("203.0.113.42"),
            Some("fp_abc"),
            Some("SDK/1.0"),
            Some("req_xyz"),
        )
        .unwrap();

        let sid = extract_session_id(&jwt).unwrap();
        assert_eq!(sid, "sess_123");

        let ctx = verify_session_jwt_with_key(&jwt, &key).unwrap();
        assert_eq!(ctx.session_id, "sess_123");
        assert_eq!(ctx.client_ip.as_deref(), Some("203.0.113.42"));
        assert_eq!(ctx.device_fingerprint.as_deref(), Some("fp_abc"));
        assert_eq!(ctx.user_agent.as_deref(), Some("SDK/1.0"));
        assert_eq!(ctx.request_id.as_deref(), Some("req_xyz"));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key = test_key();
        let wrong_key = [0xFF; 32];
        let jwt = create_session_jwt("sess_123", &key, None, None, None, None).unwrap();

        // extract_session_id works (no sig check).
        assert!(extract_session_id(&jwt).is_ok());
        // But verify with wrong key fails.
        assert!(verify_session_jwt_with_key(&jwt, &wrong_key).is_err());
    }

    #[test]
    fn test_tampered_claims_rejected() {
        let key = test_key();
        let jwt = create_session_jwt("sess_123", &key, Some("1.2.3.4"), None, None, None).unwrap();

        let parts: Vec<&str> = jwt.split('.').collect();
        let mut payload_bytes = base64_url_decode(parts[1]);
        if !payload_bytes.is_empty() {
            payload_bytes[0] ^= 0xFF;
        }
        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            base64_url_encode(&payload_bytes),
            parts[2]
        );

        assert!(verify_session_jwt_with_key(&tampered, &key).is_err());
    }

    #[test]
    fn test_minimal_claims() {
        let key = test_key();
        let jwt = create_session_jwt("sess_min", &key, None, None, None, None).unwrap();

        let ctx = verify_session_jwt_with_key(&jwt, &key).unwrap();
        assert_eq!(ctx.session_id, "sess_min");
        assert!(ctx.client_ip.is_none());
    }

    fn base64_url_decode(s: &str) -> Vec<u8> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        URL_SAFE_NO_PAD.decode(s).unwrap_or_default()
    }

    fn base64_url_encode(data: &[u8]) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        URL_SAFE_NO_PAD.encode(data)
    }
}
