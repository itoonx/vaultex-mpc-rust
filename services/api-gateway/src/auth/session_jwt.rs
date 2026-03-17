//! Session JWT — request context signed with handshake-derived key.
//!
//! After key exchange, the client uses `client_write_key` (32 bytes) to sign
//! a JWT for each request. The JWT carries:
//! - `session_id` — links to the authenticated session
//! - Request context (IP, device fingerprint, user agent)
//! - Timestamp + expiry (short-lived, per-request)
//!
//! ```text
//! Client (has client_write_key from handshake)
//! ┌───────────────────────────────────┐
//! │ For each API request:             │
//! │ 1. Build JWT claims:              │
//! │    - session_id                   │
//! │    - client_ip, device_fp, ua     │
//! │    - iat, exp (short: 60s)        │
//! │ 2. Sign with HS256(write_key)     │
//! │ 3. Send: X-Session-Token: <jwt>   │
//! └───────────────────────────────────┘
//!          │
//!          ▼
//! Gateway (has client_write_key stored in session)
//! ┌───────────────────────────────────┐
//! │ 1. Decode JWT header (no verify)  │
//! │ 2. Extract session_id from claims │
//! │ 3. Look up session → get write_key│
//! │ 4. Verify JWT sig with write_key  │
//! │ 5. Extract request context        │
//! │ 6. Carry context to handlers      │
//! └───────────────────────────────────┘
//! ```

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::auth::types::unix_now;

/// JWT claims embedded in the session token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionJwtClaims {
    /// Session ID (from handshake).
    pub sid: String,
    /// Client IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Device fingerprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    /// User-Agent.
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

/// Request context extracted and cross-verified from a session JWT.
///
/// Fields marked `verified_*` have been checked against the actual HTTP request.
/// Fields marked `claimed_*` are from the JWT only (not verifiable server-side).
#[derive(Debug, Clone)]
pub struct VerifiedRequestContext {
    /// Session ID.
    pub session_id: String,
    /// Client IP — cross-verified against actual socket/X-Forwarded-For.
    pub client_ip: Option<String>,
    /// Whether the claimed IP matched the actual IP.
    pub ip_verified: bool,
    /// Device fingerprint — claimed by client (not verifiable server-side).
    pub device_fingerprint: Option<String>,
    /// User-Agent — cross-verified against actual User-Agent header.
    pub user_agent: Option<String>,
    /// Whether the claimed UA matched the actual UA.
    pub ua_verified: bool,
    /// Request ID (from JWT claims).
    pub request_id: Option<String>,
    /// Whether any cross-verification failed (IP or UA mismatch).
    pub context_mismatch: bool,
}

/// Actual request metadata extracted from the HTTP connection.
#[derive(Debug, Clone)]
pub struct ActualRequestMeta {
    /// Real client IP from socket or X-Forwarded-For.
    pub real_ip: Option<String>,
    /// Real User-Agent from HTTP header.
    pub real_user_agent: Option<String>,
}

/// Cross-verify JWT claims against actual HTTP request metadata.
///
/// If the client claims a different IP or User-Agent than what the server sees,
/// the request is flagged (and optionally rejected depending on policy).
pub fn cross_verify_context(
    claims_ip: Option<&str>,
    claims_ua: Option<&str>,
    actual: &ActualRequestMeta,
) -> (bool, bool, bool) {
    let ip_match = match (claims_ip, &actual.real_ip) {
        (Some(claimed), Some(real)) => claimed == real,
        (None, _) => true,       // no claim = no check
        (Some(_), None) => true, // no real IP available (e.g., test)
    };

    let ua_match = match (claims_ua, &actual.real_user_agent) {
        (Some(claimed), Some(real)) => claimed == real,
        (None, _) => true,
        (Some(_), None) => true,
    };

    let any_mismatch = !ip_match || !ua_match;
    (ip_match, ua_match, any_mismatch)
}

/// Maximum age of a session JWT (seconds). Short-lived per-request token.
const MAX_JWT_AGE_SECS: u64 = 120; // 2 minutes

/// Create a session JWT (client-side).
///
/// The client calls this for each request, signing with the `client_write_key`
/// derived from the handshake.
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
        &Header::default(), // HS256
        &claims,
        &EncodingKey::from_secret(client_write_key),
    )
    .map_err(|e| format!("session JWT encode: {e}"))
}

/// Verify a session JWT (gateway-side) and cross-check against actual request.
///
/// 1. Decode JWT WITHOUT verification to extract `sid` (session_id)
/// 2. Look up the session to get `client_write_key`
/// 3. Verify the JWT signature with that key
/// 4. Cross-verify claimed IP/UA against actual HTTP metadata
/// 5. Return the verified + cross-checked context
///
/// If `reject_on_mismatch` is true, returns Err on IP/UA mismatch.
/// Otherwise, flags the mismatch in `context_mismatch` for logging/monitoring.
pub fn verify_session_jwt(
    token: &str,
    key_lookup: impl FnOnce(&str) -> Option<[u8; 32]>,
    actual: &ActualRequestMeta,
    reject_on_mismatch: bool,
) -> Result<(String, VerifiedRequestContext), String> {
    // Step 1: Decode WITHOUT verification to get session_id.
    let mut no_verify = Validation::default();
    no_verify.insecure_disable_signature_validation();
    no_verify.validate_exp = false;
    no_verify.required_spec_claims.clear();

    let unverified = decode::<SessionJwtClaims>(
        token,
        &DecodingKey::from_secret(&[]), // dummy key — sig not checked
        &no_verify,
    )
    .map_err(|e| format!("session JWT decode: {e}"))?;

    let session_id = &unverified.claims.sid;

    // Step 2: Look up session key.
    let write_key = key_lookup(session_id)
        .ok_or_else(|| "session JWT: session not found or expired".to_string())?;

    // Step 3: Verify signature with the session's write key.
    let mut validation = Validation::default();
    validation.required_spec_claims.clear();

    let verified =
        decode::<SessionJwtClaims>(token, &DecodingKey::from_secret(&write_key), &validation)
            .map_err(|e| format!("session JWT verify: {e}"))?;

    let claims = verified.claims;

    // Step 4: Check freshness.
    let now = unix_now();
    if now.abs_diff(claims.iat) > MAX_JWT_AGE_SECS {
        return Err("session JWT: token too old".into());
    }

    // Step 5: Cross-verify claimed context against actual HTTP request.
    let (ip_ok, ua_ok, any_mismatch) =
        cross_verify_context(claims.ip.as_deref(), claims.ua.as_deref(), actual);

    if any_mismatch && reject_on_mismatch {
        return Err(format!(
            "session JWT: context mismatch (ip_match={ip_ok}, ua_match={ua_ok}) — possible spoofing"
        ));
    }

    Ok((
        claims.sid.clone(),
        VerifiedRequestContext {
            session_id: claims.sid,
            client_ip: claims.ip,
            ip_verified: ip_ok,
            device_fingerprint: claims.fp,
            user_agent: claims.ua,
            ua_verified: ua_ok,
            request_id: claims.rid,
            context_mismatch: any_mismatch,
        },
    ))
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

    fn no_actual() -> ActualRequestMeta {
        ActualRequestMeta {
            real_ip: None,
            real_user_agent: None,
        }
    }

    fn actual_matching() -> ActualRequestMeta {
        ActualRequestMeta {
            real_ip: Some("203.0.113.42".into()),
            real_user_agent: Some("SDK/1.0".into()),
        }
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

        let (sid, ctx) = verify_session_jwt(
            &jwt,
            |sid| {
                assert_eq!(sid, "sess_123");
                Some(key)
            },
            &actual_matching(),
            false,
        )
        .unwrap();

        assert_eq!(sid, "sess_123");
        assert_eq!(ctx.client_ip.as_deref(), Some("203.0.113.42"));
        assert_eq!(ctx.device_fingerprint.as_deref(), Some("fp_abc"));
        assert!(ctx.ip_verified);
        assert!(ctx.ua_verified);
        assert!(!ctx.context_mismatch);
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key = test_key();
        let wrong_key = [0xFF; 32];
        let jwt = create_session_jwt("sess_123", &key, None, None, None, None).unwrap();

        let result = verify_session_jwt(&jwt, |_| Some(wrong_key), &no_actual(), false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("verify"));
    }

    #[test]
    fn test_session_not_found_rejected() {
        let key = test_key();
        let jwt = create_session_jwt("sess_missing", &key, None, None, None, None).unwrap();

        let result = verify_session_jwt(&jwt, |_| None, &no_actual(), false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_tampered_claims_rejected() {
        let key = test_key();
        let jwt = create_session_jwt("sess_123", &key, Some("1.2.3.4"), None, None, None).unwrap();

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
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

        let result = verify_session_jwt(&tampered, |_| Some(key), &no_actual(), false);
        assert!(result.is_err(), "tampered JWT must be rejected");
    }

    #[test]
    fn test_ip_mismatch_detected() {
        let key = test_key();
        let jwt = create_session_jwt(
            "sess_123",
            &key,
            Some("203.0.113.42"), // client claims this IP
            None,
            None,
            None,
        )
        .unwrap();

        // Gateway sees a different IP.
        let actual = ActualRequestMeta {
            real_ip: Some("10.0.0.1".into()), // actual IP is different
            real_user_agent: None,
        };

        // With reject_on_mismatch=false: succeeds but flags mismatch.
        let (_, ctx) = verify_session_jwt(&jwt, |_| Some(key), &actual, false).unwrap();
        assert!(!ctx.ip_verified, "IP should NOT be verified");
        assert!(ctx.context_mismatch, "should flag context mismatch");

        // With reject_on_mismatch=true: rejected.
        let jwt2 =
            create_session_jwt("sess_123", &key, Some("203.0.113.42"), None, None, None).unwrap();
        let result = verify_session_jwt(&jwt2, |_| Some(key), &actual, true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("mismatch"));
    }

    #[test]
    fn test_ua_mismatch_detected() {
        let key = test_key();
        let jwt = create_session_jwt(
            "sess_123",
            &key,
            None,
            None,
            Some("SDK/1.0"), // client claims this UA
            None,
        )
        .unwrap();

        let actual = ActualRequestMeta {
            real_ip: None,
            real_user_agent: Some("curl/7.88".into()), // actual UA is different
        };

        let (_, ctx) = verify_session_jwt(&jwt, |_| Some(key), &actual, false).unwrap();
        assert!(!ctx.ua_verified, "UA should NOT be verified");
        assert!(ctx.context_mismatch);
    }

    #[test]
    fn test_matching_context_verified() {
        let key = test_key();
        let jwt = create_session_jwt(
            "sess_123",
            &key,
            Some("203.0.113.42"),
            Some("fp_abc"),
            Some("SDK/1.0"),
            None,
        )
        .unwrap();

        let actual = ActualRequestMeta {
            real_ip: Some("203.0.113.42".into()),
            real_user_agent: Some("SDK/1.0".into()),
        };

        let (_, ctx) = verify_session_jwt(&jwt, |_| Some(key), &actual, true).unwrap();
        assert!(ctx.ip_verified);
        assert!(ctx.ua_verified);
        assert!(!ctx.context_mismatch);
    }

    #[test]
    fn test_minimal_claims_no_mismatch() {
        let key = test_key();
        let jwt = create_session_jwt("sess_min", &key, None, None, None, None).unwrap();

        let (sid, ctx) = verify_session_jwt(&jwt, |_| Some(key), &no_actual(), true).unwrap();
        assert_eq!(sid, "sess_min");
        assert!(!ctx.context_mismatch, "no claims = no mismatch");
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
