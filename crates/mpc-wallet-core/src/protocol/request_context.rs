//! Request context — encrypted metadata for sign request tracing.
//!
//! Captures device/network information at the point of request and encrypts it
//! using ChaCha20-Poly1305 with the session's derived key. This provides:
//!
//! 1. **Integrity** — context cannot be tampered with (AEAD authentication)
//! 2. **Confidentiality** — IP/device info encrypted in transit and at rest
//! 3. **Binding** — context is tied to the session key (key-exchange derived)
//! 4. **Traceability** — MPC nodes can store encrypted context for audit without decrypting
//!
//! ```text
//! Client Device                        Gateway                         MPC Node
//! ┌──────────────┐   encrypted    ┌──────────────────┐   encrypted   ┌────────────┐
//! │ IP, UA, FP   │──────────────►│ decrypt + verify  │─────────────►│ store blob │
//! │ in JWT/header│  (session key) │ re-encrypt for    │ (audit key)  │ for audit  │
//! └──────────────┘                │ audit trail       │              └────────────┘
//! ```

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CoreError;

/// Plaintext request context — captured at the gateway from the HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    /// Client IP address (from X-Forwarded-For or socket addr).
    pub client_ip: String,
    /// User-Agent header.
    pub user_agent: String,
    /// Device fingerprint (from client SDK — browser/device hash).
    pub device_fingerprint: String,
    /// Request ID (unique per request, for correlation).
    pub request_id: String,
    /// ISO 8601 timestamp when the request was received.
    pub requested_at: String,
    /// Geographic location hint (from IP geolocation, optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_hint: Option<String>,
    /// Additional metadata (extensible).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// Encrypted request context — AEAD-encrypted with ChaCha20-Poly1305.
///
/// The encryption key can be:
/// - **Session key** (`client_write_key` from handshake) — for client→gateway transmission
/// - **Audit key** (service-level key) — for at-rest storage in audit logs
///
/// The nonce is unique per encryption and included in the struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedRequestContext {
    /// 12-byte nonce (hex-encoded).
    pub nonce: String,
    /// AEAD ciphertext + 16-byte authentication tag (hex-encoded).
    pub ciphertext: String,
    /// SHA-256 of the plaintext context (hex) — for integrity verification without decryption.
    pub context_hash: String,
}

impl EncryptedRequestContext {
    /// Encrypt a `RequestContext` using ChaCha20-Poly1305.
    ///
    /// `key` must be exactly 32 bytes (e.g., session's `client_write_key`).
    pub fn encrypt(context: &RequestContext, key: &[u8; 32]) -> Result<Self, CoreError> {
        let plaintext = serde_json::to_vec(context)
            .map_err(|e| CoreError::Protocol(format!("request context serialization: {e}")))?;

        let context_hash = hex::encode(Sha256::digest(&plaintext));

        // Generate a random 12-byte nonce.
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| CoreError::Protocol(format!("AEAD key init: {e}")))?;
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_slice())
            .map_err(|e| CoreError::Protocol(format!("AEAD encrypt: {e}")))?;

        Ok(Self {
            nonce: hex::encode(nonce_bytes),
            ciphertext: hex::encode(ciphertext),
            context_hash,
        })
    }

    /// Decrypt back to `RequestContext` using the same key.
    pub fn decrypt(&self, key: &[u8; 32]) -> Result<RequestContext, CoreError> {
        let nonce_bytes = hex::decode(&self.nonce)
            .map_err(|_| CoreError::Protocol("request context: invalid nonce hex".into()))?;
        if nonce_bytes.len() != 12 {
            return Err(CoreError::Protocol(
                "request context: nonce must be 12 bytes".into(),
            ));
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = hex::decode(&self.ciphertext)
            .map_err(|_| CoreError::Protocol("request context: invalid ciphertext hex".into()))?;

        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| CoreError::Protocol(format!("AEAD key init: {e}")))?;
        let plaintext = cipher.decrypt(nonce, ciphertext.as_slice()).map_err(|_| {
            CoreError::Protocol(
                "request context: AEAD decryption failed (tampered or wrong key)".into(),
            )
        })?;

        // Verify content hash.
        let actual_hash = hex::encode(Sha256::digest(&plaintext));
        if actual_hash != self.context_hash {
            return Err(CoreError::Protocol(
                "request context: content hash mismatch after decryption".into(),
            ));
        }

        serde_json::from_slice(&plaintext)
            .map_err(|e| CoreError::Protocol(format!("request context deserialization: {e}")))
    }
}

/// Audit record for a sign operation — includes encrypted context for tracing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignAuditRecord {
    /// Session ID for correlation.
    pub session_id: String,
    /// Wallet being signed.
    pub wallet_id: String,
    /// SHA-256 of the message that was signed (hex).
    pub message_hash: String,
    /// Who requested the sign (from AuthContext).
    pub requester_id: String,
    /// Encrypted request context (IP, device, fingerprint).
    pub encrypted_context: EncryptedRequestContext,
    /// Number of approvals collected.
    pub approval_count: u32,
    /// Policy hash that was evaluated.
    pub policy_hash: String,
    /// UNIX timestamp of the sign operation.
    pub signed_at: u64,
    /// MPC signing scheme used.
    pub scheme: String,
    /// Parties that participated in signing.
    pub signers: Vec<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> RequestContext {
        RequestContext {
            client_ip: "203.0.113.42".into(),
            user_agent: "MPC-SDK/1.0 (Linux x86_64)".into(),
            device_fingerprint: "fp_a1b2c3d4e5f6".into(),
            request_id: "req_7f3a9c2b".into(),
            requested_at: "2026-03-17T12:00:00Z".into(),
            geo_hint: Some("TH-Bangkok".into()),
            extra: None,
        }
    }

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = 42;
        key[31] = 99;
        key
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let ctx = test_context();
        let key = test_key();

        let encrypted = EncryptedRequestContext::encrypt(&ctx, &key).unwrap();

        // Ciphertext should not contain plaintext.
        assert!(!encrypted.ciphertext.contains("203.0.113.42"));

        let decrypted = encrypted.decrypt(&key).unwrap();
        assert_eq!(decrypted.client_ip, "203.0.113.42");
        assert_eq!(decrypted.device_fingerprint, "fp_a1b2c3d4e5f6");
        assert_eq!(decrypted.request_id, "req_7f3a9c2b");
        assert_eq!(decrypted.geo_hint, Some("TH-Bangkok".into()));
    }

    #[test]
    fn test_wrong_key_fails() {
        let ctx = test_context();
        let key = test_key();
        let wrong_key = [0xFFu8; 32];

        let encrypted = EncryptedRequestContext::encrypt(&ctx, &key).unwrap();
        let result = encrypted.decrypt(&wrong_key);
        assert!(result.is_err());
        assert!(format!("{result:?}").contains("AEAD decryption failed"));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let ctx = test_context();
        let key = test_key();

        let mut encrypted = EncryptedRequestContext::encrypt(&ctx, &key).unwrap();
        // Flip a byte in the ciphertext.
        let mut bytes = hex::decode(&encrypted.ciphertext).unwrap();
        bytes[0] ^= 0xFF;
        encrypted.ciphertext = hex::encode(bytes);

        let result = encrypted.decrypt(&key);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let ctx = test_context();
        let key = test_key();

        let enc1 = EncryptedRequestContext::encrypt(&ctx, &key).unwrap();
        let enc2 = EncryptedRequestContext::encrypt(&ctx, &key).unwrap();

        // Same plaintext, different nonces → different ciphertext.
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
        assert_ne!(enc1.nonce, enc2.nonce);

        // But same content hash.
        assert_eq!(enc1.context_hash, enc2.context_hash);
    }

    #[test]
    fn test_context_hash_matches() {
        let ctx = test_context();
        let key = test_key();

        let encrypted = EncryptedRequestContext::encrypt(&ctx, &key).unwrap();

        // Hash should match serialized plaintext.
        let plaintext = serde_json::to_vec(&ctx).unwrap();
        let expected_hash = hex::encode(Sha256::digest(&plaintext));
        assert_eq!(encrypted.context_hash, expected_hash);
    }

    #[test]
    fn test_audit_record_serialization() {
        let ctx = test_context();
        let key = test_key();
        let encrypted = EncryptedRequestContext::encrypt(&ctx, &key).unwrap();

        let record = SignAuditRecord {
            session_id: "sess_123".into(),
            wallet_id: "wallet_abc".into(),
            message_hash: "deadbeef".into(),
            requester_id: "user_42".into(),
            encrypted_context: encrypted,
            approval_count: 2,
            policy_hash: "cafebabe".into(),
            signed_at: 1710768000,
            scheme: "gg20-ecdsa".into(),
            signers: vec![1, 3, 5],
        };

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("sess_123"));
        assert!(!json.contains("203.0.113.42")); // IP should be encrypted, not in JSON
    }
}
