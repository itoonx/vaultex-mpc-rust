//! Client-side handshake SDK.
//!
//! Provides `HandshakeClient` for performing the key-exchange handshake
//! against the API gateway. Handles transcript hashing, Ed25519 signing,
//! and session key derivation automatically.
//!
//! # Usage
//! ```rust,no_run
//! use mpc_wallet_api::auth::client::HandshakeClient;
//!
//! let client = HandshakeClient::new(client_signing_key, server_pubkey);
//! let session = client.handshake("https://api.example.com").await?;
//! // Use session.session_token in X-Session-Token header
//! ```

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use super::types::*;

/// Error during client handshake.
#[derive(Debug)]
pub enum ClientHandshakeError {
    /// Server returned non-200 status.
    ServerError(String),
    /// Server signature verification failed.
    InvalidServerSignature,
    /// Protocol version mismatch.
    VersionMismatch,
    /// Key derivation failed.
    KeyDerivationFailed,
    /// Serialization error.
    SerializationError(String),
}

impl std::fmt::Display for ClientHandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServerError(e) => write!(f, "server error: {e}"),
            Self::InvalidServerSignature => write!(f, "invalid server signature"),
            Self::VersionMismatch => write!(f, "protocol version mismatch"),
            Self::KeyDerivationFailed => write!(f, "key derivation failed"),
            Self::SerializationError(e) => write!(f, "serialization error: {e}"),
        }
    }
}

/// Client-side session after successful handshake.
#[derive(Debug, Clone)]
pub struct ClientSession {
    /// Session ID from server.
    pub session_id: String,
    /// Session token for X-Session-Token header.
    pub session_token: String,
    /// Session expiration (UNIX seconds).
    pub expires_at: u64,
    /// Key fingerprint for verification.
    pub key_fingerprint: String,
    /// Derived client→server write key.
    pub client_write_key: [u8; 32],
    /// Derived server→client write key.
    pub server_write_key: [u8; 32],
}

/// Result of building a ClientHello.
pub struct ClientHelloBundle {
    /// The ClientHello message to send.
    pub client_hello: ClientHello,
    /// Ephemeral secret (needed for step 2).
    pub ephemeral_secret: StaticSecret,
    /// Client nonce bytes (needed for key derivation).
    pub client_nonce: [u8; 32],
}

/// Client-side handshake helper.
///
/// Implements the client half of the key-exchange handshake protocol.
/// Handles transcript hashing, signature generation, and key derivation.
pub struct HandshakeClient {
    /// Client's static Ed25519 signing key.
    signing_key: SigningKey,
    /// Server's trusted Ed25519 public key (for verifying ServerHello signature).
    server_pubkey: Option<VerifyingKey>,
}

impl HandshakeClient {
    /// Create a new handshake client.
    ///
    /// `server_pubkey` is optional — if provided, the client verifies the server's
    /// signature in ServerHello (recommended for production). If None, server
    /// signature is not verified (useful for development/testing).
    pub fn new(signing_key: SigningKey, server_pubkey: Option<VerifyingKey>) -> Self {
        Self {
            signing_key,
            server_pubkey,
        }
    }

    /// Step 1: Build a ClientHello message.
    ///
    /// Returns the ClientHello and ephemeral state needed for step 2.
    pub fn build_client_hello(&self) -> ClientHelloBundle {
        let ephemeral_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_public = X25519Public::from(&ephemeral_secret);

        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let client_key_id = hex::encode(&self.signing_key.verifying_key().to_bytes()[..8]);

        ClientHelloBundle {
            client_hello: ClientHello {
                protocol_version: PROTOCOL_VERSION.to_string(),
                supported_kex: vec![KeyExchangeAlgorithm::X25519],
                supported_sig: vec![SignatureAlgorithm::Ed25519],
                client_ephemeral_pubkey: hex::encode(ephemeral_public.as_bytes()),
                client_nonce: hex::encode(nonce),
                timestamp: now,
                client_key_id,
            },
            ephemeral_secret,
            client_nonce: nonce,
        }
    }

    /// Step 2: Process ServerHello and build ClientAuth + derive session keys.
    ///
    /// Verifies the server's signature (if server_pubkey was provided),
    /// computes the transcript hash, signs it, and derives session keys.
    pub fn process_server_hello(
        &self,
        client_hello: &ClientHello,
        server_hello: &ServerHello,
        ephemeral_secret: StaticSecret,
        client_nonce: &[u8; 32],
    ) -> Result<(ClientAuth, ClientSession), ClientHandshakeError> {
        // Verify protocol version.
        if server_hello.protocol_version != PROTOCOL_VERSION {
            return Err(ClientHandshakeError::VersionMismatch);
        }

        // Build transcript (same as server).
        let mut transcript = Sha256::new();

        // ClientHello
        let ch_bytes = serde_json::to_vec(client_hello)
            .map_err(|e| ClientHandshakeError::SerializationError(e.to_string()))?;
        transcript.update(&ch_bytes);

        // ServerHello fields (minus signature)
        let sh_for_transcript = serde_json::json!({
            "protocol_version": server_hello.protocol_version,
            "selected_kex": server_hello.selected_kex,
            "selected_sig": server_hello.selected_sig,
            "selected_aead": server_hello.selected_aead,
            "server_ephemeral_pubkey": server_hello.server_ephemeral_pubkey,
            "server_nonce": server_hello.server_nonce,
            "server_challenge": server_hello.server_challenge,
            "timestamp": server_hello.timestamp,
            "server_key_id": server_hello.server_key_id,
        });
        let sh_bytes = serde_json::to_vec(&sh_for_transcript)
            .map_err(|e| ClientHandshakeError::SerializationError(e.to_string()))?;
        transcript.update(&sh_bytes);

        // Verify server signature over transcript (if we have server pubkey).
        if let Some(ref server_pk) = self.server_pubkey {
            let server_transcript_hash = transcript.clone().finalize();
            let sig_bytes = hex::decode(&server_hello.server_signature)
                .map_err(|_| ClientHandshakeError::InvalidServerSignature)?;
            if sig_bytes.len() != 64 {
                return Err(ClientHandshakeError::InvalidServerSignature);
            }
            let sig_arr: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| ClientHandshakeError::InvalidServerSignature)?;
            let server_sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
            server_pk
                .verify_strict(&server_transcript_hash, &server_sig)
                .map_err(|_| ClientHandshakeError::InvalidServerSignature)?;
        }

        // Add ClientAuth fields to transcript (minus signature).
        let client_pubkey_hex = hex::encode(self.signing_key.verifying_key().to_bytes());
        let auth_for_transcript = serde_json::json!({
            "client_static_pubkey": client_pubkey_hex,
        });
        let auth_bytes = serde_json::to_vec(&auth_for_transcript)
            .map_err(|e| ClientHandshakeError::SerializationError(e.to_string()))?;
        transcript.update(&auth_bytes);

        // Sign the full transcript hash.
        let transcript_hash = transcript.finalize();
        let client_sig = self.signing_key.sign(&transcript_hash);

        let client_auth = ClientAuth {
            client_signature: hex::encode(client_sig.to_bytes()),
            client_static_pubkey: client_pubkey_hex,
        };

        // Derive session keys via X25519 ECDH + HKDF.
        let server_eph_bytes = hex::decode(&server_hello.server_ephemeral_pubkey)
            .map_err(|_| ClientHandshakeError::KeyDerivationFailed)?;
        let server_eph_arr: [u8; 32] = server_eph_bytes
            .try_into()
            .map_err(|_| ClientHandshakeError::KeyDerivationFailed)?;
        let server_ephemeral_pubkey = X25519Public::from(server_eph_arr);

        let shared_secret = ephemeral_secret.diffie_hellman(&server_ephemeral_pubkey);

        let server_nonce_bytes = hex::decode(&server_hello.server_nonce)
            .map_err(|_| ClientHandshakeError::KeyDerivationFailed)?;
        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(client_nonce);
        salt.extend_from_slice(&server_nonce_bytes);

        let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());

        let mut client_write_key = [0u8; 32];
        let mut server_write_key = [0u8; 32];
        hk.expand(b"mpc-wallet-session-v1-client-write", &mut client_write_key)
            .map_err(|_| ClientHandshakeError::KeyDerivationFailed)?;
        hk.expand(b"mpc-wallet-session-v1-server-write", &mut server_write_key)
            .map_err(|_| ClientHandshakeError::KeyDerivationFailed)?;

        let session_id = hex::encode(&Sha256::digest(transcript_hash)[..16]);
        let key_fingerprint = hex::encode(&Sha256::digest(client_write_key)[..16]);

        Ok((
            client_auth,
            ClientSession {
                session_id,
                session_token: String::new(), // filled from server response
                expires_at: 0,                // filled from server response
                key_fingerprint,
                client_write_key,
                server_write_key,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::handshake::ServerHandshake;

    fn gen_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    #[test]
    fn test_client_sdk_full_handshake() {
        let server_key = gen_key();
        let client_key = gen_key();
        let server_pubkey = server_key.verifying_key();

        let client = HandshakeClient::new(client_key, Some(server_pubkey));

        // Step 1: Client builds hello.
        let bundle = client.build_client_hello();
        assert_eq!(bundle.client_hello.protocol_version, PROTOCOL_VERSION);

        // Step 2: Server processes hello.
        let mut server_hs = ServerHandshake::new(server_key);
        let server_hello = server_hs
            .process_client_hello(&bundle.client_hello)
            .unwrap();

        // Step 3: Client processes server hello + builds auth.
        let (client_auth, client_session) = client
            .process_server_hello(
                &bundle.client_hello,
                &server_hello,
                bundle.ephemeral_secret,
                &bundle.client_nonce,
            )
            .unwrap();

        // Step 4: Server processes client auth.
        let server_session = server_hs
            .process_client_auth(&client_auth, &bundle.client_hello)
            .unwrap();

        // Both sides derive the same session keys.
        assert_eq!(
            client_session.client_write_key,
            server_session.client_write_key
        );
        assert_eq!(
            client_session.server_write_key,
            server_session.server_write_key
        );

        // Session IDs match.
        assert_eq!(client_session.session_id, server_session.session_id);

        // Key fingerprints match.
        let server_fingerprint =
            hex::encode(&Sha256::digest(server_session.client_write_key)[..16]);
        assert_eq!(client_session.key_fingerprint, server_fingerprint);
    }

    #[test]
    fn test_client_sdk_rejects_wrong_server_key() {
        let server_key = gen_key();
        let client_key = gen_key();
        let wrong_server_pubkey = gen_key().verifying_key(); // different key

        let client = HandshakeClient::new(client_key, Some(wrong_server_pubkey));

        let bundle = client.build_client_hello();

        let mut server_hs = ServerHandshake::new(server_key);
        let server_hello = server_hs
            .process_client_hello(&bundle.client_hello)
            .unwrap();

        // Client should reject because server signature doesn't match trusted pubkey.
        let result = client.process_server_hello(
            &bundle.client_hello,
            &server_hello,
            bundle.ephemeral_secret,
            &bundle.client_nonce,
        );
        assert!(matches!(
            result,
            Err(ClientHandshakeError::InvalidServerSignature)
        ));
    }

    #[test]
    fn test_client_sdk_without_server_verification() {
        let server_key = gen_key();
        let client_key = gen_key();

        // No server pubkey — skip verification (dev mode).
        let client = HandshakeClient::new(client_key, None);

        let bundle = client.build_client_hello();
        let mut server_hs = ServerHandshake::new(server_key);
        let server_hello = server_hs
            .process_client_hello(&bundle.client_hello)
            .unwrap();

        let (client_auth, _session) = client
            .process_server_hello(
                &bundle.client_hello,
                &server_hello,
                bundle.ephemeral_secret,
                &bundle.client_nonce,
            )
            .unwrap();

        // Server should still accept.
        let result = server_hs.process_client_auth(&client_auth, &bundle.client_hello);
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_sdk_forward_secrecy() {
        let server_key = gen_key();
        let client_key = gen_key();

        let client = HandshakeClient::new(client_key, None);

        // Session 1
        let b1 = client.build_client_hello();
        let mut hs1 = ServerHandshake::new(server_key.clone());
        let sh1 = hs1.process_client_hello(&b1.client_hello).unwrap();
        let (_, s1) = client
            .process_server_hello(
                &b1.client_hello,
                &sh1,
                b1.ephemeral_secret,
                &b1.client_nonce,
            )
            .unwrap();

        // Session 2
        let b2 = client.build_client_hello();
        let mut hs2 = ServerHandshake::new(server_key);
        let sh2 = hs2.process_client_hello(&b2.client_hello).unwrap();
        let (_, s2) = client
            .process_server_hello(
                &b2.client_hello,
                &sh2,
                b2.ephemeral_secret,
                &b2.client_nonce,
            )
            .unwrap();

        // Different ephemeral keys → different session keys.
        assert_ne!(s1.client_write_key, s2.client_write_key);
        assert_ne!(s1.session_id, s2.session_id);
    }
}
