//! NATS-backed transport for MPC protocol messages with SEC-007 signed envelopes.
//!
//! Each party subscribes to a per-session subject and publishes to other parties'
//! subjects. Every message is wrapped in a [`SignedEnvelope`] that:
//! - Authenticates the sender via an Ed25519 signature (SEC-007 fix)
//! - Prevents replay attacks via a monotonic `seq_no`
//! - Enforces message freshness via a TTL (`expires_at`)
//!
//! # Subject scheme
//! `mpc.{session_id}.party.{party_id}`
//!
//! # Security status (Sprint 6)
//! - ✅ SEC-007: sender authentication via SignedEnvelope (wired in this file)
//! - ⚠️  TLS not yet configured — Epic E2 scope
//! - ⚠️  Per-session ECDH key exchange — Epic E3 scope

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use async_nats::Client;
use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::StreamExt;

use crate::{
    error::CoreError,
    transport::{
        signed_envelope::{SignedEnvelope, DEFAULT_TTL_SECS},
        ProtocolMessage, Transport,
    },
    types::PartyId,
};

/// TLS configuration for mTLS-enabled NATS connections (Epic E2).
///
/// Provides mutual TLS: the client authenticates the server via `ca_cert_path`
/// and presents its own certificate (`client_cert_path` + `client_key_path`)
/// so the NATS server can authenticate the client.
#[derive(Debug, Clone)]
pub struct NatsTlsConfig {
    /// Path to PEM-encoded CA certificate for server verification.
    pub ca_cert_path: PathBuf,
    /// Path to PEM-encoded client certificate (for mutual TLS).
    pub client_cert_path: PathBuf,
    /// Path to PEM-encoded client private key.
    pub client_key_path: PathBuf,
}

impl NatsTlsConfig {
    /// Build a [`rustls::ClientConfig`] from PEM files on disk.
    ///
    /// Loads the CA cert, client cert, and client key from the configured paths.
    /// The client key's PEM buffer is zeroized on every path, including errors.
    pub fn build_rustls_config(&self) -> Result<rustls::ClientConfig, CoreError> {
        use rustls::pki_types::pem::{self, PemObject};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use zeroize::Zeroizing;

        // 1. Load CA cert
        let ca_pem = std::fs::read(&self.ca_cert_path).map_err(|e| {
            CoreError::Transport(format!("read CA cert {}: {e}", self.ca_cert_path.display()))
        })?;
        let ca_certs: Vec<_> = CertificateDer::pem_slice_iter(&ca_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CoreError::Transport(format!("parse CA cert: {e}")))?;

        if ca_certs.is_empty() {
            return Err(CoreError::Transport(
                "no CA certificates found in PEM file".into(),
            ));
        }

        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store
                .add(cert)
                .map_err(|e| CoreError::Transport(format!("add CA cert to root store: {e}")))?;
        }

        // 2. Load client cert
        let client_pem = std::fs::read(&self.client_cert_path).map_err(|e| {
            CoreError::Transport(format!(
                "read client cert {}: {e}",
                self.client_cert_path.display()
            ))
        })?;
        let client_certs: Vec<_> = CertificateDer::pem_slice_iter(&client_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CoreError::Transport(format!("parse client cert: {e}")))?;

        // 3. Load client key. The PEM buffer is wiped when this block ends,
        //    whether parsing succeeded or returned early with an error.
        let client_key = {
            let key_pem = Zeroizing::new(std::fs::read(&self.client_key_path).map_err(|e| {
                CoreError::Transport(format!(
                    "read client key {}: {e}",
                    self.client_key_path.display()
                ))
            })?);
            PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| match e {
                pem::Error::NoItemsFound => {
                    CoreError::Transport("no private key found in PEM file".into())
                }
                e => CoreError::Transport(format!("parse client key: {e}")),
            })?
        };

        // 4. Build rustls config — TLS 1.2+ with default safe cipher suites
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key)
            .map_err(|e| CoreError::Transport(format!("build TLS config: {e}")))?;

        Ok(config)
    }
}

/// Parse `nats_url` and refuse every scheme except `tls://`.
///
/// The parsed address is the one handed to the connector, so the scheme
/// checked here is the scheme that gets dialled. Errors from this function
/// never echo the URL: it may carry credentials.
fn parse_tls_server_addr(nats_url: &str) -> Result<async_nats::ServerAddr, CoreError> {
    let addr: async_nats::ServerAddr = nats_url
        .parse()
        .map_err(|e| CoreError::Transport(format!("invalid NATS URL: {e}")))?;
    if addr.scheme() != "tls" {
        return Err(CoreError::Transport(format!(
            "NATS mTLS requires a tls:// URL, got scheme {:?}",
            addr.scheme()
        )));
    }
    Ok(addr)
}

/// Connect options for every mTLS bus connection.
///
/// TLS is required on every connection the client makes, reconnects
/// included, whatever the server's INFO says. Server addresses the cluster
/// advertises are ignored, so the client only dials the configured address.
fn mtls_connect_options(tls_client_config: rustls::ClientConfig) -> async_nats::ConnectOptions {
    async_nats::ConnectOptions::new()
        .require_tls(true)
        .ignore_discovered_servers()
        .tls_client_config(tls_client_config)
}

/// NATS-backed [`Transport`] with SEC-007 signed envelope authentication.
///
/// # Signed envelopes
///
/// Every `send` wraps the [`ProtocolMessage`] in a [`SignedEnvelope`] signed
/// with this party's Ed25519 key. Every `recv` verifies the envelope against
/// the sender's registered public key and checks the monotonic `seq_no`.
///
/// # Setup
///
/// 1. Create the transport with [`NatsTransport::connect_signed`], providing
///    this party's Ed25519 signing key and the session_id.
/// 2. Register each peer's verifying key with [`NatsTransport::register_peer_key`].
/// 3. Call `send`/`recv` as normal — envelopes are handled transparently.
pub struct NatsTransport {
    client: Client,
    party_id: PartyId,
    session_id: String,
    /// This party's Ed25519 signing key (for outgoing envelope signatures).
    signing_key: SigningKey,
    /// Registered peers: party_id → verifying key (for incoming signature verification).
    peer_keys: HashMap<PartyId, VerifyingKey>,
    /// Per-peer last-seen seq_no for replay detection.
    last_seq: Mutex<HashMap<PartyId, u64>>,
    /// Per-peer outgoing seq_no counter (monotonically increasing).
    out_seq: Mutex<u64>,
    /// Persistent subscription for receiving messages (lazy-initialized on first recv).
    /// This ensures messages published between recv() calls are not lost.
    subscriber: tokio::sync::Mutex<Option<async_nats::Subscriber>>,
}

impl NatsTransport {
    /// Connect to a NATS server with SEC-007 signed envelope support.
    ///
    /// # Arguments
    /// - `nats_url` — NATS server URL (e.g. `nats://localhost:4222`).
    /// - `party_id` — this party's ID.
    /// - `session_id` — signing session namespace.
    /// - `signing_key` — this party's Ed25519 key used to sign outgoing envelopes.
    ///
    /// # Security note
    /// Plain TCP NATS — TLS is not yet configured (Epic E2 scope).
    // SECURITY: TLS not yet configured — Epic E2 scope
    pub async fn connect_signed(
        nats_url: &str,
        party_id: PartyId,
        session_id: String,
        signing_key: SigningKey,
    ) -> Result<Self, CoreError> {
        let client = async_nats::connect(nats_url)
            .await
            .map_err(|e| CoreError::Transport(format!("NATS connect failed: {e}")))?;

        // Subscribe eagerly so no messages are lost between connect and first recv().
        let inbox = format!("mpc.{}.party.{}", session_id, party_id.0);
        let subscriber = client
            .subscribe(inbox)
            .await
            .map_err(|e| CoreError::Transport(format!("NATS subscribe failed: {e}")))?;

        // Flush ensures the SUB command reaches the NATS server before returning.
        // Without this, a fast publisher may send before the server processes SUB,
        // causing message loss (observed on CI runners with higher latency).
        client
            .flush()
            .await
            .map_err(|e| CoreError::Transport(format!("NATS flush failed: {e}")))?;

        Ok(Self {
            client,
            party_id,
            session_id,
            signing_key,
            peer_keys: HashMap::new(),
            last_seq: Mutex::new(HashMap::new()),
            out_seq: Mutex::new(0),
            subscriber: tokio::sync::Mutex::new(Some(subscriber)),
        })
    }

    /// Connect to a NATS server with mTLS + SEC-007 signed envelope support (Epic E2).
    ///
    /// Like [`connect_signed`](Self::connect_signed), but the NATS connection is
    /// secured with mutual TLS: the client verifies the server's certificate
    /// against the provided CA cert, and presents its own client certificate for
    /// server-side authentication.
    ///
    /// Only `tls://` URLs are accepted; any other scheme is refused before
    /// the key is read or the network is touched. TLS is required on every
    /// connection, reconnects included, and server addresses advertised by
    /// the cluster are never dialled.
    ///
    /// # Arguments
    /// - `nats_url` — NATS server URL (e.g. `tls://nats.example.com:4222`).
    /// - `party_id` — this party's ID.
    /// - `session_id` — signing session namespace.
    /// - `signing_key` — this party's Ed25519 key used to sign outgoing envelopes.
    /// - `tls_config` — mTLS certificate paths (CA, client cert, client key).
    pub async fn connect_signed_tls(
        nats_url: &str,
        party_id: PartyId,
        session_id: String,
        signing_key: SigningKey,
        tls_config: NatsTlsConfig,
    ) -> Result<Self, CoreError> {
        let server_addr = parse_tls_server_addr(nats_url)?;
        let tls_client_config = tls_config.build_rustls_config()?;

        let client = mtls_connect_options(tls_client_config)
            .connect(server_addr)
            .await
            .map_err(|e| CoreError::Transport(format!("NATS TLS connect failed: {e}")))?;

        let inbox = format!("mpc.{}.party.{}", session_id, party_id.0);
        let subscriber = client
            .subscribe(inbox)
            .await
            .map_err(|e| CoreError::Transport(format!("NATS TLS subscribe failed: {e}")))?;

        client
            .flush()
            .await
            .map_err(|e| CoreError::Transport(format!("NATS TLS flush failed: {e}")))?;

        Ok(Self {
            client,
            party_id,
            session_id,
            signing_key,
            peer_keys: HashMap::new(),
            last_seq: Mutex::new(HashMap::new()),
            out_seq: Mutex::new(0),
            subscriber: tokio::sync::Mutex::new(Some(subscriber)),
        })
    }

    /// Wait until this transport's subscription is confirmed active on the NATS server.
    ///
    /// Uses double flush as a synchronization barrier: the first flush ensures the
    /// SUB command reaches the server, the yield allows the server to process it,
    /// and the second flush confirms the round-trip. This replaces fixed `sleep(2s)`
    /// delays in tests (L-011 fix).
    pub async fn wait_ready(&self) -> Result<(), CoreError> {
        let map_err = |e| CoreError::Transport(format!("NATS flush failed: {e}"));
        // First flush: drain outbound buffer so SUB command reaches server.
        self.client.flush().await.map_err(map_err)?;
        // Yield to let the NATS server process the SUB and any pending messages.
        tokio::task::yield_now().await;
        // Second flush: confirm server has processed our subscription (round-trip).
        self.client.flush().await.map_err(map_err)?;
        Ok(())
    }

    /// Register a peer's Ed25519 verifying key for incoming envelope verification.
    ///
    /// Must be called for every party before `recv` is used, otherwise messages
    /// from unregistered parties are rejected with `CoreError::Transport`.
    pub fn register_peer_key(&mut self, peer_id: PartyId, verifying_key: VerifyingKey) {
        self.peer_keys.insert(peer_id, verifying_key);
    }

    /// This party's Ed25519 verifying (public) key.
    /// Share this with all peers via out-of-band key exchange before the session.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    fn party_subject(session_id: &str, target: PartyId) -> String {
        format!("mpc.{}.party.{}", session_id, target.0)
    }

    fn next_seq_no(&self) -> u64 {
        let mut seq = self.out_seq.lock().unwrap();
        *seq += 1;
        *seq
    }

    /// Sign, serialize, and publish a message to a specific party.
    async fn publish_to(&self, msg: ProtocolMessage, target: PartyId) -> Result<(), CoreError> {
        let seq_no = self.next_seq_no();
        let envelope = SignedEnvelope::sign(
            msg,
            self.party_id,
            seq_no,
            DEFAULT_TTL_SECS,
            &self.signing_key,
        );
        let subject = Self::party_subject(&self.session_id, target);
        let payload =
            serde_json::to_vec(&envelope).map_err(|e| CoreError::Serialization(e.to_string()))?;
        self.client
            .publish(subject, payload.into())
            .await
            .map_err(|e| CoreError::Transport(format!("NATS publish failed: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl Transport for NatsTransport {
    async fn send(&self, msg: ProtocolMessage) -> Result<(), CoreError> {
        if let Some(target) = msg.to {
            self.publish_to(msg, target).await?;
        } else {
            // Broadcast: send to all registered peers (one message per peer).
            let peers: Vec<PartyId> = self.peer_keys.keys().copied().collect();
            for peer_id in peers {
                self.publish_to(msg.clone(), peer_id).await?;
            }
        }
        Ok(())
    }

    async fn recv(&self) -> Result<ProtocolMessage, CoreError> {
        // Use the persistent subscription established at connect time.
        // This ensures no messages are lost between send() and recv() calls.
        let mut sub_guard = self.subscriber.lock().await;
        let subscriber = sub_guard
            .as_mut()
            .ok_or_else(|| CoreError::Transport("NATS subscriber not initialized".into()))?;

        let raw = subscriber
            .next()
            .await
            .ok_or_else(|| CoreError::Transport("NATS subscription closed".into()))?;

        // Deserialise the signed envelope
        let envelope: SignedEnvelope = serde_json::from_slice(&raw.payload)
            .map_err(|e| CoreError::Transport(format!("envelope deserialize failed: {e}")))?;

        let sender = envelope.sender;

        // Look up the sender's registered verifying key
        let peer_vk = self.peer_keys.get(&sender).ok_or_else(|| {
            CoreError::Transport(format!(
                "SEC-007: no registered key for party {} — call register_peer_key first",
                sender.0
            ))
        })?;

        // Retrieve last-seen seq_no for this sender
        let last_seen = {
            let seq_map = self.last_seq.lock().unwrap();
            *seq_map.get(&sender).unwrap_or(&0)
        };

        // SEC-007: verify signature, TTL, and seq_no
        envelope.verify(peer_vk, last_seen)?;

        // Update last-seen seq_no
        {
            let mut seq_map = self.last_seq.lock().unwrap();
            seq_map.insert(sender, envelope.seq_no);
        }

        Ok(envelope.message)
    }

    fn party_id(&self) -> PartyId {
        self.party_id
    }

    async fn wait_ready(&self) -> Result<(), CoreError> {
        let map_err = |e| CoreError::Transport(format!("NATS flush failed: {e}"));
        self.client.flush().await.map_err(map_err)?;
        tokio::task::yield_now().await;
        self.client.flush().await.map_err(map_err)?;
        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_party_subject_format() {
        let subject = NatsTransport::party_subject("session-abc", PartyId(3));
        assert_eq!(subject, "mpc.session-abc.party.3");
    }

    #[test]
    fn test_inbox_subject_format() {
        let session_id = "test-session";
        let party_id = PartyId(2);
        let expected = format!("mpc.{}.party.{}", session_id, party_id.0);
        assert_eq!(expected, "mpc.test-session.party.2");
    }

    #[test]
    fn test_seq_no_increments() {
        // Verify that seq_no increments are monotonic across calls.
        // We test the counter logic directly (no live NATS needed).
        let counter = Mutex::new(0u64);
        let mut results = Vec::new();
        for _ in 0..5 {
            let mut seq = counter.lock().unwrap();
            *seq += 1;
            results.push(*seq);
        }
        assert_eq!(results, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_signed_envelope_roundtrip_without_nats() {
        // Verify the sign→serialise→deserialise→verify pipeline works
        // without a live NATS server.
        use crate::transport::signed_envelope::SignedEnvelope;
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        let vk = signing_key.verifying_key();

        let msg = ProtocolMessage {
            from: PartyId(1),
            to: Some(PartyId(2)),
            round: 1,
            payload: b"hello from party 1".to_vec(),
        };

        let envelope =
            SignedEnvelope::sign(msg.clone(), PartyId(1), 1, DEFAULT_TTL_SECS, &signing_key);

        // Serialise and deserialise (simulating the NATS wire)
        let json = serde_json::to_vec(&envelope).unwrap();
        let decoded: SignedEnvelope = serde_json::from_slice(&json).unwrap();

        // Verify succeeds with correct key and seq_no = 0 (first message)
        assert!(decoded.verify(&vk, 0).is_ok());
        assert_eq!(decoded.message.payload, b"hello from party 1");
    }

    #[test]
    fn test_replay_blocked_in_nats_pipeline() {
        // Simulate two envelopes with seq_no 1, 1 (replay).
        use crate::transport::signed_envelope::SignedEnvelope;
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        let vk = signing_key.verifying_key();

        let msg = ProtocolMessage {
            from: PartyId(1),
            to: Some(PartyId(2)),
            round: 1,
            payload: vec![],
        };

        let env1 = SignedEnvelope::sign(msg.clone(), PartyId(1), 1, DEFAULT_TTL_SECS, &signing_key);
        let env2 = SignedEnvelope::sign(msg, PartyId(1), 1, DEFAULT_TTL_SECS, &signing_key);

        // First message is accepted
        assert!(env1.verify(&vk, 0).is_ok());
        // Second with same seq_no 1 is rejected as replay (last_seen = 1)
        assert!(env2.verify(&vk, 1).is_err());
    }

    // ─── mTLS tests ────────────────────────────────────────────────────

    #[test]
    fn test_tls_config_rejects_missing_ca_cert() {
        let config = NatsTlsConfig {
            ca_cert_path: "/nonexistent/ca.pem".into(),
            client_cert_path: "/nonexistent/client.pem".into(),
            client_key_path: "/nonexistent/key.pem".into(),
        };
        let result = config.build_rustls_config();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("read CA cert"),
            "error should mention CA cert: {err}"
        );
    }

    #[test]
    fn test_tls_config_rejects_invalid_pem() {
        let dir = tempfile::tempdir().unwrap();

        // Write garbage (not valid PEM) to all three files
        let ca_path = dir.path().join("ca.pem");
        let cert_path = dir.path().join("client.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&ca_path, b"not a valid PEM").unwrap();
        std::fs::write(&cert_path, b"not a valid PEM").unwrap();
        std::fs::write(&key_path, b"not a valid PEM").unwrap();

        let config = NatsTlsConfig {
            ca_cert_path: ca_path,
            client_cert_path: cert_path,
            client_key_path: key_path,
        };
        let result = config.build_rustls_config();
        // Should fail because no valid certs were found in the garbage PEM
        assert!(result.is_err(), "invalid PEM should fail: {:?}", result);
    }

    #[test]
    fn test_tls_config_struct_construction() {
        let config = NatsTlsConfig {
            ca_cert_path: "/tmp/test-ca.pem".into(),
            client_cert_path: "/tmp/test-client.pem".into(),
            client_key_path: "/tmp/test-key.pem".into(),
        };
        // Verify Debug works and doesn't panic
        let debug = format!("{:?}", config);
        assert!(debug.contains("NatsTlsConfig"), "Debug impl should work");
        // Verify Clone works
        let _cloned = config.clone();
    }

    #[tokio::test]
    async fn test_connect_signed_tls_rejects_bad_config() {
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);

        let bad_config = NatsTlsConfig {
            ca_cert_path: "/nonexistent/ca.pem".into(),
            client_cert_path: "/nonexistent/client.pem".into(),
            client_key_path: "/nonexistent/key.pem".into(),
        };

        let result = NatsTransport::connect_signed_tls(
            "tls://localhost:4222",
            PartyId(1),
            "test-session".into(),
            signing_key,
            bad_config,
        )
        .await;

        let err = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error for bad TLS config"),
        };
        // Should fail at TLS config build (file not found), not at NATS connect
        assert!(
            err.contains("read CA cert"),
            "should fail on TLS config, got: {err}"
        );
    }

    // ─── mTLS loader and TLS enforcement (fixtures: throwaway test CA) ──

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/nats-tls-test-only")
            .join(name)
    }

    fn fixture_tls_config(client_cert: &str, client_key: &str) -> NatsTlsConfig {
        NatsTlsConfig {
            ca_cert_path: fixture("ca.pem"),
            client_cert_path: fixture(client_cert),
            client_key_path: fixture(client_key),
        }
    }

    fn random_signing_key() -> SigningKey {
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    /// Build the config and check the client identity it will present: the
    /// fixture certificate, with a key of `algorithm` whose public half equals
    /// the certificate's (the pairing openssl produced when it issued it).
    fn assert_client_identity_loaded(config: NatsTlsConfig, algorithm: rustls::SignatureAlgorithm) {
        use rustls::pki_types::{pem::PemObject, CertificateDer};

        let tls = config
            .build_rustls_config()
            .expect("fixture mTLS config must load");
        let identity = tls
            .client_auth_cert_resolver
            .resolve(&[], &[])
            .expect("a client certificate must be configured");
        // Ok(()) rather than "unknown": the key's public half was compared.
        identity
            .keys_match()
            .expect("client key must match the client certificate");
        assert_eq!(identity.key.algorithm(), algorithm);
        let expected = CertificateDer::from_pem_file(&config.client_cert_path).unwrap();
        assert_eq!(identity.end_entity_cert().unwrap(), &expected);
    }

    #[test]
    fn test_tls_config_loads_pkcs8_ec_client_key() {
        assert_client_identity_loaded(
            fixture_tls_config("client-ec.pem", "client-ec-key-pkcs8.pem"),
            rustls::SignatureAlgorithm::ECDSA,
        );
    }

    #[test]
    fn test_tls_config_loads_sec1_ec_client_key() {
        assert_client_identity_loaded(
            fixture_tls_config("client-ec.pem", "client-ec-key-sec1.pem"),
            rustls::SignatureAlgorithm::ECDSA,
        );
    }

    #[test]
    fn test_tls_config_loads_pkcs1_rsa_client_key() {
        assert_client_identity_loaded(
            fixture_tls_config("client-rsa.pem", "client-rsa-key-pkcs1.pem"),
            rustls::SignatureAlgorithm::RSA,
        );
    }

    #[test]
    fn test_tls_config_rejects_key_file_without_private_key() {
        // A well-formed PEM file that holds a certificate and no key.
        let config = fixture_tls_config("client-ec.pem", "client-ec.pem");
        let err = config.build_rustls_config().unwrap_err().to_string();
        assert!(
            err.contains("no private key found in PEM file"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_connect_signed_tls_refuses_non_tls_url_before_network_io() {
        // A listener that never accepts: a client that dialled it would sit in
        // its backlog, and a non-blocking accept() would return it.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();

        for url in [
            format!("nats://127.0.0.1:{port}"),
            // No scheme: async-nats would default to nats://.
            format!("127.0.0.1:{port}"),
            format!("ws://127.0.0.1:{port}"),
            format!("wss://127.0.0.1:{port}"),
        ] {
            // A loadable config, so only the URL check stands in the way.
            let result = NatsTransport::connect_signed_tls(
                &url,
                PartyId(1),
                "test-session".into(),
                random_signing_key(),
                fixture_tls_config("client-ec.pem", "client-ec-key-pkcs8.pem"),
            )
            .await;
            let err = match result {
                Err(e) => e.to_string(),
                Ok(_) => panic!("{url}: connect must be refused"),
            };
            assert!(
                err.contains("NATS mTLS requires a tls:// URL"),
                "{url}: unexpected error: {err}"
            );
            match listener.accept() {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                other => panic!("{url}: a connection reached the server: {other:?}"),
            }
        }
    }

    /// A fake NATS server that speaks plaintext: it accepts one connection,
    /// sends an INFO line without `tls_required`, records the first record the
    /// client sends back, then hangs up. Returns its port and what it received.
    async fn plaintext_nats_server() -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket
                .write_all(
                    b"INFO {\"server_id\":\"plaintext-fake\",\"version\":\"2.10.0\",\
                      \"proto\":1,\"headers\":true,\"max_payload\":1048576}\r\n",
                )
                .await
                .unwrap();

            let mut received = Vec::new();
            let mut header = [0u8; 5];
            if socket.read_exact(&mut header).await.is_ok() {
                received.extend_from_slice(&header);
                if header[0] == 0x16 {
                    // TLS handshake record: read its body, then hang up.
                    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
                    let mut body = vec![0u8; len];
                    if socket.read_exact(&mut body).await.is_ok() {
                        received.extend_from_slice(&body);
                    }
                } else {
                    // Plaintext: keep the rest of what was sent for the report.
                    let mut rest = [0u8; 1024];
                    if let Ok(n) = socket.read(&mut rest).await {
                        received.extend_from_slice(&rest[..n]);
                    }
                }
            }
            received
        });
        (port, server)
    }

    /// The first thing the client sent after INFO must be a TLS ClientHello,
    /// and no plaintext CONNECT may appear.
    fn assert_client_hello_not_plaintext_connect(received: &[u8]) {
        let shown = String::from_utf8_lossy(received);
        assert!(
            !received.windows(7).any(|w| w == b"CONNECT"),
            "client sent CONNECT in plaintext: {shown:?}"
        );
        assert!(
            received.len() > 5,
            "client sent no complete record after INFO: {shown:?}"
        );
        assert_eq!(
            received[0], 0x16,
            "first record after INFO must be a TLS handshake: {shown:?}"
        );
        assert_eq!(
            received[5], 0x01,
            "TLS handshake message must be ClientHello"
        );
    }

    #[tokio::test]
    async fn test_mtls_never_sends_plaintext_connect_to_plaintext_server() {
        // 1. The public entry point with a tls:// URL.
        let (port, server) = plaintext_nats_server().await;
        let result = NatsTransport::connect_signed_tls(
            &format!("tls://127.0.0.1:{port}"),
            PartyId(1),
            "test-session".into(),
            random_signing_key(),
            fixture_tls_config("client-ec.pem", "client-ec-key-pkcs8.pem"),
        )
        .await;
        let err = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("connect must fail: the server hung up mid-handshake"),
        };
        assert!(
            err.contains("NATS TLS connect failed"),
            "unexpected error: {err}"
        );
        assert_client_hello_not_plaintext_connect(&server.await.unwrap());

        // 2. The connect options alone, dialling a nats:// address, as a
        //    reconnect to any non-tls:// address would: require_tls must force
        //    the upgrade although neither the scheme nor the server asks for it.
        let (port, server) = plaintext_nats_server().await;
        let tls = fixture_tls_config("client-ec.pem", "client-ec-key-pkcs8.pem")
            .build_rustls_config()
            .unwrap();
        let result = mtls_connect_options(tls)
            .connect(format!("nats://127.0.0.1:{port}"))
            .await;
        assert!(result.is_err(), "connect must fail: the server hung up");
        assert_client_hello_not_plaintext_connect(&server.await.unwrap());
    }

    // NatsTransport integration test requires a live NATS server.
    // Run manually: NATS_URL=nats://localhost:4222 cargo test --features nats-integration-test
    #[tokio::test]
    #[ignore = "requires live NATS server: NATS_URL=nats://localhost:4222"]
    async fn test_nats_signed_round_trip() {
        use rand::rngs::OsRng;
        use rand::RngCore;

        let url = std::env::var("NATS_URL").unwrap_or("nats://localhost:4222".into());
        let session = uuid::Uuid::new_v4().to_string();

        let mut k1_bytes = [0u8; 32];
        let mut k2_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut k1_bytes);
        OsRng.fill_bytes(&mut k2_bytes);
        let k1 = SigningKey::from_bytes(&k1_bytes);
        let k2 = SigningKey::from_bytes(&k2_bytes);
        let vk1 = k1.verifying_key();
        let vk2 = k2.verifying_key();

        let mut t1 = NatsTransport::connect_signed(&url, PartyId(1), session.clone(), k1)
            .await
            .unwrap();
        let mut t2 = NatsTransport::connect_signed(&url, PartyId(2), session.clone(), k2)
            .await
            .unwrap();

        t1.register_peer_key(PartyId(2), vk2);
        t2.register_peer_key(PartyId(1), vk1);

        let msg = ProtocolMessage {
            from: PartyId(1),
            to: Some(PartyId(2)),
            round: 1,
            payload: b"sec007-test".to_vec(),
        };

        t1.send(msg.clone()).await.unwrap();
        let received = t2.recv().await.unwrap();
        assert_eq!(received.payload, b"sec007-test");
    }
}
