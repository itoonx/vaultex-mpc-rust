# Threat Model

> MPC Wallet SDK (Vaultex) — Threshold Multi-Party Computation Wallet
>
> Last updated: 2026-03-20

## 1. System Overview

The MPC Wallet SDK implements threshold signing where no single party ever holds a complete private key. The production architecture consists of:

```
Client (web/mobile/API)
    │
    ▼
API Gateway (orchestrator, holds ZERO key shares)
    │ NATS message bus (mTLS)
    ├── MPC Node 1 (holds share 1, EncryptedFileStore)
    ├── MPC Node 2 (holds share 2, EncryptedFileStore)
    └── MPC Node 3 (holds share 3, EncryptedFileStore)
```

- **Gateway:** Authenticates clients, enforces policy, collects approvals, orchestrates MPC rounds. Holds no key shares (DEC-015).
- **MPC Nodes:** Each holds exactly one key share. Communicate via NATS for protocol rounds. Independently verify sign authorization before participating.
- **Supported Protocols:** GG20 (threshold ECDSA), CGGMP21 (threshold ECDSA with identifiable abort), FROST (Ed25519 and Secp256k1 Taproot).

## 2. Assets

| Asset | Location | Sensitivity |
|-------|----------|-------------|
| Key shares (secp256k1, Ed25519 scalars) | MPC node EncryptedFileStore (Argon2id + AES-256-GCM) | CRITICAL — compromise of t shares reconstructs the key |
| Paillier secret keys (p, q, lambda, mu) | MPC node memory during CGGMP21 keygen/signing | CRITICAL — enables extraction of peer shares via MtA |
| Pre-signatures (k_i, chi_i, big_r) | MPC node memory during CGGMP21 pre-signing | HIGH — nonce reuse leads to key extraction |
| Gateway Ed25519 signing key | Gateway process (signs SignAuthorization) | HIGH — forged authorizations bypass node verification |
| Session tokens (JWT, HMAC-SHA256) | Gateway memory / Redis (ChaCha20-Poly1305 encrypted) | HIGH — session hijack enables unauthorized signing |
| Node Ed25519 identity keys | MPC node process (signs protocol messages) | HIGH — impersonation of a node in MPC rounds |
| Audit log (hash-chained, Ed25519 signed) | Append-only storage | MEDIUM — tamper = undetectable unauthorized operations |
| Policy bundles (Ed25519 signed) | Gateway configuration | MEDIUM — bypass = unauthorized transaction approval |

## 3. Adversary Models

### 3.1 Malicious Party (< threshold t)

**Capability:** Controls fewer than t MPC nodes. Can observe own share, deviate from protocol, send malicious messages.

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Inject malicious Paillier key with small factors | Extract other parties' shares in ~16 signatures (CVE-2023-33241) | Pifac ZK proof rejects N with any factor < 2^256; Pimod proof validates Blum modulus structure |
| Send inconsistent commitments during keygen | Bias public key or learn extra information | Feldman VSS with Schnorr proofs of knowledge; commit-then-reveal (SHA-256) in all keygen rounds |
| Send invalid signature shares during signing | Denial of service or blame shifting | CGGMP21 identifiable abort detects cheating party; GG20 signature verification before broadcast |
| Replay old protocol messages | Re-sign with stale nonce or re-run keygen | SignedEnvelope with monotonic seq_no per (session, party) + TTL expiry (SEC-007 fix) |
| Claim false party ID | Impersonate another node | Ed25519 signed envelopes authenticate sender identity; FROST validates `from` against expected signer set (SEC-013 fix) |

### 3.2 Compromised Gateway

**Capability:** Full control of the orchestrator. Can forge requests, alter routing, attempt unauthorized signing. Holds zero key shares.

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Forge sign requests to MPC nodes | Unauthorized transaction signing | SignAuthorization: Ed25519-signed proof verified independently by each node (DEC-012). Nodes check: gateway signature, message hash binding, policy_passed, approval quorum, 2-minute TTL |
| Replay a captured SignAuthorization | Double-sign the same transaction | authorization_id replay dedup with AuthorizationCache at each node (TTL-based expiry, max_entries capacity) |
| Forge control plane messages (keygen/freeze) | Trigger unauthorized keygen or freeze honest nodes | All control plane messages Ed25519-signed by gateway, verified by nodes via unwrap_signed_message() (SEC-026 fix) |
| Tamper with NATS routing | Partition or delay messages between nodes | MPC nodes verify message origin via Ed25519 signatures; protocol-level timeouts detect stalls |
| Bypass policy engine | Approve transactions that violate policy | Each node verifies policy_hash in SignAuthorization matches expected policy; policy bundles are Ed25519-signed |

### 3.3 Network Attacker (MITM on NATS)

**Capability:** Can observe, modify, drop, replay, and inject messages on the NATS transport layer.

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Eavesdrop on protocol messages | Learn partial information about shares | Per-session ChaCha20-Poly1305 encryption (X25519 ECDH key agreement, HKDF-SHA256 key derivation) |
| Replay protocol messages | Disrupt protocol execution or nonce reuse | Monotonic seq_no per (session, sender) pair in SignedEnvelope; TTL-based expiry |
| Modify messages in transit | Inject malicious protocol payloads | Ed25519 signature over canonical envelope bytes; tampered messages fail verification |
| Drop messages | Denial of service | Protocol-level timeout and retry; does not compromise key security |
| MITM on NATS connection | Full message interception | NATS mTLS (NatsTlsConfig with PEM cert loading, client key zeroization) |

### 3.4 Insider (Admin with Access to One MPC Node)

**Capability:** Root access to one MPC node. Can read filesystem, dump memory, modify binaries.

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Extract key share from disk | Obtains 1 of t shares (insufficient alone) | EncryptedFileStore: Argon2id (64MiB/3t/4p) + AES-256-GCM; password not stored on disk |
| Extract key share from memory | Obtains 1 of t shares | Zeroizing<Vec<u8>> for all share material; ZeroizeOnDrop on secret structs (SEC-004, SEC-008); PaillierSecretKey with Zeroize+ZeroizeOnDrop; Debug impls redact secrets (SEC-015) |
| Modify node binary to exfiltrate | Leak share or sign unauthorized | Out of scope for SDK; operational control: code signing, integrity monitoring, SGX enclaves (Sprint 23 prototype) |
| Collude with gateway operator | 1 share + orchestration control | Still requires t shares for signing; gateway holds 0 shares (DEC-015); nodes independently verify SignAuthorization |

## 4. Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│  EXTERNAL (untrusted)                               │
│  ┌───────────┐                                      │
│  │  Client   │                                      │
│  └─────┬─────┘                                      │
│        │ TLS + Auth (mTLS / Session JWT / Bearer JWT)│
├────────┼────────────────────────────────────────────┤
│  GATEWAY ZONE (semi-trusted — no key material)      │
│  ┌─────▼─────┐                                      │
│  │  Gateway   │ Auth, Policy, Approvals, Orchestrate│
│  └─────┬─────┘                                      │
│        │ NATS mTLS + SignedControlMessage            │
├────────┼────────────────────────────────────────────┤
│  MPC NODE ZONE (trusted — holds key shares)         │
│  ┌─────▼─────┐  ┌───────────┐  ┌───────────┐      │
│  │  Node 1   │  │  Node 2   │  │  Node 3   │      │
│  │  Share 1  │  │  Share 2  │  │  Share 3  │      │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘      │
│        │ Argon2id + AES-256-GCM                     │
│  ┌─────▼─────────────────▼───────────────▼─────┐   │
│  │  Encrypted Key Store (per-node, isolated)    │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### Boundary Crossings

| Boundary | Direction | Protection |
|----------|-----------|------------|
| Client → Gateway | Inbound | 3-method auth stack (mTLS → Session JWT → Bearer JWT); rate limiting (10 req/sec); present-but-invalid = fail (no fallthrough) |
| Gateway → NATS | Internal | NATS mTLS; Ed25519-signed control messages |
| NATS → MPC Node | Internal | SignedEnvelope verification; SignAuthorization verification; authorization_id replay dedup |
| MPC Node ↔ MPC Node (via NATS) | Internal | Per-session ChaCha20-Poly1305 encryption; Ed25519 signed envelopes; seq_no replay protection |
| MPC Node → KeyStore | Local | Argon2id key derivation; AES-256-GCM encryption; Zeroizing wrappers on all secret material |

## 5. Mitigation Summary

| Category | Mechanism | Protects Against | Reference |
|----------|-----------|------------------|-----------|
| **Message Authentication** | Ed25519 SignedEnvelope | Sender impersonation, message tampering | SEC-007 |
| **Replay Protection** | Monotonic seq_no + TTL expiry | Protocol message replay | SEC-007 |
| **Sign Authorization** | Ed25519-signed gateway proof, 2-min TTL | Compromised gateway unauthorized signing | DEC-012 |
| **Authorization Replay** | authorization_id + AuthorizationCache | Double-signing via captured authorization | SEC-025 |
| **Control Plane Auth** | SignedControlMessage | Forged keygen/sign/freeze commands | SEC-026 |
| **Paillier Key Validation** | Pimod (Blum modulus) + Pifac (no small factor) ZK proofs | CVE-2023-33241 small-factor key injection | Sprint 27a |
| **MtA Security** | Pienc, Piaff-g, Pilogstar ZK proofs | Malicious MtA inputs extracting shares | Sprint 27b |
| **Key Zeroization** | Zeroize + ZeroizeOnDrop on all secret types | Memory scraping after use | SEC-004, SEC-008 |
| **Key Encryption at Rest** | Argon2id (64MiB/3t/4p) + AES-256-GCM | Disk-level key extraction | SEC-006 |
| **Transport Encryption** | Per-session ChaCha20-Poly1305 (X25519 ECDH) | Network eavesdropping | Sprint 8 |
| **NATS Security** | mTLS with PEM cert loading, client key zeroization | Network MITM | Sprint 7 |
| **Auth System** | mTLS + Session JWT + Bearer JWT, no fallthrough | Unauthorized API access | DEC-013 |
| **Low-S Normalization** | Canonical ECDSA signatures (EIP-2) | Signature malleability | SEC-012 |
| **FROST Sender Validation** | Validate `from` against expected signer set | Party impersonation in FROST rounds | SEC-013 |
| **Identifiable Abort** | CGGMP21 cheater detection on invalid sigma_i | Blame-shifting by malicious party | Sprint 20 |
| **Debug Redaction** | Manual Debug impls on all secret types | Secret material in logs | SEC-015 |

## 6. Known Limitations

| Limitation | Description | Status |
|------------|-------------|--------|
| GG20 coordinator nonce | GG20 protocol has a coordinator nonce dependency; mitigated by distributed nonce commitment in DEC-017 (deferred) | Tracked: DEC-017 |
| Simulated MtA path | CGGMP21 protocol still has a simulated MtA code path for legacy shares using SHA-256 hash-based Paillier (SEC-058) | Tracked: Sprint 28 wiring |
| Pre-signature nonce reuse (crash) | CGGMP21 PreSignature `used` flag is in-memory only; crash-replay could bypass nonce reuse detection (SEC-037) | Tracked: LOW severity |
| Pienc Pedersen commitment | verify_pienc computes Pedersen LHS but discards it, relying on Fiat-Shamir binding only (SEC-055) | Tracked: MEDIUM |
| Piaffg response binding | Prover samples fresh randomness in response phase instead of using committed Pedersen randomness (SEC-056) | Tracked: MEDIUM |
| Pilogstar verification | Group-element check is hash-based stand-in, not real EC scalar multiplication (SEC-057) | Tracked: MEDIUM |
| SGX enclave | SGX integration is prototype only (MockEnclaveProvider); not production-hardened | Sprint 23 prototype |
| KMS integration | AWS KMS signer is a stub; Ed25519 signing stays local per DEC-016 | Tracked: DEC-016 |

## 7. Assumptions

1. **Honest majority:** Fewer than t of n MPC nodes are compromised at any time.
2. **Secure randomness:** `OsRng` provides cryptographically secure randomness on all deployment targets.
3. **Time synchronization:** MPC nodes have roughly synchronized clocks (within the 2-minute SignAuthorization TTL window).
4. **Secure key provisioning:** Node Ed25519 identity keys and gateway signing keys are provisioned securely out-of-band.
5. **Infrastructure isolation:** MPC nodes run on separate infrastructure (different cloud accounts, regions, or operators).
6. **NATS availability:** NATS message bus is available; unavailability causes liveness failure but not safety failure.
