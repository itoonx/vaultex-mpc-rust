# Cryptography Reference

> MPC Wallet SDK (Vaultex) — Cryptographic Primitives and Protocol Documentation
>
> Last updated: 2026-03-20

## 1. Protocols Implemented

### GG20 — Threshold ECDSA (secp256k1)

- **Paper:** Gennaro, R. and Goldfeder, S. "One Round Threshold ECDSA with Identifiable Abort" (2020). Builds on GG18.
- **Curve:** secp256k1 (256-bit, cofactor 1)
- **Threshold:** t-of-n (configurable)
- **Keygen:** Feldman VSS with Pedersen commitments; each party receives a Shamir share of the group secret key.
- **Signing:** Additive-share distributed signing — full private key is never reconstructed (SEC-001 fix). Each party computes a partial signature from its share.
- **Key Refresh:** Additive re-sharing preserves the group public key while generating fresh shares (Epic H1).
- **Key Reshare:** Change threshold or add/remove parties; group key is preserved via additive re-sharing (Epic H2).
- **Security Level:** 128-bit (secp256k1 group order ~2^256).

### CGGMP21 — Threshold ECDSA with Identifiable Abort (secp256k1)

- **Paper:** Canetti, R., Gennaro, R., Goldfeder, S., Makriyannis, N., and Peled, U. "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts" (2021). IACR ePrint 2021/060.
- **Curve:** secp256k1 (256-bit)
- **Threshold:** t-of-n (configurable)
- **Keygen:** 3-round DKG with Feldman VSS, Schnorr proofs of knowledge, and commit-then-reveal (SHA-256). Auxiliary information generated per-party: Paillier key pair + Pedersen parameters.
- **Pre-Signing:** Offline batchable phase producing `PreSignature` (k_i, chi_i, big_r). Uses Paillier-encrypted MtA (Multiplicative-to-Additive) sub-protocol.
- **Online Signing:** Single-round sigma_i aggregation from pre-signatures. Message-independent pre-computation enables fast online phase.
- **Identifiable Abort:** When final signature verification fails, the protocol identifies the cheating party by verifying per-party sigma_i contributions.
- **Key Refresh:** Additive re-sharing preserves group public key with fresh Paillier/Pedersen auxiliary info.
- **Security Level:** 128-bit (secp256k1 + 2048-bit Paillier).

### FROST Ed25519 — Threshold EdDSA

- **Paper:** Komlo, C. and Goldberg, I. "FROST: Flexible Round-Optimized Schnorr Threshold Signatures" (2020). IACR ePrint 2020/852.
- **Curve:** Ed25519 (Curve25519, 255-bit)
- **Threshold:** t-of-n
- **Keygen:** DKG-based with Feldman VSS.
- **Signing:** 2-round Schnorr threshold signing. Full key never reconstructed (SEC-020 positive finding).
- **Key Refresh:** DKG-based re-sharing preserves group public key.
- **Reshare:** Fresh DKG produces new group key (DEC-008).
- **Security Level:** 128-bit (Curve25519 group order ~2^252).

### FROST Secp256k1-TR — Threshold Schnorr (Taproot)

- **Paper:** Same FROST paper as above, instantiated over secp256k1.
- **Curve:** secp256k1 (256-bit)
- **Threshold:** t-of-n
- **Use Case:** Bitcoin Taproot (BIP-340 Schnorr signatures).
- **Key Refresh:** Additive re-sharing preserves group public key for Taproot compatibility.
- **Security Level:** 128-bit.

## 2. Paillier Cryptosystem

### Parameters

| Parameter | Production | Test |
|-----------|-----------|------|
| Modulus N = p * q | >= 2048-bit | 512-bit |
| Prime type | Safe primes: p = 2p'+1, q = 2q'+1 | Safe primes |
| Primality testing | 40-round Miller-Rabin on both p/q and p'/q' | Same |
| Security level | 128-bit (2048-bit RSA equivalent) | Reduced for speed |

### Operations

- **Encryption:** c = (N+1)^m * r^N mod N^2, where r is random in Z*_N.
- **Decryption:** m = L(c^lambda mod N^2) * mu mod N, where L(x) = (x-1)/N.
- **Homomorphic addition:** Enc(a) * Enc(b) mod N^2 = Enc(a + b mod N).
- **Homomorphic scalar multiplication:** Enc(a)^k mod N^2 = Enc(a * k mod N).
- **Semantic security:** Same plaintext produces different ciphertexts due to random r.

### CVE-2023-33241 Mitigation

Without Paillier ZK proofs, an attacker can inject keys with small prime factors and extract private key shares within approximately 16 signing sessions. The Pifac proof rejects any modulus N with a factor smaller than 2^256, and the Pimod proof validates Blum modulus structure. Both proofs are required during CGGMP21 keygen auxiliary info exchange.

## 3. Zero-Knowledge Proof Inventory

All proofs use Fiat-Shamir transform for non-interactivity with domain-separated SHA-256 challenges.

| Proof | Full Name | Purpose | Paper Section | Status |
|-------|-----------|---------|---------------|--------|
| Pimod | Paillier-Blum Modulus Proof | Proves N = p*q is a Blum integer (p = q = 3 mod 4) | CGGMP21 Fig. 28 | Implemented (Sprint 27a) |
| Pifac | No Small Factor Proof | Proves N has no prime factor < 2^256; prevents CVE-2023-33241 | CGGMP21 Fig. 29 | Implemented (Sprint 27a) |
| Pienc | Range Proof for Paillier Encryption | Proves Paillier ciphertext encrypts a value in a given range; used in MtA Round 1 | CGGMP21 Fig. 14 | Implemented (Sprint 27b) |
| Piaff-g | Affine Operation with Group Element | Proves correctness of Paillier affine operation c_B = c_A^b * Enc(-beta); binds to EC group element | CGGMP21 Fig. 15 | Implemented (Sprint 27b) |
| Pilogstar | Discrete Log Relation | Proves knowledge of discrete log relation between Paillier ciphertext and EC point | CGGMP21 Fig. 25 | Implemented (Sprint 27b) |

### Proof Parameters

- **Pimod:** 80 rounds (security parameter kappa = 80). Prover demonstrates Nth root computation for each challenge.
- **Pifac:** Trial division covers all primes up to 2^20. Minimum factor size enforced: 2^256 bits.
- **All proofs:** Fiat-Shamir challenges use domain-separated prefixes (e.g., `pimod_challenge`, `pifac_challenge`).

### Known Limitations in ZK Proofs

- SEC-055: Pienc Pedersen commitment verification computes LHS but relies solely on Fiat-Shamir binding.
- SEC-056: Piaff-g prover samples fresh randomness in response phase instead of using committed Pedersen randomness.
- SEC-057: Pilogstar group-element verification is a hash-based stand-in, not a real EC scalar multiplication check.
- SEC-059: Pifac p_bits/q_bits are self-declared by prover; verifier does not independently verify consistency with N.

## 4. Key Derivation

### Key Store Encryption (at rest)

- **Algorithm:** Argon2id
- **Parameters:** m_cost = 65,536 (64 MiB), t_cost = 3, p_cost = 4, salt = 32 bytes (random)
- **Output:** 256-bit key for AES-256-GCM encryption of key shares
- **Rationale:** Argon2id is memory-hard and resistant to GPU/ASIC attacks. Parameters chosen for wallet-class security (SEC-006 fix).

### Data Encryption Key (DEK) Derivation

- **KMS mode:** Envelope encryption — KMS wraps/unwraps DEKs; DEK cache with TTL.
- **Local mode:** AES-256-GCM key wrapping with master key (Zeroizing wrapper). Note: SEC-044 identifies that local DEK derivation uses ad-hoc SHA-256 concat instead of HKDF.

### Session Key Derivation

- **Key Agreement:** X25519 ECDH (Curve25519)
- **KDF:** HKDF-SHA256 with transcript hash as info parameter
- **Session Encryption:** ChaCha20-Poly1305 (AEAD, 256-bit key)
- **Nonce:** Counter-based (no nonce reuse risk with AEAD counter mode)
- **Handshake:** ClientHello (X25519 ephemeral + Ed25519 static) → ServerHello → mutual authentication with transcript binding

## 5. Signature Schemes

### ECDSA (secp256k1)

- **Curve:** secp256k1 (Koblitz curve, 256-bit prime field)
- **Group order:** n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
- **Low-S normalization:** Enforced per EIP-2 / BIP-62. If s > n/2, replace with n - s and flip recovery_id (SEC-012 fix).
- **Recovery ID:** Computed via brute-force verification against public key (SEC-043 positive finding).
- **Use:** EVM chains, Bitcoin (legacy/SegWit), TRON, Cosmos, and 50+ secp256k1-based chains.

### EdDSA (Ed25519)

- **Curve:** Ed25519 (twisted Edwards curve over Curve25519)
- **Signature size:** 64 bytes (R || s)
- **Deterministic nonces:** Per RFC 8032.
- **Use:** Solana, Sui, FROST threshold signing, node identity keys, SignedEnvelope authentication, SignAuthorization, audit log signing, policy bundle signing.

### Schnorr (secp256k1, BIP-340)

- **Curve:** secp256k1
- **Standard:** BIP-340 (x-only public keys, tagged hashes)
- **Use:** Bitcoin Taproot via FROST Secp256k1-TR threshold signing.

## 6. Transport Security

### Signed Envelopes (SEC-007 Fix)

Every protocol message is wrapped in a `SignedEnvelope`:

- **Signature:** Ed25519 over SHA-256 hash of canonical JSON (with signature field empty).
- **Sender authentication:** Ed25519 public key included; receiver verifies against registered peer key.
- **Replay protection:** Monotonic `seq_no` per (session_id, sender) pair. Receivers reject seq_no <= last_seen.
- **Freshness:** `expires_at` timestamp (configurable TTL, default 30s, extended to 300s for Paillier keygen).

### Session Encryption

- **Negotiation:** X25519 ECDH key agreement during auth handshake.
- **Encryption:** ChaCha20-Poly1305 (256-bit key, 96-bit nonce).
- **Key derivation:** HKDF-SHA256 with transcript hash binding.
- **Nonce management:** Counter-based, incremented per message.

### NATS Transport

- **Connection security:** mTLS with PEM certificate loading (`NatsTlsConfig`).
- **Client key protection:** TLS client private key wrapped in zeroizing memory.
- **Channel isolation:** Per-group subject namespacing (`mpc.control.{op}.{group_id}`).
- **Control plane:** All control messages (keygen/sign/freeze) Ed25519-signed by gateway (SEC-026 fix).

### Session Management

- **Backend options:** In-memory or Redis (configurable via SESSION_BACKEND).
- **Redis encryption:** Sessions encrypted with ChaCha20-Poly1305 before storage (KEK from SESSION_ENCRYPTION_KEY).
- **Replay cache:** Redis SET NX EX (atomic, TTL-based) for handshake nonce dedup.
- **Revocation:** Dynamic key revocation via Redis SET (SADD/SISMEMBER); non-blocking SCAN instead of KEYS.

## 7. MtA (Multiplicative-to-Additive) Sub-Protocol

Used in CGGMP21 pre-signing to convert multiplicative sharings into additive sharings without revealing secrets.

1. Party A encrypts secret `a` under its Paillier key: c_A = Enc_A(a).
2. Party A sends c_A to Party B (with Pienc range proof).
3. Party B computes c_B = c_A^b * Enc_A(-beta') = Enc_A(a*b - beta') and sends back (with Piaff-g proof).
4. Party A decrypts c_B to get alpha = a*b - beta'.
5. Party B keeps beta = beta'.
6. Result: alpha + beta = a*b (mod N).

All secret values wrapped in `Zeroizing<Vec<u8>>` (SEC-065 positive finding).

## 8. References

### Papers

| Reference | Citation |
|-----------|----------|
| GG20 | Gennaro, R. and Goldfeder, S. "One Round Threshold ECDSA with Identifiable Abort." 2020. |
| CGGMP21 | Canetti, R., Gennaro, R., Goldfeder, S., Makriyannis, N., and Peled, U. "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts." IACR ePrint 2021/060. |
| FROST | Komlo, C. and Goldberg, I. "FROST: Flexible Round-Optimized Schnorr Threshold Signatures." IACR ePrint 2020/852. |
| Paillier | Paillier, P. "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes." EUROCRYPT 1999. |
| Feldman VSS | Feldman, P. "A Practical Scheme for Non-interactive Verifiable Secret Sharing." FOCS 1987. |
| CVE-2023-33241 | "Threshold ECDSA Key Extraction via Small-Factor Paillier Keys." 2023. Affects implementations without Pifac proof. |

### Standards and RFCs

| Standard | Usage |
|----------|-------|
| RFC 8032 | Ed25519 / EdDSA signature scheme |
| RFC 7748 | X25519 key agreement |
| RFC 5869 | HKDF (HMAC-based Key Derivation Function) |
| RFC 8439 | ChaCha20-Poly1305 AEAD |
| BIP-340 | Schnorr signatures for secp256k1 (Bitcoin Taproot) |
| BIP-62 | Low-S ECDSA signature normalization |
| EIP-2 | Ethereum low-S enforcement (homestead) |
| NIST SP 800-132 | Argon2 as password-based KDF (wallet-class parameters) |
| AES-256-GCM | NIST SP 800-38D — authenticated encryption for key store |

### Crate Dependencies (Cryptographic)

| Crate | Purpose |
|-------|---------|
| `k256` | secp256k1 elliptic curve operations (RustCrypto) |
| `ed25519-dalek` | Ed25519 signing and verification |
| `x25519-dalek` | X25519 key agreement |
| `chacha20poly1305` | ChaCha20-Poly1305 AEAD |
| `aes-gcm` | AES-256-GCM authenticated encryption |
| `argon2` | Argon2id password-based key derivation |
| `sha2` | SHA-256 hashing |
| `hkdf` | HMAC-based key derivation |
| `num-bigint` | Arbitrary-precision integers for Paillier |
| `zeroize` | Secure memory zeroization |
| `rand` / `OsRng` | Cryptographic random number generation |
