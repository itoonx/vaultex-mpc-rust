# DEC-017: GG20 Distributed Nonce Generation

- **Date:** 2026-03-20
- **Status:** REVERTED — mathematical error in Option 2, deferred to MtA-based approach

## Problem

Current GG20 signing flow has Party 1 (coordinator) generate the ephemeral nonce.
If Party 1 is compromised, the attacker controls the nonce and can extract the
full private key via lattice attack in as few as 2 signatures.

## Options Considered

### Option 1: MtA-based distributed nonce (CGGMP21-style) — RECOMMENDED
Each party generates k_i, uses Paillier MtA to compute shares of k⁻¹ without
any party learning the full k or k⁻¹.

- **Pro:** Strongest security — no party learns k
- **Pro:** Already have MtA infrastructure (Sprint 27b)
- **Con:** Requires additional Paillier rounds per signing session
- **Con:** Most complex to implement correctly

### Option 2: Commitment-Reveal Nonce — ATTEMPTED AND REVERTED
Each party generates k_i, commits to K_i = k_i·G, then reveals. R = Σ K_i.

**FATAL FLAW:** The partial signature formula `s_i = k_i⁻¹ · (hash + x_i_add · r)`
is mathematically incorrect. `Σ k_i⁻¹ ≠ (Σ k_i)⁻¹` — you cannot independently
invert additive nonce shares and expect the sum to equal the inverse of the
aggregate nonce. This is a fundamental property of modular arithmetic.

The correct distributed nonce requires MtA to compute shares of k⁻¹ from shares
of k, which is exactly what Option 1 provides.

### Option 3: Random Coordinator Selection
Rotate coordinator based on session_id hash.

- **Pro:** Simplest change
- **Con:** Does NOT fix the core issue

## Decision

**Option 2 was implemented in Sprint 30 and reverted** due to the mathematical
error causing all ECDSA signature verification tests to fail (6 failures in
`signature_verification.rs`, 3 in `protocol_integration.rs`).

**Restored coordinator-based signing** which is mathematically correct:
- s = k⁻¹ · (hash + r · x) where coordinator knows k⁻¹
- Each party computes s_i = x_i_add · r · k⁻¹ (partial contribution)
- Coordinator assembles: s = hash · k⁻¹ + Σ s_i

**Future plan:** Implement Option 1 (MtA-based) in a future sprint using the
existing Paillier MtA from `crate::paillier::mta`. This requires:
1. MtA rounds for k_i · γ_j → shares of k·γ = δ
2. MtA rounds for k_i · x_j → shares of k·x = σ
3. Reveal δ, compute δ⁻¹
4. Each party: s_i = m · δ⁻¹ · γ_i + r · δ⁻¹ · σ_i
5. s = Σ s_i = k⁻¹(m + rx) ✓

## Lessons Learned

**L-010:** Threshold ECDSA nonce inversion cannot be distributed by simply having
each party invert their own share. The inverse of a sum ≠ sum of inverses.
Any distributed nonce scheme requires interactive protocols (MtA) to compute
k⁻¹ shares from k shares.
