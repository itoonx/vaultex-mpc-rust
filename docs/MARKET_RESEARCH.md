# Vaultex — Market Research Report (final, round 2)

- **Date:** 2026-10-09
- **Subject:** Vaultex, an open-source threshold-MPC wallet SDK and self-hosted service stack (public repository `itoonx/vaultex-mpc-rust`).
- **Basis:** round-1 market reports M1–M8 (incl. M2a/M2b), follow-ups G5–G8, the G1 library spike, and the round-2 verified claims ledger (46 items, reproduced in §7); sequencing and capacity scenarios follow the companion ROADMAP. No new web research was done for this synthesis; every market fact below was verified by those reports on 2026-10-08/09.
- **Classification:** public-safe.
- **Publication gate:** publish only after ROADMAP M5 items 3 (GHSA) and 5 (freeze switch) are merged.

**How to read this report**

- **Labels.** **VERIFIED** = carried from a cited report together with that report's evidence (URL or file:line), or confirmed by the round-2 verifier. **HYPOTHESIS** = unproven; the cheapest test is named. **ESTIMATE** = effort, cost or time with its basis (always also a hypothesis). **VENDOR CLAIM** = a company's statement about itself. **[needs counsel]** = a legal reading, not legal advice.
- **Citations.** `[M6 §3.3]` = round-1 report M6, section 3.3; the report holds the URL or file:line evidence. `{W3}` = item W3 of the verified ledger in §7 (S = strength, W = weakness, O = opportunity, T = threat). URLs are listed in §9, grouped by section.
- **Public safety.** Vaultex vulnerabilities appear only as *category + fix*. Code-level pointers to unfixed defects, business details of the internal first user, outreach targets, and secret names or locations stay in the private reports.
- **Thai primary texts** are cited through the counsel-ready brief [G6], law-firm guides and press. No sec.or.th document was opened for this report (owner instruction: that site serves its documents as file downloads).

---

## 0. Executive summary

### 0.1 Bottom line

Between 2025 and October 2026 the wallet-infrastructure market split in two.

- **Hosted developer, embedded and agent wallets** consolidated onto TEEs (mostly AWS Nitro) and into payment, exchange and custody platforms, at list prices of $0.001–$0.10 per signature {T10, T9}.
- **MPC kept the slices where control must be distributed:** regulated and institutional custody, self-hosted stacks, device-share embedded wallets and MPC-native agent wallets {T10}.
- **Losses moved above the keys.** In 7 of the 8 custody, wallet and bridge incidents of ≥$100M in 2024–26 (≈$3.4B in total, ESTIMATE from reported figures), legitimate signers, verifiers or withdrawal engines approved malicious payloads while the keys stayed intact {T4}.
- **Regulators formalised vendor due diligence and pulled custody in-house and onshore**, most concretely in Thailand [M5 §1; G6 §1; G8 §2].

For Vaultex this means threshold cryptography and "self-hosted" are commodities, and a customer veto hook at the signer is table stakes {T6}. The ground that may still be unoccupied is narrow: an OSI-licensed, fail-closed verification layer built into *every* signing node, with TRON TRC-20 first-class, sold as software that never holds key material {O2, T2}. That layer would decode the exact transaction, check approver signatures and a quorum-signed policy, and emit a signed receipt.

Vaultex is far from it today:

- it cannot sign ECDSA at production parameters, and its hand-rolled ECDSA engines are unsound;
- its key-generation transport leaks secrets, and its gateway is the only root of trust;
- it has no LICENSE file, no external assurance and no customer contact;
- it has had no commits since 2026-06-01 {W1–W7, W12}.

Assuming one full-time engineer from 2026-11-01 {T3}, the first audited regulated pilot is ESTIMATED at ≈Q4 2027 (range Q3 2027–Q1 2028; likely optimistic). With the owner alone and part-time (ROADMAP scenario a), it is not reachable without a second human; with a 0.5-FTE contract cryptographer the ROADMAP estimates its capped MPC pilot at ≈Oct 2027–Jan 2028 (ROADMAP §4.1). Either way it lands after the Thai Travel Rule date (2027-02-27).

### 0.2 What changed in 2025–2026

One line per shift; the evidence is in the cited ledger items (§7) and the sections named.

1. **Hosted wallets moved to TEEs:** Coinbase deprecated its MPC-based Server Wallet v1 from 2026-02-02 in favour of a Nitro-TEE v2, Lit replaced its threshold network with single-enclave TEEs (GA 2026-04-01), Privy, Turnkey, Magic (Core API) and thirdweb keep keys in Nitro, and Alchemy stopped new signer sign-ups on 2026-06-16 {T10}.
2. **Independent vendors were absorbed and custody was reshaped:** Privy→Stripe (2025-06), Web3Auth→Consensys (2025-06), Portal→Monad (2025-07), ZeroDev→Offchain Labs (2025-08), Dynamic→Fireblocks (2025-10), Fordefi→Paxos (2025-11), Palisade→Ripple (2025-11), Sequence+Coinme→Polygon (2026-01), Sodot→MoonPay (2026-04) and Zengo→eToro (reported 2026-04), with Magic's wallet business→Payward agreed (closing unconfirmed); BitGo listed on the NYSE, Standard Chartered is taking full ownership of Zodia, Copper is for sale, Anchorage bought Routable, DV8 (now ASTRA) signed to buy Rakkar after its reported closure (completion is a vendor claim) and Qredo Ltd was dissolved {O6, O11, T10} (§2).
3. **Prices compressed:** per-signature list prices down to $0.0015 (Turnkey Enterprise) and $0.001 (Privy Enterprise), $0.005 per operation (Coinbase CDP), free embedded wallets for eligible businesses (Polygon), and institutional entry SaaS at $299–$999 a month or $800 a year {T9}.
4. **Self-hosted and on-prem deployment became mainstream, mostly with a vendor-run control plane:** Fireblocks Hosted MPC and KeyLink, Ledger HSM On-Premise, Dfns hybrid and on-prem, Taurus, Builder Vault, Sodot, Circle (enterprise only) and Fystack mpcium {S3, T7}.
5. **Attacks moved to the signing decision:** 7 of the 8 ≥$100M incidents of 2024–26 succeeded without key theft, DPRK-attributed actors passed $1B stolen in 2026 (Chainalysis), and customer-run signer vetoes became standard {T4, T6} (§4).
6. **Threshold-crypto implementations kept breaking, and the field moved on:** CVE-2025-66016/66017 in the Kudelski-audited `cggmp21`, THORChain's GG20 loss (2026-05-15) and tss-lib's breaking v4 hardening; Axelar and Vultisig left GG20, current choices are CGGMP24, DKLs23, vendor protocols and FROST (RFC 9591), and NIST finalised its threshold call (IR 8214C, 2026-01-20) {T8} (§3).
7. **Confidence in TEEs was dented:** cheap memory interposers (TEE.fail, Battering RAM) broke SGX, TDX and SEV-SNP attestation, and Trail of Bits (2026-09-25) recommends MPC across heterogeneous TEEs with attestation bound to party identity {O7} (§3.5).
8. **Stablecoins drive demand, and TRON support has spread:** ≈$307B of USD-pegged stablecoins, ≈$94.2B of it on TRON (DefiLlama, 2026-10-08); the US GENIUS Act takes effect 2027-01-18; Privy, Turnkey and Polygon OMS now cover TRON, and institutional vendors ship TRON fee tooling {O8, T9}.
9. **Agentic payments: crowded supply, thin demand:** Coinbase, Circle, Fireblocks, Cobo and MetaMask launched agent wallets in 2026, AWS AgentCore payments (GA 2026-08-18) connects only Coinbase CDP and Stripe-Privy wallets, and x402 settlement was reported at ≈$40K a day in September 2026 {T10}.
10. **Regulation pulled custody in-house and made vendor review formal:** Thai no-delegation and ≥95% cold (since 2025-09-01), the Thai Travel Rule (from 2027-02-27), HK SFC 25EC44 independent code reviews, the end of MiCA's transition (2026-07-01), FIPS 140-2's move to NIST's Historical list (2026-09-22), and no Vietnamese pilot licence yet {O1, O9, O7} (§5).

### 0.3 What it means for Vaultex

1. **The commodity layers do not differentiate in 2026:** threshold cryptography (adopt audited libraries), "self-hosted", "open-source MPC", TRON support and a signer veto hook {T6, T7, O8, S1}.
2. **One combination may be unoccupied (HYPOTHESIS)** {O2}. Among the vendors and repositories examined, none ships OSI-licensed code in which *every* signing node:
   - decodes the exact transaction, with TRON TRC-20 first-class, and recomputes the digest;
   - verifies k-of-n approver signatures over a canonical intent;
   - evaluates a quorum-signed policy with per-node caps;
   - fails closed and emits a signed receipt.

   This is technically feasible at negligible cost {S2}. Fystack's Cosigner is moving toward part of it {T1}.
3. **Vaultex has real, verified assets:**
   - encoders pinned to official SDK vectors on 6 chains {S4};
   - a demonstrated path to an audited-library ECDSA core at production parameters {S1};
   - FROST through the ZF crates, already signing on the distributed path {S5};
   - a vendor-blind architecture {S3};
   - a dependency tree that permits MIT OR Apache-2.0 for the whole stack {S6};
   - sound secret hygiene {S7}.
4. **Its blockers are fundamental, not cosmetic:**
   - ECDSA cannot sign at production parameters and is unsound {W1, W2};
   - authorization is asserted by the gateway, not enforced by the signers {W3};
   - key-generation transport is not confidential, and peers can be impersonated {W4};
   - trust concentrates in one gateway key and one deployment secret {W5};
   - there is no backup or recovery, no durable state, no cold tier and no working multi-host deployment {W8–W10, W16};
   - there is one dormant maintainer, with no review, no assurance and no LICENSE file {W6, W7, W11}.
5. **The best-evidenced demand is in Thailand's licensed tier:** custodians first, then exchanges, brokers and dealers, driven by dated rules. Key-less compliance modules, such as Travel Rule wallet-ownership proofs, could be adopted before a custody core is audited. Both points are HYPOTHESIS, and no prospect has been contacted {O1, O4, O5, W12} [G8 §6].
6. **Timing is unfavourable.**
   - With one full-time engineer from 2026-11-01, an audited pilot is ESTIMATED at ≈Q4 2027 (range Q3 2027–Q1 2028).
   - First-year external assurance costs ≈$0.11M–$0.56M.
   - ISO 27001 and SOC 2 need a second accountable human {T3, O3} [G7 §0].
7. **Business shape.**
   - Sell self-hosted licences, support without key access, and services.
   - Never hold shares, KEKs, policy keys or recovery material [needs counsel] {T2}.
   - A profitable niche or a tuck-in is more plausible than a venture-scale company built on SEA alone (HYPOTHESIS) {O11}.
8. **Zero-cost steps to do now** {T5}:
   - a README warning;
   - a category-level security advisory;
   - private vulnerability reporting;
   - a LICENSE file;
   - disable auto-release;
   - SHA-pin the CI Actions;
   - gate off unsafe schemes and addresses.

### 0.4 Headline claims and their status

| # | Claim | Status | Evidence / cheapest next test |
|---|---|---|---|
| 1 | Hosted developer/server wallets moved to TEEs; MPC persists in regulated, self-hosted, device-share and MPC-native agent niches | VERIFIED | {T10}; [M2a §5; M2b §5] |
| 2 | 7 of 8 ≥$100M incidents in 2024–26 were signing-decision failures with keys intact | VERIFIED (a scoped selection; "keys intact" for Bitget and Drift rests on the victims' own accounts) | {T4}; [M8 §1] |
| 3 | Customer-run signer veto hooks are table stakes | VERIFIED | {T6}; [G5 §0.1] |
| 4 | An OSI-licensed stack where every node decodes, verifies approvals and policy, and emits receipts (TRON-first) is unoccupied | HYPOTHESIS (holds within G5's examined set) | Test: G5's broader sweep (Utila, Fordefi, Liminal, Taurus, Ripple, Silence, Lit, CDP, Privy, Turnkey) {O2} |
| 5 | Node-side decode-and-verify is feasible at negligible cost | VERIFIED at unit-test level (14/14) | {S2}; node integration not yet prototyped |
| 6 | LFDT-Lockness `cggmp24` can replace Vaultex's ECDSA at production parameters | VERIFIED (single host) | {S1}; multi-host p50/p99 is HYPOTHESIS (test: 3-region run) |
| 7 | Vaultex can sign ECDSA (BTC, EVM, TRON) on its production path today | REFUTED | {W1} |
| 8 | Thailand's licensed tier shows the strongest evidenced pain | Inputs VERIFIED; scoring HYPOTHESIS | {O1}; test: G8's D1 interviews |
| 9 | Flat self-hosted pricing is a wedge | REFUTED as a general claim; holds only at high volume against volume-priced vendors (HYPOTHESIS) | {T9} |
| 10 | TRON fee and operations tooling would set Vaultex apart | REFUTED (it would be catch-up) | {O8} |
| 11 | A vendor-blind, self-hosted licence sits outside Thai custodial-wallet licensing | HYPOTHESIS [needs counsel] | {T2}; test: written Thai counsel opinion |
| 12 | An audited pilot is possible before the 2027-02-27 Thai trigger | REFUTED in every capacity scenario (ESTIMATES: ≈Q4 2027 with one full-time engineer {T3}; not reachable solo part-time [ROADMAP §4.1]) | {T3}; [G7 §10; ROADMAP §4.1] |
| 13 | Vaultex has any customer contact or reference | Absent (to be confirmed with the founder) | {W12} |

---

## 1. Market map

### 1.1 Segments

| Segment | What is sold | Dominant key technology (2026) | Representative players | Typical buyer | Relevance to Vaultex |
|---|---|---|---|---|---|
| **A. Institutional custody technology** | MPC/HSM wallet platforms with policy and workflow, as SaaS, hybrid co-signer or on-prem software | MPC (often inside SGX or Nitro) or HSM; vendor protocols (MPC-CMP, KU23) | Fireblocks, Dfns, Cobo, Safeheron, Utila, Fordefi (Paxos), Taurus, Ripple Custody, Ledger Enterprise, Blockdaemon, Sodot (MoonPay), Fystack | Exchanges, brokers, PSPs, custodians, banks | **Vaultex's lane.** Vaultex aspires to be a self-hosted engine for regulated operators [M1 §2] |
| **B. Licensed custodians** | Legal custody under charters or licences: segregation, insurance, staking, settlement | HSM-centric or MPC, often bought from segment A | Coinbase, BitGo, Anchorage, Paxos, Zodia, Komainu, Hex Trust, Ceffu, Copper. SEA: orbix, Rakkar/ASTRA, Kryptodian, ICC (Indonesia) | Funds, ETFs, exchanges, corporates | Vaultex cannot compete here; these firms are possible technology buyers [M1 §1] |
| **C. Embedded / consumer WaaS** | In-app wallets created at sign-up; SDKs; recovery | TEE-held keys (the default); device-share MPC; passkey smart accounts | Privy (Stripe), Dynamic (Fireblocks), MetaMask Embedded Wallets, Magic (→Payward), Para, Portal, Crossmint, thirdweb, Polygon OMS, Coinbase CDP Embedded | Consumer apps, fintechs | Not worth pursuing head-on [M2a §10] |
| **D. Server-side, TEE and agent wallets** | API-controlled wallets, policy engines, agent wallets, x402 | TEE (Nitro) for hosted; MPC for Circle, Cobo and Fireblocks agents | Coinbase CDP, Turnkey, Privy, Circle, Lit, Cubist, Cobo, MetaMask; AWS AgentCore as distribution | Developers, AI-agent platforms | A phase-2 option only {T10} |
| **E. Open-source libraries and stacks** | Threshold-signature libraries; self-hostable node stacks | CGGMP24, DKLs23, FROST, OT-based ECDSA; legacy GG18/GG20 | LFDT Lockness, ZF FROST, Coinbase cb-mpc, Silence Labs, NEAR, tss-lib. Stacks: Fystack mpcium, Vultisig, OpenSigner, NEAR mpc | Integrators, vendors, in-house builders | Vaultex's core should be built on these. Fystack is the nearest stack {T1} |

The dated 2025–2026 shifts behind this map are summarised in §0.2, with their evidence in the cited ledger items (§7).

---

## 2. Competitor matrices by segment

Each matrix covers approach/protocol, deployment model, chains, key features, certifications, pricing and 2026 status; where two attributes share a column they are separated by "·". Prices are list prices fetched on 2026-10-08/09. "(claim)" = VENDOR CLAIM. "Not stated" / "not public" = not found by the cited report. Certifications are as reported by the vendor or secondary sources unless the cited report says otherwise.

### 2.1 Institutional custody-technology vendors (SaaS, hybrid, on-prem)

| Vendor (owner) | Approach / protocol | Deployment model | Chains / TRON | Key features | Certifications / audits | Public pricing | 2026 status | Src |
|---|---|---|---|---|---|---|---|---|
| **Fireblocks** | MPC-CMP (proprietary); MPC-BAM 2PC (reviewed by Trail of Bits); co-signers in SGX, Nitro or GCP Confidential Space; KeyLink HSM | SaaS. In the standard model the customer holds 1 share and Fireblocks Cloud Co-signers hold 2. "Hosted MPC" keeps all shares in the customer environment, still driven through the Fireblocks platform. The SGX co-signer must attest against Fireblocks' server | Broad; TRX/TRC-20 since 2022. Gas Station auto-fuels EVM **and** TRON | Policy engine (vendor-side; in SGX per vendor claim); simulation; co-signer callback (auto-signs if no handler is configured; opt-in `rawTx` for 18 chains or chain groups incl. TRX); Policy Inspector and auditor roles (2026-06-17); Agentic Payments Suite (2026-05-20); Global Custodian Partner Program | SOC 2 Type II (EY), ISO 27001/27017/27018, CCSS L3 QSP (claims/secondary) | Essentials $999/mo for up to 6 months ($1M outbound per quarter, then 0.20%); Custom from $36K/yr | Acquisitive: Dynamic (~$90M reported), TRES (~$130M reported). Pitches onshore MPC/KeyLink in Vietnam; default vendor in SEA licensed payments | [M1 §3.1; G5 §3.2]; {S3, T6, O8, T7} |
| **Dfns** | KU23 default (patented, closed); CGGMP24; FROST; signers in Nitro | SaaS; hybrid customer-run signers (Pro and up); on-prem with all signers customer-run (Enterprise) | TRON is Tier-1, but the Fee Sponsor feature is not available for TRON (Dfns points to native resource delegation) | Vendor-side governance engine; Validation Gate (customer HTTP veto; fails closed once enabled); DR "Layer 4" (shares re-encrypted to a customer key); 10 SDKs in 8 languages | SOC 2 Type II (KPMG, 2024 period) and ISO 27001/27017/27018 (2025), as stated by Dfns; no 2025/26 SOC 2 renewal found | Starter $800/yr (100 signatures/month, 1 chain); Basic $8K (1K signatures, 3 chains); Pro $35K (10K signatures, 10 chains; hybrid available from here, priced on request); Enterprise custom; no AUM or volume fees. SLA page 99.95%; legal SLA 99.90% monthly, credits capped at 7% | Rebranded as a "core banking platform" (2026-06); its CGGMP library lives on as LFDT Lockness | [M1 §3.19; M2b §3.4; G5 §3.3]; {T9, O8, W17} |
| **Cobo** | MPC-TSS, co-managed 2-of-3; SGX (claim); HSM option for full custody | SaaS. The customer's TSS Node (closed binary) holds 1 share and is gated by callback servers | 80+ chains (claim); TRON; Fee Station energy rental ("up to 80%" savings, claim) | Unlicensed callback template that rebuilds TRON/EVM/Solana transactions and matches hashes; separate library verifying Cobo Guard approver signatures; auto-sweep (Enterprise); Agentic Wallet with "Pacts" (vendor-side) | SOC 2 Type II (2023, possibly stale); ISO 27001 (claim) | Starter $299/mo (+0.20% above $300K); Standard $999/mo (+0.16% above $1.25M); Enterprise custom | Courting Thai custody migrations after Rakkar's closure announcement (2026-01); claims Orbix as a client | [M1 §3.7; G5 §3.4]; {T6, O8, T7} |
| **Safeheron** | MPC-TSS + SGX (DCAP); C++ libraries under a non-commercial licence | SaaS; API Co-Signer run by the customer (public docs do not say whether it holds a key share); MPC Node Suite (private, white-label) | TRON; energy rental (2025-03) | Co-signer auto-approves tasks routed to it by policy; TEE policy claims (the advertised TEE-Policy-Engine repo was not found); PQ ML-DSA pilot | Kudelski, SlowMist (claims); Least Authority (library) | Starter $5,750/yr (+0.1% above $12M/yr); Enterprise and Node Suite custom | Active (Singapore) | [M1 §3.8; G5 §3.5]; {T6, O8} |
| **Utila** | Proprietary 2-share MPC (cloud + device) | SaaS | 60+ (claim) incl. TRON; TRON staking, delegation and rental (2026-03) | Stablecoin-operations platform; 24/7 chat on Starter | SOC 2 Type II (claim) | Starter $799/mo (12-month term; ≤$3M outbound per quarter) | Growing; emerging-market focus | [M1 §3.18]; {O8} |
| **Fordefi (Paxos)** | 2-party MPC: vendor enclave + one customer API Signer per organisation | SaaS + customer signer | 90+ (claim) | Policy and simulation in the vendor backend; device-signed admin actions | — | Not public | Acquired by Paxos (>$100M reported, 2025-11-25); runs standalone | [M1 §3.5]; {O11} |
| **Taurus** | Thales HSM + MPC options; OSS `multi-party-sig` (README: not production-ready) | Managed, on-prem, hybrid | — | Bank custody, tokenisation, settlement | ISO 27001, ISAE 3402, FINMA (logos) | Not public | 40+ banks; State Street platform (2026-01-15) | [M1 §3.10; M6 §6(d)] |
| **Ripple Custody** (ex-Metaco) | HSM (Luna, Securosys) or cloud MPC, chosen per vault | SaaS or self-hosted; on-prem MPC not documented | — | Bank software; KMS Connect adapters | FIPS 140-2 L3 HSMs (now Historical) | Not public | Bought Palisade (2025-11) | [M1 §3.11] |
| **Ledger Enterprise** | HSM + personal security devices (EAL6+); clear signing | HSM On-Premise (available July 2026): signer in the customer's data centre, governance in Ledger-operated HSMs | — | Clear signing; governance quorum | EAL6+ devices | Multisig: ETH priority fee only | IPO paused (2026-05) | [M1 §3.12]; {S3} |
| **Blockdaemon Builder Vault** | DKLS23 (ECDSA), SEPD19S (EdDSA); Nitro option | Fully customer-hosted; LTS release train | Signs hashes; TRON not documented | Per-node policy written as customer SDK code; PKCS#11 plugin | NCC, CryptoExperts (claims); ISO 27001, SOC 2 (third-party profiles) | AWS Marketplace ~$2.28/h (secondary); licence by quote | v73 LTS (2026-05) | [M1 §3.20; G5 §3.7]; {T6} |
| **Sodot (MoonPay)** | DKLs23 + FROST inside a TEE | 100% self-hosted | Not listed | "Independent Policy Enforcement Per Share" (closed claim) | SOC 2 Type 2 (EY); Trail of Bits (2024-09), NCC (2025-09), Halborn | Quote | Acquired for ~$100M in stock (2026-04-28/29) | [M2b §3.8; G5 §3.8]; {O11} |
| **BitGo (as technology)** | 2-of-3 multisig; TSS (DKLs23 per Silence Labs, claim) | Qualified custody; self-custody wallets with BitGo co-signing; Advanced Wallets with customer KMS/HSM | TRX/TRC-20; resource-delegation API | Vendor-side policy; "real-time API attestations" (2026-04-30); open-source Wallet Recovery Wizard | OCC conditional charter (2025-12-12) | Self-custody wallets free ("may change"); custody in basis points | Q2-2026 assets on platform $65.2B, 5,833 clients | [M1 §3.2; G5 §3.6]; {T9, O8} |
| **Fystack** (Vietnam) | Fork of tss-lib v3 (GG18/GG20 family); DKLs23 branch with a private submodule | mpcium nodes (Apache-2.0) self-hosted + closed Apex backend that runs policy and holds the initiator key; SaaS | BTC, ETH, SOL, TRON, BSC, Base (10+); TronZap energy rental (2026-03); TRX gas tank (2026-04) | Encrypted P2P (ECDH + AES-GCM since 2025-08-13); reshare (2025-07); encrypted backups + recover CLI; optional authorizers (off by default, no k-of-n); Cosigner "coming soon" (feature-branch PRs merged 2026-10-07, logic in a private SDK); Securosys HSM option; TS/Go clients | Adevar audit of the closed Apex backend only (2026-06-17; 62 findings, 17 fixed); no public mpcium audit | Free; Pro $199/mo; Growth $499/mo (billed annually); self-host price unpublished; "no per-transaction cut" | 17 releases (v0.4.0, 2026-09-09); 193★; bus factor ≈2; Circle Alliance listing | {T1, T6, O8}; [G5 §2] |
| ***Vaultex (today)*** | ZF FROST (signs); hand-rolled GG20/CGGMP21/Stark (fail at production parameters; unsound) | Self-hosted only; vendor-blind | 6 testnet-validated (EVM, BTC, SOL, Sui, Aptos, TRON); 0 mainnet | Policy, approval, whitelist, velocity and audit libraries exist but are not wired into signing | None; no LICENSE file | None | Pre-alpha; no commits since 2026-06-01; 5★ | §7 |

### 2.2 Licensed custodians (global and SEA)

| Custodian | Licence / charter | Approach (key protection) | Deployment / products | Chains · pricing | Certifications / assurance | 2026 status | Src |
|---|---|---|---|---|---|---|---|
| Coinbase Custody / Prime | NY trust (not re-checked) | Cold storage + MPC; open-sourced `cb-mpc` (MIT) | Qualified custody, prime; >80% of US BTC/ETH ETF assets (secondary) | Broad · not public | HackerOne bounty (cb-mpc) | Company assets on platform $245.9B at 2026-06-30 (10-Q) | [M1 §3.3] |
| BitGo | OCC conditional conversion (2025-12-12); NYSE (2026-01-22) | 2-of-3 multisig + TSS | Custody, self-custody, WaaS, Go Network | TRX/TRC-20 · custody in basis points; self-custody wallets free ("may change") | — | AoP $65.2B; 5,833 clients (Q2 2026) | [M1 §3.2; G5 §3.6] |
| Anchorage Digital | OCC national bank | Air-gapped HSMs enforcing client quorum *and* Anchorage approval; Secure Enclave biometrics | Custody, staking, Porto self-custody | TRON custody (2026-03) · not public | — | Tether invested at $4.2B (2026-02); bought Routable (2026-10-06) | [M1 §3.4] |
| Paxos | OCC conversion (conditional; completion disputed) | Fordefi 2-party MPC (acquired) | Stablecoin issuer + custody | 90+ via Fordefi (claim) · not public | — | Fordefi runs standalone | [M1 §3.5] |
| Zodia Custody | MiCA CASP (Luxembourg, 2025-12) | FIPS 140-2 L3 HSMs + Dfns MPC | Custody; Zodia Solutions white-label WaaS | Not stated · not public | — | Standard Chartered buyout pending; CEO stepped down (2026-09) | [M1 §3.15] |
| Hex Trust | MAS MPI + CMS; HK TCSP; VARA | HSM (Securosys / IBM; sources conflict) | Custody | Not stated · not public | SOC 1 / SOC 2 Type 2, CSA STAR L2 (2026-03-10) | Canton super validator; Aura | [M1 §3.13] |
| Komainu | Regulated (not re-checked) | HSM + MPC across multiple providers | Custody, collateral | Not stated · not public | — | Active | [M1 §3.14] |
| Copper | US broker-dealer / FINRA; HK TCSP | MPC 2-of-3 (client / Copper / third party) | ClearLoop settlement | Not stated · not public | SOC 2 Type 2 (2023, stale) | For sale since 2026-05; CEO departing | [M1 §3.6] |
| Ceffu (Binance) | — | MPC on air-gapped share devices | Custodian for Binance TH (≥90% cold) and Tokocrypto | Not stated · not public | ISO 27001/27701, SOC 2 (claims) | Active | [M1 §3.16] |
| **orbix CUSTODIAN** (KBank, TH) | Thai MoF custodial-wallet licence 2024-09-13; live 2025-03-11 | IBM HSM; client + custodian approval for every transfer | Cloud-hosted custody; plug-in for clients' own key storage (claim) | Not stated · not public | HSM "FIPS 140-2 Level 4" (PR-based press; 140-2 is now Historical) | Candidate primary custodian for Thai crypto ETFs | [G8 §3.1 T-4]; {O7} |
| **Rakkar Digital → ASTRA** (TH) | Thai custodian licence (2024-12, claim) | Fireblocks MPC-CMP (2023 source, possibly stale) | Outsourced custodian to Bitkub and Maxbit (2026-07) | Not stated · not public | ISO 27001, SOC 1 Type 1, SOC 2 Type 1 & 2 (claims) | Closure reported 2025-12-24; DV8 share purchase signed 2026-03-24 (subject to SEC approval); relaunch 2026-04-27 (claim) | [G8 §3.1 T-5]; {O1, O6} |
| **Kryptodian** (TH) | Licence claimed (PR, 2026-09). Two register reads on 2026-10-08 conflict: one lists it as "(Not operating)", the other omits it | In-house MPC (claim) | Custody infrastructure and white-label: cold custody, KYT, Travel Rule, transfer engine, "Recovery as a Service" | Not stated · not published | ISO 27001 logo; SOC 2 blog title (claims) | Local competitor | [G5 §3.9; G6 §1]; {T7} |
| **PT Kustodian Koin Indonesia (ICC)** | First OJK-licensed crypto custodian (2025-12) | MPC + cold (claim); vendor unnamed | Holds ≥70% of consumer crypto by rule | Not stated · not public | — | Vendor undisclosed | [G8 §3.3 I-1] |
| **PT Arganis Konsultindo Utama** (ICEx group, ID) | OJK custodian licence KEP-11/D.07/2026 (2026-03-02) | Undisclosed | Custodian for ICEx members | Not stated · not public | — | Greenfield custodian | [G8 §3.3 I-2] |

Malaysia has three SC-registered custodians (CoKeeps, Gambit, Jada) with undisclosed vendors [G8 §3.5].

### 2.3 Embedded and consumer WaaS

| Player (owner) | Approach / architecture | Full key ever assembled? | Deployment · assurance (claims) | Chains / TRON | Key features | List pricing | 2026 status | Src |
|---|---|---|---|---|---|---|---|---|
| Privy (Stripe) | TEE default: 2-of-2 Shamir reassembled in Nitro; on-device mode optional | Yes, inside Nitro | SaaS · SOC 2 not stated on the pricing page | EVM, Solana; Bitcoin, Sui, Cosmos need TEE mode; TRON (2025; expanded 2026-09-23) | Policies and server signers require TEE mode; export; backs Stripe Treasury wallets | Free ≤499 MAU (50K sigs); $299 / $499; overage $2K base + $0.05/MAU + $0.01/sig; Enterprise from $0.001/sig | Inside Stripe; AWS AgentCore wallet | [M2a §3.1; M2b §3.10]; {T9} |
| Dynamic (Fireblocks) | Device-share TSS-MPC; 2-of-2 default in SDK V5 (2026-08) | Not during signing (claim) | SaaS · SOC 2 Type 2 and third-party audits (claims) | EVM, Solana, Bitcoin, Stellar, Sui, TON, Tempo, Arc; TRON not stated | Resharing, backups, export | Free ≤1K MAU; $249 (1–5K); $0.05/MAU | Acquired 2025-10-23 (~$90M reported) | [M2a §3.2] |
| MetaMask Embedded Wallets (Consensys) | Shamir with client reconstruction; MPC Core Kit (DKLS19, Enterprise only) | Shamir mode: yes, on the client | SaaS · SOC 2 Type II, 99.99% SLA, Kudelski and Cure53 audits (claims) | EVM and Solana native | 9 SDK frameworks | Free 1K MAW; $69; $399 | Web3Auth brand retired | [M2a §3.3] |
| Magic (→Payward) | TEE (TKMS) | Inside the TEE | SaaS · — | Not stated | Core API v1 shut off 2026-07-31 | Free 1K MAW; $99 | Agreement signed 2026-07-27; closing unconfirmed | [M2a §3.4]; {T10} |
| Para | 2-of-2 DKLS19: passkey-gated device share + server share in an HSM | No (claim) | SaaS · SOC 2 Type II, Least Authority audit (claims) | Not stated (Canton, Tempo added) | Provider-down backup kit; REST API (2026-02) | Free 1.2K MAU; $200 / $500 / $1,000 | Independent | [M2a §3.5] |
| Portal (Monad) | CGGMP, two 2-of-2 pairs | Only on "Eject" | SaaS · "open-source and audited" CGGMP (claim) | Not stated | Presignatures; stablecoin focus | Not public | Acquired 2025-07-09 | [M2a §3.6] |
| Openfort OpenSigner | Shamir device/hot/cold shares reconstructed in an iframe | Yes (iframe) | Self-hostable (MIT) · Quantstamp audit "underway" | Ethereum, Solana | Auth-agnostic; Docker self-host | Free 2K ops; $99 / $249 / $599 | Launched 2025-11-14 | [M2a §3.7] |
| Crossmint | Smart accounts + device/passkey keys | No (non-exportable P-256) | SaaS · MiCA CASP coverage (claim) | EVM, Solana, Stellar | On-chain limits and recovery | 1K MAW free; from $0.025/MAU | Independent | [M2a §3.8] |
| thirdweb | Enclave (Nitro) | Inside the enclave | SaaS · Halborn audit (claim) | Not stated | In-app wallets; export | $0.015 → $0.005/MAU | Repositioned toward AI agents | [M2a §3.9] |
| Sequence / Polygon OMS | Nitro signer + smart wallet | Inside the enclave | SaaS · Quantstamp/CoinCover attestations (claim) | 20+ chains; TRON USDT announced 2026-10-08 | Free unlimited embedded wallets for eligible businesses (2026-08-11); the free offer is not stated to cover TRON | Free (eligible) | Acquired with Coinme (>$250M combined, 2026-01-13) | [M2a §3.11]; {T9} |
| Coinbase CDP Embedded | TEE | Inside the TEE | SaaS · Coinbase brand | EVM and Solana accounts only | Export; delegated signing | $0.005/op; 5K free per month | GA 2025-10-16 | [M2a §3.15]; {T9} |
| Zengo (eToro) | 2-of-2 MPC (Lindell17 family, patched after BitForge) | No | Consumer app · — | Not stated | Consumer subscription | Free + Pro | Acquired for ~$70M (reported 2026-04-15) | [M2a §3.16] |
| Vultisig | DKLs23 (GG20 legacy), multi-device; "Fast Vault" with a server co-signer | Emergency tool only | User devices (+ VultiServer) · Trail of Bits on the library; app audits missing | Multi-chain incl. TRON (parsing in an unlicensed repo) | Open source; MIT verifier enforcing plugin policy | Free app; swap fees | VULT token | [M2a §3.17; G5 §3.10] |
| Alchemy | Exited key custody (new signer sign-ups ended 2026-06-16; users migrate to Privy) | — | — | — | Keeps the account-abstraction transaction layer | — | Exit | [M2a §3.12] |

**Reading.** This segment is owned by distribution platforms and is priced at cents per MAU or free. Table stakes are 4–9 client SDKs, passkeys, sub-second signing, seedless recovery, export, ERC-4337/EIP-7702 support and SOC 2. Vaultex has no device party, no WASM or mobile build, and no recovery, passkey or account-abstraction support [M2a §7, §9]. Verdict: not worth pursuing head-on [M2a §10].

### 2.4 Server-side, TEE and agent wallets

| Provider | Approach / key technology | Customer self-host? | Chains · assurance | Policy enforcement point | Agent features | Public pricing | 2026 status | Src |
|---|---|---|---|---|---|---|---|---|
| Coinbase CDP Server Wallets v2 / Agentic Wallets | Nitro TEE (MPC v1 deprecated from 2026-02-02) | No. Legacy v1 had a customer-hosted Server-Signer holding 1 of 2 shares | EVM and Solana only · Coinbase brand; cb-mpc HackerOne bounty | CDP policy engine (vendor side) | Agentic Wallet CLI/MCP; delegated signing; x402 facilitator ($0.001/settlement after 1K free) | $0.005/op (a send counts as 2); 5K free per month | AWS AgentCore partner | [M2b §3.1]; {S3, T9, T10} |
| Turnkey | Nitro + QuorumOS (AGPL); reproducible builds | No. The whitepaper names on-prem only as a future target | Chain-agnostic signing incl. TRON · SOC 2 Type II (trust-center excerpt); Trail of Bits reviews; Cure53 pentest (2025-07); bounty up to $50k | Inside the enclave (vendor) | Agent credentials, sessions, x402 signer | PAYG $0.10/sig; Pro $99/mo minimum + $0.05/sig (FAQ: can fall to $0.01); Enterprise from $0.0015 | TRON policy engine since 2025-05; $12.5M raised (2026-05) | [M2b §3.3; M7; G7 §2]; {S3, T9, O8} |
| Privy (Stripe) | Shamir reassembled in Nitro | No | See §2.3 · — | Inside the TEE (vendor) | Agent wallets; AgentCore | See §2.3 | — | [M2b §3.10] |
| Circle Wallets / Agent Wallets | 2-of-2 MPC | Shared hosting offered; customer hosting both nodes "available to enterprise customers"; user-controlled wallets always Circle-hosted | Arbitrum, Arc, Avalanche, Base, Ethereum, Monad, Optimism, Polygon PoS, Unichain, Aptos, Solana, NEAR; **no TRON** · not verified | Wallet layer (vendor); keyguard (customer, enterprise only) | Agent Stack (2026-05-11); Nanopayments | Per monthly active wallet, $0.038 → $0.012 signing-only (secondary) | Arc L1 (2026-09) | [M2b §3.2; G5 §3.1]; {S3, T6} |
| Lit Protocol (V3 "Chipotle") | Single-enclave TEE (threshold "Naga" network sunset) | dstack-compatible platforms | Not stated · — | Lit Actions in the TEE | Vincent agent wallets | $0.01 per second of execution | GA 2026-04-01 | [M2b §3.9] |
| Cubist | HSM inside Nitro (not MPC) | On-prem option | Validators, exchanges, payments · not verified | WASM policies | Use-case page only | Quote | Institutional push | [M2b §3.7] |
| Cobo Agentic Wallet | MPC with agent / human / Cobo shares | No | 80+ chains (claim) · SOC 2 Type II (2023) | "Pacts" enforced through Cobo's share (vendor-side) | Purpose-built agent wallet | Free early access | Launched 2026-04-20 | [M2b §3.14; G5 §3.4] |
| MetaMask Agent Wallet | Server TEE or bring-your-own seed | No | Not stated · loss coverage up to $10k/month (vendor) | Remote policy service + MFA | Guard / Beast modes | Free (early access) | Early access 2026-06-08 | [M2b §3.14] |
| AWS Bedrock AgentCore payments | Distribution layer | — | — | "Payment limits at the infrastructure layer" | x402 + MPP | — | GA 2026-08-18; only CDP and Privy connectors | {T10} |

**Reading.** Hosted TEE vendors sell latency (vendor claims of 20–200 ms), price and SDK reach. No hosted option offers customer-run signing except Circle at enterprise level and Dfns hybrid {S3}. Agent-wallet buyers pay for policy "enforced cryptographically, not as prompt instructions" [M2b §7.1]. Vaultex has none of the agent surface (0 lines of EIP-712, EIP-3009, Permit2 or x402 code) {T10}.

### 2.5 Open-source full stacks (libraries are in §3.4)

| Stack | Language | Crypto core | Open parts | Closed parts | Policy / approvals at the nodes | Audit | Status | Src |
|---|---|---|---|---|---|---|---|---|
| **Fystack** (mpcium + Apex) | Go | tss-lib v3 fork; DKLs23 branch (private) | mpcium nodes (Apache-2.0); policy library (MIT; not imported by mpcium); indexer (MIT); self-host scripts | Apex backend (policy, sole initiator key); `mpcium-sdk` (cosigner approvals); DKLs23 submodule | Optional authorizers: all of a list, or any subset including none; signatures over digests; nodes do not decode; results unsigned (issue #78) | Apex only (Adevar, 2026-06-17) | Active; v0.4.0 (2026-09-09) | {T1}; [G5 §2] |
| **Vultisig** | Go / Rust / TS / Swift / Kotlin | DKLs23 (Silence binaries, under Silence's non-commercial licence per a walletbeat submission); GG20 legacy | Apps; MIT verifier | Core DKLs licence; TRON-parsing recipes unlicensed | The verifier is a single share-holding gate that enforces plugin policy | Trail of Bits (library) | Consumer; very active | [M3 §3.4; G5 §3.10]; {O2} |
| **OpenSigner** (Openfort) | Go | Shamir, reconstructed in an iframe | MIT | — | — | Quantstamp "underway" | Active | [M2a §3.7] |
| **NEAR mpc** | Rust | OT-based ECDSA (cait-sith lineage), FROST, BLS key derivation | MIT | — | On-chain contract governance only | Trail of Bits ×4 | Production network, not custody | [M3 §3.1] |
| **Ika** | Rust | 2PC-MPC (crypto under CC BY-NC-ND) | Node code BSD-3-Clause-Clear | Non-commercial crypto | On-chain | Symbolic Software (2024) | Mainnet beta | [M3 §3.1] |
| **Lux mpc** | Go | CGGMP21, FROST, BLS, SR25519, PQ (claims) | Source-available | Commercial use outside Lux needs a paid licence | ? | None found | 0★ | [M3 §3.5] |
| **MPC-RS** | Rust | Lockness `cggmp21` 0.6 + ZF frost 3.0 | MIT | — | On the roadmap | None | Created 2026-10-06 — evidence that AI-built entrants are cheap | [M3 §3.5] |
| ***Vaultex*** | Rust | ZF FROST + hand-rolled ECDSA (to be retired) | All code public; no LICENSE file | — | Library-only; not enforced | None | Pre-alpha; dormant | §7 |

Pricing and chains: all stacks are free to self-host, and Fystack's commercial tiers are in §2.1. Fystack lists BTC, ETH, SOL, TRON, BSC and Base; NEAR mpc signs for foreign chains; Vultisig is multi-chain including TRON; OpenSigner covers Ethereum and Solana.

**Reading.** No mature, OSI-licensed, self-hostable, full-stack Rust custody platform was found (a negative cannot be proven) [M3 §4]. Vaultex's *scope* is a real gap, but it is filled with an unsound core. In this segment, credibility comes from audits, adopted cores and production evidence, not feature count [M3 §4].

---

## 3. Threshold cryptography: state of the art, vulnerability history, libraries

### 3.1 Protocol families in 2026

| Family | Online rounds | Heavy primitive | Security model | Bug history | Standards track | 2026 verdict |
|---|---|---|---|---|---|---|
| GG18 / GG20 | 1 after preprocessing (GG20) | Paillier + range proofs | Game-based; no UC proof | Worst record: Alpha-Rays, BitForge, TSSHOCK; THORChain exploited in 2026 | None (legacy) | **Retire** |
| CGGMP21 → CGGMP24 | 1 after 3 presigning rounds | Paillier + Πmod / Πfac / Πprm / Πenc / Πaff-g / Πlog* | UC, adaptive, proactive refresh, identifiable abort (in the paper) | CVE-2025-66016 and -66017 in the reference implementation | NIST preview (Fireblocks) | **Use through a maintained library (cggmp24), not hand-rolled** |
| DKLs23 (OT/VOLE) | 3 in total | OT / VOLE | UC; statistical claim corrected to computational (2026) | Devious Transfer; Trail of Bits findings | NIST preview | Sound choice technically; licence and audit status vary by implementation |
| Lindell17 / BAM (2-party) | 2-party | Paillier (Lindell17) | Game-based | CVE-2023-33242 (abort handling) | NIST preview (BAM) | Two-party products only |
| KU23 (honest majority) | Non-interactive online | Presignature batches | Honest majority | None public | NIST preview | Closed (Dfns) |
| FROST (RFC 9591) | 2 (1 with preprocessing) | Elliptic curve only | OMDL / ROM; adaptive AOMDL + LDVR, safe for n ≤ 131 at 128-bit security | DKG commitment-length check (2024) | RFC 9591 | **Use (ZF crates)** |
| FROST3 / BIP-445 + ChillDKG | 2 | Elliptic curve | As FROST; ChillDKG supplies a secure DKG | — | BIP drafts | Use for Taproot once vetted |
| MuSig2 (BIP-327) | 2 | Elliptic curve | n-of-n only | — | Deployed BIP | n-of-n only |
| Threshold BLS | Non-interactive | Pairings | Depends on the DKG | — | IRTF draft-07 | Validator / DVT niche; quantum-vulnerable |
| Threshold ML-DSA (Mithril, Quorus) | 3 per attempt + rejection | Lattice | Dishonest majority (Mithril) / honest majority (Quorus) | Too new | NIST previews; packages from 2027-03-01 | R&D only |

Source: [M4 §5.1, §9]; current revisions per [M4 §4.2–4.6].

### 3.2 Vulnerability history, 2021–2026

| Date | Name / ID | Target | Root-cause class | Impact |
|---|---|---|---|---|
| 2021-12 | Alpha-Rays (ePrint 2021/1621) | GG18/GG20 implementations | Missing range proofs; small Paillier keys accepted | Full key from 1–8 signatures |
| 2022-12 → 2023-04 | CVE-2022-47930 / 47931; CVE-2023-26556 / 26557 | tss-lib family | Fiat–Shamir replay and encoding; non-constant-time arithmetic | Key leakage |
| 2023-03 | BitGo "Zero Proof" (found by Fireblocks) | BitGo TSS | Missing Paillier-modulus proof | Key from one signature |
| 2023-08 | BitForge CVE-2023-33241 / 33242 | GG18/GG20; Lindell17 | Unvalidated modulus; abort handling | Key in ~16 signatures / ~256 attempts |
| 2023-08 | TSSHOCK (Verichains) | GG18/GG20/CGGMP21 implementations, many of them audited | Ambiguous hash encoding; forged dlnproof | Key in 1–2 signatures, with no abort |
| 2023-09 → | OT selective abort (Trail of Bits); "Devious Transfer" (Fordefi / Mysten) | OT-based ECDSA (DKLs19 reference; sl-crypto) | OT implementation bugs | Key extraction |
| 2024-02 | DKG threshold inflation (Trail of Bits) | 10 implementations, incl. ZF FROST (fixed) | Commitment length not checked | Unusable or locked keys |
| 2025-11-24 | **CVE-2025-66016** | Lockness cggmp21 < 0.6.3; cggmp24 < alpha.2 | A check missing inside Πmod, inherited from the CGGMP21 paper | One malicious signer reconstructs the key (critical) |
| 2025-11-24 | **CVE-2025-66017** | cggmp21 ≤ 0.6.3 (no patch); cggmp24 alpha.1 | Presignatures with raw-hash signing or late HD derivation | Forgery; ~85-bit security |
| 2025-11 | Upbit wallet flaw | Proprietary | Private keys inferable from on-chain signature data | Found in a post-incident audit |
| 2026-05-11 | DKLs23 statistical vs computational security (ePrint 2026/929) | DKLs23 security claim | Split view by an unbounded adversary | Claim weakened; one-element fix |
| 2026-05-15 | **THORChain GG20 exploit** | Production GG20 | "Progressive key material leakage". Third-party analysis cites skipped MOD/FAC checks; THORChain has not confirmed this | ≈$10.7M; a full vault key rebuilt |
| 2026-05 → 09 | tss-lib v4 hardening (PR #332) | GG18 lineage | Audit-driven: constant-time Paillier, NTilde ModProof, ≥2048-bit moduli, mandatory session nonce | Breaking release |
| 2026-01 → 09 | cb-mpc security releases | Coinbase cb-mpc | Paillier validation, memory safety, a two-party ECDSA issue | Patched |
| 2026-09 | LDVR cryptanalysis; FROST bounds | Adaptive threshold Schnorr | Attacks at very large n | FROST safe for n ≤ 131 (128-bit) |

Sources: [M4 §3; M3 §3.1, §5; M8 §3]; {T8}.

**The pattern** [M4 §0, §3; M8 §3]:
- The protocols mostly held. **Implementations failed** wherever they skipped or weakened a validation step the paper requires (Paillier modulus, ring-Pedersen parameters, range proofs, Fiat–Shamir encoding, session binding, abort handling, presignature binding), or where the paper itself was incomplete (CVE-2025-66016).
- Audited code was hit repeatedly.
- The most dangerous bugs are **silent**: TSSHOCK and BitForge cause no aborts.
- Adversarial, malicious-party test harnesses are now the expected standard.

### 3.3 What a production MPC wallet should use in 2026, per curve

| Curve / use | Recommendation | Implementation options (licence; audit status) | Avoid | Vaultex today |
|---|---|---|---|---|
| **secp256k1 ECDSA** (EVM, BTC legacy/SegWit, TRON, Cosmos) | CGGMP24 (dishonest majority) via a maintained library; DKLs23 where licence and audit allow; honest-majority schemes are legitimate for server clusters | **LFDT Lockness `cggmp24` 0.7.0-alpha.3** (MIT/Apache): the G1 spike gave a GO when pinned, using full interactive signing, the num-bigint backend, a background prime pool and a delta review. **Coinbase `cb-mpc`** (MIT, C++/C ABI; Cure53 audit 2024; 2026 security releases; HD derivation not BIP-32). DKLs23: Silence (non-commercial licence) or 0xCarbon (unaudited; NO-GO in G1). KU23 is closed | GG18/GG20; any hand-rolled Paillier/ZK code; presignatures with raw hashes or a late HD path | Hand-rolled GG20/CGGMP21: fail at production parameters and unsound → retire {W1, W2} |
| **Ed25519** (Solana, Sui, Aptos) | FROST (Ed25519, SHA-512) per RFC 9591, with a robust DKG | ZF `frost-ed25519` **3.0.0** (2026-04-23); the NCC audit covers v0.6.0 only | Deterministic or additive threshold nonces; homemade Ed25519 HD (SLIP-10 Ed25519 is hardened-only) | ZF frost 2.2.0 signs on the distributed path; key-generation transport must be fixed {S5, W4} |
| **Schnorr / Taproot** (BIP-340/341) | FROST3 per BIP-445 + ChillDKG (drafts), with ROAST for robustness; MuSig2 for n-of-n; check against BIP test vectors | ZF `frost-secp256k1-tr` (outside NCC audit scope); Lockness `givre` (no audit) | Untweaked keys for key-path spends; unreviewed custom refresh | Lacks the BIP-341 tweak; P2WPKH addresses shown for FROST-TR wallets cannot spend from them {S5, W15} |
| **Stark curve** (Starknet) | No bespoke threshold Stark ECDSA: use a Starknet account contract verifying secp256k1 (OpenZeppelin EthAccount), or the cggmp24 `curve-stark` feature (G1: signatures pass `starknet-crypto`) | OpenZeppelin Cairo v4.0.1; cggmp24 | Hand-rolled Paillier proofs over the Stark curve | Hand-rolled → retire {W2} |
| **BLS12-381** | Threshold BLS with a robust DKG and the IRTF draft-07 ciphersuites (proof of possession) | `blst` + a vetted DKG | Independent per-party keys labelled "threshold" | Single-party keys {W15} |
| **Sr25519** | No audited threshold implementation found (HYPOTHESIS); prefer FROST-Ed25519 accounts on Substrate | — | Placeholder implementations | Single-party keys {W15} |
| **Post-quantum (ML-DSA)** | R&D only: Mithril (small n) or Quorus (larger n); NIST packages from 2027-03-01 | Research code only | Production use before standards and audits | Prepare crypto-agility, PQ-hybrid transport and hybrid control-plane signatures [M4 §10] |

Sources: [M4 §11; G1 §0, §2.3]; {S1, T8}.

### 3.4 Library landscape: audits, maintenance, licences

| Library | Language | Protocols | Licence (OSI?) | Public audit (scope, date) | 2026 maintenance and issues | Verdict for an MIT/Apache product |
|---|---|---|---|---|---|---|
| **LFDT-Lockness `cggmp24`** | Rust | CGGMP24 + Lockness t-of-n extension; SLIP-10 HD; `curve-stark` | MIT/Apache ✔ | Kudelski (remote review, June 2023; effort not stated) of a **2023-05-26 commit, 545 commits before alpha.3**; no public review of the 2025 CVE fixes | Active (pushed 2026-10-05) but alpha since 2025-12. Published alpha.3 compiles only with pinned sub-crates (#211). No threshold refresh (#237) or identifiable abort (#111). Message-size DoS limits left to the transport (#209, #136). Hardening on HEAD is not in alpha.3 | **Adopt, pinned**, plus a delta review {S1, T8} |
| Lockness `cggmp21` 0.6.3 | Rust | CGGMP21 | MIT/Apache ✔ (but forces LGPL GMP) | As above | Upstream says upgrade to CGGMP24; CVE-2025-66017 has no patched version | **NO-GO** [G1 §0] |
| Lockness `givre` | Rust | FROST (secp256k1, Ed25519, BIP-340) | MIT/Apache ✔ | None listed | 0.3.0 (2026-08-12) | Option for Taproot after review |
| **ZF `frost`** | Rust | RFC 9591 FROST incl. secp256k1-tr; DKG, refresh, repair | MIT/Apache ✔ | NCC 2023 of v0.6.0 (excludes secp256k1-tr and re-randomised FROST); Least Authority 2025 (demo tools) | v3.0.0 (2026-04-23); active | **Use; upgrade to 3.x** {S5, T8} |
| **Coinbase `cb-mpc`** | C++ (C ABI; Go wrapper) | ECDSA-2PC/MPC, Schnorr/EdDSA, PVE backup | MIT ✔ | Cure53 (Q4 2024); HackerOne | Security releases 2026-01, -03, -09; no WASM or mobile; HD not BIP-32 | Viable FFI alternative |
| Silence Labs `dkls23` | Rust | DKLs23 | **Non-commercial (SLL)** ✘ | Trail of Bits (report 2024; 15 issues, 2 high) | Active | Needs a commercial licence |
| 0xCarbon `DKLs23` | Rust | DKLs23 (secp256k1, P-256) | MIT/Apache ✔ | None found | Small team; fails to compile against stable k256 0.14; OT setup message 1.09 MB (over the NATS default); mandatory permanent-ban policy on aborts | **NO-GO** for funds [G1 §0] |
| NEAR `threshold-signatures` | Rust | OT-based ECDSA (robust variant is a stub), FROST, BLS CKD | MIT ✔ | Trail of Bits ×4 (2025–26) | Production network | Reference; coupled to NEAR |
| bnb-chain `tss-lib` | Go | GG18/GG20 family | MIT ✔ | Kudelski 2019 (stale) | v3.0.0 (2026-04-09); v4 hardening (≈2026-09-23); an old fork was exploited at THORChain | Legacy |
| Taurus `multi-party-sig` | Go | CMP + FROST | Apache ✔ | None; README says not production-ready | GO-2024-3288 fixed; low activity | No |
| getamis `alice` | Go | Hierarchical CGGMP / FROST | Apache ✔ | Kudelski 2020 / 2022 | v1.0.8 (2026-09-11) | Go reference |
| Fireblocks `mpc-lib` | C++ | MPC-CMP | GPL-3.0 (copyleft) | None listed | Sporadic | Copyleft |
| Safeheron `multi-party-sig-cpp` | C++ | GG18/GG20/CMP | **Non-commercial** ✘ | Least Authority (2023–24) | Active | No |
| Entropy `synedrion` | Rust | CGGMP'24 | AGPL (copyleft) | "Not audited" | **Orphaned** (Entropy wound down, 2026-01) | No |
| ZenGo `multi-party-ecdsa` | Rust | GG18/GG20/Lindell17 | GPL | Old | "No longer maintained" | No |

Sources: [M3 §2–3; M4 §5.2; G1 §2]; {T8}.

**Library adoption facts from the G1 spike** (VERIFIED, single host) {S1}:
- `cggmp24` ran 2-of-3 at production parameters (1536-bit safe primes, 3072-bit Paillier) over Vaultex's own transport.
- p50 timings: aux-info 8.59 s, key generation 6.7 ms, signing 724 ms (325 ms with the LGPL `rug` backend).
- The largest wire message was ≈692 KB, 66% of NATS's 1 MiB default.
- Safe-prime pregeneration took 15.6–107 s per party, so a background prime pool is mandatory.
- Full interactive signing with a prehash plus HD derivation is safe on cggmp24. Only presignatures are the dangerous mode [G1 §2.3].
- The library requires authenticated senders, encrypted P2P messages, unique execution IDs and transport-level message-size caps [G1 §2.5].

### 3.5 TEEs, side channels and post-quantum

- **Side channels.** `num-bigint`, cggmp24's default backend, is variable-time, and Lockness declares timing attacks out of scope. Mitigations: `rug`'s `secure_pow_mod` (LGPL), `crypto-bigint`, or a documented threat model with dedicated hosts. tss-lib v4 turned constant-time Paillier decryption on by default [M4 §7].
- **TEEs.**
  - Physical interposer attacks: TEE.fail (<$1,000, DDR5), Battering RAM (<$50, DDR4) and WireTap broke SGX, TDX or SEV-SNP attestation. None was shown against AWS Nitro in the sources found.
  - Nitro-specific work: a last-level-cache side-channel paper (SysTEX '26) and Trail of Bits' note that Nitro attestation documents can be replayed (2026-08-05).
  - Trail of Bits (2026-09-25) recommends TEEs as defence in depth for MPC: heterogeneous vendors, attestation bound to party identity, and protection against presignature rollback [M2b §5.3–5.5].
- **Post-quantum.**
  - Threshold ML-DSA is practical for small groups (Mithril, Quorus; USENIX Security 2026).
  - No chain Vaultex supports accepts ML-DSA.
  - Ethereum targets a quantum-resistant L1 by December 2029, with EIP-8141 planned for Hegotá (2027). Bitcoin BIP-360/361 are drafts. OpenZeppelin ships Falcon-512 Starknet accounts.
  - Prepare now: versioned scheme identifiers, PQ-hybrid transport (X25519 + ML-KEM), and hybrid Ed25519 + ML-DSA control-plane signatures [M4 §4.10, §10].
- **Standards.**
  - RFC 9591 (FROST).
  - BIP-445 got its number on 2026-01-30 and is still a draft; ChillDKG is PR #2227 (2026-07-30).
  - NIST IR 8214C (2026-01-20): packages are due no earlier than 2027-03-01.
  - No threshold ECDSA/EdDSA standard exists, so an MPC protocol cannot be FIPS-validated as such. Vendors meet FIPS through validated modules for randomness, share encryption and KEKs [M4 §4.11; M5 §10.4].

---

## 4. Incidents 2022–2026 and the controls they imply

### 4.1 The ≥$100M custody, wallet and bridge incidents of 2024–2026

| Date | Victim | Loss (USD) | Vector | Keys stolen? | Multisig / MPC present? | Attribution | Controls that would have prevented it |
|---|---|---|---|---|---|---|---|
| 2024-05-31 | DMM Bitcoin | ~$305–308M | Social engineering of an employee at wallet vendor Ginco → a legitimate transaction request was manipulated | No | Vendor wallet system | TraderTraitor (FBI / NPA) | C1, C2, C3 |
| 2024-07-18 | WazirX (via Liminal) | ~$230–235M | Signing UI did not match the payload → malicious Safe upgrade via delegatecall | No (victim and vendor accounts conflict) | Safe 4-of-6 | Lazarus | C1, C2, C3 |
| 2025-02-21 | Bybit | ~$1.46–1.5B | Developer machine → cloud session token → tampered Safe{Wallet} JavaScript → delegatecall upgrade of the cold wallet | No | Safe multisig | TraderTraitor (FBI PSA 2025-02-26) | C1, C2, C9 |
| 2026-04-01 | Drift Protocol | ~$280–285M | Months of social engineering → blind-signed durable-nonce transactions; 2-of-5 council with zero timelock | No (victim's account) | 2-of-5 multisig | DPRK indicators | C1, C3, C6 |
| 2026-04-18 | KelpDAO (LayerZero) | ~$290M | 1-of-1 verifier fed poisoned RPC data | No | Verifier quorum of 1 | TraderTraitor (preliminary) | C7, C11 |
| 2026-07-30 onward | Coldcard users | ~$111–116M (preliminary) | Firmware build error → weak RNG → seeds brute-forced | **Yes** | No (single-sig) | Unattributed | C10 |
| 2026-09-06 | Liquid federation | ~$319M gross; ~85% returned | Bug in range-proof verification let unbacked L-BTC through | No | 11-of-15 federation | Unattributed | C10, C11 |
| 2026-09-24/25 | Bitget | $351.6M → $387.5M | Zero-day in third-party security products → wallet job server → forged withdrawals that "bypassed existing risk controls" | Reportedly no (victim's account) | Unknown | DPRK (Chainalysis, 2026-10-01) | C2, C3 at the signer |

Sources: [M8 §1–2]; {T4}. The total of ≈$3.4B sums the reported figures (ESTIMATE).

**Context and caveats** {T4}:
- The eight are a scoped selection, not a census.
- Broader 2024–26 lists of ≥$100M events also include:
  - DeFi contract-logic exploits (Cetus, Balancer);
  - PlayDapp's ~$290M nominal mint (≈$32M realised; suspected leaked key);
  - two single-victim social-engineering thefts (~$230–245M in Aug 2024; ~$330M in Apr 2025).
- Attribution for 2026 comes from private firms and is partly preliminary.
- Aggregates: TRM counted H1-2026 hack losses at $972M, with DPRK at $643M (66%). CertiK counted ≈$1.3B over 344 incidents [M8 §6].

**Earlier pattern (2022–2023)** [M8 §1, §2.3–2.4]:
- Hot-key and host compromise: CoinEx, Poloniex, HTX/Heco, Stake, Mixin, CoinsPaid.
- Threshold concentration, or "decentralisation theatre":
  - Ronin: 5 of 9 keys, four run by one operator;
  - Harmony: 2-of-5;
  - Multichain: every node in the CEO's cloud account;
  - Orbit.
- Lesson: count independent failure domains, not shares.

**MPC implementations still fail in production** [M8 §2.6]:
- THORChain's GG20 (2026-05-15; ≈$10.7M): a newly churned-in node rebuilt a full vault key.
- The Kudelski-audited `cggmp21` shipped CVE-2025-66016.
- Upbit's post-incident audit (2025-11) found keys inferable from on-chain signatures.

**Supply-chain incidents that apply to a Rust MPC vendor** [M8 §4]:
- tj-actions / reviewdog GitHub Actions compromise (CVE-2025-30066/30154);
- typosquatted crates.io crates that stole keys (2025);
- the npm chalk/debug maintainer phish (2025-09-08);
- Kiln's CI/CD → API pod tampering (SwissBorg, 2025);
- Ledger Connect Kit (2023);
- the Safe UI tampering behind Bybit.

### 4.2 Required controls

| Code | Control | What a 2026 MPC product must do | Vaultex today (category) |
|---|---|---|---|
| C1 | Signer-side verification of intent | Each signing node receives the unsigned transaction, decodes it, recomputes the digest and fails closed if it cannot decode. Approvers see the decoded intent on an independent device | **Absent.** Nodes sign digests supplied by the gateway {W3}. Feasible on existing seams {S2} |
| C2 | Policy enforced by the signers | Node-pinned, quorum-signed policy bundle:<br>- address book with a cooling-off period;<br>- (chain, contract, selector) allowlists;<br>- deny upgrades, delegatecall and authority changes by default;<br>- per-transaction and rolling caps | **Library-only; needs redesign** {W3} |
| C3 | Signed, payload-bound human approvals verified by the signers | k-of-n approver signatures over a canonical intent statement, from device-bound keys, with separation of duties | **Absent.** Counts are asserted by the gateway {W3} |
| C4 | Wallet tiering | Hot cap; warm tier with a human quorum and a delay; offline cold tier | **Absent** {W10} |
| C5 | Velocity limits, outflow monitoring, automatic circuit-breaker | Per-node caps; value-aware anomaly detection; auto-pause | **Absent.** Freeze exists but is manual {W9} |
| C6 | Timelocks on high-risk operations | Delays with a cancel path for admin and high-value actions | **Absent** |
| C7 | Independent key holders and failure domains | Separate people, organisations, cloud accounts and secret stores per node | **Weak.** One deployment secret and one gateway key {W5} |
| C8 | Hardened privileged endpoints and identities | Phishing-resistant, hardware-bound credentials; no long-lived tokens | Mostly the operator's job. The maintainer's own endpoint is a supply-chain risk {T5} |
| C9 | Supply-chain and deployment integrity | Signed, reproducible releases; SHA-pinned CI; two-person review | **Weak** {W11, T5} |
| C10 | Crypto-implementation assurance | Audited, maintained libraries; enforced proof checks; entropy tests; control over admitting signers | **Absent.** Unsound engines; no audit {W1, W2, W14} |
| C11 | Diversity of data sources and verifiers | Multiple RPC sources; no 1-of-1 verifiers | **Weak** [M8 §8.2] |
| C12 | Insider and offboarding controls | Least privilege; just-in-time access; revocation | A one-person team cannot evidence separation of duties {W6} |

Source: control definitions and matrix [M8 §5]; Vaultex status from ledger items as cited.

### 4.3 Lessons turned into product requirements

1. **MPC is necessary but not sufficient.** In most large losses every share-holder signed what a compromised layer presented. A crypto-only audit would fail Vaultex's current engines and would also leave the authorization path behind 7 of the 8 incidents unexamined. Audit scope and acceptance tests must cover both {T4}.
2. **Build incident replays into CI** {T4, O2} [M8 §9]:
   - delegatecall or upgrade payloads (Bybit, WazirX);
   - authority changes (Kiln);
   - a tampered legitimate withdrawal (DMM; the fields altered are unpublished, so "destination swap" is an inference);
   - a risk engine that says yes (BigONE, Bitget);
   - poisoned data (KelpDAO).

   The public bar: neither a compromised gateway nor a single compromised node can obtain an out-of-policy signature.
3. **Fail closed by default.** Competitors' hooks are open by default {O2, T6}:
   - a Fireblocks co-signer with no callback auto-signs;
   - mpcium authorizers are off unless configured;
   - the Dfns gate runs only when a URL is configured.
4. **Detection limits losses.** THORChain's solvency checker halted chains within about 52 minutes; Upbit froze transfers after 27 minutes; Ronin went 6 days unnoticed [M8 §6 T6].
5. **The vendor is part of the customer's trusted computing base.** CI, release signing and developer endpoints are assessed, as DMM (Ginco), Bybit (Safe) and Kiln show [M6 §4.3; M8 §6 T3].

---

## 5. Regulation and certification (short; legal work deferred)

- **Perimeter.** The vendor never holds shares, KEKs, policy keys or recovery material, and clients can transfer and recover without it [needs counsel] {T2, S3}.
- **Thailand.** Customer-run stacks only, with no Vaultex-hosted co-signer; custodians also need a ≥95% cold tier (since 2025-09-01) [needs counsel] {O1, W10}.
- **Vendor review is formal:** independent code review, pentests and audit rights {O9}.
- **Certification:** FIPS 140-3 modules only; never "FIPS-certified MPC" {O7}.

Open questions for counsel (ROADMAP §3.7, questions 1 and 3):
- Is a self-hosted licence plus paid support without key access outside the Thai custodial-wallet perimeter? [needs counsel]
- Does a self-hosted licence count as outsourcing for a Thai licensee, and which contract terms does that require? [needs counsel]

Other questions are deferred (the owner directs legal work later). Assurance cost and lead-time ESTIMATES are in {O3} and {T3}.

Sources: [M5 §1, §11; G6 §1, §6.1; G7 §8].

---

## 6. Business models, pricing benchmarks, SEA demand and beachheads

### 6.1 What the market is worth, and what the numbers measure

- **Headline "custody market" sizes** of $650B–$1.05T measure assets held, not money spent on custody. "MPC wallet market" estimates for the same year differ 20–30× ($71M against $1.4B–$1.8B). None is fit for planning [M6 §2.1].
- **Revenue proxies** [M6 §2.2]:
  - Fireblocks ≈$124M revenue in 2024, unprofitable (Forbes);
  - BitGo subscriptions and services $121.5M in 2025;
  - Safe ≈$10M annualised revenue (Q1 2026; vendor).
  - Total vendor revenue for institutional wallet, MPC and key-management software is plausibly in the high hundreds of millions to low billions of USD (HYPOTHESIS).
- **Stablecoin demand** [M6 §2.3]: ≈$307B USD-pegged supply, ≈$94.2B of it on TRON (DefiLlama, 2026-10-08). Real stablecoin payments ran at ≈$390B a year (December-2025 annualised run rate), ≈$226B of it B2B (McKinsey/Artemis, read second-hand).
- **Thai licensed market** (SEC data via Thai press) {T7}:
  - average daily turnover THB 1.378B in July 2026, −27% on June; H1-2026 months THB 1.74–2.03B; ≈THB 2.41B in 2025;
  - active accounts ≈151K (Dec 2025) → ≈121K (Jul 2026);
  - USDT ≈66% of trading value in July 2026 and a reported 76% in August {O1}.
- **SEA serviceable market:** 150–400 prospects × $12K–$60K a year ≈ **$2M–$24M a year**. This is HYPOTHESIS and an upper bound; it supports a profitable niche or an acquisition, not a venture-scale company on SEA alone {O11} [M6 §2.4].
- **Agent payments** (the trackers are not one time series) {T10}:
  - CoinDesk (2026-03-11): x402 ≈$28K/day, unadjusted, with Artemis judging about half of transactions artificial;
  - CCN (2026-08-13, Helios data): −93% year to date;
  - American Banker (2026-09-18): ≈$800K/day in January → ≈$40K/day in September.

### 6.2 Pricing archetypes and list-price benchmarks

| Archetype | Examples | Fit for a stablecoin operator |
|---|---|---|
| A. Assets-under-custody bps + transaction bps | BitGo custody; Fireblocks Off-Exchange (3–30 bps) | Poor |
| B. Subscription + outbound cap + % overage | Fireblocks 0.20%; Cobo 0.16–0.20%; Safeheron 0.10%; Utila caps | Poor at scale (a volume tax) |
| C. Tiers by seats, wallets or signatures, no volume fee | Dfns | Good, but signature caps push PSPs to Enterprise |
| D. Pure usage (operation, signature, MAU, MAW) | Turnkey, Coinbase CDP, Privy, Circle, Dynamic, Para | Cheap, but keys sit with the vendor or its TEE |
| E. Flat self-hosted licence / open-core / white-label | Fystack, Safeheron Node Suite, Dfns on-prem, Sodot (before acquisition), Safe Pro | Best fit for buyers wanting key control and cost certainty |
| Variant: vendor holds one key | Casa $2,750/yr; Unchained $7,500/yr; BitGo free self-custody | **Not available to Vaultex for Thai customers** {T2} |

Source: [M6 §3.2].

**List prices** (fetched 2026-10-09) are in the pricing columns of the §2 matrices; the worked example for a SEA PSP sending $10M a month (≈100K signatures) is in {T9}.

### 6.3 Where self-hosted flat pricing wins, and where it does not

- **Wins against volume-linked vendors at high outbound volume**, and against per-signature vendors only at list rates and high signature counts {T9}.
- **Against negotiated per-signature rates** ($0.001–$0.0015), self-hosting breaks even only at millions of signatures a month: ≈1–5M with G2's inputs, or ≈10M if one or more FTE of 24/7 operations is counted (HYPOTHESIS) {T9}.
- **At startup volumes** (3K–10K signatures a month) {T9}:
  - Turnkey Pro costs ≈$150–600 a month and Privy plans $0–499;
  - Vaultex self-hosting would need ≈$4–12K a year of infrastructure (M2b estimates $6–36K for HA), at least 0.25 FTE on call (24/7 realistically needs 1+ FTE) and at least 4–6 months to a capped pilot (all HYPOTHESIS).
- **Sticker comparison.** M6's proposed startup ($6K/yr) and growth ($18–30K/yr) tiers are 25% and 14–49% below Dfns Basic and Pro on sticker price (M6 also proposes an Enterprise tier from $60K/yr). Once the buyer's own infrastructure and on-call are added, they come out roughly level or higher (HYPOTHESIS). At 10K signatures a month or fewer, no tier is cheaper than Turnkey Pro or Privy {T9} [M6 §8.2].
- **No named SEA PSP was found complaining publicly about volume fees** (absence of evidence, not proof) {T9} [G8 §6].
- **Conclusion: price is not the wedge.** Inspectability, onshore control and compliance features are {T9}.

### 6.4 Open-source monetisation and licence choice

- **The pattern: primitives free, platforms paid.** Large vendors publish cryptography (Coinbase cb-mpc, MIT; Fireblocks mpc-lib, GPL; Dfns→LFDT Lockness, Apache) and keep policy, approvals, integrations, monitoring and SLAs closed. Fystack, Cobo, Dfns and Fireblocks all keep the *decision layer* closed {S6} [M6 §5.1].
- **Licence moves elsewhere.** HashiCorp's BSL triggered forks (OpenTofu, OpenBao). Elastic and Redis returned to AGPL. Restrictive terms deter enterprise embedding and weaken the customer's right to fork, which is continuity insurance for a tiny vendor [M6 §5.2]. Enforceability of restrictive terms on AI-assisted code is unclear [needs counsel] {O6}.
- **Recommended direction** (HYPOTHESIS; needs legal confirmation) {S6, W7} [M6 §5.4]:
  - MIT OR Apache-2.0 for the whole stack, decision layer included, with a NOTICE file;
  - consent from the copyright holders behind both contributor accounts;
  - a DCO or CLA before outside contributions;
  - a trademark check of "Vaultex" (older firms use the name).
- **Revenue model compatible with the Thai perimeter** [needs counsel] {T2}: self-hosted licences, support without key access, and services (deployment, key ceremonies, the compliance pack). Never a hosted share, recovery service or policy key for Thai customers.

### 6.5 SEA demand: named organisations, disclosed vendors and dated triggers

**Named universe** [G8 §0, §3–4] {T7}:
- 52 organisations in five countries (Thailand 18, Vietnam 10, Indonesia 10, Philippines 6, Malaysia 8), plus about 20 more screened.
- About 24 of the 52 (23–29 depending on classification) disclose no custody or wallet vendor. These are the open doors, concentrated in new custodians and mid-tier brokers.

**Disclosed vendors:** Fireblocks is the most frequent (8 of 52); the full map is in {T7}.

**Dated triggers** {O1} [G8 §2]:

| Date | Jurisdiction | Trigger | Who must act |
|---|---|---|---|
| 2025-09-01 | TH | Custodians: no delegation of custody; ≥95% of client value cold | Licensed custodians |
| 2025-12-24 → 2026-04-27 | TH | Rakkar closure reported → DV8 share purchase (2026-03-24) → ASTRA relaunch (claim). No client churn evidenced: Maxbit appointed Rakkar in July 2026 | Rakkar's clients |
| 2026-01-20 | VN | Licence applications open; five files complete; no licence issued as of 2026-10-08 | Pilot applicants |
| 2026-03-02 / 03-12 | ID | Arganis licensed as custodian; another custodian's licence revoked | New custodians; the affected custodian's clients |
| 2026-07-13 | TH | BOT and SEC announce audits of high-volume USDT transactions | All USDT handlers |
| 2026-09-01 | VN | Decree 284 penalties in force | Unlicensed firms and investors |
| 2026-09-11 → 09-25 | TH | Stablecoin transfer-controls consultation: same-owner wallets; THB 5M per customer per day per operator; blockchain-analytics screening; end-2026 target (indicative) | Exchanges, brokers, dealers (not custodians) |
| 2026-09-15 | VN | Draft circular: weekly hot/cold reports; 7 days' notice before engaging or replacing a third-party custodian | Future licensees |
| 2026-08 → 10 | TH | Crypto-ETF consultation makes Thai-licensed custodians the primary custody route (final terms unverified) | Custodians, asset managers |
| **2027-02-27** | TH | **Travel Rule in force**: self-hosted wallet ownership/control checks; ≥5-year retention | All Thai DA operators |

**Segment scoring** (G8's HYPOTHESIS on sourced inputs; out of 21) {O1} [G8 §6]:

| Segment | Score |
|---|---|
| Thai licensed custodians | 18 |
| Thai licensed exchanges, brokers and dealers | 17 |
| Vietnam pilot licensees | 15 |
| Indonesian custodians and new licensees | 14 |
| Malaysian DAX/DAC operators | 13 |
| Licensed payment and e-money stablecoin pilots | 10 |
| Philippine VASPs and banks | 9 |
| Unlicensed TRON PSPs and OTC desks (M6's original beachhead) | 7 |

On G8's four pain criteria alone, custodians lead with 11/12, while Thai exchanges/brokers and Vietnam tie at 9/12. The custodians' lead in the total comes from reachability, open doors and compliance safety {O1}.

**What a Thai licensed buyer will likely require before a pilot** (inferred from regulation and incumbents' marketing, not from interviews; HYPOTHESIS) {T7} [G8 §7]:
- **Fixed by regulation:**
  - ≥95% cold storage (custodians only);
  - the Travel Rule;
  - KYT (so far only in the stablecoin draft);
  - pentests and independent security audits;
  - outsourcing-contract terms with SEC inspection rights. Whether a self-hosted licence counts as outsourcing is [needs counsel].
- **Market expectations, not rules:**
  - an external threshold-crypto audit;
  - ISO 27001, then SOC 2 Type 2;
  - HSM/KMS wrapping of key shares;
  - source escrow;
  - Thai 24/7 support;
  - 1–3 named production references.
- **Vaultex today meets none of the listed items.** Its vendor-holds-no-keys design does fit the separate "vendor holds no key material" expectation {T7}.

**Partners** {O6} [G8 §5]: G8 found 11 possible integrators or channel partners: systems integrators tied to Vietnamese applicants, an HSM supplier, a regional TSS security auditor and a Thai industry association. None has been contacted, and the named list is kept private. LynkiD (CAEX), Bithumb (SSID) and Dunamu (ICEx) are competitors in Korean exchange-in-a-box packages.

### 6.6 Beachhead options

| Option | Segment (public vendor disclosures: §2.2/T7) | Evidence of pain or trigger | Must exist first | Assessment |
|---|---|---|---|---|
| **1. Thai licensed custodians** | licensed custodians (two confirmed) | No-delegation + ≥95% cold; ETF custody; Rakkar continuity shock | External audit, ISO/SOC 2, HSM/KMS wrapping, ≥95% cold tier, Travel Rule/KYT, escrow, local entity, Thai 24/7 support | Best evidenced (18/21), but the bar is highest. Audited pilot unlikely before H2 2027 {O1, T3} |
| **2. Thai licensed exchanges, brokers and dealers** | licensed exchanges, brokers and dealers | Travel Rule 2027-02-27; stablecoin same-owner rule and THB caps; USDT ≈2/3 of value | For key-less modules: ownership-proof verifiers and a fail-closed Travel Rule gate (no custody core needed) | Entry through **key-less compliance modules**, not core custody (HYPOTHESIS) {O4, O5} [G8 §3.1 T-1] |
| **3. Vietnam via systems integrators** | Vietnam pilot applicants via integrators | Level-4 appraisal; 7-day notice to switch custodians; Decree 284; no licence yet | Integrator partnership; documentation of Level-4 controls | Second country; sell through integrators, not direct {O1} |
| **4. Indonesian greenfield custodians and issuers** | new OJK-licensed custodians and rupiah-stablecoin issuers | ≥70% at licensed custodians; new licensees with undisclosed vendors | As option 1, at lower intensity | Watch for RFPs [G8 §9 D4] |
| **5. "Verifying signer" behind existing co-signer hooks** | Fireblocks and Cobo customers (both send raw transactions to customer callbacks) | Decision-layer losses {T4} | The open verifier kernel shipped standalone, fail-closed | Additive, lower switching cost; demand is HYPOTHESIS {O2} [G5 §8] |
| **6. Licensed payment / e-money pilots** | payment and e-money licensees running stablecoin pilots | Stablecoin rails | — | Mostly locked to Fireblocks, Meridian or Fystack (10/21) {O1} |
| **7. Unlicensed TRON PSPs and OTC desks** (original B1) | — | Strong TRON volume, but the triggers are enforcement, not purchasing | — | **Not recommended** (7/21): enforcement target and reputational coupling {O1} |
| **8. Self-hosted agent co-signer** | — | x402 / agent hype; MPC-native agent wallets are vendor-hosted | ECDSA swap; node-enforced caps; EIP-712/3009 support | Phase 2 only; looks unoccupied (HYPOTHESIS) {T10} |
| 9. Embedded / consumer WaaS | — | Free or cents-per-MAU incumbents | Device party, SDKs, SOC 2 | Do not pursue [M2a §10] |

**Recommended sequence** (HYPOTHESIS; follows ROADMAP §0 and §4, which supersede round 1's order):
1. **Zero-cost hygiene** {T5} and a founder check of the "no customer contact" finding {W12}.
2. **Discovery sprint (G8 D1):** 12–15 Thai licensed-tier interviews over 4 weeks. G8 §1 says 15–20 calls and M6 says 20; the sample size has no stated basis.
3. **Open verifier kernel as a standalone crate** (ROADMAP M6) {O2, S2}.
4. **Additive Guard co-signer on TRON native multisig with a capped, project-owned float** (ROADMAP M7).
5. **Engine swap and verifying nodes only if D1/D2 or funding pass** (G-MPC → M8–M9); **audit on a committed user** (M10); **capped MPC pilot** (M12) {O3}.

Key-less compliance modules {O4, O5} are demand-gated in the ROADMAP; D1 tests Travel Rule readiness first.

### 6.7 Timing and exit realities

- **Timing** (ESTIMATE): see {T3} and §0.1; every capacity scenario lands after the 2027-02-27 Travel Rule date.
- **Exit** {O11}:
  - Priced single-vendor wallet-infrastructure deals in 2023–26 ran ≈$90M–$250M (Ripple–Metaco $250M; Fireblocks–Dynamic ≈$90M unconfirmed; Paxos–Fordefi >$100M; MoonPay–Sodot ≈$100M in stock).
  - Every priced comparable had ≈15–40 staff and hundreds of customers or millions of users. Sodot sold with SOC 2 Type 2, three audit firms and named clients.
  - An external audit, about three production references and a second accountable human are minimum gates. They come from M6's sales gate and G7's separation-of-duties requirement, not from acquisition evidence, and they do not justify a $90M+ price.

---

## 7. Vaultex SWOT — the verified ledger

All 46 ledger items follow. Statuses are **CORROBORATED** (confirmed as written), **CORRECTED** (confirmed only after correction; the corrected wording is used here) or **NEEDS COUNSEL** (`[NLC]` in the ledger; a legal reading). ★ marks headline items.

The wording is condensed for public release. Vulnerabilities are given as category + fix, and details of the internal first user are withheld. File:line evidence for code facts is in the cited private reports.

### 7.1 Strengths

**S1 · CORROBORATED ★ — An audited-library ECDSA path was demonstrated at production parameters (`cggmp24`).**
- **What ran.** In G1's spike, LFDT-Lockness `cggmp24` =0.7.0-alpha.3 (pinned as a crate triplet) ran 2-of-3 at production parameters (1536-bit safe primes, 3072-bit Paillier), inside the Vaultex workspace and over Vaultex's own NATS transport.
- **Results.**
  - 3/3 runs signed. p50 aux-info 8.59 s, key generation 6.7 ms, signing 724 ms (325 ms in-process with the optional LGPL `rug` backend; unchanged under `docker --cpus=2`).
  - The largest wire message was ≈692 KB, 66% of NATS's 1 MiB default.
  - Every signature verified with `k256`. EVM and TRON addresses derived through Vaultex's chain registry, and SLIP-10 HD children matched rust-bitcoin BIP-32.
  - Stark-curve signatures passed `starknet-crypto`, so the hand-rolled Stark engine can be replaced too.
- **Code impact.** Adoption deletes ≈5,943 production LOC of hand-rolled ECDSA/Paillier/HD code. It leaves ≈5.1–5.6k LOC of Vaultex integration to review, against ≈10k today; the new-code share is an ESTIMATE.
- **Verified constraints:**
  - the published alpha.3 compiles only with the triplet pinned (upstream #211);
  - the lockfile pins a yanked safe-prime crate (fix: downgrade);
  - safe-prime pregeneration takes 15.6–107 s per party (p50 ≈38 s), and the slowest party exceeded the 60 s ceremony timeout in 4/5 runs, so a background prime pool is mandatory;
  - upstream has no threshold refresh and no identifiable abort {T8};
  - pilot use is limited to full interactive signing.
- **Alternatives rejected.** `cggmp21` 0.6.3 and 0xCarbon DKLs23 are NO-GO.
- **Limits.** All results come from one host; multi-host latency is HYPOTHESIS.
- Evidence: [G1 §0, §3.2–3.4].

**S2 · CORROBORATED ★ — Node-side decode-and-verify is feasible on existing seams at negligible cost.**
- **Prototype.** G4's prototype passed 14/14 tests, including negative and tamper cases. For all 6 live chains, a signing node can recompute the exact sign payload from canonical unsigned bytes:
  - EVM: `keccak(0x02‖rlp)`;
  - TRON: `sha256(raw)`;
  - Solana: the message;
  - Sui: `blake2b(intent‖bcs)`;
  - Aptos: `prefix‖bcs`;
  - Bitcoin: BIP-143, with hash-verified previous transactions.
- **Decodable fields:** chain, sender, recipient, asset, amount and fee bound. Two exceptions: the Sui `Coin<T>` asset type needs object proofs, and TRON, Solana, Sui and Bitcoin bytes carry no network id, so each network needs its own key.
- **Parsers.** The decoders are already in the lockfile. TRON and Solana need strict parsers of ≈100–200 LOC each, because the existing TRON decoder is too permissive.
- **Measured cost (debug build):**
  - EVM decode + hash 5.9 µs; TRON strict decode 14 µs;
  - policy evaluation plus one Ed25519 approval 0.24 ms;
  - fsync'd velocity reservation 3.4 ms.
  - All negligible next to a 0.3–0.7 s ECDSA ceremony.
- **The seam exists.** Every node already verifies a gateway-signed Ed25519 authorization bound to the message hash, with a 120 s TTL and a replay cache. Hashing the preimage at the node is also what cggmp24's safe `DataToSign` API requires.
- **The hard part is trust plumbing, not decoding:** a node-pinned, quorum-signed policy; approver signatures the node can verify; persisted per-node state; pinned peers.
- Evidence: [G4 §0; G5 §9].

**S3 · CORRECTED — Vendor-blind by construction: Vaultex has no vendor-run component, so the customer runs every party.**
- **Deployment modes.**
  - There is no hosted, SaaS or co-signer mode. The production mode (DEC-015) is a customer-run gateway, NATS and set of MPC nodes, with optional Vault and Redis.
  - The other mode is the single-process CLI demo, which made every live testnet send. It keeps all n shares in one local keystore under one password.
  - Neither mode calls a vendor endpoint.
- **What each component holds.**
  - The gateway keeps only wallet metadata, in memory, and never stores a share. It does hold the Ed25519 gateway key that signs control messages, authorizations and handshakes.
  - Key-generation responses carry no secret.
  - Each node persists only its own party's share per key group, encrypted with AES-256-GCM under an Argon2id v1.3 key (64 MiB, t=3, p=4), with a random salt and nonce per file.
- **Caveats on "one share per node".** It is a convention, not an enforced invariant: in GG20, node 1 generates the full key as a trusted dealer, and the boot-node wrapper can mount a CLI keystore that holds every party's share.
- **No vendor hooks.** A repository grep on 2026-10-09 found no telemetry, licence server, phone-home, update check or escrow code. It also found no share backup, export or restore function and no recovery kit; the only recovery-named code is an unwired DR plan that outputs text steps.
- **Hosted alternatives differ:**
  - Coinbase CDP's current Server Wallets (Coinbase-run Nitro) and Turnkey (Turnkey-run Nitro) offer no self-hosting. CDP's legacy v1 (deprecated from 2026-02-02) had a customer-hosted Server-Signer holding 1 of 2 shares. Turnkey names on-prem only as a future target.
  - Circle hosts both 2-of-2 nodes by default and offers shared hosting; customer hosting of both nodes is "available to enterprise customers", and user-controlled wallets are always Circle-hosted.
  - Dfns: hybrid customer-run signers from Pro ($35,000/yr); full on-prem is Enterprise-only.
  - Fireblocks: in the standard model the customer holds 1 share and Fireblocks Cloud Co-signers hold 2. The SGX co-signer cannot operate without attesting against Fireblocks' server, from which it fetches its database key; the Nitro and GCP co-signers fetch that key from the customer's KMS. Every co-signer takes requests from Fireblocks SaaS. "Hosted MPC" (announced 2023-06-27) puts all shares in the customer environment but is still driven by the Fireblocks platform.
- **Why it matters.** The Thai perimeter test and Hong Kong's para-11 test largely turn on this property, but only if support access, recovery services and any policy key are also vendor-blind [needs counsel].
- **Not unique.** Fireblocks (all-shares option, KeyLink), Ledger HSM On-Premise and Dfns on-prem keep keys customer-side but keep a vendor-run control plane. Fystack mpcium (Apache-2.0) is fully self-run, like Vaultex.
- **What undercuts the separation in practice** (categories):
  - one gateway key for control, authorization and handshakes;
  - one deployment secret bundling the shared key-store password with gateway and node keys (the compose defaults do the same);
  - key-generation secret shares crossing an unauthenticated, unencrypted bus;
  - trusted-dealer GG20 key generation;
  - a hard-coded local message-bus URL that breaks multi-host deployment {W16}.
- Evidence: verifier repo re-check at HEAD `ccd1f7f6` (2026-10-09); [G5 §3; M2b §3; G6 §6.1].

**S4 · CORROBORATED — Chain encoders are pinned to official SDKs, with on-chain testnet sends including TRON TRC-20.**
- **Reference vectors.** Nine tests pin Vaultex's transaction encoders byte-for-byte to official SDK output: viem (ERC-20), tronweb ×2 (native and TRC-20 `TriggerSmartContract`), @mysten/sui ×2, @aptos-labs/ts-sdk ×3, and @solana/spl-token (`TransferChecked`).
- **Real testnet sends on 6 chains,** re-confirmed on-chain on 2026-10-08: Sepolia (incl. USDC), Solana devnet (incl. SPL), Bitcoin testnet, TRON Shasta (incl. a TRC-20 transfer, SUCCESS at block 64,750,375) and Sui. The Aptos testnet has since been reset.
- **This proves encoding, not distributed custody:**
  - every live transaction came from the single-process CLI holding all shares, with test parameters;
  - there are 0 mainnet transactions;
  - only 6 of the 50 advertised chains are validated;
  - token decimals are not sourced from anywhere (BSC USDT/USDC use 18 decimals);
  - Sui's default public JSON-RPC is now deprecated;
  - Bitcoin transactions are single-input with a fixed fee.
- **Use.** The encoders are raw material for node-side decoders {S2} and should lead the README in place of "50 chains". Reviewing them would be a separate, pilot-scoped audit line: TRON + EVM ≈2.7k SLOC, ≈2–3 engineer-weeks (ESTIMATE).
- Evidence: [I7 §2.3; I4 §0, §1.5].

**S5 · CORROBORATED — ZF FROST is the only scheme that signs on the production path.**
- **What signs.** FROST-Ed25519 and FROST-secp256k1-tr hand key generation and signing to the ZF `frost-*` 2.2.0 crates. They were the only schemes that signed over the real gateway → NATS → 3 × node path with production builds (HTTP 200, 64-byte signatures). GG20 and CGGMP21 failed every sign {W1}.
- **Implication.** FROST-Ed25519 (Solana, Sui, Aptos) is the smallest credible first pilot and audit target.
- **Verified caveats:**
  - key generation is flaky (FROST-Ed25519 4/8 one-shot; FROST-TR 2/6) because round collection never checks the round number;
  - FROST round-2 shares cross the bus in cleartext {W4}, so even a FROST-only pilot needs transport encryption first;
  - NCC audited only frost v0.6.0 and excluded secp256k1-tr; frost-core 3.0.0 has been out since 2026-04-23;
  - the FROST-secp256k1 refresh is hand-rolled and unverified;
  - FROST-TR lacks the BIP-341 Taproot tweak, and the gateway lists P2WPKH Bitcoin addresses for FROST-TR wallets, which cannot spend from them.
- **Contested.** Whether any capped pilot may run before an external audit: I10 proposes one; M8, I9 and M5 want the audit first.
- Evidence: [G3 checks 2a–2d, 2i, 3b–3c; I1 §1; M3 §3.2].

**S6 · CORRECTED — The dependency tree permits permissive licensing of the whole stack.**
- **Structure.** The gateway, MPC node, chain builders and the policy, approval and audit libraries live in one five-member Rust workspace. The policy, approval and audit libraries are library-only; the CLI uses only audit-pack verification.
- **Licence scan.** A full re-scan of all 618 crates.io packages in the lockfile found none licensed GPL or AGPL. Copyleft appears only as an elective alternative:
  - `r-efi` (MIT OR Apache-2.0 OR LGPL-2.1+), used only for UEFI targets;
  - `keccak-asm` / `sha3-asm` (BSD-3), bundling CRYPTOGAMS assembly under "BSD-3-Clause OR GPL"; never compiled.
- **MPL-2.0.** Three packages are MPL-2.0. Only `option-ext` is compiled, and only into the demo CLI; `fastrlp` appears in the lockfile only. The gateway and node binaries link no MPL or copyleft code.
- **Backends.** `cggmp24` defaults to num-bigint; LGPL GMP enters only if `backend-rug` is enabled. The stable `cggmp21` 0.6.3 makes GMP mandatory.
- **Conclusion.** Nothing in the Rust tree stops shipping the whole stack, decision layer included, as MIT OR Apache-2.0. That still needs:
  - a NOTICE/attribution file;
  - consent from the copyright holders behind both contributor accounts;
  - exclusion of vendored third-party content that cannot be relicensed.
- **Comparable stacks keep key parts closed:**
  - Fystack: Apex enforces policy and holds the initiator key; cosigner committee and signed-approval logic sit in a private SDK.
  - Fireblocks: `mpc-lib` is GPL-3.0; the API Co-signer ships only as a console-downloaded installer.
  - Dfns signers and the Cobo TSS Node are closed.
- **Potential only, today.** No LICENSE, COPYING or NOTICE file exists on main or dev, and GitHub detects no licence. README, Cargo.toml and the OpenAPI document say only "MIT". The grant is legally ambiguous rather than definitively all-rights-reserved, and cautious adopters will treat it as all-rights-reserved until licence text and a copyright line ship {W7}.
- Evidence: verifier lockfile re-scan (2026-10-09); [I8 §4.1; G5 §2.1].

**S7 · CORROBORATED — The engineering hygiene baseline is sound.**
- **Verified basics:**
  - 0 `unsafe` blocks; only a CSPRNG is used;
  - shares encrypted with Argon2id (64 MiB, t=3, p=4) + AES-256-GCM; key shares zeroized and redacted in debug output;
  - control messages must be Ed25519-signed and are pinned to the configured gateway key;
  - authorizations bind the message hash, with a 120 s TTL and a replay cache;
  - no private-key material in git history; clean crate layering;
  - fmt and clippy `-D warnings` clean; a CI-equivalent run on rustc 1.93.1 passes 994 tests (0 failed, 46 ignored).
- **Caveats:** share ciphertexts carry no associated data; share writes are non-atomic with no fsync; the Helm chart uses one key-store password for all nodes.
- **Scope.** None of the blockers found are memory-safety or secret-hygiene bugs. They are design and logic flaws this baseline does not reach.
- Evidence: [I6 §0, §3–4; I2].

**S8 · CORROBORATED — One developer working with AI agents built the codebase very fast.**
- **Output.** In 18 active days (2026-03-15 to 06-01): 562 commits (435 in one ISO week), ≈62K lines of Rust and ≈31K lines of Markdown. 994 tests pass, and the encoders are pinned to SDK vectors.
- **Code throughput is not the bottleneck; independent review is:**
  - the internal AI security gate ("R6") stopped on 2026-03-20;
  - no pull request was ever reviewed;
  - milestones M1–M4 were declared done within 8.7 hours with 10 of 75 exit criteria ticked;
  - the same speed produced unsound cryptography and many refuted documentation claims {W2, W14}.
- Evidence: [I9 §0.1, §1.2–1.3; I11].

### 7.2 Weaknesses

**W1 · CORROBORATED ★ — Threshold ECDSA cannot sign on the production path, so BTC, EVM and TRON are blocked.**
- **Failure.** With production 2048-bit parameters, the hand-rolled GG20 and CGGMP21 engines failed every signing attempt: 10/10 in I7's harness, and 2/2 each over the real gateway → NATS → 3-node path.
- **Cause (category):** a parameter-handling defect in the range proofs. The gateway's regression test had quietly switched to FROST.
- **Live broadcasts don't contradict this.** All six "live" testnet broadcasts used the single-process CLI with shared test parameters (1024-bit Paillier, 512-bit Pedersen), and there are 0 mainnet transactions.
- **Consequence.** No secp256k1-ECDSA asset can be signed today: not BTC, not ETH/ERC-20, not TRON/TRC-20. Only FROST signs {S5}. Fixing this defect alone would not help, because the engines are also unsound {W2}.
- **Fix category:** retire the engines and adopt an audited library {S1, O3}.
- Evidence: [I7 §0.1, §3; G3 checks 0, 2f, 2h].

**W2 · CORROBORATED ★ — The hand-rolled ECDSA and Stark protocols are unsound by design, so their keys must be retired.**
- **Scope.** All three hand-rolled threshold-ECDSA engines (GG20, CGGMP21, Stark; ≈5.8k SLOC incl. Paillier/ZK) carry key-extraction-class design flaws. Categories:
  - the multiplicative-to-additive (MtA) step lets a participating co-signer recover the full key (shown by an offline mathematical simulation);
  - GG20 key generation uses a trusted dealer;
  - the Paillier zero-knowledge proofs are unsound or misused, including missing parameter proofs and size checks;
  - the Stark MtA carries no ZK proofs.
- **Non-threshold schemes.** The Sr25519 and BLS "threshold" schemes are single-party keys.
- **Consequence.** No share conversion to a sound protocol is possible: every GG20, CGGMP21 and Stark wallet must be frozen, re-keyed on the replacement engine and swept.
- **Fix category:** retire these engines in favour of an audited library {S1, O3}.
- **Open.** End-to-end extraction through forged Paillier proofs is HYPOTHESIS until there is a proof of concept.
- Evidence: [I1 §2.1–2.4; M3 §7.2; M4 §2].

**W3 · CORROBORATED ★ — Authorization is asserted by the gateway, not enforced by the signers.**
- **Gateway.** Both signing routes hard-code a passing policy result with zero required approvals (re-checked 2026-10-09). The raw signing route accepts opaque digests (category: blind signing; missing object-level authorization).
- **Nodes.** They do not check what they sign:
  - they verify only the gateway's own attestation and never check the policy hash;
  - they accept approver evidence that is only hashes of signatures;
  - they sign the supplied digest without decoding it; the node does not depend on the chain-decoding crate.
- **Unwired libraries need redesign before wiring.** Policy, whitelist, velocity, approval, delegation, webhook and audit exist only as libraries, with these flaws:
  - amounts are u64, capping them at ≈18.4 ETH in wei;
  - an unlisted chain is allowed;
  - there is one global policy;
  - signed policy bundles accept any signer and failed verification after a JSON round trip in 194/200 runs.
- **Impact class:** a single compromised operator credential or gateway host is enough to authorize signing.
- **Comparison.** On signer-side control Vaultex is weaker than Fystack mpcium with authorizers enabled, and weaker than hosted vendors that enforce a policy engine in the signing path (Fireblocks, Dfns, Turnkey, CDP).
- **Fix category:** node-side decode-and-verify; node-pinned, quorum-signed policy; payload-bound approvals verified by nodes; per-wallet authorization {S2, O2}.
- Evidence: [I3 §0–3, §8; G4 §1; G5 §9; M8 §8].

**W4 · CORROBORATED ★ — The transport leaks key-generation secrets and lets peers impersonate each other.**
- **Confidentiality.** Key-generation secret material is not confidential against an observer on the message bus, and shipped configurations do not authenticate bus clients (demonstrated in an isolated lab).
- **Further defects (categories):**
  - sender identity is spoofable between peers (demonstrated in an isolated lab);
  - there is no reliable broadcast;
  - the round number is never checked, which causes the flaky key generation.
- **Unused fix.** A session-key encryption module exists, but only benchmarks use it.
- **Fix categories:**
  - authenticated, session-bound P2P AEAD under node-pinned identities, not identities supplied by the gateway;
  - bus TLS with per-node credentials and subject ACLs;
  - sender binding; round filtering; per-round size caps.
- **Comparators.** FROST and cggmp24 both need this layer, and Lockness requires authenticated, encrypted P2P. Fystack mpcium has had encrypted P2P (Ed25519-signed X25519 ECDH + AES-GCM) since 2025-08-13.
- Evidence: [G3 checks 3a–3c, 2a, 2i; G1 §0.6, §2.5].

**W5 · CORROBORATED ★ — Trust is concentrated in one gateway key, one deployment secret and a replayable control plane.**
- **One key.** A single hot gateway Ed25519 key signs handshakes, authorizations and all control messages. Nodes take their peer keys and bus URL from the gateway, so a compromised gateway can sign anything or intercept key generation.
- **Replayable control plane (category).** The control plane lacks freshness and existing-group protection, so a replay can destroy a wallet's key material (loss-of-funds class; demonstrated in an isolated lab). Node replies are not authenticated.
- **Deployment.** The Helm chart bundles the gateway signing key, the token secret, the node seeds and one key-store password shared by every node into a single secret. One cluster admin may therefore reach t shares (HYPOTHESIS).
- **Gateway authentication is weak:** mTLS trusts headers, and session ids are logged at INFO.
- **Fix categories:** separate keys per function; node-pinned peers; nonce + expiry + subject binding; never overwrite an existing group; per-node secrets and failure domains.
- Evidence: [I2 blockers 3–5; I6 §2.2; G3 checks 5a–5d; M8 §8.1(d)].

**W6 · CORROBORATED ★ — One dormant maintainer, no independent review, no external assurance.**
- **Team.** Vaultex is effectively one human plus AI agents:
  - one identity authored 537 of 562 commits (≈96%) and committed every content commit;
  - all 25 PRs were merged with zero reviews, 19 of them self-merged;
  - main has no branch protection;
  - the internal AI security gate last ran on 2026-03-20;
  - there has never been an external audit, pentest, SOC 2 or ISO 27001.
- **Dormancy.** No commit since 2026-06-01 (130 days as of 2026-10-09); the founder's capacity went to a related internal project.
- **This blocks buyers and auditors:**
  - SOC 2, ISO 27001 and HK SFC 25EC44 require separation of duties that a one-person team cannot evidence;
  - an audit needs a counterpart who can remediate within a 2–8-week fix window;
  - Thai buyers also need a legal entity that can sign an SEC-form outsourcing contract (inspection rights, liability, BCP) and provide Thai 24/7 support.
- **Never estimated:** team size, resourcing and funding. If capacity cannot be committed, the clean options are to park Vaultex (warning, licence, archive) or to contribute its components to an existing open-source stack.
- Evidence: [I11; I9 §0.6, §1; I8].

**W7 · CORROBORATED ★ — Not legally adoptable or procurable: no LICENSE, unpublished crates, contested name.**
- **No licence file.** GitHub reports no licence, and there was no LICENSE file at HEAD on 2026-10-09. README, Cargo.toml and the OpenAPI document say MIT, but without the file legal teams will block adoption. S6's verifier refines the legal characterisation to "ambiguous rather than definitively all-rights-reserved"; the procurement consequence is the same.
- **Other procurement problems:**
  - the crates are unpublished and cannot be published as-is (path-only dependencies);
  - the `mpc-wallet-core` crate name is taken on crates.io by an unrelated project;
  - version labels conflict (every tag 0.1.0; latest release v0.9.0; CHANGELOG 0.10.0);
  - older firms use the name "Vaultex" (trademark status HYPOTHESIS).
- **A licence is also the gate** for HackerOne Community Edition, OSTIF-managed audits, systems-integrator partnerships and any open-source adoption. The dependency tree already allows MIT OR Apache-2.0 {S6}.
- Evidence: [I8 §0, §4.1; I5].

**W8 · CORROBORATED ★ — No backup, recovery, refresh or failover: losing a node can mean losing funds.**
- **No key maintenance.**
  - There is no share backup, export, restore or escrow code.
  - The refresh route returns 501, and reshare is not wired.
  - The CLI has no refresh, reshare or freeze command.
  - The "DR drill" only generates strings, and "backup verified" just means "node healthy".
- **Fragile availability.**
  - Signing always uses parties 1..t, so if any of them is down, signing halts for every wallet.
  - A node silently drops a second sign request for the same group within 1 s; the caller sees a 60 s timeout.
  - Share writes are non-atomic, with no fsync.
- **Consequence.** Losing a second node of a 2-of-3 group is permanent. Because cggmp24 has no threshold refresh, rotating a key holder means a new DKG plus an on-chain sweep.
- **What others ship.**
  - Buyers expect customer-held recovery kits, offline restore tools and executed drills (Fireblocks recovery kit, Dfns Layer 4).
  - Thai rules require recovery approved by authorised persons and the wallet owner, split at least 3 ways, with tested tooling.
  - Fystack mpcium already ships reshare and encrypted backups with a recover CLI.
- Evidence: [I2 §4–5; M7 §2.4; G5 §2.5; G6 §1].

**W9 · CORROBORATED ★ — No durable state, transaction lifecycle or evidence trail around the signer.**
- **State.** The gateway keeps its wallet registry in memory. In a live test a restart took the wallet count from 18 to 0, every GET returned 404, and node shares were orphaned with no way to re-register them.
- **Missing entirely:**
  - a transaction object or idempotency key;
  - confirmation or receipt tracking;
  - deposit detection;
  - a wired HD deposit-address API;
  - a sweep workflow;
  - a decimals registry (BSC USDT/USDC use 18 decimals);
  - TRON energy management: a USDT transfer uses 64,285 energy, burning ≈6.43 TRX without staked energy, and out-of-energy failures are invisible;
  - a TronGrid API key (requests hit HTTP 429).
- **Transaction route.** It is EVM-only (501 for TRON and Solana) and uses a fixed 21,000 gas limit. It builds, signs and broadcasts in one call, so a client retry signs and broadcasts again.
- **Evidence trail.** Webhook delivery is a no-op, the audit ledger is not wired, and "WORM" exists only as configuration.
- **Checklist score.** M7 finds 0 of 33 P0 production items fully met (≈12 partial).
- **Regulatory gap.** Thai licensees must reconcile client assets every business day, keep evidence for 5 years and notify the SEC within one hour of incidents affecting client assets. Today none of that evidence would come from Vaultex.
- Evidence: [G3 checks 6a–6b; I3 §0.5, §4–6; I4 §0.4, §6; M7 §7].

**W10 · NEEDS COUNSEL ★ — No cold tier, while Thai custodians must keep ≥95% of client assets cold.**
- **Current design.** All parties are always-online bus subscribers. Signing uses the fixed signer set 1..t with a hard-coded 60 s timeout. There is no air-gapped relay, no hot↔cold sweep workflow and no 95/5 ratio monitor.
- **The rule.** Since 2025-09-01, Thai custodians must keep ≥95% of client value in cold wallets, defined as connected only when transacting.
  - Cold transfers must be jointly confirmed by ≥2 designated persons who are not related to each other.
  - Other licensees holding more than THB 1,000M may keep at most 10% hot.
- **Open questions:**
  - Whether an MPC quorum whose nodes connect only during ceremonies meets the definition is untested (HYPOTHESIS). A 2021 SEC consultation note says connected warm wallets resemble hot wallets.
  - Relaying interactive cggmp24 signing (6 rounds; P2P messages up to ≈92 KB) across an air gap would be heavy (HYPOTHESIS).
- **Consequence.** Without a cold design, Vaultex can serve at most the ≤5% hot tier of a Thai custodian.
- Evidence: [M5 §3.2; G8 §7 row 4; I2].

**W11 · CORROBORATED ★ — Release, CI and dependency controls are below sign-off level.**
- **CI and release:**
  - main CI failed 28 of 93 runs, the latest main run is red, and no workflow has run for ≈130 days;
  - the release workflow auto-tags every push to main with write permission; it has failed 20 of 20 runs since 2026-05-09 and produced zero assets;
  - no signed artifacts or provenance;
  - Actions pinned to mutable tags;
  - no branch protection.
- **Dependencies.** `cargo audit` (advisory DB of 2026-10-07) reports 4 vulnerabilities:
  - rustls RUSTSEC-2026-0285 and ruint RUSTSEC-2026-0220, both in shipped code;
  - quinn-proto RUSTSEC-2026-0185 (CVSS 7.5; reachability disputed);
  - a dev-only crossbeam-epoch advisory.

  9 more advisories are ignored in configuration, and a yanked safe-prime crate is pinned.
- **Why it matters.** An audit report only means something for an identifiable, reproducible, signed build. HK SFC 25EC44 puts SDLC, release and supply-chain controls inside vendor review.
- Evidence: [I5; I7 §0.5].

**W12 · CORRECTED ★ — No customers, no customer contact and no usable reference yet.**
- **Discovery so far.**
  - Round 1 contains no customer contact of any kind: no interviews, LOIs, pilots or partner agreements. All beachheads are desk research (M1, M2b, M6, G8).
  - G8 named 52 organisations, a 13-entry outreach shortlist and 11 possible integrators or channel partners; none has been contacted.
  - This absence claim spans the research corpus and the repositories; it must be confirmed with the founder.
- **The only candidate first user today is an internal project** (details private). It has no Vaultex integration yet (verified by repository search, 2026-10-09) and is not a production reference until it runs Vaultex in production.
- **Buyer expectation (HYPOTHESIS).** G8 judges that Thai licensed buyers will want 1–3 named production references before a pilot; M6 wants about 3 before its later white-label beachhead. Neither cites a buyer, an RFP or a regulator.
- **Next step.**
  - First, a zero-cost founder check of this absence claim.
  - Then G8's D1 Thai licensed-tier discovery sprint is a reasonable low-cash step. G8 proposes 12–15 interviews over 4 weeks, but its own §1 says 15–20 calls and M6 says 20; the size has no stated basis. Calling D1 the "cheapest and most informative" step is a judgment (HYPOTHESIS), and it competes for the one developer's time.
  - The named target list, contact status and pre-outreach checks are kept in the private reports.
- Evidence: verifier re-check 2026-10-09; [G8 §9, §13; G2; G6].

**W13 · CORROBORATED — Tests and CI exercise a different configuration from production.**
- **Test-only parameters.** The 994 tests, the benches, the CLI and all testnet broadcasts run with a test feature that gives every party one cached 1024-bit Paillier key and a 512-bit Pedersen set and disables the ≥2048-bit guard. A whole-workspace release build also leaks it into the node and gateway binaries.
- **CI gaps:**
  - the test step lacks pipefail and gates only on ≥860 passes, so failing core tests can still go green;
  - E2E never starts a node or bus signing;
  - some tests are tautological; there are only 3 serde-level fuzz targets and no in-protocol adversarial tests;
  - benchmarks measure test parameters, and the core bench panics.
- **Pre-audit requirements:**
  - a multi-process, production-parameter key-generation + signing CI job;
  - pipefail on the test step;
  - a `compile_error!` if test parameters reach node or gateway builds;
  - adversarial tests that call production code.
- Evidence: [I7 §0.1–0.3, §0.6, §0.8, §3; I11].

**W14 · CORROBORATED — Public claims and the internal security record cannot be relied on.**
- **The security record does not hold up:**
  - "68/68 findings resolved" is refuted: of 28 sampled, 15 are fixed, 9 partial, 2 not fixed, 1 risk-accepted, 1 library-only;
  - the CVE report's "NOT AFFECTED" for CVE-2025-66016 and its CVE-2022-47930 mitigation claim are refuted; its "GUARDED" for CVE-2025-66017 is partly refuted;
  - every audit was done by the internal AI agent;
  - the audit-scope document names no commit and excludes the gateway routes and chain encoders, where the worst bugs are;
  - the threat model says nodes verify the policy hash; they do not;
  - the runbook relies on a refresh endpoint that returns 501 and an audit ledger that is not wired;
  - M1–M4 were declared complete with 10/75 criteria met.
- **Public claims.** About 40 are contradicted by the code, among them:
  - "Production-ready infra", "50 chains", threshold Sr25519/BLS;
  - "gateway compromise = 0 shares", "CI green", "audit clean";
  - a performance table off by ≈1,000× (I8) to ≈4,000× (I7).
- **Consequence.** Anyone relying on these documents, an auditor included, must re-baseline from the code.
- Evidence: [I6 §1, §7; I1 §4; M4 §1, §12; I8].

**W15 · CORROBORATED — The advertised surface far exceeds the working product, and unsafe addresses are exposed.**
- **Chain coverage.** 50 chains are advertised. 6 are in the chain metadata and live-validated; 26 are code-complete but never broadcast; 13 are partial.
- **Unsafe outputs reach users:**
  - TON, Starknet, Monero and Zcash (probably also Injective) serve placeholder or wrong deposit addresses through the CLI and the address API, with no chain gating;
  - FROST-TR wallets are shown P2WPKH addresses they cannot spend from;
  - MegaETH's chain id is wrong.
- **Non-threshold schemes.** The Sr25519 and BLS "threshold" schemes are untested single-party keys.
- **Code health.** About 6.1k of 17k core production lines have no production caller; protocol functions run to 697 and 626 lines; there are 217 production panic sites.
- **Audit cost scales with SLOC.** G7 counts ≈14k in-scope SLOC today against ≈7–11k after a library swap.
- **Action.** Remove or feature-gate unshipped chains and non-threshold schemes before any RFQ, and gate the unsafe addresses off now.
- Evidence: [I4; I8; I11; G7 §1].

**W16 · CORROBORATED — No shipped artifact starts a working multi-host cluster.**
- **Single-host only.** The orchestrator hard-codes a local message-bus URL for nodes; with the bus anywhere else, distributed key generation fails 12/12 at the first hop.
- **Broken artifacts:**
  - Helm environment-variable names do not match what the binaries read;
  - node probes hit the wrong port;
  - the default mainnet setting panics because the chart cannot mount required files;
  - the raw k8s manifests predate the gateway/node split;
  - Terraform deploys nothing;
  - the compose files use well-known seeds;
  - only the local-infra script works, and its gateway-restart command is broken.
- **Thin operations:** SIGTERM is ignored; the node exports 3 gauges; 3 gateway metrics are dead; there is no tracing; the rate-limit setting is unused.
- **Consequence.** Until a reference multi-host deployment with per-node secrets and failure domains exists, a pentest cannot be scoped and a pilot cannot be deployed. Even incumbents' customers struggle to staff 24/7 multi-node operations.
- Evidence: [I5; G3 checks 1, 6c; I2; M2b §3.13].

**W17 · CORRECTED — No supported or correctly documented integration path from non-Rust stacks.**
- **Today an integrator can get in only by reverse-engineering the Rust source** (VERIFIED 2026-10-09):
  - no TypeScript, Python or Go files exist on any of the 8 public branches; the only JavaScript is 10 reference-vector scripts;
  - no Vaultex crate is on crates.io, and nothing is on npm or PyPI;
  - the only REST client code is the gateway's Rust integration tests.
- **The documented paths fail as written:**
  - the quickstart's handshake body returns 422, and its key-file names are wrong;
  - the documented IdP Bearer path (RS256/ES256) returns 401, because the gateway accepts only HS256 tokens signed with its own shared secret; the README's example claims also lack `iat`;
  - the OpenAPI document references an undeclared security scheme and documents the error shape wrongly;
  - the CLI demo runs all parties in one process and writes shares to the user's real data directory.
- **Handshake.** Its byte-exact transcript encoding is specified nowhere, yet it is not impossible outside Rust: a Node.js re-implementation completed it in ≈6 ms and a curl/openssl/jq script in ≈0.09 s.
- **Undocumented path.** A shared-secret (HS256) bearer design authenticates every protected route, including admin wallet creation. Anyone holding that secret can mint admin tokens.
- **Competitor SDK coverage:** Dfns 10 SDKs in 8 languages; Turnkey 8 languages (incl. Dart/Flutter); Coinbase CDP 5 (its Go SDK is autogenerated and "not first-class"); Fystack TS and Go.
- **Fix category:**
  - a canonical auth encoding (e.g. RFC 8785) with cross-language test vectors;
  - a TypeScript client;
  - corrected quickstart, README and OpenAPI;
  - an asymmetric/JWKS bearer path, or removal of the bearer path.
- **Open.** How much longer integration takes than with a vendor SDK is HYPOTHESIS. The proposed TRC-20 timing test cannot succeed today; time a FROST-Ed25519 send instead, or run it after the ECDSA fix.
- Evidence: verifier probes (2026-10-09); [I8; I3].

### 7.3 Opportunities

**O1 · CORRECTED ★ — Re-scope the beachhead to Thailand's licensed tier, where dated regulatory triggers create compliance-driven demand. That this leads to custody re-platforming is a hypothesis, not evidenced.**
- **Scoring (HYPOTHESIS; sourced inputs, some vendor claims).** Thai licensed custodians 18/21; Thai exchanges, brokers and dealers 17/21; Vietnam's pilot applicants 15/21 (none licensed as of 2026-10-08). On pain criteria alone: custodians 11/12; Thai exchanges/brokers and Vietnam 9/12.
- **The original beachhead splits two ways:** licensed payment and e-money pilots 10/21, which already chose Fireblocks, Meridian or Fystack; unlicensed TRON PSPs and OTC desks 7/21, an explicit BOT/SEC enforcement target.
- **Dated triggers:**
  - no delegation of custody and ≥95% cold for custodians (since 2025-09-01);
  - the Travel Rule from 2027-02-27 (self-hosted wallet ownership/control checks; ≥5 years' retention);
  - draft stablecoin transfer controls (same-owner wallets, per-customer THB caps, KYT; no effective date);
  - crypto ETFs: Thai-licensed custodians as the primary custody route (final terms unverified).
- **Continuity shock.**
  - Rakkar's closure was reported 2025-12-24, and Cobo said it was engaging affected institutions (release dated 2026-01-12).
  - DV8 signed for up to 100% of Rakkar on 2026-03-24, subject to SEC approval. Completion and the 2026-04-27 relaunch are vendor claims.
  - Maxbit appointed Rakkar in July 2026, so no client churn is evidenced.
- **Market data.** USDT was ≈66% of Thai licensed-exchange trading value in July 2026 and a reported 76% in August (SEC data via press); the sometimes-cited 52% lower bound is not traceable to SEC data. About 24 of the 52 named SEA organisations (23–29 depending on classification) disclose no vendor {T7}.
- **Vietnam** is second, entered through an integrator.
- **Open questions:**
  - whether SaaS with vendor-held shares fits the no-delegation rule [needs counsel];
  - whether anyone will buy from Vaultex;
  - how many Thai custodians actually operate (two confirmed; Kryptodian disputed).
- **Proposed sequence (HYPOTHESIS; round 1, superseded by the ROADMAP order in §6.6):** hygiene and discovery → core swap and TRON verification → external audit → paid design-partner pilot through a licensed operator, priced as licence plus services.
- **Timing.** On round-1 estimates (≈22–31 engineer-weeks, a 4–7-month audit, ISO 27001/SOC 2 needing a second person) an audited pilot is unlikely before H2 2027.
- **The sequence omits G8's other pre-pilot requirements:** ISO 27001 and SOC 2; HSM or KMS share wrapping; a ≥95% cold tier; Travel Rule and KYT tooling; source escrow and a local entity; Thai 24/7 support.
- Evidence: [G8 §0, §2, §6–7; G6 §2.3–2.4, §2.8; M5].

**O2 · CORRECTED ★ — Open, fail-closed decode-and-verify at every signing node, TRON-first, as the differentiator.**
- **The gap.** Among the vendors and repositories G5 examined (re-checked 2026-10-09), none ships OSI-licensed code that does all of the following:
  - every signing node, not one co-signer gate, receives the exact unsigned transaction, decodes it (TRON TRC-20 first-class), recomputes the digest and fails closed;
  - each node verifies k-of-n approver signatures over a canonical intent;
  - each node evaluates a node-pinned, quorum-signed policy bundle with per-node velocity caps and auto-pause;
  - each node emits a signed decision receipt.
- **The nearest attempts each miss pieces:**
  - Cobo: an unlicensed callback template beside a closed TSS Node holding one share. It has TRON/EVM/Solana decoders with digest recompute, plus Guard approver-signature and threshold checks.
  - Fireblocks: an MIT callback-handler boilerplate for its single customer co-signer. It recomputes Bitcoin PSBT sighashes, re-evaluates a policy fetched from Fireblocks' API and checks one RSA extra signature; it has no TRON support.
  - Vultisig: an MIT verifier that is a single share-holding gate; its TRON parsing lives in an unlicensed dependency.
  - Fystack: a "coming soon" Cosigner with its approval logic in a private module.
  - Sodot, Blockdaemon, Fireblocks (SGX) and Safeheron (TEE): closed claims of policy at share-holders, mechanism undocumented.
- **Hooks are open by default:** a Fireblocks co-signer with no handler auto-signs; mpcium authorizers are disabled unless configured, and an empty required list accepts zero signatures; the Dfns gate runs only when a URL is configured, though once enabled it fails closed on non-200 responses and connection failures.
- **Feasibility** {S2} is VERIFIED at unit-test level (14/14, re-run 2026-10-09). Node integration, auto-pause and signed receipts have not been prototyped.
- **Unproven.** Uniqueness beyond the examined set, buyer value and effort are HYPOTHESIS.
- **Effort (G4 bottom-up, one engineer, verification layer only; ESTIMATE):**
  - ≈15.5 engineer-weeks for a TRON slice with Ed25519 approvals; ≈13.5 without approvals (G4's printed ≈12.5 does not add up);
  - ≈23 for all 6 chains, excluding WebAuthn (+2) and Sui `Coin<T>` object proofs (+1.5);
  - not included: the ECDSA swap (G1: ≈14–16 engineer-weeks, partly overlapping), receipt signing and an external audit.
- **Why it matters:**
  - It targets the decision-layer pattern behind 7 of the 8 ≥$100M incidents; two of those (KelpDAO, Liquid) were validation failures that caps would only bound.
  - Node-verified approvals with k ≥ 2 can technically enforce Thailand's two-person joint confirmation for a custodian's cold tier; the "not family-related" condition remains organisational. Per-node caps map to the Annex 6 limit items.
  - It is intended as a small, deterministic, auditable component (HYPOTHESIS). The closest audited analogue, Turnkey's enclave parsers plus policy engine, took 8 auditor-weeks.
  - Shipping exact transaction bytes to each node also enables cggmp24's preimage-bound signing API. Only presignatures require it; full interactive signing with a prehash is safe.
- **Claim it only after it ships** and meets G5's seven-item bar (§8.5), including a public red-team test and an external audit that covers the decoder and the policy kernel.
- Evidence: [G5 §0, §4, §7.2, §9; G4 §0, §5; M8 §0].

**O3 · CORRECTED ★ — Swap the ECDSA core to `cggmp24` with transport fixes, then buy a library-based integration audit.**
- **Scope of G1's P0 plan:**
  - replace GG20 and the hand-rolled CGGMP21 with pinned cggmp24 (full signing only);
  - add sender and session binding;
  - add P2P encryption with node-pinned identities;
  - add a prime pool and the aux-info lifecycle;
  - re-key;
  - freeze Stark, Sr25519 and BLS.
- **Effort (ESTIMATE).**
  - G1's headline is ≈14–16 engineer-weeks, but its line items sum to ≈16.5–17, or ≈15.5 without the deletion task. That is XL for one engineer (≈4 months), or about 2 months for two if the work parallelises.
  - Replacing Stark with cggmp24's curve-stark adds ≈2 engineer-weeks.
  - Node-side authorization is excluded (G4: ≈12–15 for a TRON slice), although G7's audit scope presumes it exists.
- **Audit cost (G7; anchors verified in Arbitrum ARDC posts):**
  - Scenario B core: 6.5–12 engineer-weeks, $130k–$336k tier-1 or $65k–$216k mid-tier, plus a $5k–$36k pentest. ≈4–7 months from RFQ to public report, counted from a frozen commit; ≈35% of A.
  - Scenario A: 18–34 engineer-weeks, $360k–$952k tier-1 or $180k–$612k mid-tier; 8–14 months.
  - With a cggmp24 library-delta review, mandatory in the ROADMAP (audit line AL3; {T8}) although G7 sized it as optional for cggmp21, at G7's 2–4 engineer-week band: ≈8.5–16 engineer-weeks, $170k–$448k tier-1 or $85k–$288k mid-tier (≈47% of A).
  - For cggmp24 that band is HYPOTHESIS and may be low: the delta is ≈1.2× larger in changed lines and adds new ZK proofs.
  - $28k per engineer-week is not a ceiling: a16z cites up to almost $100k a week for specialised two-auditor reviews.
- **Preconditions:**
  - freeze the retired engines;
  - land the transport fixes;
  - build node-side authorization;
  - add production-parameter, multi-process CI;
  - freeze one commit with a matching spec and threat model;
  - scope the audit to cover transport, node authorization and key lifecycle, not only the wrapper.
- **Latency.** Tail-latency publication is rare but not unprecedented: in Sept 2026 Silence Laboratories published p50/p90/p99 for 2-of-3 DKLS23 and Lockness CGGMP on three GCP VMs, in one region and across three. A production-parameter p50/p99 report for Vaultex's full path would be useful evidence, not a first.
- Evidence: [G1 §0, §7; G7 §0, §9–10; I6; M7].

**O4 · NEEDS COUNSEL ★ — A key-less Travel Rule ownership-proof module before 2027-02-27.**
- **The duty.** From 2027-02-27 (≈20 weeks away), Thai licensees must verify that customers own or control their self-hosted wallets, and keep Travel Rule data for 5 years (Sor Thor 9/2569).
- **Vaultex has no such code:** 0 hits for EIP-191/personal_sign, BIP-322, TRON signed messages, Travel Rule or KYT.
- **The module would have two parts:**
  - a per-chain ownership-proof verifier (signed message or micro-deposit) for TRON, EVM, Bitcoin and Solana;
  - a fail-closed pre-sign Travel Rule gate that writes a payload hash to the audit ledger.
- **Why it could come first.** It holds no keys, so a licensee could adopt it before Vaultex's custody core is audited. G8 names exactly this kind of module, rather than core custody, as the way in at a large Thai licensed exchange.
- **Open points:**
  - the duty-holders are licensed operators, not vendors;
  - the THB 30,000 threshold is unverified;
  - PDPA treatment of Travel Rule data was not researched;
  - it is unknown whether licensees have already chosen a Travel Rule vendor.
- Evidence: [G6 §2.8; G8 §0, §2, §3.1 T-1, §7; M5 §3.3].

**O5 · NEEDS COUNSEL ★ — A Thai compliance-as-code pack mapped clause by clause.**
- **Controls the Thai texts specify**, which could ship as one evidence-producing pack:
  - 95/5 cold-ratio monitoring, and ≥2 unrelated approvers for cold transfers;
  - user-defined transfer-size and velocity limits;
  - daily reconciliation;
  - five-year evidence retention, the first two years immediately available;
  - key ceremonies (≥3 board-appointed staff, an independent observer, offline generation, evidence logs);
  - recovery approved by authorised persons and the wallet owner, split ≥3 ways;
  - one-hour incident hooks and forensic-grade export;
  - the draft stablecoin controls: same-owner whitelists bound to customer identity, THB-valued per-customer daily caps, KYT adapters.
- **Caveat.** The existing whitelist, velocity and policy primitives must be redesigned rather than simply wired {W3}.
- **Unproven.** Buyer value, and whether global vendors will localise quickly, are HYPOTHESIS. Kryptodian already claims to bundle Travel Rule/KYT and recovery services.
- Evidence: [G6 §2.3, §2.5, §6.2; M5 §11].

**O6 · CORRECTED — Answer vendor-continuity fear with openness, exit tooling and local partners.**
- **SEA buyers have seen custody vendors falter:**
  - Rakkar's reported closure (2025-12-24), Cobo moving in to migrate its clients, then the sale to DV8 (signed 2026-03-24; operating again from 2026-04-27 per the company);
  - Qredo's administration (2024-02-01), its assets passing to its backers' vehicle (now Zenrock), and its dissolution (2025-09-16);
  - Copper seeking a buyer since May 2026, with its CEO departing.
- **Hosted wallets have forced migrations:**
  - CDP v1's Coinbase-managed 2-of-2 MPC wallets could not export keys, so users were told to create v2 accounts and move funds on-chain;
  - Magic's Core API v1 shut down on 2026-07-31, leaving un-migrated v1 wallets inaccessible.
- **Vendors keep changing owners:** Privy→Stripe (2025-06), Dynamic→Fireblocks (2025-10), Sodot→MoonPay (2026-04).
- **Regulation adds friction:**
  - Vietnam's draft circular (2026-09-15) would require ≥7 days' notice before engaging or replacing a third-party custodian;
  - Thai outsourcing contracts must include SEC inspection consent; whether a self-hosted licence counts as outsourcing is [needs counsel].
- **What a one-person vendor could offer instead of headcount** (all HYPOTHESIS; none present today):
  - a permissive OSI licence (MIT OR Apache-2.0). Non-commercial or BSL terms undercut the right-to-fork argument; AGPL is forkable but deters embedding. Enforceability of restrictive terms on AI-assisted code is unclear [needs counsel];
  - reproducible signed builds and source escrow;
  - customer-held encrypted share backups with an offline restore/export tool;
  - candidate local partners (systems integrators, an HSM supplier and a regional auditor), none yet contacted and none shown able to run the stack; the names are kept private.
- **Test.** Whether buyers will pay for this is untested; G8's D1/D3 interviews are the test.
- Evidence: [O6 verifier sources; M1 §3.22; M2b §3.1; M6 §5; G8 §5].

**O7 · CORRECTED — PKCS#11/KMS protection of shares, as one step toward the certified-hardware expectation.**
- **Thailand.** The SEC texts G6 read name an HSM only as an example ("or a device performing a similar function"), and "FIPS" was not found in the parts read. Two instruments were read only in part, so "never required" is not proven. Whether SEC readiness reviews or Thai buyers expect certified hardware is HYPOTHESIS.
- **Elsewhere the expectation is explicit but qualified:**
  - HK SFC 25EC44 (2025-08-15, para 2) expects, "where practicable", keys generated offline and kept in a secure environment such as a certified HSM. The same circular promises "technology-neutral, outcome-based standards".
  - CCSS v9 Level III (voluntary) requires key isolation in use to "FIPS 140 or equivalent", with HSMs and TEEs as examples.
- **Market precedents keep keys *inside* certified hardware:**
  - orbix CUSTODIAN's IBM HSM "certified to FIPS 140-2 Level 4" (press, June 2025; current stack unverified);
  - Fireblocks KeyLink with Thales (Feb 2026): keys or key shares operated within customer-owned Luna HSMs;
  - Fireblocks' Vietnam offer of "MPC or KeyLink HSM";
  - Fystack's Securosys HSM option (Aug 2026).
- **FIPS 140-2 is over for new integrations.** NIST moved all remaining 140-2 certificates to the Historical list on 2026-09-22 (e.g. IBM 4769 cert #4079), usable for existing systems only; new integrations should target 140-3.
- **Trail of Bits (2026-09-25)** recommends heterogeneous TEEs with attestation bound to party identity as defence in depth for MPC. It does not discuss HSMs.
- **Vaultex today.** Trait seams exist, but the key-encryption and enclave providers have no callers, the KMS components are stubs, there is no PKCS#11 dependency, and the only enclave provider is a mock. The PRD defers HSM to v2.0.
- **Proposal.** A PKCS#11/KMS key-encryption provider per failure domain would give certified protection at rest while keeping MPC's no-single-device property.
- **Limit.** Shares would still be decrypted in-process to sign. That meets neither CCSS L3's in-use isolation nor the "operated inside the HSM" pattern; those need HSM-resident or attested-TEE signing. Whether buyers or auditors accept wrapping at rest is HYPOTHESIS.
- **Cheapest tests:** ask a CCSS auditor; obtain Thai counsel's readiness checklist; ask in the D1 interviews.
- Evidence: [G6 §2.5; M5 §6, §10; G8 §7; M1 §5 T8].

**O8 · CORRECTED — A TRON stablecoin-operations module would match competitors, not set Vaultex apart.**
- **Where the low-cost platforms are weak on TRON:**
  - Coinbase CDP supports only EVM and Solana;
  - Circle Wallets lists no TRON;
  - Dfns supports TRON but its Fee Sponsor feature is not available there; it points to a self-run sponsor wallet (freeze + delegate), and its fee-estimate endpoint excludes TRON.
- **Fireblocks is not a gap:** Gas Station auto-fuels EVM and TRON, and a Fireblocks employee confirmed TRON on Gas Station V2 (Sept 2025). TRX freezing and delegation work through WalletConnect dApps; its relay-paid gasless mode covers only EVM and Solana, and no native energy rental was found.
- **TRON fee economics.** Without staked, delegated or rented energy, a USDT-TRC20 transfer burns ≈6.43 TRX (64,285 energy) to an existing USDT holder, or ≈13.03 TRX (130,285 energy) to a first-time holder, plus 0.345 TRX of bandwidth once free bandwidth is used up.
- **What the module would cover:** energy staking, delegation and rental; account activation; out-of-energy detection; TRC-20 deposit indexing with confirmations; a verified decimals registry; daily reconciliation and hot/cold reports.
- **Possible buyers.** Thai exchanges, where USDT is roughly 52–67% of trading value per secondary sources; that is order-book value, not on-chain TRC-20 share, and O1 gives ≈66–76% from SEC data.
- **It would only catch up with vendors that already ship TRON fee tooling:**
  - Fystack: TronZap rental (2026-03); TRX gas tank and auto-refill (2026-04);
  - Utila: staking, delegation, rental (2026-03);
  - Cobo Fee Station: "up to 80%" savings (claim);
  - Safeheron: rental (2025-03);
  - BitGo: resource-delegation API;
  - Fireblocks: Gas Station.
- **Low-cost API platforms cover TRON too:** Privy (mid-2025; expanded 2026-09-23; Transatron sponsorship recipe), Turnkey (TRON signing; policy engine covers freeze and delegate), Polygon OMS (2026-10-08).
- **Unproven.** Buyer value is HYPOTHESIS.
- Evidence: verifier re-reads of vendor docs (2026-10-09); [M7 §2.9; G5 §3; M6 §3.1].

**O9 · NEEDS COUNSEL — Regulators require independent code reviews, so one public report can be reused.**
- **Three regimes require independent review:**
  - HK SFC 25EC44 (2025-08-15): independent code reviews of third-party wallet solutions before onboarding and before material changes, plus review of the vendor's SDLC, release process, separation of duties and supply chain;
  - Thai SEC IT rules: pentests and independent qualified security audits;
  - DORA Art. 30(3): audit and inspection rights. RTS 2024/1773 Art. 8 forbids relying solely on certifications.
- **Reuse (HYPOTHESIS).** For an open-source stack, one public report pinned to a commit could be reused by every licensee.
- **Cheaper re-reviews.** Small, diff-reviewable signed releases with per-release security changelogs would lower the cost of "material change" reviews.
- Evidence: [G7 §0.9, §8; M5 §6–7].

**O10 · CORRECTED — A few assurance steps cost little or nothing and can start before any paid review. Most other items are cheaper routes to a paid review, or come after the audit.**
- **Free or near-free, can start now:**
  - GitHub private vulnerability reporting costs $0 and is still disabled (re-checked 2026-10-09).
  - AI pre-audit scans: one vendor (zkSecurity's zkao) publishes per-scan medians of ≈$49, $281 and $1,112 by codebase size (VENDOR CLAIM). Vaultex falls in the top tier, ≈$0.6k–$1.6k per scan. The assurance value is HYPOTHESIS.
  - HackerOne Community Edition once eligible: the platform is free, with a 5% fee on cash bounties (VERIFIED). Eligibility needs an OSI-licensed, non-commercial project at least 3 months old and active, a SECURITY.md, a link from a project website, first response within one week, and HackerOne's approval. The LICENSE is necessary but not sufficient, and eligibility is HYPOTHESIS mainly because of commercial intent.
- **Cheaper routes to a paid review:**
  - OSTIF: one funder-paid 2024 programme worked out to ≈$253 per expert hour (≈$10k per 40-hour week; 7 projects; $472k; 1,865 hours). This is not a published OSTIF rate, and whether OSTIF would take Vaultex is HYPOTHESIS.
  - For comparison, 2024 tier-1 rates were ≈$20.8k–$28k per engineer-week (possibly stale).
  - In-region options: Verichains (no published prices, so any cost advantage is HYPOTHESIS); Thai manual web/API pentests at ฿300k–฿1.2M (≈$9k–$36k; vendor claim).
  - Possible co-funders of a library-delta review (HYPOTHESIS; ask the maintainers): LFDT, the Zcash Foundation and Zcash Community Grants.
- **After the audit, not before:** a public bug bounty. Immunefi charges 10% on payouts unless the project buys a subscription. G7's $25k–$100k-a-year reward reserve is HYPOTHESIS.
- **Trend.** Trail of Bits (2026-03-31) reported going from ≈15 to 200 bugs a week for some clients with AI, with ≈20% of reported bugs now found first by AI, and said its scoping and pricing are "on the table". No pricing change had been announced by 2026-10-09 (HYPOTHESIS, based on search).
- Evidence: verifier re-run of the GitHub API (2026-10-09); [G7 §0, §2–3, §7].

**O11 · CORRECTED — Consolidation offers an exit path, but acquirers pay for audits, references and teams.**
- **Priced single-vendor deals, 2023–26, ran ≈$90M–$250M:**
  - Ripple–Metaco $250M (company-stated, May 2023);
  - Fireblocks–Dynamic ≈$90M (unconfirmed press estimate, Oct 2025);
  - Paxos–Fordefi >$100M (Paxos spokesperson via Fortune, Nov 2025);
  - MoonPay–Sodot ≈$100M in stock (Bloomberg, unnamed sources, via CoinDesk 2026-04-29; MoonPay announced without a price).
- **Not comparable:**
  - Polygon's ">$250M" covers Sequence *and* Coinme, a licensed money transmitter reported at $100M–$125M on its own.
  - The "$260M" ceiling sometimes cited is Coinbase–Unbound ($258M, 2021–22), outside the window.
- **Undisclosed or lower:** most 2025–26 deals disclosed no price. Lower priced deals: eToro–Zengo ≈$70M (2026) and Galaxy–GK8 ≈$44M (distressed; closed 2023-02-21).
- **What Sodot sold with:** SOC 2 Type 2 (EY); cryptography audits by Trail of Bits (2024-09), NCC (2025-09) and Halborn; named clients eToro, BitGo, Flow Traders and Exodus. Vaultex has none of these.
- **Market size.** M6 sizes SEA at ≈$2M–$24M a year (an unsourced upper bound).
- **Implications (HYPOTHESIS):**
  - a profitable niche, tuck-in or acqui-hire is more plausible than a venture-scale company built on SEA alone;
  - minimum gates are an external audit, about 3 production references and a second accountable human. These come from M6's sales gate and G7's separation-of-duties requirement, not from acquisition evidence, and they do not justify a $90M+ price;
  - every priced comparable had ≈15–40 staff and hundreds of customers or millions of users;
  - tie any capital to these milestones and to strategic or non-dilutive sources.
- Evidence: [M6 §4.1; M1 §3; M2a §3.16; G5 §3.8].

### 7.4 Threats

**T1 · CORROBORATED ★ — Fystack mpcium: same thesis, same region, further ahead.**
- **What Fystack (Vietnam) ships.** Apache-2.0 mpcium on the same NATS-based self-hosted design, ahead on exactly what Vaultex lacks:
  - P2P encryption (since 2025-08-13); reshare (since 2025-07-13); encrypted backups with a recover CLI;
  - TRON with a TRX gas tank;
  - TS and Go clients; Helm and Compose self-hosting;
  - a Securosys HSM tie-up and a Circle Alliance listing;
  - SaaS at Free / $199 / $499 a month with no per-transaction cut.
- **Activity.** mpcium has 17 releases (v0.4.0 on 2026-09-09), 193★, 65 forks and a push on 2026-10-07. Vaultex has 5★ and no commit since 2026-06-01.
- **The Cosigner is landing.** Its decoding Cosigner ("coming soon") had PR #168 merged to a feature branch on 2026-10-07, but it was not on master or in a release as of 2026-10-09.
- **Fystack's verified gaps:**
  - Adevar audited only the closed Apex backend (62 findings, 17 fixed); there is no public audit of mpcium;
  - policy and the sole initiator key sit in the closed Apex;
  - authorizers are off by default, sign opaque digests and have no k-of-n;
  - results are unsigned (issue #78);
  - the core is a tss-lib v3 fork (GG18/GG20 family);
  - bus factor ≈2.
- **Comparison.** Today Vaultex is weaker than mpcium with authorizers turned on. Do not claim Fystack is "unaudited" or "unencrypted".
- Evidence: [G5 §0, §2; M1 §3.24; M2b §3.14].

**T2 · NEEDS COUNSEL ★ — Thai perimeter: a vendor-blind licence is likely outside licensing; any vendor key role is likely inside.**
- **The definition.** Thailand defines a custodial wallet provider as anyone who, for a fee, manages keys "or anything else kept secret" used to approve transfers "with full or partial authority" (MoF Notification No. 2 B.E. 2565, cl. 3/1). There is no technology-vendor carve-out.
- **Working reading.** Vendor key roles are likely inside the Thai perimeter; a self-hosted licence with support that has no key access is likely outside [needs counsel].
- **Hong Kong** exempts an MPC vendor only if clients can transfer and recover without it.
- **Consequences:**
  - revenue must come from self-hosted licences, support without key access, and services;
  - "the vendor never holds shares, KEKs, policy keys or recovery material" must be written into the product and the contracts;
  - a hosted co-signer could run only outside Thailand or through a licensed partner.
- These are legal readings, not counsel opinions.
- Evidence: [G6 §1, §2.2, §2.4, §6.1; M5 §3.1].

**T3 · CORRECTED ★ — The assurance and delivery calendar lands after the 2026–27 buying triggers.**
- **Triggers.** The Thai Travel Rule takes effect 2027-02-27 (≈20 weeks away). Stablecoin transfer controls are targeted for end-2026, with no effective date. Compliance-vendor decisions probably fall in Q4 2026–Q1 2027 (HYPOTHESIS).
- **Prerequisites (ESTIMATES):**
  - the cggmp24 swap: G1 states ≈14–16 engineer-weeks; its line items sum to ≈15.5–17;
  - TRON-only node verification: G4 states ≈12.5–15.5; its line items give ≈13.5–15.5; all six chains ≈23+;
  - in sequence for one engineer: ≈26.5–31.5 engineer-weeks on the stated figures, ≈29–32.5 on the line items, before an unquantified overlap;
  - an external audit taking ≈4–7 months from RFQ (G7 Scenario B; HYPOTHESIS). Specialist reviews may need ≥2–3 months' booking (a16z); G7 suggests booking Oct–Nov 2026 for a Feb–Apr 2027 slot;
  - ISO 27001 (≈4–8 months) and SOC 2 Type II (3–12-month window). Neither sets a headcount, but both test separation of duties, so in practice they need a second accountable human (G7 HYPOTHESIS);
  - Thai-language 24/7 support: at least 2–3 engineers on call (G8's floor). Google SRE's minimum for sustainable 24/7 cover is 8 people on one site, or 6 per site across two.
- **G7's plan** puts the public audit report at ≈Mar–May 2027, the ISO certificate at ≈Jun–Aug 2027 and the SOC 2 Type II report at late 2027 or early 2028. It assumes the engineering prerequisites land Nov 2026–Jan 2027 (≈13 weeks), which would take ≈2–2.5 full-time engineers.
- **One engineer instead.** One full-time engineer from 2026-11-01 (≈4.35 engineer-weeks a month) freezes code ≈early May to mid-June 2027. The first audited regulated pilot is ≈Q4 2027 (range Q3 2027–Q1 2028; HYPOTHESIS). That is likely optimistic:
  - it assumes full availability of a developer whose repo has been idle for 130 days;
  - it excludes registry persistence, share backup/restore, deployment artifacts and payment operations;
  - it excludes the Travel Rule, KYT, cold-tier and HSM features and non-TRON chains;
  - a buyer requiring SOC 2 Type II before a pilot pushes it toward the late end.
- **First-year external assurance** ≈$0.11M–$0.56M:
  - G7's core audit ($65k–$336k), pentest ($5k–$36k), compliance platform ($6k–$20k), SOC 2 Type I ($5k–$20k), ISO 27001 ($5k–$16k) and a bounty reserve ($25k–$100k);
  - ≈$0.12M at the low end if Type II's $10k low is added;
  - G7's envelope for selling to licensees is ≈$0.15M–$0.80M, and is the more relevant figure for an alpha cggmp24 whose post-2023 changes have no public external review.
- **Implications (HYPOTHESIS):**
  - incumbents or in-house builds will probably win the first wave;
  - Vaultex's realistic windows are later buying events: re-platforming after the deadline, Thai crypto-ETF custody, Vietnamese licensees and new Indonesian custodians;
  - key-less modules {O4} should ship first (round-1 view; the ROADMAP makes them demand-gated, §6.6);
  - several of these events are already under way in 2026, so some decisions may come before Vaultex is ready.
- Evidence: [G1 §7; G4 §5; G7 §0, §9–10; G8 §2].

**T4 · CORRECTED ★ — Real losses come from subverted signing decisions, Vaultex's weakest layer (its key/crypto layer is also critically weak).**
- **The incidents.** M8's table lists eight custody, wallet and bridge incidents of ≥$100M in 2024–26, ≈$3.4B in total (ESTIMATE): DMM, WazirX, Bybit, Drift, KelpDAO, Coldcard (preliminary), Liquid (≈85% returned) and Bitget (§4.1).
- **Key material failed in only one.** Coldcard (weak seed entropy) was ≈3% of the dollars. In the other seven, keys were reported intact. For Bitget and Drift that rests on the victims' own accounts, and WazirX's victim and vendor accounts conflict.
- **How legitimate systems were made to sign:**
  - poisoned signing UIs (Bybit, WazirX);
  - a tampered request or back office (DMM, Bitget);
  - socially engineered pre-signing (Drift);
  - poisoned RPC data feeding a 1-of-1 verifier (KelpDAO);
  - a validation bug (Liquid).
- **Scope.** The eight are a scoped selection. Broader lists add DeFi logic exploits (Cetus, Balancer), PlayDapp's ~$290M nominal mint (~$32M realised; suspected leaked key) and two single-victim social-engineering thefts (~$230–245M Aug 2024; ~$330M Apr 2025).
- **DPRK.** DPRK-attributed actors passed $1B stolen in 2026 (Chainalysis, 2026-10-01). Attribution is from private firms and partly preliminary. Entry routes:
  - developer social engineering plus stolen cloud session tokens (DMM, Bybit);
  - months of social engineering of signers (Drift);
  - compromised verifier RPC infrastructure (KelpDAO);
  - a zero-day in third-party security appliances (Bitget).
- **Vaultex concentrates the same trust (categories):**
  - nodes sign gateway-authorized digests without decoding;
  - the gateway asserts policy and approvals instead of enforcing them;
  - one gateway key signs control messages, authorizations and handshakes, and the default deployment co-locates it with the shared key-store password;
  - so a single operator credential or a compromised gateway suffices to sign, with no human approver in the path.
- **A crypto-only audit is necessary but not sufficient.** It would fail Vaultex's current engines {W2, W4} rather than certify them, and it would leave unexamined the authorization path behind 7 of the 8 incidents. Audit scope and acceptance tests must cover cryptography and authorization end to end: gateway routes, node verification code, approver keys, the policy bundle and the release pipeline.
- **Incident-replay tests**, translated to Vaultex's EOA wallets:
  - Safe delegatecall/upgrade payloads where the MPC key is a Safe owner;
  - token approvals, permits and EIP-7702 delegations through the blind-sign path;
  - a tampered legitimate withdrawal request (DMM; "destination swap" is an inference).
- Evidence: [M8 §0–2, §8]; verifier re-check at HEAD `ccd1f7f6`.

**T5 · CORROBORATED ★ — A public "production-ready" repo with unfixed key-extraction flaws and a supply-chain lure profile.**
- **Exposure.** The repository is public: 2 forks, cloned 9 times by 9 unique cloners in 14 days. It has no LICENSE.
- **Misleading signals.** The README still advertises "Production-ready infra" with no "unaudited — do not use with real funds" notice, although key-extraction-class flaws {W2, W4} and placeholder addresses {W15} are verified.
- **Disclosure.** Private vulnerability reporting is disabled. The disclosure e-mail domain predates the repository, and its ownership is unverified.
- **The release path fits the DPRK supply-chain lure profile:**
  - one maintainer plus AI agents;
  - auto-release on every push to main with write permission;
  - mutable Action tags;
  - 9 ignored advisories;
  - no signed releases or provenance.
- **Unreviewed.** Nobody has reviewed the security of the AI-agent development process itself, while AI tooling is lowering the cost of finding bugs like these.
- **Impact.** A third-party loss or poisoned release traced to Vaultex could end the project and spill onto the founder's other business.
- **Fixes that take days and cost $0:**
  - a README warning;
  - a category-level GitHub Security Advisory naming the affected schemes and the re-key requirement;
  - enable private vulnerability reporting;
  - add the LICENSE;
  - disable auto-release;
  - SHA-pin Actions;
  - sign tags and releases;
  - gate unsafe schemes and addresses off.
- Exploit mechanics stay in private reports.
- Evidence: GitHub API checks (2026-10-08/09); [I8; I5; M8 §4].

**T6 · CORRECTED ★ — "Our signers can veto" is table stakes; "first" or "only" claims are refuted.**
- **Vaultex today** trusts a gateway-asserted pass with 0/0 approvals. Customer-run gates that can refuse each signature already ship:
  - **Fireblocks:** a customer-hosted API Co-signer holding one share, gated by a callback handler. It auto-signs if no handler is configured. An opt-in `rawTx` field (enabled via support; not on the EU cloud) covers 18 listed chains or chain groups, including TRX. Included in Essentials ($999/month, up to 6 months); Custom from $36K/yr after that.
  - **Dfns:** a fail-closed Validation Gate for customer-run signers (hybrid or on-prem; MPC and HSM). Announced "available now" on 2026-06-24 and listed at signer v2.20.7 (week of 2026-08-24). Requires Pro ($35K/yr) or Enterprise.
  - **Cobo:** a TSS Node callback that can deny operations. Its public but unlicensed template rebuilds TRON/EVM/Solana transactions, matches hashes and checks destinations. A separate, unwired library verifies Guard approval signatures using data from Cobo's API.
  - **Safeheron:** an API Co-Signer that auto-approves the tasks its approval policy routes to it. Public docs do not say whether it holds a key share, and plan availability conflicts between docs and pricing.
  - **Circle:** a keyguard, for enterprise customers only.
  - **Blockdaemon Builder Vault:** per-node SDK policy, written as customer code.
  - **Fystack:** today only mpcium's optional authorizer gate (off by default). The Cosigner is still "coming soon"; the 2026-10-07 branch merges contain no public decoder, and the approval logic is in a private SDK.
- **Low price.** Only Fireblocks Essentials is verified to include the hook, and only for up to 6 months. Cobo at $299–$999/month is HYPOTHESIS.
- **Remaining opening (HYPOTHESIS):** the O2 combination. A Fystack Cosigner on master would narrow the decode-and-approve part but not the open-licence part, unless Fystack opens its private SDK. Timing is HYPOTHESIS: the branch is six months old, and an earlier PR to master was closed unmerged.
- Evidence: [G5 §0, §3–4, §7]; verifier re-check (2026-10-09).

**T7 · CORRECTED — Incumbents own disclosed SEA licensed demand and already sell customer-run deployment.**
- **Disclosure.** G8 names 52 SEA organisations. About half disclose their custody or wallet vendor, and where one is public an incumbent or an in-house build already fills the role.
- **Disclosed vendors:**
  - Fireblocks is the most frequent (8 of 52): TrueMoney/Ascend Bit; SCB–Lightnet; Coins.ph; Maya; Pintu and Reku (self-claims); Rakkar's 2023–24 engine (status after ASTRA unconfirmed); Luno (older coverage; also BitGo). Also screened on Fireblocks: Cebuana Lhuillier and Western Union PH.
  - Ceffu: Binance TH, Tokocrypto (2024 vendor claims).
  - IBM HSMs: orbix.
  - Anchorage + Coinbase Custody: InnovestX.
  - Rakkar as outsourced custodian: Bitkub, Maxbit.
  - In-house MPC: Indodax (weak evidence, from before its 2024 hack), Hata (claimed) and Kryptodian, whose licence was announced in September 2026 while two register reads on 2026-10-08 conflict.
  - Fystack: Gaian. Metaco/Ripple + IBM: UnionBank. Meridian: BPI. Bithumb: SSID.
  - Cobo is a suitor, not a disclosed choice.
- **Customer-run and onshore variants are already sold:**
  - Fireblocks Hosted MPC and KeyLink HSM, both pitched for Vietnam;
  - Ledger HSM On-Premise (announced 2026-03-25; available July 2026; governance still hosted by Ledger in France);
  - Dfns on-prem; Taurus on-prem or hybrid.

  "Self-hosted" alone does not differentiate.
- **Buyer requirements before a pilot** are inferred from regulation and marketing, not interviews (HYPOTHESIS):
  - *Fixed by regulation:* ≥95% cold for DA custodians only (exchanges and brokers cap hot holdings and place the rest with a custodian); the Travel Rule; KYT (so far only in the stablecoin draft); pentests and independent audits; prescribed outsourcing terms [needs counsel].
  - *Market expectations, not rules:* an external threshold-crypto audit; ISO 27001 then SOC 2 Type 2; HSM/KMS wrapping (not mandated; of the Thai custodians only orbix is publicly HSM-centric); source escrow; Thai 24/7 support.
- **Vaultex meets none of the listed items.** Its vendor-holds-no-keys design does fit the separate "vendor holds no key material" requirement.
- **The Thai licensed market shrank** (SEC data via press):
  - average daily turnover THB 1.378B in July 2026, −27% on June;
  - H1-2026 months THB 1.74–2.03B, against ≈THB 2.41B for 2025;
  - active accounts ≈151K (Dec 2025) → ≈121K (Jul 2026).
- **USDT flows are AML targets.** The BOT/SEC audit of high-volume USDT transactions was announced 2026-07-13. Vietnam's Decree 284 (in force 2026-09-01) fines unlicensed services and investors. Neither names TRON.
- **Likely entry points (HYPOTHESIS):**
  - the ≈24 named organisations with no disclosed vendor (23–29 depending on classification);
  - second-vendor, hot-tier or policy-module roles;
  - systems integrators.
- Evidence: [G8 §0, §3–4, §7; M1; G5; G6; M5; M6; G7].

**T8 · CORROBORATED — Inherited library assurance is thin and decaying.**
- **Moving to audited libraries shifts risk rather than removing it. cggmp24's gaps:**
  - alpha.3 does not compile as published without pinning (233 errors; upstream #211);
  - its Kudelski audit was a 10-person-day review of a 2023-05-26 commit, 545 commits earlier. *Synthesis note: G7 attributes the 10-person-day figure to Kudelski's 2022 audit of Multisig Labs' ECDSA-CGGMP; the effort of the June-2023 Dfns cggmp21 review is not stated (≈1 month calendar) [G7 §2 rows 1–2, §4.3]. The commit date and the 545-commit gap stand [G1 §2.2]. See §7.5 row 42;*
  - there is no public external review of the 2025 CVE fixes;
  - it lacks threshold refresh (#237) and identifiable abort (#111);
  - upstream leaves message-size DoS limits to the transport (#209, #136);
  - pinning alpha.3 misses hardening that exists only on upstream HEAD.
- **ZF FROST.** NCC audited only v0.6.0 and excluded secp256k1-tr; Vaultex resolves 2.2.0, and 3.0.0 has been out since 2026-04-23.
- **Audited implementations keep breaking:**
  - critical CVE-2025-66016 hit the Kudelski-audited cggmp21;
  - TSSHOCK victims had undergone multiple audits;
  - THORChain lost ≈$10.7M through GG20 on 2026-05-15 (M3 and M8 report its root cause and next steps differently).
- **Action.** A delta review of the pinned versions belongs in the audit scope, and Vaultex should not claim it "uses audited cryptography" without one.
- Evidence: [G1 §0.4, §2.2, §2.4, §3.1; M3 §3.2; G7 §0.2; M4 §0; M8 §2.6].

**T9 · CORRECTED — Price compression: signature-priced hosted vendors win at small and mid volumes.**
- **List prices** are in the pricing columns of the §2 matrices (fetched 2026-10-09). Details from the verification:
  - Turnkey Pro's $99 is labelled a monthly minimum;
  - Privy's developer plans include 50K signatures a month;
  - Dfns' legal SLA (2024-05-01) commits 99.90% monthly overall (API 99.95%), with credits capped at 7% as the sole remedy;
  - Dfns reports SOC 2 Type II (KPMG, 2024 period) and ISO 27001/27017/27018 (2025); no 2025/26 SOC 2 renewal was found.
- **Startup comparison** (3K–10K signatures a month):
  - Turnkey Pro ≈$150–600/month: $150–500 if the $99 is a spend floor, $250–600 if it is added on top;
  - Privy $0–499;
  - Dfns Pro $35K/yr;
  - Vaultex self-hosting: ≈$4–12K/yr of infrastructure (M2b: $6–36K for HA), ≥0.25 FTE on call (24/7 realistically 1+ FTE) and ≥4–6 months to a capped pilot (all HYPOTHESIS).
- **PSP comparison** (≈$10M/month, ≈100K signatures): Turnkey Pro ≈$5.1K (a ceiling at $0.05/sig); Safeheron ≈$11.9K; Cobo ≈$15–22K; Fireblocks Essentials ≈$20.3K (6-month cap).
- **Where flat self-hosted pricing wins:**
  - against volume-linked vendors at high outbound volume;
  - against per-signature vendors only at their list rates and high signature counts;
  - against negotiated enterprise rates only at millions of signatures a month: ≈1–5M with G2's inputs, ≈10M with 1+ FTE of 24/7 operations (HYPOTHESIS).
- **Why price is not a wedge:**
  - M6's proposed tiers ($6K and $18–30K/yr) are 25% and 14–49% below Dfns Basic and Pro on sticker, but roughly level or higher once the buyer's own infrastructure and on-call are added (HYPOTHESIS). At ≤10K signatures a month no tier beats Turnkey Pro or Privy.
  - The TRON gap among hosted signers has closed (Turnkey, Privy, Dfns). Polygon OMS added TRON USDT on 2026-10-08 but does not say its free offer covers TRON.
  - No named SEA PSP was found complaining publicly about volume fees (absence of evidence).
- **Conclusion.** Price is not the wedge; inspectability, onshore control and compliance features are (estimates and positioning).
- Evidence: primary pricing pages re-fetched 2026-10-09; [M6 §3; M2b §6.1; M1 §7.3].

**T10 · CORRECTED — Hosted, embedded and agent-wallet lanes have moved to TEEs and to distribution owners.**
- **TEE move.** Hosted developer and server wallets moved to TEEs (mostly AWS Nitro) in 2025–26; embedded and agent wallets split between TEEs and MPC.
  - Coinbase deprecated its MPC-based Server Wallet v1 from 2026-02-02 in favour of a Nitro-TEE v2. The v1 docs have been removed and AgentKit dropped v1 on 2026-02-25; a full shutdown is not confirmed.
  - Lit sunset its threshold network and made V3 "Chipotle" GA on 2026-04-01: TEE nodes where each request runs inside one enclave.
  - Privy (TEE by default), Turnkey, Magic (Core API) and thirdweb (Vault) keep keys in Nitro. List prices run from $0.001 (Privy enterprise floor) to $0.10 (Turnkey PAYG) per signature; Magic and thirdweb price mainly per MAU or per request.
- **MPC persists** in device-share and agent wallets: Dynamic made device+server TSS-MPC its SDK V5 default (2026-08-17), and the agent wallets of Circle (2-of-2 MPC), Cobo and Fireblocks/Dynamic are MPC-native.
- **Distribution owners absorbed embedded-wallet vendors:** Privy→Stripe (2025); Dynamic→Fireblocks (2025-10-23); Magic's wallet business→Payward (agreement 2026-07-27; closing unconfirmed as of 2026-10-09). AWS AgentCore payments (GA 2026-08-18) allows only Coinbase CDP and Stripe-Privy connectors.
- **Agent-payment volume is small** (not one time series): CoinDesk (2026-03-11) ≈$28K/day and ≈131K tx/day, unadjusted, with Artemis judging about half artificial; CCN (2026-08-13, Helios) −93% year to date, 7-day average ≈$41.8K; American Banker (2026-09-18) ≈$800K/day in January → ≈$40K/day in September.
- **Where MPC persists:** regulated and institutional WaaS, self-hosted stacks, device-share embedded wallets and MPC-native agent wallets. Vaultex's lane is the self-hosted, sovereign or regulated slice.
- **Vaultex has 0 lines** of EIP-712, EIP-3009, Permit2 or x402 code (all refs, 2026-10-09).
- **Any opening is phase 2:**
  - the official x402 spec still has no TRON "exact" binding (#2075 and PR #2076, opened 2026-04-20, unmerged on 2026-10-09), though a third-party MIT SDK (BofAI/x402) already implements TRON payments;
  - MPC-native agent wallets are sold as vendor-hosted services (Cobo, Circle, Fireblocks/Dynamic). Vultisig's open Verifier is the nearest open alternative, but Vultisig operates it;
  - a self-hosted, open-source agent co-signer with an operator-run policy quorum looks unoccupied (HYPOTHESIS).
- **Viability** comes only after the ECDSA swap and node-enforced spending caps (judgment).
- Evidence: [M2a §5; M2b §1, §3, §5, §7; M6 §6(c)]; verifier re-checks (2026-10-09).

### 7.5 Claims that did not survive verification

No ledger item was refuted outright; every item survived, some only after correction. One sub-claim of {T8} is flagged by this synthesis (row 42). The claims below, from Vaultex's own documents or from round-1 reports, were refuted or materially corrected.

| # | Claim | Origin | Verdict | Evidence |
|---|---|---|---|---|
| 1 | "Production-ready infra" | Vaultex README | **Refuted** | {W14, W1–W9} |
| 2 | "50 chains" | Vaultex README / registry | **Refuted**: 6 testnet-validated, 0 mainnet | {W15, S4} |
| 3 | Threshold Sr25519 and BLS | Vaultex docs | **Refuted**: single-party keys | {W2, W15}; [M3 §7.2; M4 §2 F9] |
| 4 | "Gateway compromise = 0 shares" / "the full key is never assembled" | Vaultex README | **Refuted**: trusted-dealer key generation; plaintext key-generation transport | {W2, W4, W14} |
| 5 | "68/68 security findings resolved" | Vaultex security docs | **Refuted**: 15 of 28 sampled fixed | {W14} |
| 6 | CVE-2025-66016 "NOT AFFECTED"; CVE-2022-47930 mitigated; CVE-2025-66017 "GUARDED (no HD derivation)" | Vaultex CVE report | **Refuted / partly refuted** | {W14}; [M4 §2 F6, F10; M6 §11] |
| 7 | "CI green", "audit clean" | Vaultex README | **Refuted**: main CI red; 4 RUSTSEC advisories | {W11, W14} |
| 8 | Published signing performance (e.g. GG20 ≈47 ms) | Vaultex benchmarks | **Refuted as production evidence**: test parameters; production ECDSA fails; off by ≈1,000–4,000× | {W13, W14, W1} |
| 9 | Nodes verify the policy hash / enforce policy and approvals | Vaultex threat model | **Refuted** | {W3, W14}; [G5 §9] |
| 10 | Six live MPC testnet broadcasts validate distributed custody | Vaultex sprint notes | **Refuted**: single-process CLI with test parameters (encoding only) | {S4, W1} |
| 11 | Stateless / HA-capable gateway | Vaultex docs | **Refuted**: in-memory registry lost on restart | {W9} |
| 12 | OIDC/JWKS bearer authentication | Vaultex docs | **Refuted**: HS256 shared secret only | {W17} |
| 13 | Refresh/reshare and DR supported; WORM audit storage | Vaultex docs / runbook | **Refuted**: refresh returns 501; DR prints strings; WORM is configuration only | {W8, W9, W14} |
| 14 | "no_std / WASM-ready core" | Vaultex specs | **Refuted** | [I11; M2a §9] |
| 15 | "Built on audited cryptography" (FROST via audited ZF crates) | Vaultex docs; I1 | **Overstated**: NCC covered v0.6.0 and excluded secp256k1-tr | {T8, S5} |
| 16 | "MIT licensed" | Vaultex README / Cargo | **Corrected**: no LICENSE file; legally ambiguous; treated as all-rights-reserved | {W7, S6} |
| 17 | GG20 via real nodes was "simply untested" and might work | I2 | **Refuted**: fails 100% at production parameters | {W1} |
| 18 | A capped real-funds CGGMP21 pilot after ≈6–9 engineer-weeks | I10 | **Superseded**: CGGMP21 cannot sign at production parameters and is unsound | {W1, W2} |
| 19 | Signer-side verification ("signers that cannot be lied to") is largely unoccupied; Vaultex could be first | M1, M7, M8 | **Corrected**: veto hooks are table stakes; only a specific conjunction may be unoccupied | {T6, O2} |
| 20 | Fystack is unaudited / does not encrypt P2P / its nodes decode and enforce policy | Critic; M1 | **Refuted**: Apex audited (mpcium not); P2P encrypted since 2025-08-13; policy runs in closed Apex | {T1}; [G5 §2] |
| 21 | Fireblocks Gas Station is EVM-only; Fireblocks lacks TRON fee tooling | M7 | **Refuted**: Gas Station covers TRON | {O8} |
| 22 | Cobo and Fireblocks cannot check TRON at the signer | Draft positioning | **Refuted**: Fireblocks `rawTx` includes TRX; Cobo's template has a TRON adapter | [G5 §7.3]; {T6} |
| 23 | TRON-first operations differentiate Vaultex from low-cost platforms | M6, M7 | **Corrected**: catch-up; Privy, Turnkey, Polygon OMS and Dfns cover TRON | {O8, T9} |
| 24 | Flat self-hosted pricing is the wedge for SEA PSPs | M6 | **Corrected**: wins only at high volume against volume-priced vendors; not a wedge | {T9} |
| 25 | SEA PSPs and OTC desks with TRON flows are the beachhead | M6 | **Corrected**: no named demand; enforcement target; re-scoped to Thailand's licensed tier | {O1}; [G8 §0.7] |
| 26 | Post-Rakkar re-platforming demand exists | M1, G8 | **Downgraded to HYPOTHESIS**: no client churn evidenced | {O1, O6} |
| 27 | USDT is 52–67% of Thai trading value | G8 | **Corrected**: ≈66% (Jul 2026) / 76% (Aug 2026) per SEC data via press; the 52% floor is not traceable | {O1} |
| 28 | Wallet-infrastructure exits cluster at $90–260M | M6 | **Corrected**: priced single-vendor deals 2023–26 ≈$90–250M; $260M is a 2021–22 deal; Polygon's figure includes Coinme | {O11} |
| 29 | No vendor publishes tail latency | M7 | **Refuted**: Silence Labs published p50/p90/p99 (Sept 2026) | {O3} |
| 30 | Swapping in cggmp24 takes "weeks rather than quarters" | M4 | **Refuted**: ≈14–17 engineer-weeks of P0 work (ESTIMATE) | {O3}; [G1 §0.7] |
| 31 | Adopt Kudelski-audited Lockness `cggmp21` | M1, M7 | **Refuted**: cggmp21 0.6.3 is NO-GO (deprecated; CVE-2025-66017 unpatched; LGPL GMP mandatory) | {S1}; [G1 §0] |
| 32 | cggmp24 is covered by the Kudelski audit | Upstream README | **Misleading**: the audit covers a 2023 commit, 545 commits earlier | {T8} |
| 33 | Thai rules require certified HSM / FIPS modules | Early desk research | **Not found**: HSM appears only as an example in the texts read ("never" not proven) | {O7}; [G6 §1] |
| 34 | Turnkey offers on-prem | Market assumption | **Not found**: the whitepaper names it only as a future target | {S3} |
| 35 | The largest MPC messages are near the 1 MiB bus limit (>0.7 MB) | I2 | **Refuted**: ≈590 KB (56%) for GG20/CGGMP21; ≈692 KB (66%) for cggmp24 | [G3]; {S1} |
| 36 | Kryptodian is licensed and operating | Kryptodian PR; M5 | **Unresolved**: licence claimed; register reads conflict ("(Not operating)" vs absent) | {T7}; [G5 §3.9; G6 §1] |
| 37 | Utila Starter costs $499/month; Taurus multi-party-sig is production-ready | Earlier listings | **Refuted**: $799/month; the README disclaims production readiness | [M1 §11] |
| 38 | Mastercard bought Zerohash; Coinbase bought BVNK | Press rumours | **Refuted**: Mastercard bought BVNK; Zerohash talks ended | [M6 §4.1] |
| 39 | x402 has an official TRON "exact" scheme; AgentCore is open to third-party wallets | Market assumption | **Refuted**: TRON scheme unmerged; AgentCore allows only CDP and Privy | {T10} |
| 40 | The internal first-user project is a usable public reference / lighthouse | M6, M8, I10 | **Refuted for now**: no Vaultex integration yet | {W12} |
| 41 | Vaultex's signed authorization protects against a compromised gateway | Vaultex specs | **Refuted**: it protects only against a *forged* gateway | {W3, W5}; [M1 §1.5] |
| 42 | The Kudelski audit behind cggmp24 was a 10-person-day review | BRIEFING; ledger {T8} | **Not supported** (found in this synthesis): 10 person-days was Kudelski's 2022 Multisig Labs audit; the 2023 Dfns cggmp21 review's effort is not stated. The conclusion that the audit is old and thin is unaffected | [G7 §2 rows 1–2, §4.3; G1 §2.2] |

---

## 8. Positioning and differentiation

### 8.1 Table stakes: no credit for having them

| Table stake (2026) | Evidence that it is standard | Vaultex today |
|---|---|---|
| A customer-controlled share-holder or gate that can veto every signature | Fireblocks, Dfns, Cobo, Safeheron, Circle (enterprise), Builder Vault, mpcium authorizers {T6} | No |
| The raw unsigned transaction delivered to that gate, at least for EVM (TRON in Asia) | Fireblocks `rawTx` (incl. TRX); Cobo template [G5 §6] | No |
| A policy engine with whitelists, limits, quorum approvals and separation of duties; admin-quorum policy changes | All vendors [G5 §6; M1 §6] | Library-only {W3} |
| Authenticated, encrypted inter-party messaging | Fystack ECDH/AES-GCM; Dfns mTLS; required by Lockness [G5 §6; G1 §2.5] | No {W4} |
| Customer-held recovery independent of the vendor | Fireblocks recovery kit; Dfns Layer 4; BitGo Wallet Recovery Wizard; Turnkey offline backup shares [M7 §2.4] | No {W8} |
| Self-hosted / on-prem option | Fireblocks Hosted MPC, Dfns on-prem, Ledger HSM On-Prem, Taurus, Builder Vault, Sodot, Circle (enterprise), Fystack {S3, T7} | Yes (vendor-blind) {S3} |
| TRON + TRC-20 with fee tooling | Fireblocks, Dfns, Cobo, Safeheron, BitGo, Utila, Fystack, Turnkey, Privy {O8} | Encoders only {S4} |
| Third-party assurance | Named audits, SOC 2 Type II, ISO 27001, bug bounties [M7 §0; M6 §10] | None {W6} |
| Client SDKs in several languages | Dfns 10 SDKs / 8 languages; Turnkey 8; CDP 5; Fystack TS/Go {W17} | Rust only |
| Durable transaction lifecycle, deposits, sweeps, webhooks, reconciliation | Fireblocks, Circle, Turnkey, Cobo, Safeheron, Fystack [M7 §0; G8 §12] | None {W9} |
| SLA and support | Dfns 99.90–99.95%; Fireblocks >99.97%; status pages [M7 §2.2] | None |
| LICENSE, SBOM, signed releases | Procurement norm [M6 §10] | None {W7, W11} |

### 8.2 No longer differentiators

- **"Self-hosted" / "sovereign".** Incumbents sell on-prem and onshore variants. Only *full* vendor-blindness, with no vendor control plane, is rarer, and Fystack mpcium shares it {S3, T7}.
- **"Open-source MPC".** cb-mpc, Lockness, ZF FROST, OpenSigner and mpcium are all open; primitives are free [M6 §5.1].
- **"MPC vs TEE".** Both camps took security hits. The question is audited implementation plus defence in depth [M2a §5.4].
- **"Signers can veto"** {T6}.
- **"TRON-first fee operations"** {O8}.
- **"Cheaper"** {T9}.
- **"Uses audited cryptography"**, until a delta review of the pinned versions exists {T8}.
- **"50 chains"** {W15}.

### 8.3 Possibly unoccupied (HYPOTHESIS)

These hold within the set G5 examined, re-checked 2026-10-09 {O2}; test: G5's broader sweep.

1. **Policy built into every share-holder, not one gate.** n independent verifiers decode the same bytes, recompute the digest and evaluate the same quorum-signed policy deterministically, so a t-of-n signature implies at least t independent policy passes. Competitors offer one customer veto, a vendor-side engine, or a closed per-share claim (Sodot) [G5 §7.2].
2. **Approver-signature verification as a native, open protocol.** Approvers sign a canonical, human-renderable intent statement (decoded fields, digest, wallet, policy version, expiry, nonce) with device-bound keys, and each node verifies k-of-n plus separation of duties. Cobo has this only as an unlicensed sample tied to its API; Fystack has it in a private SDK [G5 §7.2].
3. **TRON TRC-20 as a first-class decoder and policy path in OSI-licensed signer code:** contract-type allowlists, the transfer selector, token-contract allowlists, fee-limit caps, expiration and reference-block checks. Existing TRON parsers are unlicensed samples (Cobo, Vultisig) [G5 §7.2].
4. **Signed decision receipts from self-hosted MPC nodes,** written into a hash-chained audit ledger. Turnkey offers "verifiable policy decisions" for its own SaaS enclaves only [G5 §7.2].
5. **No single backend key with signing authority,** proven by a public red-team test. Today both mpcium's default and Vaultex depend on one backend key {T1, W5}.
6. **Fail-closed defaults.** Competitors' hooks are open by default {O2}.
7. **A fully OSI-licensed decision layer.** Fystack, Cobo, Dfns and Fireblocks keep it closed {S6}.
8. **Possible complements in Thailand:** key-less compliance modules (Travel Rule ownership proofs) and a clause-mapped compliance pack. Competing Travel Rule vendors and Kryptodian's bundle were not researched in depth {O4, O5}.

**Moat assessment (HYPOTHESIS).** The conjunction is copyable: Fystack's Cosigner is landing on branches {T1}, and Cobo and Fireblocks already have most ingredients as glue {T6}. Defensibility would come from:
- openness under a permissive licence;
- a public red-team result and an audit that covers the decoder and policy kernel;
- regulator-facing documentation mapped to local rules;
- Thai and SEA presence;
- speed.

None of this exists yet.

### 8.4 Positioning statement (conditional: a design target, not a product property)

> **For** licensed digital-asset operators in Southeast Asia — starting with Thai custodians, exchanges and brokers handling TRON-USDT — who must run custody themselves and evidence every signature to regulators,
> **Vaultex is** an open-source (MIT OR Apache-2.0), self-hosted threshold-signing stack in which **every signing node independently decodes the exact transaction, verifies approvers' signatures and a quorum-signed policy, refuses anything else, and signs a decision receipt**,
> **so that** neither a compromised application tier nor the vendor can move funds, and one public audit can serve every licensee.
> **Unlike** Fireblocks, Dfns and Cobo (a single customer veto beside a vendor control plane) and Fystack (open nodes, closed decision layer), **the whole decision layer is open, inspectable and runs entirely on the customer's infrastructure, and the vendor never holds key material.**

**Entry order** per ROADMAP §3.2: OSS kernel → callback-gate shadow deployments → Guard → licensed tier after M10-F.

**Status.** As of 2026-10-09 none of the distinguishing properties is shipped:
- signers trust gateway assertions {W3};
- ECDSA cannot sign at production parameters {W1};
- the transport leaks key-generation secrets {W4};
- there is no LICENSE {W7}.

Until the proof bar below is met, the honest public label is the canonical project banner (ROADMAP M5 item 1): *"UNAUDITED PRE-ALPHA RESEARCH SOFTWARE · TESTNET ONLY · DO NOT USE WITH REAL FUNDS. Known critical limitations (by category): (1) affected scheme classes — the hand-rolled threshold-ECDSA engines are unsound, and Sr25519/BLS signing is not threshold; (2) transport confidentiality during key generation; (3) control-plane freshness; (4) unenforced signing policy — signers do not independently verify what they sign; (5) unsafe deposit addresses: addresses exported by pre-cut versions for unimplemented chains, and P2WPKH addresses shown for FROST-TR wallets, may be unspendable; do not send funds to them."* {T5}

### 8.5 Proof bar before the claim is made

All seven items are from [G5 §9]; {O2}.

1. Nodes receive the unsigned transaction, not only a digest. They decode it with a canonical decoder (TRON first, then EVM), recompute the digest and fail closed.
2. A quorum-signed policy bundle is pinned and versioned on each node, and its hash is bound into every authorization and receipt.
3. Device-bound, k-of-n approver signatures with separation of duties, over a canonical intent statement, are verified **in each node**.
4. Velocity and limit state never comes from the gateway.
5. Each node emits a signed decision receipt into the audit ledger.
6. A **public red-team test**: neither a compromised gateway nor a single compromised node can obtain an out-of-policy TRC-20 signature. It must run on the replacement ECDSA engine with transport and peer identity hardened.
7. An **external audit** whose scope explicitly includes the decoder and policy kernel, not only the cryptography.

### 8.6 Claims to avoid

| Do not claim | Why | Say instead (once true) |
|---|---|---|
| "First" or "only" signers that cannot be lied to | Refuted {T6} | "Every signing node independently decodes, verifies approvals and enforces policy; fully open source" |
| "Nodes enforce policy and verify approvals" | False today {W3} | "Design goal; see roadmap" |
| "Production-ready", "50 chains", "audited", "FIPS", "TEE-protected" | {W14, W15, T8, O7} | Exact counts and statuses |
| "MIT open source" | No LICENSE file {W7} | Add the licence first |
| "Fystack is unaudited" / "does not encrypt P2P" | Refuted {T1} | "No public audit of mpcium was found as of 2026-10-08"; compare specific properties |
| "Cobo and Fireblocks can't check TRON at the signer" | Refuted [G5 §7.3] | "They leave TRON decoding to customer-written glue" |
| "Non-custodial software, so no licence is needed in Thailand" | [needs counsel] {T2} | Obtain a legal opinion; position as software only |
| "Cheaper than SaaS" | {T9} | Sell control, inspectability and compliance |

---

## 9. Sources

Dates are publication dates where known; "acc." means accessed 2026-10-08 or 2026-10-09 by the cited round-1 or verifier work. Round-1 report IDs show which report verified each source. Thai SEC primary documents (sec.or.th) are cited only through [G6] and [M5], and their links are deliberately omitted (owner instruction: the site serves documents as file downloads). URLs below carry no round-2 re-fetch unless marked "verifier 2026-10-09".

### §0–1. Market shifts (TEE move, consolidation, agents, stablecoins)

- Coinbase CDP security overview (Nitro) — https://docs.cdp.coinbase.com/wallets/security-and-policies/security-overview — acc. [M2b]
- Coinbase CDP pricing — https://docs.cdp.coinbase.com/server-wallets/v2/introduction/pricing — acc.; verifier 2026-10-09 [M2b; T9]
- Coinbase CDP networks (EVM/Solana) — https://docs.cdp.coinbase.com/api-reference/networks — verifier 2026-10-09 [O8]
- Lit Protocol, "Lit V3 is live" — https://spark.litprotocol.com/lit-v3-is-live-confidential-compute-and-key-management-in-one-api/ — 2026-04-01 [M2a; M2b]
- Lit Protocol, Naga sunset — https://spark.litprotocol.com/naga-network-sunset/ — 2026-03 [M2a]
- Privy security architecture — https://docs.privy.io/security/wallet-infrastructure/architecture — acc. [M2b]
- Alchemy signer sunset (sign-ups ended 2026-06-16) — https://www.alchemy.com/docs/wallets/signer/export-private-key — acc. [M2a]
- Stripe Sessions 2026 announcements — https://stripe.com/blog/everything-we-announced-at-sessions-2026 — 2026-04-29 [M2a]
- Fireblocks acquires Dynamic — https://www.fireblocks.com/blog/fireblocks-acquires-dynamic — 2025-10-23 [M2a]
- Fortune, Fireblocks–TRES (~$130M) — https://fortune.com/2026/01/07/fireblocks-tres-finance-acquisition-130-million/ — 2026-01-07 [M1]
- Paxos acquires Fordefi — https://www.prnewswire.com/news-releases/paxos-acquires-fordefi-to-build-the-custody-infrastructure-layer-to-power-the-on-chain-economy-302625620.html — 2025-11-25 [M1]
- Polygon Labs to acquire Coinme and Sequence — https://www.prnewswire.com/news-releases/polygon-labs-inks-deal-to-acquire-coinme-sequence-for-250m-to-expand-into-us-licensed-stablecoin-payments-302660006.html — 2026-01-13 [M2a]
- CoinDesk, MoonPay acquires Sodot (~$100M in stock) — https://www.coindesk.com/business/2026/04/29/moonpay-acquires-israeli-crypto-security-firm-sodot-in-usd100-million-stock-deal — 2026-04-29 [M2b; O11]
- MoonPay Institutional announcement — https://www.moonpay.com/newsroom/moonpay-institutional — 2026-04-28/29 [M6]
- Calcalist, eToro acquires Zengo (~$70M) — https://www.calcalistech.com/ctechnews/article/ryfuhp2hbl — 2026-04-15 [M2a]
- Payward to acquire Magic Labs' wallet infrastructure — https://www.payward.com/press-release/payward-to-acquire-magic-labs-wallet-infrastructure — 2026-07-27 [M2a]
- CoinDesk, Standard Chartered to acquire the rest of Zodia — https://www.coindesk.com/business/2026/05/18/standard-chartered-to-acquire-remainder-of-subsidiary-zodia-custody — 2026-05-18 [M1]
- CoinDesk, Copper sale process — https://www.coindesk.com/business/2026/05/20/crypto-custody-firm-copper-is-looking-to-sale-the-company-for-usd500-million — 2026-05-20 [M1]
- Crypto Briefing, Copper CEO departs — https://cryptobriefing.com/copper-ceo-departs-buyer-search-continues/ — 2026-09-08 [M1]
- Companies House, Qredo Ltd filing history — https://find-and-update.company-information.service.gov.uk/company/07834052/filing-history — acc. [M1]
- Polygon, free embedded wallets — https://polygon.technology/blog/get-unlimited-embedded-wallets-free-with-crosschain-routing-included — 2026-08-11 [M2a]
- Polygon OMS supports TRON — https://polygon.technology/blog/polygon-oms-supports-tron — 2026 [M2a; T9]
- AWS, Bedrock AgentCore payments GA — https://aws.amazon.com/about-aws/whats-new/2026/08/bedrock-agentcore-payments-ga/ — 2026-08-18 [M2b; T10]
- Linux Foundation, x402 Foundation operational launch — https://www.prnewswire.com/news-releases/linux-foundation-announces-operational-launch-of-x402-foundation-to-standardize-internet-native-payments-for-ai-agents-and-applications-302824778.html — 2026-07-14 [M2b]
- x402 TRON "exact" scheme tracking issue #2075 — https://github.com/x402-foundation/x402/issues/2075 — opened 2026-04-20; open on 2026-10-09 [M2b; T10]
- BofAI/x402 (third-party TRON SDK) — https://github.com/BofAI/x402 — 2026 [M2b]
- CoinDesk, x402 demand "not there yet" — https://www.coindesk.com/markets/2026/03/11/coinbase-backed-ai-payments-protocol-wants-to-fix-micropayment-but-demand-is-just-not-there-yet — 2026-03-11 [M2b]
- Chainalysis, x402 adoption — https://www.chainalysis.com/blog/x402-agentic-payments-adoption/ — 2026-06-03 [M2b]
- American Banker, agentic payment rail volume decline — https://www.americanbanker.com/payments/news/agentic-payment-rail-shows-volume-decline — 2026-09-18 [M6; T10]
- CCN (Helios Analytics data), x402 settlement volume −93% YTD — 2026-08-13 — URL not captured in the round-1/2 notes [T10]
- DefiLlama, stablecoins by chain — https://stablecoins.llama.fi/stablecoinchains — acc. 2026-10-08 [M6]

### §2. Competitor matrices

- Fireblocks pricing — https://www.fireblocks.com/pricing — acc.; verifier 2026-10-09 [M1; G5]
- Fireblocks, "What's new in security, summer 2026" — https://www.fireblocks.com/blog/new-in-fireblocks-security-summer-2026 — 2026-06-17 [M1]
- Fireblocks Vietnam blog — https://www.fireblocks.com/blog/vietnam-digital-assets-growth — 2026-07-01 [M1; G8]
- Fireblocks co-signer architecture — https://developers.fireblocks.com/docs/cosigner-architecture-overview — acc. [G5]
- Fireblocks Intel SGX API co-signer — https://developers.fireblocks.com/docs/intel-sgx-api-co-signer — acc. [G5; S3]
- Fireblocks transaction-approval callback (`rawTx`) — https://developers.fireblocks.com/reference/approve-transactions — acc. [G5]
- Fireblocks Hosted MPC overview — https://support.fireblocks.io/hc/en-us/articles/12901739472924-Hosted-MPC-Overview — article created 2024-03-03 [S3]
- Fireblocks, enable the Gas Station (EVM and TRON) — https://developers.fireblocks.com/docs/enabling-the-gas-station-1 — verifier 2026-10-09 [O8]
- Fireblocks, gas management overview — https://developers.fireblocks.com/docs/gas-management — verifier 2026-10-09 [O8]
- Fireblocks, staking TRON (freeze and delegation) — https://support.fireblocks.io/hc/en-us/articles/26617201221916-Staking-TRON-TRX-with-Freeze-and-Delegation — verifier 2026-10-09 [O8]
- Fireblocks developer community thread, "Using Custom Gas Vaults in Gas Station – Auto-Fuel Issue & Tron Support" — community.fireblocks.com — 2025-08/09 [O8]
- Fireblocks Agentic Payments Suite — https://www.prnewswire.com/news-releases/fireblocks-joins-x402-foundation-launches-agentic-payments-suite-302777251.html — 2026-05-20 [M2b]
- Fireblocks `mpc-lib` (GPL-3.0) — https://github.com/fireblocks/mpc-lib — acc. [M1; M3]
- Dfns pricing — https://dfns.co/pricing — acc.; verifier 2026-10-09 [M1; G5; T9]
- Dfns SLA — https://dfns.co/legal/sla — last updated 2024-05-01 [M7; T9]
- Dfns MPC deployment models — https://docs.dfns.co/advanced/deployment-models/mpc — acc. [G5; S3]
- Dfns Validation Gate — https://docs.dfns.co/advanced/deployment-models/validation-gate — acc.; MPC signer changelog https://docs.dfns.co/changelog/mpc-signer [G5; T6]
- Dfns disaster recovery (Layer 4) — https://docs.dfns.co/advanced/deployment-models/disaster-recovery — acc. [M7]
- Dfns TRON network page (fee sponsorship via native resource delegation) — https://docs.dfns.co/networks/tron — verifier 2026-10-09 [M7; O8]
- Dfns rebrand — https://www.businesswire.com/news/home/20260603859127/en/DFNS-Rebrands-as-the-Core-Banking-Platform-for-Digital-Assets — 2026-06-03 [M2b]
- Cobo pricing — https://www.cobo.com/pricing — acc. [M1; G5]
- Cobo TSS Node overview — https://www.cobo.com/developers/v2/guides/mpc-wallets/server-co-signer/tss-node-overview — acc. [G5]
- Cobo MPC callback-server template (no licence) — https://github.com/CoboGlobal/cobo-mpc-callback-server-v2-template — pushed 2026-08-05 [G5]
- Cobo Fee Station — https://www.cobo.com/post/cobo-fee-station-one-stop-solution-for-multi-chain-gas-issues — verifier 2026-10-09 [O8]
- Cobo Thailand custody release — https://www.cobo.com/post/cobo-thailand-institutional-digital-asset-custody — 2026-01-20 (dateline 2026-01-12) [G8]
- The Block, Cobo launches Agentic Wallet — https://www.theblock.co/post/397856/cobo-launches-agentic-wallet — 2026-04-20 [M2b]
- Safeheron pricing — https://safeheron.com/pricing/ — acc. [M6; G5]
- Safeheron API Co-Signer — https://developer.safeheron.com/concepts/api-cosigner — acc. [G5]
- Safeheron TRON energy rental — https://safeheron.com/blog/tron-energy-rental/ — verifier 2026-10-09 [O8]
- Utila pricing — https://utila.io/pricing — acc. [M1]
- Blockonomi, Utila TRON resource management — https://blockonomi.com/utila-integrates-tron-resource-management-offering-fintechs-up-to-80-reduction-in-transaction-costs/ — 2026-03 [O8]
- Taurus platform — https://www.taurushq.com/platform/ — acc. [M1]
- Ripple Custody MPC overview — https://docs.ripple.com/products/custody/deployment/integrate-kms/mpc/overview — acc. [M1]
- Ledger Enterprise HSM On-Premise — https://enterprise.ledger.com/news/hsm-on-premise — 2026-07-13 [M1]
- Blockdaemon Builder Vault MPC protocols — https://builder-vault-tsm.docs.blockdaemon.com/docs/mpc-protocols — acc.; key generation and signing https://builder-vault-tsm.docs.blockdaemon.com/docs/key-generation-and-signing — updated 2026-08-19 [M1; G5]
- Sodot MPC infrastructure — https://www.sodot.dev/product/mpc-infrastructure — acc. [M2b; G5]
- BitGo Q2 2026 results — https://investors.bitgo.com/news/news-details/2026/BitGo-Announces-Second-Quarter-2026-Financial-Results/default.aspx — 2026-08-12 [M1]
- BitGo TRON resource delegation — https://developers.bitgo.com/docs/tron-resource-delegation — verifier 2026-10-09 [O8]
- BitGo billing methodology — https://bitgo.com/resources/billing-methodology/ — undated [M6]
- Fystack mpcium — https://github.com/fystack/mpcium — HEAD `90e3ee3c`, 2026-10-07 [G5; T1]; PRs https://github.com/fystack/mpcium/pull/166 and https://github.com/fystack/mpcium/pull/168 — merged to feature branches 2026-10-07
- Fystack pricing — https://fystack.io/pricing — acc. [G5]; Cosigner page https://fystack.io/solutions/cosigner — acc.
- Adevar Labs audit index (Fystack Apex backend report, 2026-06-17) — https://github.com/AdevarLabs/audit-reports — acc. [G5; G7]
- Fystack × TronZap — https://fystack.io/blog/fystack-x-tronzap-cut-tron-network-fees-by-up-to-60-with-on-chain-energy-renting — 2026-03 [O8]; changelog https://fystack.io/changelog — verifier 2026-10-09
- Circle Wallets key management — https://developers.circle.com/wallets/key-management — acc. [M2b; G5; S3]
- Circle supported blockchains (no TRON) — https://developers.circle.com/wallets/supported-blockchains — verifier 2026-10-09 [G5; O8]
- Circle Agent Stack — https://www.circle.com/blog/introducing-circle-agent-stack-financial-infrastructure-for-the-agentic-economy — 2026-05-11 [M2b]
- Turnkey pricing — https://www.turnkey.com/pricing — acc.; verifier 2026-10-09 [M2b; T9]
- Turnkey whitepaper — https://whitepaper.turnkey.com/foundations — 2025-01 [M2b; S3]
- Turnkey TRON support ("Tron support on Turnkey") — docs.turnkey.com — verifier 2026-10-09 [O8]
- Privy pricing — https://www.privy.io/pricing — page dated 2026-10-07 [M2a; T9]
- The Block (sponsored), Privy expands TRON support — https://www.theblock.co/sponsored/2026-09-28-privy-expands-support-for-tron-with-enhanced-wallet-and-payment-infrastructure-for-developers-416194 — dateline 2026-09-23 [M2a]
- Privy recipe, "Sponsor gas on Tron with Transatron" — docs.privy.io — verifier 2026-10-09 [O8]
- CryptoBriefing, Dynamic SDK V5 (TSS-MPC default) — https://cryptobriefing.com/dynamic-sdk-v5-tss-mpc-wallet-security/ — 2026-08-17 [M2a]
- MetaMask Embedded Wallets — https://metamask.io/news/embedded-wallets-developer-platform — 2026-06-02 [M2a]
- Para pricing — https://www.getpara.com/pricing — acc. [M2a]
- Openfort OpenSigner — https://github.com/openfort-xyz/opensigner — acc. [M2a]
- thirdweb pricing — https://thirdweb.com/pricing — page dated 2026-09-25 [M2a]
- Coinbase CDP Embedded Wallets pricing — https://docs.cdp.coinbase.com/embedded-wallets/pricing — acc. [M2a]
- Vultisig verifier (MIT) — https://github.com/vultisig/verifier — acc.; recipes (no licence) https://github.com/vultisig/recipes [G5]
- OCC conditional national trust charters (NR 2025-125) — https://www.occ.gov/news-issuances/news-releases/2025/nr-occ-2025-125.html — 2025-12-12 [M1]
- Hex Trust SOC 1/SOC 2/CSA STAR — https://hextrust.com/resources-collection/hex-trust-reaffirms-soc-1-soc-2-and-csa-star-level-2-audit — 2026-03-10 [M1]
- Ceffu, Binance TH chooses Ceffu — https://www.ceffu.com/blog/binance-th-ceffu — 2024-06 [M1]
- orbix CUSTODIAN activation — https://www.orbixcustodian.com/news/orbix-custodian-activated-release/en/index.html — 2025-03-11 [M1; G8]
- The Story Thailand, orbix and IBM HSM — https://www.thestorythailand.com/en/12/06/2025/155549 — 2025-06-12 [G8; O7]
- Rakkar licence and AUC — https://www.rakkardigital.com/resources/rakkar-secures-thailands-digital-asset-custodian-license-and-achieves-us-700m-auc — 2024-12-24 [M1; G8]
- Thansettakij, Rakkar closure report — https://www.thansettakij.com/finance/wealth-tech/647387 — 2025-12-24 [G8]
- Infoquest, DV8–Rakkar share purchase — https://www.infoquest.co.th/2026/579551 — 2026-03-24 [G8]
- Thailand Times, Kryptodian licence PR — https://www.thailandtimes.net/2026/09/kryptodian-thailand.html — 2026-09-25 [G5]
- ICC Indonesia (first OJK custodian) — https://www.coincustodian.id/en/publications/siaran-pers/icc-lembaga-kustodian-pertama-berizin-ojk-jamin-keamanan-aset-kripto-konsumen — 2025-12-04 [G8]
- OJK, Arganis custodian licence — https://www.ojk.go.id/id/berita-dan-kegiatan/pengumuman/Pages/Pemberian-Izin-Usaha-PT-Arganis-Konsultindo-Utama.aspx — 2026-03 [M1; G8]

### §3. Threshold cryptography, vulnerabilities and libraries

- GHSA-m95p-425x-x889 (CVE-2025-66016) — https://github.com/advisories/GHSA-m95p-425x-x889 — 2025-11-24 [M3; M4]
- GHSA-8frv-q972-9rq5 (CVE-2025-66017) — https://github.com/advisories/GHSA-8frv-q972-9rq5 — 2025-11-24 [M3; M4]
- RUSTSEC-2025-0129 — https://rustsec.org/advisories/RUSTSEC-2025-0129.html — 2025-11-25 [M4]
- Dfns, "CGGMP21 vulnerabilities patched and explained" — https://dfns.co/article/cggmp21-vulnerabilities-patched-and-explained — 2025-11-24 [M3; G1]
- LFDT-Lockness cggmp21/cggmp24 repository — https://github.com/LFDT-Lockness/cggmp21 — pushed 2026-10-05 [M3; G1]
- LF Decentralized Trust, Lockness — https://www.lfdecentralizedtrust.org/blog/lockness-a-new-home-for-trusted-key-cryptography — 2024-09 [M3]
- Zcash Foundation FROST — https://github.com/ZcashFoundation/frost — acc.; v3.0.0 release https://zfnd.org/frost-release-v3-0-0/ — 2026-04 [M3; M4]
- NCC Group, Zcash FROST assessment — https://research.nccgroup.com/2023/10/23/public-report-zcash-frost-security-assessment/ — 2023-10-23 [M3]
- Coinbase cb-mpc — https://github.com/coinbase/cb-mpc — acc.; Cure53 report https://cure53.de/audit-report_coinbase-kms.pdf — 2024 [M3; M4]
- Silence Laboratories dkls23 (licence) — https://github.com/silence-laboratories/dkls23 — acc. [M2a; M3]
- Trail of Bits, DKLs23 library review — https://blog.trailofbits.com/2025/06/10/what-we-learned-reviewing-one-of-the-first-dkls23-libraries-from-silence-laboratories/ — 2025-06-10 [M3; M4]
- Silence Labs DKLs23 benchmarks — https://dkls23.silencelaboratories.com/ — 2026-09-01 [M7]
- 0xCarbon DKLs23 — https://github.com/0xCarbon/DKLs23 — acc. [M3; G1]
- NEAR mpc — https://github.com/near/mpc — acc. [M3]
- bnb-chain tss-lib — https://github.com/bnb-chain/tss-lib — acc.; v4 hardening PR https://github.com/bnb-chain/tss-lib/pull/332 [M3; M4]
- Taurus multi-party-sig — https://github.com/taurushq-io/multi-party-sig — acc.; GO-2024-3288 https://pkg.go.dev/vuln/GO-2024-3288 [M3]
- getamis alice — https://github.com/getamis/alice — acc. [M3]
- Entropy synedrion — https://github.com/entropyxyz/synedrion — acc. [M3]
- ZenGo multi-party-ecdsa — https://github.com/ZenGo-X/multi-party-ecdsa — acc. [M3]
- Axelar tofn — https://github.com/axelarnetwork/tofn — acc. [M3]
- Alpha-Rays, ePrint 2021/1621 — https://eprint.iacr.org/2021/1621 — 2021-12 [M4]
- Fireblocks, GG18/GG20 Paillier key vulnerability (BitForge) — https://www.fireblocks.com/blog/gg18-and-gg20-paillier-key-vulnerability-technical-report — 2023-08-09 [M4]
- Verichains, TSSHOCK — https://verichains.io/tsshock/ — 2023-08-10 [M4; G8]
- ePrint 2023/1234, practical key-extraction attacks — https://eprint.iacr.org/2023/1234 — 2023-08 [M4]
- Trail of Bits, "Breaking the shared key in threshold signature schemes" — https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/ — 2024-02-20 [M4]
- Fordefi, "Devious Transfer" — https://blog.fordefi.com/devious-transfer-breaking-oblivious-transfer-based-threshold-ecdsa — undated [M4]
- Segev, DKLs23 statistical vs computational security (ePrint 2026/929) — https://eprint.iacr.org/2026/929 — 2026-05-11 [M4]
- Cryptanalysis of LDVR (ePrint 2026/2126) — https://eprint.iacr.org/2026/2126 — 2026-09-22; FROST and LDVR (ePrint 2026/2203) — https://eprint.iacr.org/2026/2203 — 2026-09-27 [M4]
- THORChain Exploit Report #1 — https://blog.thorchain.org/thorchain-exploit-report-1 — 2026-05-20 [M3; M8]
- QuillAudits, THORChain GG20 analysis — https://www.quillaudits.com/blog/hack-analysis/thorchain-gg20-hack — 2026-05-26 [M3]
- RFC 9591 (FROST) — https://www.rfc-editor.org/info/rfc9591 — 2024 [M4]
- BIP-445 draft PR — https://github.com/bitcoin/bips/pull/2070 — opened 2026-01-03 [M4]
- ChillDKG — https://github.com/BlockstreamResearch/bip-frost-dkg — acc. [M4]
- NIST, first call for multi-party threshold schemes (IR 8214C) — https://www.nist.gov/news-events/news/2026/01/nist-first-call-multi-party-threshold-schemes-nist-ir-8214c — 2026-01-20 [M3; M4]
- NIST threshold cryptography project — https://csrc.nist.gov/projects/threshold-cryptography — updated 2026-10-06 [M4]
- Mithril (ePrint 2026/013) — https://eprint.iacr.org/2026/013 — 2026; Quorus (ePrint 2025/1163) — https://eprint.iacr.org/2025/1163 [M4]
- Trail of Bits, "Don't let TEEs break your MPC" — https://blog.trailofbits.com/2026/09/25/dont-let-tees-break-your-mpc/ — 2026-09-25 [M2b; O7]
- Trail of Bits, Nitro Enclaves KMS notes — https://blog.trailofbits.com/2026/08/05/a-few-notes-on-aws-nitro-enclaves-kms-integration/ — 2026-08-05 [M2b]
- TEE.fail — https://tee.fail/ — 2025-10; Battering RAM — https://batteringram.eu/ — 2025-09-30 [M2a; M2b]
- ethereum.org, quantum-resistance roadmap — https://ethereum.org/roadmap/security/quantum-resistance/ — updated 2026-09-08 [M4]

### §4. Incidents

- FBI IC3 PSA (Bybit / TraderTraitor) — https://www.ic3.gov/PSA/2025/PSA250226 — 2025-02-26 [M1; M8]
- Sygnia, Bybit investigation — https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/ — 2025-03-16 [M8]
- Wikipedia, 2024 WazirX hack — https://en.wikipedia.org/wiki/2024_WazirX_hack — acc. [M1; M8]
- NPA (Japan), DMM attribution — https://www.npa.go.jp/bureau/cyber/pdf/20241224_caution.pdf — 2024-12-24 [M8]
- Chainalysis, lessons from the Drift hack — https://www.chainalysis.com/blog/lessons-from-the-drift-hack/ — 2026-04-09 [M8]
- LayerZero, KelpDAO incident statement — https://layerzero.network/blog/kelpdao-incident-statement — 2026-04-19 [M8]
- TRM Labs, Coldcard exploit — https://www.trmlabs.com/resources/blog/the-largest-hardware-wallet-exploit-of-2026-inside-the-usd-116-million-coldcard-hack — 2026-08-05 [M8]
- TRM Labs, Liquid Network hack — https://www.trmlabs.com/resources/blog/2026s-biggest-hack-to-date-attackers-drained-usd-319-million-in-bitcoin-from-liquid-network-then-returned-85-of-funds — 2026-09-08 [M1; M8]
- The Hacker News, Bitget third-party zero-day — https://thehackernews.com/2026/10/bitget-confirms-third-party-zero-day.html — 2026-10-01 [M8]
- Chainalysis, $387M Bitget theft — https://www.chainalysis.com/blog/387m-bitget-theft-2026/ — 2026-10-01 [M8]
- Bitget incident page — https://www.bitget.com/campaigns/bitget-security-incident-2026 — 2026-09/10 [M1]
- Kiln, security incident information — https://www.kiln.fi/post/re-enablement-of-kiln-services-and-security-incident-information — 2025-10-07 [M8]
- CoinDesk, BigONE hack — https://www.coindesk.com/markets/2025/07/16/crypto-exchange-bigone-confirms-27m-hack-vows-full-user-compensation — 2025-07-16 [M8]
- The Block, Upbit flaw — https://www.theblock.co/post/380764/upbit-says-emergency-audit-of-30m-hack-uncovered-flaw-that-could-expose-private-keys — 2025-11-28 [M8]
- UPI on TRM H1-2026 (DPRK $643M / 66%) — https://www.upi.com/Top_News/World-News/2026/07/03/North-Korea-crypto-theft-two-thirds-H1-TRM-Labs/4361783069480/ — 2026-07-03 [M8]
- Forbes on CertiK H1-2026 (~$1.3B) — https://www.forbes.com/sites/boazsobrado/2026/07/17/fewer-but-far-more-surgical-crypto-hacks-hit-13-billion-in-2026/ — 2026-07-17 [M8]
- CISA, tj-actions/reviewdog compromise — https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction — 2025-03-18 [M8]
- Rust blog, malicious crates `faster_log` / `async_println` — https://blog.rust-lang.org/2025/09/24/crates.io-malicious-crates-fasterlog-and-asyncprintln/ — 2025-09-24 [M8]
- Aikido, npm debug/chalk compromise — https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised — 2025-09-08 [M8]
- Ledger, Connect Kit exploit letter — https://www.ledger.com/blog/a-letter-from-ledger-chairman-ceo-pascal-gauthier-regarding-ledger-connect-kit-exploit — 2023-12-14 [M8]
- ERC-7730 (clear-signing descriptors, draft) — https://eips.ethereum.org/EIPS/eip-7730 — created 2024-02-07 [M8]
- Other 2024–26 incident URLs (Radiant, Phemex, Nobitex, CoinDCX, Infini, BitoPro, Ronin, Harmony, Multichain, Orbit) are listed in [M8 §13]

### §5. Regulation and certification (brief)

- Infoquest, SEC revises DA custodian rules (≥95% cold; no delegation) — https://www.infoquest.co.th/2025/526256 — 2025-09-02 [M5; G8]
- Mahanakorn Partners, Thai stablecoin transfer controls and Travel Rule — https://mahanakornpartners.com/thailand-tightens-the-net-on-stablecoin-transactions-proposed-transfer-controls-and-a-new-digital-asset-travel-rule/ — 2026-09-16 [M5; G8]
- Fintech News Singapore, Thailand Travel Rule from Feb 2027 — https://fintechnews.sg/136660/thailand/thailand-crypto-travel-rule/ — 2026-09-03 [M5]
- Baker McKenzie, *A Complete Guide to Digital Asset Law in Thailand*, 2025 edition — https://www.bakermckenzie.com/en/-/media/files/insight/guides/2025/a-complete-guide-to-digital-asset-law-in-thailand-2025.pdf — law as of 2025-02-14 [M5; M6; G6]
- FSTB & SFC, consultation conclusions on VA custodian services — https://www.fstb.gov.hk/fsb/en/publication/consult/doc/Custodian_consultation_conclusion_e.pdf — 2025-12 [M5; G6]; HK Government press release https://www.info.gov.hk/gia/general/202512/24/P2025122400265.htm — 2025-12-24
- SFC circular 25EC44 — https://apps.sfc.hk/edistributionWeb/api/circular/list-content/circular/intermediaries/supervision/doc?refNo=25EC44&lang=EN — 2025-08-15 [G7; M5]
- ESMA, MiCA — https://www.esma.europa.eu/esmas-activities/digital-finance-and-innovation/markets-crypto-assets-regulation-mica — updated 2026-10-07 [M1]; AMF on the end of the MiCA transition https://www.amf-france.org/en/news-publications/news/end-mica-transitional-period-esma-sets-out-its-expectations-professionals-and-warns-retail-investors — 2026-06-23 [M5]
- DORA Art. 30 — https://www.digital-operational-resilience-act.com/Article_30.html — acc.; RTS (EU) 2024/1773 Art. 8 https://www.springlex.eu/en/packages/dora/rts-tisp-regulation/article-8/ [G7]
- Covington, the GENIUS Act becomes law — https://www.cov.com/en/news-and-insights/insights/2025/07/the-genius-act-becomes-law-key-provisions-from-the-federal-stablecoin-regulatory-framework — 2025-07 [M5]
- NIST CMVP (FIPS 140-2 Historical) — https://csrc.nist.gov/projects/cryptographic-module-validation-program — acc. [M1; M5]
- CCSS — https://cryptoconsortium.org/standards/CCSS — acc. [M5; M8]
- Baker McKenzie, Vietnam Resolution 05/2025 — https://www.bakermckenzie.com/-/media/files/insight/publications/alerts/09/vietnam-new-resolution-on-pilot-program-for-digital-and-crypto-assets-marke.pdf — 2025-09 [M5; G8]; Tilleke, Decision 96 https://www.tilleke.com/insights/vietnam-begins-accepting-license-applications-for-crypto-asset-trading-platforms/ — 2026-01-22
- Mondaq, Vietnam draft reporting circular — https://www.mondaq.com/commoditiesderivativesstock-exchanges/1849520/ — 2026-09 [G8]
- LuatVietnam, Decree 284/2026/ND-CP — https://english.luatvietnam.vn/decree-no-284-2026-nd-cp-dated-july-16-2026-of-the-government-prescribing-the-sanctioning-of-administrative-violations-regarding-crypto-assets-and-t-440680-doc1.html — 2026-07-16 [G8]
- Assurance anchors [G7]:
  - Arbitrum ARDC applications (rate cards) — https://forum.arbitrum.foundation/t/arbitrum-research-development-collective-elections-applications/20805 — 2024-02-12
  - Trail of Bits ARDC v2 ($700/h) — https://forum.arbitrum.foundation/t/election-application-thread-v2-arbitrum-research-development-collective/27267/16 — 2024-11-18
  - a16z crypto, security audit best practices — https://a16zcrypto.com/posts/article/security-audit-best-practices/ — 2025-05-09
  - OSTIF–STA impact report — https://ostif.org/wp-content/uploads/2025/01/2024-Sovereign-Tech-Agency_OSTIF-Impact-Report.pdf — 2025-01
  - Vanta, SOC 2 audit cost — https://www.vanta.com/collection/soc-2/soc-2-audit-cost; ISO 27001 cost — https://www.vanta.com/collection/iso-27001/iso-27001-certification-cost
  - HackerOne Community Edition — https://www.hackerone.com/company/open-source-community
  - Immunefi — https://immunefi.com/bug-bounty-program/
  - Reconix, Thai pentest cost guide — https://reconix.co/blog/pentest-cost-thailand-guide/ — 2026-03-03
  - Trail of Bits, AI-native — https://blog.trailofbits.com/2026/03/31/how-we-made-trail-of-bits-ai-native-so-far/ — 2026-03-31
- Thai SEC notifications and news releases (Kor Thor 19/2561 cl. 49/2(1); outsourcing cl. 6/1; Annex 6; Nor Por 7/2565 and 8/2565; Sor Thor 9/2569; SEC News 179/2026 and 183/2026) are cited via [G6 §2, §15] and [M5 §3]. Links are omitted here per the owner instruction.

### §6. Business models, pricing and SEA demand

- Forbes, Fireblocks company profile (2024 revenue) — https://www.forbes.com/companies/fireblocks/ — updated 2026-03 [M6]
- BitGo IPO pricing — https://www.businesswire.com/news/home/20260121850585/en/BitGo-Holdings-Announces-Pricing-of-Initial-Public-Offering — 2026-01-21 [M6]
- Safe Foundation Q1 2026 report — https://safefoundation.org/reports/q1-2026 — 2026 [M6]
- Ripple acquires Metaco — https://ripple.com/insights/ripple-acquires-metaco — 2023-05-17 [M6; O11]
- Calcalist, Fireblocks–Dynamic (~$90M) — https://www.calcalistech.com/ctechnews/article/s1zemqprel — 2025-10 [M6]
- Blockhead, Paxos–Fordefi (>$100M) — https://www.blockhead.co/2025/11/26/paxos-acquires-crypto-wallet-provider-fordefi-for-over-100-million/ — 2025-11-26 [M6]
- Coinbase 10-Q (Unbound, $258M consideration) — https://www.sec.gov/Archives/edgar/data/1679788/000167978822000085/coin-20220630.htm — 2022 [M6]
- Mastercard completes BVNK acquisition — https://investor.mastercard.com/investor-news/investor-news-details/2026/Mastercard-completes-acquisition-of-BVNK-to-advance-global-stablecoin-capabilities/default.aspx — 2026-08-03 [M6]
- Collaborative-custody pricing — https://casa.io/pricing ; https://www.unchained.com/pricing ; https://nunchuk.io/pricing — acc. [M6]
- Thai market statistics (SEC July 2026 data, summary) — https://x.com/cryptomindgroup/article/2090374887580070115 — 2026-08-20 [M6]; further press per {T7}
- TNGlobal, TrueMoney × Fireblocks THBT Phase 2 — https://technode.global/2026/09/15/truemoney-fireblocks-thbt-thailand-blockchain-payments/ — 2026-09-15 [G8]
- InnovestX custody disclosure — https://www.innovestx.co.th/cafeinvest/th/articles/digitalasset-security-24072026 — 2026 [G8]
- Marketing Oops, Maxbit PR (Rakkar as external custodian) — https://www.marketingoops.com/pr-news/crypto-currency-2/ — 2026-07-24 [G8]
- Cointelegraph, Thailand targets stablecoins in laundering crackdown — https://cointelegraph.com/news/thailand-targets-stablecoins-in-latest-laundering-crackdown — 2026-07 [G8]
- Tuoi Tre / Saigon Times, five Vietnamese applicants — https://tuoitre.vn/saigontimes/chan-dung-5-doanh-nghiep-vuot-vong-ho-so-thi-diem-san-tai-san-ma-hoa/ — 2026-03-19 [G8]
- CoinDesk, OKX and HashKey back CAEX — https://www.coindesk.com/markets/2026/04/10/okx-hashkey-back-usd380-million-vietnam-crypto-push-as-new-rules-near-rollout — 2026-04-10 [M1; G8]
- TNGlobal, Bithumb × SSI Digital — https://technode.global/2026/05/07/koreas-virtual-asset-exchange-bithumb-vietnams-ssi-digital-to-jointly-build-crypto-exchange/ — 2026-05-07 [G8]
- VTV, MoF reply (no licence yet) — https://vtv.vn/giao-dich-tai-san-ma-hoa-khong-qua-to-chuc-duoc-cap-phep-co-the-bi-xu-ly-100261007170845968.htm — 2026-10-08 [G8]
- Fireblocks Vietnam executive forums — https://luma.com/sbqfpbob ; https://luma.com/97zrasr1 — 2026-07-15/17 (year inferred) [G8]
- ICEx launch — https://icex.id/indonesia-crypto-exchange-launches-as-institutional-crypto-market-infrastructure-in-southeast-asia/ — 2026-04-02 [G8]
- Infobank, OJK revokes a crypto custodian's licence — https://infobanknews.com/ojk-cabut-izin-usaha-pengelola-aset-kripto-tennet-depository/ — 2026-03 [G8]
- Coins.ph × Fireblocks — https://coins.ph/blog/coins-ph-partners-with-fireblocks-for-crypto-asset-management/ — 2022-06 [G8]
- BPI × Meridian stablecoin remittance pilot — https://www.bpi.com.ph/about-bpi/news/bpi-to-pilot-digital-asset-to-peso-remittance-rail-using-stablecoin-settlement — 2026-07 [G8]
- Western Union selects Fireblocks (USDPT) — https://www.prnewswire.com/news-releases/western-union-selects-fireblocks-to-power-its-first-stablecoin-usdpt-302760774.html — 2026 [G8]
- The Edge, Kenanga takes 81.7% of KDX — https://theedgemalaysia.com/node/796929 — 2026-03-19 [G8]
- TNGlobal, Hata Series A — https://technode.global/2026/04/21/malaysias-digital-asset-exchange-hata-secures-8m-in-series-a-funding-led-by-bybit/ — 2026-04-21 [G8]
- Fireblocks Global Custodian Partner Program — https://www.fireblocks.com/press/fireblocks-creates-worlds-first-licensed-custodian-partner-program-for-digital-assets — 2024 [G8]
- The full named-organisation source list (T1–T31, V1–V20, I1–I13, P1–P14, M1–M11, R2–R6) is in [G8 §14]

### §7–8. SWOT ledger and positioning

- Round-2 verified ledger (S1–S8, W1–W17, O1–O11, T1–T10), verified 2026-10-09 against repo HEAD `ccd1f7f6` (read-only), the GitHub API, and the vendor pages listed above.
- Round-1 evidence reports: I1–I11 (internal code audits; private), M1–M8, G1–G8, all in the research folder. Code-level file:line evidence for unfixed defects is there and is not reproduced here.
- G5 teardown sources (Fystack, Circle, Fireblocks, Dfns, Cobo, Safeheron, BitGo, Blockdaemon, Sodot, Kryptodian, Vultisig, Turnkey) — [G5 §12]
- Turnkey, verifiable policy decisions — https://turnkey.com/blog/introducing-verifiable-policy-decisions — 2025-12-08 (modified 2026-09-24) [G5]
- BitGo, intent attestations press release — https://www.businesswire.com/news/home/20260430000122/en/ — 2026-04-30 [G5]
