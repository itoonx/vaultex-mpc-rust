# Threat model v2

| | |
|---|---|
| **Version** | 2.0-draft, 2026-10-11 |
| **Status** | **PROPOSED.** Drafted by R6 (advisory). Review by an independent cryptographer is pending; none is engaged yet (ADR-01). It models designs that are mostly **not implemented yet**; §0 explains how to read the status of each control. |
| **Covers** | Phase 1: the verifier kernel, the Guard co-signer and the outflow monitor (M6–M7). Phase 2: the target MPC line, meaning verifying nodes and a gateway relay (M8–M9, only if the G-MPC gate passes). The legacy code at HEAD appears only as a summary (§3.1). |
| **Replaces** | [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) v1 (2026-04-01), which is withdrawn. It described controls as effective that the code does not enforce. |
| **Sources** | [`docs/ROADMAP.md`](../ROADMAP.md) §2–§4 and §10; [`SECURITY_STATUS.md`](../../SECURITY_STATUS.md); the kernel, Guard and monitor design studies (WS-05, WS-06 and WS-07 deep dives in the private research archive; their public content lands as RFCs and specs). |
| **Public safety** | Category + fix only. No exploit mechanics, and no pointers into the code for unfixed defects. Known defects of the code at HEAD are listed in [`SECURITY_STATUS.md`](../../SECURITY_STATUS.md). |
| **Owner** | WS-14 (R7 + owner). Updated at every freeze (§10). |

---

## 0. How to read this

**Status of a control:**
- **Now**: present in the code at HEAD. It is experimental and has had no independent review ([`SECURITY_STATUS.md`](../../SECURITY_STATUS.md), "Controls present in the code").
- **M5 … M12**: an exit criterion of that milestone in [ROADMAP §4.3](../ROADMAP.md#43-milestone-definitions), cited as `M6 #2`; `PC-nn`, `PL-nn` and `RF-n` are the ROADMAP §2.2–§2.3 and §3.4 criteria. A control counts only once its milestone closes on an artifact (ROADMAP §9.5). Until then it is a plan.
- **Gated**: lands only if G-MPC passes (ADR-07). It may never be built.
- **Limit**: an accepted residual risk. It stays after every milestone, is listed in §9, and goes into the [known-issues list](KNOWN_ISSUES.md) §2.

**IDs.** SO (objectives), AS (assets), TB (trust boundaries), AC (actors), TH (threats), SC (scenarios), AP (assumptions) and LM (limits) are local to this document. They never reuse a ROADMAP prefix (RK, K, PC, PL, RF, ST, B, AL).

**Words.** A *signer* is any Vaultex component that contributes a signature: the Guard in Phase 1, an MPC node in Phase 2. *The kernel* is the verifier library that every signer runs before it signs (`vaultex-verify`, working name).

**What changed since v1:**
1. v1 listed protocol-level mitigations for the hand-rolled threshold-ECDSA engines. Those engines leave every build in M5 (deleted or quarantined: ADR-03), so v2 leaves them out of scope.
2. v1 treated the gateway as semi-trusted and relied on a gateway-issued authorization. v2 takes the gateway out of the value trust boundary: each signer decodes the bytes and checks policy and approvals itself.
3. v2 adds the Phase-1 Guard line, the independent outflow monitor, policy governance, operational domains and the supply chain.
4. Every control now names the milestone and the evidence that make it real. Nothing is described as done before its artifact exists.

---

## 1. Scope

**In scope:**
- the verifier kernel and the admin and approver CLIs (M6);
- the Guard co-signer, its keys and state, at Rungs 0–2 of the additive ladder (ROADMAP §3.4), plus the K-alt veto-hook fallback;
- the outflow monitor and the operational domains around the Guard (M7);
- the target MPC line for the declared v1 support matrix: TRON (TRX + TRC-20), 2-of-3 on one adopted, pinned engine with full interactive signing; verifying nodes; the gateway relay; transport and control plane v2; key store v2; recovery tooling (M8–M11, Gated).

**Out of scope, with the reason:**

| Item | Reason |
|---|---|
| Hand-rolled threshold-ECDSA engines, and Sr25519/BLS signing | Removed from builds in M5, deleted or quarantined (ADR-03), and outside every audit scope. Their keys are treated as exposed ([`SECURITY_STATUS.md`](../../SECURITY_STATUS.md) category 1) |
| Quarantined code: FROST adapters, staged chains other than TRON, the unverified chains, the single-process CLI, Helm/k8s/Terraform | Outside release builds (M5 #4, #8). An item re-enters scope only together with an update to this model |
| Rung 3 (a Guard quorum that can sign alone) and the partner callback gate in enforce mode | Each needs M10-K first (ROADMAP §2.4, §3.4). They get their own section before they are built. The callback gate has K-alt's guarantees (LM10) |
| The caller's side of the caller-builds boundary (ROADMAP §2.1): fees and energy, building, broadcast, confirmation, deposits, sweeps | Vaultex treats caller bytes as untrusted and refuses what it cannot verify. It does not protect the caller from its own builder beyond that (LM9) |
| The chains and token contracts themselves | Issuer and chain events are detected by the monitor (AC12), not prevented |
| The internals of the adopted engine library | Audit line AL3 reviews the library; this model covers its integration (TH42–TH43) |

---

## 2. Security objectives

| ID | Objective | Applies to |
|---|---|---|
| SO1 | **No out-of-policy signature.** No Vaultex-held key contributes to a signature over bytes that are not an allowlisted shape permitted by the active, quorum-signed policy. | Guard, node |
| SO2 | **Authorization is bound to the bytes.** The required approver signatures and the initiator signature are bound to the decoded intent, fresh and distinct, and they respect separation of duties (SoD). | Guard, node |
| SO3 | **Governance integrity.** Policy changes only through a pinned admin quorum. No rollback. A loosening is time-locked and visible; a tightening or a freeze is cheap. | Guard, node |
| SO4 | **Bounded loss.** If the checks above fail, outflow per window is still bounded by velocity caps, the breaker, the float size and freeze. | Guard, node, monitor |
| SO5 | **Accountability.** Every decision, accept or refuse, leaves a signed, hash-chained receipt. Every on-chain outflow matches a receipt, or an independent domain raises an alarm. | Guard, node, monitor |
| SO6 | **No single point of key compromise.** No single host, process or credential holds enough to sign alone. Once two humans exist, no single person does either. | All |
| SO7 | **Fail closed.** Unknown input, missing or corrupt state, clock rollback or an unavailable store produces a refusal, never a signature. Availability comes from the overflow path, not from relaxed checks. | Guard, node |
| SO8 | **What runs is what was reviewed.** Release binaries are reproducible from reviewed source, with pinned dependencies, and link no test parameters or experimental features. | All |

---

## 3. System and trust boundaries

### 3.1 Today: the legacy code at HEAD (summary only)

- **Topology.** A gateway and three nodes communicate over a message bus. The gateway holds no key share, but nodes rely on its assertion of the policy result and do not decode what they sign. Chain encoders for six chains are pinned to SDK reference output where a reference exists.
- **Verdict.** None of SO1–SO8 holds today. [`SECURITY_STATUS.md`](../../SECURITY_STATUS.md) lists the known limitations in ten categories. The gateway is inside the value trust boundary today (category 4).
- **Interim controls (M5).**
  - The freeze switch: release builds refuse key generation, digest-only signing, every legacy scheme and every mainnet network (M5 #5).
  - The shipped-build guard (M5 #8).
  - The cut: legacy engines removed from builds (ADR-03), other code quarantined (M5 #4).
- **How to model it:** assume complete compromise, and hold no value. Nothing below applies to the legacy code.

### 3.2 Phase 1: kernel, Guard and monitor (M6–M7)

The kernel is a pure library with no clock, network, randomness, async runtime or MPC code (M6 #1). It recomputes everything from the bytes, and its only authority is signatures that it checks against keys pinned at installation. The Guard wraps it as a required co-signer on a TRON native-multisig account (Rung 2).

```
 D-C  cold domain (offline devices)
   owner keys (cold 2-of-3) ...... permission updates, on chain ......> TRON float account
   policy admin keys (M-of-N) .... signed bundles and orders (TB6) ...> D-G

 TRON float account (holds at most the written loss budget)
   owner permission:  cold 2-of-3 (recovery, key rotation, hard freeze)
   active permission: threshold 2 = operator key + Guard key
                      operations: transfers and contract calls only; no permission updates

 D-G  Guard host (one per network)
   vaultex-guard
     kernel (TB2): decode -> policy -> approvals -> velocity -> receipt (fsync'd)
     signs with the Guard key only after the receipt is durable
     no chain RPC on the sign path (TB3)

 D-OP operator domain
   submitter: builds, signs with the operator key, broadcasts (TB9)
     ---- TB1 mTLS: unsigned bytes + approvals + initiator evidence ---->  D-G
     <--- co-signature + receipt ----------------------------------------  D-G
   on refusal or outage: overflow to the operator's existing payout path

 D-M  monitor domain
   vaultex-monitor  <--- TB4 receipts, pulled read-only ----------------  D-G
                    ---- TB4 freeze orders only ------------------------>  D-G
                    <--- TB5 chain data from 2 independent providers
   matches every outflow to a receipt; pages; auto-freezes

 D-R  build and release: signed reproducible binaries for D-G and D-M (TB8)
```

| ID | Boundary | What crosses | Trusted? | Control | Lands in |
|---|---|---|---|---|---|
| TB1 | Operator submitter → Guard API | Unsigned transaction bytes, approvals, initiator evidence | **No.** Transport identifies the caller's role only | mTLS with pinned client certificates, one role each; canonical binary bodies only, with size caps checked before parsing; the kernel recomputes the txid, intent, amount and destination | M6 #2; M7 #1 |
| TB2 | Guard service → kernel | The request, and the time supplied by the caller | The kernel trusts only keys pinned at installation and its own verified journal | The admin set comes from local config written at a ceremony, never from a request or a bundle; caller time is checked against the receipt high-water mark | M6 #3–#5 |
| TB3 | Guard → chain | Nothing on the sign path | — | No chain RPC in a decision. An optional chain-view witness stays off in v1 (LM3) | M7 #1 |
| TB4 | Guard ↔ monitor | Receipts out (the monitor pulls them); freeze orders in | The monitor accepts receipts only after verifying the signature chain. The Guard accepts freezes only from pinned freeze keys | The monitor can freeze and can never unfreeze. The Guard cannot write into the monitor | M6 #5–#6; M7 #3 |
| TB5 | Chain providers → monitor | Blocks, logs, balances, allowances, permissions | **No.** Any one provider may lie or fail | ≥ 2 providers run by different operators; an event seen by either raises an alarm; "all clear" needs both | M7 #3 |
| TB6 | Cold domain → Guard | Signed bundles, freeze and unpause orders; on chain, permission updates | The authority is the signatures, not the channel | Loosening needs M-of-N; tightening needs 1-of-N and must be provably tighter; unpause needs M-of-N with a nonce and an expiry and is applied locally; permission updates need the cold owner keys | M6 #3, #5; M7 #1 |
| TB7 | Any channel → approver workstation | Raw bytes to approve | **No.** Text supplied by a gateway or operator is never shown | The approver CLI decodes locally with the same decoder and a locally verified bundle, renders the intent and signs its digest | M6 #9 |
| TB8 | Build and release → hosts | Guard and monitor binaries and config | Only signed, reproducible releases | SHA-pinned CI, cosign signatures, SLSA provenance, SBOM, `cargo-deny` and `cargo-vet`; a rebuild on a second machine; no agent credential in any production domain | M7 #4, #6 |
| TB9 | The chain's permission check | Co-signed transactions | Trusted to enforce the threshold and the operations bitmap as documented. **Not** able to restrict destination, token or amount (LM11) | The Nile spike verifies co-signing under the active permission (AP4); the kernel enforces what the chain cannot | M6 #11 |

**Domains.** D-OP (operator), D-G (Guard), D-M (monitor), D-C (cold) and D-R (build and release). D-OP, D-G and D-M use different hosting providers, cloud accounts, credentials and credential-recovery channels, and no credential reaches two domains (M7 #3–#4). One human can still reach every domain in solo mode (LM7).

**K-alt fallback** (if the Nile spike is a no-go, K3). The Guard holds no chain key. It returns a signed decision receipt, which the operator's own signer must verify and honour before it signs. TB9 is then replaced by the operator's signer: the veto holds only if that signer fails closed, and a compromised operator signer bypasses the Guard. The monitor detects that afterwards (LM10).

### 3.3 Target MPC line (M8–M9; Gated)

```
 caller (builds transactions) --- TB10 mTLS ---> gateway relay
                                   holds no key share and no policy authority;
                                   rebuilt from signed node registries (TB14)
                                        | TB11 SignRequestV2: unsigned bytes
                                        |      + context + signatures
        +-------------------------------+-------------------------------+
        v                               v                               v
   node 1                          node 2                          node 3
   kernel -> engine                kernel -> engine                kernel -> engine
   state log, receipts             state log, receipts             state log, receipts
   key store v2, KEK (TB13)        key store v2, KEK               key store v2, KEK
        <---------- TB12 message bus (untrusted): transport v2 ---------->

 monitor (third failure domain): receipts and chain data in, freeze orders out
 engine library (TB15): one pinned engine, full interactive signing, reviewed delta (AL3)
```

The relay leaves the value trust boundary. It may deny or delay service, but it must not be able to obtain an out-of-policy signature (PC-06).

| ID | Boundary | Control | Lands in |
|---|---|---|---|
| TB10 | Caller → relay | In-process rustls mTLS; caller-built transactions only; per-wallet FIFO with an explicit 429 | M9 #4 (ADR-09) |
| TB11 | Relay → nodes | Nodes receive canonical bytes, never a bare digest, and refuse payload-less requests. Every node, on every request: registry lookup → freshness and persisted replay check → kernel decode → bundle → approvals and initiator → fsync'd velocity reservation (observers reserve too) → receipt → sign | M9 #1–#2; PC-05 |
| TB12 | Node ↔ node over the bus | Transport v2: sender authenticated and bound to its party index; execution id inside the signed envelope; per-recipient authenticated encryption under identities pinned in each node's config; size caps before parsing; bus TLS, per-node credentials and subject ACLs | M8 #4–#5; PC-03 |
| TB13 | Node → key store and KEK | Key store v2 (AAD-bound, atomic fsync'd writes, refuses overwrite); a KMS- or PKCS#11-wrapped KEK per node; distinct per-node secrets, accounts and failure domains | M8 #6; M11 #1; PC-09 |
| TB14 | Nodes → relay state | The relay is rebuilt from signed node registries by t-of-n agreement. Keygen intents are admin-signed. Node-signed {wallet, public key, address} attestations are confirmed out of band by ≥ 2 humans | M9 #3–#4; PC-07; PC-11 (ADR-10) |
| TB15 | Vaultex → engine library | Pinned library versions; full interactive signing only; no presignatures; HD only if a use case needs it; production-size parameters only | M8 #1–#3, #7; PC-12 |

---

## 4. Assets

| ID | Asset | Where | Impact if compromised |
|---|---|---|---|
| AS1 | Funds in the float (Phase 1) or in MPC-held wallets (Phase 2) | On chain | Direct loss, bounded by caps, float size and RF-1–RF-4 |
| AS2 | Guard co-signer key, one per network | D-G, in an encrypted file or a non-exportable KMS/HSM key (ADR-17) | Half of the active permission. Together with the operator key: spend up to the float |
| AS3 | Operator key | D-OP (outside Vaultex) | The other half. Alone it cannot spend from the float at Rung 2 |
| AS4 | Owner (cold) permission keys | D-C, offline | Account takeover: permission rewrite or direct transfers. The monitor alerts; no Vaultex component can stop it |
| AS5 | The pinned admin set and the policy admin keys (M-of-N) | Admin set: each signer's config. Keys: D-C | Policy loosening after the time-lock and alert. A substituted admin set means arbitrary policy |
| AS6 | Approver and initiator keys | Approver devices; the operator domain | Approvals within tier caps. Cannot exceed caps or bypass SoD alone |
| AS7 | Freeze keys | D-M | Unwanted freezes (availability only) |
| AS8 | Receipt-signing key, one per kernel instance | D-G; each node | Forged receipts while access lasts. Anchoring exposes a rewrite |
| AS9 | Kernel state: the receipt journal (velocity usage, pause state, bundle lineage) | D-G; each node | Reset or replayed velocity, if writes are not durable and the chain is not verified on open |
| AS10 | MPC key shares and auxiliary material (Phase 2) | Each node, in key store v2 | Fewer than t shares: no signature. t or more: the full key |
| AS11 | Node identity keys and bus credentials (Phase 2) | Each node | Impersonation of a party on the bus |
| AS12 | KEKs and backups (M11) | Per-node KMS or PKCS#11; customer-held backups | Share recovery from backups |
| AS13 | Release-signing identity, CI and the source repository | D-R | Malicious code in every domain at once |
| AS14 | Monitor configuration (loss-budget caps, expected permissions) and evidence packs | D-M | Suppressed alarms; false evidence |

---

## 5. Actors

| ID | Actor | Capability assumed | Must not achieve | Residual |
|---|---|---|---|---|
| AC1 | Network attacker | Observes, drops, injects and replays traffic between any two domains and on the bus | Any signature, or any change of policy or state (SO1–SO3); any share material (SO6) | Denial of service |
| AC2 | Malicious caller or operator submitter (holds the operator key at Rung 2; any API client in Phase 2) | Sends arbitrary bytes; replays, retries and floods; picks signer subsets | An accept outside policy; a second, uncharged signature; a signature from another subset after a refusal | Within-policy outflow up to the caps (LM1) |
| AC3 | **Compromised gateway or relay** (Phase 2; also the legacy gateway today, §3.1) | Full control of the relay process, its keys and bus routing; forges, reorders, withholds and replays requests; chooses the signer subset | Any out-of-policy signature (PC-06); a key generation that the nodes and two humans did not confirm; supplying peer keys or the bus endpoint to nodes | Denial of service; delay |
| AC4 | Compromised Guard host (Phase 1) | Root on the Guard host while the compromise lasts: uses the Guard key through its custody backend, holds the operator signatures it received, rewrites local state and receipts | Moving funds without the operator key; hiding an outflow from the monitor; double pay through a refusal that is later broadcast | False refusals; a forged local log, which anchoring exposes; with a file-held key, persistence until rotation (ADR-17) |
| AC5 | Compromised MPC nodes, c < t (Phase 2), alone or together with AC3 | Root on c nodes: their shares, kernels, state and receipt keys; arbitrary protocol messages | A signature without t parties; framing an honest node; total outflow above the bound (LM1) | The outflow bound grows with c (LM1) |
| AC6 | Malicious protocol participant | Malformed or adversarial protocol messages inside the MPC protocol | Learning other parties' shares; biasing keys; an invalid signature that is accepted (every returned signature is verified against the group key, PC-04) | Aborts that the engine does not attribute to a party (no identifiable abort upstream; RK5): availability only. Otherwise, the library's guarantees (AP7) |
| AC7 | **Insider: one policy admin** | One admin key | A loosening without M-of-N and the time-lock; a bundle that signers did not receipt | Can tighten and freeze by design, which can delay service |
| AC8 | **Insider: an approver** | Their own approver key | Approving outside their tier, approving their own initiation, or approving bytes other than those decoded | Approves within tier caps |
| AC9 | **Insider: host operator with root on one domain** (Guard, monitor or one node) | Reads disk and memory, replaces binaries, changes the clock | More than AC4 or AC5 allows for that host; any effect in a second domain | As AC4 or AC5 for that host |
| AC10 | **Insider: the solo owner**, or anyone who controls the owner's accounts and devices | Every domain's credentials and the cold keys | — (cannot be prevented while one human holds everything) | LM7: out of scope until ≥ 2 humans (PL-03); bounded by the float size and monitoring |
| AC11 | Data-source attacker | Controls or poisons one chain RPC provider; denies service to another | Hiding an outflow from the monitor; influencing a decision (there is no RPC on the sign path) | Degraded monitoring raises alarms; it is never silent |
| AC12 | Token issuer or chain-level event | Blacklist, pause or upgrade of a token; chain parameter changes | — (environment) | Detected and alerted; availability loss |
| AC13 | Supply-chain or process attacker | A dependency, a CI action, the release pipeline, a maintainer or agent account | Shipping code that no reviewer saw; reaching production credentials | Reviewed but wrong code (LM2) |
| AC14 | Clock attacker | Moves a signer host's clock | Reusing stale approvals or orders; resetting velocity windows | A forward move shortens a pending time-lock (LM5) |

---

## 6. Threats and controls

Each row is one threat category. **Lands in** is the milestone whose exit criterion carries the control. **Evidence** is the artifact that proves it (ROADMAP §9.4). Rows in §6.7–§6.8, and the Phase-2 parts of other rows, are Gated.

### 6.1 Transaction content (the decoder)

| ID | Threat | Actors | Control | Lands in | Evidence |
|---|---|---|---|---|---|
| TH1 | Blind signing: a signer signs a digest whose transaction it never decoded | AC2, AC3 | No digest-only entry point on any value path. Signers receive canonical unsigned bytes and recompute the digest. Interim: release builds refuse digest-only signing | M5 #5; M6 #2; M9 #1; PC-05 | Refusal tests; payload-less request test |
| TH2 | Parser differential: the signer and the chain read different transactions from the same bytes | AC2 | Strict decoding profile (known fields only, each once, in order, minimal encodings); byte-equal canonical re-encoding by an independently written encoder; recomputed txid; fuzzing, a tronweb differential and an independent JS oracle. A second decoder is decided in ADR-15 | M6 #2, #7, #8 | Fuzz and differential reports; oracle job |
| TH3 | Shape smuggling: a memo, a second contract, another contract type, a call value, an `approve`/`transferFrom` or any other selector, a permission update | AC2 | An allowlist of exactly two shapes, with a distinct refusal code for everything else. Permission updates are also outside the active permission's operations on chain | M6 #2, #8, #11 | Incident-replay suite, 100% refused; Nile spike |
| TH4 | Wrong signing context: another permission id, another owner address, an unconfigured wallet | AC2 | The permission id must equal the configured one; the owner must be the wallet named in the active bundle; unknown wallets are refused | M6 #2–#3 | Negative tests |
| TH5 | Stale or long-lived pre-signed payloads; pre- or post-dated builds | AC2 | A decoder ceiling on expiry; a validity window per approval tier from the bundle; a timestamp skew check | M6 #2–#3 | Incident-replay cases |
| TH6 | Fee-limit abuse that drains the fee balance | AC2 | The network maximum is enforced in the decoder; a per-rule cap and a rolling fee budget in policy | M6 #2, #3, #5 | Incident-replay cases |
| TH7 | Cross-network replay: TRON bytes carry no network id | AC2 | One key per network; network facts come only from the bundle; separate testnet and mainnet Guard keys; release builds refuse mainnet until M10-F | M5 #5; M6 #3; M7 #1 | Key inventory; tests. Residual: LM3 |
| TH8 | Address poisoning and degenerate recipients (zero amount; zero, self or token-contract recipient) | AC2 | Refused by the decoder or by policy; allowlist mode | M6 #2–#3 | Incident-replay cases |

### 6.2 Authorization: approvals and initiator

| ID | Threat | Actors | Control | Lands in | Evidence |
|---|---|---|---|---|---|
| TH9 | Destination or amount swapped after approval (UI substitution, request manipulation) | AC2, AC3 | Approvers sign a domain-separated digest of the decoded intent, which includes the txid. The approver tool decodes locally and never shows supplied text | M6 #4, #9 | Vectors; incident-replay cases |
| TH10 | Forged, duplicate or replayed approvals; approvals by keys without the approver role | AC2, AC3, AC8 | Approver keys only from the bundle; strict signature verification; one counted approval per key and per principal, and a duplicate is refused rather than deduplicated; expiry and TTL bounds | M6 #4 | Vectors; incident-replay cases |
| TH11 | Self-approval by the initiator; collusion below the quorum | AC8 | The initiator's principal must differ from every approving principal; k-of-n by amount tier | M6 #4 | Incident-replay case |
| TH12 | "The back office said yes": a missing initiator, or approvals asserted by a gateway | AC3 | Every signer verifies the initiator signature itself; a zero-approval tier must be explicit and quorum-signed | M6 #3–#4; M9 #2 | Incident-replay case |
| TH13 | A compromised approver key | AC8, AC1 | Immediate freeze (1-of-N); removal through a later, time-locked bundle; hardware-held approver keys recommended | M6 #3, #5; M7 #4 | Runbook; drill log |

### 6.3 Governance: policy bundle, admin set and orders

| ID | Threat | Actors | Control | Lands in | Evidence |
|---|---|---|---|---|---|
| TH14 | Self-supplied verification key: a bundle or request names the key that verifies it | AC2, AC3 | The admin set and its threshold are pinned in each signer's config at a recorded ceremony, with the hash confirmed out of band. They are never taken from a bundle or a request | M6 #3; M7 #4; PC-11 | Ceremony transcript |
| TH15 | Rolled-back or forked policy history | AC3, AC7 | Strictly sequential versions linked by digest; anti-rollback against the highest version seen, rebuilt from receipts | M6 #3 | Incident-replay cases |
| TH16 | A loosening without quorum, or one disguised as an emergency tightening | AC7 | A loosening needs M-of-N and activates only after a time-lock counted from the signer's own receipt, using the active bundle's delay. A tightening needs 1-of-N and only if it is provably tighter. Every bundle offer alerts the monitor. Any admin can cancel a pending loosening by tightening | M6 #3; M7 #3 | Classifier property test; alert drill |
| TH17 | Verification depends on serialization (non-canonical policy encoding) | AC2 | Canonical binary encoding; re-encode equality; sorted, unique lists | M6 #3, #7 | Vectors reproduced by the JS oracle |
| TH18 | Replayed or forged freeze and unpause orders | AC1, AC3 | Freeze is 1-of-N (the safe direction). Unpause needs M-of-N with a nonce, the pause sequence number and a short expiry, applied locally on each signer. The monitor holds no unpause authority | M6 #5; M7 #1, #3; M8 #6 | Incident-replay case; drill log |
| TH19 | Policy versions diverge across nodes (Phase 2) | AC3 | Each node evaluates only its own installed bundle and records its version in every receipt; how nodes refuse a mismatched version is an open M9 design question (WS-10) | M9 #2–#3 | Tests |

### 6.4 Velocity and loss bounds

| ID | Threat | Actors | Control | Lands in | Evidence |
|---|---|---|---|---|---|
| TH20 | Splitting a large transfer under the per-transaction cap | AC2 | Rolling windows on amount, count and fees per wallet and asset | M6 #5 | Incident-replay case |
| TH21 | Counters reset by a crash or restart | AC9 | The velocity charge is the fsync'd receipt record, written before any signature is released; the chain is verified on open; a corrupt log refuses to start | M6 #5–#6 | `kill -9` tests |
| TH22 | Subset rotation: requests steered to different signer subsets so that each sees less (Phase 2) | AC3, AC5 | A per-node cap derived from the group budget; observer nodes charge requests they do not sign; a total bound that degrades with c non-enforcing nodes (LM1) | M6 #5; M9 #2, #5; PC-06 | Harness report |
| TH23 | Misuse within policy: correctly approved but unwanted transfers | AC2, AC8 | Caps; allowlist; breaker auto-pause on refusal bursts or cap hits; the monitor's own caps, taken from the written loss budget | M6 #5; M7 #3 | Drill log. Residual: LM1 |
| TH24 | Breaker evasion through clock rollback | AC14 | A persisted time high-water mark; a rollback is refused and pauses the signer | M6 #5 | Clock tests |

### 6.5 State, receipts and freeze

| ID | Threat | Actors | Control | Lands in | Evidence |
|---|---|---|---|---|---|
| TH25 | A signature without a durable record | AC9 | The receipt is appended and fsync'd before the signature is released; a store failure refuses | M6 #6; M7 #1 | Crash tests |
| TH26 | A compromised signer host rewrites its receipt log | AC4, AC5 | A hash chain plus a signature on each receipt; receipts stream to the monitor, which anchors heads in another domain; an offline verifier; deterministic replay from evidence packs | M6 #6; M7 #3, #8 | Verifier output; evidence pack. Residual: LM6 |
| TH27 | An outflow with no receipt: a key used outside the software, or operator or owner keys misused | AC4, AC10, AC1 | The monitor matches every outflow to an accepted receipt. An unmatched outflow is Sev-1: auto-freeze and page | M7 #3 | Drill log |
| TH28 | Co-signatures already issued outlive a freeze | AC2, AC4 | Short validity on zero-approval tiers; an outstanding-exposure report; a hard freeze through the owner permission | M7 #1, #4 | Freeze drill log. Residual: LM4 |
| TH29 | Double pay through the overflow path: the Guard answers "refused" and broadcasts later | AC4 | The submitter overflows only once the transaction is provably dead (expired and absent on ≥ 2 providers), unless no co-signature can exist | M7 #1–#2 | Integration tests |
| TH30 | Replayed or repeated requests | AC2, AC3 | A persisted replay registry; the same intent re-signs the same txid without a second charge; in Phase 2, execution ids and a persisted replay cache | M7 #1; M8 #6; PC-04 | Tests |

### 6.6 Keys and custody

| ID | Threat | Actors | Control | Lands in | Evidence |
|---|---|---|---|---|---|
| TH31 | Guard key exfiltrated, or still usable after a compromise is cleaned up | AC4, AC9, AC13 | A non-exportable custody option with an independent signing log, or an encrypted file (ADR-17); a separate key per network; rotation through the owner permission, drilled; the float cap | M7 #1, #4 | Drill log |
| TH32 | Receipt key compromise | AC4 | Separate from every chain key; rotation is itself receipted; anchoring makes forgery detectable | M6 #6 | Verifier output |
| TH33 | t or more shares reachable through shared secrets, co-location or one person (Phase 2) | AC9, AC10 | Per-node secrets, KEKs, accounts and failure domains; no single person holds t node credentials; the boot-node wrapper never mounts a multi-party keystore; the single-process CLI is quarantined | M5 #4; M11 #1; PL-03 | Per-node inventory (kept private) |
| TH34 | Share or backup leakage at rest, or loss on overwrite (Phase 2) | AC9 | Key store v2 (AAD-bound, atomic, refuses overwrite); customer-held encrypted backups; an offline restore tool; restore and node-replacement drills | M8 #6; M11 #2; PC-10 | Crash test; drill logs |
| TH35 | A subverted key-generation ceremony: wrong group key or substituted address | AC3, AC5 | Admin-signed keygen intents; node-signed attestations confirmed out of band by ≥ 2 humans; keygen never overwrites an existing group | M9 #4; PC-04; PC-11 | Ceremony transcript |
| TH36 | Admin or owner key loss or theft | AC1, AC10 | Cold, offline keys under M-of-N; transaction hashes checked on an air-gapped device; every permission change rehearsed on testnet first | M7 #4 | Ceremony transcript |

### 6.7 Transport and control plane (Phase 2; Gated)

| ID | Threat | Actors | Control | Lands in | Evidence |
|---|---|---|---|---|---|
| TH37 | Key-generation confidentiality on the bus ([`SECURITY_STATUS.md`](../../SECURITY_STATUS.md) category 2) | AC1, AC3 | Per-recipient authenticated encryption under pinned identities; bus TLS. Interim: release builds refuse key generation | M5 #5; M8 #4–#5; PC-03 | Adversarial suite, including "an unprivileged bus client reads no peer-to-peer plaintext" |
| TH38 | Sender spoofing; cross-session or cross-execution replay | AC1, AC3, AC5 | Sender bound to its party index inside the signed envelope; execution-id binding; round filtering | M8 #4–#5; PC-03 | Adversarial suite |
| TH39 | Oversized or malformed messages exhaust or crash a node | AC1, AC5 | Per-round size caps checked before parsing; deadlines; retry with a fresh execution id | M8 #4; PC-03 | Adversarial suite |
| TH40 | Control-plane freshness and trust concentrated in one gateway key ([`SECURITY_STATUS.md`](../../SECURITY_STATUS.md) category 3) | AC1, AC3 | Control plane v2: nonce, expiry and subject binding; a persisted replay cache; node-signed replies checked for party uniqueness and address continuity; gateway keys split by purpose | M8 #6; PC-04 | Tests |
| TH41 | The gateway supplies peer keys or the bus endpoint | AC3 | Identities and endpoints are pinned in node config only | M8 #4 | Design note; tests |

### 6.8 Engine library (Phase 2; Gated)

| ID | Threat | Actors | Control | Lands in | Evidence |
|---|---|---|---|---|---|
| TH42 | A flaw in the adopted engine, or in its unreviewed changes since its last audit | AC6 | Pinned versions; the mandatory library-delta review (AL3); the upstream security channel; an unpatched Critical triggers a signing freeze (K11) | M8 #1; M10-F | AL3 report |
| TH43 | Engine misuse by the integration (presignatures, HD derivation, message typing, parameter sizes) | AC6 | Full interactive signing only; a typed `SignInput` instead of an untyped 32-byte input; production-size parameters only, with sizes asserted in CI; misuse classes in the AL1 scope | M8 #1, #7; M10-F | CI check; AL1 report |
| TH44 | Test parameters or experimental features linked into shipped builds ([`SECURITY_STATUS.md`](../../SECURITY_STATUS.md) category 6) | AC13 | The shipped-build guard; a compile-time or start-up refusal | M5 #8; PC-01 | CI run |

### 6.9 Monitoring and environment

| ID | Threat | Actors | Control | Lands in | Evidence |
|---|---|---|---|---|---|
| TH45 | The monitor is blinded: provider poisoning or outage | AC11 | Two providers run by different operators; alarm on any, clear on all; a failover cannot suppress an alarm. Optional: the Guard co-signs only while the monitor's heartbeat is fresh (fail closed; decision pending, §11) | M7 #3 | Drill log |
| TH46 | A standing token allowance drains the float without another float signature | AC2 | The decoder refuses `approve`-class selectors; the monitor alerts on `Approval` events and non-zero allowances; every refill first checks that the allowance is 0 | M6 #2; M7 #3; RF-4 | Drill log |
| TH47 | Attacker-triggered false freezes | AC1, AC2 | A freeze rule needs a float signature, a real allowance, an issuer action or a Guard-domain event. Dust and events from unknown contracts never freeze | M7 #3 | Rung 1 calibration report |
| TH48 | The monitor itself is compromised and suppresses alarms | AC9 | A separate domain and a different implementer from the Guard; monitor caps come from the written loss budget, not from the bundle; the owner reviews the monthly evidence pack | M7 #3, #8 | Evidence pack |
| TH49 | Token issuer actions: blacklist, pause, upgrade | AC12 | Monitor alerts; caps bound the exposure | M7 #3 | Alert test |

### 6.10 Supply chain and process

| ID | Threat | Actors | Control | Lands in | Evidence |
|---|---|---|---|---|---|
| TH50 | CI passes with failing tests ([`SECURITY_STATUS.md`](../../SECURITY_STATUS.md) category 10) | AC13 | bash with pipefail; gating on exit codes; a deliberately failing canary PR turns CI red | M5 #6 | Canary run |
| TH51 | A compromised dependency or CI action | AC13 | SHA-pinned actions; 0 open RUSTSEC advisories; `cargo-deny` and `cargo-vet` on crypto crates; a daily audit job; new crates only through review | M5 #6–#7; M7 #6; PC-13 | Audit run |
| TH52 | A tampered or unreproducible release; mutable tags; auto-release | AC13 | Auto-release disabled; cosign-signed reproducible builds, rebuilt on a second machine; SLSA provenance; SBOM; digest-pinned images | M5 #6; M7 #6; M11 #5 | Release page |
| TH53 | An agent or maintainer account is abused | AC10, AC13 | Agents commit from a machine account with no merge or admin rights; branch protection that includes administrators; hardware-key 2FA; release keys off the development laptop; no secret reachable by agents; no agent credential in any production domain | M5 #6, #12; M7 #4 | Branch-protection API output |
| TH54 | Unreviewed code on trust paths (one maintainer) | AC13 | CODEOWNERS human review; paid limited evaluations at the M6 and M7 gates; the focused review (M10-K); the full audit (M10-F) | M5 #6; M6; M7; M10 | Letters and reports |

### 6.11 Availability (a secondary objective)

| ID | Threat | Actors | Control | Lands in | Evidence |
|---|---|---|---|---|---|
| TH55 | False refusals of legitimate payouts | — | Rung 0 retro-shadow and ≥ 14 days of live shadow before enforcement; false refusals ≤ 1%, each explained; overflow to the operator's existing path | M6 #10; M7 #5 | Shadow report |
| TH56 | Guard or node unavailable; request or receipt flooding | AC1, AC2 | The overflow path; queue depth, 429 and per-identity rate limits; in Phase 2, any t of n with failover and no silent drops under bursts | M7 #2; M9 #6; PC-08 | Load report |

---

## 7. Compromise scenarios

What each compromise yields once the controls above are in place. "Today" refers to the legacy code (§3.1).

| ID | Scenario | Phase 1 (Guard, Rung 2) | Phase 2 (verifying MPC nodes) | Evidence |
|---|---|---|---|---|
| SC1 | **Compromised gateway or relay** | There is no gateway on the Guard path. The nearest equivalent, a compromised operator submitter, is AC2 and is covered by §6.1–§6.2 | **0 out-of-policy signatures.** It can deny or delay service and choose subsets. Honest nodes evaluate the same bytes against the same bundle, so steering a refused request to another subset does not change the policy outcome; differences in per-node velocity state are covered by the outflow bound (LM1). Today it can obtain signatures (category 4), which is why the freeze switch blocks every value path | PC-06 harness report (M9 #5) |
| SC2 | Compromised gateway **plus one node** | — | As SC1, with outflow under subset rotation bounded with c = 1 (LM1) | PC-06 harness report |
| SC3 | Compromised Guard host | No funds move without the operator key. Possible effects: false refusals, a forged local log that the monitor's anchor exposes, and double pay, which the dead-transaction rule closes (TH29). Persistence after cleanup depends on custody (ADR-17) | — | Guard harness (M7 #7); drill logs |
| SC4 | Guard host **plus** operator key | Loss ≤ float. The monitor sees outflows without a receipt, or above the caps, auto-freezes and pages; the owner hard-freezes on chain | Not applicable: the equivalent is t nodes, which AP1 excludes | Freeze drill (M7 #3) |
| SC5 | One policy admin (insider) | Can tighten or freeze (availability only). A loosening needs M-of-N, waits the time-lock and pages the monitor. The monitor's caps do not loosen with the bundle | Same | Classifier property test; alert drill |
| SC6 | One approver, or k colluding approvers (insider) | Can approve transfers inside their tier, the allowlist and the velocity caps. Cannot approve their own initiation | Same | Incident-replay cases |
| SC7 | Host insider on one node | — | One share (< t). Counts as c = 1 in the outflow bound | PC-06 harness report |
| SC8 | Common-mode kernel bug | Every signer accepts the same bad payload. Bounded by caps, the breaker, the float size and a monitor that judges executed effects on chain, not decoded intent (RK4) | Same | M6 #8 evidence; ADR-15 |
| SC9 | Solo owner compromised or coerced | Out of scope until two humans exist (LM7). Bounded by the float size and the project-owned-float default (RF-1) | Same; M12 needs ≥ 2 humans | PL-03 |
| SC10 | Compromised release (supply chain) | Reaches every domain at once. Signed reproducible builds with a second-machine rebuild; the monitor comes from a different implementer and judges chain effects | Same | Release page (M7 #6, M11 #5) |

---

## 8. Controls by milestone

| Milestone | What lands (threat IDs) | Gate and evidence |
|---|---|---|
| **M5** | Freeze switch: interim cover for TH1, TH7, TH37 and TH40. Shipped-build guard (TH44). The cut (§1 scope). Boot-node mount (TH33). CI integrity, dependencies, auto-release off, branch protection and agent rules (TH50–TH53) | Owner closing issue; CI runs |
| **M6** | Kernel: TH1–TH18, TH20–TH21, TH23–TH26, TH32. Evidence: incident replay, mutation check, fuzzing, tronweb differential, JS oracle. Nile spike (TB9, AP4) | Owner + independent paid limited evaluation; this model's Phase-1 part is part of its package |
| **M7** | Guard, monitor and operations: TH7, TH13, TH25–TH31, TH36, TH45–TH49, TH55–TH56. Signed reproducible Guard release (TH52). RF-1 + RF-4 in writing | Owner + independent reviewer + counsel |
| **M8** (Gated) | Engine, transport v2, control plane v2, key store v2: TH18, TH30, TH34, TH37–TH44 | Cryptographer or paid limited evaluation (mandatory) |
| **M9** (Gated) | Verifying node, relay, attestations: TH1, TH12, TH19, TH22, TH35, TH56; compromised-gateway harness (SC1–SC2) | Owner + cryptographer. M9 #8 requires this model and sign-authorization spec v2 to match the code |
| **M10-K** | Focused review of the kernel, the Guard and its key handling as built (the Phase-1 rows of §6.1–§6.6), plus a Guard pentest | Fix-review letter |
| **M10-F** | AL1 (integration and trust boundaries, including a check that nothing on the value path trusts the relay), AL2 (fix review), AL3 (TH42), AL4 (TH2–TH8), PT1 (pentest) | **Auditor's fix-review letter (decisive)** |
| **M11** | Per-node KEKs, backups, ceremonies, monitoring, signed releases, game days: TH33–TH35, TH52 | A second human runs the drills |
| **M12** | Caps and ≥ 2 human operators, which narrows LM7; a monitor in a third failure domain | Owner + second human + counsel |

---

## 9. Assumptions and accepted limits

**Assumptions.** If one fails, the objectives that depend on it may fail.

| ID | Assumption | Objectives at risk | How it is checked |
|---|---|---|---|
| AP1 | At Rung 2, the operator key and the Guard key are not both compromised. In Phase 2, fewer than t nodes are compromised at once | SO1, SO6 | Separate domains (M7 #3–#4; M11 #1); monitor |
| AP2 | Pinned keys (admin set, freeze keys, receipt keys, peer identities) are installed at a recorded ceremony, and their hashes are confirmed out of band | SO1–SO3 | Ceremony transcript (M7 #4; PC-11) |
| AP3 | The operating system provides cryptographic randomness. The kernel uses none; the CLIs, key ceremonies and the engine do | SO6 | Platform choice; review |
| AP4 | TRON enforces native multisig thresholds and the operations bitmap as documented. **HYPOTHESIS** until the Nile spike | SO1, SO6 | M6 #11; else K-alt (LM10) |
| AP5 | Host clocks follow multiple or authenticated time sources. The kernel detects rollback and skew only | SO3, SO4 | Host baseline (M7 #4) |
| AP6 | The domains' hosting providers, accounts and credential-recovery channels are really distinct | SO6 | Domain audit in the evidence pack (M7 #8) |
| AP7 | The adopted engine provides its documented guarantees under its documented usage | SO6 | AL3 (M10-F); nothing beyond what AL3 covers is assumed |
| AP8 | The primitives are sound: SHA-256, Ed25519 with strict verification, secp256k1 ECDSA, the chosen AEAD | All | Standard primitives from reviewed libraries |

**Accepted limits.** Each one stays, and each goes into the [known-issues list](KNOWN_ISSUES.md) §2 (KI-11 to KI-21).

| ID | Limit |
|---|---|
| LM1 | **Within-policy outflow is bounded, not zero.** Per window it is at most the group budget when every signer enforces, and the bound grows with the number c of non-enforcing signers (ROADMAP §3.3). The velocity spec fixes the exact formula |
| LM2 | **Common mode.** A kernel bug is shared by every signer. Caps, the breaker and the monitor bound the loss (RK4); decoder diversity is ADR-15 |
| LM3 | **One key per network.** TRON, Solana, Sui and Bitcoin bytes carry no network id, so network facts come from the bundle, and cross-network replay cannot be refused offline |
| LM4 | A soft freeze does not revoke co-signatures already issued. They remain usable until they expire, unless the owner hard-freezes on chain |
| LM5 | A host clock moved forward shortens a pending time-lock. The responses are the alert on every bundle offer and "a tightening cancels a pending loosening" |
| LM6 | Receipts make a rewritten log detectable through anchoring; they do not prevent the rewrite while a host is compromised |
| LM7 | **Solo mode.** One human can reach every domain. Domain separation defends against the compromise of one credential, vendor or host, not of the owner. ST4 requires ≥ 2 humans (PL-03) |
| LM8 | No threshold key refresh upstream: rotation means a new key generation plus a sweep |
| LM9 | **Caller-builds boundary.** Fees, energy, broadcast, confirmation, deposits and sweeps are the caller's responsibility (ROADMAP §2.1) |
| LM10 | **K-alt** (if adopted) and the partner callback gate: the veto holds only if the operator's signer fails closed. A compromised operator signer is detected afterwards, not prevented |
| LM11 | The chain cannot restrict destination, token or amount for the active permission; only the Guard does. That is the Guard's purpose, and also why "Guard defect plus operator key" is the worst Phase-1 case |

---

## 10. Validation and maintenance

- **When it is checked.**
  - The Phase-1 part (§3.2; §6.1–§6.6 and §6.9–§6.11) is frozen with the kernel at the M6 freeze, and goes into the M6 limited-evaluation package.
  - The MPC part (§3.3; §6.7–§6.8) is re-validated before the M9 freeze. M9 #8 requires this model and sign-authorization spec v2 to match the code.
  - The M10-F integration audit line (AL1) is asked to validate this model, in particular that nothing on the value path trusts the relay.
- **How it is tested.** Each TH row reaches its milestone only with the evidence it names. The WS-13 harnesses (incident replay, the Guard harness, the compromised-gateway harness) exercise the actor capabilities in §5.
- **When it changes.** At every freeze; when a chain, transaction shape or key type is added; when a trust path or domain is added; when a finding is confirmed (its category goes into [`SECURITY_STATUS.md`](../../SECURITY_STATUS.md) first); and when a decision in §11 is made.
- **Who.** R6 drafts (advisory). The contract cryptographer reviews once engaged. The owner approves.

---

## 11. Open decisions this model depends on

| Decision | Effect on this model |
|---|---|
| ADR-03, ADR-04 | Scope (§1) |
| ADR-05, ADR-06 | Which assets hold real funds, and when (AS1) |
| ADR-07 (G-MPC) | Whether §3.3, §6.7 and §6.8 are ever built |
| ADR-09, ADR-10 | TB10 and TB14 |
| ADR-11 | TB6; TH14–TH17 |
| ADR-15 | TH2; LM2 |
| ADR-17 | TH31; AC4's residual |
| Nile spike (M6 #11; K3) | TB9 and AP4 hold, or K-alt applies (LM10) |
| Whether the Guard co-signs only while the monitor's heartbeat is fresh | TH45: fail closed when the monitor is lost, at some cost in availability |
| Policy-version consistency across nodes (WS-10) | TH19 |
