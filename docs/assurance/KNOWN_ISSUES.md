# Known issues

| | |
|---|---|
| **Version** | 1.0-draft, 2026-10-11 |
| **Status** | **PROPOSED.** Drafted by R6 (advisory) with R7. The owner approves. No independent reviewer has read it, because none is engaged yet (ADR-01). |
| **Purpose** | One public list of what is already known to be wrong, missing or limited, by category. Users can see what still holds after each fix. Reviewers and auditors do not have to spend paid time finding it again. |
| **Covers** | Defects in the code at HEAD, by reference to [`SECURITY_STATUS.md`](../../SECURITY_STATUS.md) (§1). The accepted limits of the Phase-1 design and the target MPC design, from [threat model v2](THREAT_MODEL_V2.md) §9 (§2). Upstream, chain and token issues (§3). Gaps in assurance evidence (§4). |
| **Public safety** | Category + fix only. No exploit mechanics, and no pointers into the code for unfixed defects. |
| **Owner** | WS-14 (R7 + owner). Updated at every freeze, and whenever `SECURITY_STATUS.md` or the threat model changes (§5). |

---

## 0. How to use this list

**If you use Vaultex.** Nothing here is fixed unless its row says **Fixed** and gives a version. The limits in §2 stay **after every milestone**: plan around them, using the operator column.

**If you review or audit Vaultex.** This list goes into every review package: the paid limited evaluations at M6 and M7, the M10-K and M10-F RFQs, and the audit-scope manifest (T14-3).
- A report that only restates an entry is not a new finding.
- A report **is** a finding if:
  - the implementation behaves worse than the bound or behaviour an entry states;
  - an entry's planned fix does not hold once it lands;
  - a limit is missing from the user documentation where its row says it must appear.
- An entry is **not** a risk acceptance for the M10 fix-review letter. Every Critical and High finding is still fixed and re-verified ([ROADMAP](../ROADMAP.md) M10). The §2 limits are accepted by design, and the owner's written risk acceptance (RF-1) cites them by ID.

**Statuses.**
- **Open**: a defect with a planned fix, and no part of the fix merged.
- **In progress**: part of the fix is merged.
- **Fixed**: the whole fix is merged, with a named test or CI run, and the release that contains it is named.
- **Limit**: accepted by design. It stays after every milestone.
- **Upstream**: a property of a library, chain or token that Vaultex cannot change. Vaultex tracks it and bounds its effect.
- **Gap**: evidence or process that does not exist yet. The code may not be at fault, but no claim may rely on what the evidence would show.
- **Retired**: no longer applies. The row stays, with the reason and the evidence.

**IDs.** `KI-nn` is local to this list. IDs are never reused. The prefix differs from every ROADMAP prefix and every threat-model prefix (RK, K, PC, PL, RF, ST, B, AL; SO, AS, TB, AC, TH, SC, AP, LM).

---

## 1. Defects in the code at HEAD

The authoritative list is [`SECURITY_STATUS.md`](../../SECURITY_STATUS.md), which WS-01 maintains. It holds the status and the planned fix for each category. This table maps those categories to IDs so that review packages can cite them, and it says how a review treats each one. It deliberately does not repeat their status. If this table and `SECURITY_STATUS.md` ever disagree, `SECURITY_STATUS.md` wins and this table is corrected.

| ID | `SECURITY_STATUS` # | Category | In review scope? |
|---|---|---|---|
| KI-01 | 1 | Affected scheme classes: the hand-rolled threshold-ECDSA engines are unsound, and Sr25519/BLS signing is not threshold signing | **No.** Removed from builds in M5 (ADR-03). Their keys are treated as exposed. Any future engine is an adopted library (KI-28) |
| KI-02 | 2 | Transport confidentiality and peer authentication during key generation | Only as transport v2 (M8, Gated). Until then, release builds refuse key generation |
| KI-03 | 3 | Control-plane freshness; trust concentrated in one gateway key and one deployment secret | Only as control plane v2 (M8, Gated) and per-node secrets (M11) |
| KI-04 | 4 | Unenforced signing policy: signers do not verify what they sign | Yes, as the kernel (M6) and the verifying node (M9). Until then, release builds refuse digest-only signing |
| KI-05 | 5 | Unsafe deposit addresses from pre-cut versions | Only as chain gating (M5). The advisory reaches existing clones (ADR-13) |
| KI-06 | 6 | Test-only cryptographic parameters can reach builds | Yes, as the shipped-build guard (M5 #8) and production-size fixtures (M8 #7) |
| KI-07 | 7 | Key shares co-located by demo tooling | Only to confirm the M5 #4 quarantine |
| KI-08 | 8 | Custom, unreviewed gateway authentication | **No**; it is replaced (M9 #4, ADR-09). The freeze switch blocks every value path until then |
| KI-09 | 9 | No key backup, recovery or durable state | Only as node state (M9 #3) and recovery tooling (M11) |
| KI-10 | 10 | CI, release and dependency controls | Yes, as part of supply-chain review (M5 #6–#7, M7 #6, M11 #5) |

---

## 2. Accepted limits (by design)

These come from threat model v2 §9 (LM1–LM11), plus one availability limit. Each one stays after every milestone. A user-facing document that describes the affected mode must state the limit (the README support matrix, the Guard and operator docs, and the canary reports).

| ID | Limit | Source | What it means in practice | What bounds it | What an operator should do |
|---|---|---|---|---|---|
| KI-11 | **Within-policy outflow is bounded, not zero** | LM1; ROADMAP §3.3 | A caller who passes every check can move funds up to the caps. When every signer enforces, outflow per window is at most the group budget G (each signer caps its own reservations at L = ⌈t·G/n⌉; L alone holds only when every request reaches every signer). With c < t signers that do not enforce, it can reach (n−c)·L (ROADMAP §3.3, PC-06). The velocity spec fixes the exact formula | Velocity caps L = ⌈t·G/n⌉, the breaker, the float size, the monitor | Derive G from the written loss budget. Keep the float at or below that budget |
| KI-12 | **Common mode** | LM2; RK4 | Every signer runs the same kernel. A kernel bug accepts the same bad payload at all of them, so the threshold adds nothing against it | A two-shape allowlist, canonical re-encoding, fuzzing, a tronweb differential and an independent oracle (M6 #7–#8); caps; a monitor that judges what happened on chain, not the decoded intent. A second decoder is open (ADR-15) | Keep caps tight, and run the monitor in its own domain |
| KI-13 | **One key per network** | LM3 | TRON, Solana, Sui and Bitcoin transaction bytes carry no network id. For identical bytes, a testnet signature is also valid on mainnet | A separate key per network; network facts come only from the signed bundle; release builds refuse mainnet until M10-F | Never reuse a key across networks, including testnets |
| KI-14 | **A soft freeze does not revoke issued co-signatures** | LM4 | A co-signature already returned stays usable until the transaction expires | Short validity on zero-approval tiers; an outstanding-exposure report; an on-chain hard freeze with the owner keys | Rehearse the hard-freeze runbook on testnet |
| KI-15 | **A clock moved forward shortens a pending time-lock** | LM5 | A host whose clock jumps ahead activates a pending loosening early | An alert on every bundle offer; any admin can cancel a pending loosening by tightening; the host time baseline (AP5) | Act on bundle-offer alerts. Use several or authenticated time sources |
| KI-16 | **Receipts detect a rewritten log; they do not prevent it** | LM6 | While a host is compromised, its local receipt log can be rewritten | Hash chain plus signatures; heads anchored in the monitor's domain; the offline verifier | Pull and verify the evidence pack every month |
| KI-17 | **Solo mode** | LM7; RK1 | One human can reach every domain. Domain separation protects against losing one credential, vendor or host, not against the owner being compromised | The float size; a project-owned float by default (RF-1). Limited production needs ≥ 2 humans (PL-03) | Do not hold third-party funds (RF-3) |
| KI-18 | **No threshold key refresh** | LM8; RK5 | Rotating a key, or replacing a node, means a new key generation plus a sweep | None; it is an engine property (KI-28) | Plan sweeps and their fees ahead of time |
| KI-19 | **Caller-builds boundary** | LM9; ROADMAP §2.1 | Fees, energy, building, broadcast, confirmation, deposits and sweeps are the caller's job. Vaultex refuses bytes it cannot verify. Beyond that, it does not protect the caller from its own builder | None inside Vaultex | Run your own builder checks and confirmation monitoring |
| KI-20 | **K-alt and the callback gate rely on the operator's signer** | LM10 | If the Guard becomes a veto hook (K-alt), the veto holds only while the operator's signer fails closed. A compromised operator signer bypasses it | The monitor detects the bypass afterwards | Configure your signer to fail closed when the Guard is unreachable |
| KI-21 | **The chain cannot restrict destination, token or amount** | LM11 | Under the active permission, only the Guard limits what is paid and to whom. A Guard defect plus the operator key is the worst Phase-1 case: a loss of up to the float | The float cap; the monitor; the on-chain hard freeze | Keep the float at or below the loss budget |
| KI-22 | **Narrow coverage, and availability second** | SO7; TH55 | The kernel accepts exactly two TRON shapes, and refuses everything else and anything it cannot verify. Legitimate payouts outside those shapes, or caught by a false refusal, are refused | Retro-shadow and ≥ 14 days of live shadow before enforcement; false refusals ≤ 1%, each explained (M6 #10, M7 #5) | Keep the existing payout path as the overflow path |

---

## 3. Upstream, chain and token issues

| ID | Issue | Status | Effect | How Vaultex bounds it |
|---|---|---|---|---|
| KI-23 | Co-signing under a TRON active permission (threshold 2, restricted operations) is unproven for this setup | Upstream; **HYPOTHESIS** until the Nile spike (M6 #11) | If it does not work as documented, the Rung-2 design fails | The Nile spike decides go or no-go; the fallback is K-alt (KI-20) |
| KI-24 | A TRC-20 approval leaves a standing allowance. The spender can drain it with `transferFrom` without any further float signature | Upstream (standard token behaviour) | Loss without a Guard signature | The decoder refuses `approve`-class selectors; the monitor alerts on `Approval` events and non-zero allowances; every refill first checks that the allowance is 0 (RF-4) |
| KI-25 | Token issuers can blacklist, pause or upgrade a token, and chains can change parameters such as fees | Upstream | Funds frozen, or behaviour changed, with no Vaultex signature involved | The monitor alerts (TH49); caps bound the exposure |
| KI-26 | A chain data provider can lie or fail | Upstream | The monitor misses or misreads an outflow | ≥ 2 providers run by different operators; an event seen by either raises an alarm; "all clear" needs both (TB5) |
| KI-27 | Ed25519 libraries disagree on edge cases (non-canonical encodings, small-order points, cofactored or cofactorless checks) | Upstream | A signature that one implementation accepts and another refuses: approvals, bundles or receipts that verify differently in different places | Each RFC names one strict verification rule, and the kernel and the independent oracle are held to it by edge-case vectors ([KAT plan](KAT_PLAN.md) KAT-02) |
| KI-28 | The planned ECDSA engine (`cggmp24`, pinned as a triplet with `cggmp24-keygen` and `paillier-zk`) is an alpha release line. It has no identifiable abort and no threshold refresh, and its last audit predates the pinned version | Upstream; Gated (G-MPC, ADR-07) | Aborts that cannot be attributed to a party (availability only); rotation by new key generation (KI-18); unreviewed changes since the audit | An exact pin; the mandatory library-delta review (AL3); the upstream security channel; an unpatched Critical freezes signing (K11). The pin must sit at or above every release that fixes a published advisory. At the time of writing, one advisory database lists a cryptographic issue in releases before `0.7.0-alpha.2` ([Snyk](https://security.snyk.io/package/cargo/cggmp24)); the planned pin `=0.7.0-alpha.3` is above it. Re-check RUSTSEC and GHSA at pin time ([KAT plan](KAT_PLAN.md) KAT-30) |
| KI-29 | Engine auxiliary-material generation is heavy-tailed (15.6–107 s per party in the round-1 measurements) | Upstream; Gated | Slow or timed-out key setup | A background prime pool, encrypted at rest; an asynchronous job with a timeout ≥ 120 s; 20/20 epochs on 2-vCPU nodes (M8 #2) |

---

## 4. Gaps in assurance and evidence

| ID | Gap | Consequence | Closes with |
|---|---|---|---|
| KI-30 | No independent review, audit or penetration test of any Vaultex code has taken place | No claim of "reviewed" or "audited" may be made (ROADMAP §3.3) | Paid limited evaluations at the M6 and M7 gates; M10-K; M10-F (ADR-08) |
| KI-31 | The internal security notes were written by AI agents during development. Their "resolved" statuses are not audit results, and they do not cover KI-01–KI-10 | Do not cite them as assurance | Nothing to fix. `SECURITY_STATUS.md` states it |
| KI-32 | The Phase-1 components (kernel, Guard, monitor) are skeletons. Every control in threat model v2 is a plan until its milestone closes on an artifact | Phase-1 claims wait for M6 and M7 | M6, M7 |
| KI-33 | The `INTENT_V1`, `RECEIPT_V1` and `POLICY_BUNDLE_V1` specs are drafts, and no independent implementation has reproduced their vectors yet | Formats and vectors may still change | M6 #7; the [KAT plan](KAT_PLAN.md) |
| KI-34 | The kernel evidence does not exist yet: incident replay, the mutation check, ≥ 24 CPU-hours of fuzzing per decoder, and the ≥ 10k-input tronweb differential | No claim about decoder robustness | M6 #8. Local fuzzing waits on Q-RUN-2 and Q-RUN-3 |
| KI-35 | One maintainer, and most of the code was written by AI agents. In scenario (a), the owner's review is the only human review | Review is not independent; bus factor of one | The M5 #6 machine-account and branch-protection rules; external evaluations at M6 and M7; a contract cryptographer in scenarios (b) and (c) (ADR-01); kill criterion K1 |

---

## 5. Keeping this list current

- **Add an entry** when:
  - `SECURITY_STATUS.md` adds a category (WS-01 adds it there first, at category level);
  - the threat model adds a limit;
  - an upstream advisory, or a chain or token behaviour, is confirmed;
  - the owner accepts a review finding as a limit, in writing.
- **Retire an entry** only with the release that fixes it and the named test or CI run that proves the fix. Set the status to **Retired** and never delete the row.
- **Check it:**
  - at every freeze (M6, M7, M9);
  - before every review package or RFQ goes out (T14-1, T00-13);
  - when the threat model changes.
- **Consistency.** §1 follows `SECURITY_STATUS.md`, and §2 follows threat model v2 §9. A change to either is mirrored here in the same change.
- **Who.** R6 drafts (advisory), the contract cryptographer reviews once engaged, and the owner approves.
