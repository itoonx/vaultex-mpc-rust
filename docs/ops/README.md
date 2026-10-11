# Guard-line operations

| | |
|---|---|
| **Version** | 0.1-draft, 2026-10-11 |
| **Status** | **PROPOSED.** Drafted by R9 with R2 (WS-07, task T07-5). **Nothing here has been executed.** The procedures depend on components that are not built yet (§2). The real ceremonies and drills are owner work, gated by M7 and blocked on ADR-17 (T07-6). |
| **Covers** | Operating the Phase-1 Guard line before and during Rung 2: the Guard host, the outflow-monitor host, the cold domain, the key ceremonies, incident and recovery runbooks, drills, and the monthly evidence pack ([ROADMAP](../ROADMAP.md) §3.4 RF-4, §4.3 M7 #3, #4 and #8). |
| **Does not cover** | The legacy MPC stack. [`docs/RUNBOOKS.md`](../RUNBOOKS.md), [`docs/MONITORING.md`](../MONITORING.md) and [`docs/DEPLOYMENT.md`](../DEPLOYMENT.md) describe that stack. They do not apply to the Guard or the monitor. |
| **Sources** | ROADMAP §3.4, §4.3 (M7), §5.2 (WS-06, WS-07); [threat model v2](../assurance/THREAT_MODEL_V2.md) §3.2, §6.5, §6.6, §6.9 and §9; the WS-06 and WS-07 design studies (private research archive; their public content lands in specs and in these files). |
| **Public safety** | Category + fix only. These files hold no secret values, no secret locations, no account names and no float addresses. Real transcripts, drill logs and evidence packs are private (§5). |
| **Owner** | WS-07 (R9, R2). The owner runs every ceremony and drill. |

---

## 0. Files

| File | What it holds | ROADMAP |
|---|---|---|
| [`host-baseline.md`](host-baseline.md) | Failure-domain rules and the hardening baseline for the Guard and monitor hosts, with reference configuration and the evidence to capture | M7 #4 |
| [`runbooks.md`](runbooks.md) | The monitor's alert catalogue, incident and recovery runbooks RB-0…RB-14, the drill catalogue DR-1…DR-9, and the record templates | M7 #3, #4, #8 |
| [`evidence-pack.md`](evidence-pack.md) | The monthly evidence-pack format, its signatures, and the offline verification procedure | M7 #8, #9 |
| [`../ceremonies/guard.md`](../ceremonies/guard.md) | Genesis, rotation and recovery ceremonies for the Guard line, with the transcript template | M7 #4 |

---

## 1. Vocabulary

### 1.1 Failure domains

The same names as [threat model v2](../assurance/THREAT_MODEL_V2.md) §3.2.

| Domain | Holds | Hosting |
|---|---|---|
| **D-OP** operator | The operator key; the submitter that builds, signs and broadcasts; its own chain-RPC accounts | Operator's provider |
| **D-G** Guard | The Guard key (one per network); the receipt key; the kernel state | A second provider and account |
| **D-M** monitor | The monitor's freeze, evidence and (optional) ack keys; its own chain-RPC accounts; alerting | A third provider and account |
| **D-C** cold | Owner keys (the float's owner permission, cold 2-of-3); policy admin keys (M-of-N) | Offline devices |
| **D-R** build and release | The release-signing identity; CI | Code host |

### 1.2 Keys

| Key | Type | Domain | Purpose | Can it move funds? |
|---|---|---|---|---|
| Operator key | secp256k1 | D-OP | One of the two signatures the active permission needs | Not alone |
| Guard key, one per network | secp256k1 | D-G | The Guard's co-signature. Custody: ADR-17 | Not alone |
| Receipt key | Ed25519 | D-G | Signs every decision receipt | No |
| Owner keys (3) | secp256k1 | D-C | The float's owner permission, 2-of-3: permission updates, hard freeze, recovery | **Yes, any two of them.** The float cap bounds the loss |
| Policy admin keys (M-of-N) | Ed25519 | D-C | Sign policy bundles and unfreeze orders. Any one can freeze | No |
| Monitor freeze key | Ed25519 | D-M | Freeze orders only. It can never unfreeze | No |
| Monitor ack key (only if OD-1 is adopted) | Ed25519 | D-M | The liveness lease (§4) | No |
| Monitor evidence key | Ed25519, OpenSSH format | D-M | Signs evidence-pack manifests and refill-check reports | No |
| Admin review credential | FIDO2 `sk-ssh-ed25519` | D-C | Countersigns ceremony transcripts, drill logs and evidence packs | No |
| SSH credentials, one per domain | FIDO2 `sk-ssh-ed25519` | each host domain | Host login | No |
| mTLS client certificates | per role | D-OP (`op`), D-M (`mon`) | Authenticate to the Guard API | No |
| Release-signing identity | — | D-R | Signs Guard and monitor releases | No |

### 1.3 Terms

- **Float.** The TRON account the Guard co-signs for. It holds at most the owner's written loss budget, within the Phase caps of ROADMAP §3.4.
- **Cold treasury.** The owner's own account that refills the float. It is outside the Guard line.
- **Soft freeze.** A freeze order to the Guard: the kernel stops co-signing, and every later co-sign request is refused with `FROZEN` and receipted. One admin key or the monitor's freeze key is enough. It does **not** revoke co-signatures already issued ([threat model](../assurance/THREAT_MODEL_V2.md) LM4).
- **Hard freeze.** An on-chain permission update signed by 2 of the 3 owner keys, which removes or replaces a compromised key. It is human-bound: the time it takes is measured by drill DR-9.
- **Outstanding exposure.** Co-signatures the Guard has issued whose transactions have not expired and have not been seen on chain. After a soft freeze, only these can still execute.
- **Overflow.** When the Guard refuses or is down, the payout leaves through the operator's pre-existing path, and the float is not used. A false freeze costs availability, not funds.
- **Solidified.** A TRON block confirmed by enough block producers to be final, typically about a minute after it is produced. Alarms act on the latest block; accounting and evidence use solidified data.

### 1.4 Severity

| Severity | Meaning | Response |
|---|---|---|
| **Sev-1** | Funds may be at risk | Page every channel at any hour. Almost every Sev-1 rule also freezes the Guard automatically; the alert catalogue lists the exceptions. Start at [RB-0](runbooks.md#rb-0-first-response-to-any-page) |
| **Sev-2** | Degraded or suspicious, no direct loss path | Page; handle the same business day. A few Sev-2 rules also freeze ([runbooks](runbooks.md) §1) |
| **Info** | Expected noise | Daily digest |

---

## 2. What exists at this commit

| Component | Task | State |
|---|---|---|
| Chain watcher, `vaultex-monitor watch` | T07-2 | **Implemented.** Follows TRON on two or more keyless public providers, with a crash-safe cursor per provider, fork detection and rate-limit backoff. No matching, alerts or freeze |
| Receipt matching, alert rules, refill check | T07-3 | Planned (waits on receipts, T05-6) |
| Freeze path; drills DR-1…DR-5 and DR-8 | T07-4 | Planned (waits on T07-3 and T06-5) |
| Guard service | T06-5 | Skeleton that refuses every request; blocked on ADR-11 and ADR-17. These files also need from it a read-only journal export for the `mon` role ([host baseline](host-baseline.md) HB-29) |
| `vaultex-policy` and `vaultex-approve` | T05-8 | Skeletons |
| Offline receipt verifier | T05-6 | Planned |
| `vaultex-monitor evidence build` / `evidence verify` | Follow-up (WS-07) | Planned. Until it exists, the manual checks in [`evidence-pack.md`](evidence-pack.md) §7 apply |
| Deployable host files (`infra/guard/**`) | Follow-up (WS-07) | Planned. Reference snippets are in [`host-baseline.md`](host-baseline.md) |
| Signed reproducible releases | T02-12 | Gated by M7 |
| Real ceremonies and drills | T07-6 | Owner; gated by M7; blocked on ADR-17 |

Every command these files name for a planned component is marked *(planned)*. Its exact flags come with the task that builds it.

---

## 3. Operating rules

1. **Executed effects, not decoded intent.** The monitor judges what the chain did: token transfer events, contract results, balance changes and fees. A decoder defect therefore cannot hide an outflow from it.
2. **Alarm on any source, clear only when all agree.** An event seen by either chain provider raises an alarm. A block counts as clear only when both providers agree at solidified height.
3. **Freeze is cheap, unfreeze is dear.** Any Sev-1 freezes. An unfreeze needs M-of-N admins, a written cause, and local submission on the Guard host ([RB-10](runbooks.md#rb-10-unfreeze)).
4. **No cheap attacker-triggered freeze.** Every freeze rule needs a float signature, a real (non-zero) allowance, an issuer action, a donation that takes the float more than its headroom above its ceiling (MR-12), or an event inside the Guard domain. Dust, zero-value transfers, zero-value approvals and events from unlisted contracts never freeze.
5. **The monitor can never unfreeze.** It holds no admin key.
6. **Fail closed.** No real-funds operation without a running monitor (RF-4). If the monitor is lost, an admin freezes the Guard, or the liveness lease lapses (OD-1).
7. **Nile first.** Every ceremony and drill runs on Nile before mainnet, with the same steps and the same transaction shapes.
8. **No AI-agent credential in any production domain** (M5 #12, M7 #4). Agents write code and drafts. The owner deploys signed releases and runs every ceremony and drill.
9. **Nothing secret in a transcript, a log, a pack or this repository.** Public keys, addresses, digests and transaction hashes only. Locations are recorded by label.

---

## 4. Open decisions

ADR-05, ADR-06, ADR-11 and ADR-17 (see [`docs/adr/`](../adr/)) gate all of this. These operational decisions are also open; their IDs are local to `docs/ops`.

| ID | Question | Options | Recommendation | Needed by |
|---|---|---|---|---|
| OD-1 | **Liveness lease:** the Guard co-signs only while it holds a fresh, monitor-signed acknowledgement of its receipt head, with at most a few unacknowledged accepts | Adopt · page only | **Adopt.** It enforces RF-4 by mechanism and bounds unmonitored exposure. Cost: a monitor outage moves payouts to overflow | Before the Guard API freezes (T06-5) |
| OD-2 | Destination mode in Phase A | Allowlist (an unknown destination freezes) · open (it pages) | **Allowlist** for a project-owned float | Genesis bundle (CER-4) |
| OD-3 | Custody of the monitor's keys | Host-sealed software keys · cloud KMS Ed25519 | **Host-sealed.** A leak costs availability only (unwanted freezes) | CER-3 |
| OD-4 | Cold signing device for owner-permission transactions | A hardware wallet, after a Nile test · an air-gapped laptop | **Test one device on Nile first**; the laptop is the fallback | Before CER-5 |
| OD-5 | The monitor's chain data in Phase A | Two hosted providers run by different operators · plus a self-hosted node | **Two hosted providers now**; a self-hosted node from Phase B, or when quotas bind | Before T07-3 ends |
| OD-6 | What the public canary report shows | Aggregates only · plus the float address and transaction hashes | **Aggregates plus transaction hashes** for a project-owned float | Before M7 #9 |
| OD-7 | Admin workstation | Dedicated device · a separate OS user gated by hardware keys | **Separate user now**; dedicated device by Phase B | Before CER-1 |
| OD-8 | M7 #4 says "encrypted Guard-key backup in 2 offline locations". With a non-exportable key there is no backup | Keep the wording · "backup, or a drilled chain-native replacement" | **Re-word** if ADR-17 picks a non-exportable key | With ADR-17 |

---

## 5. Where real records go

| Record | Where | Public? |
|---|---|---|
| Ceremony transcripts | Private evidence store, then the next evidence pack | Public keys and transaction hashes only, if OD-6 allows |
| Drill logs, incident records | Private evidence store and the evidence pack | No; summarised in the canary report |
| Monthly evidence packs | Private evidence store: two offline copies plus one encrypted off-host copy | No; the canary report is derived from them |
| Account inventory (providers, accounts, recovery channels) | Private, by label | No |

None of these ever goes into this repository, an issue, a CI log, or a file an agent can read.

---

## 6. Keeping these files true

- Update them in the same change as the code they describe: alert rules (T07-3), the freeze path (T07-4), the Guard API (T06-5) and the receipt format (T05-6).
- After each real ceremony or drill, the owner records deviations here as procedure fixes, never as narrative.
- Status words follow ROADMAP §9.5: nothing is described as done before its artifact exists.
