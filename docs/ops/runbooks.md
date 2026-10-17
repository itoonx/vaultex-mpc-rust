# Runbooks and drills: Guard line

| | |
|---|---|
| **Version** | 0.1-draft, 2026-10-11 |
| **Status** | **PROPOSED.** No runbook or drill has been run. The monitor rules in §1 are the specification for T07-3 and T07-4; the Guard behaviour they rely on is the specification for T06-5. Commands for components that do not exist yet are marked *(planned)*. |
| **Covers** | Responding to monitor alerts; recovering from lost or compromised keys and hosts; refills and unfreezes; the drill catalogue that produces the M7 #3, #4 and #8 evidence ([ROADMAP](../ROADMAP.md) §4.3). |
| **Who runs them** | The owner. Agents may draft incident records from logs; they never run a runbook step that signs, unfreezes, moves funds or touches a production host (FD-4). |

Vocabulary (domains, keys, severities, soft and hard freeze, outstanding exposure) is in the [ops README](README.md) §1.

---

## 0. How to use these runbooks

- Times are UTC. Record each step's time in the incident record (§6) as you go.
- Paste only public values into records: alert IDs, transaction hashes, receipt sequence numbers, digests, public keys. Never a secret, a passphrase or a provider key.
- **Mainnet steps that sign with owner keys move value or change permissions.** They follow the ceremony rules ([`../ceremonies/guard.md`](../ceremonies/guard.md) §1): air-gapped preparation, two-tool hash check, then signing.
- When a runbook says "freeze" and the monitor has not already frozen the Guard, any one admin can: sign a freeze order with the admin CLI *(planned, T05-8)* and submit it through the monitor's relay or locally on the Guard host.
- When in doubt, stay frozen. A freeze costs availability (payouts overflow to the operator's existing path); an early unfreeze can cost funds.

---

## 1. Alert catalogue (monitor rules)

The monitor implements these rules in T07-3. IDs are append-only and never reused, and each freezing rule maps one to one to a freeze reason. "Float-signed" means a transaction whose owner is the float address.

| ID | Detects | Severity | Freezes | Runbook |
|---|---|---|---|---|
| MR-01 | A float-signed transaction of a contract type other than a TRX transfer or a smart-contract call. **Fires during ceremonies:** an owner-signed permission update (type 46) raises it; expected there ([ceremony](../ceremonies/guard.md#1-rules-for-every-ceremony) rule 2) | 1 | Yes | RB-1, then RB-3 or RB-4. Not for a transaction in a declared ceremony's plan |
| MR-02 | A float-signed transaction under a permission other than the configured active one, including the owner permission. **Fires during ceremonies:** every owner-signed ceremony or recovery transaction raises it; there the Guard is already frozen, and the alert is expected and closed in the transcript, incident record or drill log (ceremony rule 2) | 1 | Yes | RB-1; RB-8 if owner keys are suspect |
| MR-03 | A float-signed contract call to a token outside the allowlist, or anything but the plain token transfer (selector, call value, call-data length). **Fires during recovery:** RB-2's owner-signed `approve(spender, 0)` raises it; expected there (ceremony rule 2) | 1 | Yes | RB-1; RB-2 if it changed an allowance |
| MR-04 | A float-signed transaction with no matching co-sign accept receipt after the grace period (10 s, ESTIMATE; it covers receipt-export lag, since the Guard records a receipt before it releases a signature). **Fires during ceremonies:** no owner-signed transaction has a co-sign receipt, so each one in a ceremony or recovery raises it; expected there (ceremony rule 2) | 1 | Yes | RB-1, then RB-3 or RB-4. Not for a transaction in a declared ceremony's plan |
| MR-05 | A matched transaction whose executed effects (recipient, asset, amount, fee) differ from its receipt or from the monitor's own derivation of the intent | 1 | Yes | RB-1; a kernel defect is suspected (stay frozen; report it under `SECURITY.md`) |
| MR-06 | Receipt-chain integrity failure: signature, sequence gap, previous-link, key continuity, time going backwards, a receipt later than its transaction's block, or a history that does not extend the monitor's anchored head | 1 | Yes | RB-3 |
| MR-07 | An `Approval` event with a **non-zero** value naming the float as owner, on an allowlisted token. A zero-value `Approval` (such as RB-2's revocation) is Info under MR-19: it raises no allowance, and the float-signed transaction behind it is caught by MR-02, MR-03 or MR-04 | 1 | Yes; refills blocked | RB-2 |
| MR-08 | A non-zero allowance from the float to any spender in the watched set | 1 | Yes; refills blocked | RB-2 |
| MR-09 | Tokens leave the float in a transaction the float did not sign | 1 | Yes | RB-2 |
| MR-10 | A monitor cap exceeded: per transaction, rolling 24 h amount or count per asset, or fee spend. The monitor's caps are the written loss budget, not the policy bundle's | 1 | Yes | RB-1 |
| MR-11 | A destination outside the monitor's allowlist | 1 (allowlist mode) or 2 (open mode; OD-2) | In allowlist mode | RB-1 |
| MR-12 | The float's balance (any asset, or TRX) above its ceiling. Up to the **headroom** above it (per asset, in `monitor.toml`; ESTIMATE 10% of the ceiling, and always far above dust) it only pages; beyond the headroom it also freezes. Refills stop at the ceiling minus the headroom (RB-9), so only a sizeable donation can freeze | 2 | Only beyond the headroom | RB-9 (excess); RB-1 if frozen |
| MR-13 | Solvency at solidified height: the balance change differs from inflows − outflows − fees over every transaction the monitor observed, so something moved that the monitor did not see. Matching is MR-04's job | 1 | Yes | RB-1 |
| MR-14 | The account's permissions differ from the expected set (keys, thresholds, operations, permission count). During a ceremony it is expected until `monitor.toml` is updated | 1 | Yes | RB-3 or RB-8, unless it is the ceremony's own change |
| MR-15 | A token issuer action: deprecation, or blacklisting of the float (Sev-1, freezes); pause or a fee-parameter change (Sev-2) | 1 or 2 | Sev-1 cases | RB-12 |
| MR-16 | Guard lifecycle: a **loosening** policy bundle offered (Sev-1 page inside its time-lock, no freeze); tightening, activation, state changes, key rotations (Sev-2). The changes a declared ceremony makes are expected (ceremony rule 2) | 1 or 2 | No | RB-1: confirm an admin intended it. A pending loosening is superseded only by an M-of-N bundle; any admin can freeze |
| MR-17 | An accept receipt whose transaction never appeared by its expiry plus 2 minutes | Info; Sev-2 above 5 a day | No | — |
| MR-18 | A possible double pay: the same recipient, asset and amount within 24 h | 2 | No | RB-1 (reconcile with the operator) |
| MR-19 | Spoofable noise: dust, zero-value transfers, zero-value `Approval` events, and events from unlisted contracts naming the float. Only a donation that takes the float past its MR-12 headroom can freeze, and that costs the sender real funds | Info | **Never** | — |
| MR-20 | Data and host health: provider divergence at solidified height; a provider down > 5 min; head lag > 30 s; clock offset > 500 ms; a Guard binary digest ≠ the pinned release; a login outside a declared window; the pull of the Guard host's journal failing for > 5 min or showing a gap ([host baseline](host-baseline.md) HB-29) | 2 (both providers down: 1) | No (with OD-1 the Guard fails closed) | RB-7, RB-14 |

**Freeze latency.** From the block time of the triggering transaction to the Guard's first `FROZEN` refusal receipt: target p99 ≤ 32 s, hard limit **60 s** (RF-4; ESTIMATE budget: 3–6 s to reach a provider, ≤ 3 s poll, ≤ 2 s fetch, up to the grace period for MR-04, ≤ 1 s to sign, post and fsync, plus retry slack).

**Paging.** Two independent push channels plus email. A dead-man check pages if the monitor's heartbeat stops.

---

## 2. First response

### RB-0. First response to any page

1. Acknowledge the page, so it stops escalating. Open an incident record (§6) with the alert ID.
2. Read the Guard state from the monitor host: `vaultex-monitor status` *(planned)*. Note FROZEN or RUNNING, the receipt head, and the outstanding exposure.
3. **Sev-1:** confirm the Guard is FROZEN. If no state-change receipt appears within 30 s of the alert, freeze with an admin key; if that also fails, go to [RB-3](#rb-3-guard-key-compromise-suspected-or-freeze-not-confirmed) (hard freeze).
4. If the outstanding exposure is not zero and compromise is suspected, a soft freeze is not enough: those co-signatures can still execute until they expire ([threat model](../assurance/THREAT_MODEL_V2.md) LM4). Decide now whether to hard-freeze (RB-3).
5. Never unfreeze to "see if it happens again". Never change the monitor's caps or configuration while a Sev-1 is open.
6. Go to the runbook the alert catalogue (§1) names.

---

## 3. Incident runbooks

### RB-1. Sev-1 triage after an auto-freeze

**Goal:** find the cause before anything is unfrozen.

1. Collect the facts: the transaction(s), the receipts the monitor matched (or did not), both providers' views, and the Guard's state history.
2. Classify:
   - **Benign** (a configuration error, a data-source error, a stale allowlist): fix the cause, write the root-cause note, then [RB-10](#rb-10-unfreeze).
   - **Malicious or unexplained:** stay frozen and go to RB-2, RB-3 or RB-4 as the facts point. Payouts keep using the overflow path.
3. If a kernel defect is suspected (MR-05, or an accept the policy should have refused): keep the Guard frozen until a fix is released and reviewed, and report the defect privately under [`SECURITY.md`](../../SECURITY.md).

**Done when:** the cause is written down and the next runbook (or RB-10) is chosen. **Evidence:** the alert ID and the root-cause note in the incident record.

### RB-2. Allowance or `Approval` on the float

**Trigger:** MR-07, MR-08 or MR-09. A standing allowance lets the spender move the float's tokens without another float signature (ROADMAP §3.4 RF-4), so this is always treated as live.

1. Keep the Guard frozen. Refills are blocked automatically.
2. If tokens are already leaving (MR-09): the owner permission (2-of-3) sweeps the remaining tokens to the cold treasury first. Then continue.
3. The owner permission signs `approve(spender, 0)` for every spender with a non-zero allowance, following the ceremony rules. Each owner-signed transaction here (sweep or revocation) raises the alerts listed for it in [ceremony rule 2](../ceremonies/guard.md#1-rules-for-every-ceremony): acknowledge each one in the incident record against its transaction hash.
4. Confirm that every allowance in the watched set is 0 **at solidified height on both providers**.
5. An allowance needs a float signature, so find which keys signed the approving transaction. Until that is explained, treat it as RB-3 (Guard key) and RB-4 (operator key) together.
6. Close the alerts in the incident record: the triggering MR-07, MR-08 or MR-09 once step 4 holds and step 5 is explained (including any RB-3 or RB-4 it led to), and the expected alerts from step 3. The refill check needs no open Sev-1, so this comes first.
7. Refill only after the refill check passes ([RB-9](#rb-9-refill)).

**Evidence:** transaction hashes; the allowance readings; the closed alerts; the refill-check report.

### RB-3. Guard-key compromise suspected, or freeze not confirmed

**Trigger:** MR-04 or MR-06; a freeze that did not take effect within 30 s; a Guard-host compromise.

1. **Hard freeze.** The owner permission signs a permission update that replaces the Guard key in the active permission with a new key ([CER-R1](../ceremonies/guard.md#cer-r1-guard-key-rotation)). If funds are at risk faster than that can be prepared, sweep the float to the cold treasury first.
   - The float always keeps enough TRX for two permission updates and their fees, so this step can never stall for fees. Read the live fee (chain parameter #22) at each ceremony.
2. Treat the Guard host as lost: rebuild it ([RB-5](#rb-5-guard-host-lost-or-rebuilt)).
3. Receipt key: if the host was compromised, the old receipt key is not trusted. Create a new one and record the re-anchor point, the last receipt the monitor anchored before the compromise window ([CER-R2](../ceremonies/guard.md#cer-r2-receipt-key-rotation)).
4. Reconcile every outflow since the last clean evidence pack.

**Evidence:** transaction hashes; the new ceremony transcript; the reconciliation.

### RB-4. Operator-key compromise suspected

1. Keep the Guard frozen.
2. The owner permission replaces the operator key in the active permission (same procedure as CER-R1, for the operator's key).
3. The operator rebuilds the D-OP host and its credentials.
4. Then RB-1.

**Evidence:** transaction hash; read-back of the new permissions (MR-14 clear).

### RB-5. Guard host lost or rebuilt

1. Keep the Guard frozen (it is down anyway; payouts overflow).
2. Create a new host at the Guard domain's provider, preferably in another region, and apply the [host baseline](host-baseline.md). Verify the release signature on the host.
3. Restore the Guard key according to ADR-17: from one of the two offline backups (file custody), or by switching to the standby key and running CER-R1 (non-exportable custody).
4. Restore the receipt journal **from the monitor's anchored copy**, then verify it end to end with the offline receipt verifier *(planned, T05-6)*. Its head must equal the monitor's last anchor.
5. Restore the configuration files from backup and compare their SHA-256 with the ceremony transcript.
6. Start the Guard frozen. The monitor must reconnect and report head continuity.
7. Unfreeze ([RB-10](#rb-10-unfreeze)). A frozen Guard refuses co-signing, so the test comes after this.
8. Test. On Nile: co-sign one test transfer through the full path, matched by the monitor (this is drill DR-6, the M7 #4 restore drill). On mainnet: the first payout after the unfreeze, with the monitor watching. If the test fails, any admin re-freezes at once and the failure goes to [RB-1](#rb-1-sev-1-triage-after-an-auto-freeze).

**Evidence:** drill or incident log; head continuity; the unfreeze receipt; the test transaction hash.

### RB-6. Monitor host lost

1. RF-4 forbids real-funds operation without the monitor. With the liveness lease (OD-1), the Guard refuses on its own once the lease expires. Without it, **an admin freezes the Guard now**.
2. Create a new host at the monitor domain's provider and apply the [host baseline](host-baseline.md).
3. Restore `monitor.toml` from backup; its SHA-256 must match the latest ceremony or change record.
4. Keys:
   - Freeze key lost: make a new one ([CER-3](../ceremonies/guard.md#cer-3-monitor-keys)), add it with a tightening bundle (one admin while no loosening is pending, otherwise M-of-N; immediate; the v1 bundle has no freeze-key field yet), and remove the old one later with a loosening bundle (M-of-N, time-locked) ([CER-R3](../ceremonies/guard.md#cer-r3-monitor-key-rotation)).
   - Evidence or ack key lost: make new ones and record them (CER-R3).
5. Rebuild the receipt copy: pull the Guard's export from the receipt after the last evidence pack's head for the current receipt key (sequence numbers count per key; [evidence-pack.md](evidence-pack.md) §4), and verify that it extends that head. The anchors taken since that pack are lost with the host, so a rewrite inside that window would go unseen; record the gap in the incident record.
6. Rescan the chain from the last solidified height in the last evidence pack, so nothing in the outage window is missed.
7. Every outflow during the outage must be matched before the Guard is unfrozen ([RB-10](#rb-10-unfreeze)).

**Evidence:** bundle receipts for any key change; the rescan range; the match report.

### RB-7. Chain-data provider outage or divergence

1. **One provider down:** the monitor runs degraded and pages Sev-2. Alarms still fire from the other one. Open a ticket with the vendor.
2. **Both down:** no block can be cleared. Switch one provider to the pre-arranged standby (a recorded configuration change, which pages). With OD-1 the Guard fails closed meanwhile; without it this is Sev-1, so freeze.
3. **Divergence at solidified height:** compare with a third, read-only view (for example a block explorer). Record which provider was wrong. It never clears automatically.

**Evidence:** the provider health table in the evidence pack; the configuration change record.

### RB-8. Owner key lost or compromised

1. One owner key lost or suspected: the other two sign a permission update that replaces it, rehearsed first on Nile with the same JSON ([CER-R4](../ceremonies/guard.md#cer-r4-owner-key-replacement)). A suspected compromise is urgent: one more key gives an attacker the owner permission.
2. Two or more owner keys lost or compromised: the owner permission is lost. This cannot be recovered on chain; the float cap is what bounds the loss. Sweep what the remaining controls still allow, and record the incident.

**Evidence:** transaction hashes; read-back of the new permissions.

### RB-9. Refill

1. Run the refill check on the monitor host: `vaultex-monitor refill-check` *(planned, T07-3)*. It prints PASS only if:
   - no Sev-1 alert is open, and the Guard is RUNNING or deliberately FROZEN;
   - every allowance-raising transaction has been followed by a revocation and has a closed ceremony, incident or drill record; every allowance in the watched set reads 0 at solidified height on both providers;
   - every outflow up to the solidified height is matched to a receipt, or (owner-signed) to a closed ceremony, incident or drill record, and the balances reconcile (MR-13 clean);
   - the balance plus the refill amount stays at or under **the ceiling minus the headroom** (MR-12), for the asset and for TRX;
   - the permissions equal the expected set.
2. The owner signs the transfer from the cold treasury **only with a PASS report less than 10 minutes old**, and for an amount within that bound.
3. The monitor confirms the inflow (class "refill") and the new balance.

A refill that arrives without a matching PASS report pages Sev-2. **Evidence:** the signed PASS report and the transaction hash, both in the evidence pack.

**Excess above the ceiling (MR-12).** Within the headroom the Guard keeps running: the owner has the excess sent back to the cold treasury as a normal co-signed transfer (operator → Guard), allowed because the cold treasury is on the destination allowlist (CER-4). An owner-permission sweep would freeze the Guard (MR-02), so it is not used here. Beyond the headroom the Guard is already frozen, and stays frozen while the excess is there: the owner permission sweeps the excess to the cold treasury under the ceremony rules (its alerts are expected, [ceremony rule 2](../ceremonies/guard.md#1-rules-for-every-ceremony)), then RB-1 and RB-10.

### RB-10. Unfreeze

1. Preconditions, all written in the incident record (in a drill, the drill log):
   - the cause is known and fixed (RB-1);
   - every outflow is matched to a receipt or to a closed ceremony, incident or drill record, every allowance is 0, and the permissions equal the expected set;
   - for a host rebuild, head continuity is confirmed.
2. M admins each sign the unfreeze order on their own admin devices.
3. The order is submitted **locally on the Guard host**, through its admin socket. The network API refuses unfreeze orders.
4. Confirm the state-change receipt, and confirm that the monitor's log shows it took no part.

**Evidence:** the unfreeze receipt (sequence number and digest).

### RB-11. Chain parameter change

**Trigger:** a change in the permission-update fee (#22), the multi-signature fee (#23) or the energy price.

1. Re-check the fee-limit bounds in the policy bundle and the monitor's fee caps against the new values.
2. Tighten (one admin while no loosening is pending, otherwise M-of-N; immediate) or loosen (M-of-N, time-locked) as needed.
3. Update the TRX reserve rule (RB-3 step 1) and the ceremony fee estimates.

**Evidence:** the bundle digest.

### RB-12. Token issuer event

1. Deprecation, or blacklisting of the float: the monitor has frozen the Guard (MR-15). Keep it frozen.
2. Pause or fee-parameter change: assess. A non-zero transfer fee breaks amount matching, so tighten the policy to stop that asset.
3. The owner contacts the issuer if needed.
4. Before the asset is used again, re-run the token onboarding checklist (§5).

**Evidence:** notes in the incident record; the bundle digest if the policy changed.

### RB-13. Policy admin key lost or compromised

1. A single admin key can freeze (availability) and can count towards a loosening, which is time-locked and pages Sev-1 (MR-16). If compromise is suspected, freeze, and have the admin quorum supersede any pending loosening with an M-of-N bundle.
2. The admin set is pinned in local configuration at a ceremony and is never changed by a network message. Replace the key with [CER-R5](../ceremonies/guard.md#cer-r5-admin-key-replacement).
3. If the loss leaves fewer than M usable admin keys, no unfreeze or loosening is possible until CER-R5 completes. That is the intended failure mode.

**Evidence:** the new admin-set digest; the ceremony transcript.

### RB-14. Planned maintenance

For a release upgrade, an OS reboot or any login.

1. Declare the window to the monitor in advance: start, end, host, reason. Logins inside it are still logged; they do not page.
2. Release upgrade: verify the new release on the host (HB-26). Update the monitor's pinned digest **first** (a recorded configuration change). Stop the Guard; payouts overflow. Install, start, and confirm receipt-head continuity and one shadow request.
3. Nothing in this runbook unfreezes. If the Guard was frozen before, it stays frozen.
4. Close the window, and record the new binary digest in `host/releases.csv` of the evidence pack.

---

## 4. Drills

Drills prove the runbooks work. Each produces a signed drill log (§7) that goes into the evidence pack. Mainnet drills are owner actions under RF-1; agents never run them.

| ID | What it proves | How | Pass criterion | When |
|---|---|---|---|---|
| DR-1 | The freeze pipeline, without the chain | Inject a drill-tagged event into the monitor's matcher on a testnet Guard: `vaultex-monitor drill --synthetic` *(planned, T07-4)* | Freeze receipt and first `FROZEN` refusal within 60 s of injection; unfreeze with test-only admin keys | Weekly, automated |
| DR-2 | **The ≤ 60 s auto-freeze on a real outflow** (M7 #3; on mainnet, M7 #8) | See §4.1 | t2 − t0 ≤ 60 s | Nile before Rung 2; mainnet once in Phase A |
| DR-3 | Approval and allowance detection, and the refill block | On Nile, the owner permission signs `approve(treasury, 1)` on the test token | MR-07 at once and MR-08 at the next snapshot; freeze within 60 s; refill check FAIL. Then RB-2: `approve(treasury, 0)` raises only the expected alerts (MR-02, MR-03, MR-04; no MR-07); after solidification, and once the drill's alerts are closed in the drill log, refill check PASS | Nile before Rung 2 |
| DR-4 | The Guard fails closed when the monitor is lost (only if OD-1 is adopted) | Stop the monitor on a testnet setup | Guard refuses co-sign requests within the lease period, with a receipted refusal | Nile before Rung 2 |
| DR-5 | Degraded data sources | Block provider A at the monitor's firewall, then both | One down: Sev-2 within 5 min and alarms still fire. Both down: no block clears; lease lapse or Sev-1 | Nile before Rung 2 |
| DR-6 | Guard restore to a fresh host (M7 #4 restore drill) | RB-5 end to end on Nile | Head continuity; after the unfreeze, a co-signed test transfer matched by the monitor | Before Rung 2; then quarterly |
| DR-7 | Chain-native recovery: the owner keys rotate the Guard key (M7 #4; on mainnet, M7 #8) | CER-R1 | New permissions read back; the old Guard key's co-signature is rejected by the chain; the monitor's expected set updated | Nile before Rung 2; mainnet in Phase A |
| DR-8 | Receipt-history tampering is detected | On a testnet Guard, serve the monitor a receipt history that does not extend its anchored head (test fixture) | MR-06 and a freeze | Before Rung 2 |
| DR-9 | Time to hard freeze | Retrieve 2 of the 3 cold keys and sign a Nile permission update, from a cold start | Measured. The result is the documented exposure window for a stolen Guard key plus operator key | Before Rung 2; then quarterly |

ESTIMATE of owner time before Rung 2: about 6–10 h for DR-2…DR-9 on Nile; then about 2–4 h a month including quarterly drills and pack review.

### 4.1 DR-2: chain-injected unmatched outflow

**Preconditions:**
- The Guard is RUNNING. A shadow probe in the operator domain sends a valid request every 2 s, so the first refusal after the freeze is timestamped.
- Both hosts are NTS-synced; record `chronyc tracking` offsets.
- The owner-permission signing setup is ready (ceremony rules).

**Steps:**
1. **t0.** The owner permission (2-of-3) signs a 1 TRX transfer from the float to the cold treasury and broadcasts it. (Not to the float itself: TRON refuses self-transfers.) t0 is the timestamp of the block that includes it.
2. The monitor raises MR-02 at once: the owner permission signed a transfer, and no ceremony is under way.
   - **Nile variant DR-2b:** the drill configuration lists a Nile-only drill permission (its own key, transfers only) as allowed, so the transaction passes MR-02 and must be caught by MR-04 (no receipt) after the grace period. This exercises the matcher instead of the permission check.
3. The monitor signs and posts the freeze. **t1:** the Guard's state-change receipt.
4. **t2:** the first `FROZEN` refusal receipt for a probe request.
5. **Pass if t2 − t0 ≤ 60 s.**
6. Unfreeze per RB-10. The monitor's log must show it issued no unfreeze.

**Record:** t0, the monitor's detection time, t1, t2, the freeze order's digest, both receipts' sequence numbers and digests, the transaction hash, and the clock offsets.

### 4.2 Canary amounts

Scripted Phase-A payouts carry a unique tag in the lowest digits of the amount. Any repeated (recipient, amount) pair is then a real double pay by construction, which makes M7 #8's "0 double-pays" directly checkable from MR-18.

---

## 5. Token onboarding checklist

Before an asset enters the token allowlist (policy bundle and `monitor.toml`), and again after any issuer event (RB-12):

- [ ] The contract has no signature-based approval function (`permit`-style). Otherwise allowances can appear without a float transaction, and the monitor needs an extra rule first.
- [ ] Transfer-fee parameters are zero.
- [ ] The contract is not deprecated or forwarding to another contract.
- [ ] Decimals are pinned in the bundle and in `monitor.toml`.
- [ ] If the contract is upgradeable, its admin and upgrade events are added to MR-15 first.
- [ ] The contract address is checked against the issuer's published address on two independent sources.

---

## 6. Incident record template

```markdown
# Incident <YYYY-MM-DD>-<n>: <one-line summary>

- Alert ID(s) and rule(s): …
- Severity: Sev-1 | Sev-2      Network: tron:<id>
- Detected (UTC): …      Acknowledged: …      Frozen (state-change receipt seq/digest): …
- Outstanding exposure at freeze: <count> co-signatures, latest expiry …

## Timeline (UTC)
| Time | Who (role) | Action or observation | Public reference (tx hash, receipt seq, digest) |
|---|---|---|---|

## Cause
What happened, at category level. Root cause, and why the controls did or did not stop it.

## Resolution
Runbook(s) followed; deviations from them; transactions signed; keys rotated.

## Follow-ups
| Item | Owner | Due |
|---|---|---|

## Unfreeze
Preconditions checked (RB-10): … Unfreeze receipt seq/digest: …
```

Records never contain secrets. A record that names a defect is private until the fix ships (`SECURITY.md`).

---

## 7. Drill log template

```markdown
# Drill <DR-n> — <network> — <YYYY-MM-DD>

- Drill: DR-n (<name>)      Runbook exercised: RB-…
- Guard release digest: …      Monitor release digest: …
- Clock offsets (chronyc tracking): Guard …, monitor …
- Participants (role): …

| Mark | Meaning | Value (UTC, ms) | Reference |
|---|---|---|---|
| t0 | Trigger (block time, or injection time for DR-1) | | tx hash / drill id |
| t_detect | Monitor detection | | alert id |
| t1 | Guard state-change receipt | | seq / digest |
| t2 | First refusal receipt | | seq / digest |

- Result: PASS | FAIL against the criterion in runbooks.md §4: …
- Deviations and fixes: …
- Signed: drill log SHA-256 …; signatures (namespace vaultex-drill-v1) by …
```

Signing uses the admin review credential: `ssh-keygen -Y sign -f <credential> -n vaultex-drill-v1 <log.md>` ([evidence-pack.md](evidence-pack.md) §6).
