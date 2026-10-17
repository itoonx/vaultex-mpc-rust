# Guard key ceremonies

| | |
|---|---|
| **Version** | 0.1-draft, 2026-10-11 |
| **Status** | **PROPOSED.** No ceremony has been held. The first real ceremonies are owner work (T07-6), gated by M7 and blocked on ADR-17. Several tools they use are not built yet; they are marked *(planned)*. |
| **Covers** | Setting up the Guard line for one network (genesis: CER-0…CER-3, CER-F for the float account, then CER-4…CER-7), and the rotation and recovery ceremonies CER-R1…CER-R6 ([ROADMAP](../ROADMAP.md) M7 #4: "recorded key ceremony; encrypted Guard-key backup in 2 offline locations; restore drill; chain-native recovery drill"). |
| **Public safety** | This file is public. Transcripts are private (§5) and hold public values only. |
| **Owner** | WS-07 (R9, R2) maintains the procedure; the owner runs it. |

Vocabulary (domains, keys, float, soft and hard freeze) is in the [ops README](../ops/README.md) §1. Incident procedures that call these ceremonies are in the [runbooks](../ops/runbooks.md).

---

## 0. Preconditions

| Needed | For | State at this commit |
|---|---|---|
| Nile spike says GO (M6 #11, T06-3) | Native co-signing under the active permission. If NO-GO, the K-alt variant applies (§6) | Waiting on owner funding (T00-12) |
| ADR-17 (Guard key custody) | CER-2 | OPEN |
| ADR-11 (policy distribution) | CER-4 | OPEN |
| Guard service v0 (T06-5), admin CLIs (T05-8), monitor matching and freeze path (T07-3, T07-4) | CER-2…CER-6 | Planned |
| ADR-05 and ADR-06, the signed RF-1 memo (M7 #7), signed releases (T02-12) | **Mainnet only** | OPEN / gated |
| Host baseline applied to the Guard and monitor hosts | CER-0 | [`host-baseline.md`](../ops/host-baseline.md) |

---

## 1. Rules for every ceremony

1. **Nile first.** Every ceremony runs on Nile, then on mainnet with the same steps and the same transaction shapes. The mainnet run starts only after the Nile transcript has been reviewed.
2. **The Guard is frozen until CER-7** (if it exists yet), which unfreezes it M-of-N ([RB-10](../ops/runbooks.md#rb-10-unfreeze)) before the co-signed test. The ceremony window is declared to the monitor in advance. Owner-signed transactions carry no co-sign receipt, so they raise Sev-1 alerts by design. The alerts in the table below are expected: acknowledge each one in the transcript against its transaction id, and close it there. Any other alert, or one of these on a transaction that is not in the ceremony plan, is real: stop (rule 7) and start at [RB-0](../ops/runbooks.md#rb-0-first-response-to-any-page). In an incident or a drill, the incident record or drill log stands in for the transcript.

   | Ceremony action | Used in | Expected alerts ([runbooks](../ops/runbooks.md) §1) |
   |---|---|---|
   | Owner-signed permission update (contract type 46; at CER-5, signed by the float's original key) | CER-5, CER-R1, CER-R4; RB-3, RB-4, RB-8 | MR-01 (contract type), MR-02 (owner permission), MR-04 (no co-sign receipt), MR-14 (until the account's permissions and the expected set in `monitor.toml` agree again) |
   | Owner-signed `approve(spender, 0)` revocation | RB-2 | MR-02, MR-03 (not a plain transfer), MR-04. A zero-value `Approval` is Info, not MR-07 |
   | Owner-signed sweep to the cold treasury | RB-2, RB-3, RB-9 (excess beyond the MR-12 headroom) | MR-02, MR-04; MR-10 if it exceeds a monitor cap |
   | Guard lifecycle change the ceremony makes: bundle install or tightening, key rotation, state change | CER-4, CER-7, CER-R1…CER-R5 | MR-16 (Sev-2) |
3. **Cold devices never touch a network.** Transactions move between the networked machine and the air-gapped machine by file (removable media used only for the ceremony) or by QR code.
4. **Two tools, two machines.** Every transaction id, address and file digest is computed twice, on two machines with two independent tools, and compared before anything is signed.
5. **What may be written down:** public keys, addresses, digests, transaction ids, device labels, hashed device serial numbers, locations by label. **Never:** a private key, a seed, a passphrase or a provider key. Passphrases are not spoken aloud and never typed into a networked machine.
6. **No AI agent, no screen sharing, no cloud notes** during a ceremony. Phones stay out of the room, except a dedicated recording device.
7. **Abort rule.** Any mismatch stops the step. Record it, discard what the step produced, and restart the step from the beginning. A key is never "fixed forward".
8. **Solo mode.** With one person, separation is between devices, not people. The ceremony is filmed, and every digest that matters is read back on a second device ([threat model](../assurance/THREAT_MODEL_V2.md) LM7). A second person acts as witness whenever one is available.

---

## 2. Roles and equipment

**Roles.** *Lead* (the owner) runs the steps. *Witness* reads back every digest and initials each step; in solo mode the video and the second device stand in. *Recorder* fills the transcript; the lead may also be the recorder.

**Equipment checklist:**
- [ ] Air-gapped machine booted from an image whose digest was verified on two machines; no network hardware enabled.
- [ ] Networked machine for building unsigned transactions and broadcasting; it never holds a private key.
- [ ] Cold signing devices for the three owner keys (OD-4), tested on Nile first.
- [ ] Admin devices for the M-of-N policy admin keys, on separate devices (OD-7).
- [ ] Two hardware security keys per admin: the SSH credentials ([host baseline](../ops/host-baseline.md) HB-07) and the admin review credential, primary and backup.
- [ ] Removable media, wiped and used only for the ceremony.
- [ ] The Guard host and monitor host, built to the baseline, with the release digests verified on each host.
- [ ] Printed copy of this procedure and the transcript template (§5); recording device.
- [ ] TRX in the cold treasury to fund the float at CER-F: read chain parameters #22 (permission update, documented at 100 TRX) and #23 (multi-signature fee, documented at 1 TRX) live at CER-0. The float needs the CER-5 update plus a reserve of two more updates ([RB-3](../ops/runbooks.md#rb-3-guard-key-compromise-suspected-or-freeze-not-confirmed)).

---

## 3. Genesis ceremony (one network)

ESTIMATE: 4–6 h per network the first time, plus about 2 h of preparation. Cold-device handling takes most of it.

### CER-0. Preparation

1. Verify the Guard and monitor release signatures and digests on two machines; record both digests.
2. Read the hosts' SSH key fingerprints from the provider consoles and record them (HB-10).
3. Capture the baseline checks on both hosts ([host baseline](../ops/host-baseline.md) §8).
4. Read the live chain parameters #22 and #23 (`getchainparameters`) on both monitor providers; record values and height.
5. Declare the ceremony window to the monitor.

**Record:** release digests; host-key fingerprints; baseline output digests; chain parameters.

### CER-1. Policy admin keys

1. Each admin key (Ed25519) is generated on its own admin device with `vaultex-policy` *(planned, T05-8)*.
2. Assemble the admin-set file (M-of-N, the public keys). Compute its SHA-256 on two machines.
3. **Read the digest back out of band:** on a second device, and on video in solo mode.
4. Each admin also creates an admin review credential (FIDO2), used for signing transcripts, drill logs and evidence-pack reviews:
   `ssh-keygen -t ed25519-sk -O verify-required -O application=ssh:vaultex-review -C admin-<n> -f ~/.ssh/vaultex_review_sk`

**Record:** admin public keys; admin-set SHA-256; review-credential public keys; video SHA-256.

### CER-2. Guard key and receipt key

One Guard key per network; never reused across networks. The branch follows ADR-17.

- **(a) Encrypted key file.**
  1. Generate the key on the air-gapped machine, or on the Guard host for testnet, with the Guard's key tool *(planned, T06-5)*. The tool prints the public key and the TRON address.
  2. Derive the address again from the public key with a second, independent tool, and compare.
  3. Write two encrypted backups to two offline media, stored at **two different sites** (M7 #4). Record each backup's SHA-256 and its location label.
  4. Test one backup before use: decrypt it on the air-gapped machine and check that it yields the same address.
- **(b) Non-exportable cloud key.**
  1. In the Guard domain's own cloud account, the break-glass administrator creates a secp256k1 signing key. Its key policy lets the Guard host's role sign with this one key and nothing else; key administration stays with the break-glass principal (hardware MFA).
  2. Fetch the public key and derive the TRON address on two machines with two tools; compare.
  3. Create a **standby** key the same way. It is not registered on chain; it is what CER-R1 rotates to.
  4. There is no backup to make: recovery is the chain-native rotation, drilled as DR-7 (OD-8).
- **(c) Hardware security module.** Generate on the device; make the vendor's wrapped backup onto a second device kept at another site; derive the address on two machines.

**Receipt key (Ed25519).** Created by the Guard's key tool, or in the cloud key service if ADR-17 says so. With file custody it is sealed on the Guard host ([host baseline](../ops/host-baseline.md) HB-18). Its public key goes into the transcript and into every evidence pack.

**Record:** Guard address and public key per network; receipt public key; backup digests and location labels (a), or key ids kept private and the standby key's address (b).

### CER-3. Monitor keys

On the monitor host:
1. Generate the **freeze key** and, if OD-1 is adopted, the **ack key** (Ed25519). Seal both with `systemd-creds` (HB-18; OD-3).
2. Generate the **evidence key** as an OpenSSH Ed25519 key and seal it the same way:
   `ssh-keygen -t ed25519 -N '' -C monitor-evidence -f /run/vx-ceremony/evidence-key` (in a RAM-backed directory, sealed, then deleted).
3. Write the trusted `allowed_signers` file: the monitor evidence key and every admin review credential, each restricted to its namespaces ([evidence-pack.md](../ops/evidence-pack.md) §6). Compute its SHA-256.

**Record:** freeze, ack and evidence public keys; `allowed_signers` SHA-256.

### CER-F. Float account (genesis only)

A new TRON account's owner and active permissions each hold only the account's own key, at threshold 1, so that key controls the float until the CER-5 update lands. It is therefore made on the air-gapped machine, signs exactly one transaction (CER-5), and is destroyed after the CER-6 read-back. CER-4 needs the float's address, so this step comes first.

1. On the air-gapped machine, generate the float account key (secp256k1) in a RAM-backed directory, and keep that machine powered on until CER-6. The key is never written to disk or to removable media and has no backup. If the session breaks before CER-5 lands, the key is gone: abandon that account (the loss is its fee TRX) and repeat genesis from this step.
2. Derive the float address from the public key with two independent tools, on two machines (rule 4), and compare. Only the public key and the address leave the air-gapped machine.
3. Activate and fund the float with one TRX transfer from the cold treasury, after checking the destination on the networked machine against step 2. Send enough for the CER-5 update (#22; it carries one signature) plus the two-update reserve that must remain after it (#22 + #23 each; [RB-3](../ops/runbooks.md#rb-3-guard-key-compromise-suspected-or-freeze-not-confirmed) step 1): at the documented values, 302 TRX plus a margin for bandwidth. This is genesis funding, not a refill: the float is not yet in `monitor.toml` (CER-4). Nothing else goes to the float until the original key is destroyed (CER-6); its working balance comes later by refill ([RB-9](../ops/runbooks.md#rb-9-refill)).
4. Read the account back on both monitor providers: it exists, its balance is what was sent, and its permissions name only the float's own key.

**Record:** the float address and both tools' outputs; the funding transaction id; the read-back; the original key's label (never the key).

### CER-4. Genesis policy bundle and configuration

1. Build the genesis bundle with `vaultex-policy` *(planned, T05-8)*:
   - freeze keys: the monitor's freeze key (admins can always freeze);
   - caps: the Phase caps, at or under ROADMAP §3.4 and the owner's written loss budget;
   - destinations: the allowlist (OD-2), which includes the cold treasury so that an excess can be swept back by a normal co-signed transfer (MR-12);
   - tokens: each one through the token onboarding checklist ([runbooks](../ops/runbooks.md) §5);
   - the Guard key's address and the configured active permission id.
2. M admins sign it. Install it **locally** on the Guard host, together with the admin-set file.
3. Write `monitor.toml`: network and float address, token allowlist, the monitor's own caps (the written loss budget, not the bundle's), the float ceiling and its headroom per asset (MR-12; for TRX, the ceiling minus its headroom covers the CER-F reserve, so refills can restore it), the destination allowlist, the **expected permission set** (CER-5), the Guard's receipt public key, certificate pin and endpoint, the pinned Guard release digest, the cold treasury address, the provider endpoints (never their keys), and alert routing.
4. Write `guard.toml` *(planned, T06-5)*. Neither file holds a secret value.

**Record:** SHA-256 of the bundle, the admin set, `monitor.toml` and `guard.toml`.

### CER-5. Account permissions

1. On the networked machine, build the unsigned permission update for the float:
   - **owner** permission: threshold 2; the three owner keys, weight 1 each;
   - **active** permission, id 2: threshold 2; the operator key and the Guard key, weight 1 each; operations = TRX transfer (contract type 1) and smart-contract call (type 31) only. The 32-byte operations value is `0200008000000000000000000000000000000000000000000000000000000000`. Bit 46 (permission update) is **clear**, so the active permission can never rewrite permissions;
   - no other active permission (on mainnet);
   - the float's original key (CER-F) in **no** permission.
2. Compare the unsigned JSON with the reviewed expected set field by field (keys, weights, thresholds, operations). In solo mode, a second reading on video.
3. Move it to the air-gapped machine. Compute the transaction id with two independent tools and compare.
4. Sign.
   - **At genesis**, the update is signed by the float's original key alone, on the air-gapped machine. Until it lands, that key is the account's only owner key, so the owner devices cannot sign it.
   - **Later updates** (CER-R1, CER-R4; RB-3, RB-4, RB-8) are signed by two of the three owner devices. Each device's screen must show the same transaction id, or the fields of the update. If the device can only sign the hash of a permission update (blind signing), step 3 is the only check: do it twice, and switch that device setting off again after the ceremony.
5. Broadcast from the networked machine.

**Record:** transaction id; the expected-permission JSON's SHA-256; both tool outputs; which keys signed, by label (the float's original key at genesis, owner devices after).

### CER-6. Read-back and chain checks

The Guard is still frozen, so nothing here goes through it.

1. Read the account's permissions on both monitor providers and compare them with the expected set. At genesis, also check that the float's original key is in **no** permission. The monitor reports MR-14 clear.
2. **Genesis only:** destroy the float's original key, and only after step 1 passes; until then it is the one key that can correct the account (rule 7). Delete it and power the air-gapped machine off; it existed only in RAM (CER-F). Record the destruction in the transcript by the key's label, with the method, the time and the witness's initials.
3. On **Nile**, two checks that the chain itself enforces:
   - a transaction with only the operator's signature must be rejected by the chain;
   - a permission update signed under the active permission must be rejected by the chain.
4. Capture the baseline checks again on both hosts.
5. Check that every alert the ceremony raised is in the rule-2 table (§1) and closed in the transcript.

A frozen Guard refuses co-signing with `FROZEN`, so the co-signed test transfer comes after the unfreeze (CER-7 step 3).

**Record:** monitor read-back report; at genesis, the original key's destruction (label, method, time); the rejection messages; the alert ids and how each was closed.

### CER-7. Unfreeze, test and close

1. Unfreeze: M admins sign, submitted locally on the Guard host ([RB-10](../ops/runbooks.md#rb-10-unfreeze)).
2. Close the declared ceremony window, so that any alert from here on is real.
3. **Post-unfreeze test.** On **Nile**: one co-signed test transfer through the full path (operator submitter → Guard → chain), matched by the monitor with no alert. On **mainnet**: the first payout after the unfreeze is the test, with the monitor watching; at genesis that is the first Phase-A payout, an owner action under RF-1. If the test fails, any admin re-freezes at once and the failure goes to [RB-1](../ops/runbooks.md#rb-1-sev-1-triage-after-an-auto-freeze); the ceremony is not complete.
4. Complete the transcript. Compute its SHA-256. M admins sign it with their review credentials:
   `ssh-keygen -Y sign -f ~/.ssh/vaultex_review_sk -n vaultex-ceremony-v1 < transcript.md > transcript.md.admin-<n>.sig`
5. Store the transcript, its signatures and the video digest in the private evidence store. They go into the next evidence pack.
6. The public parts (public keys, transaction ids) may appear in the canary report if OD-6 allows.

**Record:** the unfreeze receipt (sequence number and digest); the test transaction id and its receipt.

---

## 4. Rotation and recovery ceremonies

Each one follows §1 and §2, runs on Nile first (with the same JSON shape), and ends with CER-6 (read-back and chain checks, Guard still frozen) and CER-7 (unfreeze, then the co-signed test, then close).

### CER-R1. Guard key rotation

Used for scheduled rotation, by [RB-3](../ops/runbooks.md#rb-3-guard-key-compromise-suspected-or-freeze-not-confirmed), and as drill DR-7 (M7 #4 chain-native recovery; on mainnet, M7 #8).

1. Freeze the Guard.
2. Make the new key per the CER-2 branch, or use the standby key (b), and derive its address on two machines.
3. Build a permission update that replaces the old Guard key with the new one in active permission 2 and changes **nothing else**. Review it as a diff against the current expected set.
4. Sign with two owner devices (CER-5 steps 3–5) and broadcast.
5. Update the expected permission set in `monitor.toml` and the Guard's configuration (both are recorded changes); restart the Guard frozen.
6. Read back (CER-6). On Nile, also show that a co-signature by the **old** key is now rejected by the chain. That signature is made with the old key's own custody tool (key tool or key service), not through the Guard, and before step 7 retires the key.
7. Retire the old key: file custody, crypto-shred both backups and record it by location label; cloud custody, disable the key now and schedule its deletion after 30 days; for (b), create a new standby key.
8. Unfreeze, test and close (CER-7).

### CER-R2. Receipt key rotation

1. **Old key trusted** (scheduled rotation): the Guard records the rotation in a receipt signed by the old key (semantics: `RECEIPT_V1`, T05-6/T05-7a). The new public key goes into the transcript and `monitor.toml`.
2. **Old key not trusted** (host compromise): make a new key. The transcript names the **re-anchor point**: the last receipt the monitor anchored before the compromise window. Receipts after that point under the old key are evidence of the incident, not of decisions.

### CER-R3. Monitor key rotation

1. **Freeze key:** make the new key (CER-3). Add it to the bundle's freeze keys with a tightening bundle (one admin while no loosening is pending, otherwise M-of-N; takes effect at once). Confirm the Guard accepts a freeze from it: on Nile, after CER-7, run drill DR-1 ([runbooks](../ops/runbooks.md) §4), whose freeze is now signed by the new key; it must pass. Then remove the old key with a loosening bundle (M-of-N; time-locked).
2. **Evidence key:** make a new key; publish the new `allowed_signers` in a transcript. Packs signed before the change keep verifying against the transcript that was current when they were signed.
3. **Ack key** (OD-1): make a new key and install its public key in the Guard's configuration.

### CER-R4. Owner key replacement

Used by [RB-8](../ops/runbooks.md#rb-8-owner-key-lost-or-compromised).

1. Prepare the replacement cold device and key; record its address.
2. Build a permission update that replaces only the lost key in the owner permission. Rehearse it on Nile with the same JSON shape.
3. The two remaining owner keys sign it (CER-5 steps 3–5).
4. Read back; update the expected permission set.

### CER-R5. Admin key replacement

Used by [RB-13](../ops/runbooks.md#rb-13-policy-admin-key-lost-or-compromised).

1. Run CER-1 for the new key and assemble the new admin-set file; read its digest back out of band.
2. Install the new admin-set file **locally** on the Guard host, and re-sign the bundle in force if the bundle format requires it (`POLICY_BUNDLE_V1`, T05-7b).
3. Update the trusted `allowed_signers` if the admin's review credential also changed.

### CER-R6. Host rebuild

A rebuilt Guard or monitor host is not a key ceremony, but it is recorded like one: [RB-5](../ops/runbooks.md#rb-5-guard-host-lost-or-rebuilt) and [RB-6](../ops/runbooks.md#rb-6-monitor-host-lost), with CER-0 steps 1–3, CER-6, and the unfreeze before the co-signed test as in CER-7.

---

## 5. Transcript template

```markdown
# Ceremony transcript CT-<YYYYMMDD>-<n>: <CER ids> — <network> — <YYYY-MM-DD>

- Network: tron:<id>        Float: <label in any copy that may become public>
- Participants (role: label): Lead …; Witness …; Recorder …
- Window declared to the monitor: <start>–<end> UTC
- Releases: vaultex-guard <version> sha256 …; vaultex-monitor <version> sha256 …
  signature verified on: <machine label 1>, <machine label 2>
- Chain parameters at height …: #22 = … sun; #23 = … sun
- Devices (label: SHA-256 of serial number): …
- Video: SHA-256 …

## Steps
| Step | Time (UTC) | Action | Output (public values only) | Check (two tools / read-back) | Initials |
|---|---|---|---|---|---|

## Public keys and addresses
| Key | Type | Public key or address | Derived on (two machines) |
|---|---|---|---|
| float account key (genesis only) | secp256k1 | float address | |

## Keys destroyed or retired
| Key (label) | Public key or address | Method (and medium or location label) | Time (UTC) | Initials |
|---|---|---|---|---|
| float original key (genesis only; after the CER-6 read-back) | | | | |

## File digests
| File | SHA-256 | Computed on (two machines) |
|---|---|---|
| admin set | | |
| genesis bundle | | |
| guard.toml / monitor.toml | | |
| expected permission set | | |
| allowed_signers | | |

## Backups (file custody only)
| Backup | SHA-256 | Location label | Restore-tested |
|---|---|---|---|

## Transactions
| Purpose | Transaction id | Height | Result |
|---|---|---|---|

## Deviations
What differed from docs/ceremonies/guard.md, and why.

## Sign-off
Transcript SHA-256: …
Signatures: transcript.md.admin-<n>.sig (namespace vaultex-ceremony-v1)
```

---

## 6. K-alt variant

If the Nile spike is NO-GO, the Guard holds no chain key and returns a signed decision instead, which the operator's own signer must verify before it signs ([threat model](../assurance/THREAT_MODEL_V2.md) §3.2, LM10). The ceremonies then change as follows: CER-2 makes only the receipt key; CER-F is unchanged; CER-5, still signed at genesis by the float's original key alone, puts only the operator key in the active permission, still without the permission-update bit, and CER-6 still checks that the original key is in no permission before destroying it; the operator's signer pins the Guard's receipt public key, recorded in the transcript; and CER-R1 rotates the operator's pin instead of an on-chain key. This file will be revised in full if K-alt is adopted.
