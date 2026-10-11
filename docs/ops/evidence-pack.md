# Monthly evidence pack: format and offline verification

| | |
|---|---|
| **Version** | Format 1, 0.1-draft, 2026-10-11 |
| **Status** | **PROPOSED.** No pack has been built. The build and verify tooling is planned (`vaultex-monitor evidence build` / `evidence verify`, a WS-07 follow-up). Until it exists, §7 gives the checks that stock tools can already run. Some contents depend on Guard and receipt work that is not merged yet (§9). |
| **Covers** | The monthly evidence pack of [ROADMAP](../ROADMAP.md) M7 #8 ("a monthly evidence pack re-verified offline"), the off-host copy of the Guard's receipts, and the source of the public canary report (M7 #9). |
| **Privacy** | **Packs are private.** They hold float addresses, archived requests, recipients and approver public keys (§10). This file, which defines the format, is public. |

Vocabulary is in the [ops README](README.md) §1.

---

## 1. Purpose

A pack lets anyone with the pack, the trusted public keys from the ceremony transcript, and access to a chain-data source the monitor did not use, check **months later and offline** that for one network and one calendar month:

1. every outflow from the float matched a Guard receipt, and the Guard's receipt log is one unbroken, signed chain that continues from the previous pack;
2. every decision can be re-derived from the archived request and the policy bundle in force;
3. balances reconcile to zero residual every day, and every allowance from the float is zero (or an alert explains it);
4. every alert, freeze, drill, incident, key change, configuration change and release change in the month is recorded;
5. the hosts still meet the [baseline](host-baseline.md).

It also serves as the off-host backup of the receipt log ([RB-5](runbooks.md#rb-5-guard-host-lost-or-rebuilt)).

---

## 2. Period, naming and timing

- **One pack per network per calendar month (UTC).** The period runs from the first solidified block whose timestamp is at or after 00:00:00 UTC on the 1st, up to the last solidified block before the next period starts.
- **Directory name:** `evidence-<network-label>-<YYYY-MM>/`, for example `evidence-tron-nile-2026-12/`. The CAIP-2 network id (`tron:728126428` for mainnet, `tron:3448148188` for Nile) is inside the manifest.
- **Transport form:** a `tar` of that directory, optionally compressed. Verification always runs on the extracted directory and never trusts archive metadata.
- **Timing:** the monitor builds the pack within 5 days after the period ends (time for solidification and the last receipts). At least one admin reviews and countersigns within 10 days. ESTIMATE of size: well under 50 MB at Phase-A volume.

---

## 3. Layout

```text
evidence-<network-label>-<YYYY-MM>/
  MANIFEST.json                 what the pack contains (§4)
  MANIFEST.json.sig             monitor evidence-key signature (§6)
  MANIFEST.json.review-<n>.sig  admin countersignature(s), added after review (§6)
  summary.md                    KPIs for the month (§5.6)
  config/
    monitor.toml                monitor configuration in force at period end (holds no secret)
    changes.csv                 every monitor configuration change in the period
    adminset.bin                the admin-set file pinned at the ceremony
    allowed_signers             copy of the trusted signer keys (§6; never trusted on its own)
  receipts/
    segment.bin                 the Guard's receipt frames for the period (§5.1)
    anchors.csv                 the monitor's anchors of the receipt head
    requests/<request-id>.bin   archived request for each decision
  bundles/<version>-<digest>.bin  every policy bundle in force or offered in the period
  chain/
    outflows.csv  inflows.csv  balances.csv  allowances.csv  permissions.json
  monitor/
    alerts.csv  freezes.csv  providers.csv  latency.csv
    acks.csv                    only if the liveness lease (OD-1) is adopted
    refill-checks/*.txt         signed refill-check reports (RB-9)
  drills/<YYYY-MM-DD>-DR-<n>.md  and .sig
  incidents/<YYYY-MM-DD>-<n>.md
  host/
    <host-label>-<YYYY-MM-DD>-<check>.txt   baseline check outputs (host-baseline.md §8)
    logins.csv  releases.csv  domain-audit.txt
  replay/report.txt             output of the offline replay (§7, V-6)
```

A directory with nothing to record (no incidents this month) is omitted. Files are only ever those listed in the manifest (§4).

---

## 4. `MANIFEST.json`

UTF-8 JSON. The signatures cover the file's **exact bytes**, so a verifier hashes the file as stored and never re-serialises it.

| Field | Type | Meaning |
|---|---|---|
| `format` | string | Always `"vaultex-evidence-pack"` |
| `format_version` | integer | `1`. A change to any column list or field below bumps it |
| `network` | string | CAIP-2 network id |
| `period.start`, `period.end` | RFC 3339 UTC | The month; `end` is exclusive |
| `blocks.first`, `blocks.last` | integer | Solidified heights covered, inclusive |
| `floats` | array of strings | Float addresses (base58check) |
| `receipts.receipt_keys` | array of hex | Guard receipt public keys seen in the segment, in order of use |
| `receipts.first_seq`, `receipts.last_seq` | integer | Sequence numbers of the first and last frame in `segment.bin` |
| `receipts.head_digest` | hex | Digest of the last receipt |
| `receipts.checkpoint` | object or `null` | `{seq, digest}` of the previous pack's last receipt; `null` only for the first pack after genesis |
| `prev_manifest_sha256` | hex or `null` | SHA-256 of the previous pack's `MANIFEST.json`; `null` only for the first pack |
| `monitor.version`, `monitor.binary_sha256`, `monitor.config_sha256` | string, hex, hex | The monitor build and configuration at period end |
| `guard.release_digests` | array of hex | Every Guard binary digest that ran in the period, in order (details in `host/releases.csv`) |
| `created_at` | RFC 3339 UTC | Build time |
| `files` | array of `{path, bytes, sha256}` | **Every** file in the pack except `MANIFEST.json` and the `*.sig` files beside it, sorted by `path` (byte order) |

Example (values shortened to placeholders):

```json
{
  "format": "vaultex-evidence-pack",
  "format_version": 1,
  "network": "tron:3448148188",
  "period": { "start": "2026-12-01T00:00:00Z", "end": "2027-01-01T00:00:00Z" },
  "blocks": { "first": 1000000, "last": 1892799 },
  "floats": ["<float address>"],
  "receipts": {
    "receipt_keys": ["<32-byte hex>"],
    "first_seq": 1042,
    "last_seq": 1987,
    "head_digest": "<32-byte hex>",
    "checkpoint": { "seq": 1041, "digest": "<32-byte hex>" }
  },
  "prev_manifest_sha256": "<32-byte hex>",
  "monitor": { "version": "<semver>", "binary_sha256": "<32-byte hex>", "config_sha256": "<32-byte hex>" },
  "guard": { "release_digests": ["<32-byte hex>"] },
  "created_at": "2027-01-03T09:12:00Z",
  "files": [
    { "path": "chain/outflows.csv", "bytes": 18234, "sha256": "<32-byte hex>" },
    { "path": "receipts/segment.bin", "bytes": 401220, "sha256": "<32-byte hex>" }
  ]
}
```

---

## 5. File formats

**Conventions for every CSV:** UTF-8, LF line ends, RFC 4180 quoting, a header row with exactly the columns below in this order. Amounts are integers in the asset's base unit (sun for TRX, the token's smallest unit otherwise), never decimals. Times are Unix milliseconds UTC unless a column says seconds. Transaction ids and digests are lowercase hex. Addresses are base58check. Booleans are `true`/`false`. An empty cell means "not applicable", never zero.

### 5.1 Receipts

- **`receipts/segment.bin`:** a sequence of frames, each a 4-byte little-endian length followed by that many bytes of the canonical (BCS) encoding of one `ReceiptV1` ([`vaultex-types`](../../crates/vaultex-types/src/receipt.rs); semantics in the `RECEIPT_V1` RFC, T05-7a). Frames are in sequence order, gapless from `first_seq` to `last_seq`. The segment holds **every** receipt in the period: accepts and refusals, co-sign and shadow, and state changes.
- **`receipts/anchors.csv`:** `seq,digest,monitor_time_ms`. The monitor anchors the head at least every 60 s and at every accept. Every anchor must lie on the chain in `segment.bin` (or in an earlier pack).
- **`receipts/requests/<request-id-hex>.bin`:** the canonical bytes of the archived request for each decision, as the Guard exported them. They make replay possible (§7, V-6).

### 5.2 Policy and configuration

- **`bundles/<version>-<first 8 hex of digest>.bin`:** the canonical signed bundle bytes as installed, for every bundle in force at any time in the period or offered in it.
- **`config/changes.csv`:** `time_ms,old_sha256,new_sha256,reason,record` (the change record or incident id).
- **`config/adminset.bin`:** the admin-set file; its SHA-256 must equal the one in the ceremony transcript.

### 5.3 Chain tables

| File | Columns | Rule |
|---|---|---|
| `chain/outflows.csv` | `txid,height,block_time_ms,solidified,contract_type,token,amount,recipient,fee_sun,receipt_seq,intent_digest_ok,rules_fired` | One row per float-signed transaction and per token transfer out of the float. `receipt_seq` is empty only if `rules_fired` names the rule that fired. `token` is empty for TRX. `rules_fired` is a `;`-separated list of rule ids |
| `chain/inflows.csv` | `txid,height,block_time_ms,from,token,amount,class` | `class` is `refill`, `dust` or `other`. A `refill` row names its refill-check report in `monitor/refill-checks/` |
| `chain/balances.csv` | `date,height,asset,balance,inflows,outflows,fees,residual` | Daily at solidified height. `residual = previous balance + inflows − outflows − fees − balance` and **must be 0** |
| `chain/allowances.csv` | `date,height,token,spender_set_sha256,spender,value` | Daily reading of every spender in the watched set. Any non-zero value must have an alert |
| `chain/permissions.json` | `{expected_sha256, snapshots:[{date,height,sha256}], diffs:[{height,before,after,record}]}` | Daily digests of the account's permissions; any diff names its ceremony or incident |

### 5.4 Monitor tables

| File | Columns |
|---|---|
| `monitor/alerts.csv` | `alert_id,rule,severity,detected_at_ms,acked_at_ms,froze,resolution,record` |
| `monitor/freezes.csv` | `order_sha256,reason,trigger_block_time_ms,detected_at_ms,state_change_seq,state_change_time_s,first_refusal_seq,first_refusal_time_s,unfreeze_seq,record` |
| `monitor/providers.csv` | `provider,uptime_pct,http_429,http_403,divergences,head_lag_p95_ms` |
| `monitor/latency.csv` | `rule,count,p50_ms,p95_ms,p99_ms,max_ms` (block time to detection) |
| `monitor/acks.csv` | `lapse_start_ms,lapse_end_ms,cause` (only with OD-1) |

`monitor/refill-checks/<YYYY-MM-DD-HHMM>.txt` is the refill-check report (height, spender-set digest, values, PASS or FAIL) with its signature beside it.

### 5.5 Records and host files

- `drills/` and `incidents/`: the templates in [`runbooks.md`](runbooks.md) §6 and §7. Drill logs carry their own signatures.
- `host/<host-label>-<date>-<check>.txt`: the outputs listed in [`host-baseline.md`](host-baseline.md) §8, captured in the period.
- `host/logins.csv`: `time_ms,host,user,source,in_declared_window,record`.
- `host/releases.csv`: `time_ms,host,binary_sha256,release_ref,signature_verified`.
- `host/domain-audit.txt`: the quarterly one-line domain-audit attestation (host-baseline.md §8), or a pointer to the pack that holds the latest one.

### 5.6 `summary.md`

The month's KPIs, each computed from the tables above so a verifier can recompute it:

- outflows: count and value per asset; matched (must be all); unmatched (must be 0);
- policy bypasses (confirmed MR-04 or MR-05 findings): 0; double pays (confirmed MR-18): 0; unreconciled days (non-zero residual): 0;
- false refusals: rate and an explanation for each (M7 #5, #8);
- freezes: true and false, each with its record; freeze latency p99 and maximum; drill results;
- alerts by severity; provider health; lease-lapse minutes (OD-1);
- changes: bundles, admin set, configuration, releases, key rotations, permissions;
- open items carried to next month.

---

## 6. Signatures

ponytail: signatures use OpenSSH's file-signing format (`ssh-keygen -Y sign`, OpenSSH ≥ 8.1; FIDO2 keys from 8.2). A pack then verifies with stock tools on any machine for as long as it is kept, and admins countersign with the same kind of hardware key they use for SSH, as a separate credential. A native signer can later replace the monitor's call to `ssh-keygen` without changing the format.

| Signed object | Signer (principal) | Namespace |
|---|---|---|
| `MANIFEST.json` | Monitor evidence key (`monitor-evidence`) | `vaultex-evidence-v1` |
| `MANIFEST.json`, after review | Each reviewing admin (`admin-<n>`) | `vaultex-evidence-review-v1` |
| Refill-check reports | Monitor evidence key | `vaultex-refill-check-v1` |
| Drill logs | Admin review credential | `vaultex-drill-v1` |
| Ceremony transcripts | Admin review credential | `vaultex-ceremony-v1` |

The namespace binds each signature to its purpose, so a signature made for one purpose never verifies for another.

**Trusted keys.** The `allowed_signers` file restricts each key to its namespaces:

```text
monitor-evidence namespaces="vaultex-evidence-v1,vaultex-refill-check-v1" ssh-ed25519 AAAA…
admin-1 namespaces="vaultex-evidence-review-v1,vaultex-ceremony-v1,vaultex-drill-v1" sk-ssh-ed25519@openssh.com AAAA…
```

The **trusted** copy comes from the latest ceremony transcript (CER-3, CER-7, or a rotation ceremony), never from the pack. The pack's `config/allowed_signers` is only compared against it.

**Signing:**

```sh
# On the monitor host, by the monthly build job (writes MANIFEST.json.sig)
ssh-keygen -Y sign -f "$CREDENTIALS_DIRECTORY/evidence-key" -n vaultex-evidence-v1 MANIFEST.json

# Each reviewing admin, after the checks in §7 pass
ssh-keygen -Y sign -f ~/.ssh/vaultex_review_sk -n vaultex-evidence-review-v1 < MANIFEST.json > MANIFEST.json.review-1.sig
```

Adding a countersignature adds a file next to the manifest; it does not change `MANIFEST.json` or any listed file.

---

## 7. Offline verification

Run on any machine, in the extracted pack directory, with the trusted `allowed_signers` from the ceremony records and the previous pack's `MANIFEST.json` at hand. Every step must pass; record the result in the review record, outside the pack.

| Step | Check | How (today) |
|---|---|---|
| V-1 | Trusted keys: the pack's `config/allowed_signers` equals the trusted copy, or every difference is a rotation recorded in the transcripts | `diff` |
| V-2 | The monitor's signature, and every admin countersignature | `ssh-keygen -Y verify` (below) |
| V-3 | Every listed file exists with the listed size and SHA-256, and no unlisted file exists | `jq`, `shasum` (below) |
| V-4 | Continuity with the previous pack: `prev_manifest_sha256` is its manifest's SHA-256; `receipts.checkpoint` is its last receipt; `receipts.first_seq` is one more than its `last_seq`; `blocks.first` is one more than its `blocks.last` | `shasum`, `jq` |
| V-5 | The receipt chain: canonical decoding, signatures, sequence, previous links, key continuity, non-decreasing time, starting at the checkpoint; every anchor in `anchors.csv` lies on it | Offline receipt verifier *(planned, T05-6)* |
| V-6 | Replay: each decision re-derived from its archived request and the bundle in force gives the same decision | Offline replay *(planned, T05-6/T06-5)*; compare with `replay/report.txt` |
| V-7 | Chain re-check against a **third** data source the monitor did not use: every outflow exists at its height with its effects; daily balances and allowances match; no float-signed transaction in the period is missing from `outflows.csv` | `vaultex-monitor evidence verify --rpc <third source>` *(planned)* |
| V-8 | Table invariants: every outflow has a receipt or a fired rule; every residual is 0; every non-zero allowance and every freeze has a record; `summary.md` recomputes from the tables | `vaultex-monitor evidence verify` *(planned)* |

V-1 to V-4 work with stock tools now:

```sh
# V-2: signatures (the trusted allowed_signers lives outside the pack)
ssh-keygen -Y verify -f /path/to/trusted/allowed_signers -I monitor-evidence \
  -n vaultex-evidence-v1 -s MANIFEST.json.sig < MANIFEST.json
ssh-keygen -Y verify -f /path/to/trusted/allowed_signers -I admin-1 \
  -n vaultex-evidence-review-v1 -s MANIFEST.json.review-1.sig < MANIFEST.json

# V-3: listed files match, and nothing unlisted is present (prints nothing when clean)
jq -r '.files[] | "\(.sha256)  \(.path)"' MANIFEST.json | shasum -a 256 -c --quiet -
comm -3 <(find . -type f ! -name 'MANIFEST.json*' | sed 's|^\./||' | LC_ALL=C sort) \
        <(jq -r '.files[].path' MANIFEST.json | LC_ALL=C sort)

# V-4: link to the previous pack
shasum -a 256 /path/to/previous/MANIFEST.json   # must equal .prev_manifest_sha256
jq '.prev_manifest_sha256, .receipts.checkpoint, .receipts.first_seq, .blocks.first' MANIFEST.json
```

A pack that fails any step is an incident ([RB-1](runbooks.md#rb-1-sev-1-triage-after-an-auto-freeze) if it points to missing or altered receipts).

---

## 8. Retention and storage

- **Kept forever** (receipts must stay verifiable for as long as anyone may rely on them).
- Two offline copies at different sites, plus one encrypted off-host copy. Locations are recorded by label only.
- A pack is immutable once the monitor has signed it. Corrections go into the next pack as a record that references the earlier one.

---

## 9. Dependencies on work not merged yet

| Pack content | Needs | From |
|---|---|---|
| Receipts that say whether a decision was co-sign or shadow, and receipts for state changes (freeze, unfreeze, bundle offered or activated, key rotation) | Receipt format | T05-6 / T05-7a (WS-05, WS-03) |
| Archived requests (`receipts/requests/`) and the exported frames | Guard receipt export with a request sidecar | T06-5 (WS-06) |
| V-5, V-6 | Offline receipt verifier and replay | T05-6 |
| Chain tables, monitor tables, refill checks | Matching and alert rules | T07-3 |
| Freeze rows, drill logs | Freeze path and drills | T07-4 |
| `evidence build` / `evidence verify` | Pack tooling | WS-07 follow-up |
| Release digests and their signatures | Signed reproducible releases | T02-12 |

Until a dependency lands, its file is absent and the manifest omits it. The pack is then **partial**, and `summary.md` says so on its first line.

---

## 10. Privacy and the public canary report

- A pack is private: it holds float addresses, recipients, archived requests and approver public keys.
- The public canary report (M7 #9) is derived from `summary.md` and aggregate tables only, and contains no sensitive data. Whether it also lists the float address and transaction hashes is decision OD-6 ([README](README.md) §4).
- Incident records that describe a defect stay private until its fix ships (`SECURITY.md`).
