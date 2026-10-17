# Vaultex Task Backlog: executable plan for `docs/ROADMAP.md`

| | |
|---|---|
| **Date** | 2026-10-09. Week numbers follow ROADMAP (wk 0 = Mon 2026-10-12). |
| **Source** | `docs/ROADMAP.md` §4 (milestones M5–M13), §5 (workstreams WS-01..17), §7 (first six weeks), §11 (ADRs). |
| **Purpose** | Every task in one place, so that a long unattended run can execute all **READY** work in parallel and skip anything that waits for the owner. |
| **Public safety** | This file is public-safe. Vulnerabilities appear by category only. Owner-private tasks (Track 0) and private decisions live in `~/vaultex-private/TASKS_PRIVATE.md`. |

---

## 1. How to read this file

**Status**:
- **READY**: an agent can run it now.
- **WAIT:Txx-n**: waits on another task, and becomes READY when that task is merged.
- **BLOCKED:ID**: waits on an owner answer in the Decision Inbox (§3). The run **skips** it.
- **OWNER**: a human-only action: external contact, GitHub settings, funds, hiring or legal. Agents may prepare drafts.
- **GATED:X**: waits on a roadmap gate (G-MPC, D1, M7, M9, M10…). It is decomposed further when the gate opens.

**Mode**:
- **R**: research/design. Writes only to `$OUT = ~/vaultex-private/research-2026-10/round3/`, never to the repo.
- **A**: agent code/docs change in the repo, on the workstream's branch, with tests.
- **A→O**: the agent drafts, and the owner executes or publishes.
- **O**: owner only.

**Size** (ESTIMATE, one agent + review): **S** ≤ 2 days · **M** ≤ 1 week · **L** ≤ 3 weeks.

A task may carry several conditions. It runs only when **all** of them are cleared.

---

## 2. Run protocol for long unattended runs

These are the defaults chosen so that **nothing irreversible or outward-facing happens without the owner**. Change them via Q-RUN-1..5 (§3).

1. **Branches.**
   - Each workstream (WS) gets one worktree and one branch, `ws/<WS>-<slug>`, cut from the local integration branch **`integration/phase1`** (created from `dev` HEAD at run start).
   - Tasks inside a WS run **sequentially** on that branch. Workstreams run **in parallel**.
   - Research tasks (mode R) do not touch the repo, so they can all run at once.
2. **File ownership.**
   - An agent edits only the paths its WS owns (ROADMAP §5.2 and the shared-file table in §5.0).
   - A change needed elsewhere becomes a note in the run log for the owning WS.
   - Workspace `Cargo.toml` belongs to WS-03. `Cargo.lock` is regenerated only by the orchestrator at merge time.
3. **Every code task**, before it is called done:
   - `cargo fmt --all`;
   - `cargo clippy --workspace --all-targets -- -D warnings`;
   - targeted tests, then `cargo test --workspace --features local-transport -- --test-threads=4`;
   - a checkpoint commit `[R<n>][T<id>] <what> — tests pass`, with the Co-Authored-By trailer;
   - fragments only: `claims/<ws>/*.toml`, `changelog.d/<ws>-*.md`, `status/<ws>.toml`.
   - Never skip ZK or crypto checks in tests, and never inflate timeouts to hide slowness.
   - **CPU budget (the owner's laptop overheated on 2026-10-10):**
     - Run every cargo command as `CARGO_BUILD_JOBS=4 taskpolicy -b cargo …`.
     - Allow at most one cargo build or test at a time across all agents.
     - Research and review agents never compile.
     - Always use the same flags (`--workspace --features local-transport`) so the cache is reused. Switching to `-p` rebuilds about 160 crates.
4. **Merge gate into `integration/phase1`** (run by the orchestrator, never by the task agent):
   1. Re-run fmt, clippy and test **at the repo root** after merging; never trust agent-reported results.
   2. `/simplify` pass.
   3. An R6 review agent on any path touching crypto, transport, node, gateway, kernel or CI.
   4. On failure: fix or revert, and log it.
5. **Never, during the run:**
   - push, publish, tag remotely, open PRs or issues, or change GitHub settings;
   - contact any third party, or use a browser or desktop automation (WebSearch/WebFetch only, and never sec.or.th);
   - move funds or broadcast any mainnet transaction. Testnet broadcasts are allowed only in tasks marked for them, and only after the owner has funded the account;
   - read, print or copy secrets or keystore passwords;
   - touch sibling projects (CRM etc.);
   - delete keystores;
   - install global tools (Q-RUN-2);
   - add a crate that is not already in `Cargo.lock` (list it in the run log for approval);
   - merge into `dev` or `main` (Q-RUN-1).
6. **Skipping.** BLOCKED, OWNER and GATED tasks are skipped. Each skip, with its blocking ID, goes to the run log. When a run reaches a point where only blocked work remains, it stops and reports.
7. **Logs and outputs.**
   - Run log: `~/vaultex-private/runs/<date>/RUN_LOG.md` (private).
   - Research outputs: `$OUT`.
   - After each wave, an R10 Scribe pass renders fragments.
   - Update the agent scorecard (`AGENT_BACKLOG.md` in memory) per task.
8. **Every research prompt** is prefixed with the standard preamble in ROADMAP §5.0, item 5, and uses the WS deep-dive prompt in ROADMAP §5.2.

---

## 3. Decision Inbox (owner answers; the run skips anything that depends on these)

Answer in any form, for example "ADR-03: delete". Each row lists the tasks it unblocks. Recommendations come from ROADMAP §11, or are new and marked ★.

| ID | Question | Options | Recommendation | Unblocks | By | Owner answer (2026-10-16) |
|---|---|---|---|---|---|---|
| **ADR-01** | Capacity scenario | (a) solo + agents · (b) + contract applied cryptographer · (c) team of 3 | (b) at minimum | T00-17, G-MPC path, T12-2 | Day 14 | (b) + contract applied cryptographer |
| **ADR-02** | Licence | MIT OR Apache-2.0 · Apache-2.0 · AGPL/BSL | MIT OR Apache-2.0 + NOTICE, after author consent (T00-5) | T01-5, T01-11b | Day 3 | MIT OR Apache-2.0 + NOTICE (after T00-5) |
| **ADR-03** | Legacy hand-rolled crypto | Delete · Quarantine | Delete in M5 (after pre-cut tag, balance check, crypto-shred) | T04-6, T04-7, T04-8, T14-3 | Day 7 | Delete in M5 |
| **ADR-04** | v1 support matrix | TRON-only · TRON + EVM · multi-chain · FROST/Solana first | TRON (TRX + TRC-20) on pinned `cggmp24`; others quarantined | T04-7, scope of WS-05 beyond TRON | Day 7 | TRON on `cggmp24`, confirmed with changes after the TKeeper teardown (2026-10-17) |
| **ADR-05** | Real-funds rule | RF-1..RF-4 · audit before any funds · other | Adopt RF-1..RF-4 | T06-8, M7 Rung 2 | Day 7 | Adopt RF-1..RF-4 |
| **ADR-06** | First-funds host for Rung 2 | Project-owned float · other float with counsel clearance · none until audit | Project-owned float | T06-8, M7 Rung 2 | Day 7 | Project-owned float |
| **ADR-07** | MPC engine swap | Always · conditional on G-MPC · never (kernel-only) | Conditional on G-MPC | T03-4, T08-2, T09-2, T10-2 | wk 16 | Conditional on G-MPC |
| **ADR-08** | Audit sourcing and timing | Book now with deposit · RFQ now, pay on commitment · none | RFQ now; pay on a committed user; split firms | T00-13, T14-5 | wk 2 | RFQ now, no deposit |
| **ADR-09** | Gateway authentication | Keep custom handshake · quarantine · replace | Replace with rustls mTLS + node-verified signatures | T11-2 | G-MPC | Replace (rustls mTLS + node-verified signatures) |
| **ADR-10** | Gateway persistence | Postgres · SQLite cache · nodes as source of truth | Nodes as source of truth | T10-2, T11-2 | G-MPC | Nodes as source of truth |
| **ADR-11** | Policy distribution | Unsigned static file · quorum-signed bundle file · remote governance service | Quorum-signed bundle installed per signer as a file | T05-3, T05-4, T05-7b, T05-8, T06-5 | ≈ wk 5 (M6 start) | Quorum-signed bundle file per signer |
| **ADR-12** | Name and crate prefix | Keep "Vaultex" · rename | Decide after the desk search (T17-2); crate names stay working names until then | crate rename/publish, entity | Day 30 | Rename now (name to be chosen) |
| **ADR-13** | Disclosure posture | Category GHSA now · full advisory now · silence | Category-level GHSA now | T00-9, T00-10 | Day 7 | Category-level GHSA now |
| **ADR-14** | Callback-adapter vendor | Fireblocks · Cobo · none | Only the vendor D1 names | T16-1 | After D1 | Only the vendor D1 names |
| **ADR-15** | Decoder diversity | One kernel decoder · a second independent decoder at ≥ 1 node | Cost it during WS-05 design | second decoder | Before M10-F freeze | D0 at M6; D1 decided before M10-F |
| **ADR-16** | Status and IDs | Hand-edited docs · CI-generated status + GitHub issue IDs | CI-generated status; issue numbers as IDs | T02-8, final ADR file names | M5 | CI-generated status + issue IDs |
| **ADR-17** ★ | Guard key custody for Rung 2 | Cloud-KMS secp256k1 · HSM · encrypted passphrase file | Decide after T06-1 costs the options | T06-5, T07-6 | Before M7 | TPM-sealed key file (testnet); non-exportable AWS KMS key (mainnet Rung 2) |
| **D-AGENTS** ★ | Remove vendored `.agents/**` (74 files) + `skills-lock.json` from the repo? They may be part of your local agent setup | Remove · keep (and document licences) | Remove from the repo; keep a local copy outside git if you use them | T01-6 | With ADR-02 | Remove from the repo (local copy kept) |
| **D-RETRO** ★ | Which accounts may Rung-0 retro-shadow analyse? | Project-owned only · plus your own business accounts (results private) · none yet | Your call; raw data stays private either way | T06-4 | Before M6 | Project-owned accounts only |
| **Q-RUN-1** ★ | Where may the long run land work? | Local `integration/phase1` only (default) · also merge to `dev` after gates · also push | Default: local integration branch, no push | all merges | Any time | Merge to `dev` and push after the gates; `main` only by PR with owner approval |
| **Q-RUN-2** ★ | May the run install dev tools? (`cargo-deny`, `cargo-vet`, `cargo-mutants`, `cargo-fuzz` + nightly toolchain) | Yes · CI-only checks (default) | Yes (needed for M6 evidence) | T05-10, local runs of T02-4/T02-11 checks | Any time | Yes |
| **Q-RUN-3** ★ | Compute budget for fuzzing on this machine (M6 asks ≥ 24 CPU-h per decoder) | Smoke only (default, ≤ 15 min) · full campaign locally · cloud box | Full campaign, overnight | T05-10 | Before M6 exit | Cloud box, about 40 CPU-h |
| **Q-RUN-4** ★ | CODEOWNERS handle(s): which GitHub account(s) are yours? | — | — | final value in T02-10 (draft uses `@OWNER`) | Day 1 | @itoonx |
| **Q-RUN-5** ★ | New crates not yet in `Cargo.lock`: approve per request | Approve list · deny | Reviewed per request in the run log | any task the run log lists as dep-blocked | Rolling | Approved: async-nats 0.47 (+ tokio-stream), libfuzzer-sys + arbitrary (fuzz workspace only), prometheus without default features; advisory and licence exceptions signed off |

Answered in the Claude Code session of 2026-10-16. Accepted ADRs quote the answers in `docs/adr/`; ADR-04 was confirmed with changes on 2026-10-17, after the TKeeper teardown.

Other decisions from the same session:
- Competitor watch DN-1 (TKeeper vs kill criterion K9): an agent does a teardown of at most 1 day (code reading, no build) before ADR-04 is confirmed.
- Kernel defaults: refuse native TRX amounts above 2^53−1 sun; the Guard co-signs only while the monitor heartbeat is fresh (TH45); velocity bound rounded up, with the tighter WS-05 bound once R1 has proved it; signed encoding BCS + tagged SHA-256, never JSON.
- Legacy docs: remove `docs/SECURITY_FINDINGS.md`, `docs/CVE_SECURITY_REPORT.md` and `docs/CVE_2025_66016_VERIFICATION.md` from the tree (git history keeps them); `retro/**` stays in place with banners.
- T13-1: rerun with a narrowed scope (oracle, CI and process design only).
- Monitor providers: keyless public providers on testnet; choose providers and create keys before Rung 2.
- T00-8 canary PR: the orchestrator may push a throwaway branch and open, then close, the canary PR.

Answered 2026-10-17 (ADR-11 follow-ups, recorded in `docs/adr/ADR-11-policy-distribution.md`):
- While a loosening is pending, any bundle that supersedes it needs M-of-N.
- Versions in `(h, h+K]` with K = 16 (provisional), ordered by the parent-digest link; loosening time lock capped at 30 days.
- 2026-10-18: an M-of-N bundle anchors to the last M-of-N bundle and is not held to the version window.

Private decisions (business and owner-only, D-1..D-11) are in the private task list.

---

## 4. Wave plan (what the run does, in order)

```
Wave 1 (start immediately, all parallel)
  Research pool (mode R, 18 tasks): T01-1 T02-1 T03-1 T04-1 T05-1 T06-1 T07-1 T08-1 T09-1 T10-1
                                    T11-1 T12-1 T13-1 T14-1 T15-1 T15-2 T17-1 T17-2
  WS-01 lane: T01-2 → T01-3 → T01-4 → T01-11a
  WS-02 lane: T02-2 → T02-3 → T02-4 → T02-6 → T02-9 → T02-10 → T02-11
  WS-03 lane: T03-2
  WS-04 lane: T04-2 → T04-3 → T04-4 → T04-5
Wave 2 (as their dependencies merge)
  WS-01: T01-7 → T01-8 → T01-9 → T01-10      (after T01-1)
  WS-02: T02-5 (after T04-3) · T02-7 (after T01-7)
  WS-03: T03-3 scaffolding + vaultex-types v0   (after T03-1, T02-4)
  WS-13: T13-3 incident catalogue               (after T13-1)
  WS-14: T14-2 threat model v2                  (after T14-1, T05-1)
  WS-06: T06-2 Nile spike script                (after T06-1) → stops at OWNER funding (T00-12)
Wave 3 (after T03-3)
  WS-05: T05-2 → T05-5 → T05-6 → T05-7a → T05-9
  WS-07: T07-2 → T07-5 → T07-3
  WS-13: T13-2 JS oracle                        (after T05-7a; different agent from WS-05)
  WS-14: T14-4 known-issues + KAT plan          (after T14-2)
Then the run stops and reports: the remaining work is BLOCKED (Decision Inbox), OWNER or GATED.
```

**Run 2026-10-11:** waves 1–3 ran in full. All 34 code tasks were merged to `dev` on 2026-10-13, after a branch-level R6 review whose fixes were also merged. 19 of 20 research outputs were written; T13-1 needs a narrower scope before it is rerun.

**Wave 4 candidates.** These are requests the agents raised during that run. None needs an owner decision; R7 assigns IDs before the next run.
- WS-03: `publish = false` on every workspace crate; `rust-version.workspace = true` in member manifests; `docs/rfcs/registries.md` (ChainId, NetworkId, RefusalCode and domain-tag registries).
- WS-02: CI jobs for `cargo-deny`/`cargo-vet`, `infra/node/test-node-wrapper.sh`, the kernel `crash-kill9` tests (Linux) and the tronweb differential (Node 20). The shipped-build guard should read the Dockerfile's build line instead of its own copy.
- WS-12: `--locked` in the Dockerfile build.
- WS-04: rename or remove the gateway's stub `aws-kms` feature; quarantine feature gates on the legacy core modules; put the single-process CLI behind a non-default feature.
- WS-13: a tronweb vector with `permissionId: 2`; a narrowed T13-1 (oracle, CI and process design only).
- WS-01: link `docs/assurance/THREAT_MODEL_V2.md` from `SECURITY_STATUS.md`; claims rule R9 compares bytes.

**Run 2026-10-16/17 (wave 4):** T01-13, T02-4b, T05-2b, T05-3 and T09-F1 were merged after root checks and branch-level security and public-safety reviews; MEDIUM findings were fixed before the merge. Research DN-1 (TKeeper teardown), T00-19 name candidates and T13-1 (narrowed) were written to the private archive.

**Wave 5 candidates** (from that run; R7 assigns IDs):
- WS-13 + WS-05: the JS oracle implements the native-amount bound, then the INTENT_V1 vector file is regenerated in the same merge; a Rust test that reads the INTENT_V1 vector file; a CI job that runs the oracle on a supported Node LTS; CODEOWNERS for `scripts/oracle/` and `specs/`.
- WS-05: T05-7b RFC with the policy-bundle open points; re-verify the active bundle on load and write install receipts; clock-rollback handling for the effective bundle.
- WS-03: a dedicated amount-bound refusal code; a receipt kind for bundle installs; widen the `BUNDLE_INVALID` description.
- WS-09: async-nats without default features; a test for ignoring cluster-advertised servers; an availability check of system-certificate loading.
- WS-14: a known-issues row for host-level tampering with the installed policy file; align the threat model with the bundle's version and parent rules.
- WS-01: link the archived auth review directly and delete its redirect stub.
- WS-02: `sloc.py` counts inline test modules as production code; allowlist the TLS test fixtures when a secret scanner lands.

ESTIMATE: Waves 1–3 ≈ 12–16 agent-weeks of work. Review load for the owner is in ROADMAP §4.2 and §7.

---

## 5. Task index

| ID | Title | WS | M | Mode | Status | Size |
|---|---|---|---|---|---|---|
| T00-1 | Track 0: owner prerequisites (private checklist) | — | — | O | OWNER | — |
| T00-2 | D0 founder check of "no customer contact" | 15 | D0 | O | OWNER | S |
| T00-3 | Enable private vulnerability reporting; prove the contact channel | 01 | M5 | O | OWNER (after T01-3) | S |
| T00-4 | Branch protection, machine account for agents, hardware-key 2FA | 02 | M5 | O | OWNER | S |
| T00-5 | Licence consent from all author identities (or day-30 fallback) | 01 | M5 | O | OWNER | S |
| T00-6 | Decision day: answer the Decision Inbox | — | M5 | O | OWNER | S |
| T00-7 | Capacity log + day-14 gate (ADR-01) | — | M5 | O | OWNER | S |
| T00-8 | Push the integration work; verify the CI canary turns red, then main green | 02 | M5 | O | OWNER · push done 2026-10-13; canary red on push and PR runs 2026-10-16 (#26, runs 38825841936 and 38825847332); main green waits for a dev→main PR, which first needs main's release squash recorded in dev history | S |
| T00-9 | Publish the category-level GHSA | 01 | M5 | O | OWNER (ready) | S |
| T00-10 | Notify the fork owners privately (list in private notes) | 01 | M5 | O | OWNER · WAIT:T00-9 | S |
| T00-11 | Crypto-shred legacy testnet shares; optional sweep to plain testnet wallets | 04 | M5 | O | OWNER · WAIT:T04-1 (runbook) | S |
| T00-12 | Fund the Nile spike accounts from a faucet | 06 | M6 | O | OWNER (T06-2 done) | S |
| T00-13 | Send RFQs (no deposit) | 14 | M10 | O | OWNER (ready) | S |
| T00-14 | Upstream asks: Lockness delta review / co-funding; ZF FROST audit status; OSTIF intake | 14 | M10 | O | OWNER (ready) | S |
| T00-15 | Counsel quotes for the three roadmap §3.7 questions | 17 | — | O | OWNER (ready) | S |
| T00-16 | D1 interviews (≥ 12 + ≥ 3 integrators), then D2 LOI | 15 | D1/D2 | O | OWNER (ready) | L |
| T00-17 | Engage the contract applied cryptographer; find a second operator | 17 | G-MPC | O | OWNER (ready) | L |
| T00-18 | Agent-process hygiene (private notes §3.2); encrypt the private research archive | — | M5 | O | OWNER | S |
| T00-19 | Name decision (ADR-12) | 17 | — | O | OWNER (ready; candidate names drafted 2026-10-17, private) | S |
| T01-1 | Deep-dive: truth infrastructure, claims inventory, docs to archive vs rewrite | 01 | M5 | R | DONE 2026-10-11 | M |
| T01-2 | README truth banner (canonical M5 #1 text) + support matrix + overclaim removal, EN + zh-CN | 01 | M5 | A | DONE 2026-10-11 | S |
| T01-3 | One security policy (`SECURITY.md`): supported versions, 90-day disclosure; `SECURITY_STATUS.md` (category + fix) | 01 | M5 | A | DONE 2026-10-11 | S |
| T01-4 | Draft the category-level GHSA text with re-key guidance (private draft) | 01 | M5 | A→O | DONE 2026-10-11 | S |
| T01-5 | `LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE`; manifests `MIT OR Apache-2.0` | 01 | M5 | A | WAIT:T00-5 | S |
| T01-6 | Remove `.agents/**` and `skills-lock.json` | 01 | M5 | A | DONE 2026-10-16 | S |
| T01-7 | Claims ledger: `claims/schema.toml`, per-WS fragments, rendered `CLAIMS.md` | 01 | M5 | A | DONE 2026-10-11 | M |
| T01-8 | Archive stale planning docs with a "superseded" banner; publish the M1–M4 re-baseline | 01 | M5 | A | DONE 2026-10-11 | S |
| T01-9 | Slim `CLAUDE.md` to stable agent rules (history → archive) | 01 | M5 | A | DONE 2026-10-11 | S |
| T01-10 | Role charters (ROADMAP §9.1): `docs/AGENTS.md` + `.claude/agents/*`; track the R8–R10 files | 01 | M5 | A | DONE 2026-10-11 | S |
| T01-11a | `CODE_OF_CONDUCT.md` | 01 | M5 | A | DONE 2026-10-11 | S |
| T01-11b | `CONTRIBUTING.md` (DCO vs CLA) | 01 | M5 | A | DONE 2026-10-18 | S |
| T01-12 | `GOVERNANCE.md` + docs site | 01 | M13 | A | GATED:M13 | M |
| T01-13 | Remove the three legacy security docs from the tree (git history keeps them) | 01 | M5 | A | DONE 2026-10-17 | S |
| T02-1 | Deep-dive: CI and release integrity plan | 02 | M5 | R | DONE 2026-10-11 | M |
| T02-2 | CI integrity: bash + pipefail, exit-code gating, SHA-pinned actions, least-privilege `permissions:`, concurrency; canary procedure | 02 | M5 | A | DONE 2026-10-11 | S |
| T02-3 | Disable auto-release | 02 | M5 | A | DONE 2026-10-11 | S |
| T02-4 | Dependency advisories: bump rustls/ruint/quinn-proto/crossbeam-epoch, `glass_pumpkin` 1.9.1, re-review the 9 suppressions, daily audit job, `deny.toml` draft | 02 | M5 | A | DONE 2026-10-11 | M |
| T02-4b | async-nats 0.47, prometheus without default features; remaining advisory exceptions signed off | 02 | M5 | A | DONE 2026-10-17 | S |
| T02-5 | Shipped-build guard: build node + gateway as shipped; fail if test parameters or experimental features are linked | 02 | M5 | A | DONE 2026-10-11 | S |
| T02-6 | Production-SLOC job + report (`sloc.yml`) | 02 | M5 | A | DONE 2026-10-11 | S |
| T02-7 | Claims-lint CI job | 02 | M5 | A | DONE 2026-10-11 | S |
| T02-8 | Status generator → `docs/status/` | 02 | M5 | A | DONE 2026-10-18 | S |
| T02-9 | `rust-toolchain.toml` (installed 1.93.1) + MSRV note + `dependabot.yml` | 02 | M5 | A | DONE 2026-10-11 | S |
| T02-10 | `CODEOWNERS` for trust paths (handle placeholder `@OWNER`) | 02 | M5 | A | DONE 2026-10-11 | S |
| T02-11 | `cargo-deny` / `cargo-vet` config for crypto crates (`supply-chain/**`) | 02 | M5 | A | DONE 2026-10-11 | S |
| T02-12 | Guard release pipeline: cosign, reproducible build, SLSA provenance, CycloneDX SBOM | 02 | M7 | A | GATED:M7 · WAIT:T06-5 | M |
| T02-13 | Signed reproducible releases for the stack | 02 | M11 | A | GATED:M11 | M |
| T03-1 | Deep-dive: contracts v0/v2, encodings (BCS vs JCS), file-split plan | 03 | M5 | R | DONE 2026-10-11 | M |
| T03-2 | ADR + RFC process: `docs/adr/` and `docs/rfcs/` templates; ADR-01..17 stubs with status OPEN | 03 | M5 | A | DONE 2026-10-11 | S |
| T03-3 | Phase-1 scaffolding + `vaultex-types` v0; CI assertion that `vaultex-verify` has no tokio/network deps | 03 | M5 | A | DONE 2026-10-11 | M |
| T03-4 | Contracts v2, hotspot splits, Phase-2 scaffolding | 03 | M8 | A | GATED:G-MPC | M |
| T04-1 | Deep-dive: executable cut plan, SLOC inventory, crypto-shred template, balance-check procedure | 04 | M5 | R | DONE 2026-10-11 | M |
| T04-2 | Mainnet-balance check of every legacy derived address (read-only public RPC; results PRIVATE) | 04 | M5 | A | DONE 2026-10-11 (6 of 14 groups) · OWNER: offline check of the other 8 | S |
| T04-3 | Runtime freeze switch: release builds refuse keygen, raw `/sign`, legacy schemes, mainnet; a named test per refusal | 04 | M5 | A | DONE 2026-10-11 | M |
| T04-4 | Chain gating: never serve placeholder or unspendable addresses (CLI + REST) | 04 | M5 | A | DONE 2026-10-11 | S |
| T04-5 | Boot-node wrapper never mounts a multi-party keystore | 04 | M5 | A | DONE 2026-10-11 | S |
| T04-6 | Local `pre-cut-2026-10` tag | 04 | M5 | A | WAIT:T00-11 · OWNER: offline balance check of the other 8 key groups | S |
| T04-7 | Deletion and quarantine PR series (ROADMAP §3.5) | 04 | M5 | A | BLOCKED:ADR-04 · WAIT:T04-6 | L |
| T04-8 | SLOC report + ≤ 10k gate on the default release build | 04 | M5 | A | WAIT:T04-7 | S |
| T05-1 | Deep-dive: kernel design (decoder grammar, bundle, approvals, velocity, receipts, test plan, decoder-diversity option) | 05 | M6 | R | DONE 2026-10-11 | M |
| T05-2 | Port the TRON strict decoder (private G4 prototype) into `vaultex-verify` + negative tests + fuzz target skeleton | 05 | M6 | A | DONE 2026-10-11 | M |
| T05-2b | Decoder refuses native TRX amounts above 2^53−1 sun (kernel default) | 05 | M6 | A | DONE 2026-10-17 | S |
| T05-3 | Policy bundle v1 + vectors | 05 | M6 | A | DONE 2026-10-17 | M |
| T05-3b | Policy bundle: M-of-N to supersede a pending bundle; version window `(h, h+K]`; 30-day lock cap (ADR-11 follow-ups) | 05 | M6 | A | DONE 2026-10-18 | S |
| T05-3c | Policy bundle: quorum bundles anchor to the last quorum bundle (ADR-11 follow-up, 2026-10-18) | 05 | M6 | A | DONE 2026-10-18 | S |
| T05-4 | Approvals v1 + vectors | 05 | M6 | A | READY | M |
| T05-5 | Velocity store + breaker (fsync'd reservation, calibration helper, auto-pause, `kill -9` tests) | 05 | M6 | A | DONE 2026-10-11 | M |
| T05-6 | Receipts v1 (signed, hash-chained, accept + refuse) + offline verifier | 05 | M6 | A | DONE 2026-10-11 | S |
| T05-7a | RFC drafts `INTENT_V1`, `RECEIPT_V1` | 05 | M6 | A | DONE 2026-10-11 | S |
| T05-7b | RFC draft `POLICY_BUNDLE_V1` | 05 | M6 | A | READY | S |
| T05-8 | Admin CLIs `vaultex-approve` (local decode + render) and `vaultex-policy` | 05 | M6 | A | WAIT:T05-4 | M |
| T05-9 | Evidence part 1: incident-replay suite + tronweb differential (≥ 10k mutated inputs) | 05 | M6 | A | DONE 2026-10-11 | M |
| T05-10 | Evidence part 2: mutation check + fuzzing ≥ 24 CPU-h per decoder | 05 | M6 | A | READY | M |
| T05-11 | Single source for the TRON encoder and decoder | 05 | M6+ | A | GATED:M6 | S |
| T06-1 | Deep-dive: Guard design, key-custody options with costs, K-alt fallback | 06 | M7 | R | DONE 2026-10-11 | M |
| T06-2 | Nile spike, part 1: testnet keys + spike script (2-of-3 owner, 2-of-2 active, ops {1,31}) | 06 | M6 | A | DONE 2026-10-11 | S |
| T06-3 | Nile spike, part 2: run, record `Permission_id` behaviour and fees; go / no-go | 06 | M6 | A | WAIT:T00-12 | S |
| T06-4 | Retro-shadow tool (Rung 0) + report (raw data private) | 06 | M6 | A | READY | M |
| T06-5 | Guard service v0 | 06 | M7 | A | WAIT:T05-3..T05-6 | L |
| T06-6 | Operator-side TS submitter | 06 | M7 | A | WAIT:T06-5 | S |
| T06-7 | Testnet: ≥ 50 co-signed TRC-20 transfers, key rotation, Guard-down overflow | 06 | M7 | A | WAIT:T06-5,T06-6,T06-3 | M |
| T06-8 | Live shadow (Rung 1) ≥ 14 days | 06 | M7 | A→O | GATED:M7 | M |
| T06-9 | K-alt veto-hook interface (only if Nile = no-go) | 06 | M7 | A | WAIT:T06-3 | S |
| T07-1 | Deep-dive: outflow monitor + Guard ops | 07 | M7 | R | DONE 2026-10-11 | M |
| T07-2 | Chain watcher on ≥ 2 public TRON RPC providers | 07 | M7 | A | DONE 2026-10-11 | M |
| T07-3 | Receipt matching, caps, new-destination checks, `Approval`/allowance alerts | 07 | M7 | A | DONE 2026-10-11 | M |
| T07-4 | Soft-freeze path + ≤ 60 s auto-freeze drill (testnet) | 07 | M7 | A | WAIT:T06-5 | S |
| T07-5 | Ops docs: host baseline, ceremony + recovery runbooks, evidence-pack format | 07 | M7 | A | DONE 2026-10-11 | S |
| T07-6 | Real ceremonies and drills | 07 | M7 | O | OWNER · GATED:M7 | M |
| T08-1 | Deep-dive: `cggmp24` engine integration | 08 | M8 | R | DONE 2026-10-11 | M |
| T08-2 | Engine implementation (M8 #1–3, #7) | 08 | M8 | A | GATED:G-MPC | L |
| T09-1 | Deep-dive: transport v2 + control plane v2 | 09 | M8 | R | DONE 2026-10-11 | M |
| T09-F1 | NATS mTLS connect: require TLS, ignore advertised servers, `tls://` only; PEM loader tests | 09 | M8 | A | DONE 2026-10-17 | S |
| T09-2 | Transport v2 + control plane v2 implementation (M8 #4–6) | 09 | M8 | A | GATED:G-MPC | L |
| T10-1 | Deep-dive: verifying node, node state, key store v2 | 10 | M9 | R | DONE 2026-10-11 | M |
| T10-2 | Verifying node implementation (M9 #1–3) | 10 | M9 | A | GATED:G-MPC | L |
| T11-1 | Deep-dive: gateway relay (with ADR-09/10 options) | 11 | M9 | R | DONE 2026-10-11 | M |
| T11-2 | Gateway relay implementation (M9 #4) | 11 | M9 | A | GATED:G-MPC | L |
| T12-1 | Deep-dive: operator-grade reference deployment | 12 | M11 | R | DONE 2026-10-11 | M |
| T12-2 | Reference deployment implementation (M11) | 12 | M11 | A | GATED:M9 | L |
| T13-1 | Deep-dive: adversarial verification program | 13 | M6–M9 | R | DONE 2026-10-17 (narrowed: oracle, CI and process design) | M |
| T13-2 | Independent JS vector oracle (a different agent from the WS-05 implementer) | 13 | M6 | A | DONE 2026-10-11 | M |
| T13-3 | Incident catalogue → TRON test cases + fixtures | 13 | M6 | A | DONE 2026-10-11 | S |
| T13-4 | Guard harness (≥ 20 scenarios) | 13 | M7 | A | WAIT:T06-5 | M |
| T13-5 | Public category-level regression tests for the round-1 live-validation classes | 13 | M8 | A | GATED:M8 | M |
| T13-6 | Multi-host deterministic E2E, compromised-gateway(+1 node) harness, burst tests, live testnet job | 13 | M8–M9 | A | GATED:G-MPC | L |
| T14-1 | Deep-dive: assurance plan (RFQ texts, firm shortlist, timeline, co-funding letters, scope manifest, budget) | 14 | M10 | R | DONE 2026-10-11 | M |
| T14-2 | Threat model v2 (category level, public) | 14 | M10 | A | DONE 2026-10-11 | M |
| T14-3 | Audit-scope manifest v0 | 14 | M5 | A | WAIT:T04-8 | S |
| T14-4 | Known-issues list + KAT plan | 14 | M10 | A | DONE 2026-10-11 | S |
| T14-5 | Bookings, on commitment | 14 | M10 | O | OWNER (ready) | — |
| T15-1 | D1 discovery kit (guide, rubric, outreach plan with names private, LOI template, revenue-model structure) | 15 | D1 | R | DONE 2026-10-11 | M |
| T15-2 | Competitor watch (weekly): Fystack/Cosigner, Dfns Validation Gate, others | 15 | — | R | DONE 2026-10-11 | S |
| T15-3 | `docs/positioning/**` public-safe synthesis | 15 | D1 | A | GATED:D1 | S |
| T16-1 | Callback-gate adapter for the vendor D1 names | 16 | M6+ | R→A | GATED:D1 | M |
| T17-1 | People & counsel pack (cryptographer JD + rate survey, second-operator role, 3-question counsel brief, entity/KYB checklist) | 17 | — | R | DONE 2026-10-11 | S |
| T17-2 | Name/trademark desk search (WebSearch only; registries needing a browser marked UNVERIFIABLE) | 17 | — | R | DONE 2026-10-11 | S |
| M7-RF | M7 Rung 2 real funds (RF-1 memo, Phase A/B, mainnet drills, canary report) | 06/07 | M7 | A→O | GATED:M7 · BLOCKED:ADR-05,ADR-06 | — |
| M10..M13 | Assurance, operator deployment, MPC pilot, v1.0 | — | M10–M13 | — | GATED (decomposed at each gate) | — |

---

## 6. Task cards (READY and WAIT tasks; research prompts live in ROADMAP §5.2)

### WS-01 Truth, licence & disclosure (R10 lead, R7)
- **T01-2 README truth banner.**
  - Files: `README.md`, `README.zh-CN.md` (always together).
  - Do: insert the canonical banner from ROADMAP M5 #1 verbatim (EN; zh-CN translation). Add a support matrix (supported / staged / experimental) that matches HEAD. Remove overclaims: production-ready, 50 chains, threshold Sr25519/BLS, CI green, audit clean, the performance table, MIT-without-file.
  - Done when: both files render, the matrix matches the code, and grep finds no removed claim.
- **T01-3 Security policy.**
  - Files: `SECURITY.md`, `SECURITY_STATUS.md`; delete `specs/SECURITY.md` (merged).
  - Do: one policy covering supported versions, 90-day coordinated disclosure and GitHub private vulnerability reporting as the channel (owner proves it in T00-3). Write `SECURITY_STATUS.md` at category + fix level only.
  - Done when: no file:line or mechanism of any unfixed defect appears.
- **T01-4 GHSA draft.**
  - Output: `$OUT/GHSA-draft.md` (private).
  - Content: category-level classes as in M5 #3, the unsafe-deposit-address notice, re-key guidance and affected versions.
  - The owner publishes it (T00-9).
- **T01-7 Claims ledger.**
  - Files: `claims/schema.toml`, `claims/01/*.toml`, `CLAIMS.md` (rendered), and a renderer script under `scripts/ci/` (coordinate with WS-02).
  - Schema: id, text, status, artifact URL, expiry.
  - Done when: rendering is deterministic, and every README claim maps to a ledger id.
- **T01-8 Archive.**
  - Move superseded planning docs to `docs/archive/` with a banner; the list comes from T01-1.
  - Publish the M1–M4 re-baseline (ROADMAP §1.4) as `docs/archive/MILESTONES_M1-M4_REBASELINE.md`.
- **T01-9 Slim `CLAUDE.md`.**
  - Keep stable agent rules (roles, ownership, gates, never-do list, the memory rules on verification and checkpoints).
  - Move the sprint history to `docs/archive/`.
  - The owner reviews before merge: this file steers every agent.
- **T01-10 Charters.** Update `docs/AGENTS.md` + `.claude/agents/*` to ROADMAP §9.1 (R6 advisory, machine-account rule, three-layer gates). Add the R8–R10 agent files to git.
- **T01-11a Code of conduct.** Contributor Covenant 2.1, with the contact in GitHub-only form.

### WS-02 CI, release & supply chain (R9 lead, R5)
- **T02-2 CI integrity.**
  - File: `.github/workflows/ci.yml`.
  - Do: `defaults.run.shell: bash` with `set -euo pipefail`; replace the `TEST_COUNT` floor with exit codes; pin every action by SHA; set top-level `permissions: contents: read`; add `concurrency`. Document the canary procedure (a deliberately failing test on a throwaway branch must turn CI red; executed in T00-8).
  - Done when: `actionlint`-style review is clean (no new tool install), and the workflow still lists the same jobs.
- **T02-3 Auto-release off.** In `.github/workflows/release.yml`, trigger only on `workflow_dispatch`. Add a note that signed releases return in M7/M11.
- **T02-4 Dependency advisories.**
  - Do: bump rustls ≥ 0.23.45, ruint ≥ 1.20, quinn-proto ≥ 0.11.15, crossbeam-epoch ≥ 0.9.20; `glass_pumpkin` = 1.9.1.
  - If async-nats pins an old rustls-webpki, record the upgrade path. A minimal client upgrade is in scope only if it compiles without transport rewrites.
  - Re-review the 9 suppressions in `.cargo/audit.toml` with reachability (`cargo tree -i`).
  - Draft `deny.toml`, with exceptions marked "pending owner sign-off" and an expiry.
  - Add `.github/workflows/audit.yml` (daily).
  - Coordinate workspace `Cargo.toml` version lines with R0 (WS-03 owns the file; this task runs before T03-3).
  - Done when: `cargo audit` exits 0 except for listed pending exceptions, and the full test suite is green.
- **T02-5 Shipped-build guard.**
  - Do: add a CI job that builds `-p mpc-node -p api-gateway --release` in a fresh target without workspace feature unification. It fails if `local-transport` or any `experimental-*` feature is linked.
  - Add a compile-time guard (`compile_error!`) or a startup refusal, coordinated with WS-04's refusal hooks.
- **T02-6 SLOC job.**
  - Files: `.github/workflows/sloc.yml`, `scripts/ci/sloc.*`.
  - Count production SLOC per G7/P5 (non-blank, non-comment, excluding tests, benches and examples). The report is an artifact.
  - Done when: today's count reproduces ≈ 26.3k ± 1%.
- **T02-9 Toolchain.** `rust-toolchain.toml` pinned to 1.93.1 (already installed; no download); MSRV note; `.github/dependabot.yml` (cargo + github-actions, weekly).
- **T02-10 CODEOWNERS.** Trust paths: crypto, transport, node, gateway, kernel, CI and supply chain, mapped to `@OWNER` (the placeholder is replaced via Q-RUN-4).
- **T02-11 Supply-chain config.** `supply-chain/` for cargo-vet (imports for crypto crates) plus the final `deny.toml` policy. Verification runs in CI; local runs need Q-RUN-2.

### WS-03 Architecture contracts (R0)
- **T03-2 ADR/RFC process.**
  - Add `docs/adr/README.md` (template, statuses) and `docs/rfcs/README.md`.
  - Add one stub per ADR-01..17 with options and recommendation copied from §3, `Status: OPEN` and the decision left blank.
  - File names are provisional until ADR-16.
- **T03-3 Scaffolding.**
  - Workspace members, plus skeleton crates `crates/vaultex-types`, `crates/vaultex-verify`, `crates/vaultex-cli-admin`, `services/vaultex-guard`, `services/vaultex-monitor`, `tools/retro-shadow`. These are working names; ADR-12 may rename them.
  - `vaultex-types` v0: `ChainId`, `NetworkId`, `Intent`, `IntentDigest`, `SignInput { EcdsaPreimage{hash, bytes}, Ed25519Message(bytes) }` (no raw-prehash variant on value paths), `Decision`, `RefusalCode`, `Receipt`, `GuardRequest/Response`, with docs.
  - CI step: `cargo tree -p vaultex-verify` must not contain tokio, async-nats, reqwest or hyper.
  - Only crates already in `Cargo.lock`.

### WS-04 Cut & freeze (R0 lead; R1, R3, R4, R5)
- **T04-2 Mainnet-balance check.**
  - List every address ever derived from legacy wallets (`tests/e2e/funded-wallets.local.json` plus public keys from local keystore metadata, never shares or passwords).
  - Derive mainnet addresses for each chain, and query balances read-only via public RPC.
  - Output only to the private archive (PRIVATE_NOTES §8 table). Any non-zero mainnet balance is an incident: stop and report.
- **T04-3 Freeze switch.**
  - Files: refusal hooks only, in `services/mpc-node/src/main.rs` and `services/api-gateway/src/routes/{wallets,transactions}.rs`, plus tests.
  - Do: release builds refuse keygen, raw `/sign`, every legacy scheme and any mainnet network. Each refusal has a named test (`freeze_refuses_*`). A build-time flag or cfg makes the switch impossible to disable in release builds before M10-F.
- **T04-4 Chain gating.**
  - Files: `crates/mpc-wallet-chains/src/{registry,metadata}.rs`, `services/api-gateway/src/routes/chains.rs`, the CLI export-address path.
  - Unimplemented chains return a refusal instead of an address. FROST-TR wallets never show P2WPKH.
  - Tests for every previously placeholder chain.
- **T04-5 Boot-node mount.** In `infra/node/**` and `scripts/node.sh`, remove or quarantine any mount of a multi-party CLI keystore. Document it in `infra/node/README.md`.

### WS-05 Verifier kernel (R3, R6; R1 reviews)
- **T05-2 TRON strict decoder.**
  - Port from the private G4 prototype patch into `crates/vaultex-verify/src/tron/`.
  - Accept exactly `TransferContract` and `TriggerSmartContract` → `transfer(address,uint256)` on an allowlisted token with zero call value.
  - Refuse memo/data, more than one contract, an unconfigured `Permission_id`, `AccountPermissionUpdate`, unknown or duplicate fields, non-canonical varints, and any other selector.
  - Recompute `sha256(raw)`, require byte-equal canonical re-encoding, and bound expiry and `fee_limit`.
  - Negative test per refusal; fuzz target skeleton (not run in this task).
- **T05-5 Velocity + breaker.**
  - `VelocityStore` trait with an fsync'd file implementation.
  - Calibration helper `L = ⌈t·G/n⌉`; auto-pause state machine; `kill -9` crash tests.
  - The M-of-N unpause waits for T05-3.
- **T05-6 Receipts.** Ed25519-signed, hash-chained receipts for accepts and refusals, plus an offline verifier binary and vectors.
- **T05-7a RFCs.** `specs/INTENT_V1.md`, `specs/RECEIPT_V1.md` with vectors. Posting them for public comment is an owner action, after push.
- **T05-9 Evidence part 1.**
  - Incident-replay tests from T13-3: 100% refused.
  - tronweb differential harness: ≥ 10k mutated inputs with 0 accept-disagreements. It reuses `scripts/` Node tooling owned by WS-13; request changes through the run log.

### WS-06 Guard (R4, R2, R3, R8)
- **T06-2 Nile spike script.**
  - Generate testnet-only keys: 2-of-3 owner, 2-of-2 active (operator + verifier), operations {1, 31}.
  - Script: set permissions; co-sign a TRC-20 transfer with a Rust `k256` key and a tronweb key; attempt `AccountPermissionUpdate` under active, which must fail.
  - Output: the script, plus the list of addresses to fund (→ T00-12). Keys stay in the private archive, never in the repo.

### WS-07 Monitor & ops (R9, R2; a different implementer from WS-06)
- **T07-2 Chain watcher.** In `services/vaultex-monitor`: ≥ 2 public TRON providers behind a trait, block cursor persistence, and rate-limit handling. Production API keys come later (owner).
- **T07-5 Ops docs.** In `docs/ops/**` and `docs/ceremonies/guard.md`: host baseline, ceremony and recovery runbooks, and the evidence-pack format.
- **T07-3 Matching.** Every outflow is matched to a receipt; caps and new-destination checks; TRC-20 `Approval` and non-zero allowance alerts; the refill checks that allowance = 0.

### WS-13 Adversarial (R5, R6)
- **T13-3 Incident catalogue.**
  - In `crates/vaultex-redteam/` (or `tests/guard-adversarial/fixtures/`), map the incident classes to TRON cases: approve-to-attacker, destination swap, permission takeover, memo or second-contract smuggling, fee-limit abuse, expired or overlong validity, rolled-back bundle, forged or duplicate approvals, initiator self-approval.
  - Category-level descriptions only.
- **T13-2 JS oracle.** In `scripts/oracle/**`, an independent implementation that reproduces the RFC vectors. It must be written by a different agent from WS-05, from the RFC text only.

### WS-14 Assurance (R7 + owner; R6 drafts)
- **T14-2 Threat model v2.** Rewrite `docs/THREAT_MODEL.md` for the Phase-1 architecture (kernel, Guard, monitor) and the target MPC architecture: trust boundaries, actors (including a compromised gateway and an insider), and controls mapped to milestones. Category level only.
- **T14-4 Known issues + KATs.** A public known-issues list at category level, and a KAT plan for the kernel and the future engine.

---

## 7. Gated and later work (decomposed when its gate opens)

| Gate | Opens when | Work it releases |
|---|---|---|
| **G-MPC** | D1 + D2 pass, or funding for scenario (b)/(c); plus an independent crypto reviewer engaged (ADR-01, ADR-07) | T03-4, T08-2, T09-2, T10-2, T11-2, T13-6 |
| **M6 exit** | M6 table in ROADMAP §4.3 | T05-11; M7 build-out |
| **M7** | M6 exit + RF-1 preconditions (ADR-05/06, counsel) | T06-8, T07-6, M7-RF, T02-12 |
| **D1** | ≥ 12 interviews, ≥ 4 intents | T15-3, T16-1 (with ADR-14) |
| **M8 / M9** | Engine and transport, then the verifying node | T13-5, T12-2 |
| **M10–M13** | Committed user, audit letter, second human, buyer | Audits, operator deployment, MPC pilot, v1.0 |

*PROPOSED TASKS — awaiting human approval.*
