# Agent roles and charters

This file maps the agent roles R0–R10 to their charters, workstreams and gates. It holds rules, never status: status lives in [CLAIMS.md](../CLAIMS.md), [SECURITY_STATUS.md](../SECURITY_STATUS.md) and, once the CI status job lands, `docs/status/`.

**Order of authority.** [ROADMAP](ROADMAP.md) §9 (process) and §5 (workstreams) → this file → the role files in `.claude/agents/`. Where a lower document disagrees with a higher one, the higher one wins; fix the lower one through WS-01. The rules every agent follows, whatever its role, are in [CLAUDE.md](../CLAUDE.md).

| Source | What it holds |
|---|---|
| ROADMAP §9.1 | The charters below, verbatim in substance |
| ROADMAP §9.2–§9.4 | Gates, agent rules, cadence, the definition of finished work |
| ROADMAP §5.0, §5.2 | Shared-file owners; each workstream's exclusive paths. **The path lists there are authoritative**; this file and the role files only summarise them |
| [TASKS](TASKS.md) §2, §3, §6 | Run protocol, the owner's Decision Inbox, task cards |
| `.claude/agents/r<n>-*.md` | One prompt file per role, loaded by Claude Code as a subagent definition |

## Roles

| Role | Charter (ROADMAP §9.1) | Workstreams | Role file |
|---|---|---|---|
| R0 Architect | Contracts, shared files and dependency batches (WS-03); leads the cut (WS-04) | WS-03 lead · WS-04 lead | `r0-architect.md` |
| R1 Crypto | `cggmp24` wrapper and aux lifecycle (WS-08); reviews kernel encodings. **No GG20 or Stark work** | WS-08 (with the contract cryptographer; from G-MPC) · WS-05 reviewer · WS-04 protocol deletions | `r1-crypto.md` |
| R2 Infra | Transport and control plane (WS-09); node (WS-10); Guard persistence; deployment (with R9) | WS-09 · WS-10 (with R6) · WS-06 persistence and keyfile · WS-07, WS-12 (with R9) | `r2-infra.md` |
| R3 Chains | **TRON first** (WS-05 decoder, WS-06, WS-16); every other chain is experimental | WS-05 (with R6) · WS-06 TRON · WS-16, WS-11 (with R4) · WS-04 chain gating | `r3-chain.md` |
| R4 Service | Guard service (WS-06); gateway relay (WS-11); adapter (WS-16) | WS-06 service · WS-11 · WS-16 · WS-04 refusal hooks | `r4-service.md` |
| R5 QA | KPI is **oracle-backed evidence**, not test count (WS-13, CI) | WS-13 (with R6) · WS-02 (with R9) · WS-04 test fixes | `r5-qa.md` |
| R6 Security | Harness author and threat-model drafter. **Advisory only, never the merge gate** | WS-13 (with R5) · WS-05 adversarial tests · WS-10 (with R2) · WS-14 threat-model draft | `r6-security.md` |
| R7 PM | Owns the roadmap's artifacts, decision days, RFQs and discovery logistics | WS-01 (with R10) · WS-14, WS-15 (with the owner) | `r7-pm.md` |
| R8 SDK | The thin TS Guard client (WS-06) now, a TS client at M13; other SDKs deferred. The admin and approver CLIs belong to WS-05 | WS-06 TS client | `r8-sdk.md` |
| R9 DevOps | CI, the release chain and deployment (WS-02, WS-07, WS-12) | WS-02 lead (with R5) · WS-07, WS-12 (with R2) | `r9-devops.md` |
| R10 Scribe | Claims ledger and CI-generated status (WS-01). **Never hand-edits status** | WS-01 lead (with R7) | `r10-scribe.md` |

**The owner** approves plans, answers the Decision Inbox (TASKS §3), approves every merge into `dev` and `main`, and does everything marked OWNER: external contact, GitHub settings, funds, keys and ceremonies, hiring and legal. WS-17 (organisation, people, counsel) is owner-only and stays outside the repo. A contract cryptographer, once engaged (ADR-01), works with R1 on WS-08, reviews WS-09 and joins the human review of crypto and kernel paths.

A role is a set of rules, not an agent instance. Several agents may run as the same role in parallel, each in its own workstream worktree; one agent may act for several roles only where the independence rules below allow it.

## Independence rules

A check written by the same author as the code it checks is not evidence. These pairs must be different agents (and, where a human is named, a different human):

| Must differ | Why (ROADMAP) |
|---|---|
| The WS-13 JS vector oracle ≠ the WS-05 Rust kernel author | M6 #7: vectors are reproduced by an independent implementation |
| The WS-07 outflow monitor ≠ the WS-06 Guard implementer | M7 #3, RF-4: the monitor is a separate failure domain |
| R1's review of kernel encodings and signatures ≠ their author | WS-05 card |
| The R6 advisory note ≠ the author of the change it reviews | Follows from the first line of this section; R6 is advisory (§9.1) |
| Independent review (layer 3) ≠ the owner or any agent | §9.2: in solo mode, owner review is not independent review |

## Gates: three layers (ROADMAP §9.2)

| Layer | What | Applies to |
|---|---|---|
| **1. CI required checks** | fmt; clippy `-D warnings`; tests with pipefail and exit-code gating; audit, deny, vet; claims-lint; SLOC budget; shipped-build guard; then, as each lands, the transport adversarial suite, redteam, multi-host E2E and kernel vectors checked by the JS oracle | Every PR |
| **2. Human review (CODEOWNERS)** | The owner, plus the cryptographer when engaged, on the trust paths listed in [`.github/CODEOWNERS`](../.github/CODEOWNERS). Every trust-path PR carries an external-oracle test (`k256`/`ecrecover`, canonical SDK vectors, a public-testnet run, or the adversarial harness) | Trust paths |
| **3. External review** | Paid limited evaluations (mandatory in solo mode), focused review, full audit, pentest. The fix-review letter decides for any real-funds mode | M6, M7, M8, M10 |

An agent never stands in for a layer. In particular the **R6 note is advisory**: it informs the human reviewer, and it neither approves nor blocks a merge. Gates are enforced by CI and branch protection, not by prose (failure class 8 in CLAUDE.md).

### The R6 advisory note

R6 writes one note per branch or PR that touches crypto, transport, node, gateway, kernel or CI (TASKS §2, item 4). Its shape:

```text
R6 ADVISORY (advisory only; not a merge gate)
Change:       <branch or PR> @ <40-hex commit>
Read:         <paths reviewed>
Against:      <task card / security checklist / threat-model section>
Observations: <one line each: severity CRITICAL|HIGH|MEDIUM|LOW|INFO, category, suggested fix>
External oracle present: <yes: which | no: which one to add>
Suggestion:   <proceed | fix first | needs human or external review>
Private detail: <none | sent to the owner privately>
```

The note follows the public-safety rule: weaknesses by category and fix only. Mechanisms, reproduction steps and file:line pointers to an unfixed defect never go into the repo, a PR or an issue; they go to the owner privately. A finding that needs tracking becomes a GitHub issue (ADR-16), never a new `SEC-` number.

## Agent rules (ROADMAP §9.2)

- **Agents never merge.** A run orchestrator merges into its local integration branch only after re-running fmt, clippy and tests at the repo root (TASKS §2, item 4). `dev` reaches `main` only by PR, with passing CI and the owner's approval.
- **Machine account.** Agents author commits and PRs only from a dedicated machine account with write access and no merge or admin rights. The owner's approval is the required review, with "Do not allow bypassing the above settings" (include administrators) enabled; no other account the owner controls may approve. Without that account, or without the owner asking in the session, agents do not push at all.
- **No secrets.** Agents never hold secrets, never touch production or mainnet credentials, and agent memory never stores secrets.
- **Dependencies** come only through R0, with `cargo-deny`/`cargo-vet` output and the owner's approval. An agent that needs a crate not in `Cargo.lock` lists it as a request instead of adding it.
- **Maintainer hygiene (owner):** hardware-key 2FA on maintainer accounts; release-signing keys stay off the development laptop and out of every agent's reach.
- **WIP limit:** at most two trust-boundary streams under active change per human reviewer, plus at most two low-risk streams (docs, CI, infra, tests). Review capacity sets the pace, not agent capacity.
- **Third-party agent content.** General-purpose agent definitions kept outside the repo may be used as consultants: they own no paths, follow CLAUDE.md, and their output is advisory like R6's. Do not add third-party agent or skill files to the repo; whether the existing `.agents/**` stays is owner decision D-AGENTS.

## How a task runs

The steps are in CLAUDE.md ("Workflow", "Commits") and TASKS §2. In short:

1. R7 writes the task card; the owner's open decisions are skipped, never guessed.
2. The agent works in its workstream's worktree, outside the main checkout, and edits only its workstream's paths (ROADMAP §5.2) plus its fragments: `claims/<ws>/*.toml`, `changelog.d/<ws>-*.md`, `status/<ws>.toml`. Anything else becomes a request to the owning stream.
3. It commits `[R<n>][T<id>] <what> — tests pass` (or `— docs/ci only`), with the `Co-Authored-By:` trailer.
4. The work counts as finished only against ROADMAP §9.4: linked artifacts, an external-oracle test on trust paths, mutation-checked refusals, fragments, human approval with the R6 note attached, no unapproved dependency, a public-safety check.

## Retired practices

These appear in archived documents, in git history and possibly in agent memory. They are not current.

| Retired | Now | ROADMAP |
|---|---|---|
| R6 verdicts (approve or defect) gate every merge | R6 writes an advisory note; the three layers above gate | §9.1, §9.2 |
| One worktree and `agent/r<n>-*` branch per agent, at fixed local paths | One worktree and branch per workstream (`ws/<WS>-<slug>`; a run may cut task branches under it) | §5.0; TASKS §2 |
| Sprints and sprint numbers; "PROPOSED TASKS" reports per sprint | Batches, numbers never reused; task cards in TASKS.md; owner decisions batched on decision days | §9.3 |
| `SEC-`, `DEC-`, `L-` numbers assigned in documents | GitHub issue numbers; ADR files `docs/adr/ADR-<issue>.md` (ADR-16) | §5.0, §9.5 |
| R10 updates test counts, sprint and finding status by hand after each merge | Status is generated by CI from checks and the claims ledger; R10 renders fragments | §9.5 |
| Test count as R5's KPI | Oracle-backed evidence | §9.1 |
| R3 implements every chain behind one trait | TRON first; every other chain experimental; no new chain before M10 | §9.1, §3.6 |
| R1 maintains GG20, Stark, Sr25519 and BLS engines | No GG20 or Stark work; legacy engines are cut or quarantined in WS-04 (ADR-03); the planned engine work, the `cggmp24` wrapper, waits on G-MPC and ADR-07 | §9.1, §3.5 |
| R8 builds TS, Python and Go SDKs | The thin TS Guard client now, a TS client at M13 | §9.1 |
| R9 owns Helm, Terraform and multi-cloud stacks | CI, release chain, deployment (WS-02, WS-07, WS-12); legacy `infra/{k8s,terraform,helm}` moves to `infra/experimental/` in the cut | §9.1, §5.2 |
| A catalogue of extended "Agency" agents with local install paths | Consultants only, outside the repo (see Agent rules) | §9.2 |
