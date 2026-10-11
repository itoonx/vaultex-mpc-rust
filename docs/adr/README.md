# Architecture Decision Records

An ADR records one decision that is costly to reverse or that every workstream must follow, such as scope, licence, trust model, real-funds rules or naming. It states the question, the options, a recommendation, and the decision once the owner has made it.

An ADR records **which option** was chosen. A byte-level format or interface that other implementations must reproduce is specified in an RFC instead (see [`../rfcs/README.md`](../rfcs/README.md)).

Owner: WS-03 (R0). This directory is listed among WS-03's exclusive paths in `docs/ROADMAP.md` §5.2.

## When to write one

- Every item in the Decision Inbox (`docs/TASKS.md` §3) that is named `ADR-*`.
- A change that breaks the SLOC budget (`docs/ROADMAP.md` §9.4 item 5).
- Any other decision that changes scope, a trust boundary or a contract for more than one workstream.

## Statuses

| Status | Meaning | Allowed next |
|---|---|---|
| `OPEN` | The question, options and recommendation are recorded. The Decision section is blank. | `ACCEPTED`, `WITHDRAWN` |
| `ACCEPTED` | The owner chose an option. The Decision section quotes the owner's answer, with its date and where it was recorded. | `SUPERSEDED` |
| `SUPERSEDED` | A later ADR replaces this one. Add `Superseded by: ADR-…` to the header list. | none |
| `WITHDRAWN` | The question no longer needs a decision. One line says why. | none |

## Rules

1. **Only the owner decides.** Agents may create `OPEN` ADRs and add context, options and evidence. An agent fills the Decision section only to transcribe an answer the owner has recorded, quoted word for word, with its date and source.
2. **A recommendation is advisory.** It never unblocks a task. Tasks listed under *Unblocks* stay skipped while the ADR is `OPEN`.
3. **Accepted ADRs do not change.** Typo fixes and a `Superseded by` line are the only edits. To change a decision, write a new ADR that supersedes the old one.
4. **Public-safe.** Name vulnerabilities by category and fix only: no exploit mechanics, no file:line pointers to unfixed defects, no secret names or locations, no internal business details. If the decision rests on private context, the ADR says only that private context exists.
5. **No unbacked status claims.** An ADR states the status of code or assurance only when a claims-ledger entry backs it (`docs/ROADMAP.md` §9.5).

## File names and IDs

- ADR-01 to ADR-17 use the IDs of the Decision Inbox, as `ADR-<NN>-<slug>.md`. These names are **provisional**.
- If ADR-16 is accepted as recommended, ADR IDs become GitHub issue numbers, and files are renamed to `ADR-<issue>.md` (`docs/ROADMAP.md` §5.0 rule 3).
- Until ADR-16 is decided, only R0 assigns a new number: the next free two-digit number, so that parallel streams cannot collide.
- "Day N" and "wk N" in *Decide by* count from day 0 = Monday 2026-10-12 (`docs/ROADMAP.md` §4.1, §7.1).
- The earlier decision log (`docs/DECISIONS.md`, `retro/decisions/DEC-*.md`) keeps its own `DEC-` numbers and is not renumbered. New decisions are recorded here.

## Template

Copy this block into a new file and replace each `<…>`.

```markdown
# ADR-<NN>: <short title>

- Status: OPEN
- Decider: owner
- Decide by: <date, day number or gate>
- Unblocks: <task IDs, or "none">
- Background: <docs/ROADMAP.md sections, other public docs>

## Context

<Why a decision is needed now and what depends on it. Public-safe; category level only.>

## Options

- <option 1>
- <option 2>

## Recommendation

<The option recommended, and the reason in one or two sentences.>

_Advisory: <who recommended it, and where>._

## Decision

_Blank until the owner decides._
<When accepted: the owner's answer, quoted word for word, then "Decided <YYYY-MM-DD>; recorded in <issue or record>.">

## Consequences

_Recorded with the decision._
<What changes, which tasks it unblocks, and what moves out of scope.>
```

## Index

The `Status:` line in each file is authoritative. This table lists titles only, so it does not drift; once ADR-16 is decided, a CI-generated status page replaces any hand-kept status.

| ADR | Title | Decide by |
|---|---|---|
| [ADR-01](ADR-01-capacity-scenario.md) | Capacity scenario | Day 14 |
| [ADR-02](ADR-02-licence.md) | Licence | Day 3 |
| [ADR-03](ADR-03-legacy-crypto.md) | Legacy hand-rolled crypto | Day 7 |
| [ADR-04](ADR-04-v1-support-matrix.md) | v1 support matrix | Day 7 |
| [ADR-05](ADR-05-real-funds-rule.md) | Real-funds rule | Day 7 |
| [ADR-06](ADR-06-first-funds-host.md) | First-funds host for Rung 2 | Day 7 |
| [ADR-07](ADR-07-mpc-engine-swap.md) | MPC engine swap | wk 16 |
| [ADR-08](ADR-08-audit-sourcing.md) | Audit sourcing and timing | wk 2 |
| [ADR-09](ADR-09-gateway-authentication.md) | Gateway authentication | G-MPC |
| [ADR-10](ADR-10-gateway-persistence.md) | Gateway persistence | G-MPC |
| [ADR-11](ADR-11-policy-distribution.md) | Policy distribution | ≈ wk 5 (M6 start) |
| [ADR-12](ADR-12-name-and-crate-prefix.md) | Name and crate prefix | Day 30 |
| [ADR-13](ADR-13-disclosure-posture.md) | Disclosure posture | Day 7 |
| [ADR-14](ADR-14-callback-adapter-vendor.md) | Callback-adapter vendor | After D1 |
| [ADR-15](ADR-15-decoder-diversity.md) | Decoder diversity | Before M10-F freeze |
| [ADR-16](ADR-16-status-and-ids.md) | Status and IDs | M5 |
| [ADR-17](ADR-17-guard-key-custody.md) | Guard key custody for Rung 2 | Before M7 |
