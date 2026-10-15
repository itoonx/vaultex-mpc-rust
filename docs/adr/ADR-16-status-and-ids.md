# ADR-16: Status and IDs

- Status: ACCEPTED
- Decider: owner
- Decide by: M5
- Unblocks: T02-8, final ADR file names
- Background: `docs/ROADMAP.md` §5.0 rule 3, §9.5, §11

## Context

Owner decision from the Decision Inbox (`docs/TASKS.md` §3). Tasks under *Unblocks* stay skipped until it is decided.

## Options

- Hand-edited docs
- CI-generated status + GitHub issue IDs

## Recommendation

CI-generated status; issue numbers as IDs

_Advisory, copied from `docs/TASKS.md` §3._

## Decision

"ก) สถานะสร้างจาก CI + เลข GitHub issue เป็น ID (Recommended)"

Source: owner's answer in the Claude Code session of 2026-10-16 (option selected in the Decision Inbox walk-through). Meaning: CI-generated status; GitHub issue numbers as IDs.

## Consequences

Unblocks T02-8; ADR files move to `ADR-<issue>.md` names when issues exist.
