# ADR-07: MPC engine swap

- Status: ACCEPTED
- Decider: owner
- Decide by: wk 16
- Unblocks: T03-4, T08-2, T09-2, T10-2
- Background: `docs/ROADMAP.md` §4.3 G-MPC, §10 (K6–K8), §11

## Context

Owner decision from the Decision Inbox (`docs/TASKS.md` §3). Tasks under *Unblocks* stay skipped until it is decided.

## Options

- Always
- conditional on G-MPC
- never (kernel-only)

## Recommendation

Conditional on G-MPC

_Advisory, copied from `docs/TASKS.md` §3._

## Decision

"ยอมรับตามคำแนะนำทั้งหมด (Recommended)"

Source: owner's answer in the Claude Code session of 2026-10-16 (option selected in the Decision Inbox walk-through). Meaning: Conditional on G-MPC (answered ahead of its due date, as part of a batch accepting the recommendations for ADR-07, -09, -10, -14 and -15).

## Consequences

T03-4, T08-2, T09-2 and T10-2 proceed only if G-MPC passes.
