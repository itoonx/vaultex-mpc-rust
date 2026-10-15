# ADR-09: Gateway authentication

- Status: ACCEPTED
- Decider: owner
- Decide by: G-MPC
- Unblocks: T11-2
- Background: `docs/ROADMAP.md` §4.3 M9, §11

## Context

Owner decision from the Decision Inbox (`docs/TASKS.md` §3). Tasks under *Unblocks* stay skipped until it is decided.

## Options

- Keep custom handshake
- quarantine
- replace

## Recommendation

Replace with rustls mTLS + node-verified signatures

_Advisory, copied from `docs/TASKS.md` §3._

## Decision

"ยอมรับตามคำแนะนำทั้งหมด (Recommended)"

Source: owner's answer in the Claude Code session of 2026-10-16 (option selected in the Decision Inbox walk-through). Meaning: Replace the custom handshake with rustls mTLS plus node-verified signatures (answered ahead of its G-MPC due date).

## Consequences

Unblocks T11-2 when the G-MPC path starts.
