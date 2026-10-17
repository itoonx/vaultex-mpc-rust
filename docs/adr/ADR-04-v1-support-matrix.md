# ADR-04: v1 support matrix

- Status: ACCEPTED
- Decider: owner
- Decide by: Day 7
- Unblocks: T04-7, scope of WS-05 beyond TRON
- Background: `docs/ROADMAP.md` §2.1, §3.5, §11

## Context

Provisional owner answer, 2026-10-16: "ก) TRON (TRX + TRC-20) บน cggmp24 (Recommended)", to be re-confirmed after the TKeeper teardown (competitor watch DN-1). The teardown was done on 2026-10-17: kill criterion K9 has substantially fired. Its details stay in the private competitor watch.

Owner decision from the Decision Inbox (`docs/TASKS.md` §3). Tasks under *Unblocks* stay skipped until it is decided.

## Options

- TRON-only
- TRON + EVM
- multi-chain
- FROST/Solana first

## Recommendation

TRON (TRX + TRC-20) on pinned `cggmp24`; others quarantined

_Advisory, copied from `docs/TASKS.md` §3._

## Decision

"ยืนยันแบบปรับ (แนะนำ)"

Source: owner's answer in the Claude Code session of 2026-10-17. Meaning: confirm TRON (TRX + TRC-20) on pinned `cggmp24`, with these changes:

1. **Rationale.** The bet is to be assured, spec-first and fail-closed by default, not that the combination may be unoccupied.
2. **Spec-first M6.** Publish `INTENT_V1`, `RECEIPT_V1` and `POLICY_BUNDLE_V1` with vectors as early as the comment window allows.
3. **Interop.** Prepare a TRON test-vector exchange; the owner decides when to send it.
4. **K9 at G-MPC.** A K9 re-score against OSI entrants becomes an input to G-MPC (wk 16). If K9 has fully fired by then, contribute the kernel and specs instead of racing the full-stack MPC phase. Phase 1 (M5–M7) proceeds either way.
5. **Tripwires.** The weekly competitor watch carries escalation tripwires (kept in the private watch).

## Consequences

Unblocks T04-7 and the WS-05 scope beyond TRON (others stay quarantined). `docs/ROADMAP.md` item 3 of the summary carries the new rationale. G-MPC gains the K9 re-score input.
