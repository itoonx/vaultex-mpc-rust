# ADR-17: Guard key custody for Rung 2

- Status: ACCEPTED
- Decider: owner
- Decide by: Before M7
- Unblocks: T06-5, T07-6
- Background: `docs/ROADMAP.md` §4.3 M7 #4; costed options come from T06-1 (not yet in §11)

## Context

Owner decision from the Decision Inbox (`docs/TASKS.md` §3). Tasks under *Unblocks* stay skipped until it is decided.

## Options

- Cloud-KMS secp256k1
- HSM
- encrypted passphrase file

## Recommendation

Decide after T06-1 costs the options

_Advisory, copied from `docs/TASKS.md` §3._

## Decision

"ตามคำแนะนำ (Recommended)"

Source: owner's answer in the Claude Code session of 2026-10-16 (option selected in the Decision Inbox walk-through). Meaning: As recommended by T06-1: on testnet an encrypted key file sealed to the host TPM; on mainnet Rung 2 a non-exportable AWS KMS secp256k1 key in an AWS account dedicated to the Guard; YubiHSM 2 documented for self-hosters.

## Consequences

Unblocks T06-5 and T07-6.
