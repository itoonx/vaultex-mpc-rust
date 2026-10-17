# ADR-11: Policy distribution

- Status: ACCEPTED
- Decider: owner
- Decide by: ≈ wk 5 (M6 start)
- Unblocks: T05-3, T05-4, T05-7b, T05-8, T06-5
- Background: `docs/ROADMAP.md` §4.3 M6 #3, §11

## Context

Owner decision from the Decision Inbox (`docs/TASKS.md` §3). Tasks under *Unblocks* stay skipped until it is decided.

## Options

- Unsigned static file
- quorum-signed bundle file
- remote governance service

## Recommendation

Quorum-signed bundle installed per signer as a file

_Advisory, copied from `docs/TASKS.md` §3._

## Decision

"ก) bundle ที่ quorum เซ็น ติดตั้งเป็นไฟล์ที่ signer ทุกตัว (Recommended)"

Source: owner's answer in the Claude Code session of 2026-10-16 (option selected in the Decision Inbox walk-through). Meaning: Quorum-signed policy bundle, installed per signer as a file.

## Follow-up decisions (2026-10-17)

From the security review of the policy bundle v1 (T05-3), answered by the owner in the Claude Code session of 2026-10-17:

- **Superseding a pending bundle:** "ต้อง M-of-N ถ้ามี bundle รออยู่ (แนะนำ)". While a loosening is pending, any bundle that supersedes it needs M-of-N admin signatures, even a tightening. A single admin can no longer cancel a pending change, such as an admin-set rotation.
- **Version rule and time lock:** "ช่วง (h, h+K] + lock ไม่เกิน 30 วัน (แนะนำ)". A candidate's version must lie in `(h, h+K]`, where `h` is the highest accepted version and K = 16 (provisional); order comes from the parent-digest link. The loosening time lock is capped at 30 days.

## Consequences

Unblocks T05-3, T05-4, T05-7b, T05-8 and T06-5. The follow-up decisions are implemented by T05-3b.
