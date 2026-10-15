# ADR-02: Licence

- Status: ACCEPTED
- Decider: owner
- Decide by: Day 3
- Unblocks: T01-5, T01-11b
- Background: `docs/ROADMAP.md` §4.3 M5 #2, §7.1, §11

## Context

Owner decision from the Decision Inbox (`docs/TASKS.md` §3). Tasks under *Unblocks* stay skipped until it is decided.

## Options

- MIT OR Apache-2.0
- Apache-2.0
- AGPL/BSL

## Recommendation

MIT OR Apache-2.0 + NOTICE, after author consent (T00-5)

_Advisory, copied from `docs/TASKS.md` §3._

## Decision

"ก) MIT OR Apache-2.0 + ลบ .agents (Recommended)"

Source: owner's answer in the Claude Code session of 2026-10-16 (option selected in the Decision Inbox walk-through). Meaning: MIT OR Apache-2.0 + NOTICE, after consent from every author identity (T00-5). D-AGENTS answered in the same choice: remove `.agents/**` and `skills-lock.json` from the repo.

## Consequences

T01-5 (licence files and manifests) waits only for the author consents (T00-5). T01-11b (CONTRIBUTING, DCO) and T01-6 are unblocked.
