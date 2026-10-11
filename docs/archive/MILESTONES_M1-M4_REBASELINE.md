> **ARCHIVED — SUPERSEDED (2026-10-11).** Kept for history only; it does not describe Vaultex today.
> Current status: [README](../../README.md), [SECURITY_STATUS.md](../../SECURITY_STATUS.md), [CLAIMS.md](../../CLAIMS.md).
> Superseded by: the milestones M5–M13 in [ROADMAP §4](../ROADMAP.md#4-milestones-m5).

# Milestones M1–M4: re-baseline

In March 2026 the project defined eight milestones and declared the first four done. This page records what those milestones actually delivered. It is the public record that replaces every earlier "M1–M4 done" statement.

| | |
|---|---|
| **Source** | [ROADMAP §1.4](../ROADMAP.md#14-honest-re-baseline-of-milestone-history) (2026-10-09). The table below repeats it, so that the record sits beside the documents it supersedes. If the two ever differ, the roadmap wins. |
| **Original definitions** | M1–M8 in §4 of `docs/ROADMAP.md` at commit [`ad038c9b`](https://github.com/itoonx/vaultex-mpc-rust/blob/ad038c9b51aa34a2f434a83af1029add42f83533/docs/ROADMAP.md) (2026-03-19). |
| **Earlier status line** | "M1-M4: DONE" in `CLAUDE.md` at commit [`ccd1f7f6`](https://github.com/itoonx/vaultex-mpc-rust/blob/ccd1f7f6007ef7e481d812cea4c78f3772b13371/CLAUDE.md#L257) (2026-06-01). |
| **M5(2026-03)–M8(2026-03)** | Dropped when `docs/ROADMAP.md` was rewritten at commit [`75d585e8`](https://github.com/itoonx/vaultex-mpc-rust/blob/75d585e896073fa882fe4c0fefcf1f625fbfaba8/docs/ROADMAP.md) (2026-04-01). |
| **Numbering** | The roadmap's M5–M13 are new milestones. The withdrawn March milestones are cited as M5(2026-03)…M8(2026-03). |

## Re-baselined status

| Milestone (defined 2026-03-19) | Declared | Ground truth | Re-baselined status | Claims ledger today |
|---|---|---|---|---|
| M1 Security hardening | "Done" 03-19 | Control messages are signed but carry no freshness; the "audit clean without ignores" criterion is unmet | **Partial** [I9 §2.2; W5] | [`01.banner`](../../CLAIMS.md#01banner) (limitation 3), [`01.withdrawn.security-findings-resolved`](../../CLAIMS.md#01withdrawnsecurity-findings-resolved) |
| M2 CGGMP21 | "Done" 03-19 | Library completed about 10 days *after* the declaration. Now known to be unsound and to fail at production parameters | **Void.** Superseded by `cggmp24`; code to be deleted [W1, W2] | [`01.scheme.hand-rolled-ecdsa`](../../CLAIMS.md#01schemehand-rolled-ecdsa), [`01.scheme.cggmp24-not-integrated`](../../CLAIMS.md#01schemecggmp24-not-integrated) |
| M3 HSM/SGX | "Done" 03-19 | KMS signer and client are stubs; the only enclave is a mock | **Not met** [I9 §2.2] | [`01.component.kms-hsm-tee`](../../CLAIMS.md#01componentkms-hsm-tee) |
| M4 Policy v2 & delegation | "Done" 03-20 | Library only, not enforced on the sign path. The signed-policy type fails verification after a JSON round trip in 194 of 200 runs | **Library only.** Replaced by the kernel's policy bundle v1 [W3; G4 §3.2] | [`01.component.policy-library`](../../CLAIMS.md#01componentpolicy-library) |
| M5(2026-03)–M8(2026-03) (DeFi screening; multi-tenant/webhooks; compliance & external audit; launch) | Deleted from the roadmap on 2026-04-01 | None delivered. Fragments exist: unwired webhooks, audit-prep documents, a Helm chart that cannot start a cluster | **Withdrawn**; content re-planned in ROADMAP §4 [I9 §2.1–2.2] | [`01.component.deployment`](../../CLAIMS.md#01componentdeployment), [`01.no-independent-audit`](../../CLAIMS.md#01no-independent-audit) |
| Process facts | "52 sprints" | 18 active days; 562 commits; M1–M4 declared within 8.7 hours with 10 of 75 exit criteria ticked; internal security gate inactive after 2026-03-20 | Milestones now close **only on artifacts** (ROADMAP §9.5) [S8; I9 §2] | [`01.provenance.ai-agents`](../../CLAIMS.md#01provenanceai-agents) |

The first four columns are ROADMAP §1.4 verbatim, except that "below" and "§9" now name the roadmap section they point to. The last column links the claims-ledger entries that state the current position.

## Evidence IDs

- **W1, W2, W3, W5, S8** are entries of the round-2 verified claims ledger: [ROADMAP Appendix A](../ROADMAP.md#appendix-a-verified-claims-ledger-round-2-summary-with-final-status).
- **I9** (history and stage review) and **G4** (node-side verification feasibility) are round-1 reports in the project's private research archive, indexed in [ROADMAP Appendix B](../ROADMAP.md#appendix-b-report-index-private-research-archive). Their public conclusions are the ledger entries above.

## How milestones close now

A milestone closes only when every exit criterion links an artifact (a CI run, a transaction hash, a drill log or a report) and the named gatekeeper has signed the closing issue. A commit message never declares a milestone done ([ROADMAP §9.5](../ROADMAP.md#95-single-source-of-status-fixing-the-stale-docs-problem)).
