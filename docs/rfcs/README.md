# RFCs

An RFC specifies a public, versioned format or interface precisely enough that an independent implementation, written from the text alone, produces the same bytes and the same accept or refuse result. Examples: intents, policy bundles, receipts, and later the MPC-phase contracts.

An RFC specifies **how** something is encoded and checked. A choice between options (scope, licence, trust model) is an ADR instead (see [`../adr/README.md`](../adr/README.md)).

Owner of this process: WS-03 (R0). Each RFC is written by the workstream that implements it.

## Where RFCs live

- The RFC text is the normative spec file `specs/<NAME>_V<n>.md`, for example `specs/INTENT_V1.md`. It starts with the header list from the template below.
- Test vectors are files next to the implementation or under `specs/`; the header gives their path. Vectors are data files, not prose.
- This directory holds the process, the template and the index.

## Statuses

| Status | Meaning | Allowed next |
|---|---|---|
| `DRAFT` | Text and vectors may still change. Code may implement a draft, but nothing outside the repo should depend on it. | `COMMENT`, `WITHDRAWN` |
| `COMMENT` | Open for public comment for at least 14 days (`docs/ROADMAP.md` §4.3 M6 #7). The owner posts it publicly; agents never do. The header records the window's start and end dates. A normative change during the window restarts it. | `ACCEPTED`, `DRAFT`, `WITHDRAWN` |
| `ACCEPTED` | The bytes are frozen. Requires all of: the comment window has closed; every comment has a recorded answer; the vectors are reproduced by an independent implementation written from the RFC text only, by a different author or agent from the Rust code (WS-13); and R0 and the owner approve. | `SUPERSEDED` |
| `SUPERSEDED` | A later version replaces it. Add `Superseded by: <NAME>_V<n+1>` to the header list. | none |
| `WITHDRAWN` | Abandoned. One line says why. | none |

## Versioning

- `<NAME>_V<n>` names exactly one byte-level format.
- After `ACCEPTED`, a change that alters encoded bytes, a digest or signature input, or the accept or refuse result of any vector needs a new RFC, `<NAME>_V<n+1>`. The new RFC states which older versions an implementation must still accept.
- Editorial fixes that change no bytes and no result are allowed at any status, with a dated line in the RFC's changelog.
- Contract changes after the v0 freeze are versioned additions reviewed by R0 and a human (`docs/ROADMAP.md` §5.0 rule 2).

## Rules

1. **One canonical encoding per RFC.** The encoding choice (for example BCS or RFC 8785 JCS) is open in T03-1. Each RFC names exactly one encoding and says how a decoder refuses non-canonical input.
2. **Every rule has a vector.** Each validation rule has at least one refuse vector naming the rule and the expected refusal code, and the accept vectors cover every accepted shape.
3. **Public-safe.** Security considerations stay at category level: no exploit mechanics, no file:line pointers to unfixed defects, no secret names or locations, no internal business details.
4. **No unbacked status claims.** An RFC states the status of code or assurance only when a claims-ledger entry backs it (`docs/ROADMAP.md` §9.5).

## Template

Copy this block into `specs/<NAME>_V<n>.md` and replace each `<…>`. Key words such as MUST, SHOULD and MAY follow RFC 2119 and RFC 8174.

```markdown
# <NAME>_V<n>: <title>

- RFC: <NAME>_V<n>
- Status: DRAFT
- Writer: WS-<NN> (<roles>)
- Implementation: <crate and module>
- Vectors: <path to vector files>
- Comment window: <YYYY-MM-DD> to <YYYY-MM-DD>, or "not yet open"
- Discussion: <issue or discussion link, once public>
- Supersedes: <NAME>_V<n-1>, or "none"
- Related ADRs: <ADR IDs, or "none">

## 1. Summary

<What this format is for, in three sentences or fewer.>

## 2. Scope

<What is in scope, what is explicitly out of scope, and the caller/verifier boundary.>

## 3. Terminology

<Terms used in the rules below. Key words follow RFC 2119 and RFC 8174.>

## 4. Data model

<Every field: name, type, allowed range, required or optional, and meaning.>

## 5. Canonical encoding

<The exact byte layout in one named encoding, field order, length limits, and how a decoder refuses non-canonical input (re-encode and compare bytes).>

## 6. Digests and signatures

<Domain-separation tags, hash function, signature scheme, and exactly which bytes are hashed and signed.>

## 7. Validation and refusal

<Numbered rules an implementation MUST check, each with its refusal code. Anything not explicitly accepted is refused.>

## 8. Versioning and compatibility

<How the version is carried in the bytes, and which older versions an implementation accepts.>

## 9. Test vectors

<Vector file format; accept vectors; refuse vectors, each naming the rule in §7 and the expected refusal code; how CI runs them against both implementations.>

## 10. Security considerations

<Threats this format addresses or leaves open, at category level only.>

## 11. Open questions

<Empty before ACCEPTED.>

## 12. Changelog

- <YYYY-MM-DD>: <change>
```

## Index

The `Status:` line in each spec file is authoritative; this table lists planned RFCs only.

| RFC | Spec file | Writer | Task |
|---|---|---|---|
| `INTENT_V1` | `specs/INTENT_V1.md` | WS-05 | T05-7a |
| `RECEIPT_V1` | `specs/RECEIPT_V1.md` | WS-05 | T05-7a |
| `POLICY_BUNDLE_V1` | `specs/POLICY_BUNDLE_V1.md` | WS-05 | T05-7b |
| Contracts v2 | to be named at G-MPC | WS-03 | T03-4 |
