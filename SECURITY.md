# Security policy

Vaultex is **unaudited pre-alpha research software**. Use it on testnets only, and never with real funds. The known critical limitations are listed by category, each with its planned fix, in [SECURITY_STATUS.md](SECURITY_STATUS.md) and in the banner at the top of the [README](README.md).

This is the project's only security policy. It replaces the former `specs/SECURITY.md`.

---

## Supported versions

| Version | Fit for real funds | Receives security fixes |
|---|---|---|
| Latest commit on `main` | No | Yes |
| Every earlier tag or release (all `v0.x` tags, including `v0.1.0-audit`) | No | No. Move to the latest `main` |

- **No version is supported for real funds.** That changes only when a roadmap milestone closes on public evidence ([docs/ROADMAP.md](docs/ROADMAP.md)), and only for the scope that milestone declares.
- Fixes are made on the development branch and reach `main` through review. Earlier tags get no backports.
- Every open category in [SECURITY_STATUS.md](SECURITY_STATUS.md) affects every published version.
- The `v0.1.0-audit` tag marks an internal audit-preparation snapshot. No independent audit or external review of Vaultex has taken place.

---

## Reporting a vulnerability

Report it privately through **GitHub private vulnerability reporting**:

1. Open this repository's **Security** tab.
2. Choose **Report a vulnerability** ([direct link](https://github.com/itoonx/vaultex-mpc-rust/security/advisories/new)).

Do not report a suspected vulnerability in a public issue, pull request or discussion. If the **Report a vulnerability** button is missing, open a public issue titled "Security contact request" that contains no details. A maintainer will then open a private channel on GitHub.

GitHub is the only reporting channel. Earlier versions of this file named an email address; it is no longer a reporting channel.

Please include:

- the affected component and the version or commit;
- what the issue is, and its impact;
- steps to reproduce, using only test networks, local networks and keys you own;
- a suggested fix, if you have one;
- whether, and how, you would like to be credited.

---

## What to expect

Vaultex has one maintainer today, so these are targets, not guarantees:

| Step | Target |
|---|---|
| Acknowledge the report | Within 7 days |
| Initial assessment: valid or not, severity, and the category it falls in | Within 14 days |
| Status updates to you | At least every 30 days until the report is closed |

Severity uses GitHub's advisory levels: critical, high, moderate and low. There is no bug bounty and no payment. With your permission, we credit you in the advisory.

---

## Coordinated disclosure (90 days)

- Please keep your report private for **90 days from the day you send it**, or until a fix is released, whichever comes first. We can agree a different window with you, for example when users must re-key before details go public.
- Fixed issues get a GitHub Security Advisory, with a CVE where one applies.
- For an issue that is still unfixed, the project publishes at **category level only**: what is affected, the planned fix and what users should do. It publishes no exploit details and no pointers into the code. Detailed advisories follow only after the fix ships, affected users have had time to re-key, and a grace period has passed.
- After the 90 days you are free to publish. If the issue is still unfixed, we ask you to publish at category level as well and to leave out working exploit details, because users may still hold keys that it affects.

---

## Scope

**In scope:** all code and configuration in this repository, including `crates/`, `services/`, `infra/`, `scripts/` and the CI workflows, plus any document that makes a security claim.

**Already known:** [SECURITY_STATUS.md](SECURITY_STATUS.md) lists categories that are known and public. A report inside one of them is still welcome when it shows something the listed fix would not cover. Otherwise we may close it as a duplicate.

**Out of scope:**

- vulnerabilities in third-party dependencies that do not affect Vaultex (report them upstream, and tell us if Vaultex is affected);
- deployments run by other people (contact the operator);
- social engineering, physical attacks, and denial of service against people or infrastructure. The project runs no hosted service, so there is nothing online to test.

---

## Testing rules

- Test only on machines you control, with keys you own, on public testnets or local networks.
- Never test against mainnet, against funds or keys that are not yours, or against systems you do not own.
- Do not access, change or keep other people's data. If you reach any, stop and tell us.
- Give us the disclosure window above before you publish.

We will not take legal action against anyone who researches and reports in good faith under this policy.

---

## Security model and history

- **Current status:** [SECURITY_STATUS.md](SECURITY_STATUS.md), by category and fix.
- **Design target:** [docs/ROADMAP.md §3.3](docs/ROADMAP.md#33-the-differentiator-precisely) (proposed). It describes where the project is going, not the code at HEAD.
- **Internal notes:** [docs/SECURITY_FINDINGS.md](docs/SECURITY_FINDINGS.md) and [docs/SECURITY_AUDIT_AUTH.md](docs/SECURITY_AUDIT_AUTH.md) were written by AI agents during development. They are not independent audits, and their "resolved" statuses do not cover the categories in [SECURITY_STATUS.md](SECURITY_STATUS.md).
