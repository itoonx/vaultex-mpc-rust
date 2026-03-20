# Security Policy

## Project

**MPC Wallet SDK (Vaultex)** — Threshold multi-party computation wallet SDK for enterprise custody systems.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly. **Do not open a public GitHub issue.**

**Email:** [security@vaultex.io](mailto:security@vaultex.io)

**PGP Key:** Available upon request. Contact the security email to receive our public PGP key for encrypted communications.

Please include the following in your report:

- Description of the vulnerability
- Steps to reproduce or proof-of-concept
- Affected component (e.g., protocol, transport, key store, chain provider)
- Potential impact assessment
- Any suggested remediation

## Response SLA

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within **48 hours** of receipt |
| Triage and severity assessment | Within **7 business days** |
| Status update to reporter | Every **14 days** until resolution |
| Fix development and release | Based on severity (see below) |

### Severity-Based Fix Timelines

| Severity | Target Resolution |
|----------|-------------------|
| CRITICAL | 72 hours |
| HIGH | 14 days |
| MEDIUM | 30 days |
| LOW / INFO | Next scheduled release |

## Scope

The following are **in scope** for this security policy:

- All code in this repository (`crates/`, `services/`, `specs/`)
- Cryptographic protocol implementations (GG20, CGGMP21, FROST)
- Paillier encryption and zero-knowledge proofs
- Key generation, storage, and zeroization
- Transport layer security (signed envelopes, session encryption)
- Authentication and authorization (mTLS, JWT, session management)
- Sign authorization and policy enforcement
- MPC node ↔ gateway communication
- Chain-specific transaction building and signature handling

## Out of Scope

The following are **out of scope**:

- Social engineering attacks against project maintainers or users
- Denial-of-service attacks against hosted infrastructure
- Vulnerabilities in third-party dependencies (report these upstream; notify us if they affect this project)
- Attacks requiring physical access to hardware running MPC nodes
- Issues in example/demo code clearly marked as non-production (`#[cfg(test)]`, `feature = "demo"`)

## Safe Harbor

We consider security research conducted in accordance with this policy to be:

- **Authorized** under applicable anti-hacking laws
- **Exempt** from DMCA restrictions on circumvention of technological measures
- **Lawful, helpful, and conducted in good faith**

We will not pursue legal action against researchers who:

1. Act in good faith to avoid privacy violations, data destruction, and service disruption
2. Only interact with accounts they own or with explicit permission of the account holder
3. Report vulnerabilities promptly and do not publicly disclose details before a fix is available
4. Do not exploit vulnerabilities beyond what is necessary to demonstrate the issue
5. Provide sufficient detail for us to reproduce and address the vulnerability

If legal action is initiated by a third party against you for activities conducted in accordance with this policy, we will take steps to make it known that your actions were authorized.

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter submits vulnerability via the security email
2. We acknowledge, triage, and develop a fix
3. We coordinate a disclosure date with the reporter (typically 90 days from report)
4. Fix is released and advisory is published
5. Reporter may publish their findings after the coordinated disclosure date

## Recognition

We maintain a security acknowledgments page for researchers who report valid vulnerabilities. If you would like to be credited, please indicate so in your report.

## Contact

- **Security reports:** security@vaultex.io
- **General questions:** Open a GitHub issue (non-security topics only)
