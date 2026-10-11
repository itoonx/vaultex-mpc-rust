# Threat model

The current threat model is **[version 2](assurance/THREAT_MODEL_V2.md)** (draft, 2026-10-11). It covers:
- the Phase-1 verifier kernel, Guard co-signer and outflow monitor;
- the target MPC architecture of verifying nodes and a gateway relay.

For each, it lists the security objectives, assets, trust boundaries and actors, including a compromised gateway, a compromised Guard host and insiders. Every threat category is mapped to the roadmap milestone whose control addresses it and the evidence that proves the control. It is written at category level only.

For the known security limitations of the code at HEAD, read [`SECURITY_STATUS.md`](../SECURITY_STATUS.md). To report a vulnerability, follow [`SECURITY.md`](../SECURITY.md).

## Version 1 (withdrawn)

Version 1 (2026-04-01) is withdrawn. It described the legacy gateway and node design as if its controls were effective, and it reported every known finding as resolved. Neither matched the code: see categories 1–4 of [`SECURITY_STATUS.md`](../SECURITY_STATUS.md). Do not rely on it. It remains only in the git history.
