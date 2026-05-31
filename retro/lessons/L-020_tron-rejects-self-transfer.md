# L-020: TRON rejects self-transfer — native-coin self-sends are not a universal smoke-test primitive

- **Date:** 2026-06-01
- **Category:** Live broadcast / chain validator rules
- **Severity:** Low (caught immediately at broadcast; non-silent, MPC sign + encode were correct)
- **Found by:** Sprint 52 — chain registry refactor E2E gate (live re-broadcast on all 6 chains)

## What happened

The Sprint 52 smoke-test pattern was a tiny **self-transfer** (sender == recipient)
on each chain — the same trick used in Sprints 45–50 for token tests. It worked
on EVM, Solana, Bitcoin, Sui, and Aptos. On TRON Shasta it failed at broadcast:

    Error: broadcast failed: TRON broadcast rejected:
      code=CONTRACT_VALIDATE_ERROR
      msg='Contract validate error : Cannot transfer TRX to yourself.'

Critically, everything *before* broadcast succeeded:

    ✓ Signed
    ✓ Encoded tx: raw_len=132 sig_len=65 (ECDSA r|s|v)
    ✓ Signature recovers to sender TGbSVxCm4yConwQyQQifV5We2Zmany8SFS (verified)

So this is **not** an MPC, encoding, or refactor bug. The TRON node's
`TransferContract` validator explicitly forbids `owner_address == to_address`.

## Root cause

TRON's full-node contract validation rejects a `TransferContract` whose
`to_address` equals `owner_address`. Most other chains have no such rule —
a self-send is a valid no-op-ish transaction that still pays fees and bumps
nonce/sequence. The self-transfer smoke-test silently depended on that
permissiveness.

## Fix / workaround

Send to a **second address the test operator controls** instead of self.
TRON addresses derive from the same secp256k1 pubkey as EVM, so any other
GG20 key group yields a usable TRON recipient:

    mpc-wallet export-address --key-group <other-gg20-group> --chain tron --password <pw>
    # → TE8xGvXfuYQijhYKDoFizRWQXjNv3u11CS  (derived from the Sepolia GG20 group)

Then `--to` that address. Broadcast succeeded:
`5821dd9dd0bac3361ae5380ba0a116ec4059ae26d7345cb4dc8dd4c07204b404` (contractRet SUCCESS).

## Lesson

- A self-transfer is **not** a portable "does signing+broadcast work" primitive.
  Validator-level rules differ per chain; TRON is the known exception in this repo.
- For any future cross-chain live smoke test, keep a **second controlled recipient
  per chain** in `funded-wallets.local.json` rather than relying on self-send.
- The diagnostic ladder (sign → encode → recover/verify → broadcast) correctly
  isolated the failure to the remote validator, not our code — keep printing the
  recover/verify line before every broadcast so chain-rule rejections are obviously
  distinct from signing bugs.
