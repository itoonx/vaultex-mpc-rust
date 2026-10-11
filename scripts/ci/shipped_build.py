#!/usr/bin/env python3
"""Shipped-build guard for the node and gateway (ROADMAP M5 #8).

Builds the two binaries with the command infra/docker/Dockerfile ships them with,
`cargo build --release -p mpc-wallet-api -p mpc-wallet-node` (plus --locked), and fails if any
workspace crate in that build has a forbidden feature enabled:
  local-transport   in-process transport plus cached reduced-size test parameters
  gg20-simulation   simulated legacy signing
  dev-unfreeze      debug-only override of the release freeze
  experimental[-*]  quarantined code (ROADMAP §3.5)
Selecting only these two packages keeps other members' features out: `--workspace` would unify in
the CLI's dependency on mpc-wallet-core/local-transport.

Before that, a canary rebuild with mpc-wallet-core/local-transport must be flagged by the same
check, and each binary from it must refuse to start (the startup guard in its main.rs). A guard
that is never seen to fire proves nothing. The shipped build runs last, so target/release ends up
holding the shipped binaries.

Usage:
  python3 scripts/ci/shipped_build.py [--no-canary]
CI runs it in a fresh checkout with no build cache, so the target dir starts empty. Stdlib only.
"""

import argparse
import json
import os
import re
import subprocess
import sys

PACKAGES = ["mpc-wallet-api", "mpc-wallet-node"]
BINARIES = ["mpc-wallet-api", "mpc-node"]
FORBIDDEN = re.compile(r"local-transport|gg20-simulation|dev-unfreeze|experimental(-.*)?")
CANARY_FEATURE = "mpc-wallet-core/local-transport"
CANARY_FLAG = "mpc_wallet_core/local-transport"  # how forbidden() names it (target name)
GUARD_MARKER = "shipped-build guard:"  # printed by the startup guard in both main.rs


def parse(lines):
    """From `cargo build --message-format=json` output, return ({target: features} for workspace
    crates, {executable file name: path})."""
    features, executables = {}, {}
    for line in lines:
        if not line.startswith("{"):
            continue
        msg = json.loads(line)
        if msg.get("reason") != "compiler-artifact":
            continue
        if msg.get("executable"):
            executables[os.path.basename(msg["executable"])] = msg["executable"]
        # Workspace members are path packages; registry and git crates' feature names are not ours.
        if "path+file://" in msg["package_id"]:
            features.setdefault(msg["target"]["name"], set()).update(msg["features"])
    return features, executables


def forbidden(features):
    """Every forbidden feature as "target/feature", sorted."""
    return sorted(
        f"{target}/{feature}"
        for target, enabled in features.items()
        for feature in enabled
        if FORBIDDEN.fullmatch(feature)
    )


def build(*extra):
    cmd = ["cargo", "build", "--release", "--locked", "--message-format=json-render-diagnostics"]
    for package in PACKAGES:
        cmd += ["-p", package]
    cmd += extra
    print("+ " + " ".join(cmd), flush=True)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)  # diagnostics stay on stderr
    if proc.returncode:
        sys.exit(f"FAIL: cargo build exited {proc.returncode}")
    return parse(proc.stdout.splitlines())


def refuses_to_start(exe):
    """True if `exe` exits non-zero with the guard message. The guard runs before any config is
    read, so an empty environment is enough; the timeout only bounds a binary whose guard failed."""
    try:
        proc = subprocess.run(
            [exe], env={}, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30
        )
    except subprocess.TimeoutExpired:
        return False
    return proc.returncode != 0 and GUARD_MARKER in proc.stderr


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--no-canary", action="store_true", help="skip the canary rebuild")
    args = ap.parse_args()
    failures = []

    if not args.no_canary:
        features, executables = build("--features", CANARY_FEATURE)
        if CANARY_FLAG not in forbidden(features):
            failures.append(f"canary: the feature check did not flag {CANARY_FEATURE}")
        for name in BINARIES:
            if name not in executables or not refuses_to_start(executables[name]):
                failures.append(f"canary: {name} built with test parameters did not refuse to start")
        print(f"canary: {'FAILED' if failures else 'ok (flagged, both binaries refused to start)'}")

    features, executables = build()
    for name in BINARIES:
        if name not in executables:
            failures.append(f"shipped build did not produce {name}")
    failures += [f"shipped build links forbidden feature {f}" for f in forbidden(features)]

    print("Workspace crates in the shipped build and their features:")
    for target in sorted(features):
        print(f"  {target}: {', '.join(sorted(features[target])) or '(none)'}")
    for failure in failures:
        print(f"FAIL: {failure}")
    if failures:
        sys.exit(1)
    print("shipped-build guard: ok")


if __name__ == "__main__":
    main()
