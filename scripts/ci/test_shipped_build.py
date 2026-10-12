"""Tests for shipped_build.py. Run: python3 -B -m unittest discover -s scripts/ci -p test_shipped_build.py"""

import json
import unittest

import shipped_build

WS = "path+file:///w/crates/mpc-wallet-core#0.1.0"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index#tokio@1.0.0"


def artifact(package_id, target, features, executable=None, debug_assertions=False, kind="lib"):
    return json.dumps({
        "reason": "compiler-artifact",
        "package_id": package_id,
        "target": {"name": target, "kind": [kind]},
        "profile": {"debug_assertions": debug_assertions},
        "features": features,
        "executable": executable,
    })


def check(*lines):
    features, executables, _ = shipped_build.parse(lines)
    return shipped_build.forbidden(features), executables


class Check(unittest.TestCase):
    def test_shipped_core_features_pass(self):
        self.assertEqual(check(artifact(WS, "mpc_wallet_core", ["default", "gg20-distributed"]))[0], [])

    def test_test_parameters_and_canary_are_flagged(self):
        flagged, _ = check(artifact(WS, "mpc_wallet_core", ["default", "local-transport"]))
        self.assertEqual(flagged, [shipped_build.CANARY_FLAG])

    def test_every_forbidden_feature_on_a_workspace_crate_is_flagged(self):
        flagged, _ = check(
            artifact(WS, "mpc_wallet_core", ["gg20-simulation", "experimental-frost", "experimental"]),
            artifact("path+file:///w/services/mpc-node#mpc-wallet-node@0.1.0", "mpc-node", ["dev-unfreeze"]),
        )
        self.assertEqual(flagged, [
            "mpc-node/dev-unfreeze",
            "mpc_wallet_core/experimental",
            "mpc_wallet_core/experimental-frost",
            "mpc_wallet_core/gg20-simulation",
        ])

    def test_names_only_match_whole_features(self):
        flagged, _ = check(artifact(WS, "x", ["no-local-transport", "local-transport-docs", "not-experimental"]))
        self.assertEqual(flagged, [])

    def test_third_party_feature_names_are_ignored(self):
        self.assertEqual(check(artifact(REGISTRY, "tokio", ["experimental-async"]))[0], [])

    def test_other_messages_are_ignored_and_executables_collected(self):
        flagged, executables = check(
            "   Compiling mpc-wallet-core v0.1.0",
            json.dumps({"reason": "compiler-message", "package_id": WS, "features": ["local-transport"]}),
            json.dumps({"reason": "build-finished", "success": True}),
            artifact(WS, "mpc-node", [], executable="/t/release/mpc-node"),
        )
        self.assertEqual(flagged, [])
        self.assertEqual(executables, {"mpc-node": "/t/release/mpc-node"})

    def test_debug_assertions_on_a_workspace_target_are_flagged(self):
        # The release freeze keys on cfg(debug_assertions); build scripts and registry crates don't count.
        _, _, debug = shipped_build.parse([
            artifact(WS, "mpc-node", [], debug_assertions=True, kind="bin"),
            artifact(WS, "build_script_build", [], debug_assertions=True, kind="custom-build"),
            artifact(REGISTRY, "tokio", [], debug_assertions=True),
            artifact(WS, "mpc_wallet_core", []),
        ])
        self.assertEqual(debug, {"mpc-node"})


if __name__ == "__main__":
    unittest.main()
