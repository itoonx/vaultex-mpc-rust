"""Tests for claims_lint.sh. Run: python3 -B -m unittest discover -s scripts/ci -p test_claims_lint.py

Each test builds a one-claim ledger in a scratch git repository, with the real claims/claims.py and
claims/schema.toml, and checks that the lint passes it and turns red on each kind of drift.
"""

import pathlib
import shutil
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]

# Fixed dates and --today keep the fixture independent of the clock.
CLAIM = """schema = 1
id = "01.research"
kind = "process"
status = "hypothesis"
text = "Vaultex is research software."
surfaces = ["README.md"]
quotes = ["Vaultex is research software"]
observed = 2026-10-01
expires = 2026-10-31
"""


class ClaimsLint(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        (self.root / "scripts" / "ci").mkdir(parents=True)
        (self.root / "claims" / "01").mkdir(parents=True)
        shutil.copy2(REPO / "scripts" / "ci" / "claims_lint.sh", self.root / "scripts" / "ci")
        for name in ("claims.py", "schema.toml"):
            shutil.copy2(REPO / "claims" / name, self.root / "claims")
        self.write("claims/surfaces.toml", '[[surface]]\npath = "README.md"\nlang = "en"\n')
        self.write("README.md", "# Fixture\n\nVaultex is research software.\n")
        self.write("claims/01/research.toml", CLAIM)
        subprocess.run(["python3", "-I", "claims/claims.py", "render"], cwd=self.root, check=True,
                       capture_output=True)
        self.git("init", "-q")
        self.git("add", "-A")

    def write(self, path, text):
        (self.root / path).parent.mkdir(parents=True, exist_ok=True)
        (self.root / path).write_bytes(text.encode("utf-8"))

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True)

    def lint(self):
        r = subprocess.run(["bash", str(self.root / "scripts" / "ci" / "claims_lint.sh"),
                            "--no-git", "--today", "2026-10-11"], capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr

    def test_clean_ledger_passes(self):
        code, out = self.lint()
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count("\nok\n"), 2, out)

    def test_hand_edit_of_claims_md_fails_and_is_left_alone(self):
        edited = (self.root / "CLAIMS.md").read_text(encoding="utf-8") + "Audited and production-ready.\n"
        self.write("CLAIMS.md", edited)
        code, out = self.lint()
        self.assertEqual(code, 1, out)
        self.assertIn("(R9)", out)
        self.assertIn("differs byte-for-byte", out)
        self.assertEqual((self.root / "CLAIMS.md").read_text(encoding="utf-8"), edited)

    def test_crlf_claims_md_fails_on_the_byte_check(self):
        path = self.root / "CLAIMS.md"
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        code, out = self.lint()
        self.assertEqual(code, 1, out)
        self.assertIn("surfaces: ok", out)  # claims.py check alone folds CRLF and passes
        self.assertIn("differs byte-for-byte", out)

    def test_schema_violation_fails(self):
        # The renderer ignores unknown fields, so only the schema check can catch this one.
        self.write("claims/01/research.toml", CLAIM + 'verdict = "complete"\n')
        code, out = self.lint()
        self.assertEqual(code, 1, out)
        self.assertIn("unknown field 'verdict'", out)
        self.assertEqual(out.count("\nok\n"), 2, out)  # the byte and file checks still pass

    def test_misplaced_claim_files_fail(self):
        for path in ("claims/1/typo.toml", "claims/01/typo.tml", "claims/01/nested/x.toml", "claims/loose.toml"):
            self.write(path, CLAIM)
        self.write("claims/README.md", "Not a claim; top-level non-TOML files are allowed.\n")
        self.git("add", "-A")
        code, out = self.lint()
        self.assertEqual(code, 1, out)
        self.assertIn("surfaces: ok", out)  # the renderer never reads these files
        for path in ("claims/1/typo.toml", "claims/01/typo.tml", "claims/01/nested/x.toml", "claims/loose.toml"):
            self.assertIn(f"  {path}\n", out)
        self.assertNotIn("claims/README.md", out)


if __name__ == "__main__":
    unittest.main()
