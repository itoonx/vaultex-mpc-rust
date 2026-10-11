"""Tests for sloc.py. Run: python3 -B -m unittest discover -s scripts/ci -p test_sloc.py"""

import os
import tempfile
import textwrap
import unittest

import sloc


def count(src):
    return sloc.count_file(textwrap.dedent(src))


class CountFile(unittest.TestCase):
    def test_blank_and_comment_lines_do_not_count(self):
        self.assertEqual(count("""
            // line comment
            /// doc comment
            //! inner doc comment

            /* block
               comment */
            /* outer /* nested */ still comment */
        """), 0)

    def test_code_with_comments_counts_once(self):
        self.assertEqual(count("""
            let a = 1; // trailing
            /* lead */ let b = 2;
            /* multi
            */ let c = 3;
        """), 3)

    def test_comment_markers_inside_literals_are_code(self):
        self.assertEqual(count("""
            let s = "// not a comment /* nor this";
            let t = 1;
            let r = r#"a " { // "#;
            let u = br"\\";
            let q = '"';
            let v = 2;
        """), 6)

    def test_lifetimes_and_char_literals(self):
        self.assertEqual(count("""
            fn f<'a>(x: &'a str) -> char {
                let _ = '\\'';
                '{'
            }
        """), 4)

    def test_cfg_test_module_is_excluded(self):
        self.assertEqual(count("""
            fn a() {}
            #[cfg(test)]
            #[allow(dead_code)]
            mod tests {
                fn b() { let s = "}"; let c = '}'; }
                // }
                /* } */
            }
            fn c() {}
        """), 2)

    def test_cfg_test_one_line_module_and_feature_gated_code(self):
        self.assertEqual(count("""
            #[cfg(test)] mod t { fn x() {} }
            #[cfg(any(test, feature = "local-transport"))]
            fn shipped_with_feature() {}
        """), 2)


class Collect(unittest.TestCase):
    def test_excluded_directories(self):
        with tempfile.TemporaryDirectory() as repo:
            files = {
                "crates/x/src/lib.rs": "fn a() {}\n",
                "crates/x/src/m/mod.rs": "fn b() {}\nfn c() {}\n",
                "crates/x/tests/t.rs": "fn t() {}\n",
                "crates/x/benches/b.rs": "fn b() {}\n",
                "crates/x/examples/e.rs": "fn e() {}\n",
                "crates/x/fuzz/fuzz_targets/f.rs": "fn f() {}\n",
                "crates/x/README.md": "text\n",
            }
            for path, body in files.items():
                os.makedirs(os.path.dirname(os.path.join(repo, path)), exist_ok=True)
                with open(os.path.join(repo, path), "w") as f:
                    f.write(body)
            counts = sloc.collect(repo, ["crates"])
        self.assertEqual(counts, {os.path.join("crates", "x", "src", "lib.rs"): 1,
                                  os.path.join("crates", "x", "src", "m", "mod.rs"): 2})
        self.assertEqual(sloc.unit_of(os.path.join("crates", "x", "src", "m", "mod.rs")),
                         ("crates/x", "m"))


if __name__ == "__main__":
    unittest.main()
