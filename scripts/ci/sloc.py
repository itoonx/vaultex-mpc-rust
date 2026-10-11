#!/usr/bin/env python3
"""Production-SLOC counter for Vaultex (ROADMAP §3.5 "Budget", M5 #9).

Production SLOC = lines of Rust that contain code, by the roadmap's counting rule (its 26.3k baseline
also counted examples/; without them the baseline tree gives 26,238):
  - files: every *.rs under the given roots (default: crates/ and services/);
  - excluded files: anything under a tests/, benches/, examples/, fuzz/ or target/ directory;
  - excluded lines: blank lines, comment-only lines (//, ///, //!, nested /* */), and every line of an
    in-file `#[cfg(test)] mod ... { ... }` block, attribute line included.
A line that holds any code outside a comment counts once; so does a non-blank line inside a string.

Usage:
  python3 scripts/ci/sloc.py [ROOT ...] [--json FILE]
Prints a Markdown report to stdout; --json also writes per-file counts. Stdlib only, no build needed.
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

EXCLUDED_DIRS = {"tests", "benches", "examples", "fuzz", "target"}
RAW_STRING = re.compile(r'b?r(#*)"')
IDENT = re.compile(r"[A-Za-z0-9_]")
CFG_TEST = re.compile(r"#\[cfg\(test\)\]")
MOD_DECL = re.compile(r"(pub(\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*([{;])")


def strip_code(text):
    """Return one string per source line: the code on that line with comments and literal contents
    removed (quotes stay, so a line holding only a literal still counts as code)."""
    out = []
    depth = 0  # block-comment nesting depth
    in_str = False  # inside a normal "..." string (backslash escapes apply)
    raw_end = None  # closing token of the raw string we are inside, e.g. '"#'
    for line in text.split("\n"):
        code = []
        i, n = 0, len(line)
        while i < n:
            c = line[i]
            if depth:
                if line.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif line.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            elif in_str:
                code.append("s")  # literal content is code, but opens no brace or comment
                if c == "\\":
                    i += 2
                else:
                    in_str, i = c != '"', i + 1
            elif raw_end:
                code.append("s")
                if line.startswith(raw_end, i):
                    i, raw_end = i + len(raw_end), None
                else:
                    i += 1
            elif line.startswith("//", i):
                break
            elif line.startswith("/*", i):
                depth, i = 1, i + 2
            elif c == '"':
                code.append(c)
                in_str, i = True, i + 1
            elif c in "br" and not (i and IDENT.match(line[i - 1])) and RAW_STRING.match(line, i):
                m = RAW_STRING.match(line, i)
                code.append(m.group(0))
                raw_end, i = '"' + m.group(1), m.end()
            elif c == "'":
                # A char literal ('x', '\n', '\u{..}', '"') or a lifetime ('a, 'static).
                if line.startswith("\\", i + 1):
                    end = line.find("'", i + 3)
                    i = n if end < 0 else end + 1
                    code.append("'c'")
                elif i + 2 < n and line[i + 2] == "'":
                    code.append("'c'")
                    i += 3
                else:
                    code.append(c)
                    i += 1
            else:
                code.append(c)
                i += 1
        out.append("".join(code).strip())
    return out


def count_file(text):
    """Production SLOC of one Rust source file."""
    code = strip_code(text)
    total, i, n = 0, 0, len(code)
    while i < n:
        attr = CFG_TEST.match(code[i])
        if attr:
            # The item the cfg(test) applies to: rest of this line, else the next line that is
            # not blank and not another attribute.
            j, item = i, code[i][attr.end() :].strip()
            if not item:
                j += 1
                while j < n and (not code[j] or code[j].startswith("#[")):
                    j += 1
                item = code[j] if j < n else ""
            mod = MOD_DECL.match(item)
            if mod:
                # ponytail: brace count on comment- and literal-stripped text is enough for test
                # modules. A `#[cfg(test)] mod x;` file would sit outside this file; none exist.
                bal = item.count("{") - item.count("}")
                while bal > 0 and j + 1 < n:
                    j += 1
                    bal += code[j].count("{") - code[j].count("}")
                i = j + 1
                continue
        if code[i]:
            total += 1
        i += 1
    return total


def collect(repo, roots):
    """Map repo-relative path → production SLOC for every counted file under roots."""
    counts = {}
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(os.path.join(repo, root)):
            dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
            for name in sorted(filenames):
                if name.endswith(".rs"):
                    path = os.path.join(dirpath, name)
                    with open(path, encoding="utf-8") as f:
                        counts[os.path.relpath(path, repo)] = count_file(f.read())
    return counts


def unit_of(path):
    """('crates/mpc-wallet-core', 'protocol') for crates/mpc-wallet-core/src/protocol/gg20.rs."""
    parts = path.split(os.sep)
    crate = "/".join(parts[:2])
    rest = parts[2:]
    if rest and rest[0] == "src" and len(rest) > 1:
        rest = rest[1:]
    module = rest[0][:-3] if len(rest) == 1 and rest[0].endswith(".rs") else rest[0]
    return crate, module


def markdown(counts, rev):
    crates, modules = defaultdict(int), defaultdict(int)
    for path, n in counts.items():
        crate, module = unit_of(path)
        crates[crate] += n
        modules[(crate, module)] += n
    total = sum(counts.values())
    lines = [
        "# Production SLOC report",
        "",
        f"Revision: `{rev}` · Files counted: {len(counts)} · **Total: {total:,}**",
        "",
        "Counting rule: non-blank, non-comment Rust lines under the counted roots, excluding "
        "`tests/`, `benches/`, `examples/`, `fuzz/` and in-file `#[cfg(test)] mod` blocks "
        "(`scripts/ci/sloc.py`). This is the whole tree, not yet the default release build.",
        "",
        "## By crate",
        "",
        "| Crate | SLOC |",
        "|---|---:|",
    ]
    lines += [f"| `{c}` | {n:,} |" for c, n in sorted(crates.items())]
    lines += [f"| **Total** | **{total:,}** |", "", "## By module", "", "| Crate | Module | SLOC |",
              "|---|---|---:|"]
    lines += [f"| `{c}` | `{m}` | {n:,} |" for (c, m), n in sorted(modules.items())]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("roots", nargs="*", default=["crates", "services"],
                    help="directories to count, relative to the repo root")
    ap.add_argument("--json", metavar="FILE", help="also write {total, files: {path: sloc}} here")
    args = ap.parse_args(argv)
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    missing = [r for r in args.roots if not os.path.isdir(os.path.join(repo, r))]
    if missing:
        sys.exit(f"sloc: no such directory under the repo root: {', '.join(missing)}")
    counts = collect(repo, args.roots)
    rev = os.environ.get("GITHUB_SHA", "working tree")
    sys.stdout.write(markdown(counts, rev))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"revision": rev, "roots": args.roots, "total": sum(counts.values()),
                       "files": dict(sorted(counts.items()))}, f, indent=2)
            f.write("\n")


if __name__ == "__main__":
    main()
