#!/usr/bin/env python3
"""Claims ledger: validate claims/<ws>/*.toml and render CLAIMS.md.

    python3 -I claims/claims.py render                 # rewrite CLAIMS.md
    python3 -I claims/claims.py check [--today DATE] [--no-git]

`check` applies rules R1-R9 from claims/schema.toml, prints one line per
finding and exits 1 if there is any. `render` output is deterministic: claims
are sorted by id, lines end in LF, and nothing depends on the clock, the locale,
the hash seed or the order in which the filesystem lists files.

Stdlib only (Python >= 3.11 for tomllib).
"""

import argparse
import datetime as dt
import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEDGER = ROOT / "claims"
OUTPUT = ROOT / "CLAIMS.md"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CI_RUN_RE = re.compile(r"^https://github\.com/[^/]+/[^/]+/actions/runs/[0-9]+$")
EXPIRY_WARNING_DAYS = 14


def load_toml(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def load_claims():
    """Return [(path, data)] for every claims/<ws>/*.toml, sorted by path."""
    return [(p, load_toml(p)) for p in sorted(LEDGER.glob("[0-9][0-9]/*.toml"))]


def rel(path):
    return path.relative_to(ROOT).as_posix()


# ------------------------------------------------------------------ check


def type_ok(value, kind):
    if kind == "string":
        return isinstance(value, str) and value.strip() != ""
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "date":
        return isinstance(value, dt.date) and not isinstance(value, dt.datetime)
    if kind == "array":
        return isinstance(value, list) and all(isinstance(v, str) and v for v in value)
    if kind == "array-of-tables":
        return isinstance(value, list) and all(isinstance(v, dict) for v in value)
    if kind == "table":
        return isinstance(value, dict)
    raise ValueError(f"schema.toml: unknown field type {kind!r}")


class Git:
    """Read-only, cached lookups against the local git history."""

    def __init__(self):
        self.cache = {}

    def _run(self, *args):
        if args not in self.cache:
            r = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True,
                               encoding="utf-8", errors="replace")
            self.cache[args] = r.stdout if r.returncode == 0 else None
        return self.cache[args]

    def has_commit(self, sha):
        return self._run("cat-file", "-t", sha) == "commit\n"

    def show(self, sha, path):
        return self._run("show", f"{sha}:{path}")


def check_evidence(where, item, schema, git):
    errors = []
    etype = item.get("type")
    spec = schema["evidence_type"].get(etype)
    if spec is None:
        return [f"{where}: unknown evidence type {etype!r}"]
    allowed = {"type", "note", *spec["required"]}
    errors += [f"{where}: {etype} evidence needs {k!r}" for k in spec["required"] if not item.get(k)]
    errors += [f"{where}: unexpected key {k!r} in {etype} evidence" for k in sorted(set(item) - allowed)]
    if errors:
        return errors
    if etype == "ci_run" and not CI_RUN_RE.match(item["url"]):
        errors.append(f"{where}: ci_run url is not a pinned Actions run URL")
    sha = item.get("commit")
    if sha is None:
        return errors
    if not SHA_RE.match(sha):
        return errors + [f"{where}: commit must be a full 40-hex SHA, got {sha!r}"]
    if git is None:
        return errors
    if not git.has_commit(sha):
        return errors + [f"{where}: commit {sha[:12]} is not in local git history (CI needs fetch-depth: 0)"]
    path = {
        "code": item["ref"].split("::")[0],
        "test": item.get("path"),
        "report": item["ref"].split("#")[0],
    }.get(etype)
    if path:
        blob = git.show(sha, path)
        if blob is None:
            errors.append(f"{where}: {path} does not exist at {sha[:12]}")
        elif etype == "test":
            name = item["ref"].split("::")[-1]
            if not re.search(rf"\bfn {re.escape(name)}\s*\(", blob):
                errors.append(f"{where}: no `fn {name}` in {path} at {sha[:12]}")
        elif etype == "code" and "::" in item["ref"]:
            symbol = item["ref"].split("::", 1)[1]
            if not re.search(rf"\b{re.escape(symbol)}\b", blob):
                errors.append(f"{where}: symbol {symbol!r} not found in {path} at {sha[:12]}")
    return errors


def claim_bearing_lines(text):
    """Yield (line_no, stripped_line) for the lines rule R7 must cover."""
    # ponytail: only ``` fences are recognised, and fenced blocks are skipped
    # whole. Claims inside them (the README project tree) are mapped by quote
    # (R6) but not coverage-enforced; split such blocks out if that matters.
    lines = text.split("\n")
    fenced = False
    for i, raw in enumerate(lines):
        line = raw.strip()
        if line.startswith("```"):
            fenced = not fenced
            continue
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
        if (
            fenced
            or not line
            or line.startswith("#")
            or re.fullmatch(r"-{3,}|\*{3,}", line)
            or re.fullmatch(r"\|[\s:|-]+\|", line)  # table delimiter row
            or (line.startswith("|") and re.fullmatch(r"\|[\s:|-]+\|", nxt))  # table header row
            or re.fullmatch(r">\s*(\[![A-Z]+\])?", line)  # empty quote / alert marker
            or re.fullmatch(r"(<[^>]+>\s*)+", line)  # HTML-only line
        ):
            continue
        yield i + 1, line


def check(today, use_git):
    schema = load_toml(LEDGER / "schema.toml")
    surfaces = {s["path"]: s for s in load_toml(LEDGER / "surfaces.toml").get("surface", [])}
    git = Git() if use_git else None
    errors, warnings = [], []
    claims = {}

    for path, data in load_claims():
        where = rel(path)
        cid = data.get("id")
        before = len(errors)
        # Generic field checks driven by schema.toml.
        for name in sorted(set(data) - set(schema["field"])):
            errors.append(f"{where}: unknown field {name!r}")
        for name, spec in schema["field"].items():
            if name not in data:
                if spec.get("required"):
                    errors.append(f"{where}: missing required field {name!r}")
                continue
            value = data[name]
            if not type_ok(value, spec["type"]):
                errors.append(f"{where}: field {name!r} must be a non-empty {spec['type']}")
            elif "enum" in spec and value not in spec["enum"]:
                errors.append(f"{where}: {name} = {value!r} is not one of {spec['enum']}")
            elif "pattern" in spec and not re.match(spec["pattern"], value):
                errors.append(f"{where}: {name} = {value!r} does not match {spec['pattern']}")
        if data.get("schema") != schema["version"]:
            errors.append(f"{where}: schema must be {schema['version']}")
        if len(errors) > before:
            continue  # the rules below assume well-typed fields
        # R1
        expected = f"{path.parent.name}.{path.stem}"
        if cid != expected:
            errors.append(f"{where}: id must be {expected!r} (R1)")
            continue
        claims[cid] = (where, data)
        status, kind = data.get("status"), data.get("kind")
        evidence = data.get("evidence", [])
        # R2
        if status in ("verified", "limitation") and not evidence:
            errors.append(f"{where}: status {status} needs at least one evidence item (R2)")
        # R4
        observed, expires = data.get("observed"), data.get("expires")
        if status == "withdrawn":
            if "expires" in data:
                errors.append(f"{where}: a withdrawn claim has no expiry (R4)")
        elif expires is None:
            errors.append(f"{where}: missing field 'expires' (R4)")
        elif type_ok(observed, "date") and type_ok(expires, "date") and kind in schema["max_age_days"]:
            max_age = schema["max_age_days"][kind]
            if not observed < expires <= observed + dt.timedelta(days=max_age):
                errors.append(f"{where}: expires must be after observed and within {max_age} days for kind {kind} (R4)")
            if expires < today:
                errors.append(f"{where}: expired on {expires}; re-verify or withdraw (R4)")
            elif expires <= today + dt.timedelta(days=EXPIRY_WARNING_DAYS):
                warnings.append(f"{where}: expires on {expires}")
        # R5
        if kind == "metric" and status != "withdrawn" and "instrument" not in data:
            errors.append(f"{where}: a metric needs [instrument] (R5)")
        # R8
        for n, item in enumerate(evidence, 1):
            errors += check_evidence(f"{where}: evidence {n}", item, schema, git)
        # R3 (replaced_by is checked once every claim is loaded)
        if status == "withdrawn":
            w = data.get("withdrawn", {})
            if not (type_ok(w.get("on"), "date") and type_ok(w.get("reason"), "string")):
                errors.append(f"{where}: withdrawn claims need withdrawn.on (date) and withdrawn.reason (R3)")
            if data.get("surfaces"):
                errors.append(f"{where}: a withdrawn claim must not list surfaces (R3)")
        elif "withdrawn" in data:
            errors.append(f"{where}: [withdrawn] is only for status = withdrawn (R3)")
        # R6
        langs = set()
        for s in data.get("surfaces", []):
            if s not in surfaces:
                errors.append(f"{where}: surface {s!r} is not declared in claims/surfaces.toml (R6)")
                continue
            lang = surfaces[s]["lang"]
            langs.add(lang)
            quotes = data.get("quotes" if lang == "en" else "quotes_zh", [])
            if not quotes:
                errors.append(f"{where}: lists {s} but has no {'quotes' if lang == 'en' else 'quotes_zh'} (R6)")
            if not (ROOT / s).is_file():
                errors.append(f"{where}: surface {s} does not exist (R6)")
                continue
            text = (ROOT / s).read_text(encoding="utf-8")
            for q in quotes:
                if q not in text:
                    errors.append(f"{where}: quote not found in {s}: {q[:70]!r} (R6)")
        if "zh" in langs and "text_zh" not in data:
            errors.append(f"{where}: a zh surface needs text_zh (R6)")
        for field, lang in (("quotes", "en"), ("quotes_zh", "zh")):
            if data.get(field) and lang not in langs:
                errors.append(f"{where}: {field} given but no {lang} surface is listed (R6)")

    for cid, (where, data) in sorted(claims.items()):
        target = data.get("withdrawn", {}).get("replaced_by")
        if target and (target not in claims or claims[target][1].get("status") == "withdrawn"):
            errors.append(f"{where}: replaced_by {target!r} is not a live claim (R3)")

    # R7 coverage
    for spath, spec in sorted(surfaces.items()):
        if spec.get("lang") not in ("en", "zh") or not (ROOT / spath).is_file():
            errors.append(f"claims/surfaces.toml: {spath}: needs an existing file and lang = 'en' or 'zh'")
            continue
        field = "quotes" if spec["lang"] == "en" else "quotes_zh"
        quotes = [
            q
            for _, data in claims.values()
            if data.get("status") != "withdrawn" and spath in data.get("surfaces", [])
            for q in data.get(field, [])
        ]
        exempt = {e["line"] for e in spec.get("exempt", [])}
        text = (ROOT / spath).read_text(encoding="utf-8")
        seen_exempt = set()
        for n, line in claim_bearing_lines(text):
            if line in exempt:
                seen_exempt.add(line)
            elif not any(q in line for q in quotes):
                errors.append(f"{spath}:{n}: no claim maps to this line (R7): {line[:70]!r}")
        for line in sorted(exempt - seen_exempt):
            errors.append(f"claims/surfaces.toml: stale exempt line for {spath}: {line[:70]!r}")

    # R9 (only on a valid ledger: render() assumes the fields R1-R8 guarantee)
    if not errors and (
        not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != render(schema, claims_sorted(claims))
    ):
        errors.append("CLAIMS.md is out of date: run `python3 -I claims/claims.py render` (R9)")

    for w in warnings:
        print(f"warning: {w}")
    for e in errors:
        print(e)
    live = sum(1 for _, d in claims.values() if d.get("status") != "withdrawn")
    print(f"{len(claims)} claims ({live} live, {len(claims) - live} withdrawn), {len(surfaces)} surfaces: "
          + ("FAIL" if errors else "ok"))
    return 1 if errors else 0


def claims_sorted(claims):
    return [data for _, (_, data) in sorted(claims.items())]


# ----------------------------------------------------------------- render


def anchor(cid):
    """GitHub's heading anchor for a heading that is just `cid` in backticks."""
    return re.sub(r"[^\w\- ]", "", cid.lower()).replace(" ", "-")


def evidence_line(item, repo):
    def blob(path, sha):
        file, _, frag = path.partition("#")
        return f"[`{file}`]({repo}/blob/{sha}/{file}" + (f"#{frag}" if frag else "") + ")"

    def at(sha):
        return f"at [`{sha[:9]}`]({repo}/commit/{sha})"

    t = item["type"]
    if t == "code":
        file, _, symbol = item["ref"].partition("::")
        line = f"code {blob(file, item['commit'])}" + (f" (`{symbol}`)" if symbol else "") + f" {at(item['commit'])}"
    elif t == "test":
        line = f"test `{item['ref']}` in {blob(item['path'], item['commit'])} {at(item['commit'])}"
    elif t == "report":
        line = f"document {blob(item['ref'], item['commit'])} {at(item['commit'])}"
    elif t == "command":
        line = f"command `{item['ref']}` {at(item['commit'])} → {item['result']}"
    elif t == "tx":
        line = f"transaction `{item['ref']}` on `{item['network']}`"
    elif t == "ci_run":
        line = f"CI run {item['url']}"
    else:  # unreachable after check(); keep render total
        line = f"{t} evidence"
    return f"- {line}" + (f". {item['note']}" if item.get("note") else "")


def claim_block(c, repo):
    out = [f"### `{c['id']}`", "", c["text"], ""]
    if c.get("text_zh"):
        out += [f"中文：{c['text_zh']}", ""]
    status = c["status"] + (f" · **support:** {c['support']}" if c.get("support") else "")
    out.append(f"- **Status:** {status} · **kind:** {c['kind']} · **owner:** WS-{c['id'][:2]}")
    out.append(f"- **Observed:** {c['observed']}" + (f" · **expires:** {c['expires']}" if c.get("expires") else ""))
    if c.get("surfaces"):
        out.append("- **Appears in:** " + ", ".join(f"[{s}]({s})" for s in c["surfaces"]))
    if c.get("instrument"):
        out.append("- **Instrument:** " + ", ".join(f"{k} = {c['instrument'][k]}" for k in sorted(c["instrument"])))
    w = c.get("withdrawn")
    if w:
        out.append(f"- **Withdrawn on:** {w['on']}. {w['reason']}")
        if w.get("replaced_by"):
            out.append(f"- **Replaced by:** [`{w['replaced_by']}`](#{anchor(w['replaced_by'])})")
    if c.get("evidence"):
        out += ["", "Evidence:", ""] + [evidence_line(e, repo) for e in c["evidence"]]
    return out + [""]


def render(schema, claims):
    repo = schema["repo_url"]
    kinds = schema["field"]["kind"]["enum"]
    statuses = schema["field"]["status"]["enum"]
    live = [c for c in claims if c["status"] != "withdrawn"]
    withdrawn = [c for c in claims if c["status"] == "withdrawn"]
    out = [
        "<!-- GENERATED by claims/claims.py from claims/<ws>/*.toml. Do not edit by hand:"
        " edit or add a claim file, then run `python3 -I claims/claims.py render`. -->",
        "",
        "# Claims ledger",
        "",
        "Every statement that Vaultex's checked public documents make about the project has an entry here,"
        " with its status, its pinned evidence and the date by which it must be re-checked."
        " A claim that stops being true is not deleted: it moves to [Withdrawn claims](#withdrawn-claims),"
        " with the date and the reason.",
        "",
        "Checked documents: "
        + ", ".join(f"[{s}]({s})" for s in sorted({s for c in live for s in c.get("surfaces", [])}))
        + ". Every claim-bearing line in them maps to a claim below; `python3 -I claims/claims.py check`"
        " enforces this, together with evidence pinning and expiry.",
        "",
        "- **verified**: evidence is attached and pinned to a commit, a transaction or a CI run.",
        "- **limitation**: a known weakness, stated publicly. Fixes are tracked by category in"
        " [SECURITY_STATUS.md](SECURITY_STATUS.md).",
        "- **hypothesis**: not yet proven. It may appear only in plans and research, marked as a hypothesis.",
        "- **withdrawn**: stated publicly in the past and now retracted. No document may repeat it.",
        "",
        "Each claim is one file, `claims/<workstream>/<slug>.toml`, with the ID `<workstream>.<slug>`."
        " The fields are defined in [claims/schema.toml](claims/schema.toml)."
        " Evidence links point at fixed commits, so they keep showing what was checked.",
        "",
        "## Summary",
        "",
        "| Status | Claims |",
        "|---|---|",
    ]
    out += [f"| {s} | {sum(1 for c in claims if c['status'] == s)} |" for s in statuses]
    out += [f"| **Total** | **{len(claims)}** |", "", "## Index", "",
            "| ID | Kind | Status | Support | Expires |", "|---|---|---|---|---|"]
    out += [
        f"| [`{c['id']}`](#{anchor(c['id'])}) | {c['kind']} | {c['status']} | {c.get('support', '—')} | {c.get('expires', '—')} |"
        for c in claims
    ]
    out.append("")
    for kind in kinds:
        group = [c for c in live if c["kind"] == kind]
        if group:
            out += [f"## {kind.capitalize()} claims", ""]
            for c in group:
                out += claim_block(c, repo)
    out += ["## Withdrawn claims", "",
            "These statements were made publicly in earlier versions and are retracted."
            " They are kept so that the retraction stays visible.", ""]
    for c in withdrawn:
        out += claim_block(c, repo)
    return "\n".join(out).rstrip("\n") + "\n"


def write_render():
    schema = load_toml(LEDGER / "schema.toml")
    try:
        claims = sorted((data for _, data in load_claims()), key=lambda c: c["id"])
        text = render(schema, claims)
    except (KeyError, TypeError) as e:
        print(f"cannot render: a claim file is malformed ({e!r}); run `claims.py check` for details")
        return 1
    with open(OUTPUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"wrote {rel(OUTPUT)} ({len(claims)} claims)")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("render", help="rewrite CLAIMS.md from the ledger")
    c = sub.add_parser("check", help="validate the ledger, surfaces and CLAIMS.md")
    c.add_argument("--today", type=dt.date.fromisoformat,
                   default=dt.datetime.now(dt.timezone.utc).date(), help="date for expiry checks (UTC)")
    c.add_argument("--no-git", action="store_true", help="skip evidence lookups in git history")
    args = p.parse_args(argv)
    if args.cmd == "render":
        return write_render()
    return check(args.today, use_git=not args.no_git)


if __name__ == "__main__":
    sys.exit(main())
