#!/usr/bin/env bash
# Claims-lint (ROADMAP M5 #10, Beta criterion B8). Run from anywhere:
#
#     scripts/ci/claims_lint.sh [--today YYYY-MM-DD] [--no-git]
#
# Arguments are passed to `claims.py check`. All three checks always run, so one run reports every
# problem; the exit status is non-zero if any of them fails. The working tree is never written.
#   1. Ledger rules: `claims/claims.py check` validates every claim against claims/schema.toml and
#      rules R1-R9 (pinned evidence, expiry, README coverage, CLAIMS.md out of date).
#   2. CLAIMS.md is byte-identical to a fresh render. R9 compares decoded text, which folds CRLF
#      line endings, so this check compares bytes. It renders into a scratch copy of claims/.
#   3. No claim file is silently skipped. The renderer reads only claims/<NN>/<name>.toml, so any
#      other .toml under claims/, and any other file in a sub-folder, fails.
# Needs python3 >= 3.11 (tomllib), git and cmp. No build, no network.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
fail=0

echo "== 1/3 ledger rules: claims/claims.py check"
python3 -I claims/claims.py check "$@" || fail=1

echo "== 2/3 CLAIMS.md is byte-identical to a fresh render"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
cp -R claims "$scratch/claims"
if ! python3 -I "$scratch/claims/claims.py" render > /dev/null; then
  echo "cannot render CLAIMS.md; see the check output above"
  fail=1
elif ! cmp -s "$scratch/CLAIMS.md" CLAIMS.md; then
  echo "CLAIMS.md differs byte-for-byte from a fresh render (a hand edit, or CRLF line endings):"
  diff -u CLAIMS.md "$scratch/CLAIMS.md" | head -n 40 || true
  echo "fix: python3 -I claims/claims.py render"
  fail=1
else
  echo "ok"
fi

echo "== 3/3 every file under claims/ is one the renderer reads"
tracked=$(git -c core.quotepath=off ls-files -- claims)
stray=$(printf '%s\n' "$tracked" \
  | grep -E '^claims/([^/]+/.+|[^/]+\.toml)$' \
  | grep -Ev '^claims/([0-9]{2}/[^./][^/]*\.toml|schema\.toml|surfaces\.toml)$' || true)
if [ -n "$stray" ]; then
  echo "never rendered into CLAIMS.md; a claim file must be claims/<NN>/<name>.toml:"
  printf '%s\n' "$stray" | sed 's/^/  /'
  fail=1
else
  echo "ok"
fi

exit "$fail"
