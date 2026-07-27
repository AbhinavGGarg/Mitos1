#!/usr/bin/env bash
# The engine is developed in its own repo and vendored here, because the GitHub Action has
# to pip-install it from somewhere public. Two copies drift: a --out flag added upstream and
# not copied here made the Action fail with "unrecognized arguments" while every local run
# passed. Run this before releasing the Action.
#
#   ./sync-check.sh ../../patchdna
set -euo pipefail

SRC="${1:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ -n "$SRC" ] && [ -d "$SRC/mitos" ]; then
  drift=0
  # tests count as much as the package: a stale test_repair.py here failed against a
  # correctly-synced repair.py, which reads as an engine bug and is not one.
  for d in mitos tests examples; do
    [ -d "$SRC/$d" ] || continue
    if ! diff -rq --exclude=__pycache__ "$SRC/$d" "$HERE/$d" >/dev/null 2>&1; then
      echo "OUT OF SYNC: $d"
      diff -rq --exclude=__pycache__ "$SRC/$d" "$HERE/$d" || true
      drift=1
    fi
  done
  [ "$drift" -eq 0 ] && echo "engine matches $SRC" || exit 1
fi

# The vendored copy has to stand on its own — this is what the Action installs.
python -m pytest -q "$HERE/tests" 2>&1 | tail -3
