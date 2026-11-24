#!/usr/bin/env bash
# verify_licence.sh - gate: the repository carries the source-available all-rights-reserved LICENSE.
# Exit 0 = present and well-formed, 1 = missing or altered, 2 = cannot determine (never a pass).
# --prove-failure: builds mutated copies of LICENSE in fresh temp dirs and requires exit 1 for each.
set -u
here="$(cd "$(dirname "$0")/.." && pwd)"
check() { # $1 = repo dir
  local f="$1/LICENSE"
  [ -d "$1" ] || { echo "UNDETERMINED: no directory $1"; return 2; }
  [ -f "$f" ] || { echo "FAIL: LICENSE missing"; return 1; }
  grep -q 'Source-Available License, All Rights Reserved' "$f" || { echo "FAIL: header marker absent"; return 1; }
  grep -q 'NOT AN OPEN-SOURCE LICENCE' "$f" || { echo "FAIL: not-open-source statement absent"; return 1; }
  grep -q 'Everything else is reserved' "$f" || { echo "FAIL: reservation clause absent"; return 1; }
  if grep -qiE 'Apache License|MIT License|Permission is hereby granted, free of charge' "$f"; then
    echo "FAIL: OSI licence text present"; return 1; fi
  echo "PASS: LICENSE present with all required markers"; return 0
}
if [ "${1:-}" = "--prove-failure" ]; then
  bad=0
  expect1() { # $1 label, $2 dir
    check "$2" >/dev/null; [ $? -eq 1 ] && echo "caught: $1" || { echo "MISSED: $1"; bad=1; }; }
  d="$(mktemp -d)"; expect1 "missing file" "$d"
  d="$(mktemp -d)"; : > "$d/LICENSE"; expect1 "empty file" "$d"
  d="$(mktemp -d)"; sed 's/NOT AN OPEN-SOURCE LICENCE/Open source/' "$here/LICENSE" > "$d/LICENSE"; expect1 "open-source statement removed" "$d"
  d="$(mktemp -d)"; sed 's/Everything else is reserved/Everything is permitted/' "$here/LICENSE" > "$d/LICENSE"; expect1 "reservation clause removed" "$d"
  d="$(mktemp -d)"; { cat "$here/LICENSE"; echo "Apache License"; } > "$d/LICENSE"; expect1 "OSI text appended" "$d"
  check "$here" >/dev/null || { echo "control not green"; bad=1; }
  check "$here/no-such-dir" >/dev/null; [ $? -eq 2 ] || { echo "rc2 state not reported"; bad=1; }
  exit $bad
fi
check "$here"; exit $?
