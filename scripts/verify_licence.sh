#!/usr/bin/env bash
# verify_licence.sh - gate: the repository carries the source-available all-rights-reserved LICENSE.
# Exit 0 = present and well-formed, 1 = missing or altered, 2 = cannot determine (never a pass).
# Also requires THIRD_PARTY_NOTICES.md (LICENSE section 4 refers to it) and lists EVERY conflicting SPDX hit,
# including spelling variants such as 'SPDX-License-Identifier :' or lower-case keys.
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
  if [ -f "$1/README.md" ] && grep -qiE '^(MIT|Apache[- ]2(\.0)?|BSD[^ ]*)\.?$' "$1/README.md"; then
    echo "FAIL: README states an OSI licence line"; return 1; fi
  # THIRD_PARTY_NOTICES.md: LICENSE section 4 points at it, so it must exist and be non-empty.
  [ -s "$1/THIRD_PARTY_NOTICES.md" ] || { echo "FAIL: THIRD_PARTY_NOTICES.md missing or empty (LICENSE section 4 refers to it)"; return 1; }
  grep -q 'Third-party notices' "$1/THIRD_PARTY_NOTICES.md" || { echo "FAIL: THIRD_PARTY_NOTICES.md lacks its heading marker"; return 1; }
  # SPDX conflicts: any SPDX-License-Identifier (any case, optional space before the colon) other than the
  # repository's own LicenseRef contradicts LICENSE. Every hit is listed, not just the first few.
  local spdx n
  spdx="$(grep -rIniE --exclude-dir=.git --exclude=verify_licence.sh 'SPDX-License-Identifier[[:space:]]*:' "$1" 2>/dev/null \
    | grep -vE 'SPDX-License-Identifier:[[:space:]]*LicenseRef-Source-Available-All-Rights-Reserved[[:space:]]*(-->|\*/)?[[:space:]]*$')"
  if [ -n "$spdx" ]; then
    n="$(printf '%s\n' "$spdx" | wc -l)"
    echo "FAIL: $n conflicting SPDX identifier line(s):"; printf '%s\n' "$spdx" | sed 's/^/  /'; return 1; fi
  echo "PASS: LICENSE present with all required markers"; return 0
}
if [ "${1:-}" = "--prove-failure" ]; then
  bad=0
  expect1() { # $1 label, $2 dir
    check "$2" >/dev/null; [ $? -eq 1 ] && echo "caught: $1" || { echo "MISSED: $1"; bad=1; }; }
  note() { printf '# Third-party notices\n' > "$d/THIRD_PARTY_NOTICES.md"; }
  mk() { d="$(mktemp -d)"; cp "$here/LICENSE" "$d/LICENSE"; note; }
  d="$(mktemp -d)"; expect1 "missing file" "$d"
  d="$(mktemp -d)"; : > "$d/LICENSE"; expect1 "empty file" "$d"
  d="$(mktemp -d)"; sed 's/NOT AN OPEN-SOURCE LICENCE/Open source/' "$here/LICENSE" > "$d/LICENSE"; note; expect1 "open-source statement removed" "$d"
  d="$(mktemp -d)"; sed 's/Everything else is reserved/Everything is permitted/' "$here/LICENSE" > "$d/LICENSE"; note; expect1 "reservation clause removed" "$d"
  d="$(mktemp -d)"; { cat "$here/LICENSE"; echo "Apache License"; } > "$d/LICENSE"; note; expect1 "OSI text appended" "$d"
  mk; printf '## License\n\nMIT\n' > "$d/README.md"; expect1 "README claims MIT" "$d"
  mk; printf '// SPDX-License-Identifier: Apache-2.0\npackage x\n' > "$d/a.go"; expect1 "Apache-2.0 SPDX header present" "$d"
  mk; printf '# SPDX-License-Identifier: MIT\n' > "$d/b.yaml"; expect1 "MIT SPDX header in yaml" "$d"
  mk; printf '// SPDX-License-Identifier: LicenseRef-Source-Available-All-Rights-Reserved\npackage x\n' > "$d/c.go"; check "$d" >/dev/null || { echo "MISSED: own LicenseRef SPDX wrongly rejected"; bad=1; }
  mk; rm "$d/THIRD_PARTY_NOTICES.md"; expect1 "THIRD_PARTY_NOTICES.md missing" "$d"
  mk; : > "$d/THIRD_PARTY_NOTICES.md"; expect1 "THIRD_PARTY_NOTICES.md empty" "$d"
  mk; printf '// SPDX-License-Identifier : Apache-2.0\n' > "$d/e.go"; expect1 "spaced SPDX-License-Identifier :" "$d"
  mk; printf '// spdx-license-identifier: MIT\n' > "$d/f.go"; expect1 "lower-case SPDX key" "$d"
  mk; for i in 1 2 3 4 5 6 7 8; do printf '// SPDX-License-Identifier: MIT\n' > "$d/g$i.go"; done
  out="$(check "$d")"; printf '%s\n' "$out" | grep -q '8 conflicting' && echo "caught: all 8 hits listed" || { echo "MISSED: hits truncated"; bad=1; }
  mk; printf '<!-- SPDX-License-Identifier: LicenseRef-Source-Available-All-Rights-Reserved -->\n' > "$d/h.md"; check "$d" >/dev/null || { echo "MISSED: own LicenseRef in HTML comment wrongly rejected"; bad=1; }
  mk; printf '// SPDX-License-Identifier: LicenseRef-Source-Available-All-Rights-Reserved OR MIT\n' > "$d/i.go"; expect1 "compound expression with own LicenseRef" "$d"
  check "$here" >/dev/null || { echo "control not green"; bad=1; }
  check "$here/no-such-dir" >/dev/null; [ $? -eq 2 ] || { echo "rc2 state not reported"; bad=1; }
  exit $bad
fi
check "$here"; exit $?
