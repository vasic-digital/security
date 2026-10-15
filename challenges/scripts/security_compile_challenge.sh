#!/usr/bin/env bash
# security_compile_challenge.sh - Validates Security module compilation and code quality
#
# Usage:
#   bash challenges/scripts/security_compile_challenge.sh                   # validate this module
#   bash challenges/scripts/security_compile_challenge.sh --prove-failure   # §1.1 paired proof
#
# THREE-VALUED, and a 2 is never a pass:
#   0 = the module builds and vets, the docs are present, and the number of
#       packages the build covered reached the recorded floor (COMPILE_FLOOR)
#   1 = a real finding — a build / vet / layout failure, or the build covered
#       FEWER packages than the floor (0 included)
#   2 = COULD NOT DETERMINE — no usable go toolchain, the package population
#       could not be enumerated (`go list` failed while the build passed), or
#       an unknown argument. Precedence: 1 outranks 2 outranks 0.
#
# EXECUTED-COUNT FLOOR (VSC-371): COMPILE_FLOOR is the number of packages
# `go list ./...` reports today (measured 2026-10-15: 18). `go build ./...`
# exits 0 on a tree with NO Go packages at all ("matched no packages" is only
# a warning), so a build that compiled almost nothing used to read as a pass.
# Adding packages needs no edit here; removing packages on purpose means
# lowering COMPILE_FLOOR in the same commit. There is deliberately no
# environment override that lowers it. The floor is a MINIMUM, not an exact
# count, on purpose: what the gate must catch is a build that covered too
# little; an exact count would turn every new package into an edit here
# without catching anything more (a new package is built by go build ./...
# and vetted either way).
#
# --prove-failure (§1.1 paired proof, VSC-371): copies this module (no .git)
# into throw-away trees under $TMPDIR, plants a defect in each copy and runs
# THIS file there — a clean copy must exit 0; a planted syntax error, a copy
# that keeps only pkg/content's Go files and a copy with no Go files must
# exit 1; an unusable toolchain, a `go list` that cannot enumerate and an
# unknown argument must exit 2. Exits 0 only when every case holds, 1 when
# any does not, 2 when the proof itself cannot run.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MODULE_NAME="Security"

# Executed-count floor — see the header. Packages, from `go list ./...`.
COMPILE_FLOOR=18

# ── paired proof ─────────────────────────────────────────────────────────────
prove_failure() {
    # T is deliberately NOT local: the EXIT trap runs after this function has
    # returned, and a local T would be empty by then and leak the scratch tree.
    local self_rel real_go c0 d victim
    self_rel="challenges/scripts/$(basename "${BASH_SOURCE[0]}")"
    real_go=$(command -v go) || { echo "prove-failure: cannot determine — no go toolchain on PATH"; return 2; }
    T=$(mktemp -d) || { echo "prove-failure: cannot determine — mktemp -d failed"; return 2; }
    trap 'chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"' EXIT
    P_PASS=0; P_FAIL=0; P_UNDET=0

    # mkcopy <name> -> path of a fresh copy of this module's working tree (no .git)
    mkcopy() {
        local dst="$T/$1"
        mkdir -p "$dst" || return 1
        ( cd "$MODULE_DIR" && tar --exclude=.git -cf - . ) | ( cd "$dst" && tar -xf - ) || return 1
        [ -f "$dst/$self_rel" ] || return 1
        printf '%s\n' "$dst"
    }
    # expect <name> <want-rc> <copy> <needle> [VAR=value ...] [-- script args...]
    # Runs the copy's own instance of THIS file; the rc must equal <want-rc>
    # and the output must contain <needle>, so an rc reached for an unrelated
    # reason does not count as the planted defect being caught.
    expect() {
        local name=$1 want=$2 dir=$3 needle=$4 out rc
        shift 4
        local envs=() args=()
        while [ $# -gt 0 ]; do
            if [ "$1" = "--" ]; then shift; args=("$@"); break; fi
            envs+=("$1"); shift
        done
        out=$(cd "$dir" && env "${envs[@]}" bash "$dir/$self_rel" "${args[@]}" 2>&1); rc=$?
        if [ "$rc" -ne "$want" ]; then
            P_FAIL=$((P_FAIL + 1)); echo "  FAIL $name: want rc $want, got rc $rc"
            printf '%s\n' "$out" | tail -8 | sed 's/^/       | /'
        elif ! grep -qF -- "$needle" <<<"$out"; then
            P_FAIL=$((P_FAIL + 1)); echo "  FAIL $name: rc $rc as wanted, but the output does not name '$needle'"
            printf '%s\n' "$out" | tail -8 | sed 's/^/       | /'
        else
            P_PASS=$((P_PASS + 1)); echo "  PASS $name (rc $rc)"
        fi
    }
    cannot() { echo "prove-failure: cannot determine — $1"; }

    mkdir -p "$T/shim-nolist" "$T/shim-broken" || { cannot "cannot create shim dirs"; return 2; }
    # a toolchain that builds and vets but cannot enumerate packages
    printf '#!/usr/bin/env bash\ncase "${1:-}" in list) echo "go: list unavailable (prove-failure shim)" >&2; exit 1 ;; esac\nexec %q "$@"\n' "$real_go" > "$T/shim-nolist/go"
    # a toolchain that cannot run at all
    printf '#!/usr/bin/env bash\necho "go: toolchain unusable (prove-failure shim)" >&2\nexit 1\n' > "$T/shim-broken/go"
    chmod +x "$T/shim-nolist/go" "$T/shim-broken/go"

    echo "prove-failure: ${MODULE_NAME} compile challenge ${MODULE_DIR}/${self_rel} (floor ${COMPILE_FLOOR} packages)"
    c0=$(mkcopy c0) || { cannot "could not copy the module"; return 2; }
    expect "C0 clean copy of this module" 0 "$c0" "VERDICT: PASS"

    d=$(mkcopy m1) || { cannot "could not copy the module"; return 2; }
    victim=$(find "$d/pkg/content" -maxdepth 1 -name '*.go' ! -name '*_test.go' | sort | head -1)
    [ -n "$victim" ] || { cannot "pkg/content has no non-test Go file to break"; return 2; }
    printf '\nfunc proveFailureBroken( {\n' >> "$victim"
    expect "M1 a planted syntax error in pkg/content" 1 "$d" "Module compilation failed"

    d=$(mkcopy m2) || { cannot "could not copy the module"; return 2; }
    find "$d" -name '*.go' ! -path "$d/pkg/content/*" -delete
    expect "M2 far fewer packages (only pkg/content keeps its Go files)" 1 "$d" "below the floor"

    d=$(mkcopy m3) || { cannot "could not copy the module"; return 2; }
    find "$d" -name '*.go' -delete
    expect "M3 zero packages (no Go file left; go build only warns)" 1 "$d" "below the floor"

    expect "U1 go toolchain unusable" 2 "$c0" "UNDETERMINED" "PATH=$T/shim-broken:$PATH"
    expect "U2 the package population cannot be enumerated (go list fails, build passes)" 2 "$c0" "UNDETERMINED" "PATH=$T/shim-nolist:$PATH"
    expect "U3 unknown argument" 2 "$c0" "unknown argument" -- --no-such-flag

    echo "prove-failure: ${P_PASS} passed, ${P_FAIL} failed, ${P_UNDET} undetermined"
    [ "$P_FAIL" -gt 0 ] && return 1
    [ "$P_UNDET" -gt 0 ] && return 2
    return 0
}

case "${1:-}" in
    "") ;;
    --prove-failure)
        [ $# -eq 1 ] || { echo "ERROR: --prove-failure takes no further argument" >&2; exit 2; }
        prove_failure; exit $? ;;
    -h|--help) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "ERROR: unknown argument: $1 — this challenge validates ${MODULE_DIR} and takes no target" >&2
       echo "=== VERDICT: UNDETERMINED — NOT a pass ===" >&2
       exit 2 ;;
esac

PASS=0
FAIL=0
UNDET=0
TOTAL=0

pass()  { PASS=$((PASS+1));  TOTAL=$((TOTAL+1)); echo "  PASS: $1"; }
fail()  { FAIL=$((FAIL+1));  TOTAL=$((TOTAL+1)); echo "  FAIL: $1"; }
undet() { UNDET=$((UNDET+1)); TOTAL=$((TOTAL+1)); echo "  UNDETERMINED: $1"; }

finish() {
    echo ""
    echo "=== Results: ${PASS}/${TOTAL} passed, ${FAIL} failed, ${UNDET} undetermined ==="
    if [ "${FAIL}" -gt 0 ]; then
        echo "=== VERDICT: FAIL (real finding) ==="
        exit 1
    elif [ "${UNDET}" -gt 0 ]; then
        echo "=== VERDICT: UNDETERMINED — NOT a pass ==="
        exit 2
    fi
    echo "=== VERDICT: PASS ==="
    exit 0
}

# show_tail <output>: the first lines of a tool's complaint, as evidence
show_tail() { printf '%s\n' "$1" | head -10 | sed 's/^/      | /'; }

echo "=== ${MODULE_NAME} Compile Challenge ==="
echo ""

# Test 0: a toolchain that can answer at all. Without one nothing below can
# be measured, and "could not run" must not read as "does not compile".
echo "Test: go toolchain is usable"
if go_version=$(go version 2>&1); then
    pass "${go_version}"
else
    undet "go toolchain unusable — compilation cannot be measured (${go_version:-no output})"
    finish
fi

# Test 1: go.mod exists
echo "Test: go.mod exists"
if [ -f "${MODULE_DIR}/go.mod" ]; then
    pass "go.mod exists"
else
    fail "go.mod missing"
fi

# Test 2: Module name is correct
echo "Test: Module name is digital.vasic.security"
if grep -q "^module digital.vasic.security$" "${MODULE_DIR}/go.mod" 2>/dev/null; then
    pass "Module name is digital.vasic.security"
else
    fail "Module name mismatch"
fi

# Test 3: Go version is 1.24+
echo "Test: Go version is 1.24+"
if grep -qE "^go 1\.2[4-9]" "${MODULE_DIR}/go.mod" 2>/dev/null; then
    pass "Go version is 1.24+"
else
    fail "Go version is not 1.24+"
fi

# Test 4: Module compiles
echo "Test: Module compiles"
build_ok=1
if out=$(cd "${MODULE_DIR}" && go build ./... 2>&1); then
    pass "Module compiles successfully"
else
    build_ok=0
    fail "Module compilation failed"
    show_tail "$out"
fi

# Test 5: go vet passes
echo "Test: go vet passes"
if out=$(cd "${MODULE_DIR}" && go vet ./... 2>&1); then
    pass "go vet passes"
else
    fail "go vet found issues"
    show_tail "$out"
fi

# Test 6: Documentation exists
echo "Test: Required documentation exists"
docs_ok=true
for doc in README.md CLAUDE.md AGENTS.md; do
    if [ ! -f "${MODULE_DIR}/${doc}" ]; then
        fail "Missing ${doc}"
        docs_ok=false
    fi
done
if [ "$docs_ok" = true ]; then
    pass "All documentation files present (README.md, CLAUDE.md, AGENTS.md)"
fi

# Test 7: docs/ directory exists
echo "Test: docs/ directory exists"
if [ -d "${MODULE_DIR}/docs" ]; then
    pass "docs/ directory exists"
else
    fail "docs/ directory missing"
fi

# Test 8: All 5 packages compile independently
echo "Test: All packages compile independently"
all_compile=true
for pkg in content guardrails pii policy scanner; do
    if [ -d "${MODULE_DIR}/pkg/${pkg}" ]; then
        if ! out=$(cd "${MODULE_DIR}" && go build "./pkg/${pkg}/..." 2>&1); then
            fail "Package pkg/${pkg} failed to compile"
            show_tail "$out"
            all_compile=false
        fi
    fi
done
if [ "$all_compile" = true ]; then
    pass "All packages compile independently"
fi

# Test 9: EXECUTED-COUNT FLOOR (VSC-371). `go build ./...` builds exactly the
# packages `go list ./...` enumerates — and exits 0 when that is none at all.
# The floor is the package population this module is known to have.
echo "Test: The build covered at least ${COMPILE_FLOOR} packages"
if pkgs=$(cd "${MODULE_DIR}" && go list ./... 2>/dev/null); then
    npkgs=$(printf '%s\n' "$pkgs" | grep -c .)
    if [ "$npkgs" -lt "$COMPILE_FLOOR" ]; then
        fail "the build covered ${npkgs} package(s), below the floor ${COMPILE_FLOOR} — a build of almost nothing is not a pass"
    else
        pass "the build covered ${npkgs} package(s) (floor ${COMPILE_FLOOR})"
    fi
elif [ "$build_ok" -eq 0 ]; then
    undet "go list could not enumerate the packages of a module that does not build — the covered count is unreadable"
else
    undet "go list could not enumerate the packages although the build passed — the covered count is unreadable"
fi

finish
