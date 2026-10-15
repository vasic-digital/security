#!/usr/bin/env bash
# security_unit_challenge.sh - Validates Security module unit tests
#
# Usage:
#   bash challenges/scripts/security_unit_challenge.sh                   # validate this module
#   bash challenges/scripts/security_unit_challenge.sh --prove-failure   # §1.1 paired proof
#
# THREE-VALUED, and a 2 is never a pass:
#   0 = every declared test function EXECUTED and passed, and the executed
#       count reached the recorded floor (UNIT_FLOOR) in both runs
#   1 = a real finding — a test failed, a structural assertion failed, or a
#       run REPORTED fewer test functions than the floor (0 included)
#   2 = COULD NOT DETERMINE — the run did not cover every declared test
#       function (self-skipped tests, an explicit -short run, or
#       executed != declared), or the executed count could not be read
#       (no go toolchain, no scratch file, a runner that reported success
#       but printed no package result), or an unknown argument.
#       Precedence: 1 outranks 2 outranks 0.
#
# EXECUTED-COUNT FLOOR (VSC-371): UNIT_FLOOR is the number of top-level test
# functions this module declares and runs today (measured 2026-10-15: 388 =
# 384 Test + 4 Fuzz seed runs; 388 executed / 388 passed in full mode with
# -tags=integration, and 388 under -race). A run that executes fewer — a
# deleted test file, a build constraint that excludes a package's tests, a
# runner that ran nothing — is rc 1, even when executed == declared, because
# declared shrinks with the source. Adding tests needs no edit here; REMOVING
# tests on purpose means lowering UNIT_FLOOR in the same commit. There is
# deliberately no environment override that lowers it.
#
# --prove-failure (§1.1 paired proof, VSC-371): copies this module (no .git)
# into throw-away trees under $TMPDIR, plants a defect in each copy and runs
# THIS file there — a clean copy must exit 0; a planted failing test, a copy
# whose eight pkg/ packages outside the five named below lose their tests and
# a copy whose tests are all excluded by a build constraint must exit 1; a
# runner that prints no result, an unusable toolchain, an unusable TMPDIR, an
# explicit -short run and an unknown argument must exit 2. Exits 0 only when
# every case holds, 1 when any does not, 2 when the proof itself cannot run.
#
# WHY THIS GATE CHANGED (measured 2026-10-15 at a992a21):
#   It ran `go test -short ./pkg/...` and reported a bare PASS ("9/9 passed",
#   rc 0) on 355 executed test functions, while the module declares 388. Two
#   populations never ran and nothing in the output said so:
#     * tests/{e2e,integration,security,stress} (27) — outside ./pkg/..., and
#       they self-skip under -short anyway;
#     * pkg/attestation and pkg/e2ee integration_test.go (6) — behind
#       `//go:build integration`, whose own header says they "MUST NOT be
#       skipped" (pure crypto, no external dependency).
#   All 388 pass in full mode with -tags=integration (and under -race) and
#   need no infrastructure, so the gate now runs them, compares DECLARED
#   (from source) against EXECUTED (from the runner), and holds the floor —
#   the same model as RAG's unit gate after RAG 13f4bac.
#   `-short` stays reachable for a fast local loop but can never PASS:
#     SECURITY_UNIT_ALLOW_SHORT=1 bash challenges/scripts/security_unit_challenge.sh
#   GOMAXPROCS is no longer `export`ed (it leaked into every later child
#   process); it is passed to the two `go test` invocations only.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MODULE_NAME="Security"

# Executed-count floor — see the header. Per run (plain and -race).
UNIT_FLOOR=388

# ── paired proof ─────────────────────────────────────────────────────────────
prove_failure() {
    # T is deliberately NOT local: the EXIT trap runs after this function has
    # returned, and a local T would be empty by then and leak the scratch tree.
    local self_rel real_go c0 d f p
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

    mkdir -p "$T/shim-silent" "$T/shim-broken" || { cannot "cannot create shim dirs"; return 2; }
    # a runner that reports success for `go test` but prints nothing
    printf '#!/usr/bin/env bash\ncase "${1:-}" in test) exit 0 ;; esac\nexec %q "$@"\n' "$real_go" > "$T/shim-silent/go"
    # a toolchain that cannot run at all
    printf '#!/usr/bin/env bash\necho "go: toolchain unusable (prove-failure shim)" >&2\nexit 1\n' > "$T/shim-broken/go"
    chmod +x "$T/shim-silent/go" "$T/shim-broken/go"

    echo "prove-failure: ${MODULE_NAME} unit challenge ${MODULE_DIR}/${self_rel} (floor ${UNIT_FLOOR})"
    c0=$(mkcopy c0) || { cannot "could not copy the module"; return 2; }
    expect "C0 clean copy of this module" 0 "$c0" "VERDICT: PASS"

    d=$(mkcopy m1) || { cannot "could not copy the module"; return 2; }
    printf 'package content\n\nimport "testing"\n\nfunc TestPlantedFailure(t *testing.T) { t.Fatal("planted by --prove-failure") }\n' \
        > "$d/pkg/content/zz_prove_failure_test.go"
    expect "M1 a planted failing unit test" 1 "$d" "TestPlantedFailure"

    d=$(mkcopy m2) || { cannot "could not copy the module"; return 2; }
    for p in attestation e2ee gpuattest headers i18n securestorage security ssrf; do
        find "$d/pkg/$p" -name '*_test.go' -delete
    done
    expect "M2 far fewer tests (8 of 13 pkg/ packages lose their tests; declared == executed)" 1 "$d" "below the floor"

    d=$(mkcopy m3) || { cannot "could not copy the module"; return 2; }
    while IFS= read -r -d '' f; do
        if head -1 "$f" | grep -q '^//go:build'; then
            sed -i '1s#.*#//go:build prove_failure_never#' "$f"
        else
            { printf '//go:build prove_failure_never\n\n'; cat "$f"; } > "$f.prove" && mv "$f.prove" "$f"
        fi
    done < <(find "$d" -name '*_test.go' -print0)
    expect "M3 zero executed (every test file excluded by a build constraint)" 1 "$d" "below the floor"

    expect "U1 runner reports success but prints no package result" 2 "$c0" "UNDETERMINED" "PATH=$T/shim-silent:$PATH"
    expect "U2 go toolchain unusable" 2 "$c0" "UNDETERMINED" "PATH=$T/shim-broken:$PATH"
    expect "U3 scratch directory unusable (TMPDIR)" 2 "$c0" "UNDETERMINED" "TMPDIR=$T/no-such-dir"
    expect "U4 explicit -short run" 2 "$c0" "UNDETERMINED" "SECURITY_UNIT_ALLOW_SHORT=1"
    expect "U5 unknown argument" 2 "$c0" "unknown argument" -- --no-such-flag

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
    echo "  evidence: ${declared} declared / ${executed} executed / ${plain_pass} passed / 0 skipped (floor ${UNIT_FLOOR});"
    echo "            race: ${race_pass} passed / ${race_skip} skipped; GOMAXPROCS=${GOMAXPROCS_VAL} -p ${GOTEST_P} -tags=${GOTEST_TAGS}"
    exit 0
}

echo "=== ${MODULE_NAME} Unit Test Challenge ==="
echo ""

# Test 0: a toolchain that can answer at all. Without one nothing below can
# be measured, and "could not run" must not read as "tests failed".
echo "Test: go toolchain is usable"
if go_version=$(go version 2>&1); then
    pass "${go_version}"
else
    undet "go toolchain unusable — the executed count cannot be measured (${go_version:-no output})"
    finish
fi

# Test 1: Test files exist in pkg/
echo "Test: Test files exist"
test_count=$(find "${MODULE_DIR}/pkg" -name "*_test.go" -type f 2>/dev/null | wc -l)
if [ "$test_count" -gt 0 ]; then
    pass "Found ${test_count} test files in pkg/"
else
    fail "No test files found in pkg/"
fi

# Test 2-6: Each package has tests
for pkg in content guardrails pii policy scanner; do
    echo "Test: Package pkg/${pkg} has test files"
    if ls "${MODULE_DIR}/pkg/${pkg}/"*_test.go >/dev/null 2>&1; then
        pass "Package pkg/${pkg} has test files"
    else
        fail "Package pkg/${pkg} missing test files"
    fi
done

# Test 7: Tests also exist in tests/ directory
echo "Test: tests/ directory has test files"
if find "${MODULE_DIR}/tests" -name "*_test.go" -type f 2>/dev/null | grep -q .; then
    pass "tests/ directory has test files"
else
    fail "tests/ directory missing test files"
fi

# Resource budget: DEFAULTS, not constants — the cap exists so `go test ./...`
# does not saturate a host it shares, but the right number is a property of
# the host. Override per run:
#   GOMAXPROCS=8 GOTEST_P=4 bash challenges/scripts/security_unit_challenge.sh
# NOT exported: passed to the `go test` children only.
GOMAXPROCS_VAL="${GOMAXPROCS:-2}"
GOTEST_P="${GOTEST_P:-1}"
GOTEST_NICE="${GOTEST_NICE:-19}"
IONICE=()
command -v ionice >/dev/null 2>&1 && IONICE=(ionice -c 3)
# integration_test.go in pkg/attestation and pkg/e2ee are behind this tag and
# declare that they MUST NOT be skipped. Not configurable: without it 6
# declared test functions never run and executed != declared.
GOTEST_TAGS="integration"

# Coverage mode. -short is opt-in and can never yield a PASS.
ALLOW_SHORT="${SECURITY_UNIT_ALLOW_SHORT:-0}"
SHORT_FLAG=()
if [ "${ALLOW_SHORT}" = "1" ]; then
    SHORT_FLAG=(-short)
fi

# Declared population, read from source rather than from the runner, so
# "executed" can be compared against something the runner did not produce.
# Fuzz targets are counted too: `go test` runs their seed corpus and reports
# them as top-level `--- PASS: FuzzX` lines.
declared_raw=$(grep -rhcE '^func (Test|Fuzz)[A-Z_]' --include='*_test.go' "${MODULE_DIR}"); declared_rc=$?
if [ "$declared_rc" -ge 2 ]; then
    declared=0
    undet "the declared test population could not be read from source (grep rc ${declared_rc})"
else
    declared=$(printf '%s\n' "$declared_raw" | awk '{s+=$1} END{print s+0}')
fi

echo ""
echo "  budget: GOMAXPROCS=${GOMAXPROCS_VAL} -p ${GOTEST_P} nice ${GOTEST_NICE} ${IONICE[*]:-}"
echo "  mode:   $([ "${ALLOW_SHORT}" = "1" ] && echo '-short (verdict capped at UNDETERMINED)' || echo 'full') -tags=${GOTEST_TAGS} ./..."
echo "  declared test functions (from source): ${declared}"
echo "  executed-count floor (per run): ${UNIT_FLOOR}"
echo ""

# run_suite <logfile> [extra go-test flags...]
# Emits nothing; sets R_PASS/R_SKIP/R_FAIL/R_PKGS/R_RC and writes the log.
run_suite() {
    local log="$1"; shift
    ( cd "${MODULE_DIR}" && env GOMAXPROCS="${GOMAXPROCS_VAL}" \
        nice -n "${GOTEST_NICE}" "${IONICE[@]}" \
        go test -count=1 -p "${GOTEST_P}" -v -tags="${GOTEST_TAGS}" "${SHORT_FLAG[@]}" "$@" ./... ) \
        > "$log" 2>&1
    R_RC=$?
    # Top-level results only: `go test -v` indents subtest result lines, so a
    # column-0 match counts each test FUNCTION exactly once (measured
    # 2026-10-15: 388 PASS / 0 SKIP / 0 FAIL in full mode).
    R_PASS=$(grep -c '^--- PASS:' "$log")
    R_SKIP=$(grep -c '^--- SKIP:' "$log")
    R_FAIL=$(grep -c '^--- FAIL:' "$log")
    # Per-package result lines (`ok`, `FAIL`, `?  ... [no test files]`). A
    # run with none of them has told us nothing about what it executed: the
    # count is UNREADABLE, which is not the same thing as a count of zero.
    R_PKGS=$(grep -cE '^(ok|FAIL|\?)[[:space:]]+[^[:space:]]+' "$log")
}

# Names the packages that self-skipped, so an UNDETERMINED verdict says WHICH
# populations were not covered instead of only that some were not.
skipped_packages() {
    awk '
        /^--- SKIP:/ { n++; next }
        /^(ok|FAIL|\?)[ \t]+[^ \t]+/ {
            if (n > 0) { printf "      %s (%d skipped)\n", $2, n }
            n = 0
        }
    ' "$1"
}

if ! LOG_PLAIN="$(mktemp 2>/dev/null)" || ! LOG_RACE="$(mktemp 2>/dev/null)"; then
    rm -f "${LOG_PLAIN:-}"
    undet "cannot create a scratch log under TMPDIR=${TMPDIR:-/tmp} — the executed count cannot be measured"
    finish
fi
trap 'rm -f "$LOG_PLAIN" "$LOG_RACE"' EXIT

# Test 8: Unit tests pass
echo "Test: Unit tests pass (full, -tags=${GOTEST_TAGS}, -count=1, -p ${GOTEST_P})"
run_suite "$LOG_PLAIN"
plain_rc=$R_RC; plain_pass=$R_PASS; plain_skip=$R_SKIP; plain_fail=$R_FAIL; plain_pkgs=$R_PKGS
executed=$((plain_pass + plain_skip + plain_fail))
plain_readable=1
if [ "$plain_rc" -ne 0 ] || [ "$plain_fail" -gt 0 ]; then
    fail "Unit tests failed (${plain_fail} failing test function(s), go test rc=${plain_rc})"
    grep -E '^(--- FAIL:|FAIL)' "$LOG_PLAIN" | head -20
    tail -20 "$LOG_PLAIN"
elif [ "$plain_pkgs" -eq 0 ]; then
    plain_readable=0
    undet "go test exited 0 but printed no package result line — what it executed is unreadable"
else
    pass "Unit tests pass (${plain_pass} test function(s) executed and passed)"
    grep -E '^(ok|\?)[[:space:]]' "$LOG_PLAIN"
fi

# Test 9: No race conditions
echo "Test: Race detector clean"
run_suite "$LOG_RACE" -race
race_rc=$R_RC; race_pass=$R_PASS; race_skip=$R_SKIP; race_fail=$R_FAIL; race_pkgs=$R_PKGS
race_readable=1
if [ "$race_rc" -ne 0 ] || [ "$race_fail" -gt 0 ]; then
    fail "Race conditions detected (${race_fail} failing test function(s), go test rc=${race_rc})"
    grep -E '^(--- FAIL:|FAIL|WARNING: DATA RACE)' "$LOG_RACE" | head -20
elif [ "$race_pkgs" -eq 0 ]; then
    race_readable=0
    undet "go test -race exited 0 but printed no package result line — what it executed is unreadable"
else
    pass "No race conditions detected (${race_pass} test function(s) executed under -race)"
fi

# Test 10: EXECUTED-COUNT FLOOR (VSC-371). executed == declared cannot catch
# a population that shrank at the source: delete a package's tests and both
# sides fall together. Applied only to a READABLE count — an unreadable one is
# already UNDETERMINED and is not silently turned into "zero". A self-SKIPPED
# function counts toward the floor because the runner REPORTED it (the
# population is known); Test 11 then makes the run UNDETERMINED for it.
# Calling a deliberate -short run a "real finding" would be a FAIL-bluff; a
# function that is never reported at all is what the floor exists to catch.
echo "Test: Executed count reaches the floor (${UNIT_FLOOR} per run)"
plain_ran=$((plain_pass + plain_skip + plain_fail))
race_ran=$((race_pass + race_skip + race_fail))
floor_ok=1
if [ "$plain_readable" -eq 1 ] && [ "$plain_ran" -lt "$UNIT_FLOOR" ]; then
    floor_ok=0
    fail "plain run executed ${plain_ran} test function(s), below the floor ${UNIT_FLOOR} — a partial run is not a pass"
fi
if [ "$race_readable" -eq 1 ] && [ "$race_ran" -lt "$UNIT_FLOOR" ]; then
    floor_ok=0
    fail "-race run executed ${race_ran} test function(s), below the floor ${UNIT_FLOOR} — a partial run is not a pass"
fi
if [ "$floor_ok" -eq 1 ]; then
    if [ "$plain_readable" -eq 1 ] && [ "$race_readable" -eq 1 ]; then
        pass "executed ${plain_ran} (plain) and ${race_ran} (-race), floor ${UNIT_FLOOR}"
    else
        undet "the floor cannot be checked against an unreadable count"
    fi
fi

# Test 11: COVERAGE — no bare PASS for a population that never ran.
echo "Test: Every declared test function actually executed"
echo "  declared=${declared} executed=${executed} passed=${plain_pass} skipped=${plain_skip} failed=${plain_fail}"
if [ "${plain_skip}" -gt 0 ]; then
    echo "    packages that self-skipped:"
    skipped_packages "$LOG_PLAIN"
fi
if [ "$plain_readable" -eq 0 ]; then
    undet "executed count unreadable — coverage of this module is NOT established"
elif [ "$executed" -ne "$declared" ]; then
    undet "executed ${executed} != declared ${declared} — some test functions never ran at all; coverage of this module is NOT established"
elif [ "${plain_skip}" -gt 0 ]; then
    undet "${plain_skip} of ${declared} declared test function(s) self-skipped — the populations named above were NOT covered by this run"
elif [ "${race_skip}" -gt 0 ]; then
    undet "${race_skip} test function(s) self-skipped under -race"
else
    pass "all ${declared} declared test function(s) executed (0 skipped)"
fi

if [ "${ALLOW_SHORT}" = "1" ]; then
    echo "Test: Coverage mode is not capped"
    undet "SECURITY_UNIT_ALLOW_SHORT=1 — this run used -short, under which tests/{e2e,integration,security,stress} self-skip; a -short run is never a PASS"
fi

finish
