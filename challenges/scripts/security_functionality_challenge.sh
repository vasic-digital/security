#!/usr/bin/env bash
# security_functionality_challenge.sh - Validates Security module core functionality
# Checks guardrails engine, PII detection/redaction, content filtering, policy enforcement, scanner
#
# Usage:
#   bash challenges/scripts/security_functionality_challenge.sh                   # validate this module
#   bash challenges/scripts/security_functionality_challenge.sh --prove-failure   # §1.1 paired proof
#
# THREE-VALUED, and a 2 is never a pass:
#   0 = every assertion held, and the number of assertions that actually ran
#       reached the recorded floor (FUNC_FLOOR)
#   1 = a real finding — an assertion failed, or FEWER assertions ran than
#       the floor (an assertion lost to an edit or an early exit)
#   2 = COULD NOT DETERMINE — part of the source could not be read (an
#       unreadable package directory or file), or an unknown argument.
#       Precedence: 1 outranks 2 outranks 0.
#
# EXECUTED-COUNT FLOOR (VSC-371): FUNC_FLOOR is the number of assertions this
# file makes (24, S01..S24). Every assertion ends in exactly one `verdict`
# call, which is what is counted; a run that reaches the end having made
# fewer — an assertion deleted or commented out, a block skipped — is rc 1,
# never a quiet pass over a smaller check. Adding an assertion means raising
# FUNC_FLOOR in the same commit; there is no environment override.
#
# --prove-failure (§1.1 paired proof, VSC-371): copies this module (no .git)
# into throw-away trees under $TMPDIR, plants a defect in each copy and runs
# THIS file there — a clean copy must exit 0; a renamed guardrails Engine, a
# renamed PII Redactor and a copy of this file with one assertion deleted
# must exit 1; an unreadable package directory and an unknown argument must
# exit 2. Exits 0 only when every case holds, 1 when any does not, 2 when the
# proof itself cannot run (e.g. as root, where chmod 000 does not deny a read).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MODULE_NAME="Security"

# Executed-count floor — see the header. Assertions (verdict calls).
FUNC_FLOOR=24

# ── paired proof ─────────────────────────────────────────────────────────────
prove_failure() {
    # T is deliberately NOT local: the EXIT trap runs after this function has
    # returned, and a local T would be empty by then and leak the scratch tree.
    local self_rel c0 d
    self_rel="challenges/scripts/$(basename "${BASH_SOURCE[0]}")"
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

    echo "prove-failure: ${MODULE_NAME} functionality challenge ${MODULE_DIR}/${self_rel} (floor ${FUNC_FLOOR} assertions)"
    c0=$(mkcopy c0) || { cannot "could not copy the module"; return 2; }
    expect "C0 clean copy of this module" 0 "$c0" "VERDICT: PASS"

    d=$(mkcopy m1) || { cannot "could not copy the module"; return 2; }
    grep -lZ 'type Engine struct' "$d"/pkg/guardrails/*.go | xargs -0 -r sed -i 's/type Engine struct/type EngineRenamed struct/'
    expect "M1 the guardrails Engine struct is renamed away" 1 "$d" "Guardrails Engine struct missing"

    d=$(mkcopy m2) || { cannot "could not copy the module"; return 2; }
    grep -lZ 'type Redactor struct' "$d"/pkg/pii/*.go | xargs -0 -r sed -i 's/type Redactor struct/type RedactorRenamed struct/'
    expect "M2 the PII Redactor struct is renamed away" 1 "$d" "PII Redactor struct missing"

    d=$(mkcopy m3) || { cannot "could not copy the module"; return 2; }
    if grep -q '^verdict S24 ' "$d/$self_rel" && sed -i '/^verdict S24 /d' "$d/$self_rel" \
       && ! grep -q '^verdict S24 ' "$d/$self_rel"; then
        expect "M3 one assertion deleted from this file, floor left as is" 1 "$d" "below the floor"
    else
        P_UNDET=$((P_UNDET + 1)); echo "  UNDET M3: could not delete assertion S24 from the copy of this file"
    fi

    if [ "$(id -u)" -eq 0 ]; then
        P_UNDET=$((P_UNDET + 1)); echo "  UNDET U1: running as root — chmod 000 does not deny reads here"
    else
        d=$(mkcopy u1) || { cannot "could not copy the module"; return 2; }
        chmod 000 "$d/pkg/policy"
        expect "U1 an unreadable package directory is not a pass" 2 "$d" "UNDETERMINED"
        chmod 755 "$d/pkg/policy"
    fi
    expect "U2 unknown argument" 2 "$c0" "unknown argument" -- --no-such-flag

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
EXECUTED=0

pass()  { PASS=$((PASS+1));  TOTAL=$((TOTAL+1)); echo "  PASS: $1"; }
fail()  { FAIL=$((FAIL+1));  TOTAL=$((TOTAL+1)); echo "  FAIL: $1"; }
undet() { UNDET=$((UNDET+1)); TOTAL=$((TOTAL+1)); echo "  UNDETERMINED: $1"; }

# has_decl <pkg> <pattern>: grep -q over pkg/<pkg>/*.go (that directory only)
#   0 match; 1 no match (a missing directory or one with no .go file is "no
#   match": a real finding); 2 could not read — the directory cannot be
#   listed, or grep hit an unreadable file and found no match, so "absent"
#   cannot be told apart from "not looked at".
has_decl() {
    local dir="${MODULE_DIR}/pkg/$1" pat=$2 files rc
    [ -d "$dir" ] || return 1
    { [ -r "$dir" ] && [ -x "$dir" ]; } || return 2
    shopt -s nullglob
    files=("$dir"/*.go)
    shopt -u nullglob
    [ "${#files[@]}" -gt 0 ] || return 1
    grep -q -e "$pat" -- "${files[@]}" 2>/dev/null
    rc=$?
    [ "$rc" -le 1 ] && return "$rc"
    return 2
}

# verdict <id> <rc> <pass-message> <fail-message> — ONE assertion, counted once
verdict() {
    EXECUTED=$((EXECUTED+1))
    case "$2" in
        0) pass "$3" ;;
        1) fail "$4" ;;
        *) undet "$1: part of the source could not be read — '$4' cannot be ruled out" ;;
    esac
}

echo "=== ${MODULE_NAME} Functionality Challenge ==="
echo ""

# --- Section 1: Required packages ---
echo "Section 1: Required packages (5)"

n=0
for pkg in content guardrails pii policy scanner; do
    n=$((n+1))
    echo "Test: Package pkg/${pkg} exists"
    if [ -d "${MODULE_DIR}/pkg/${pkg}" ]; then rc=0; else rc=1; fi
    verdict "S0${n}" "$rc" "Package pkg/${pkg} exists" "Package pkg/${pkg} missing"
done

# --- Section 2: Guardrails ---
echo ""
echo "Section 2: Guardrails engine"

echo "Test: Rule interface exists"
has_decl guardrails "type Rule interface"; rc=$?
verdict S06 "$rc" "Rule interface exists" "Rule interface missing"

echo "Test: Engine struct exists"
has_decl guardrails "type Engine struct"; rc=$?
verdict S07 "$rc" "Guardrails Engine struct exists" "Guardrails Engine struct missing"

echo "Test: Result struct exists in guardrails"
has_decl guardrails "type Result struct"; rc=$?
verdict S08 "$rc" "Result struct exists in guardrails" "Result struct missing in guardrails"

echo "Test: MaxLengthRule struct exists"
has_decl guardrails "type MaxLengthRule struct"; rc=$?
verdict S09 "$rc" "MaxLengthRule struct exists" "MaxLengthRule struct missing"

echo "Test: ForbiddenPatternsRule struct exists"
has_decl guardrails "type ForbiddenPatternsRule struct"; rc=$?
verdict S10 "$rc" "ForbiddenPatternsRule struct exists" "ForbiddenPatternsRule struct missing"

# --- Section 3: PII detection ---
echo ""
echo "Section 3: PII detection and redaction"

echo "Test: Detector interface exists"
has_decl pii "type Detector interface"; rc=$?
verdict S11 "$rc" "PII Detector interface exists" "PII Detector interface missing"

echo "Test: Match struct exists"
has_decl pii "type Match struct"; rc=$?
verdict S12 "$rc" "PII Match struct exists" "PII Match struct missing"

echo "Test: Redactor struct exists"
has_decl pii "type Redactor struct"; rc=$?
verdict S13 "$rc" "PII Redactor struct exists" "PII Redactor struct missing"

# --- Section 4: Content filtering ---
echo ""
echo "Section 4: Content filtering"

echo "Test: Filter interface exists"
has_decl content "type Filter interface"; rc=$?
verdict S14 "$rc" "Content Filter interface exists" "Content Filter interface missing"

echo "Test: ChainFilter struct exists"
has_decl content "type ChainFilter struct"; rc=$?
verdict S15 "$rc" "ChainFilter struct exists" "ChainFilter struct missing"

echo "Test: KeywordFilter struct exists"
has_decl content "type KeywordFilter struct"; rc=$?
verdict S16 "$rc" "KeywordFilter struct exists" "KeywordFilter struct missing"

echo "Test: FilterResult struct exists"
has_decl content "type FilterResult struct"; rc=$?
verdict S17 "$rc" "FilterResult struct exists" "FilterResult struct missing"

# --- Section 5: Policy enforcement ---
echo ""
echo "Section 5: Policy enforcement"

echo "Test: Policy struct exists"
has_decl policy "type Policy struct"; rc=$?
verdict S18 "$rc" "Policy struct exists" "Policy struct missing"

echo "Test: Enforcer struct exists"
has_decl policy "type Enforcer struct"; rc=$?
verdict S19 "$rc" "Enforcer struct exists" "Enforcer struct missing"

echo "Test: EvaluationContext struct exists"
has_decl policy "type EvaluationContext struct"; rc=$?
verdict S20 "$rc" "EvaluationContext struct exists" "EvaluationContext struct missing"

# --- Section 6: Vulnerability scanner ---
echo ""
echo "Section 6: Vulnerability scanner"

echo "Test: Scanner interface exists"
has_decl scanner "type Scanner interface"; rc=$?
verdict S21 "$rc" "Scanner interface exists" "Scanner interface missing"

echo "Test: Finding struct exists"
has_decl scanner "type Finding struct"; rc=$?
verdict S22 "$rc" "Finding struct exists" "Finding struct missing"

echo "Test: Report struct exists in scanner"
has_decl scanner "type Report struct"; rc=$?
verdict S23 "$rc" "Report struct exists in scanner" "Report struct missing in scanner"

# --- Section 7: Source structure completeness ---
echo ""
echo "Section 7: Source structure"

echo "Test: Each package has non-test Go source files"
rc=0
lacking=""
for pkg in content guardrails pii policy scanner; do
    non_test=$(find "${MODULE_DIR}/pkg/${pkg}" -name "*.go" ! -name "*_test.go" -type f 2>/dev/null); frc=$?
    [ -n "$non_test" ] && continue
    if [ "$frc" -ne 0 ] && [ -d "${MODULE_DIR}/pkg/${pkg}" ]; then
        [ "$rc" -eq 1 ] || rc=2      # found nothing, but could not read it all: cannot tell
        continue
    fi
    rc=1
    lacking="${lacking} pkg/${pkg}"
done
verdict S24 "$rc" "All packages have non-test Go source files" "Package(s) with no non-test Go files:${lacking}"

# EXECUTED-COUNT FLOOR (VSC-371): an assertion that did not run is not an
# assertion that passed.
echo ""
echo "Test: Every assertion ran (floor ${FUNC_FLOOR})"
if [ "$EXECUTED" -lt "$FUNC_FLOOR" ]; then
    fail "executed ${EXECUTED} assertion(s), below the floor ${FUNC_FLOOR} — a partial run is not a pass"
else
    pass "executed ${EXECUTED} assertion(s) (floor ${FUNC_FLOOR})"
fi

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
