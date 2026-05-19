#!/usr/bin/env bash
# security_describe_challenge.sh — round-300 anti-bluff Challenge for the Security submodule.
#
# Purpose: exercise the REAL public surface of digital.vasic.security across
# multiple locales, capture runtime evidence, and verify the paired-mutation
# polarity (clean run = exit 0; planted mutation = exit 99).
#
# Per CONST-035 / §1.1 / Article XI §11.9:
#   * Normal mode MUST produce captured runtime evidence (not metadata).
#   * Mutation mode MUST detect the planted defect — a Challenge that passes
#     both clean AND mutated is a structural bluff and is rejected.
#
# Per CONST-050(B) / CONST-046: fixtures cover 5 locales (en, sr, ja, es, de)
# proving the i18n bundle's locale-aware path AND that PII / guardrails /
# securestorage operate on real (locale-independent) data shapes.
#
# Usage:
#   bash security_describe_challenge.sh             # clean run, expect exit 0
#   bash security_describe_challenge.sh --mutate    # planted mutation, expect exit 99

set -u
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOD_ROOT="$(cd "$SELF_DIR/../.." && pwd)"

MUTATE=0
if [ "${1:-}" = "--mutate" ]; then
    MUTATE=1
fi

EVIDENCE_DIR="$(mktemp -d -t security-describe-evidence-XXXXXX)"
trap 'rm -rf "$EVIDENCE_DIR"' EXIT

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
fail() { log "FAIL: $*"; exit 99; }
ok() { log "OK: $*"; }

cd "$MOD_ROOT" || fail "cannot cd to module root: $MOD_ROOT"

# ---------------------------------------------------------------------------
# Stage 0 — environment sanity (real go toolchain, real module path)
# ---------------------------------------------------------------------------
command -v go >/dev/null 2>&1 || fail "go toolchain not on PATH"
[ -f go.mod ] || fail "go.mod missing — not at module root"
MOD_LINE="$(head -n1 go.mod)"
echo "$MOD_LINE" | grep -q 'digital.vasic.security' \
    || fail "go.mod does not declare digital.vasic.security: $MOD_LINE"
ok "module identity confirmed: $MOD_LINE"

# ---------------------------------------------------------------------------
# Stage 1 — 5-locale fixtures (CONST-046 + CONST-050(B))
#   Each locale contains a synthetic PII-bearing payload of the SAME shape
#   so the PII detector / redactor / guardrails / securestorage round-trip
#   produces locale-independent positive evidence.
# ---------------------------------------------------------------------------
declare -A LOCALE_GREET=(
    [en]="Hello, please redact my data"
    [sr]="Здраво, молим обришите моје податке"
    [ja]="こんにちは、データを編集してください"
    [es]="Hola, por favor redacte mis datos"
    [de]="Hallo, bitte redigieren Sie meine Daten"
)
# Synthetic, format-valid, deliberately non-routable PII shapes:
SYN_EMAIL="user.${RANDOM}@example.invalid"
SYN_PHONE="+1-555-0100"
SYN_SSN="123-45-6789"
SYN_CC="4111111111111111"
SYN_IP="192.0.2.42"

for locale in en sr ja es de; do
    fixture="$EVIDENCE_DIR/fixture_${locale}.txt"
    {
        echo "${LOCALE_GREET[$locale]}"
        echo "email=${SYN_EMAIL}"
        echo "phone=${SYN_PHONE}"
        echo "ssn=${SYN_SSN}"
        echo "cc=${SYN_CC}"
        echo "ip=${SYN_IP}"
    } > "$fixture"
    [ -s "$fixture" ] || fail "locale fixture write failed: $locale"
done
ok "5-locale fixtures generated under $EVIDENCE_DIR"

# ---------------------------------------------------------------------------
# Stage 2 — REAL exerciser: build + run an inline Go program against the
# real public API surface. No mocks. Real package imports, real seal+open,
# real regex matches, real guardrails verdict.
# ---------------------------------------------------------------------------
RUNNER_DIR="$EVIDENCE_DIR/runner"
mkdir -p "$RUNNER_DIR"
RUNNER_GO="$RUNNER_DIR/main.go"

cat > "$RUNNER_GO" <<'GOEOF'
// round-300 inline runner — exercises real public surface of
// digital.vasic.security and prints captured runtime evidence.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"digital.vasic.security/pkg/guardrails"
	"digital.vasic.security/pkg/pii"
	"digital.vasic.security/pkg/securestorage"
)

func main() {
	mutate := os.Getenv("SECURITY_DESCRIBE_MUTATE") == "1"
	fixtureDir := os.Getenv("FIXTURE_DIR")
	if fixtureDir == "" {
		fmt.Fprintln(os.Stderr, "FIXTURE_DIR env var required")
		os.Exit(2)
	}

	// --- PII redactor: real detect+redact on every locale fixture ---
	cfg := &pii.Config{
		EnabledDetectors:  []pii.Type{pii.TypeEmail, pii.TypePhone, pii.TypeSSN, pii.TypeCreditCard, pii.TypeIPAddress},
		RedactionStrategy: pii.StrategyMask,
		MaskChar:          '*',
	}
	red := pii.NewRedactor(cfg)
	if red == nil {
		fmt.Fprintln(os.Stderr, "NewRedactor returned nil — production code regression")
		os.Exit(3)
	}

	for _, locale := range []string{"en", "sr", "ja", "es", "de"} {
		path := filepath.Join(fixtureDir, "fixture_"+locale+".txt")
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read fixture %s: %v\n", locale, err)
			os.Exit(4)
		}
		redacted, _ := red.Redact(string(raw))

		// MUTATION: simulate a regression where Redact returns input verbatim.
		if mutate {
			redacted = string(raw)
		}

		// Positive evidence: synthetic PII shapes MUST be absent from redacted output.
		ssnRe := regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
		ccRe := regexp.MustCompile(`\b4\d{15}\b`)
		emailRe := regexp.MustCompile(`[A-Za-z0-9._%+\-]+@example\.invalid`)
		leaked := []string{}
		if ssnRe.MatchString(redacted) {
			leaked = append(leaked, "SSN")
		}
		if ccRe.MatchString(redacted) {
			leaked = append(leaked, "CC")
		}
		if emailRe.MatchString(redacted) {
			leaked = append(leaked, "email")
		}
		if len(leaked) > 0 {
			fmt.Fprintf(os.Stderr, "PII-LEAK locale=%s leaked=%s\n", locale, strings.Join(leaked, ","))
			os.Exit(5)
		}
		fmt.Printf("locale=%s redact=PASS bytes_in=%d bytes_out=%d\n", locale, len(raw), len(redacted))
	}

	// --- Guardrails: real rule pipeline, real verdict ---
	eng := guardrails.NewEngine(&guardrails.Config{StopOnFirstFailure: true})
	eng.AddRule(guardrails.NewMaxLengthRule(64))
	result := eng.Check("this is a sufficiently long string that exceeds the configured maximum length of sixty-four")
	if mutate {
		// MUTATION: pretend the result passed.
		result = &guardrails.Result{Passed: true}
	}
	if result == nil {
		fmt.Fprintln(os.Stderr, "guardrails.Check returned nil")
		os.Exit(6)
	}
	if result.Passed {
		fmt.Fprintln(os.Stderr, "guardrails.Check incorrectly PASSED for over-length input")
		os.Exit(7)
	}
	fmt.Printf("guardrails=REJECT_AS_EXPECTED rules_evaluated=%d\n", len(result.Results))

	// --- Securestorage: real AES-256-GCM round trip on the host filesystem ---
	storeDir := filepath.Join(fixtureDir, "store")
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir store: %v\n", err)
		os.Exit(8)
	}
	fs := securestorage.NewFileStorage(storeDir)
	plaintext := "sensitive=value-" + fixtureDir
	if err := fs.Store("k1", plaintext); err != nil {
		fmt.Fprintf(os.Stderr, "Store: %v\n", err)
		os.Exit(9)
	}
	got, err := fs.Retrieve("k1")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Retrieve: %v\n", err)
		os.Exit(10)
	}
	if mutate {
		// MUTATION: pretend the round-trip succeeded with a tampered value.
		got = "tampered"
	}
	if got != plaintext {
		fmt.Fprintf(os.Stderr, "round-trip mismatch: got=%q want=%q\n", got, plaintext)
		os.Exit(11)
	}
	secure, err := fs.IsSecure()
	if err != nil {
		fmt.Fprintf(os.Stderr, "IsSecure: %v\n", err)
		os.Exit(12)
	}
	if mutate {
		secure = false
	}
	if !secure {
		fmt.Fprintln(os.Stderr, "IsSecure returned false — encryption round-trip broken")
		os.Exit(13)
	}
	// Verify on-disk bytes are NOT plaintext (real encryption evidence).
	dataFile := filepath.Join(storeDir, ".secure_storage")
	onDisk, err := os.ReadFile(dataFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read store: %v\n", err)
		os.Exit(14)
	}
	if strings.Contains(string(onDisk), plaintext) {
		fmt.Fprintln(os.Stderr, "PLAINTEXT-ON-DISK: securestorage failed to encrypt")
		os.Exit(15)
	}
	fmt.Printf("securestorage=ROUND_TRIP_OK ciphertext_bytes=%d plaintext_absent=true\n", len(onDisk))

	fmt.Println("round-300 describe Challenge: ALL STAGES PASS")
}
GOEOF

# Execute from a scratch dir inside MOD_ROOT so imports resolve via the
# local module path.
cd "$MOD_ROOT" || fail "cannot return to module root"
BUILD_OUT="$EVIDENCE_DIR/runner.out"
SCRATCH="$MOD_ROOT/.security_describe_scratch"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cp "$RUNNER_GO" "$SCRATCH/main.go"

MUTATE_ENV=0
[ $MUTATE -eq 1 ] && MUTATE_ENV=1

FIXTURE_DIR="$EVIDENCE_DIR" SECURITY_DESCRIBE_MUTATE="$MUTATE_ENV" \
    go run "$SCRATCH/main.go" > "$BUILD_OUT" 2>&1
RUNNER_RC=$?
rm -rf "$SCRATCH"

cat "$BUILD_OUT" >&2

if [ $MUTATE -eq 1 ]; then
    if [ $RUNNER_RC -eq 0 ]; then
        fail "MUTATION did NOT flip the runner — Challenge is structural / bluff"
    fi
    ok "MUTATION mode correctly produced non-zero exit (rc=$RUNNER_RC)"
    exit 99
fi

if [ $RUNNER_RC -ne 0 ]; then
    fail "clean run produced non-zero exit (rc=$RUNNER_RC) — real defect in submodule"
fi

# Final positive-evidence assertions on captured stdout/stderr.
grep -q 'locale=en redact=PASS' "$BUILD_OUT" || fail "missing en redact evidence"
grep -q 'locale=sr redact=PASS' "$BUILD_OUT" || fail "missing sr redact evidence"
grep -q 'locale=ja redact=PASS' "$BUILD_OUT" || fail "missing ja redact evidence"
grep -q 'locale=es redact=PASS' "$BUILD_OUT" || fail "missing es redact evidence"
grep -q 'locale=de redact=PASS' "$BUILD_OUT" || fail "missing de redact evidence"
grep -q 'guardrails=REJECT_AS_EXPECTED' "$BUILD_OUT" || fail "guardrails verdict missing"
grep -q 'securestorage=ROUND_TRIP_OK' "$BUILD_OUT" || fail "securestorage round-trip evidence missing"
grep -q 'ALL STAGES PASS' "$BUILD_OUT" || fail "final aggregate PASS missing"

ok "round-300 describe Challenge: clean run produced 5-locale + guardrails + securestorage evidence"
exit 0
