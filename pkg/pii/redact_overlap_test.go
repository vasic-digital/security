package pii

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRedactor_Redact_OverlappingMatches_Deterministic proves that Redact
// produces a stable, non-leaking result when a single substring is detected by
// more than one detector.
//
// Defect (RED): a 16-digit credit-card number's leading digits also match the
// phone pattern, so Detect() returns two OVERLAPPING matches for the same span.
// Redact()'s descending-start splice
//
//	result = result[:m.Start] + replacement + result[m.End:]
//
// applies the second overlapping span against an already-mutated string, so the
// offsets no longer line up: the output is garbled (dropped / re-spliced
// characters — observed pre-fix as "card:***-***-5112****-0366" instead of a
// clean mask). Because Detect() aggregates detector results in Go map-iteration
// order, WHICH overlapping match is spliced first — and therefore whether
// original PII bytes are re-spliced into the output — is order-dependent. The
// correct behaviour is one deterministic, fully-covering redacted span.
func TestRedactor_Redact_OverlappingMatches_Deterministic(t *testing.T) {
	cfg := &Config{
		EnabledDetectors:  []Type{TypePhone, TypeCreditCard},
		RedactionStrategy: StrategyMask,
		MaskChar:          '*',
	}
	r := NewRedactor(cfg)

	const card = "4532015112830366" // 16-digit Visa-format, all-distinct digits
	text := "card: " + card

	// Sanity: the input really triggers overlapping phone+card detections.
	require.GreaterOrEqual(t, len(r.Detect(text)), 2,
		"expected overlapping phone+creditcard matches on %q", text)

	// The credit card is the longer span, so it is the representative: the whole
	// overlapping region (the phone match starts one char earlier, at the
	// separating space) is redacted once with the card mask, deterministically.
	const want = "card:****-****-****-0366"

	observed := make(map[string]int)
	for i := 0; i < 256; i++ {
		red, _ := r.Redact(text)
		observed[red]++
		// The original card must never survive verbatim.
		assert.NotContains(t, red, card, "raw card leaked into redacted output")
	}

	// A redaction engine must be deterministic: overlapping detections must
	// resolve to exactly one output regardless of map-iteration order.
	require.Lenf(t, observed, 1,
		"Redact is nondeterministic on overlapping detections; observed variants: %v",
		observed)
	for got := range observed {
		assert.Equal(t, want, got)
	}
}
