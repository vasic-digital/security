//go:build integration

package attestation

// Integration tests for the attestation package (ed25519 sign/verify + nonce binding).
//
// These tests exercise the full attestation stack in-process (pure-crypto, no
// external dependency) and MUST NOT be skipped — crypto/ed25519 is always
// available on any Go 1.25 platform.
//
// Run with: cd security && go test -tags=integration -race -count=1 -v ./pkg/attestation/...

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"
)

// newRunID returns a per-run unique identifier using crypto/rand so that no
// pre-computed or cached value can produce a false PASS.
func newRunID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("rand.Read: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// TestIntegration_SignVerifyRoundTrip is the primary end-to-end integration proof:
//   - An Attester generates a fresh Ed25519 key and signs a document whose
//     measurement contains a per-run UUID, binding it to a freshly generated nonce.
//   - A Verifier trusting that key verifies the document: the sink-side assertion
//     is byte-exact equality of the recovered measurement value.
//   - Replay: a second verifier is challenged with a DIFFERENT nonce; presenting
//     the original document (bound to the first nonce) MUST return ErrNonceMismatch.
//   - Mutation: flipping a byte in a measurement MUST return ErrSignatureInvalid.
func TestIntegration_SignVerifyRoundTrip(t *testing.T) {
	runID := newRunID()
	now := time.Now().UTC()

	// Attester with a fresh key.
	att, err := NewAttester()
	if err != nil {
		t.Fatalf("NewAttester: %v", err)
	}
	ver, err := NewVerifier(att.PublicKey(), time.Hour)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// Verifier issues a fresh nonce challenge.
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}

	// Measurements include the per-run UUID so no cached result passes.
	measurementValue := []byte(fmt.Sprintf("firmware-%s", runID))
	measurements := map[string][]byte{
		"tdx.rtmr0":    measurementValue,
		"gpu.firmware": []byte(fmt.Sprintf("gpu-%s", runID)),
	}

	// Sign the document.
	doc, err := att.Attest(measurements, nonce, now, 30*time.Minute)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}

	// Verify with matching nonce and policy.
	policy := MeasurementPolicy{
		Expected: map[string][]byte{
			"tdx.rtmr0": measurementValue,
		},
		Required: []string{"gpu.firmware"},
	}
	if err := ver.Verify(doc, nonce, policy, now); err != nil {
		t.Fatalf("INTEGRATION FAIL: valid doc failed Verify: %v", err)
	}

	// Sink-side: the measurement value must be byte-exactly what we attested.
	if got := doc.Measurements["tdx.rtmr0"]; !bytes.Equal(got, measurementValue) {
		t.Fatalf("INTEGRATION FAIL: measurement round-trip mismatch\n  got:  %x\n  want: %x",
			got, measurementValue)
	}

	// ── Replay rejection ───────────────────────────────────────────────────
	// Verifier now challenges with a NEW nonce; the old document must be rejected.
	newNonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce (new): %v", err)
	}
	err = ver.Verify(doc, newNonce, policy, now)
	if !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("INTEGRATION FAIL: stale-nonce replay not rejected; got: %v", err)
	}

	// ── Tamper rejection ───────────────────────────────────────────────────
	// Flip a byte in the measurement; Verify MUST detect signature invalidity.
	doc.Measurements["tdx.rtmr0"][0] ^= 0x01
	err = ver.Verify(doc, nonce, MeasurementPolicy{}, now)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("INTEGRATION FAIL: tampered measurement not caught; got: %v", err)
	}

	t.Logf("INTEGRATION PASS: run-id=%s; sign→verify round-trip, replay rejection, tamper detection all confirmed", runID)
}

// TestIntegration_AttestationReplayRejection specifically exercises the nonce
// freshness invariant: a document signed against nonce-A is ALWAYS rejected when
// the verifier expects nonce-B, even if the document is otherwise valid.
func TestIntegration_AttestationReplayRejection(t *testing.T) {
	runID := newRunID()
	now := time.Now().UTC()

	att, err := NewAttester()
	if err != nil {
		t.Fatalf("NewAttester: %v", err)
	}
	ver, err := NewVerifier(att.PublicKey(), time.Hour)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// Issue nonce-A and sign the document.
	nonceA, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce A: %v", err)
	}
	ms := map[string][]byte{"run": []byte(runID)}
	doc, err := att.Attest(ms, nonceA, now, time.Hour)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}

	// ── Correct nonce: must succeed ────────────────────────────────────────
	if err := ver.Verify(doc, nonceA, MeasurementPolicy{}, now); err != nil {
		t.Fatalf("INTEGRATION FAIL: valid doc rejected: %v", err)
	}

	// ── Challenge with nonce-B: must fail ─────────────────────────────────
	nonceB, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce B: %v", err)
	}
	err = ver.Verify(doc, nonceB, MeasurementPolicy{}, now)
	if !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("INTEGRATION FAIL: replay with nonce-B not rejected; got: %v", err)
	}
	t.Logf("INTEGRATION PASS: replay rejection confirmed for run-id=%s", runID)
}

// TestIntegration_MutatedMeasurementRejection exercises the measurement-mutation
// path: the per-run UUID measurement value is changed after signing and Verify
// MUST catch it via the Ed25519 signature.
func TestIntegration_MutatedMeasurementRejection(t *testing.T) {
	runID := newRunID()
	now := time.Now().UTC()

	att, err := NewAttester()
	if err != nil {
		t.Fatalf("NewAttester: %v", err)
	}
	ver, err := NewVerifier(att.PublicKey(), time.Hour)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}

	origVal := []byte(fmt.Sprintf("measurement-%s", runID))
	ms := map[string][]byte{"component": origVal}
	doc, err := att.Attest(ms, nonce, now, time.Hour)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}

	// Mutate a single byte in the signed measurement value.
	doc.Measurements["component"][0] ^= 0xFF
	err = ver.Verify(doc, nonce, MeasurementPolicy{}, now)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("INTEGRATION FAIL: mutated measurement not caught by signature; got: %v", err)
	}
	t.Logf("INTEGRATION PASS: measurement mutation caught for run-id=%s", runID)
}
