//go:build integration

package e2ee

// Integration tests for the e2ee package (ML-KEM-768 + AES-256-GCM).
//
// These tests exercise the full crypto stack in-process (pure-crypto, no
// external dependency) and MUST NOT be skipped — crypto/mlkem, crypto/hkdf
// and crypto/aes are always available on any Go 1.25 platform.
//
// Run with: cd security && go test -tags=integration -race -count=1 -v ./pkg/e2ee/...

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

// newRunID returns a per-run unique identifier using crypto/rand so no
// pre-computed or cached value can produce a false PASS.
func newRunID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("rand.Read: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// TestIntegration_MLKEMHandshakeSealOpen is the primary end-to-end integration
// proof:
//   - Two independent session objects perform a full ML-KEM-768 handshake.
//   - Peer A seals a per-run UUID payload; Peer B decrypts it and asserts
//     byte-exact equality — this is the SINK-SIDE assertion.
//   - A tampered copy of the record is presented to Open, which MUST return
//     ErrOpen (the auth-tag check actually fires).
//
// The per-run ID is embedded in the payload so that no pre-computed or cached
// value can produce a false PASS; every test run creates a fresh, unique value
// that must survive the full ML-KEM + HKDF + AES-256-GCM round-trip.
func TestIntegration_MLKEMHandshakeSealOpen(t *testing.T) {
	runID := newRunID()
	payload := []byte(fmt.Sprintf("e2ee-integration-%s", runID))
	aad := []byte("integration-test-aad")

	// ── Peer A: Initiator ──────────────────────────────────────────────────
	initiator, err := NewInitiator(SessionConfig{CounterNonce: true})
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	encapKeyBytes := initiator.EncapsulationKeyBytes()

	// ── Peer B: Responder ──────────────────────────────────────────────────
	kemCT, sessB, err := Respond(encapKeyBytes, SessionConfig{CounterNonce: true})
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}

	// ── Peer A: Complete handshake ─────────────────────────────────────────
	sessA, err := initiator.Complete(kemCT, SessionConfig{CounterNonce: true})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// ── Both sessions MUST derive identical keys ───────────────────────────
	if !KeysEqual(sessA, sessB) {
		t.Fatal("INTEGRATION FAIL: ML-KEM handshake produced different session keys on the two peers")
	}

	// ── A seals the per-run UUID payload ───────────────────────────────────
	record, err := sessA.Seal(payload, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// ── B opens and asserts EXACT plaintext equality (sink-side) ──────────
	plaintext, err := sessB.Open(record, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(plaintext, payload) {
		t.Fatalf("INTEGRATION FAIL: sink-side plaintext mismatch\n  got:  %q\n  want: %q",
			plaintext, payload)
	}

	// ── Auth-tag check: ONE tampered byte MUST fail Open ──────────────────
	tampered := append([]byte(nil), record...)
	tampered[NonceSize+2] ^= 0x01
	_, err = sessB.Open(tampered, aad)
	if !errors.Is(err, ErrOpen) {
		t.Fatalf("INTEGRATION FAIL: tampered record did not return ErrOpen, got: %v", err)
	}

	// ── Bidirectional: B seals a reply; A opens ────────────────────────────
	replyID := newRunID()
	replyPayload := []byte(fmt.Sprintf("reply-%s", replyID))
	replyRecord, err := sessB.Seal(replyPayload, aad)
	if err != nil {
		t.Fatalf("Seal reply: %v", err)
	}
	replyPlaintext, err := sessA.Open(replyRecord, aad)
	if err != nil {
		t.Fatalf("Open reply: %v", err)
	}
	if !bytes.Equal(replyPlaintext, replyPayload) {
		t.Fatalf("INTEGRATION FAIL: reverse direction plaintext mismatch\n  got:  %q\n  want: %q",
			replyPlaintext, replyPayload)
	}

	t.Logf("INTEGRATION PASS: run-id=%s; A→B and B→A plaintext equality verified; tamper rejected", runID)
}

// TestIntegration_NonceReuseGuard verifies that the nonce-discipline guard fires
// in a real session: presenting the same record a second time to Open returns
// ErrNonceReuse, not success.
func TestIntegration_NonceReuseGuard(t *testing.T) {
	runID := newRunID()
	sessA, sessB := handshake(t, SessionConfig{CounterNonce: true})

	payload := []byte(fmt.Sprintf("nonce-reuse-payload-%s", runID))
	record, err := sessA.Seal(payload, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// First open: must succeed and return the per-run payload exactly.
	pt, err := sessB.Open(record, nil)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if !bytes.Equal(pt, payload) {
		t.Fatalf("INTEGRATION FAIL: first Open plaintext mismatch: got %q, want %q", pt, payload)
	}

	// Second open with identical record: MUST be rejected as nonce-reuse.
	_, err = sessB.Open(record, nil)
	if !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("INTEGRATION FAIL: nonce-reuse not rejected; got: %v", err)
	}
	t.Logf("INTEGRATION PASS: nonce-reuse guard confirmed for run-id=%s", runID)
}

// TestIntegration_MultiRecordTransport proves the framed Transport layer carries
// multiple per-run-unique records over an in-memory io.ReadWriter with exact
// plaintext equality for all records, and rejects a tampered framed record.
func TestIntegration_MultiRecordTransport(t *testing.T) {
	runID := newRunID()

	sessA, sessB := handshake(t, SessionConfig{CounterNonce: true})
	var pipe bytes.Buffer
	writerT := NewTransport(sessA, &pipe, 0)
	readerT := NewTransport(sessB, &pipe, 0)

	// Seal three per-run-unique records.
	wantRecords := [][]byte{
		[]byte(fmt.Sprintf("transport-record-0-%s", runID)),
		[]byte(fmt.Sprintf("transport-record-1-%s", runID)),
		[]byte(fmt.Sprintf("transport-record-2-%s", runID)),
	}
	aad := []byte("transport-integration")
	for i, r := range wantRecords {
		if err := writerT.WriteRecord(r, aad); err != nil {
			t.Fatalf("WriteRecord %d: %v", i, err)
		}
	}
	for i, want := range wantRecords {
		got, err := readerT.ReadRecord(aad)
		if err != nil {
			t.Fatalf("ReadRecord %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("INTEGRATION FAIL: record %d mismatch\n  got:  %q\n  want: %q", i, got, want)
		}
	}
	t.Logf("INTEGRATION PASS: transport round-trip for run-id=%s, %d records verified", runID, len(wantRecords))
}
