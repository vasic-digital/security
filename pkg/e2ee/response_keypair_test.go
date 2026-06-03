package e2ee

// Anti-bluff tests for the per-request bidirectional response keypair.
//
// These tests prove the security property that actually matters for the Chutes
// confidential-inference pattern: each request carries its own ephemeral response
// key, the worker seals the response to THAT key, and a response sealed for one
// request CANNOT be opened with another request's keypair (per-request
// isolation). They assert distinctness + isolation + round-trip correctness, not
// exact key bytes (key generation uses crypto/rand).
//
// Run: cd security && GOMAXPROCS=2 nice -n 19 go test ./pkg/e2ee/ -race -count=1 \
//        -run TestResponseKeypair

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

func mustResponseKeypair(t *testing.T, cfg SessionConfig) *ResponseKeypair {
	t.Helper()
	rk, err := NewResponseKeypair(cfg)
	if err != nil {
		t.Fatalf("NewResponseKeypair: %v", err)
	}
	return rk
}

// randPayload returns a per-run unique payload so no cached/precomputed value can
// produce a false PASS — the bytes must survive the full ML-KEM + HKDF +
// AES-256-GCM round trip.
func randPayload(t *testing.T, tag string) []byte {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return []byte(fmt.Sprintf("e2ee-resp-%s-%s", tag, hex.EncodeToString(b)))
}

// TestResponseKeypair_RotationFingerprintDiffers proves per-request rotation:
// keypairs generated for two sequential requests have distinct fingerprints and
// distinct public keys.
func TestResponseKeypair_RotationFingerprintDiffers(t *testing.T) {
	cfgs := []struct {
		name string
		cfg  SessionConfig
	}{
		{"zero-config", SessionConfig{}},
		{"counter-nonce", SessionConfig{CounterNonce: true}},
		{"custom-info", SessionConfig{Info: "helix-resp-test"}},
	}
	for _, tc := range cfgs {
		t.Run(tc.name, func(t *testing.T) {
			req1 := mustResponseKeypair(t, tc.cfg)
			req2 := mustResponseKeypair(t, tc.cfg)

			fp1, fp2 := req1.Fingerprint(), req2.Fingerprint()
			if fp1 == "" {
				t.Fatal("Fingerprint returned empty string")
			}
			if fp1 == fp2 {
				t.Fatalf("per-request fingerprints must differ (rotation failed): both %q", fp1)
			}
			if bytes.Equal(req1.PublicKey(), req2.PublicKey()) {
				t.Fatal("per-request public keys must differ (rotation failed)")
			}
			// Fingerprint is stable for the same keypair.
			if got := req1.Fingerprint(); got != fp1 {
				t.Fatalf("fingerprint not stable: first %q, second %q", fp1, got)
			}
		})
	}
}

// TestResponseKeypair_Isolation is the load-bearing test: a response sealed to
// request-1's keypair MUST open with request-1's keypair and MUST NOT open with
// request-2's keypair. This proves responses are cryptographically bound to their
// per-request response key.
func TestResponseKeypair_Isolation(t *testing.T) {
	cases := []struct {
		name string
		cfg  SessionConfig
		aad  []byte
	}{
		{"zero-config-nil-aad", SessionConfig{}, nil},
		{"counter-nonce-with-aad", SessionConfig{CounterNonce: true}, []byte("req-1-aad")},
		{"custom-info-with-aad", SessionConfig{Info: "helix-resp-iso"}, []byte("ctx")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req1 := mustResponseKeypair(t, tc.cfg)
			req2 := mustResponseKeypair(t, tc.cfg)

			payload := randPayload(t, "isolation")

			// Worker seals the response to request-1's response public key.
			env, err := SealResponse(req1.PublicKey(), payload, tc.aad, tc.cfg)
			if err != nil {
				t.Fatalf("SealResponse: %v", err)
			}

			// request-1 opens correctly (sink-side byte-exact assertion).
			got, err := req1.OpenResponse(env, tc.aad)
			if err != nil {
				t.Fatalf("req1.OpenResponse: unexpected error: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("req1 round-trip mismatch: got %q want %q", got, payload)
			}

			// request-2 MUST NOT be able to open request-1's envelope.
			if _, err := req2.OpenResponse(env, tc.aad); err == nil {
				t.Fatal("ISOLATION VIOLATION: request-2's keypair opened request-1's envelope")
			}
		})
	}
}

// TestResponseKeypair_RoundTrip proves normal-request correctness across configs
// and payload sizes, including AAD-mismatch rejection.
func TestResponseKeypair_RoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		cfg       SessionConfig
		plaintext []byte
		sealAAD   []byte
		openAAD   []byte
		wantOpen  bool
	}{
		{"empty-payload", SessionConfig{}, []byte{}, []byte("a"), []byte("a"), true},
		{"counter-nonce", SessionConfig{CounterNonce: true}, []byte("hello-worker"), nil, nil, true},
		{"large-payload", SessionConfig{}, bytes.Repeat([]byte("X"), 4096), []byte("aad"), []byte("aad"), true},
		{"aad-mismatch-rejected", SessionConfig{}, []byte("secret"), []byte("aad-1"), []byte("aad-2"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rk := mustResponseKeypair(t, tc.cfg)
			env, err := SealResponse(rk.PublicKey(), tc.plaintext, tc.sealAAD, tc.cfg)
			if err != nil {
				t.Fatalf("SealResponse: %v", err)
			}
			got, err := rk.OpenResponse(env, tc.openAAD)
			if tc.wantOpen {
				if err != nil {
					t.Fatalf("OpenResponse: unexpected error: %v", err)
				}
				if !bytes.Equal(got, tc.plaintext) {
					t.Fatalf("round-trip mismatch: got %q want %q", got, tc.plaintext)
				}
			} else {
				if err == nil {
					t.Fatal("expected Open failure on AAD mismatch, got nil")
				}
				if !errors.Is(err, ErrOpen) {
					t.Fatalf("expected ErrOpen on AAD mismatch, got %v", err)
				}
			}
		})
	}
}

// TestResponseKeypair_NilEnvelope guards the nil-envelope path.
func TestResponseKeypair_NilEnvelope(t *testing.T) {
	rk := mustResponseKeypair(t, SessionConfig{})
	if _, err := rk.OpenResponse(nil, nil); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("expected ErrInvalidCiphertext for nil envelope, got %v", err)
	}
}
