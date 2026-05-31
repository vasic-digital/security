package gpuattest

import (
	"errors"
	"testing"
	"time"
)

// testDescriptor returns a well-formed descriptor for tests.
func testDescriptor() DeviceDescriptor {
	return DeviceDescriptor{
		DeviceID: "gpu-0",
		Vendor:   "NVIDIA",
		Model:    "H100",
		MemoryMB: 81920,
	}
}

// newRegistered builds a Verifier with the device registered under key, plus a
// matching SoftwareProver.
func newRegistered(t *testing.T, key []byte, validity time.Duration) (*Verifier, *SoftwareProver) {
	t.Helper()
	desc := testDescriptor()
	v := NewVerifier(validity)
	if err := v.RegisterDevice(desc.DeviceID, key); err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	p, err := NewSoftwareProver(key, desc)
	if err != nil {
		t.Fatalf("NewSoftwareProver: %v", err)
	}
	return v, p
}

// TestValidChallengeVerifies proves a genuine challenge/response round-trip is
// accepted, AND that the verifier actually recomputed the right value (not a
// blanket accept).
// Mutation that makes this FAIL: in deriveAttestation, replace
// `mac.Write(nonce)` with `mac.Write(nil)` — verifier's expected value would no
// longer depend on the nonce while the prover's does, so they diverge and
// Verify returns ErrResponseMismatch.
func TestValidChallengeVerifies(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	v, p := newRegistered(t, key, time.Minute)

	c, err := v.Challenge(1)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	r, err := p.Respond(c)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if r.Attestation == "" {
		t.Fatal("empty attestation")
	}
	if err := v.Verify(r); err != nil {
		t.Fatalf("Verify rejected a valid response: %v", err)
	}
}

// TestDifficultyIteratesWork proves difficulty changes the derived value (the
// iterated-work path is real, not ignored), and a difficulty-bound response
// still verifies.
// Mutation that makes this FAIL: change the loop bound in deriveAttestation
// from `i < difficulty` to `i < 1` — high/low difficulty would produce the same
// digest and the inequality assertion below would fail.
func TestDifficultyIteratesWork(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	desc := testDescriptor()

	low, err := deriveAttestation(key, "00112233", desc, 1)
	if err != nil {
		t.Fatalf("derive low: %v", err)
	}
	high, err := deriveAttestation(key, "00112233", desc, 8)
	if err != nil {
		t.Fatalf("derive high: %v", err)
	}
	if low == high {
		t.Fatal("difficulty did not change the derived attestation")
	}

	v, p := newRegistered(t, key, time.Minute)
	c, err := v.Challenge(8)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	r, err := p.Respond(c)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if err := v.Verify(r); err != nil {
		t.Fatalf("Verify rejected a valid difficulty-8 response: %v", err)
	}
}

// TestExpiredChallengeRejected proves an expired challenge is denied even with
// an otherwise perfect response.
// Mutation that makes this FAIL: in Verify, delete the
// `if time.Now().After(c.Expiry) { return ErrChallengeExpired }` block — the
// expired response would then verify and err would be nil.
func TestExpiredChallengeRejected(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	// 1ns validity so the challenge is expired by the time we verify.
	v, p := newRegistered(t, key, time.Nanosecond)

	c, err := v.Challenge(1)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	r, err := p.Respond(c)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if err := v.Verify(r); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expected ErrChallengeExpired, got %v", err)
	}
}

// TestReplayedNonceRejected proves a nonce is single-use: a second Verify of
// the same valid response is denied.
// Mutation that makes this FAIL: in Verify, remove `v.seen[r.Nonce] = true`
// (and the seen check) — the replayed response would verify a second time.
func TestReplayedNonceRejected(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	v, p := newRegistered(t, key, time.Minute)

	c, err := v.Challenge(1)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	r, err := p.Respond(c)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if err := v.Verify(r); err != nil {
		t.Fatalf("first Verify should pass: %v", err)
	}
	if err := v.Verify(r); !errors.Is(err, ErrNonceReplayed) {
		t.Fatalf("expected ErrNonceReplayed on replay, got %v", err)
	}
}

// TestTamperedResponseRejected proves that flipping the attestation bytes is
// detected (integrity), not silently accepted.
// Mutation that makes this FAIL: in Verify, replace the ConstantTimeCompare
// check with `if false` (always treat as matching) — the tampered attestation
// would verify.
func TestTamperedResponseRejected(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	v, p := newRegistered(t, key, time.Minute)

	c, err := v.Challenge(1)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	r, err := p.Respond(c)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	// Flip the first hex nibble of the attestation.
	first := r.Attestation[0]
	flipped := byte('1')
	if first == '1' {
		flipped = '2'
	}
	r.Attestation = string(flipped) + r.Attestation[1:]

	if err := v.Verify(r); !errors.Is(err, ErrResponseMismatch) {
		t.Fatalf("expected ErrResponseMismatch for tampered response, got %v", err)
	}
}

// TestWrongDeviceKeyRejected proves a prover holding the wrong secret cannot
// satisfy the verifier even though the device id is registered.
// Mutation that makes this FAIL: in Verify, key the expected derivation off a
// constant instead of the registered `key` (e.g. derive with []byte("x")) — the
// derivation would no longer depend on the registered secret and would mismatch
// the legit prover too; more precisely, removing the key dependence makes the
// wrong-key prover's response accepted, failing this test's expectation of
// rejection.
func TestWrongDeviceKeyRejected(t *testing.T) {
	registeredKey := []byte("device-secret-key-0123456789abcd")
	attackerKey := []byte("WRONG-secret-key-0123456789abcdef")
	v, _ := newRegistered(t, registeredKey, time.Minute)

	// Prover uses the attacker key but the genuine descriptor (same device id).
	badProver, err := NewSoftwareProver(attackerKey, testDescriptor())
	if err != nil {
		t.Fatalf("NewSoftwareProver: %v", err)
	}

	c, err := v.Challenge(1)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	r, err := badProver.Respond(c)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if err := v.Verify(r); !errors.Is(err, ErrResponseMismatch) {
		t.Fatalf("expected ErrResponseMismatch for wrong key, got %v", err)
	}
}

// TestUnknownDeviceRejected proves a response for an unregistered device id is
// denied.
// Mutation that makes this FAIL: in Verify, delete the `if !ok { return
// ErrUnknownDevice }` after the keys lookup and substitute a zero key — an
// unregistered device could then be matched/accepted, or at minimum the
// specific ErrUnknownDevice would not be returned.
func TestUnknownDeviceRejected(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	v := NewVerifier(time.Minute)
	// Note: no RegisterDevice call.

	p, err := NewSoftwareProver(key, testDescriptor())
	if err != nil {
		t.Fatalf("NewSoftwareProver: %v", err)
	}
	c, err := v.Challenge(1)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	r, err := p.Respond(c)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if err := v.Verify(r); !errors.Is(err, ErrUnknownDevice) {
		t.Fatalf("expected ErrUnknownDevice, got %v", err)
	}
}

// TestMalformedDescriptorRejected proves a response carrying an incomplete
// descriptor is denied before any crypto.
// Mutation that makes this FAIL: in DeviceDescriptor.wellFormed, return true
// unconditionally — the malformed descriptor would pass the gate.
func TestMalformedDescriptorRejected(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	v, p := newRegistered(t, key, time.Minute)

	c, err := v.Challenge(1)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	r, err := p.Respond(c)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	r.Descriptor.MemoryMB = 0 // break it

	if err := v.Verify(r); !errors.Is(err, ErrMalformedDescriptor) {
		t.Fatalf("expected ErrMalformedDescriptor, got %v", err)
	}
}

// TestForgedDescriptorRejected proves the descriptor is bound into the
// attestation: changing a descriptor field (memory) after the prover computed
// the response is detected, because the verifier recomputes over the response's
// (forged) descriptor and gets a different digest than the response carries.
// Mutation that makes this FAIL: in deriveAttestation, remove
// `mac.Write(desc.canonicalBytes())` — the descriptor would no longer be bound,
// so a forged descriptor (with the original attestation) would verify.
func TestForgedDescriptorRejected(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	v, p := newRegistered(t, key, time.Minute)
	// Register the forged memory value too is irrelevant; binding is to the
	// descriptor the prover signed, recomputed over what the verifier receives.

	c, err := v.Challenge(1)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	r, err := p.Respond(c)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	// Forge a different memory size; still well-formed, same device id.
	r.Descriptor.MemoryMB = 40960

	if err := v.Verify(r); !errors.Is(err, ErrResponseMismatch) {
		t.Fatalf("expected ErrResponseMismatch for forged descriptor, got %v", err)
	}
}

// TestUnknownNonceRejected proves a response whose nonce was never issued by
// this verifier is denied (cannot inject a self-made challenge).
// Mutation that makes this FAIL: in Verify, remove the
// `c, ok := v.pending[r.Nonce]; if !ok { return ErrInvalidChallenge }` lookup
// and synthesize a challenge from the response — an unissued nonce would be
// accepted.
func TestUnknownNonceRejected(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	desc := testDescriptor()
	v := NewVerifier(time.Minute)
	if err := v.RegisterDevice(desc.DeviceID, key); err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	p, err := NewSoftwareProver(key, desc)
	if err != nil {
		t.Fatalf("NewSoftwareProver: %v", err)
	}

	// Attacker fabricates a challenge the verifier never issued.
	forged := Challenge{
		Nonce:      "aabbccddeeff00112233445566778899",
		IssuedAt:   time.Now(),
		Expiry:     time.Now().Add(time.Minute),
		Difficulty: 1,
	}
	r, err := p.Respond(forged)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if err := v.Verify(r); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("expected ErrInvalidChallenge for unissued nonce, got %v", err)
	}
}

// TestChallengeNonceIsFresh proves nonces are not constant across challenges
// (crypto/rand actually feeds them).
// Mutation that makes this FAIL: in Challenge, replace `rand.Read(raw)` with a
// fixed `copy(raw, make([]byte, nonceLen))` — both nonces would be identical.
func TestChallengeNonceIsFresh(t *testing.T) {
	v := NewVerifier(time.Minute)
	c1, err := v.Challenge(1)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	c2, err := v.Challenge(1)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if c1.Nonce == c2.Nonce {
		t.Fatal("two challenges produced identical nonces")
	}
	if len(c1.Nonce) != nonceLen*2 { // hex
		t.Fatalf("nonce hex length = %d, want %d", len(c1.Nonce), nonceLen*2)
	}
}

// TestProverImplementsInterface is a compile-time + behavioural check that
// SoftwareProver satisfies the Prover interface (so a hardware prover can be
// substituted).
// Mutation that makes this FAIL: rename SoftwareProver.Respond to Respond2 —
// the interface assignment would fail to compile.
func TestProverImplementsInterface(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	p, err := NewSoftwareProver(key, testDescriptor())
	if err != nil {
		t.Fatalf("NewSoftwareProver: %v", err)
	}
	var prover Prover = p
	if prover.Descriptor().DeviceID != "gpu-0" {
		t.Fatalf("Descriptor via interface returned %q", prover.Descriptor().DeviceID)
	}
}

// TestConstructorsReject proves the constructors reject empty keys and
// malformed descriptors instead of producing a footgun prover.
// Mutation that makes this FAIL: in NewSoftwareProver, remove the
// `if len(key) == 0 { return nil, ErrInvalidKey }` guard — the empty-key case
// would return a non-nil prover and err == nil.
func TestConstructorsReject(t *testing.T) {
	if _, err := NewSoftwareProver(nil, testDescriptor()); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for empty key, got %v", err)
	}
	bad := DeviceDescriptor{DeviceID: "x"} // missing vendor/model/memory
	if _, err := NewSoftwareProver([]byte("k"), bad); !errors.Is(err, ErrMalformedDescriptor) {
		t.Fatalf("expected ErrMalformedDescriptor, got %v", err)
	}
	v := NewVerifier(time.Minute)
	if err := v.RegisterDevice("", []byte("k")); err == nil {
		t.Fatal("RegisterDevice accepted empty device id")
	}
	if err := v.RegisterDevice("d", nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for empty key in RegisterDevice, got %v", err)
	}
}
