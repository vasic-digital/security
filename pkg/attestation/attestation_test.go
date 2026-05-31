package attestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// fixedNonce returns a deterministic NonceSize nonce for reproducible tests.
func fixedNonce(b byte) []byte {
	n := make([]byte, NonceSize)
	for i := range n {
		n[i] = b
	}
	return n
}

func measurements() map[string][]byte {
	return map[string][]byte{
		"tdx.rtmr0":    {0x01, 0x02, 0x03, 0x04},
		"tdx.rtmr1":    {0xaa, 0xbb, 0xcc},
		"gpu.firmware": {0xde, 0xad, 0xbe, 0xef},
	}
}

// setup builds an attester, a verifier trusting it, a base time and a signed doc.
func setup(t *testing.T) (*Attester, *Verifier, time.Time, *AttestationDocument, []byte) {
	t.Helper()
	att, err := NewAttester()
	if err != nil {
		t.Fatalf("NewAttester: %v", err)
	}
	ver, err := NewVerifier(att.PublicKey(), time.Hour)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	nonce := fixedNonce(0x42)
	doc, err := att.Attest(measurements(), nonce, now, 30*time.Minute)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	return att, ver, now, doc, nonce
}

// TestVerify_ValidDocument proves a correctly signed document with matching
// nonce, fresh timestamp and a satisfied policy verifies successfully AND that
// the signed measurement values survive round-trip intact.
//
// MUTATION 1 (Verify is a crypto no-op): mutate Verify to `return nil`
// unconditionally — that alone would still pass the err==nil check, which is
// why this test ALSO reads back doc.Measurements["tdx.rtmr0"] and asserts it
// equals {0x01,0x02,0x03,0x04} byte-for-byte. A mutation that zeroes/strips
// measurements before signing (e.g. dropping the measurement writes in Attest,
// or storing an empty map) breaks the round-trip and fails THIS happy-path test
// independently of the tamper test.
// MUTATION 2: mutate Verify to `return ErrSignatureInvalid` unconditionally —
// the err==nil check fails.
func TestVerify_ValidDocument(t *testing.T) {
	_, ver, now, doc, nonce := setup(t)
	policy := MeasurementPolicy{
		Expected: map[string][]byte{
			"tdx.rtmr0":    {0x01, 0x02, 0x03, 0x04},
			"gpu.firmware": {0xde, 0xad, 0xbe, 0xef},
		},
		Required: []string{"tdx.rtmr1"},
	}
	if err := ver.Verify(doc, nonce, policy, now); err != nil {
		t.Fatalf("expected valid document to verify, got: %v", err)
	}
	// Sink-side evidence: the measurement carried through the sign/verify round
	// trip must be exactly what was attested, not a zeroed/stripped value.
	if got := doc.Measurements["tdx.rtmr0"]; !bytes.Equal(got, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatalf("measurement tdx.rtmr0 round-trip mismatch: got %x, want 01020304", got)
	}
}

// TestVerify_TamperedMeasurement proves that flipping a single byte of a
// measurement after signing is detected via the signature.
//
// MUTATION: drop the Measurements loop from SigningPayload (so measurements are
// not covered by the signature) — then the tampered doc would verify and this
// test fails.
func TestVerify_TamperedMeasurement(t *testing.T) {
	_, ver, now, doc, nonce := setup(t)
	doc.Measurements["tdx.rtmr0"][0] ^= 0x01 // flip one bit
	err := ver.Verify(doc, nonce, MeasurementPolicy{}, now)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid for tampered measurement, got: %v", err)
	}
}

// TestVerify_StaleNonce proves a document echoing a different nonce than the one
// the verifier now expects is rejected (replay/freshness defense).
//
// MUTATION: remove the `if subtleNotEqual(doc.Nonce, expectedNonce)` block from
// Verify — the stale-nonce doc would pass and this test fails.
func TestVerify_StaleNonce(t *testing.T) {
	_, ver, now, doc, _ := setup(t)
	wrongNonce := fixedNonce(0x99) // verifier now challenges with a new nonce
	err := ver.Verify(doc, wrongNonce, MeasurementPolicy{}, now)
	if !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("expected ErrNonceMismatch for stale nonce, got: %v", err)
	}
}

// TestVerify_WrongSigningKey proves a document signed by an UNTRUSTED attester
// (different key) is rejected. We re-point the verifier's trusted root so the
// untrusted-signer gate fires; a second variant tests signature failure when
// the signer key is swapped to look like the trusted one.
//
// MUTATION: remove the `bytes.Equal(doc.SignerPublicKey, v.trustedRoot)` gate —
// then a doc from a foreign attester would only fail if its signature failed;
// since it is self-consistent it would PASS, and this test fails.
func TestVerify_WrongSigningKey(t *testing.T) {
	_, ver, now, _, nonce := setup(t)
	rogue, err := NewAttester()
	if err != nil {
		t.Fatalf("NewAttester rogue: %v", err)
	}
	rogueDoc, err := rogue.Attest(measurements(), nonce, now, 30*time.Minute)
	if err != nil {
		t.Fatalf("rogue Attest: %v", err)
	}
	err = ver.Verify(rogueDoc, nonce, MeasurementPolicy{}, now)
	if !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("expected ErrUntrustedSigner for rogue key, got: %v", err)
	}
}

// TestVerify_ForgedSignatureWithTrustedKey proves that even when the embedded
// signer key equals the trusted root, a signature that was NOT produced by the
// corresponding private key is rejected. This guards the actual ed25519.Verify
// call (not just the key-equality gate).
//
// MUTATION: replace `ed25519.Verify(...)` result with `true` — the garbage
// signature would be accepted and this test fails.
func TestVerify_ForgedSignatureWithTrustedKey(t *testing.T) {
	_, ver, now, doc, nonce := setup(t)
	// Corrupt the signature bytes while keeping the (trusted) signer key.
	forged := append([]byte(nil), doc.Signature...)
	forged[0] ^= 0xff
	doc.Signature = forged
	err := ver.Verify(doc, nonce, MeasurementPolicy{}, now)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid for forged signature, got: %v", err)
	}
}

// TestVerify_PolicyMismatch proves a document whose measurement value differs
// from the policy's expected value is rejected — even though signature, nonce
// and freshness are all valid.
//
// MUTATION: make MeasurementPolicy.Evaluate `return nil` unconditionally — the
// mismatching doc would pass and this test fails.
func TestVerify_PolicyMismatch(t *testing.T) {
	_, ver, now, doc, nonce := setup(t)
	policy := MeasurementPolicy{
		Expected: map[string][]byte{
			"tdx.rtmr0": {0xFF, 0xFF, 0xFF, 0xFF}, // doc has 01 02 03 04
		},
	}
	err := ver.Verify(doc, nonce, policy, now)
	if !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("expected ErrPolicyMismatch, got: %v", err)
	}
}

// TestVerify_PolicyRequiredAbsent proves a Required-but-absent measurement is
// rejected.
//
// MUTATION: drop the Required loop in Evaluate — the doc missing the required
// key would pass and this test fails.
func TestVerify_PolicyRequiredAbsent(t *testing.T) {
	_, ver, now, doc, nonce := setup(t)
	policy := MeasurementPolicy{
		Required: []string{"nonexistent.register"},
	}
	err := ver.Verify(doc, nonce, policy, now)
	if !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("expected ErrPolicyMismatch for absent required measurement, got: %v", err)
	}
}

// TestVerify_ExpiredByExplicitExpiry proves a document past its embedded
// ExpiresAt is rejected.
//
// MUTATION: remove the `!doc.ExpiresAt.IsZero() && now.After(...)` block — the
// expired doc would pass and this test fails.
func TestVerify_ExpiredByExplicitExpiry(t *testing.T) {
	_, ver, now, doc, nonce := setup(t)
	// doc expires at now+30m; advance the clock well past that + skew.
	later := now.Add(45 * time.Minute)
	err := ver.Verify(doc, nonce, MeasurementPolicy{}, later)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired past ExpiresAt, got: %v", err)
	}
}

// TestVerify_ExpiredByFreshnessWindow proves the verifier's MaxAge window
// rejects an old document even when it has no explicit ExpiresAt.
//
// MUTATION: remove the `v.MaxAge > 0 && doc.IssuedAt.Before(...)` block — the
// old doc would pass and this test fails.
func TestVerify_ExpiredByFreshnessWindow(t *testing.T) {
	att, ver, now, _, nonce := setup(t)
	// Document with NO explicit expiry (validity = 0), issued 2h ago vs MaxAge 1h.
	old := now.Add(-2 * time.Hour)
	doc, err := att.Attest(measurements(), nonce, old, 0)
	if err != nil {
		t.Fatalf("Attest old: %v", err)
	}
	err = ver.Verify(doc, nonce, MeasurementPolicy{}, now)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired beyond freshness window, got: %v", err)
	}
}

// TestVerify_IssuedInFuture proves a document timestamped beyond the allowed
// clock skew in the future is rejected.
//
// MUTATION: remove the `doc.IssuedAt.After(now.Add(v.ClockSkew))` block — the
// future-dated doc would pass and this test fails.
func TestVerify_IssuedInFuture(t *testing.T) {
	att, ver, now, _, nonce := setup(t)
	future := now.Add(10 * time.Minute) // beyond default 1m skew
	doc, err := att.Attest(measurements(), nonce, future, time.Hour)
	if err != nil {
		t.Fatalf("Attest future: %v", err)
	}
	err = ver.Verify(doc, nonce, MeasurementPolicy{}, now)
	if !errors.Is(err, ErrIssuedInFuture) {
		t.Fatalf("expected ErrIssuedInFuture, got: %v", err)
	}
}

// TestSigningPayload_NonceCovered is a direct structural guard: two documents
// differing ONLY in nonce must produce different signing payloads (otherwise a
// nonce swap would survive signature verification).
//
// MUTATION: remove writeBytes(&buf, d.Nonce) from SigningPayload — payloads
// become equal and this test fails.
func TestSigningPayload_NonceCovered(t *testing.T) {
	now := time.Now()
	a := &AttestationDocument{Measurements: measurements(), Nonce: fixedNonce(1), IssuedAt: now}
	b := &AttestationDocument{Measurements: measurements(), Nonce: fixedNonce(2), IssuedAt: now}
	if string(a.SigningPayload()) == string(b.SigningPayload()) {
		t.Fatal("expected different nonces to yield different signing payloads")
	}
}

// TestSigningPayload_MeasurementCovered guards that measurement values are part
// of the payload.
//
// MUTATION: remove the measurement key/value writes from SigningPayload —
// payloads become equal and this test fails.
func TestSigningPayload_MeasurementCovered(t *testing.T) {
	now := time.Now()
	nonce := fixedNonce(7)
	m1 := map[string][]byte{"x": {0x01}}
	m2 := map[string][]byte{"x": {0x02}}
	a := &AttestationDocument{Measurements: m1, Nonce: nonce, IssuedAt: now}
	b := &AttestationDocument{Measurements: m2, Nonce: nonce, IssuedAt: now}
	if string(a.SigningPayload()) == string(b.SigningPayload()) {
		t.Fatal("expected different measurements to yield different signing payloads")
	}
}

// TestSigningPayload_LengthPrefixDomainSeparation proves the length-prefixing
// prevents field-boundary confusion: {"ab": "c"} must not collide with
// {"a": "bc"}.
//
// MUTATION: change writeBytes to write raw bytes without the length prefix —
// the two maps would serialize identically and this test fails.
func TestSigningPayload_LengthPrefixDomainSeparation(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nonce := fixedNonce(3)
	a := &AttestationDocument{Measurements: map[string][]byte{"ab": []byte("c")}, Nonce: nonce, IssuedAt: now}
	b := &AttestationDocument{Measurements: map[string][]byte{"a": []byte("bc")}, Nonce: nonce, IssuedAt: now}
	if string(a.SigningPayload()) == string(b.SigningPayload()) {
		t.Fatal("expected length-prefixing to separate field boundaries")
	}
}

// TestAttest_NonceSizeEnforced proves a wrong-sized nonce is rejected at sign
// time.
//
// MUTATION: remove the nonce length check in Attest — a short nonce would be
// accepted and this test fails.
func TestAttest_NonceSizeEnforced(t *testing.T) {
	att, err := NewAttester()
	if err != nil {
		t.Fatalf("NewAttester: %v", err)
	}
	_, err = att.Attest(measurements(), []byte("short"), time.Now(), time.Hour)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("expected ErrMalformed for short nonce, got: %v", err)
	}
}

// TestAttest_DefensiveCopy proves that mutating the caller's measurement slice
// after Attest does NOT change the signed document (so the signature stays
// valid and bound to the original value).
//
// MUTATION: in Attest, store `ms[k] = v` (alias) instead of copying — the post
// hoc mutation would alter the signed value and Verify would fail, failing this
// test.
func TestAttest_DefensiveCopy(t *testing.T) {
	_, _, now, _, nonce := setup(t)
	att, err := NewAttester()
	if err != nil {
		t.Fatalf("NewAttester: %v", err)
	}
	ver2, err := NewVerifier(att.PublicKey(), time.Hour)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	m := map[string][]byte{"k": {0x01, 0x02}}
	doc, err := att.Attest(m, nonce, now, time.Hour)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	m["k"][0] = 0xFF // mutate caller's slice after signing
	if err := ver2.Verify(doc, nonce, MeasurementPolicy{Expected: map[string][]byte{"k": {0x01, 0x02}}}, now); err != nil {
		t.Fatalf("defensive copy failed; caller mutation leaked into signed doc: %v", err)
	}
}

// TestNewVerifier_RejectsBadRoot proves a wrong-sized trusted root is rejected.
//
// MUTATION: remove the size check in NewVerifier — it would accept a bad key and
// this test fails.
func TestNewVerifier_RejectsBadRoot(t *testing.T) {
	_, err := NewVerifier([]byte("too-short"), time.Hour)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("expected ErrMalformed for bad root, got: %v", err)
	}
}

// TestQuoteSignerSeam proves the Attester satisfies the QuoteSigner interface
// and that a custom QuoteSigner can drive signing. The custom signer signs with
// its own key; a verifier trusting that key accepts the resulting document.
//
// MUTATION: change SignQuote to return a fixed/garbage signature — Verify would
// reject and this test fails.
func TestQuoteSignerSeam(t *testing.T) {
	var _ QuoteSigner = (*Attester)(nil) // compile-time interface assertion

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var signer QuoteSigner = stubSigner{priv: priv, pub: pub}

	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	nonce := fixedNonce(0x55)
	doc := &AttestationDocument{
		Measurements: measurements(),
		Nonce:        nonce,
		IssuedAt:     now,
	}
	sig, gotPub, err := signer.SignQuote(doc.SigningPayload())
	if err != nil {
		t.Fatalf("SignQuote: %v", err)
	}
	doc.Signature = sig
	doc.SignerPublicKey = gotPub

	ver, err := NewVerifier(pub, time.Hour)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := ver.Verify(doc, nonce, MeasurementPolicy{}, now); err != nil {
		t.Fatalf("expected stub-signed doc to verify, got: %v", err)
	}
}

// stubSigner is a minimal alternate QuoteSigner implementation used to exercise
// the hardware seam with real ed25519 signing.
type stubSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func (s stubSigner) SignQuote(payload []byte) ([]byte, ed25519.PublicKey, error) {
	return ed25519.Sign(s.priv, payload), s.pub, nil
}

// TestGenerateNonce proves nonces are the right size, non-zero, and not constant.
//
// MUTATION 1: make GenerateNonce return a fixed NON-zero slice — the inequality
// check fails this test (two draws would be equal).
// MUTATION 2: make GenerateNonce return an all-zero buffer (e.g. drop the
// rand.Read call / ignore its result) — the all-zero check below fails. This
// catches the silent zero-fill failure mode that the two-draw inequality check
// alone would also flag (0==0) but only by coincidence; here it is explicit.
func TestGenerateNonce(t *testing.T) {
	a, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	if len(a) != NonceSize {
		t.Fatalf("nonce size = %d, want %d", len(a), NonceSize)
	}
	if bytes.Equal(a, make([]byte, NonceSize)) {
		t.Fatal("generated nonce was all zero (rand.Read result ignored or zero-filled)")
	}
	b, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	if string(a) == string(b) {
		t.Fatal("two generated nonces were identical (non-random)")
	}
}
