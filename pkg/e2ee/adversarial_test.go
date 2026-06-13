package e2ee

// Adversarial / negative tests for the post-quantum E2EE envelope.
//
// These tests exist to defeat the "PASS-bluff" failure mode: a happy-path
// round-trip test proves the encrypt->decrypt path runs, but it does NOT prove
// the security property — that tampering or a wrong key is actually REJECTED.
// Every assertion below is written so that it FAILS if the corresponding
// security check were removed from production code. Each test names, in a
// comment, the exact mutation that makes it fail ("why it bites"). The wider
// session-level surface (single-bit ciphertext flip, AAD mismatch, wrong
// session, replay) is already covered in package_test.go; this file fills the
// remaining gaps the task called out specifically:
//
//   1. AEAD tag-byte flip, tag truncation, and nonce-substitution at the
//      Session.Open layer (the existing suite flips a body byte and the nonce,
//      but not the trailing tag specifically, nor truncation, nor swapping in a
//      different *valid-length* nonce than the one that sealed).
//   2. The ML-KEM-768 KEM primitive's wrong-key / implicit-rejection property,
//      proven directly on crypto/mlkem AND end-to-end through the package's
//      Initiator/Respond/Complete handshake — including a tampered KEM
//      ciphertext yielding a DIFFERENT channel secret that then fails to Open a
//      record sealed under the real secret.
//   3. Deterministic AEAD round-trip across several plaintext sizes incl. empty.
//
// Real keys: every test uses crypto/rand via the package keygen (GenerateKey768,
// random session keys) — never fixed zero keys.

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

// randKey returns a fresh 32-byte key from crypto/rand. Using real random keys
// (not a fixed zero key) ensures the tests exercise the cipher over realistic
// key material, as the task requires.
func randKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, SessionKeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	return k
}

// -----------------------------------------------------------------------------
// 1. AEAD tamper rejection (anti-bluff core) — gaps beyond package_test.go.
// -----------------------------------------------------------------------------

// TestSessionTamperedAuthTagFails proves the GCM/Poly1305 authentication tag is
// actually verified: flipping a byte in the TRAILING tag (the last 16 bytes of
// the record) makes Open fail. The existing suite flips a ciphertext-body byte;
// this targets the tag bytes specifically, which is where a "verify the tag"
// shortcut bug would hide.
//
// WHY IT BITES: if Session.Open's underlying aead.Open ignored the tag (e.g. a
// bluff impl that stripped the last 16 bytes and returned the rest), the
// tag-flipped record would "decrypt" and err would be nil — this test then
// FAILS. The untampered record still opens, so the assertion is not vacuous.
func TestSessionTamperedAuthTagFails(t *testing.T) {
	for _, suite := range []AEADSuite{SuiteAES256GCM, SuiteChaCha20Poly1305} {
		t.Run(suite.String(), func(t *testing.T) {
			isess, rsess := handshakeSuite(t, suite)
			pt := []byte("authentication tag must be checked")
			rec, err := isess.Seal(pt, []byte("aad"))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			// Untampered first, to prove the channel works at all.
			if got, err := rsess.Open(rec, []byte("aad")); err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("baseline Open: got %q err %v", got, err)
			}
			// Re-seal because Open consumed the nonce (replay guard).
			rec2, err := isess.Seal(pt, []byte("aad"))
			if err != nil {
				t.Fatalf("Seal 2: %v", err)
			}
			// Flip the LAST byte: that is inside the 16-byte auth tag.
			tampered := append([]byte(nil), rec2...)
			tampered[len(tampered)-1] ^= 0x80
			got, err := rsess.Open(tampered, []byte("aad"))
			if !errors.Is(err, ErrOpen) {
				t.Fatalf("expected ErrOpen on flipped auth tag, got err=%v plaintext=%q", err, got)
			}
			if got != nil {
				t.Fatalf("tampered Open returned non-nil plaintext %q (must yield NO plaintext)", got)
			}
			t.Logf("[%s] flipped-auth-tag record rejected: %v", suite, err)
		})
	}
}

// TestSessionTruncatedCiphertextFails proves that lopping bytes off the end of a
// record (destroying part of the tag) is rejected, not silently accepted. Two
// truncation depths are exercised: one byte short (tag damaged but record still
// long enough to pass the length guard) and a hard truncation into the body.
//
// WHY IT BITES: an Open that did not verify the tag length / contents would
// either panic or return partial plaintext on a truncated record; here it MUST
// return an error and NO plaintext. If the production length guard or tag check
// were removed, the one-byte-short case would slip through aead.Open as a forged
// shorter tag (rejected by real GCM) — a bluff impl returns nil err and fails.
func TestSessionTruncatedCiphertextFails(t *testing.T) {
	isess, rsess := handshake(t, SessionConfig{})
	rec, err := isess.Seal([]byte("do not truncate me"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// (a) One byte short: still longer than NonceSize+overhead-ish but the tag is
	// now incomplete/forged — real AEAD rejects it.
	short1 := rec[:len(rec)-1]
	if got, err := rsess.Open(short1, nil); err == nil || got != nil {
		t.Fatalf("one-byte-truncated record must fail: got %q err %v", got, err)
	} else {
		t.Logf("one-byte-truncated record rejected: %v", err)
	}
	// (b) Truncated below the minimum framed length -> ErrInvalidCiphertext.
	short2 := rec[:NonceSize+1]
	if got, err := rsess.Open(short2, nil); !errors.Is(err, ErrInvalidCiphertext) || got != nil {
		t.Fatalf("hard-truncated record: expected ErrInvalidCiphertext and nil pt, got %q err %v", got, err)
	} else {
		t.Logf("hard-truncated record rejected with ErrInvalidCiphertext: %v", err)
	}
}

// TestSessionNonceSubstitutionFails proves the nonce is bound into the AEAD
// authentication: replacing the record's 12-byte nonce prefix with a DIFFERENT
// valid-length nonce (one never used to seal this body) makes Open fail. This is
// distinct from package_test.go's TestTamperedNonceFails, which flips a single
// nonce byte; here we substitute a wholesale different, well-formed nonce, which
// is exactly what a man-in-the-middle replacing the framed nonce would do.
//
// WHY IT BITES: GCM/Poly1305 use the nonce as input to the tag computation, so a
// different nonce over the same ciphertext+tag fails authentication. If Open
// derived the tag without the nonce (a bluff), the substituted-nonce record
// would authenticate and this test FAILS. We assert no plaintext is returned.
func TestSessionNonceSubstitutionFails(t *testing.T) {
	isess, rsess := handshake(t, SessionConfig{})
	rec, err := isess.Seal([]byte("nonce binds the tag"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	tampered := append([]byte(nil), rec...)
	// Overwrite the nonce prefix with a different, valid-length nonce. Use a
	// value distinct from the original (XOR the whole prefix with 0xA5) so it is
	// guaranteed different yet still 12 well-formed bytes.
	for i := 0; i < NonceSize; i++ {
		tampered[i] ^= 0xA5
	}
	if bytes.Equal(tampered[:NonceSize], rec[:NonceSize]) {
		t.Fatal("test setup error: substituted nonce equals original")
	}
	got, err := rsess.Open(tampered, nil)
	if !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen on substituted nonce, got err=%v plaintext=%q", err, got)
	}
	if got != nil {
		t.Fatalf("substituted-nonce Open returned non-nil plaintext %q", got)
	}
	t.Logf("substituted-nonce record rejected: %v", err)
}

// -----------------------------------------------------------------------------
// 2. ML-KEM-768 wrong-key / implicit-rejection (post-quantum KEM anti-bluff).
// -----------------------------------------------------------------------------

// TestMLKEM768ImplicitRejectionPrimitive proves the post-quantum KEM property
// directly on crypto/mlkem (the primitive the handshake is built on), before any
// of the package's own derivation logic:
//
//   - Encapsulate to a public key -> (senderSecret, kemCT).
//   - Decapsulate kemCT with the CORRECT secret key -> recovers senderSecret
//     EXACTLY (happy path / correctness).
//   - Decapsulate the SAME kemCT with a DIFFERENT (wrong) secret key -> yields a
//     shared secret that DIFFERS from senderSecret. FIPS 203 ML-KEM uses
//     *implicit rejection*: a wrong key does not error, it deterministically
//     derives an unrelated secret, so a channel keyed on it cannot agree.
//   - Tamper one byte of kemCT and Decapsulate with the RIGHT key -> the derived
//     secret DIFFERS from senderSecret (again implicit rejection), so a MITM that
//     alters the KEM ciphertext cannot make both peers land on the same key.
//
// WHY IT BITES: if Decapsulate returned a constant, or ignored its key/ciphertext
// inputs, the wrong-key and tampered-ct secrets would EQUAL senderSecret and the
// "must differ" assertions FAIL. This is the core anti-bluff for the KEM: a fake
// Decapsulate that always "succeeds" is caught here.
func TestMLKEM768ImplicitRejectionPrimitive(t *testing.T) {
	dkRight, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768 (right): %v", err)
	}
	dkWrong, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768 (wrong): %v", err)
	}

	// Sender encapsulates to the RIGHT public key.
	senderSecret, kemCT := dkRight.EncapsulationKey().Encapsulate()
	if len(senderSecret) != mlkem.SharedKeySize {
		t.Fatalf("sender secret size %d, want %d", len(senderSecret), mlkem.SharedKeySize)
	}
	if len(kemCT) != mlkem.CiphertextSize768 {
		t.Fatalf("kem ciphertext size %d, want %d", len(kemCT), mlkem.CiphertextSize768)
	}

	// Happy path: correct key recovers the exact shared secret.
	recovered, err := dkRight.Decapsulate(kemCT)
	if err != nil {
		t.Fatalf("Decapsulate with correct key: %v", err)
	}
	if !bytes.Equal(recovered, senderSecret) {
		t.Fatalf("correct-key decapsulation did not recover sender secret:\n got  %x\n want %x",
			recovered, senderSecret)
	}
	t.Logf("correct-key decapsulation recovered sender secret (%d bytes)", len(recovered))

	// Wrong key: implicit rejection -> a DIFFERENT secret (no error expected).
	wrongSecret, err := dkWrong.Decapsulate(kemCT)
	if err != nil {
		t.Fatalf("Decapsulate with wrong key unexpectedly errored (ML-KEM uses implicit "+
			"rejection, should return a different secret, not error): %v", err)
	}
	if bytes.Equal(wrongSecret, senderSecret) {
		t.Fatal("wrong-key decapsulation produced the SAME shared secret as the sender — " +
			"implicit rejection is broken (a constant/stub Decapsulate would do this)")
	}
	t.Logf("wrong-key shared secret differs from sender secret (implicit rejection holds)")

	// Tampered KEM ciphertext, decapsulated with the RIGHT key: also a different
	// secret. A MITM altering the KEM ct cannot make the channel agree.
	tamperedCT := append([]byte(nil), kemCT...)
	tamperedCT[0] ^= 0x01
	tamperedSecret, err := dkRight.Decapsulate(tamperedCT)
	if err != nil {
		t.Fatalf("Decapsulate tampered ct with right key errored (implicit rejection should "+
			"yield a different secret, not error): %v", err)
	}
	if bytes.Equal(tamperedSecret, senderSecret) {
		t.Fatal("tampered-KEM-ciphertext decapsulation produced the SAME secret as the sender — " +
			"a MITM-altered KEM ct would yield the same channel key (security broken)")
	}
	t.Logf("tampered-KEM-ct shared secret differs from sender secret (MITM cannot agree)")
}

// TestHandshakeTamperedKemCiphertextBreaksChannel proves the full chain: a KEM
// ciphertext altered in flight makes the initiator derive a DIFFERENT session
// key than the responder, so the initiator cannot Open a record the responder
// sealed under the real secret. This is the end-to-end proof that tampering the
// KEM hop anywhere breaks the established channel.
//
// Flow: initiator publishes its encapsulation key; responder Respond()s,
// producing (kemCT, responderSession); we TAMPER kemCT before the initiator
// Complete()s; the initiator's resulting session keys off a different secret.
// The responder seals a record; the initiator's Open MUST fail.
//
// WHY IT BITES: if Complete ignored the ciphertext (constant key), or if the KEM
// implicit rejection were faked so a tampered ct still recovered the responder's
// secret, the keys would agree and Open would SUCCEED — this test then FAILS.
// KeysEqual is asserted false to make the key-disagreement explicit.
func TestHandshakeTamperedKemCiphertextBreaksChannel(t *testing.T) {
	cfg := SessionConfig{}
	in, err := NewInitiator(cfg)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	kemCT, rsess, err := Respond(in.EncapsulationKeyBytes(), cfg)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}

	// Responder seals a record under the REAL session key.
	secretMsg := []byte("only the real-secret peer may read this")
	rec, err := rsess.Seal(secretMsg, nil)
	if err != nil {
		t.Fatalf("responder Seal: %v", err)
	}

	// MITM flips one byte of the KEM ciphertext in transit. It is still the
	// correct length, so Complete's length guard passes and it reaches
	// Decapsulate — exercising the real implicit-rejection path.
	tamperedCT := append([]byte(nil), kemCT...)
	tamperedCT[len(tamperedCT)/2] ^= 0x01
	if len(tamperedCT) != kemCiphertextSize {
		t.Fatalf("tampered ct length %d, want %d (must stay valid length)", len(tamperedCT), kemCiphertextSize)
	}

	isess, err := in.Complete(tamperedCT, cfg)
	if err != nil {
		// Complete should still succeed structurally (implicit rejection gives a
		// secret, not an error); a hard error here would also be acceptable
		// security-wise, but the package's contract is to derive a (wrong) key.
		t.Fatalf("Complete on tampered ct errored (expected a derived-but-wrong key): %v", err)
	}

	// The two sessions MUST NOT share a key.
	if KeysEqual(isess, rsess) {
		t.Fatal("initiator and responder derived the SAME key despite tampered KEM ciphertext — " +
			"the channel is not bound to the KEM transcript (security broken)")
	}
	t.Logf("tampered KEM ct -> initiator/responder keys differ (channel not established)")

	// And the initiator cannot read the responder's real-secret record.
	got, err := isess.Open(rec, nil)
	if !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen opening real-secret record with tampered-KEM key, got err=%v pt=%q", err, got)
	}
	if got != nil {
		t.Fatalf("Open under wrong (tampered-KEM) key returned non-nil plaintext %q", got)
	}
	t.Logf("record sealed under real secret rejected by tampered-KEM session: %v", err)
}

// TestHandshakeWrongInitiatorCannotOpen proves that an initiator whose ephemeral
// keypair is NOT the one the responder encapsulated against derives a different
// session key (wrong-key path), and so cannot Open the responder's record. This
// is the handshake-level analogue of the primitive wrong-key test: the responder
// encapsulated to initiator A's public key, but initiator B tries to Complete
// the same ciphertext with its own (unrelated) secret key.
//
// WHY IT BITES: B decapsulating A's ciphertext exercises ML-KEM implicit
// rejection at the handshake layer; B lands on a different secret -> different
// session key -> Open fails. A stubbed Decapsulate returning a constant would
// make A and B agree, and the Open would succeed, failing this test.
func TestHandshakeWrongInitiatorCannotOpen(t *testing.T) {
	cfg := SessionConfig{}
	inA, err := NewInitiator(cfg)
	if err != nil {
		t.Fatalf("NewInitiator A: %v", err)
	}
	inB, err := NewInitiator(cfg)
	if err != nil {
		t.Fatalf("NewInitiator B: %v", err)
	}

	// Responder encapsulates against A's public key.
	kemCT, rsess, err := Respond(inA.EncapsulationKeyBytes(), cfg)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	rec, err := rsess.Seal([]byte("addressed to initiator A"), nil)
	if err != nil {
		t.Fatalf("responder Seal: %v", err)
	}

	// Wrong initiator B tries to Complete A's ciphertext with B's own secret key.
	wrongSess, err := inB.Complete(kemCT, cfg)
	if err != nil {
		t.Fatalf("Complete (wrong initiator) errored instead of deriving wrong key: %v", err)
	}
	if KeysEqual(wrongSess, rsess) {
		t.Fatal("wrong initiator derived the responder's session key — KEM key-binding broken")
	}
	if got, err := wrongSess.Open(rec, nil); !errors.Is(err, ErrOpen) || got != nil {
		t.Fatalf("wrong initiator must not Open the record: got %q err %v", got, err)
	}
	t.Logf("wrong-initiator session cannot Open responder record (wrong-key path holds)")

	// Sanity: the RIGHT initiator (A) still opens it, proving the rejection above
	// is about the wrong key, not a generally-broken channel.
	rightSess, err := inA.Complete(kemCT, cfg)
	if err != nil {
		t.Fatalf("Complete (right initiator): %v", err)
	}
	if got, err := rightSess.Open(rec, nil); err != nil || !bytes.Equal(got, []byte("addressed to initiator A")) {
		t.Fatalf("right initiator should Open: got %q err %v", got, err)
	}
}

// -----------------------------------------------------------------------------
// 3. Deterministic AEAD round-trip across sizes (incl. empty) — both suites.
// -----------------------------------------------------------------------------

// TestDeterministicRoundTripSizes proves SealWithKeySuite/OpenWithKeySuite
// round-trip plaintexts of several lengths, including the empty plaintext, for
// both AEAD suites, recovering the EXACT input bytes. This is a real round-trip
// equality check (no fabricated KAT vectors) over a representative size sweep,
// complementing the pinned KAT/interop vectors already present.
//
// WHY IT BITES: a Seal/Open that mangled length handling (off-by-one on the tag,
// dropping the empty-plaintext case, or truncating long inputs) would fail the
// exact-bytes comparison for the affected size. Using fresh random keys per case
// ensures this is not keyed to one lucky key.
func TestDeterministicRoundTripSizes(t *testing.T) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}
	sizes := []int{0, 1, 15, 16, 17, 31, 32, 33, 64, 1000, 4096}
	for _, suite := range []AEADSuite{SuiteAES256GCM, SuiteChaCha20Poly1305} {
		for _, n := range sizes {
			key := randKey(t)
			pt := make([]byte, n)
			if _, err := io.ReadFull(rand.Reader, pt); err != nil {
				t.Fatalf("rand pt(%d): %v", n, err)
			}
			aad := []byte("size-sweep")
			ct, err := SealWithKeySuite(suite, key, nonce, aad, pt)
			if err != nil {
				t.Fatalf("[%s] Seal n=%d: %v", suite, n, err)
			}
			if len(ct) != n+16 {
				t.Fatalf("[%s] n=%d: ciphertext len %d, want %d (pt+tag)", suite, n, len(ct), n+16)
			}
			got, err := OpenWithKeySuite(suite, key, nonce, aad, ct)
			if err != nil {
				t.Fatalf("[%s] Open n=%d: %v", suite, n, err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("[%s] n=%d round-trip mismatch", suite, n)
			}
			// Anti-bluff cross-check: opening the SAME ciphertext under a freshly
			// generated WRONG key must fail (proves Open is keyed, not a passthrough).
			if got, err := OpenWithKeySuite(suite, randKey(t), nonce, aad, ct); err == nil || got != nil {
				t.Fatalf("[%s] n=%d: wrong-key Open must fail, got %q err %v", suite, n, got, err)
			}
		}
	}
	t.Logf("deterministic round-trip + wrong-key rejection verified for %d sizes x 2 suites", len(sizes))
}

// handshakeSuite is a suite-selectable variant of the package_test.go handshake
// helper, used by the AEAD-tamper tests that must run under both AEAD suites.
func handshakeSuite(t *testing.T, suite AEADSuite) (initiatorSess, responderSess *Session) {
	t.Helper()
	cfg := SessionConfig{Suite: suite}
	in, err := NewInitiator(cfg)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	ct, rsess, err := Respond(in.EncapsulationKeyBytes(), cfg)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	isess, err := in.Complete(ct, cfg)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	return isess, rsess
}
