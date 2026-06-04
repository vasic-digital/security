package e2ee

import (
	"errors"
	"testing"
)

// fuzzKey is a fixed valid 32-byte session key used to build real Sessions /
// real deterministic AEADs inside the fuzz targets. Using a real key means the
// fuzzers exercise the genuine AES-256-GCM / ChaCha20-Poly1305 Open path, not a
// stub: a successful Open returns real plaintext and a failure returns the real
// ErrOpen / ErrInvalidCiphertext sentinels.
var fuzzKey = []byte("0123456789abcdef0123456789abcdef")

// FuzzSessionOpen feeds arbitrary bytes to Session.Open — the AEAD record
// decode + decrypt path (nonce split, GCM/ChaCha Open, replay tracking). The
// invariant: Open must never panic on hostile input and must surface a clean
// error (or, vanishingly rarely, a clean success) — never an out-of-range slice
// or unhandled state.
//
// This calls the REAL Session.Open through a real AES-256-GCM AEAD; the length
// guard, nonce copy, and aead.Open are all on the live path.
func FuzzSessionOpen(f *testing.F) {
	// Seed corpus: empty, short-but-nonzero, a plausible-length-but-garbage
	// record, and a genuinely valid record produced by the real Seal path.
	f.Add([]byte{}, []byte{})
	f.Add([]byte{1, 2, 3}, []byte("aad"))
	f.Add(make([]byte, NonceSize+16), []byte(nil))

	seedSess, err := NewSessionFromKey(fuzzKey, true)
	if err != nil {
		f.Fatalf("seed session: %v", err)
	}
	if rec, err := seedSess.Seal([]byte("seed plaintext"), []byte("seed-aad")); err == nil {
		f.Add(rec, []byte("seed-aad"))
	}

	f.Fuzz(func(t *testing.T, record, aad []byte) {
		// Fresh session per call so the replay-tracking map does not accumulate
		// across iterations and so a valid seed record can legitimately Open.
		sess, err := NewSessionFromKey(fuzzKey, false)
		if err != nil {
			t.Fatalf("NewSessionFromKey: %v", err)
		}
		pt, err := sess.Open(record, aad)
		if err != nil {
			// Errors are expected for arbitrary input; they must be the
			// package's typed sentinels, never a panic.
			if !errors.Is(err, ErrOpen) && !errors.Is(err, ErrInvalidCiphertext) && !errors.Is(err, ErrNonceReuse) {
				t.Fatalf("unexpected error class from Open: %v", err)
			}
			return
		}
		// On the rare authenticated success, plaintext must be addressable.
		_ = pt
	})
}

// FuzzOpenWithKey feeds arbitrary bytes to the deterministic OpenWithKeySuite
// framing entry point under both AEAD suites. This exercises the raw
// ciphertext||tag decode/authenticate path with a caller-supplied nonce — the
// cross-implementation interop surface. Invariant: no panic; only typed errors.
func FuzzOpenWithKey(f *testing.F) {
	f.Add([]byte{}, []byte{}, uint8(0))
	f.Add(make([]byte, 16), []byte("aad"), uint8(1))
	f.Add([]byte("short"), []byte(nil), uint8(0))

	// A real sealed ciphertext under a fixed nonce, so the corpus contains at
	// least one input that authenticates.
	nonce := make([]byte, NonceSize)
	if ct, err := SealWithKey(fuzzKey, nonce, []byte("a"), []byte("hello")); err == nil {
		f.Add(ct, []byte("a"), uint8(0))
	}

	f.Fuzz(func(t *testing.T, ciphertext, aad []byte, suiteByte uint8) {
		suite := SuiteAES256GCM
		if suiteByte%2 == 1 {
			suite = SuiteChaCha20Poly1305
		}
		nonce := make([]byte, NonceSize) // valid 12-byte nonce
		pt, err := OpenWithKeySuite(suite, fuzzKey, nonce, aad, ciphertext)
		if err != nil {
			if !errors.Is(err, ErrOpen) && !errors.Is(err, ErrInvalidCiphertext) && !errors.Is(err, ErrInvalidKeySize) {
				t.Fatalf("unexpected error class from OpenWithKeySuite: %v", err)
			}
			return
		}
		_ = pt
	})
}

// FuzzRespond feeds arbitrary bytes to Respond — the responder-side parse of the
// initiator's ML-KEM-768 encapsulation key. Invariant: a malformed key bytes
// blob must yield a clean parse error, never a panic, and must never return a
// non-nil Session alongside an error.
func FuzzRespond(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 32))
	// A real, well-formed encapsulation key so the corpus has a valid path.
	if in, err := NewInitiator(SessionConfig{}); err == nil {
		f.Add(in.EncapsulationKeyBytes())
	}

	f.Fuzz(func(t *testing.T, encapKey []byte) {
		ct, sess, err := Respond(encapKey, SessionConfig{})
		if err != nil {
			if sess != nil || ct != nil {
				t.Fatalf("Respond returned non-nil ciphertext/session with error: %v", err)
			}
			return
		}
		if sess == nil {
			t.Fatal("Respond returned nil session with nil error")
		}
	})
}

// FuzzComplete feeds arbitrary bytes to Initiator.Complete — the initiator-side
// KEM ciphertext length check + Decapsulate path. Invariant: malformed
// ciphertext yields a clean error (ErrInvalidCiphertext for wrong length, or a
// wrapped decapsulate error), never a panic.
func FuzzComplete(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, kemCiphertextSize))
	f.Add([]byte("too short"))

	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		in, err := NewInitiator(SessionConfig{})
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		sess, err := in.Complete(ciphertext, SessionConfig{})
		if err != nil {
			if sess != nil {
				t.Fatalf("Complete returned non-nil session with error: %v", err)
			}
			return
		}
		if sess == nil {
			t.Fatal("Complete returned nil session with nil error")
		}
	})
}
