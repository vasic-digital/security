package e2ee

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
)

// handshake runs a full two-peer handshake and returns the initiator's and
// responder's sessions. It fails the test on any error.
func handshake(t *testing.T, cfg SessionConfig) (initiatorSess, responderSess *Session) {
	t.Helper()
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

// TestHandshakeRoundTrip proves the full handshake yields working bidirectional
// AEAD: plaintext sealed by one peer is recovered EXACTLY by the other.
//
// MUTATION THAT FAILS THIS: in deriveSessionKey, change the HKDF info on one
// path (e.g. responder uses "x") so the two sides derive different keys; Open
// then returns ErrOpen and bytes.Equal fails. Equivalently, returning a fixed
// zero plaintext from Open fails the exact-bytes comparison.
func TestHandshakeRoundTrip(t *testing.T) {
	isess, rsess := handshake(t, SessionConfig{})

	msg := []byte("confidential inference prompt: 42")
	aad := []byte("route=worker-7")

	// initiator -> responder
	rec, err := isess.Seal(msg, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := rsess.Open(rec, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, msg)
	}

	// responder -> initiator (reverse direction works too)
	reply := []byte("completion tokens here")
	rec2, err := rsess.Seal(reply, nil)
	if err != nil {
		t.Fatalf("Seal reply: %v", err)
	}
	got2, err := isess.Open(rec2, nil)
	if err != nil {
		t.Fatalf("Open reply: %v", err)
	}
	if !bytes.Equal(got2, reply) {
		t.Fatalf("reverse mismatch: got %q want %q", got2, reply)
	}
}

// TestBothPeersDeriveSameKey proves the KEM+HKDF handshake converges on one key.
//
// MUTATION THAT FAILS THIS: make deriveSessionKey ignore the salt on one side
// (e.g. pass nil salt in Respond but kemCiphertext on Complete), or XOR a
// constant into one side's key. KeysEqual then returns false.
func TestBothPeersDeriveSameKey(t *testing.T) {
	isess, rsess := handshake(t, SessionConfig{})
	if !KeysEqual(isess, rsess) {
		t.Fatal("initiator and responder derived different session keys")
	}
	// And an independent handshake yields a DIFFERENT key (ephemeral keys),
	// proving the equality above is not vacuous.
	isess2, _ := handshake(t, SessionConfig{})
	if KeysEqual(isess, isess2) {
		t.Fatal("two independent handshakes produced identical keys (ephemerality broken)")
	}
}

// TestTamperedCiphertextFails proves integrity: flipping one ciphertext byte
// makes Open fail.
//
// MUTATION THAT FAILS THIS: replace gcm.Open with a routine that ignores the
// auth tag and returns the raw bytes; the flipped record would then "decrypt"
// and err would be nil.
func TestTamperedCiphertextFails(t *testing.T) {
	isess, rsess := handshake(t, SessionConfig{})
	rec, err := isess.Seal([]byte("integrity matters"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Flip a bit in the ciphertext body (past the 12-byte nonce).
	tampered := append([]byte(nil), rec...)
	tampered[NonceSize+1] ^= 0x01

	_, err = rsess.Open(tampered, nil)
	if !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen on tampered ciphertext, got %v", err)
	}
}

// TestTamperedNonceFails proves the nonce is authenticated (GCM binds it):
// flipping a nonce byte breaks authentication.
//
// MUTATION THAT FAILS THIS: same as above — an Open that skips tag verification
// would not detect the altered nonce.
func TestTamperedNonceFails(t *testing.T) {
	isess, rsess := handshake(t, SessionConfig{})
	rec, err := isess.Seal([]byte("nonce is aad"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	tampered := append([]byte(nil), rec...)
	tampered[0] ^= 0xFF
	if _, err := rsess.Open(tampered, nil); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen on tampered nonce, got %v", err)
	}
}

// TestWrongSessionKeyFails proves confidentiality is keyed: a session from an
// unrelated handshake cannot Open another's record.
//
// MUTATION THAT FAILS THIS: derive the session key from a constant instead of
// the shared secret (e.g. return a fixed key in deriveSessionKey); then all
// sessions share a key and the wrong session would Open successfully.
func TestWrongSessionKeyFails(t *testing.T) {
	isess, _ := handshake(t, SessionConfig{})
	rec, err := isess.Seal([]byte("only for the right peer"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// A wholly separate handshake -> different ephemeral keys -> different key.
	_, otherResponder := handshake(t, SessionConfig{})
	if _, err := otherResponder.Open(rec, nil); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen with wrong session key, got %v", err)
	}
}

// TestAADMismatchFails proves the AAD is authenticated: opening with different
// AAD than was sealed fails.
//
// MUTATION THAT FAILS THIS: pass nil aad to gcm.Seal/gcm.Open inside Seal/Open
// (dropping the caller's aad); then the mismatched-AAD Open would succeed.
func TestAADMismatchFails(t *testing.T) {
	isess, rsess := handshake(t, SessionConfig{})
	rec, err := isess.Seal([]byte("bound to context"), []byte("ctx=A"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := rsess.Open(rec, []byte("ctx=B")); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen on AAD mismatch, got %v", err)
	}
	// Sanity: correct AAD still opens.
	if _, err := rsess.Open(rec, []byte("ctx=A")); err != nil {
		t.Fatalf("correct AAD should open, got %v", err)
	}
}

// TestNonceReuseRejected proves replay protection: replaying an already-opened
// record (same nonce) is rejected even though it authenticates.
//
// MUTATION THAT FAILS THIS: remove the s.used[nonce] tracking in Open (delete
// the reuse check / map insertion); the replayed record would then Open again
// with no error.
func TestNonceReuseRejected(t *testing.T) {
	isess, rsess := handshake(t, SessionConfig{})
	rec, err := isess.Seal([]byte("exactly once"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := rsess.Open(rec, nil); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	// Replay the identical record.
	if _, err := rsess.Open(rec, nil); !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("expected ErrNonceReuse on replay, got %v", err)
	}
}

// TestCounterNonceUniqueness proves counter-mode Seal never repeats a nonce, so
// many records all Open and none trips the reuse guard.
//
// MUTATION THAT FAILS THIS: make nextNonce return a constant nonce in counter
// mode (e.g. drop the ctr increment); the second Open would then hit
// ErrNonceReuse and the loop fails.
func TestCounterNonceUniqueness(t *testing.T) {
	isess, rsess := handshake(t, SessionConfig{CounterNonce: true})
	seen := make(map[[NonceSize]byte]bool)
	for i := 0; i < 1000; i++ {
		rec, err := isess.Seal([]byte{byte(i)}, nil)
		if err != nil {
			t.Fatalf("Seal %d: %v", i, err)
		}
		var nonce [NonceSize]byte
		copy(nonce[:], rec[:NonceSize])
		if seen[nonce] {
			t.Fatalf("counter nonce repeated at %d", i)
		}
		seen[nonce] = true
		got, err := rsess.Open(rec, nil)
		if err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
		if len(got) != 1 || got[0] != byte(i) {
			t.Fatalf("plaintext mismatch at %d: %v", i, got)
		}
	}
}

// TestShortRecordRejected proves a truncated record (no room for nonce+tag) is
// rejected rather than panicking or silently succeeding.
//
// MUTATION THAT FAILS THIS: remove the length guard at the top of Open; slicing
// record[:NonceSize] would then panic on a 3-byte input instead of returning
// ErrInvalidCiphertext.
func TestShortRecordRejected(t *testing.T) {
	_, rsess := handshake(t, SessionConfig{})
	if _, err := rsess.Open([]byte{1, 2, 3}, nil); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("expected ErrInvalidCiphertext on short record, got %v", err)
	}
}

// TestInvalidKemCiphertextRejected proves Complete validates the KEM ciphertext
// length instead of feeding garbage to Decapsulate.
//
// MUTATION THAT FAILS THIS: remove the length check in Complete; a 10-byte
// ciphertext would reach Decapsulate and return a different (non-length) error
// path or panic, failing the ErrInvalidCiphertext assertion.
func TestInvalidKemCiphertextRejected(t *testing.T) {
	in, err := NewInitiator(SessionConfig{})
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	if _, err := in.Complete([]byte("too short"), SessionConfig{}); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("expected ErrInvalidCiphertext, got %v", err)
	}
}

// TestDistinctInfoYieldsDistinctKeys proves the HKDF info label is real domain
// separation: differing labels on the two peers break interop.
//
// MUTATION THAT FAILS THIS: have deriveSessionKey ignore the info argument
// (pass a constant string to hkdf.Key); both peers would then agree despite the
// label mismatch and Open would succeed.
func TestDistinctInfoYieldsDistinctKeys(t *testing.T) {
	in, err := NewInitiator(SessionConfig{Info: "label-A"})
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	// Responder uses a DIFFERENT label.
	ct, rsess, err := Respond(in.EncapsulationKeyBytes(), SessionConfig{Info: "label-B"})
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	isess, err := in.Complete(ct, SessionConfig{Info: "label-A"})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if KeysEqual(isess, rsess) {
		t.Fatal("different HKDF info labels must yield different keys")
	}
	rec, err := isess.Seal([]byte("x"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := rsess.Open(rec, nil); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen across mismatched info labels, got %v", err)
	}
}

// TestTransportRoundTrip proves the framed transport carries multiple records
// over an io.ReadWriter and recovers each plaintext exactly.
//
// MUTATION THAT FAILS THIS: drop the length prefix in WriteRecord (write only
// the record); ReadRecord's io.ReadFull(hdr) would consume body bytes as the
// length and the decrypted plaintext would not match.
func TestTransportRoundTrip(t *testing.T) {
	isess, rsess := handshake(t, SessionConfig{CounterNonce: true})

	// A pipe-like in-memory duplex: writer feeds reader.
	var buf bytes.Buffer
	writer := NewTransport(isess, &buf, 0)
	reader := NewTransport(rsess, &buf, 0)

	msgs := [][]byte{
		[]byte("first record"),
		[]byte(""),
		bytes.Repeat([]byte("A"), 5000),
	}
	aad := []byte("stream=1")
	for _, m := range msgs {
		if err := writer.WriteRecord(m, aad); err != nil {
			t.Fatalf("WriteRecord: %v", err)
		}
	}
	for i, m := range msgs {
		got, err := reader.ReadRecord(aad)
		if err != nil {
			t.Fatalf("ReadRecord %d: %v", i, err)
		}
		if !bytes.Equal(got, m) {
			t.Fatalf("record %d mismatch: got %d bytes want %d", i, len(got), len(m))
		}
	}
}

// TestTransportRejectsOversizeLength proves the reader guards against a hostile
// length prefix rather than allocating unboundedly.
//
// MUTATION THAT FAILS THIS: remove the `n > t.maxRecv` check in ReadRecord; the
// reader would attempt to read 0xFFFFFFFF bytes and block/err elsewhere instead
// of returning ErrRecordTooLarge.
func TestTransportRejectsOversizeLength(t *testing.T) {
	_, rsess := handshake(t, SessionConfig{})
	// Craft a length prefix far above the small max we configure.
	r := bytes.NewReader([]byte{0x00, 0x10, 0x00, 0x00}) // 1 MiB
	rt := NewTransport(rsess, readOnlyRW{r}, 1024)
	if _, err := rt.ReadRecord(nil); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("expected ErrRecordTooLarge, got %v", err)
	}
}

// TestConcurrentSealOpen proves the Session is safe under -race for concurrent
// Seal/Open with no nonce collisions or map races.
//
// MUTATION THAT FAILS THIS: remove the mutex around nextCtr/used (the race
// detector flags the data race), or counter increments collide producing
// ErrNonceReuse.
func TestConcurrentSealOpen(t *testing.T) {
	isess, rsess := handshake(t, SessionConfig{CounterNonce: true})
	const workers = 16
	const each = 64

	records := make(chan []byte, workers*each)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				rec, err := isess.Seal([]byte("concurrent"), nil)
				if err != nil {
					t.Errorf("Seal: %v", err)
					return
				}
				records <- rec
			}
		}()
	}
	wg.Wait()
	close(records)

	count := 0
	for rec := range records {
		got, err := rsess.Open(rec, nil)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, []byte("concurrent")) {
			t.Fatalf("bad plaintext: %q", got)
		}
		count++
	}
	if count != workers*each {
		t.Fatalf("expected %d records, got %d", workers*each, count)
	}
}

// readOnlyRW adapts an io.Reader into an io.ReadWriter for Transport read tests;
// Write is unused.
type readOnlyRW struct{ io.Reader }

func (readOnlyRW) Write(p []byte) (int, error) { return len(p), nil }
