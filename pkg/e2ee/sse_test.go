package e2ee

import (
	"bytes"
	"errors"
	"testing"
)

// handshakeSessions runs the real e2e_init handshake (Initiator/Respond/Complete)
// and returns the worker-side (seal) and client-side (open) sessions, both with
// CounterNonce so chunk nonces form an ordered stream. The two sessions share the
// derived key, so records sealed by one are openable by the other.
func handshakeSessions(t *testing.T) (worker, client *Session) {
	t.Helper()
	cfg := SessionConfig{Info: "helix-e2ee-sse-test", CounterNonce: true}
	in, err := NewInitiator(cfg)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	kemCT, workerSess, err := Respond(in.EncapsulationKeyBytes(), cfg)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	clientSess, err := in.Complete(kemCT, cfg)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !KeysEqual(workerSess, clientSess) {
		t.Fatal("handshake produced mismatched session keys")
	}
	return workerSess, clientSess
}

// sealCompletion seals each token in order with the worker session and returns
// the ordered sealed chunk records.
func sealCompletion(t *testing.T, worker *Session, tokens []string) [][]byte {
	t.Helper()
	sealer, err := NewStreamSealer(worker, nil)
	if err != nil {
		t.Fatalf("NewStreamSealer: %v", err)
	}
	records := make([][]byte, 0, len(tokens))
	for i, tok := range tokens {
		rec, err := sealer.SealChunk([]byte(tok))
		if err != nil {
			t.Fatalf("SealChunk[%d]=%q: %v", i, tok, err)
		}
		records = append(records, rec)
	}
	return records
}

// TestSSEStreamReassembly is the load-bearing anti-bluff test: a multi-chunk
// completion is sealed chunk-by-chunk over the real handshake-derived session,
// fed to the StreamDecryptor in order, and the reassembled plaintext MUST equal
// the exact concatenation "Hello world!". This proves the decryptor reproduces
// the end-user-visible completion, not merely that Open returns without error.
func TestSSEStreamReassembly(t *testing.T) {
	tokens := []string{"Hello", " ", "world", "!"}
	const want = "Hello world!"

	worker, client := handshakeSessions(t)
	records := sealCompletion(t, worker, tokens)

	dec, err := NewStreamDecryptor(client, nil)
	if err != nil {
		t.Fatalf("NewStreamDecryptor: %v", err)
	}

	// Feed each chunk in order and verify the per-chunk plaintext too.
	for i, rec := range records {
		got, err := dec.DecryptChunk(rec)
		if err != nil {
			t.Fatalf("DecryptChunk[%d]: %v", i, err)
		}
		if string(got) != tokens[i] {
			t.Fatalf("chunk %d plaintext = %q, want %q", i, got, tokens[i])
		}
	}

	full, err := dec.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if string(full) != want {
		t.Fatalf("reassembled completion = %q, want %q", full, want)
	}
	if dec.String() != want {
		t.Fatalf("String() = %q, want %q", dec.String(), want)
	}
	if dec.Chunks() != len(tokens) {
		t.Fatalf("Chunks() = %d, want %d", dec.Chunks(), len(tokens))
	}
}

// TestSSEStreamDecryptStream exercises the whole-slice convenience path and
// asserts exact reassembly.
func TestSSEStreamDecryptStream(t *testing.T) {
	tokens := []string{"Hello", " ", "world", "!"}
	const want = "Hello world!"

	worker, client := handshakeSessions(t)
	records := sealCompletion(t, worker, tokens)

	dec, err := NewStreamDecryptor(client, nil)
	if err != nil {
		t.Fatalf("NewStreamDecryptor: %v", err)
	}
	full, err := dec.DecryptStream(records)
	if err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}
	if string(full) != want {
		t.Fatalf("reassembled completion = %q, want %q", full, want)
	}
}

// TestSSEStreamTamperedChunkFails proves a tampered chunk is rejected by the AEAD
// (ErrOpen) and the stream is poisoned — the completion is NOT silently
// reassembled from the surviving chunks.
func TestSSEStreamTamperedChunkFails(t *testing.T) {
	tokens := []string{"Hello", " ", "world", "!"}

	worker, client := handshakeSessions(t)
	records := sealCompletion(t, worker, tokens)

	// Flip a bit inside the ciphertext body of the "world" chunk (index 2),
	// past the 12-byte nonce prefix.
	tampered := make([][]byte, len(records))
	for i, r := range records {
		cp := make([]byte, len(r))
		copy(cp, r)
		tampered[i] = cp
	}
	tampered[2][NonceSize+1] ^= 0x01

	dec, err := NewStreamDecryptor(client, nil)
	if err != nil {
		t.Fatalf("NewStreamDecryptor: %v", err)
	}
	_, err = dec.DecryptStream(tampered)
	if err == nil {
		t.Fatal("tampered chunk accepted; expected failure")
	}
	if !errors.Is(err, ErrOpen) {
		t.Fatalf("tampered chunk error = %v, want ErrOpen", err)
	}
	// The poisoned stream must not yield the full completion.
	if _, ferr := dec.Finish(); ferr == nil {
		t.Fatal("Finish succeeded on poisoned stream; expected error")
	}
	if got := dec.String(); bytes.Contains([]byte(got), []byte("world")) {
		t.Fatalf("poisoned stream leaked post-tamper plaintext: %q", got)
	}
}

// TestSSEStreamOutOfOrderChunkFails proves that replaying an already-consumed
// chunk (a duplicate / out-of-order delivery on the counter-nonce stream) is
// rejected with ErrNonceReuse rather than producing a corrupted completion.
func TestSSEStreamOutOfOrderChunkFails(t *testing.T) {
	tokens := []string{"Hello", " ", "world", "!"}

	worker, client := handshakeSessions(t)
	records := sealCompletion(t, worker, tokens)

	dec, err := NewStreamDecryptor(client, nil)
	if err != nil {
		t.Fatalf("NewStreamDecryptor: %v", err)
	}

	// Deliver chunk 0 then re-deliver chunk 0 (replay / wrong order).
	if _, err := dec.DecryptChunk(records[0]); err != nil {
		t.Fatalf("DecryptChunk[0]: %v", err)
	}
	_, err = dec.DecryptChunk(records[0])
	if err == nil {
		t.Fatal("replayed chunk accepted; expected failure")
	}
	if !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("replayed chunk error = %v, want ErrNonceReuse", err)
	}
}

// TestSSEStreamWrongSessionFails proves a chunk sealed for one request's session
// cannot be opened by an unrelated session — the per-request isolation property.
func TestSSEStreamWrongSessionFails(t *testing.T) {
	tokens := []string{"Hello", " ", "world", "!"}

	worker, _ := handshakeSessions(t)
	records := sealCompletion(t, worker, tokens)

	// A completely independent handshake => different key.
	_, otherClient := handshakeSessions(t)

	dec, err := NewStreamDecryptor(otherClient, nil)
	if err != nil {
		t.Fatalf("NewStreamDecryptor: %v", err)
	}
	if _, err := dec.DecryptStream(records); !errors.Is(err, ErrOpen) {
		t.Fatalf("wrong-session error = %v, want ErrOpen", err)
	}
}
