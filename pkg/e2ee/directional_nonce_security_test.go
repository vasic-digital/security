package e2ee

import (
	"bytes"
	"testing"
)

// TestBidirectionalCounterNonceSessionsNeverCollide is the permanent regression
// guard for a critical nonce-reuse defect found by security audit (2026-07-10):
// two independently-constructed Session objects derived from the SAME
// handshake (the initiator's Session from Complete, the responder's Session
// from Respond) each start their own CounterNonce counter at zero. Before the
// role-partitioning fix, the FIRST Seal call made by EACH side therefore
// emitted the IDENTICAL 12-byte nonce under the IDENTICAL AEAD key -- the
// textbook AES-256-GCM / ChaCha20-Poly1305 catastrophic (key, nonce) reuse.
//
// This is not a theoretical concern: the package's own architecture invites it
// directly. Transport (transport.go) wraps ONE Session per peer around a
// bidirectional io.ReadWriter and offers both WriteRecord (Seal) and
// ReadRecord (Open) on that same Session -- so a peer that both writes and
// reads on its Transport is calling Seal on its own independently-constructed
// Session, exactly like the other peer does on its own. The package's own
// integration test (TestIntegration_MLKEMHandshakeSealOpen, e2ee package,
// //go:build integration) explicitly exercises "A seals, then B seals a
// reply" under SessionConfig{CounterNonce: true} on both sides and asserts it
// as a PASS case, never noticing the underlying key/nonce collision because
// Session.Open's replay guard only tracks nonces THAT SPECIFIC Session object
// has itself seen on Open -- it cannot detect that a *different* Session
// object (the peer's) sealed under a colliding nonce.
//
// This test proves two things:
//  1. The two peers' first-ever Seal nonces MUST differ (directional
//     partitioning holds) even though both peers share the identical AEAD key.
//  2. Constructing the attack scenario directly (both sides' first Seal, two
//     known equal-length plaintexts) does NOT let an observer recover
//     XOR(plaintextA, plaintextB) by XORing the two ciphertext bodies -- i.e.
//     the AEAD keystreams are NOT reused. Before the fix, this assertion is
//     exactly backwards: the XOR-recovery succeeds, which IS the
//     confidentiality break (and for GCM/Poly1305, (key,nonce) reuse across
//     two authenticated messages additionally leaks material that enables
//     universal forgery -- the keystream-XOR check below is the minimal,
//     directly-reproducible symptom of that same root cause).
//
// MUTATION THAT FAILS THIS: remove the `nonce[0] = byte(s.role)` partitioning
// in nextNonce (or construct both Sessions with the same role) -- the two
// peers' first nonces collide again and the keystream-XOR recovery in part 2
// succeeds, failing the "must NOT equal" assertion.
func TestBidirectionalCounterNonceSessionsNeverCollide(t *testing.T) {
	isess, rsess := handshake(t, SessionConfig{CounterNonce: true})
	if !KeysEqual(isess, rsess) {
		t.Fatal("test setup error: initiator/responder must share a key for this to be a meaningful test")
	}

	// Two equal-length, fully-known plaintexts -- one per direction -- so a
	// keystream-reuse attack can be checked directly by XOR.
	ptA := []byte("alpha-secret-message-001-AAAAAA")
	ptB := []byte("bravo-classified-payload-002-BB")
	if len(ptA) != len(ptB) {
		t.Fatalf("test setup error: plaintexts must be equal length, got %d and %d", len(ptA), len(ptB))
	}

	recA, err := isess.Seal(ptA, nil) // initiator's FIRST Seal call ever
	if err != nil {
		t.Fatalf("initiator Seal: %v", err)
	}
	recB, err := rsess.Seal(ptB, nil) // responder's FIRST Seal call ever
	if err != nil {
		t.Fatalf("responder Seal: %v", err)
	}

	nonceA := recA[:NonceSize]
	nonceB := recB[:NonceSize]
	if bytes.Equal(nonceA, nonceB) {
		t.Fatalf("CRITICAL: initiator and responder emitted the SAME nonce (%x) under the "+
			"SAME key on their first Seal call -- catastrophic AEAD (key,nonce) reuse", nonceA)
	}

	// Keystream-reuse confidentiality check: if (key,nonce) had collided, the
	// ciphertext bodies would be the plaintexts XORed with an IDENTICAL
	// keystream, so XORing the two ciphertext bodies recovers XOR(ptA, ptB)
	// exactly. Assert this does NOT hold now that nonces are partitioned.
	bodyA := recA[NonceSize : NonceSize+len(ptA)]
	bodyB := recB[NonceSize : NonceSize+len(ptB)]
	gotXOR := make([]byte, len(ptA))
	wantXORIfBroken := make([]byte, len(ptA))
	for i := range gotXOR {
		gotXOR[i] = bodyA[i] ^ bodyB[i]
		wantXORIfBroken[i] = ptA[i] ^ ptB[i]
	}
	if bytes.Equal(gotXOR, wantXORIfBroken) {
		t.Fatalf("CRITICAL: XOR(ciphertextA, ciphertextB) == XOR(plaintextA, plaintextB); " +
			"the two directions reused the same AEAD keystream (confidentiality broken)")
	}
	t.Logf("PASS: initiator nonce=%x responder nonce=%x (distinct); keystream-XOR recovery "+
		"attack does not succeed", nonceA, nonceB)
}

// TestManyBidirectionalCounterSealsNeverCollide extends the single-message
// proof above across many sequential message pairs (not just the very first
// message each way), since the role-partitioning fix must hold for the entire
// counter sequence, not just message #1. It also proves ordinary Open still
// works in both directions after the fix (no functional regression).
func TestManyBidirectionalCounterSealsNeverCollide(t *testing.T) {
	isess, rsess := handshake(t, SessionConfig{CounterNonce: true})

	seen := make(map[[NonceSize]byte]string)
	for i := 0; i < 200; i++ {
		recA, err := isess.Seal([]byte{byte(i)}, nil)
		if err != nil {
			t.Fatalf("initiator Seal %d: %v", i, err)
		}
		recB, err := rsess.Seal([]byte{byte(i)}, nil)
		if err != nil {
			t.Fatalf("responder Seal %d: %v", i, err)
		}
		var nA, nB [NonceSize]byte
		copy(nA[:], recA[:NonceSize])
		copy(nB[:], recB[:NonceSize])
		if nA == nB {
			t.Fatalf("iteration %d: initiator and responder nonces collided: %x", i, nA)
		}
		if prev, ok := seen[nA]; ok {
			t.Fatalf("iteration %d: initiator nonce %x repeats prior nonce from %s", i, nA, prev)
		}
		seen[nA] = "initiator"
		if prev, ok := seen[nB]; ok {
			t.Fatalf("iteration %d: responder nonce %x repeats prior nonce from %s", i, nB, prev)
		}
		seen[nB] = "responder"

		// Functional sanity: each side can still open what the OTHER sealed.
		gotA, err := rsess.Open(recA, nil)
		if err != nil || !bytes.Equal(gotA, []byte{byte(i)}) {
			t.Fatalf("iteration %d: responder Open(initiator record) failed: got %v err %v", i, gotA, err)
		}
		gotB, err := isess.Open(recB, nil)
		if err != nil || !bytes.Equal(gotB, []byte{byte(i)}) {
			t.Fatalf("iteration %d: initiator Open(responder record) failed: got %v err %v", i, gotB, err)
		}
	}
	t.Logf("PASS: %d bidirectional message pairs, %d total nonces, zero collisions", 200, len(seen))
}
