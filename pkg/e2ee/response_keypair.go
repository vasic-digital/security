package e2ee

// Per-request bidirectional response keypair (Chutes confidential-inference
// pattern).
//
// In a confidential-inference exchange the CLIENT issues a request and the
// WORKER must seal its response so that ONLY the client that issued THAT request
// can open it. To bind a response to its originating request, each request
// carries its own freshly-generated ephemeral RESPONSE public key: the worker
// seals the response to that per-request key, and a response sealed for
// request-1 is cryptographically unopenable with request-2's key.
//
// This is composed entirely from the existing handshake primitives — it does
// NOT reinvent ML-KEM:
//
//   - ResponseKeypair wraps a fresh Initiator. Its EncapsulationKeyBytes is the
//     per-request response PUBLIC key the client publishes inside the request.
//   - SealResponse (worker side) runs Respond against that public key to derive
//     a per-request Session and seals the response, returning the KEM ciphertext
//     plus the sealed record as a ResponseEnvelope.
//   - ResponseKeypair.OpenResponse (client side) runs Complete with the KEM
//     ciphertext to derive the identical per-request Session and opens.
//
// Key generation uses crypto/rand via NewInitiator (no seed-injection hook is
// exposed by SessionConfig). The tests therefore assert DISTINCTNESS and
// per-request ISOLATION rather than exact key bytes, which is the security
// property that actually matters: responses are bound to their per-request key.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ResponseFingerprintLen is the number of leading SHA-256 bytes used by
// ResponseKeypair.Fingerprint. 8 bytes (16 hex chars) is ample for
// logging/rotation-evidence collision-avoidance while staying compact.
const ResponseFingerprintLen = 8

// ResponseKeypair is a per-request response context held by the client. It wraps
// a freshly-generated ephemeral ML-KEM-768 Initiator: PublicKey() is the
// per-request response public key the client embeds in its request, and
// OpenResponse decapsulates the worker's KEM ciphertext to recover the
// per-request session and open the sealed response.
//
// A new ResponseKeypair MUST be generated for every request — reusing one across
// requests defeats per-request isolation (a response sealed for an earlier
// request would then be openable with the reused key).
type ResponseKeypair struct {
	initiator *Initiator
	cfg       SessionConfig
}

// ResponseEnvelope is the worker's sealed response bound to a specific
// per-request response public key. KEMCiphertext is the ML-KEM-768 ciphertext
// the client decapsulates to re-derive the per-request session; Record is the
// Session.Seal output (nonce || ciphertext || tag).
type ResponseEnvelope struct {
	KEMCiphertext []byte
	Record        []byte
}

// NewResponseKeypair generates a fresh per-request response keypair. cfg controls
// the derived session parameters (Info / CounterNonce) and MUST match the cfg the
// worker passes to SealResponse for the derived session keys to agree.
func NewResponseKeypair(cfg SessionConfig) (*ResponseKeypair, error) {
	in, err := NewInitiator(cfg)
	if err != nil {
		return nil, fmt.Errorf("e2ee: new response keypair: %w", err)
	}
	return &ResponseKeypair{initiator: in, cfg: cfg}, nil
}

// PublicKey returns the per-request response PUBLIC key (the ML-KEM-768
// encapsulation key bytes) that the client embeds in its request so the worker
// can seal the response to it. It is safe to transmit over an untrusted relay.
func (rk *ResponseKeypair) PublicKey() []byte {
	return rk.initiator.EncapsulationKeyBytes()
}

// Fingerprint returns a short, stable hex fingerprint of the per-request response
// public key (SHA-256 prefix), suitable for logging and rotation evidence. Two
// distinct response keypairs produce distinct fingerprints with overwhelming
// probability; the same keypair always produces the same fingerprint.
func (rk *ResponseKeypair) Fingerprint() string {
	sum := sha256.Sum256(rk.initiator.EncapsulationKeyBytes())
	return hex.EncodeToString(sum[:ResponseFingerprintLen])
}

// SealResponse is the WORKER-side operation. It encapsulates against the
// client's per-request response public key to derive a per-request Session, seals
// plaintext (authenticating aad), and returns a ResponseEnvelope carrying the KEM
// ciphertext and the sealed record. cfg MUST match the cfg used to create the
// client's ResponseKeypair.
//
// Because the session key is derived from a fresh ML-KEM encapsulation against
// THIS request's public key, the resulting envelope can only be opened by the
// matching ResponseKeypair — a response sealed for one request cannot be opened
// with another request's keypair.
func SealResponse(responsePubKey, plaintext, aad []byte, cfg SessionConfig) (*ResponseEnvelope, error) {
	kemCT, sess, err := Respond(responsePubKey, cfg)
	if err != nil {
		return nil, fmt.Errorf("e2ee: seal response: %w", err)
	}
	record, err := sess.Seal(plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("e2ee: seal response record: %w", err)
	}
	return &ResponseEnvelope{KEMCiphertext: kemCT, Record: record}, nil
}

// OpenResponse is the CLIENT-side operation. It completes the handshake against
// the worker's KEM ciphertext to re-derive the identical per-request Session and
// opens the sealed record, verifying aad. It returns ErrOpen (wrapped) on any
// authentication failure — including the load-bearing case where the envelope was
// sealed for a DIFFERENT request's response key, so this keypair's decapsulation
// yields a different session key and the AEAD tag check fails.
func (rk *ResponseKeypair) OpenResponse(env *ResponseEnvelope, aad []byte) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("e2ee: nil response envelope: %w", ErrInvalidCiphertext)
	}
	sess, err := rk.initiator.Complete(env.KEMCiphertext, rk.cfg)
	if err != nil {
		return nil, fmt.Errorf("e2ee: open response complete: %w", err)
	}
	plaintext, err := sess.Open(env.Record, aad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
