package e2ee

// Streaming SSE (server-sent-events) E2EE decryption — the Chutes confidential
// streaming pattern.
//
// A confidential streaming completion is delivered as:
//
//   - an "e2e_init" frame that establishes a per-request session. This reuses
//     the existing handshake primitives unchanged: either the two-peer
//     Initiator/Respond/Complete flow, or the per-request ResponseKeypair flow
//     (response_keypair.go). The handshake yields ONE *Session shared by client
//     and worker.
//   - an ordered sequence of SSE token/chunk frames, each an independently
//     sealed AEAD record (Session.Seal output: nonce(12) || ciphertext || tag).
//     The worker seals each emitted token in stream order; the client decrypts
//     each in the SAME order and concatenates the plaintext into the full
//     completion.
//
// Counter-nonce ordering is load-bearing. When the session is created with
// SessionConfig.CounterNonce=true the worker's per-chunk nonces are a strictly
// increasing counter, so the chunks form an ordered stream; the client's
// Session.Open enforces single-use of each nonce (a replayed or duplicated chunk
// is rejected with ErrNonceReuse) and the AEAD tag rejects any tampered chunk
// with ErrOpen. This decryptor adds the stream-assembly layer on top of those
// guarantees — it does NOT reinvent any crypto.
//
// This file deliberately holds ONLY the stream-assembly logic; all
// confidentiality, integrity, replay, and ordering guarantees come from the
// underlying Session.

import "fmt"

// StreamDecryptor decrypts an ordered sequence of independently-sealed SSE chunk
// records against a per-request Session established by an e2e_init handshake, and
// reassembles them into the full completion.
//
// It is the client-side sink of the Chutes confidential streaming pattern: the
// caller establishes the Session (via Initiator/Respond/Complete or the
// ResponseKeypair flow), then feeds each sealed chunk to DecryptChunk in arrival
// order; Bytes/String return the running reassembled plaintext.
//
// A StreamDecryptor is single-stream and NOT safe for concurrent use by multiple
// goroutines: chunks of one completion are inherently ordered and must be fed
// sequentially. The underlying Session itself remains safe for concurrent use.
type StreamDecryptor struct {
	sess    *Session
	aad     []byte
	out     []byte
	chunks  int
	done    bool
	lastErr error
}

// NewStreamDecryptor binds a per-request Session (the result of the e2e_init
// handshake) to a fresh stream-assembly buffer. aad, if non-nil, is the
// additional authenticated data that every chunk record was sealed with and is
// verified on every DecryptChunk; pass nil when chunks carry no AAD. The session
// MUST be the one derived from the handshake for this request — typically created
// with SessionConfig.CounterNonce=true so chunk nonces form an ordered stream.
func NewStreamDecryptor(sess *Session, aad []byte) (*StreamDecryptor, error) {
	if sess == nil {
		return nil, fmt.Errorf("e2ee: nil session: %w", ErrInvalidKeySize)
	}
	return &StreamDecryptor{sess: sess, aad: aad}, nil
}

// DecryptChunk decrypts a single sealed chunk record (Session.Seal output) and
// appends its plaintext to the running completion, returning that chunk's
// plaintext. Chunks MUST be supplied in stream order. It returns:
//
//   - ErrOpen (wrapped) if the chunk is tampered, was sealed under a different
//     key, or its AAD does not match — the chunk is NOT appended.
//   - ErrNonceReuse if the chunk's nonce was already consumed on this session
//     (a duplicated or replayed chunk) — the chunk is NOT appended.
//   - ErrInvalidCiphertext (wrapped) if the record is too short to be a record.
//
// Once any chunk fails, the stream is considered poisoned: the first failure is
// retained and every subsequent DecryptChunk/Finish reports it, because a partial
// or reordered completion must never be silently reassembled.
func (d *StreamDecryptor) DecryptChunk(record []byte) ([]byte, error) {
	if d.lastErr != nil {
		return nil, d.lastErr
	}
	if d.done {
		return nil, fmt.Errorf("e2ee: stream already finished: %w", ErrInvalidCiphertext)
	}
	plain, err := d.sess.Open(record, d.aad)
	if err != nil {
		// Poison the stream: a failed chunk means the reassembled completion can
		// no longer be trusted to be complete and in-order.
		d.lastErr = err
		return nil, err
	}
	d.out = append(d.out, plain...)
	d.chunks++
	// Return a copy so the caller cannot mutate the assembled buffer.
	cp := make([]byte, len(plain))
	copy(cp, plain)
	return cp, nil
}

// DecryptStream decrypts an entire ordered slice of sealed chunk records and
// returns the fully reassembled completion. It is a convenience wrapper over
// repeated DecryptChunk calls and stops at the first failing chunk, returning
// that error (so a tampered or out-of-order chunk fails the whole stream rather
// than yielding a truncated completion).
func (d *StreamDecryptor) DecryptStream(records [][]byte) ([]byte, error) {
	for i, rec := range records {
		if _, err := d.DecryptChunk(rec); err != nil {
			return nil, fmt.Errorf("e2ee: stream chunk %d: %w", i, err)
		}
	}
	return d.Finish()
}

// Finish marks the stream complete and returns the full reassembled completion.
// It returns the retained error if any chunk previously failed. After Finish,
// further DecryptChunk calls fail.
func (d *StreamDecryptor) Finish() ([]byte, error) {
	if d.lastErr != nil {
		return nil, d.lastErr
	}
	d.done = true
	return d.Bytes(), nil
}

// Bytes returns the running reassembled completion decrypted so far. The returned
// slice is a copy and is safe for the caller to retain or mutate.
func (d *StreamDecryptor) Bytes() []byte {
	cp := make([]byte, len(d.out))
	copy(cp, d.out)
	return cp
}

// String returns the running reassembled completion as a string.
func (d *StreamDecryptor) String() string {
	return string(d.out)
}

// Chunks returns the number of chunks successfully decrypted and appended.
func (d *StreamDecryptor) Chunks() int {
	return d.chunks
}

// StreamSealer is the worker-side counterpart used to PRODUCE an ordered sequence
// of independently-sealed SSE chunk records from a per-request Session. It exists
// primarily so the worker side of the streaming pattern (and its tests) can seal
// a multi-token completion chunk-by-chunk with the same Session the e2e_init
// handshake produced, mirroring StreamDecryptor on the consuming side.
//
// Like StreamDecryptor it is single-stream and not safe for concurrent use; seal
// the chunks of one completion sequentially so their counter nonces stay ordered.
type StreamSealer struct {
	sess *Session
	aad  []byte
}

// NewStreamSealer binds a per-request Session to a chunk sealer. aad, if non-nil,
// is authenticated into every sealed chunk and MUST be supplied (identically) to
// the StreamDecryptor that opens the stream.
func NewStreamSealer(sess *Session, aad []byte) (*StreamSealer, error) {
	if sess == nil {
		return nil, fmt.Errorf("e2ee: nil session: %w", ErrInvalidKeySize)
	}
	return &StreamSealer{sess: sess, aad: aad}, nil
}

// SealChunk seals a single stream token/chunk, returning its sealed record
// (Session.Seal output). Successive calls produce records with strictly
// increasing counter nonces when the session was created with CounterNonce=true,
// establishing the stream order the decryptor relies on.
func (s *StreamSealer) SealChunk(plaintext []byte) ([]byte, error) {
	return s.sess.Seal(plaintext, s.aad)
}
