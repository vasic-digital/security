package e2ee

import (
	"encoding/binary"
	"fmt"
	"io"
)

// DefaultMaxRecordSize is the default upper bound on a single framed record's
// ciphertext length, guarding the reader against hostile length prefixes.
const DefaultMaxRecordSize = 16 << 20 // 16 MiB

// recordLenPrefix is the number of length-prefix bytes preceding each record.
const recordLenPrefix = 4

// Transport wraps an io.ReadWriter with the session AEAD, sending and receiving
// length-prefixed encrypted records. The wire format per record is:
//
//	uint32 big-endian length || (nonce(12) || ciphertext||tag)
//
// Transport is a thin framing layer over Session.Seal/Session.Open; all
// confidentiality, integrity, and replay guarantees come from the Session.
type Transport struct {
	sess    *Session
	rw      io.ReadWriter
	maxRecv uint32
}

// NewTransport binds a Session to an io.ReadWriter. maxRecordSize bounds the
// accepted record length on Read; pass 0 for DefaultMaxRecordSize.
func NewTransport(sess *Session, rw io.ReadWriter, maxRecordSize uint32) *Transport {
	if maxRecordSize == 0 {
		maxRecordSize = DefaultMaxRecordSize
	}
	return &Transport{sess: sess, rw: rw, maxRecv: maxRecordSize}
}

// WriteRecord seals plaintext (with aad) and writes a single length-prefixed
// record to the underlying writer.
func (t *Transport) WriteRecord(plaintext, aad []byte) error {
	record, err := t.sess.Seal(plaintext, aad)
	if err != nil {
		return err
	}
	if len(record) > int(t.maxRecv) {
		return fmt.Errorf("e2ee: sealed record %d exceeds max %d: %w",
			len(record), t.maxRecv, ErrRecordTooLarge)
	}
	var hdr [recordLenPrefix]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(record)))
	if _, err := t.rw.Write(hdr[:]); err != nil {
		return fmt.Errorf("e2ee: write length prefix: %w", err)
	}
	if _, err := t.rw.Write(record); err != nil {
		return fmt.Errorf("e2ee: write record body: %w", err)
	}
	return nil
}

// ReadRecord reads one length-prefixed record and returns the decrypted
// plaintext. aad must match what the writer passed to WriteRecord.
func (t *Transport) ReadRecord(aad []byte) ([]byte, error) {
	var hdr [recordLenPrefix]byte
	if _, err := io.ReadFull(t.rw, hdr[:]); err != nil {
		return nil, fmt.Errorf("e2ee: read length prefix: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > t.maxRecv {
		return nil, fmt.Errorf("e2ee: record length %d out of range (max %d): %w",
			n, t.maxRecv, ErrRecordTooLarge)
	}
	record := make([]byte, n)
	if _, err := io.ReadFull(t.rw, record); err != nil {
		return nil, fmt.Errorf("e2ee: read record body: %w", err)
	}
	return t.sess.Open(record, aad)
}
