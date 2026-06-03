package e2ee

// Gzip-before-encrypt payload compression for the e2ee record layer.
//
// Large JSON prompts (the Chutes-style request envelopes this transport
// carries) are highly repetitive and compress well. Compressing BEFORE the
// AEAD seal — never after, since ciphertext is incompressible — shrinks the
// sealed wire record while leaving the AES-256-GCM envelope and the
// length-prefixed Transport framing byte-for-byte unchanged.
//
// The compression stage is self-describing: each payload is prefixed with a
// single tag byte declaring whether the body that follows is raw or gzipped.
// compressPayload chooses gzip only when it actually shrinks the input (a tiny
// or already-incompressible JSON body stays raw, avoiding gzip's framing
// overhead), so the stage never inflates a payload. decompressPayload reverses
// either case exactly, so decompressPayload(compressPayload(x)) == x for every
// x — the transparency guarantee.
//
// The tagged plaintext is what gets sealed; the AEAD authenticates the tag
// byte along with the body, so a flipped tag is rejected as a forgery rather
// than mis-decoded. Because only the plaintext fed to Session.Seal changes
// (and the cipher, nonce, and framing do not), a peer using the plain
// Transport interoperates with the reference protocol framing unchanged; the
// CompressedTransport adds the compression header inside the sealed plaintext.

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

// compressionTag is the leading byte of a compression-framed plaintext,
// declaring how the remaining bytes are encoded.
type compressionTag byte

const (
	// payloadRaw marks a plaintext body stored verbatim (no compression).
	payloadRaw compressionTag = 0x00

	// payloadGzip marks a plaintext body stored as a gzip stream.
	payloadGzip compressionTag = 0x01
)

// gzipCompressionLevel is the gzip level used for payload compression.
// BestCompression maximises the wire-size win on large repetitive JSON, which
// is the payload class this transport is tuned for; the CPU cost is negligible
// next to the ML-KEM handshake and AES-GCM sealing already on the path.
const gzipCompressionLevel = gzip.BestCompression

// DefaultMaxDecompressedSize bounds the plaintext a single record may expand to
// after gunzip, guarding the reader against a decompression bomb in a record
// that authenticated correctly but was crafted with a pathological ratio.
const DefaultMaxDecompressedSize = 64 << 20 // 64 MiB

// compressPayload frames plaintext for sealing: it returns tag(1) || body,
// where body is gzip(plaintext) when that is strictly smaller than plaintext,
// otherwise plaintext verbatim. The result is never larger than
// len(plaintext)+1, so the stage cannot inflate a payload beyond the one-byte
// tag.
func compressPayload(plaintext []byte) ([]byte, error) {
	var gz bytes.Buffer
	gz.WriteByte(byte(payloadGzip))
	w, err := gzip.NewWriterLevel(&gz, gzipCompressionLevel)
	if err != nil {
		return nil, fmt.Errorf("e2ee: gzip writer: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("e2ee: gzip write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("e2ee: gzip close: %w", err)
	}

	// Use the gzipped framing only when it is strictly smaller than the raw
	// framing; otherwise fall back to the verbatim body so we never inflate.
	if gz.Len() < len(plaintext)+1 {
		return gz.Bytes(), nil
	}
	raw := make([]byte, 0, len(plaintext)+1)
	raw = append(raw, byte(payloadRaw))
	raw = append(raw, plaintext...)
	return raw, nil
}

// decompressPayload reverses compressPayload: it reads the leading tag byte and
// returns the original plaintext, gunzipping the body when the tag says so.
// maxSize bounds the recovered plaintext length (0 uses
// DefaultMaxDecompressedSize) so a decompression bomb cannot exhaust memory.
func decompressPayload(framed []byte, maxSize int) ([]byte, error) {
	if len(framed) == 0 {
		return nil, fmt.Errorf("e2ee: empty compression frame: %w", ErrInvalidCiphertext)
	}
	if maxSize <= 0 {
		maxSize = DefaultMaxDecompressedSize
	}
	tag := compressionTag(framed[0])
	body := framed[1:]
	switch tag {
	case payloadRaw:
		// Return a copy so the caller owns the slice independently of the input.
		out := make([]byte, len(body))
		copy(out, body)
		return out, nil
	case payloadGzip:
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("e2ee: gzip reader: %w", err)
		}
		defer zr.Close()
		// LimitReader bounds the work to maxSize+1 so we can detect overflow.
		limited := io.LimitReader(zr, int64(maxSize)+1)
		out, err := io.ReadAll(limited)
		if err != nil {
			return nil, fmt.Errorf("e2ee: gzip read: %w", err)
		}
		if len(out) > maxSize {
			return nil, fmt.Errorf("e2ee: decompressed payload exceeds max %d: %w",
				maxSize, ErrRecordTooLarge)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("e2ee: unknown compression tag 0x%02x: %w",
			byte(tag), ErrInvalidCiphertext)
	}
}

// CompressedTransport wraps a Transport with transparent gzip-before-encrypt
// payload compression. SealPayload gzips the (JSON) payload when that shrinks
// it, then seals the tagged result through the underlying Session; OpenPayload
// reverses both stages, recovering the exact original bytes. The AEAD, nonce
// discipline, and length-prefixed wire framing are inherited unchanged from the
// embedded Transport, preserving interop with the reference protocol framing.
type CompressedTransport struct {
	*Transport

	// maxDecompressed bounds the plaintext recovered per record after gunzip;
	// 0 means DefaultMaxDecompressedSize.
	maxDecompressed int
}

// NewCompressedTransport binds compression to an existing Transport.
// maxDecompressedSize bounds the post-gunzip plaintext per record; pass 0 for
// DefaultMaxDecompressedSize.
func NewCompressedTransport(t *Transport, maxDecompressedSize int) *CompressedTransport {
	return &CompressedTransport{Transport: t, maxDecompressed: maxDecompressedSize}
}

// WritePayload compresses payload (transparently — gzip only when smaller),
// seals it, and writes one length-prefixed record. aad is authenticated
// alongside the compression-framed plaintext.
func (c *CompressedTransport) WritePayload(payload, aad []byte) error {
	framed, err := compressPayload(payload)
	if err != nil {
		return err
	}
	return c.WriteRecord(framed, aad)
}

// ReadPayload reads one length-prefixed record, opens it, and decompresses the
// recovered plaintext back to the exact original payload bytes.
func (c *CompressedTransport) ReadPayload(aad []byte) ([]byte, error) {
	framed, err := c.ReadRecord(aad)
	if err != nil {
		return nil, err
	}
	return decompressPayload(framed, c.maxDecompressed)
}

// SealCompressed compresses plaintext (transparently) and seals it on sess,
// returning the wire record (nonce || ciphertext||tag). It is the framing-free
// counterpart to CompressedTransport.WritePayload for callers that handle their
// own record framing, and pairs with OpenCompressed.
func SealCompressed(sess *Session, plaintext, aad []byte) ([]byte, error) {
	framed, err := compressPayload(plaintext)
	if err != nil {
		return nil, err
	}
	return sess.Seal(framed, aad)
}

// OpenCompressed opens a record produced by SealCompressed on sess and
// decompresses it back to the exact original plaintext. maxSize bounds the
// recovered plaintext (0 uses DefaultMaxDecompressedSize).
func OpenCompressed(sess *Session, record, aad []byte, maxSize int) ([]byte, error) {
	framed, err := sess.Open(record, aad)
	if err != nil {
		return nil, err
	}
	return decompressPayload(framed, maxSize)
}
