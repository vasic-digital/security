package e2ee

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// largeRepetitiveJSON builds a large, highly repetitive JSON prompt payload of
// the Chutes-envelope shape this transport carries. Repetition is what makes
// the compression win measurable and deterministic.
func largeRepetitiveJSON(t *testing.T) []byte {
	t.Helper()
	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type req struct {
		Model       string `json:"model"`
		Stream      bool   `json:"stream"`
		Temperature float64
		Messages    []msg `json:"messages"`
	}
	const line = "The quick brown fox jumps over the lazy dog. "
	r := req{Model: "chutes/llama-3.1-70b-instruct", Stream: true, Temperature: 0.7}
	for i := 0; i < 400; i++ {
		r.Messages = append(r.Messages, msg{
			Role:    "user",
			Content: strings.Repeat(line, 8) + fmt.Sprintf(" turn=%d", i),
		})
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestCompressedTransport_MeasurableCompressionAndExactRoundTrip is the primary
// closure proof. It captures the raw payload size BEFORE compression and the
// sealed wire-record size AFTER gzip-then-seal over an in-memory pipe, asserts
// the wire is MEASURABLY smaller than the raw payload (sink-side: the bytes
// actually on the wire shrank), and asserts the decrypted+gunzipped payload is
// byte-for-byte identical to the original.
//
// MUTATION THAT FAILS THIS: in compressPayload, always take the raw branch
// (e.g. `if false {` guarding the gzip return) — the wire record then grows
// past the raw payload and the `after < before` assertion fails. Equivalently,
// neutering gunzip in decompressPayload (returning body verbatim for the gzip
// tag) breaks the byte-equality assertion.
func TestCompressedTransport_MeasurableCompressionAndExactRoundTrip(t *testing.T) {
	payload := largeRepetitiveJSON(t)
	before := len(payload)

	sessA, sessB := handshake(t, SessionConfig{CounterNonce: true})
	var pipe bytes.Buffer
	writer := NewCompressedTransport(NewTransport(sessA, &pipe, 0), 0)
	reader := NewCompressedTransport(NewTransport(sessB, &pipe, 0), 0)

	aad := []byte("chutes-prompt-v1")
	if err := writer.WritePayload(payload, aad); err != nil {
		t.Fatalf("WritePayload: %v", err)
	}

	// SINK-SIDE: the full framed record now sitting on the wire (length prefix
	// + nonce + ciphertext+tag) is what an observer/peer actually receives.
	after := pipe.Len()

	if after >= before {
		t.Fatalf("compression did not shrink the wire: before(raw)=%d after(sealed wire)=%d", before, after)
	}
	// Demand a real win, not a 1-byte fluke: repetitive JSON must compress hard.
	if after*2 >= before {
		t.Fatalf("compression weaker than expected: before(raw)=%d after(sealed wire)=%d (want after < before/2)", before, after)
	}
	t.Logf("CLOSURE: before(raw JSON)=%d bytes, after(gzip+seal wire)=%d bytes, ratio=%.1f%%",
		before, after, 100*float64(after)/float64(before))

	// Full round-trip: decrypt + gunzip must recover the EXACT original bytes.
	got, err := reader.ReadPayload(aad)
	if err != nil {
		t.Fatalf("ReadPayload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d bytes (byte-equality failed)", len(got), len(payload))
	}
}

// TestSealOpenCompressed_ExactRoundTrip proves the framing-free SealCompressed /
// OpenCompressed pair round-trips arbitrary payloads to exact byte-equality,
// including binary and empty inputs.
//
// MUTATION THAT FAILS THIS: drop the tag byte in compressPayload (return only
// the gzip body / raw body without prepending the tag) — decompressPayload then
// reads the wrong leading byte as the tag and either errors or mis-decodes, so
// byte-equality fails for at least one case.
func TestSealOpenCompressed_ExactRoundTrip(t *testing.T) {
	sessA, sessB := handshake(t, SessionConfig{CounterNonce: true})
	aad := []byte("ctx=sealcompressed")

	cases := map[string][]byte{
		"empty":            {},
		"tiny":             []byte("{}"),
		"binary":           {0x00, 0x01, 0xfe, 0xff, 0x00, 0x7f},
		"large-repetitive": largeRepetitiveJSON(t),
	}
	for name, pt := range cases {
		t.Run(name, func(t *testing.T) {
			rec, err := SealCompressed(sessA, pt, aad)
			if err != nil {
				t.Fatalf("SealCompressed: %v", err)
			}
			got, err := OpenCompressed(sessB, rec, aad, 0)
			if err != nil {
				t.Fatalf("OpenCompressed: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("round-trip mismatch for %q: got %q want %q", name, got, pt)
			}
		})
	}
}

// TestCompressPayload_Transparency proves the pure compress/decompress stage is
// transparent for every input class and never inflates: the framed output is at
// most len(input)+1, and decompressPayload(compressPayload(x)) == x exactly.
//
// MUTATION THAT FAILS THIS: in compressPayload, remove the "gzip only when
// smaller" guard and always return the gzip framing — a tiny input then inflates
// past len(input)+1 and the no-inflation assertion fails.
func TestCompressPayload_Transparency(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		[]byte("x"),
		[]byte("{}"),
		bytes.Repeat([]byte("ab"), 4096), // highly compressible
		[]byte(`{"k":"` + strings.Repeat("v", 10000) + `"}`), // compressible JSON
	}
	for i, in := range inputs {
		framed, err := compressPayload(in)
		if err != nil {
			t.Fatalf("case %d compressPayload: %v", i, err)
		}
		if len(framed) > len(in)+1 {
			t.Fatalf("case %d inflated: framed=%d, want <= len(in)+1=%d", i, len(framed), len(in)+1)
		}
		out, err := decompressPayload(framed, 0)
		if err != nil {
			t.Fatalf("case %d decompressPayload: %v", i, err)
		}
		if !bytes.Equal(out, in) && !(len(out) == 0 && len(in) == 0) {
			t.Fatalf("case %d transparency broken: got %q want %q", i, out, in)
		}
	}
}

// TestCompressPayload_GzipBranchTakenForRepetitive proves the gzip branch is
// actually exercised (the tag byte is payloadGzip) for a large repetitive
// payload, so the compression path is not silently dead.
//
// MUTATION THAT FAILS THIS: force compressPayload to always take the raw branch
// — the leading tag byte becomes payloadRaw and this assertion fails.
func TestCompressPayload_GzipBranchTakenForRepetitive(t *testing.T) {
	in := bytes.Repeat([]byte("repetitive-json-line-"), 2000)
	framed, err := compressPayload(in)
	if err != nil {
		t.Fatalf("compressPayload: %v", err)
	}
	if compressionTag(framed[0]) != payloadGzip {
		t.Fatalf("expected gzip tag 0x%02x, got 0x%02x", byte(payloadGzip), framed[0])
	}
	if len(framed) >= len(in) {
		t.Fatalf("gzip branch did not shrink: framed=%d in=%d", len(framed), len(in))
	}
}

// TestDecompressPayload_RejectsBombAndBadTag proves the reader bounds
// decompressed size and rejects an unknown compression tag, rather than
// trusting an authenticated-but-hostile body.
//
// MUTATION THAT FAILS THIS: remove the maxSize overflow check in
// decompressPayload — the oversized bomb then decodes without ErrRecordTooLarge.
func TestDecompressPayload_RejectsBombAndBadTag(t *testing.T) {
	// A 1 MiB zero-payload gzips tiny but expands large; cap at 4 KiB.
	bomb, err := compressPayload(bytes.Repeat([]byte{0}, 1<<20))
	if err != nil {
		t.Fatalf("compressPayload: %v", err)
	}
	if compressionTag(bomb[0]) != payloadGzip {
		t.Fatalf("test precondition: expected gzip framing for zero-bomb, got tag 0x%02x", bomb[0])
	}
	if _, err := decompressPayload(bomb, 4<<10); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("expected ErrRecordTooLarge for decompression bomb, got %v", err)
	}

	// Unknown tag byte must be rejected.
	if _, err := decompressPayload([]byte{0xAB, 1, 2, 3}, 0); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("expected ErrInvalidCiphertext for unknown tag, got %v", err)
	}
}

// TestCompressedTransport_TamperedRecordRejected proves the AEAD still
// authenticates the compression-framed plaintext: flipping a byte in the sealed
// wire record makes OpenCompressed fail rather than mis-decode.
//
// MUTATION THAT FAILS THIS: none in compress.go directly — this guards that the
// compression layer did not bypass the seal; if SealCompressed stopped sealing
// (e.g. returned the framed plaintext directly), the tamper would not be caught.
func TestCompressedTransport_TamperedRecordRejected(t *testing.T) {
	sessA, sessB := handshake(t, SessionConfig{CounterNonce: true})
	aad := []byte("tamper-ctx")
	rec, err := SealCompressed(sessA, largeRepetitiveJSON(t), aad)
	if err != nil {
		t.Fatalf("SealCompressed: %v", err)
	}
	tampered := append([]byte(nil), rec...)
	tampered[NonceSize+3] ^= 0x01
	if _, err := OpenCompressed(sessB, tampered, aad, 0); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen on tampered record, got %v", err)
	}
}
