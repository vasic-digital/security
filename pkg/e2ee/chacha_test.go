package e2ee

import (
	"bytes"
	"testing"
)

// TestChaChaRoundTrip proves the ChaCha20-Poly1305 suite yields working
// bidirectional AEAD over a full ML-KEM handshake: plaintext sealed by one peer
// is recovered EXACTLY by the other when both select SuiteChaCha20Poly1305.
//
// MUTATION THAT FAILS THIS: route the ChaCha suite back to AES-GCM in newAEAD
// (so only one side actually uses ChaCha) — Open returns ErrOpen and the
// bytes.Equal check fails. (Symmetric mutation: have one peer use AES, the other
// ChaCha — key/cipher mismatch makes Open fail.)
func TestChaChaRoundTrip(t *testing.T) {
	cfg := SessionConfig{Suite: SuiteChaCha20Poly1305}
	isess, rsess := handshake(t, cfg)

	msg := []byte("confidential inference prompt over chacha: 1337")
	aad := []byte("route=worker-chacha")

	rec, err := isess.Seal(msg, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := rsess.Open(rec, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("chacha round-trip mismatch: got %q want %q", got, msg)
	}

	// reverse direction
	reply := []byte("chacha completion tokens here")
	rec2, err := rsess.Seal(reply, nil)
	if err != nil {
		t.Fatalf("Seal reply: %v", err)
	}
	got2, err := isess.Open(rec2, nil)
	if err != nil {
		t.Fatalf("Open reply: %v", err)
	}
	if !bytes.Equal(got2, reply) {
		t.Fatalf("chacha reverse round-trip mismatch: got %q want %q", got2, reply)
	}
}

// TestChaChaRFC8439KnownAnswer is the load-bearing anti-bluff assertion: it
// feeds the EXACT public test vector from RFC 8439 §2.8.2 (the AEAD
// construction example) through the package's ChaCha20-Poly1305 deterministic
// Seal path and asserts the produced ciphertext||tag matches the RFC's expected
// bytes EXACTLY, byte for byte. A crypto path that "executes without panic" but
// computes the wrong bytes FAILS here.
//
// Source vector (RFC 8439, §2.8.2):
//
//	Key      = 80..9f
//	Nonce    = 070000004041424344454647
//	AAD      = 50515253c0c1c2c3c4c5c6c7
//	Plaintext= "Ladies and Gentlemen of the class of '99: ..."
//	-> ciphertext (114 bytes) followed by the 16-byte Poly1305 tag.
//
// MUTATION THAT FAILS THIS: (a) swap the ChaCha path back to AES-GCM in newAEAD
// — AES produces entirely different bytes, KAT FAILs; or (b) flip a single byte
// of wantCiphertext / wantTag — the exact-match assertion FAILs.
func TestChaChaRFC8439KnownAnswer(t *testing.T) {
	key := []byte{
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	}
	nonce := []byte{
		0x07, 0x00, 0x00, 0x00,
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	}
	aad := []byte{
		0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
		0xc4, 0xc5, 0xc6, 0xc7,
	}
	plaintext := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")

	// Expected ciphertext (114 bytes) from RFC 8439 §2.8.2.
	wantCiphertext := []byte{
		0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
		0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
		0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
		0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
		0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
		0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
		0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
		0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
		0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
		0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
		0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
		0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
		0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
		0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
		0x61, 0x16,
	}
	// Expected Poly1305 tag (16 bytes) from RFC 8439 §2.8.2.
	wantTag := []byte{
		0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
		0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
	}
	want := append(append([]byte{}, wantCiphertext...), wantTag...)

	got, err := SealWithKeySuite(SuiteChaCha20Poly1305, key, nonce, aad, plaintext)
	if err != nil {
		t.Fatalf("SealWithKeySuite(chacha): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("RFC 8439 KAT mismatch:\n got=%x\nwant=%x", got, want)
	}

	// Round-trip through Open to confirm the inverse path also agrees with the
	// RFC vector (decrypts the RFC ciphertext back to the RFC plaintext).
	back, err := OpenWithKeySuite(SuiteChaCha20Poly1305, key, nonce, aad, want)
	if err != nil {
		t.Fatalf("OpenWithKeySuite(chacha) on RFC vector: %v", err)
	}
	if !bytes.Equal(back, plaintext) {
		t.Fatalf("RFC 8439 open mismatch: got %q want %q", back, plaintext)
	}
}

// TestAESGCMDefaultStillWorks confirms the default (zero-value Suite) path
// remains AES-256-GCM and is unaffected by the ChaCha addition: a handshake with
// a zero SessionConfig still round-trips, and the deterministic AES path is
// distinct from ChaCha for identical inputs.
//
// MUTATION THAT FAILS THIS: make SuiteAES256GCM dispatch to ChaCha in newAEAD —
// the AES-vs-ChaCha distinctness assertion FAILs (they'd be equal).
func TestAESGCMDefaultStillWorks(t *testing.T) {
	// Default handshake (Suite unset == SuiteAES256GCM) round-trips.
	isess, rsess := handshake(t, SessionConfig{})
	msg := []byte("default suite payload")
	rec, err := isess.Seal(msg, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := rsess.Open(rec, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("default-suite round-trip mismatch: got %q want %q", got, msg)
	}

	// Deterministic AES path still works and is byte-distinct from ChaCha for
	// the same (key, nonce, aad, plaintext) — proving the two suites are really
	// different ciphers, not the same one behind two names.
	key := make([]byte, SessionKeySize)
	nonce := make([]byte, NonceSize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range nonce {
		nonce[i] = byte(0xa0 + i)
	}
	pt := []byte("same plaintext under both suites")

	aesOut, err := SealWithKey(key, nonce, nil, pt)
	if err != nil {
		t.Fatalf("SealWithKey(aes default): %v", err)
	}
	// Default SealWithKey must equal the explicit AES-GCM suite call.
	aesOut2, err := SealWithKeySuite(SuiteAES256GCM, key, nonce, nil, pt)
	if err != nil {
		t.Fatalf("SealWithKeySuite(aes): %v", err)
	}
	if !bytes.Equal(aesOut, aesOut2) {
		t.Fatalf("default SealWithKey != explicit AES suite:\n a=%x\n b=%x", aesOut, aesOut2)
	}

	chachaOut, err := SealWithKeySuite(SuiteChaCha20Poly1305, key, nonce, nil, pt)
	if err != nil {
		t.Fatalf("SealWithKeySuite(chacha): %v", err)
	}
	if bytes.Equal(aesOut, chachaOut) {
		t.Fatalf("AES-GCM and ChaCha20-Poly1305 produced identical output; suites are not distinct")
	}

	// AES open round-trips its own output.
	rt, err := OpenWithKey(key, nonce, nil, aesOut)
	if err != nil {
		t.Fatalf("OpenWithKey(aes): %v", err)
	}
	if !bytes.Equal(rt, pt) {
		t.Fatalf("aes deterministic round-trip mismatch: got %q want %q", rt, pt)
	}
}
