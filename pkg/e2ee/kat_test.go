package e2ee

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Known-Answer Tests (KAT) for the two canonical AEAD suites the e2ee envelope
// supports. These are named with the "KAT" token so they are selectable via
// `go test -run KAT ./pkg/e2ee/...`, and they assert REAL crypto output: for a
// fixed (key, nonce, AAD, plaintext) the deterministic Seal path MUST produce
// the exact ciphertext||tag bytes published by an independent authority, and
// Open MUST recover the exact plaintext. A path that "executes without panic"
// but computes the wrong bytes FAILS here — this is not a tautology.
//
//   - SuiteAES256GCM (canonical default): McGrew & Viega "The Galois/Counter
//     Mode of Operation (GCM)" Test Case 16 (AES-256, 96-bit IV), the same
//     vector reproduced in NIST SP 800-38D interop suites.
//   - SuiteChaCha20Poly1305 (negotiable alt): RFC 8439 §2.8.2 AEAD example.
//
// The ChaCha RFC 8439 vector also has a dedicated assertion in
// TestChaChaRFC8439KnownAnswer; the entry below is the KAT-named twin so a
// `-run KAT` invocation exercises BOTH canonical suites, not just one.

func mustHexKAT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex literal %q: %v", s, err)
	}
	return b
}

// TestKAT_AES256GCM_TestCase16 pins the canonical-default suite against the
// published GCM Test Case 16 (AES-256). The expected ciphertext||tag is NOT a
// self-snapshot of this package — it is the byte string from the GCM
// specification's own worked example, also used across NIST SP 800-38D interop
// vectors.
//
// MUTATION THAT FAILS THIS: route SuiteAES256GCM to ChaCha in newAEAD (entirely
// different bytes), drop the AAD argument in the Seal path (tag changes), or
// flip any byte of wantHex (exact-match assertion fails).
func TestKAT_AES256GCM_TestCase16(t *testing.T) {
	key := mustHexKAT(t, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	nonce := mustHexKAT(t, "cafebabefacedbaddecaf888")
	aad := mustHexKAT(t, "feedfacedeadbeeffeedfacedeadbeefabaddad2")
	plaintext := mustHexKAT(t, "d9313225f88406e5a55909c5aff5269a"+
		"86a7a9531534f7da2e4c303d8a318a72"+
		"1c3c0c95956809532fcf0e2449a6b525"+
		"b16aedf5aa0de657ba637b39")

	// GCM spec Test Case 16: ciphertext (60 bytes) followed by the 16-byte tag.
	wantHex := "522dc1f099567d07f47f37a32a84427d" +
		"643a8cdcbfe5c0c97598a2bd2555d1aa" +
		"8cb08e48590dbb3da7b08b1056828838" +
		"c5f61e6393ba7a0abcc9f662" + // ciphertext (60 bytes) ends here
		"76fc6ece0f4e1768cddf8853bb2d551b" // 16-byte GCM authentication tag
	want := mustHexKAT(t, wantHex)

	got, err := SealWithKeySuite(SuiteAES256GCM, key, nonce, aad, plaintext)
	if err != nil {
		t.Fatalf("SealWithKeySuite(AES-256-GCM): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("AES-256-GCM KAT mismatch:\n got=%x\nwant=%x", got, want)
	}
	if len(got) != len(plaintext)+16 {
		t.Fatalf("output length %d, want %d (ciphertext+tag, no nonce prefix)",
			len(got), len(plaintext)+16)
	}

	// Default SealWithKey (suite-implicit) MUST equal the explicit AES-GCM call,
	// proving the zero-value suite is AES-256-GCM (the canonical default).
	gotDefault, err := SealWithKey(key, nonce, aad, plaintext)
	if err != nil {
		t.Fatalf("SealWithKey (default suite): %v", err)
	}
	if !bytes.Equal(gotDefault, want) {
		t.Fatalf("default SealWithKey != AES-256-GCM KAT vector:\n got=%x\nwant=%x",
			gotDefault, want)
	}

	// Inverse path: Open the published vector back to the exact plaintext.
	back, err := OpenWithKeySuite(SuiteAES256GCM, key, nonce, aad, want)
	if err != nil {
		t.Fatalf("OpenWithKeySuite(AES-256-GCM) on KAT vector: %v", err)
	}
	if !bytes.Equal(back, plaintext) {
		t.Fatalf("AES-256-GCM KAT open mismatch:\n got=%x\nwant=%x", back, plaintext)
	}
}

// TestKAT_ChaCha20Poly1305_RFC8439 is the KAT-named twin of
// TestChaChaRFC8439KnownAnswer: it feeds the EXACT RFC 8439 §2.8.2 AEAD example
// through the negotiable ChaCha20-Poly1305 suite and asserts byte-for-byte
// equality of ciphertext||tag, plus an inverse-path Open back to the RFC
// plaintext.
//
// MUTATION THAT FAILS THIS: route SuiteChaCha20Poly1305 to AES-GCM in newAEAD
// (different bytes) or flip any byte of want (exact-match assertion fails).
func TestKAT_ChaCha20Poly1305_RFC8439(t *testing.T) {
	key := mustHexKAT(t, "808182838485868788898a8b8c8d8e8f"+
		"909192939495969798999a9b9c9d9e9f")
	nonce := mustHexKAT(t, "070000004041424344454647")
	aad := mustHexKAT(t, "50515253c0c1c2c3c4c5c6c7")
	plaintext := []byte("Ladies and Gentlemen of the class of '99: " +
		"If I could offer you only one tip for the future, sunscreen would be it.")

	// RFC 8439 §2.8.2: 114-byte ciphertext followed by the 16-byte Poly1305 tag.
	want := mustHexKAT(t, "d31a8d34648e60db7b86afbc53ef7ec2"+
		"a4aded51296e08fea9e2b5a736ee62d6"+
		"3dbea45e8ca9671282fafb69da92728b"+
		"1a71de0a9e060b2905d6a5b67ecd3b36"+
		"92ddbd7f2d778b8c9803aee328091b58"+
		"fab324e4fad675945585808b4831d7bc"+
		"3ff4def08e4b7a9de576d26586cec64b"+
		"6116"+ // ciphertext (114 bytes) ends here
		"1ae10b594f09e26a7e902ecbd0600691") // 16-byte Poly1305 tag

	got, err := SealWithKeySuite(SuiteChaCha20Poly1305, key, nonce, aad, plaintext)
	if err != nil {
		t.Fatalf("SealWithKeySuite(ChaCha20-Poly1305): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("RFC 8439 ChaCha20-Poly1305 KAT mismatch:\n got=%x\nwant=%x", got, want)
	}

	back, err := OpenWithKeySuite(SuiteChaCha20Poly1305, key, nonce, aad, want)
	if err != nil {
		t.Fatalf("OpenWithKeySuite(ChaCha20-Poly1305) on RFC vector: %v", err)
	}
	if !bytes.Equal(back, plaintext) {
		t.Fatalf("RFC 8439 ChaCha20-Poly1305 open mismatch: got %q want %q", back, plaintext)
	}

	// The two canonical suites MUST be distinct ciphers, not one behind two
	// names: same inputs, different output bytes.
	aesOut, err := SealWithKeySuite(SuiteAES256GCM, key, nonce, aad, plaintext)
	if err != nil {
		t.Fatalf("SealWithKeySuite(AES-256-GCM) distinctness probe: %v", err)
	}
	if bytes.Equal(aesOut, got) {
		t.Fatal("AES-256-GCM and ChaCha20-Poly1305 produced identical output; suites are not distinct")
	}
}
