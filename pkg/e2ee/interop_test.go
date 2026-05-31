package e2ee

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"testing"
)

// Byte-interop test vectors for the deterministic AES-256-GCM AEAD.
//
// The KEM handshake is randomized (ephemeral ML-KEM keys), so it cannot produce
// reproducible bytes. The AEAD layer, given a FIXED key + nonce + aad +
// plaintext, is fully deterministic. These tests pin the EXACT ciphertext||tag
// hex a conforming AES-256-GCM implementation must produce, proving any other
// implementation that agrees on these bytes will interoperate at the record
// layer.
//
// The pinned hex was produced by raw crypto/aes + crypto/cipher GCM (NIST
// FIPS 197 / SP 800-38D) over the exact inputs below and independently
// re-derived inside TestInteropMatchesStdlibAESGCM, so it is not a self-
// referential snapshot of this package's own output.

// Pinned interop vector #1: 43-byte plaintext, non-empty AAD.
var (
	interopKey   = mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	interopNonce = mustHex("a0a1a2a3a4a5a6a7a8a9aaab")
	interopAAD   = []byte("helix-e2ee-interop-vector-v1")
	interopPT    = []byte("The quick brown fox jumps over the lazy dog")
	// EXACT AES-256-GCM ciphertext||tag for the inputs above (59 bytes = 43 + 16).
	interopCTTagHex = "b270190d34be6bdc0945e5a1680daefe16c32130f8c22f1cef2e49f01ad95575" +
		"ba136793ce582a1d3bf3635217fa2eee5714e7ea51bd60f3b065cf"

	// Pinned interop vector #2: empty plaintext, nil AAD -> pure 16-byte tag.
	interopEmptyTagHex = "5c699625af4b93a0f8220a2a6119c5d0"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex literal: " + err.Error())
	}
	return b
}

// TestSealWithKeyPinnedVector proves SealWithKey produces the EXACT pinned
// ciphertext||tag for the fixed key/nonce/aad/plaintext, with no nonce prefix.
//
// MUTATION THAT FAILS THIS: in SealWithKey, drop the caller's aad (call
// gcm.Seal(nil, nonce, plaintext, nil)) — the authentication tag changes and the
// hex no longer matches. Equivalently, prepend the nonce to the output (out :=
// append(append([]byte{}, nonce...), gcm.Seal(...)...)) — the length and leading
// bytes diverge from the pinned 59-byte vector.
func TestSealWithKeyPinnedVector(t *testing.T) {
	got, err := SealWithKey(interopKey, interopNonce, interopAAD, interopPT)
	if err != nil {
		t.Fatalf("SealWithKey: %v", err)
	}
	want := mustHex(interopCTTagHex)
	if !bytes.Equal(got, want) {
		t.Fatalf("ciphertext mismatch:\n got  %s\n want %s",
			hex.EncodeToString(got), interopCTTagHex)
	}
	// The output carries NO nonce prefix: it is exactly plaintext+tag length.
	if len(got) != len(interopPT)+16 {
		t.Fatalf("output length %d, want %d (plaintext+tag, no nonce prefix)",
			len(got), len(interopPT)+16)
	}
}

// TestSealWithKeyEmptyPlaintextPinned proves the empty-plaintext / nil-AAD case
// yields the pinned pure 16-byte authentication tag.
//
// MUTATION THAT FAILS THIS: have SealWithKey substitute a constant nonce (e.g.
// always 12 zero bytes) instead of the caller's nonce — the tag changes and the
// pinned hex no longer matches.
func TestSealWithKeyEmptyPlaintextPinned(t *testing.T) {
	got, err := SealWithKey(interopKey, interopNonce, nil, nil)
	if err != nil {
		t.Fatalf("SealWithKey empty: %v", err)
	}
	want := mustHex(interopEmptyTagHex)
	if !bytes.Equal(got, want) {
		t.Fatalf("empty-plaintext tag mismatch:\n got  %s\n want %s",
			hex.EncodeToString(got), interopEmptyTagHex)
	}
}

// TestOpenWithKeyPinnedVector proves OpenWithKey recovers the EXACT plaintext
// from the pinned ciphertext||tag.
//
// MUTATION THAT FAILS THIS: in OpenWithKey, pass nil aad to gcm.Open instead of
// the caller's aad — authentication fails and Open returns ErrOpen instead of
// the plaintext.
func TestOpenWithKeyPinnedVector(t *testing.T) {
	pinned := mustHex(interopCTTagHex)
	got, err := OpenWithKey(interopKey, interopNonce, interopAAD, pinned)
	if err != nil {
		t.Fatalf("OpenWithKey: %v", err)
	}
	if !bytes.Equal(got, interopPT) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, interopPT)
	}
}

// TestSealOpenWithKeyRoundTrip proves the deterministic entry points round-trip
// arbitrary data, and that the same inputs always yield the same bytes
// (determinism).
//
// MUTATION THAT FAILS THIS: make SealWithKey draw a random nonce internally
// instead of using the caller's — round-tripping with the caller's nonce on
// Open then fails (ErrOpen), and two seals of identical inputs differ.
func TestSealOpenWithKeyRoundTrip(t *testing.T) {
	pt := []byte("round-trip payload \x00\x01\xfe\xff with binary")
	aad := []byte("ctx=roundtrip")
	ct1, err := SealWithKey(interopKey, interopNonce, aad, pt)
	if err != nil {
		t.Fatalf("SealWithKey: %v", err)
	}
	ct2, err := SealWithKey(interopKey, interopNonce, aad, pt)
	if err != nil {
		t.Fatalf("SealWithKey (2nd): %v", err)
	}
	if !bytes.Equal(ct1, ct2) {
		t.Fatal("deterministic AEAD produced different bytes for identical inputs")
	}
	out, err := OpenWithKey(interopKey, interopNonce, aad, ct1)
	if err != nil {
		t.Fatalf("OpenWithKey: %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("round-trip mismatch: got %q want %q", out, pt)
	}
}

// TestOpenWithKeyTamperFails proves a 1-byte tamper of the pinned ciphertext
// makes OpenWithKey fail authentication.
//
// MUTATION THAT FAILS THIS: replace OpenWithKey's gcm.Open with a routine that
// strips the trailing 16-byte tag and returns the remaining bytes unverified;
// the tampered ciphertext would then "decrypt" and err would be nil.
func TestOpenWithKeyTamperFails(t *testing.T) {
	pinned := mustHex(interopCTTagHex)
	for _, idx := range []int{0, len(pinned) / 2, len(pinned) - 1} {
		tampered := append([]byte(nil), pinned...)
		tampered[idx] ^= 0x01
		if _, err := OpenWithKey(interopKey, interopNonce, interopAAD, tampered); !errors.Is(err, ErrOpen) {
			t.Fatalf("tamper at byte %d: expected ErrOpen, got %v", idx, err)
		}
	}
	// Sanity: the untampered pinned ciphertext still opens.
	if _, err := OpenWithKey(interopKey, interopNonce, interopAAD, pinned); err != nil {
		t.Fatalf("untampered pinned ciphertext should open, got %v", err)
	}
}

// TestOpenWithKeyAADMismatchFails proves the AAD is authenticated: opening the
// pinned ciphertext with different AAD fails.
//
// MUTATION THAT FAILS THIS: drop the caller's aad in OpenWithKey (pass nil to
// gcm.Open); the mismatched-AAD open would then succeed.
func TestOpenWithKeyAADMismatchFails(t *testing.T) {
	pinned := mustHex(interopCTTagHex)
	wrongAAD := append([]byte(nil), interopAAD...)
	wrongAAD[0] ^= 0x01
	if _, err := OpenWithKey(interopKey, interopNonce, wrongAAD, pinned); !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen on AAD mismatch, got %v", err)
	}
}

// TestInteropMatchesStdlibAESGCM is the core cross-implementation proof: it
// computes the ciphertext for the pinned inputs using ONLY raw crypto/aes +
// crypto/cipher GCM (an implementation independent of this package's helpers)
// and asserts byte-equality with SealWithKey's output AND with the pinned hex.
// This establishes that the package output is exactly standard AES-256-GCM, so
// any conforming third-party implementation interoperates.
//
// MUTATION THAT FAILS THIS: change SealWithKey's nonce placement or AAD handling
// (e.g. prepend the nonce, or swap plaintext/aad arguments to gcm.Seal); the
// package output then diverges from the independent stdlib computation and the
// byte-equality assertion fails.
func TestInteropMatchesStdlibAESGCM(t *testing.T) {
	// Independent stdlib computation — no calls into the package under test.
	block, err := aes.NewCipher(interopKey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	stdGCM, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	stdCT := stdGCM.Seal(nil, interopNonce, interopPT, interopAAD)

	// 1) The independent computation must equal the pinned vector.
	if want := mustHex(interopCTTagHex); !bytes.Equal(stdCT, want) {
		t.Fatalf("stdlib output != pinned vector:\n got  %s\n want %s",
			hex.EncodeToString(stdCT), interopCTTagHex)
	}

	// 2) The package output must byte-equal the independent stdlib computation.
	pkgCT, err := SealWithKey(interopKey, interopNonce, interopAAD, interopPT)
	if err != nil {
		t.Fatalf("SealWithKey: %v", err)
	}
	if !bytes.Equal(pkgCT, stdCT) {
		t.Fatalf("package output != independent stdlib AES-GCM:\n pkg %s\n std %s",
			hex.EncodeToString(pkgCT), hex.EncodeToString(stdCT))
	}

	// 3) Cross-open: the package opens what stdlib sealed, and vice versa.
	if pt, err := OpenWithKey(interopKey, interopNonce, interopAAD, stdCT); err != nil || !bytes.Equal(pt, interopPT) {
		t.Fatalf("package failed to open stdlib-sealed record: pt=%q err=%v", pt, err)
	}
	if pt, err := stdGCM.Open(nil, interopNonce, pkgCT, interopAAD); err != nil || !bytes.Equal(pt, interopPT) {
		t.Fatalf("stdlib failed to open package-sealed record: pt=%q err=%v", pt, err)
	}
}

// TestSealWithKeyRejectsBadSizes proves the deterministic entry points validate
// key and nonce lengths instead of feeding malformed input to the cipher.
//
// MUTATION THAT FAILS THIS: remove the len(key)/len(nonce) checks in
// newDeterministicAEAD; a 16-byte key would build an AES-128 cipher (no error)
// and a wrong-size nonce would reach gcm.Seal, so the ErrInvalidKeySize
// assertions would no longer hold.
func TestSealWithKeyRejectsBadSizes(t *testing.T) {
	if _, err := SealWithKey(interopKey[:16], interopNonce, nil, nil); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("expected ErrInvalidKeySize for 16-byte key, got %v", err)
	}
	if _, err := SealWithKey(interopKey, interopNonce[:8], nil, nil); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("expected ErrInvalidKeySize for 8-byte nonce, got %v", err)
	}
	if _, err := OpenWithKey(interopKey, interopNonce, nil, []byte{1, 2, 3}); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("expected ErrInvalidCiphertext for sub-tag ciphertext, got %v", err)
	}
}
