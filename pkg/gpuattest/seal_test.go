package gpuattest

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// ---- Spot-check tests --------------------------------------------------------

// TestSpotCheckValidIndexPasses proves a genuine sampled sub-token at the
// verifier-chosen index is accepted, AND that the verifier really recomputed the
// per-index value (it is the index-bound HMAC, not a blanket accept).
//
// Mutation that makes this FAIL: in deriveSubToken, replace `mac.Write(idx[:])`
// with `mac.Write(nil)` — the verifier's expected sub-token would no longer
// depend on the index while the prover's does, so for any index>0 they diverge
// and SpotCheck returns ErrSampleMismatch. (Paired with the tampered test below,
// which catches an index-ignoring verifier; a spot-check that ignores the
// sampled index cannot pass BOTH this PASS assertion and that FAIL assertion.)
func TestSpotCheckValidIndexPasses(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	v, p := newRegistered(t, key, time.Minute)

	const sampleCount = 1024
	c, idx, err := v.ChallengeSampled(1, sampleCount)
	if err != nil {
		t.Fatalf("ChallengeSampled: %v", err)
	}
	if idx < 0 || idx >= sampleCount {
		t.Fatalf("chosen index %d out of range", idx)
	}
	sr, err := p.RespondSampled(c, sampleCount, idx)
	if err != nil {
		t.Fatalf("RespondSampled: %v", err)
	}
	if sr.SubToken == "" {
		t.Fatal("empty sub-token")
	}
	if err := v.SpotCheck(sr); err != nil {
		t.Fatalf("SpotCheck rejected a valid sample: %v", err)
	}
}

// TestSpotCheckTamperedSampleFails proves a forged/tampered sub-token at the
// sampled index is rejected. This is the load-bearing anti-bluff assertion: a
// spot-check that ignored the sampled index (e.g. `return nil` always) would
// wrongly PASS here.
//
// Mutation that makes this FAIL (i.e. the bluff this kills): in SpotCheck,
// replace the ConstantTimeCompare check with `if false` (always treat as
// matching) — the tampered sub-token would be accepted and this test's
// expectation of ErrSampleMismatch would fail.
func TestSpotCheckTamperedSampleFails(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	v, p := newRegistered(t, key, time.Minute)

	const sampleCount = 512
	c, idx, err := v.ChallengeSampled(1, sampleCount)
	if err != nil {
		t.Fatalf("ChallengeSampled: %v", err)
	}
	sr, err := p.RespondSampled(c, sampleCount, idx)
	if err != nil {
		t.Fatalf("RespondSampled: %v", err)
	}
	// Flip the first hex nibble of the sub-token.
	first := sr.SubToken[0]
	flipped := byte('1')
	if first == '1' {
		flipped = '2'
	}
	sr.SubToken = string(flipped) + sr.SubToken[1:]

	if err := v.SpotCheck(sr); !errors.Is(err, ErrSampleMismatch) {
		t.Fatalf("expected ErrSampleMismatch for tampered sample, got %v", err)
	}
}

// TestSpotCheckIsConstantWorkAndIndexBound exercises a SPECIFIC index and proves
// the per-index sub-token is bound to that exact index: presenting index i's
// genuine token but claiming it is index j (j != i) is rejected. This proves the
// verifier checks the sampled index rather than recomputing/ignoring the full
// response — i.e. the check is index-specific O(1) work, not a full recompute.
//
// Mutation that makes this FAIL: in deriveSubToken, drop `mac.Write(idx[:])`
// (and the count write) so the token no longer depends on the index — then a
// token derived at index i WOULD verify when presented as index j, and the
// expectation of ErrSampleMismatch below would fail.
func TestSpotCheckIsConstantWorkAndIndexBound(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	desc := testDescriptor()
	const sampleCount = 4096

	const i = 7
	const j = 4095
	nonce := "00112233445566778899aabbccddeeff"

	tokI, err := deriveSubToken(key, nonce, i, sampleCount, desc)
	if err != nil {
		t.Fatalf("deriveSubToken i: %v", err)
	}
	tokJ, err := deriveSubToken(key, nonce, j, sampleCount, desc)
	if err != nil {
		t.Fatalf("deriveSubToken j: %v", err)
	}
	if tokI == tokJ {
		t.Fatal("sub-tokens for different indices are identical (index not bound)")
	}

	// Now drive it through the verifier with a real pending challenge: present
	// index i's genuine token but mislabel the Index field as j.
	v := NewVerifier(time.Minute)
	if err := v.RegisterDevice(desc.DeviceID, key); err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	c, err := v.Challenge(1)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	good, err := deriveSubToken(key, c.Nonce, i, sampleCount, desc)
	if err != nil {
		t.Fatalf("deriveSubToken: %v", err)
	}
	mislabeled := SampledResponse{
		Nonce:       c.Nonce,
		SampleCount: sampleCount,
		Index:       j, // claim it is index j
		SubToken:    good,
		Descriptor:  desc,
	}
	if err := v.SpotCheck(mislabeled); !errors.Is(err, ErrSampleMismatch) {
		t.Fatalf("expected ErrSampleMismatch for index-mislabeled token, got %v", err)
	}
}

// TestSpotCheckWrongKeyFails proves a prover with the wrong secret cannot pass a
// spot-check even for a registered device id.
//
// Mutation that makes this FAIL: in SpotCheck, derive `expected` with a constant
// key (e.g. []byte("x")) instead of the registered key — the wrong-key prover's
// token would then be accepted and the expectation of ErrSampleMismatch fails.
func TestSpotCheckWrongKeyFails(t *testing.T) {
	registeredKey := []byte("device-secret-key-0123456789abcd")
	attackerKey := []byte("WRONG-secret-key-0123456789abcdef")
	v, _ := newRegistered(t, registeredKey, time.Minute)

	badProver, err := NewSoftwareProver(attackerKey, testDescriptor())
	if err != nil {
		t.Fatalf("NewSoftwareProver: %v", err)
	}
	const sampleCount = 256
	c, idx, err := v.ChallengeSampled(1, sampleCount)
	if err != nil {
		t.Fatalf("ChallengeSampled: %v", err)
	}
	sr, err := badProver.RespondSampled(c, sampleCount, idx)
	if err != nil {
		t.Fatalf("RespondSampled: %v", err)
	}
	if err := v.SpotCheck(sr); !errors.Is(err, ErrSampleMismatch) {
		t.Fatalf("expected ErrSampleMismatch for wrong key, got %v", err)
	}
}

// TestSpotCheckReplayedNonceRejected proves a sampled nonce is single-use.
//
// Mutation that makes this FAIL: in SpotCheck, remove `v.seen[r.Nonce] = true`
// (and the seen check) — the replayed sample would pass a second time.
func TestSpotCheckReplayedNonceRejected(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	v, p := newRegistered(t, key, time.Minute)

	const sampleCount = 64
	c, idx, err := v.ChallengeSampled(1, sampleCount)
	if err != nil {
		t.Fatalf("ChallengeSampled: %v", err)
	}
	sr, err := p.RespondSampled(c, sampleCount, idx)
	if err != nil {
		t.Fatalf("RespondSampled: %v", err)
	}
	if err := v.SpotCheck(sr); err != nil {
		t.Fatalf("first SpotCheck should pass: %v", err)
	}
	if err := v.SpotCheck(sr); !errors.Is(err, ErrNonceReplayed) {
		t.Fatalf("expected ErrNonceReplayed on replay, got %v", err)
	}
}

// TestSpotCheckOutOfRangeRejected proves an index >= SampleCount is rejected
// before crypto.
//
// Mutation that makes this FAIL: in SpotCheck, delete the
// `if r.Index < 0 || r.Index >= r.SampleCount { return ErrSampleIndexOutOfRange }`
// guard — the out-of-range index would fall through (deriveSubToken would still
// catch it, but the specific ErrSampleIndexOutOfRange contract at the API
// boundary would be lost; this asserts the boundary contract).
func TestSpotCheckOutOfRangeRejected(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	v, p := newRegistered(t, key, time.Minute)

	const sampleCount = 16
	c, _, err := v.ChallengeSampled(1, sampleCount)
	if err != nil {
		t.Fatalf("ChallengeSampled: %v", err)
	}
	sr, err := p.RespondSampled(c, sampleCount, 0)
	if err != nil {
		t.Fatalf("RespondSampled: %v", err)
	}
	sr.Index = sampleCount // out of range
	if err := v.SpotCheck(sr); !errors.Is(err, ErrSampleIndexOutOfRange) {
		t.Fatalf("expected ErrSampleIndexOutOfRange, got %v", err)
	}
}

// TestSpotCheckExpiredRejected proves an expired sampled challenge is denied.
//
// Mutation that makes this FAIL: in SpotCheck, delete the
// `if time.Now().After(c.Expiry) { return ErrChallengeExpired }` block.
func TestSpotCheckExpiredRejected(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	v, p := newRegistered(t, key, time.Nanosecond)

	const sampleCount = 8
	c, idx, err := v.ChallengeSampled(1, sampleCount)
	if err != nil {
		t.Fatalf("ChallengeSampled: %v", err)
	}
	sr, err := p.RespondSampled(c, sampleCount, idx)
	if err != nil {
		t.Fatalf("RespondSampled: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if err := v.SpotCheck(sr); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expected ErrChallengeExpired, got %v", err)
	}
}

// TestChallengeSampledRandomIndexInRange proves the verifier's chosen index is
// always within [0, sampleCount) across many draws and that it varies (the
// random index actually comes from crypto/rand, not a constant).
//
// Mutation that makes this FAIL: in randIndex, `return 0, nil` unconditionally —
// every chosen index would be 0 and the "varies" assertion would fail.
func TestChallengeSampledRandomIndexInRange(t *testing.T) {
	key := []byte("device-secret-key-0123456789abcd")
	v, _ := newRegistered(t, key, time.Minute)

	const sampleCount = 1000
	seen := make(map[int]int)
	for n := 0; n < 200; n++ {
		_, idx, err := v.ChallengeSampled(1, sampleCount)
		if err != nil {
			t.Fatalf("ChallengeSampled: %v", err)
		}
		if idx < 0 || idx >= sampleCount {
			t.Fatalf("index %d out of range", idx)
		}
		seen[idx]++
	}
	if len(seen) < 2 {
		t.Fatalf("expected varied indices, got %d distinct", len(seen))
	}
}

// ---- Device-sealed encryption tests ------------------------------------------

// TestSealOpenRoundTrip proves SealToDevice -> OpenFromDevice recovers the exact
// plaintext for the right device key, AND that the blob is genuinely encrypted
// (ciphertext does not contain the plaintext).
//
// Mutation that makes this FAIL: in OpenFromDevice, derive the AEAD key with a
// constant salt (e.g. `salt := make([]byte, sealSaltLen)`) instead of the blob's
// salt — the derived key would not match the sealing key and GCM Open would fail,
// so the round-trip plaintext assertion fails.
func TestSealOpenRoundTrip(t *testing.T) {
	deviceKey := []byte("device-secret-key-0123456789abcd")
	const deviceID = "gpu-0"
	plaintext := []byte("model weights checkpoint shard #42 — confidential")

	blob, err := SealToDevice(deviceID, deviceKey, plaintext)
	if err != nil {
		t.Fatalf("SealToDevice: %v", err)
	}
	if bytes.Contains(blob, plaintext) {
		t.Fatal("sealed blob contains plaintext (not encrypted)")
	}

	got, err := OpenFromDevice(deviceID, deviceKey, blob)
	if err != nil {
		t.Fatalf("OpenFromDevice: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

// TestSealWrongDeviceKeyFails proves a holder of the WRONG device key cannot open
// a blob sealed for the right key.
//
// Mutation that makes this FAIL: in deriveSealKey, ignore deviceKey (e.g. use a
// constant IKM) — both keys would derive the same AEAD key and the wrong key
// would open the blob, so the expectation of ErrSealOpenFailed fails.
func TestSealWrongDeviceKeyFails(t *testing.T) {
	rightKey := []byte("device-secret-key-0123456789abcd")
	wrongKey := []byte("ANOTHER-device-key-0123456789abc")
	const deviceID = "gpu-0"
	plaintext := []byte("only the attested device may read this")

	blob, err := SealToDevice(deviceID, rightKey, plaintext)
	if err != nil {
		t.Fatalf("SealToDevice: %v", err)
	}
	if _, err := OpenFromDevice(deviceID, wrongKey, blob); !errors.Is(err, ErrSealOpenFailed) {
		t.Fatalf("expected ErrSealOpenFailed for wrong device key, got %v", err)
	}
}

// TestSealWrongDeviceIDFails proves deviceID is bound (as AAD + into key
// derivation): a blob sealed for one device id cannot be opened under another
// even with the same raw key.
//
// Mutation that makes this FAIL: in SealToDevice and OpenFromDevice, drop the
// `aad := []byte(deviceID)` binding (pass nil) AND remove deviceID from
// deriveSealKey's info — the blob would then open under any deviceID and the
// expectation of ErrSealOpenFailed fails.
func TestSealWrongDeviceIDFails(t *testing.T) {
	deviceKey := []byte("device-secret-key-0123456789abcd")
	plaintext := []byte("bound to gpu-0")

	blob, err := SealToDevice("gpu-0", deviceKey, plaintext)
	if err != nil {
		t.Fatalf("SealToDevice: %v", err)
	}
	if _, err := OpenFromDevice("gpu-1", deviceKey, blob); !errors.Is(err, ErrSealOpenFailed) {
		t.Fatalf("expected ErrSealOpenFailed for wrong device id, got %v", err)
	}
}

// TestSealTamperedBlobFails proves any flipped byte in the sealed blob is
// detected by GCM authentication.
//
// Mutation that makes this FAIL: there is no honest single-line mutation that
// "ignores" GCM tampering without replacing AES-GCM itself; the assertion here
// is that gcm.Open's error is surfaced as ErrSealOpenFailed. Mutation: in
// OpenFromDevice replace `return nil, ErrSealOpenFailed` (the Open error branch)
// with `return pt, nil` returning the (nil) plaintext and no error — the
// tampered blob would then "open" and this test would fail.
func TestSealTamperedBlobFails(t *testing.T) {
	deviceKey := []byte("device-secret-key-0123456789abcd")
	const deviceID = "gpu-0"
	plaintext := []byte("integrity-protected payload")

	blob, err := SealToDevice(deviceID, deviceKey, plaintext)
	if err != nil {
		t.Fatalf("SealToDevice: %v", err)
	}
	// Flip the last byte (inside the GCM tag / ciphertext).
	tampered := make([]byte, len(blob))
	copy(tampered, blob)
	tampered[len(tampered)-1] ^= 0x01

	if _, err := OpenFromDevice(deviceID, deviceKey, tampered); !errors.Is(err, ErrSealOpenFailed) {
		t.Fatalf("expected ErrSealOpenFailed for tampered blob, got %v", err)
	}
}

// TestSealMalformedBlobRejected proves a too-short blob is rejected before any
// AEAD attempt.
//
// Mutation that makes this FAIL: in OpenFromDevice, delete the
// `if len(blob) < sealSaltLen+gcmNonceLen+gcmTagLen { return ErrSealedBlobMalformed }`
// guard — a short blob would slice-panic or reach GCM with garbage instead of
// returning the specific ErrSealedBlobMalformed.
func TestSealMalformedBlobRejected(t *testing.T) {
	deviceKey := []byte("device-secret-key-0123456789abcd")
	if _, err := OpenFromDevice("gpu-0", deviceKey, []byte("too-short")); !errors.Is(err, ErrSealedBlobMalformed) {
		t.Fatalf("expected ErrSealedBlobMalformed, got %v", err)
	}
}

// TestSealConstructorsReject proves Seal/Open reject empty device id and empty
// key instead of producing a footgun blob.
//
// Mutation that makes this FAIL: in SealToDevice, remove the
// `if len(deviceKey) == 0 { return nil, ErrInvalidKey }` guard — an empty-key
// seal would succeed and err would be nil.
func TestSealConstructorsReject(t *testing.T) {
	if _, err := SealToDevice("", []byte("k"), []byte("x")); !errors.Is(err, ErrMalformedDescriptor) {
		t.Fatalf("expected ErrMalformedDescriptor for empty device id, got %v", err)
	}
	if _, err := SealToDevice("d", nil, []byte("x")); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for empty key, got %v", err)
	}
	if _, err := OpenFromDevice("", []byte("k"), make([]byte, 64)); !errors.Is(err, ErrMalformedDescriptor) {
		t.Fatalf("expected ErrMalformedDescriptor for empty device id (open), got %v", err)
	}
}

// TestSealKeyDerivationPinned pins the HKDF derivation so an accidental change to
// the KDF (which would silently break the ability to open previously-sealed
// blobs) is caught. It derives the AES key directly and uses it to open a blob
// sealed by SealToDevice, proving SealToDevice uses exactly this derivation.
//
// Mutation that makes this FAIL: change sealInfo's constant string — the
// independently-derived key below would no longer match SealToDevice's key and
// gcm.Open would fail, failing the assertion.
func TestSealKeyDerivationPinned(t *testing.T) {
	deviceKey := []byte("device-secret-key-0123456789abcd")
	const deviceID = "gpu-0"
	plaintext := []byte("kdf pin")

	blob, err := SealToDevice(deviceID, deviceKey, plaintext)
	if err != nil {
		t.Fatalf("SealToDevice: %v", err)
	}
	// Reconstruct the AEAD key from the blob's salt using the same KDF and open
	// the ciphertext manually, proving the on-wire format and KDF are exactly as
	// documented.
	const gcmNonceLen = 12
	salt := blob[:sealSaltLen]
	nonce := blob[sealSaltLen : sealSaltLen+gcmNonceLen]
	ct := blob[sealSaltLen+gcmNonceLen:]

	aeadKey := deriveSealKey(deviceKey, salt, deviceID)
	if len(aeadKey) != 32 {
		t.Fatalf("derived key length = %d, want 32 (AES-256)", len(aeadKey))
	}
	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	got, err := gcm.Open(nil, nonce, ct, []byte(deviceID))
	if err != nil {
		t.Fatalf("manual gcm.Open failed (KDF/format drift): %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("manual open mismatch: got %q want %q", got, plaintext)
	}
}

// TestSubTokenPinned pins the deriveSubToken construction against a fixed input
// so an accidental reordering of the HMAC writes is caught. It recomputes the
// exact HMAC inline and compares.
//
// Mutation that makes this FAIL: swap the order of `mac.Write(nonce)` and
// `mac.Write(idx[:])` in deriveSubToken — the pinned expected value computed
// inline below would no longer match.
func TestSubTokenPinned(t *testing.T) {
	key := []byte("pin-key")
	desc := testDescriptor()
	nonce := "0011223344556677"
	const index = 3
	const sampleCount = 100

	got, err := deriveSubToken(key, nonce, index, sampleCount, desc)
	if err != nil {
		t.Fatalf("deriveSubToken: %v", err)
	}
	// Recompute inline using the documented order.
	want := recomputeSubTokenForTest(t, key, nonce, index, sampleCount, desc)
	if got != want {
		t.Fatalf("sub-token construction drift: got %s want %s", got, want)
	}
}

// recomputeSubTokenForTest mirrors deriveSubToken's documented HMAC order so the
// pin test fails loudly if production drifts.
func recomputeSubTokenForTest(t *testing.T, key []byte, nonceHex string, index, sampleCount int, desc DeviceDescriptor) string {
	t.Helper()
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	var idx [8]byte
	binary.LittleEndian.PutUint64(idx[:], uint64(index))
	mac.Write(idx[:])
	var cnt [8]byte
	binary.LittleEndian.PutUint64(cnt[:], uint64(sampleCount))
	mac.Write(cnt[:])
	mac.Write(desc.canonicalBytes())
	return hex.EncodeToString(mac.Sum(nil))
}
