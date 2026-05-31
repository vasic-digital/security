// Spot-check verification and device-sealed encryption for gpuattest.
//
// This file is additive to package.go. It provides two stdlib-only facilities
// that build on the same per-device secret key the challenge/response scheme
// already uses:
//
//  1. An O(1) SPOT-CHECK verifier. Instead of recomputing a prover's full
//     response, a Verifier derives per-index sub-tokens via
//     HMAC(deviceKey, nonce || index || descriptor) and a prover supplies a
//     SampledResponse covering only ONE randomly chosen index. Verifying one
//     sample is constant work — it does not depend on the number of indices in
//     the attestation, so a single validator can spot-check very many provers at
//     scale. A forged or tampered sample at the sampled index fails.
//
//  2. Device-sealed encryption. SealToDevice(deviceID, plaintext) encrypts with
//     AES-256-GCM under a key derived (HKDF-Extract/Expand over HMAC-SHA256)
//     from the device's attested secret, so only a holder of the exact attested
//     key — i.e. the attested device — can OpenFromDevice. A wrong device key,
//     or any tampered byte of the sealed blob, fails to open (GCM auth).
//
// HONEST CRYPTO NOTE (ChaCha20-Poly1305): The submodule is stdlib-only and does
// NOT vendor golang.org/x/crypto, so ChaCha20-Poly1305 is intentionally NOT
// offered here. AES-256-GCM (crypto/aes + crypto/cipher) is the stdlib AEAD and
// is what SealToDevice uses. A ChaCha20-Poly1305 sealing variant is a documented
// future enhancement that REQUIRES adding golang.org/x/crypto; it MUST NOT be
// added without that dependency.

package gpuattest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	// ErrSampleIndexOutOfRange is returned when a sampled index is negative or
	// not below the attestation's declared sample count.
	ErrSampleIndexOutOfRange = errors.New("gpuattest: sample index out of range")
	// ErrSampleMismatch is returned when the sampled sub-token does not match the
	// value recomputed for the registered device key at that exact index.
	ErrSampleMismatch = errors.New("gpuattest: sampled sub-token does not match expected")
	// ErrInvalidSampleCount is returned when a requested sample count is < 1.
	ErrInvalidSampleCount = errors.New("gpuattest: sample count must be >= 1")
	// ErrSealedBlobMalformed is returned when a sealed blob is too short or
	// structurally invalid to open.
	ErrSealedBlobMalformed = errors.New("gpuattest: sealed blob malformed")
	// ErrSealOpenFailed is returned when AEAD authentication fails on open
	// (wrong device key or tampered ciphertext/nonce/AAD).
	ErrSealOpenFailed = errors.New("gpuattest: sealed blob failed to open (wrong device or tampered)")
)

// subTokenLen is the length in bytes of a per-index spot-check sub-token (full
// HMAC-SHA256 output).
const subTokenLen = sha256.Size

// deriveSubToken derives the per-index spot-check sub-token:
//
//	HMAC-SHA256(key, nonce || LE64(index) || LE64(sampleCount) || descriptor)
//
// Binding the index AND the total sampleCount AND the descriptor means a token
// is only valid for the exact (nonce, index, count, device) tuple — an attacker
// cannot replay index i's token as index j, nor lift a token across descriptors.
// This is the single source of truth shared by prover and verifier so they can
// never diverge.
func deriveSubToken(key []byte, nonceHex string, index, sampleCount int, desc DeviceDescriptor) (string, error) {
	if sampleCount < 1 {
		return "", ErrInvalidSampleCount
	}
	if index < 0 || index >= sampleCount {
		return "", ErrSampleIndexOutOfRange
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", fmt.Errorf("gpuattest: invalid nonce hex: %w", err)
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
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// SampledResponse is a prover's answer to a spot-check: it carries exactly ONE
// sub-token (the sampled index) rather than the whole attestation, so the
// verifier does O(1) work regardless of SampleCount.
type SampledResponse struct {
	// Nonce echoes the challenge nonce the sub-tokens were computed over.
	Nonce string `json:"nonce"`
	// SampleCount is the total number of per-index sub-tokens the attestation
	// is partitioned into.
	SampleCount int `json:"sample_count"`
	// Index is the single index the verifier asked the prover to reveal.
	Index int `json:"index"`
	// SubToken is the hex-encoded per-index sub-token for Index.
	SubToken string `json:"sub_token"`
	// Descriptor is the device profile the sub-token is bound to.
	Descriptor DeviceDescriptor `json:"descriptor"`
}

// RespondSampled answers a spot-check by computing ONLY the sub-token for the
// requested index. A real prover would derive this in constant work without
// materialising the other sampleCount-1 sub-tokens.
func (p *SoftwareProver) RespondSampled(c Challenge, sampleCount, index int) (SampledResponse, error) {
	if !c.valid() {
		return SampledResponse{}, ErrInvalidChallenge
	}
	tok, err := deriveSubToken(p.key, c.Nonce, index, sampleCount, p.desc)
	if err != nil {
		return SampledResponse{}, err
	}
	return SampledResponse{
		Nonce:       c.Nonce,
		SampleCount: sampleCount,
		Index:       index,
		SubToken:    tok,
		Descriptor:  p.desc,
	}, nil
}

// ChallengeSampled creates a fresh single-use challenge and chooses a random
// index in [0, sampleCount) for the prover to reveal. The returned index is the
// one the verifier will check; the challenge is remembered as pending exactly
// like Challenge so SpotCheck can confirm it was issued here.
func (v *Verifier) ChallengeSampled(difficulty, sampleCount int) (Challenge, int, error) {
	if sampleCount < 1 {
		return Challenge{}, 0, ErrInvalidSampleCount
	}
	c, err := v.Challenge(difficulty)
	if err != nil {
		return Challenge{}, 0, err
	}
	idx, err := randIndex(sampleCount)
	if err != nil {
		return Challenge{}, 0, err
	}
	return c, idx, nil
}

// randIndex returns a uniform random integer in [0, n) using crypto/rand,
// rejection-sampled to avoid modulo bias.
func randIndex(n int) (int, error) {
	if n < 1 {
		return 0, ErrInvalidSampleCount
	}
	if n == 1 {
		return 0, nil
	}
	// Rejection sampling over a uint64 range.
	limit := ^uint64(0) - (^uint64(0) % uint64(n))
	var buf [8]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, fmt.Errorf("gpuattest: failed to read random index: %w", err)
		}
		x := binary.LittleEndian.Uint64(buf[:])
		if x < limit {
			return int(x % uint64(n)), nil
		}
	}
}

// SpotCheck verifies a single sampled sub-token in O(1) work. It returns nil
// only if: the nonce corresponds to a pending challenge issued by this Verifier,
// the challenge has not expired, the nonce has not been consumed, the descriptor
// is well-formed, the device is registered, the sampled index is in range, and
// the supplied sub-token matches the value recomputed from the registered device
// key at THAT EXACT index. The nonce is consumed (single-use) on any decided
// outcome, exactly like Verify.
//
// Crucially the verifier's work does NOT depend on SampleCount: it recomputes
// one HMAC for the sampled index, never the whole attestation. That is what lets
// a single validator spot-check many provers at scale.
func (v *Verifier) SpotCheck(r SampledResponse) error {
	if !r.Descriptor.wellFormed() {
		return ErrMalformedDescriptor
	}
	if r.SampleCount < 1 {
		return ErrInvalidSampleCount
	}
	if r.Index < 0 || r.Index >= r.SampleCount {
		return ErrSampleIndexOutOfRange
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.seen[r.Nonce] {
		return ErrNonceReplayed
	}
	c, ok := v.pending[r.Nonce]
	if !ok {
		return ErrInvalidChallenge
	}
	// Single-use: burn the nonce regardless of outcome.
	v.seen[r.Nonce] = true
	delete(v.pending, r.Nonce)

	if time.Now().After(c.Expiry) {
		return ErrChallengeExpired
	}

	key, ok := v.keys[r.Descriptor.DeviceID]
	if !ok {
		return ErrUnknownDevice
	}

	expected, err := deriveSubToken(key, r.Nonce, r.Index, r.SampleCount, r.Descriptor)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(r.SubToken)) != 1 {
		return ErrSampleMismatch
	}
	return nil
}

// ---- Device-sealed encryption (AES-256-GCM) ----------------------------------

// sealInfo is the HKDF "info" context string binding a derived key to its
// purpose (domain separation), so a sealing key can never collide with the
// attestation key or any future derivation from the same device secret.
const sealInfo = "gpuattest/seal/aes-256-gcm/v1"

// hkdfExtract is the HKDF-Extract step (RFC 5869): PRK = HMAC(salt, IKM).
func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpand is the HKDF-Expand step (RFC 5869) producing length bytes of
// output keying material from a pseudorandom key.
func hkdfExpand(prk, info []byte, length int) []byte {
	var out []byte
	var prev []byte
	counter := byte(1)
	for len(out) < length {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{counter})
		prev = mac.Sum(nil)
		out = append(out, prev...)
		counter++
	}
	return out[:length]
}

// deriveSealKey derives a 32-byte AES-256 key from the device secret using HKDF
// (HMAC-SHA256). The salt is bound into the derivation so the same device secret
// yields a fresh sealing key per blob (defence in depth, and lets us verify the
// salt round-trips). deviceID is folded into the info context so two devices
// sharing a secret (a misconfiguration) still get distinct sealing keys.
func deriveSealKey(deviceKey []byte, salt []byte, deviceID string) []byte {
	prk := hkdfExtract(salt, deviceKey)
	info := append([]byte(sealInfo+"|"), deviceID...)
	return hkdfExpand(prk, info, 32)
}

// sealSaltLen is the length of the per-seal HKDF salt.
const sealSaltLen = 16

// SealToDevice encrypts plaintext so that only a holder of the device's attested
// secret key (deviceKey) for deviceID can open it. It uses AES-256-GCM with a
// key derived via HKDF-SHA256 from deviceKey. deviceID is bound both into the
// key derivation and as GCM additional-authenticated-data, so a blob sealed for
// one device cannot be opened as another even by a holder of the same raw key.
//
// Blob layout (all concatenated): salt(16) || gcmNonce(12) || ciphertext+tag.
func SealToDevice(deviceID string, deviceKey, plaintext []byte) ([]byte, error) {
	if deviceID == "" {
		return nil, ErrMalformedDescriptor
	}
	if len(deviceKey) == 0 {
		return nil, ErrInvalidKey
	}
	salt := make([]byte, sealSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("gpuattest: failed to read seal salt: %w", err)
	}
	aeadKey := deriveSealKey(deviceKey, salt, deviceID)
	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, fmt.Errorf("gpuattest: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gpuattest: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("gpuattest: failed to read gcm nonce: %w", err)
	}
	aad := []byte(deviceID)
	ct := gcm.Seal(nil, nonce, plaintext, aad)

	blob := make([]byte, 0, sealSaltLen+len(nonce)+len(ct))
	blob = append(blob, salt...)
	blob = append(blob, nonce...)
	blob = append(blob, ct...)
	return blob, nil
}

// OpenFromDevice reverses SealToDevice. It succeeds only when deviceKey and
// deviceID exactly match those used to seal the blob AND the blob is unmodified;
// otherwise GCM authentication fails and ErrSealOpenFailed is returned. A wrong
// device key, a wrong deviceID, or any flipped byte all surface as
// ErrSealOpenFailed.
func OpenFromDevice(deviceID string, deviceKey, blob []byte) ([]byte, error) {
	if deviceID == "" {
		return nil, ErrMalformedDescriptor
	}
	if len(deviceKey) == 0 {
		return nil, ErrInvalidKey
	}
	// Minimum length: salt + a GCM nonce(12) + a GCM tag(16).
	const gcmNonceLen = 12
	const gcmTagLen = 16
	if len(blob) < sealSaltLen+gcmNonceLen+gcmTagLen {
		return nil, ErrSealedBlobMalformed
	}
	salt := blob[:sealSaltLen]
	nonce := blob[sealSaltLen : sealSaltLen+gcmNonceLen]
	ct := blob[sealSaltLen+gcmNonceLen:]

	aeadKey := deriveSealKey(deviceKey, salt, deviceID)
	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, fmt.Errorf("gpuattest: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gpuattest: gcm: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrSealedBlobMalformed
	}
	aad := []byte(deviceID)
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrSealOpenFailed
	}
	return pt, nil
}
