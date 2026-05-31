// Package gpuattest implements clean-room proof-of-GPU attestation
// (challenge/response + device fingerprinting) for Helix Cluster OS.
//
// It is a software attestation scheme modelled on the GraVal ("Graphics card
// Validation") design (see docs/research/phase_08C/dossiers/graval.md): a
// trusted Verifier issues a single-use Challenge to an untrusted Prover; the
// Prover holds a per-device secret key and a device descriptor and computes a
// Response derived deterministically from the challenge nonce. The Verifier
// recomputes the expected value for the registered device key and admits the
// device only if the response matches, the challenge has not expired, the
// nonce has not been replayed, and the descriptor is well-formed.
//
// HONEST SCOPE NOTE: This package does NOT execute GPU kernels. The cryptographic
// binding here is computed in software (HMAC-SHA256 over the nonce keyed by the
// device key, with an optional iterated memory-ish hash to model proof-of-work
// difficulty). It proves possession of the device *secret*, not physical
// possession of the GPU silicon. Genuine hardware-rooted attestation (a real
// CUDA/OpenCL GraVal kernel whose output is infeasible to produce without the
// exact device, or a TEE quote) requires hardware and MUST implement the Prover
// interface in its place. The SoftwareProver below is the reference
// implementation against which any hardware prover is validated.
package gpuattest

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrChallengeExpired is returned when a challenge is verified after its
	// expiry time.
	ErrChallengeExpired = errors.New("gpuattest: challenge expired")
	// ErrNonceReplayed is returned when a challenge nonce is presented to the
	// same Verifier more than once.
	ErrNonceReplayed = errors.New("gpuattest: challenge nonce replayed")
	// ErrUnknownDevice is returned when no device key is registered for the
	// device id in a response.
	ErrUnknownDevice = errors.New("gpuattest: unknown device")
	// ErrResponseMismatch is returned when the response does not match the
	// value expected for the registered device key (tampered response, wrong
	// key, or a spoofed device).
	ErrResponseMismatch = errors.New("gpuattest: response does not match expected attestation")
	// ErrMalformedDescriptor is returned when the device descriptor in a
	// response is not well-formed.
	ErrMalformedDescriptor = errors.New("gpuattest: malformed device descriptor")
	// ErrInvalidChallenge is returned when a challenge is structurally invalid
	// (empty nonce, expiry before issue, or non-positive difficulty).
	ErrInvalidChallenge = errors.New("gpuattest: invalid challenge")
	// ErrInvalidKey is returned when a device key is empty.
	ErrInvalidKey = errors.New("gpuattest: invalid device key")
)

// nonceLen is the length in bytes of a challenge nonce.
const nonceLen = 32

// DeviceDescriptor is the hardware profile a Prover claims. It is bound into
// the attestation so that a response is only valid for the exact descriptor the
// Prover presented.
type DeviceDescriptor struct {
	DeviceID string `json:"device_id"`
	Vendor   string `json:"vendor"`
	Model    string `json:"model"`
	MemoryMB uint64 `json:"memory_mb"`
}

// wellFormed reports whether the descriptor has the minimum required fields.
func (d DeviceDescriptor) wellFormed() bool {
	return d.DeviceID != "" && d.Vendor != "" && d.Model != "" && d.MemoryMB > 0
}

// canonicalBytes returns a deterministic byte encoding of the descriptor used
// as additional authenticated context when deriving the attestation. The
// length prefixes prevent field-boundary ambiguity (e.g. {"ab","c"} vs
// {"a","bc"}).
func (d DeviceDescriptor) canonicalBytes() []byte {
	var b []byte
	appendField := func(s string) {
		var lp [8]byte
		n := uint64(len(s))
		for i := 0; i < 8; i++ {
			lp[i] = byte(n >> (8 * i))
		}
		b = append(b, lp[:]...)
		b = append(b, s...)
	}
	appendField(d.DeviceID)
	appendField(d.Vendor)
	appendField(d.Model)
	var mem [8]byte
	for i := 0; i < 8; i++ {
		mem[i] = byte(d.MemoryMB >> (8 * i))
	}
	b = append(b, mem[:]...)
	return b
}

// Challenge is a single-use attestation challenge issued by a Verifier.
type Challenge struct {
	// Nonce is a fresh random value (hex-encoded) the Prover must bind into
	// its response.
	Nonce string `json:"nonce"`
	// IssuedAt is when the challenge was created.
	IssuedAt time.Time `json:"issued_at"`
	// Expiry is the instant after which the challenge is no longer valid.
	Expiry time.Time `json:"expiry"`
	// Difficulty controls how many iterations of the memory-ish hash the Prover
	// must perform. A value <= 1 means a single HMAC (no iterated work).
	Difficulty int `json:"difficulty"`
}

// valid reports whether the challenge is structurally sound.
func (c Challenge) valid() bool {
	return c.Nonce != "" && !c.Expiry.Before(c.IssuedAt) && c.Difficulty >= 1
}

// Response is what a Prover returns for a Challenge.
type Response struct {
	// Nonce echoes the challenge nonce the response was computed over.
	Nonce string `json:"nonce"`
	// Attestation is the hex-encoded derived proof value.
	Attestation string `json:"attestation"`
	// Descriptor is the device profile the proof is bound to.
	Descriptor DeviceDescriptor `json:"descriptor"`
}

// Prover computes attestation responses for challenges. The SoftwareProver in
// this package is the reference implementation; a real GPU prover (CUDA/OpenCL
// GraVal kernel, or a TEE-backed prover) would implement this same interface
// and is validated against the SoftwareProver's observable behaviour.
type Prover interface {
	// Descriptor returns the device profile this prover attests to.
	Descriptor() DeviceDescriptor
	// Respond computes a Response for the given Challenge.
	Respond(c Challenge) (Response, error)
}

// deriveAttestation is the shared, deterministic attestation function used by
// both the SoftwareProver (to compute) and the Verifier (to check). It is
// HMAC-SHA256(key, nonce || descriptor); for difficulty > 1 the result is fed
// back through HMAC iteratively to model proof-of-work cost. It is the single
// source of truth so prover and verifier can never diverge.
func deriveAttestation(key []byte, nonceHex string, desc DeviceDescriptor, difficulty int) (string, error) {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", fmt.Errorf("gpuattest: invalid nonce hex: %w", err)
	}
	if difficulty < 1 {
		difficulty = 1
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write(desc.canonicalBytes())
	acc := mac.Sum(nil)
	for i := 1; i < difficulty; i++ {
		m := hmac.New(sha256.New, key)
		m.Write(acc)
		acc = m.Sum(nil)
	}
	return hex.EncodeToString(acc), nil
}

// SoftwareProver is the clean-room reference Prover. It holds a per-device
// secret key and descriptor and derives responses in software.
type SoftwareProver struct {
	key  []byte
	desc DeviceDescriptor
}

// NewSoftwareProver constructs a SoftwareProver. The key is the per-device
// secret shared (out of band) with the Verifier at registration; descriptor
// must be well-formed.
func NewSoftwareProver(key []byte, desc DeviceDescriptor) (*SoftwareProver, error) {
	if len(key) == 0 {
		return nil, ErrInvalidKey
	}
	if !desc.wellFormed() {
		return nil, ErrMalformedDescriptor
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &SoftwareProver{key: k, desc: desc}, nil
}

// Descriptor returns the prover's device profile.
func (p *SoftwareProver) Descriptor() DeviceDescriptor {
	return p.desc
}

// Respond computes the attestation for the challenge.
func (p *SoftwareProver) Respond(c Challenge) (Response, error) {
	if !c.valid() {
		return Response{}, ErrInvalidChallenge
	}
	att, err := deriveAttestation(p.key, c.Nonce, p.desc, c.Difficulty)
	if err != nil {
		return Response{}, err
	}
	return Response{
		Nonce:       c.Nonce,
		Attestation: att,
		Descriptor:  p.desc,
	}, nil
}

// Verifier issues challenges and verifies responses against a registry of
// per-device keys. It enforces single-use nonces. A Verifier is safe for
// concurrent use.
type Verifier struct {
	mu       sync.Mutex
	keys     map[string][]byte // deviceID -> key
	seen     map[string]bool   // nonce -> consumed
	pending  map[string]Challenge
	defaultD time.Duration
}

// NewVerifier constructs a Verifier. validity is the lifetime applied to
// challenges created by Challenge; if validity <= 0 a default of 30s is used.
func NewVerifier(validity time.Duration) *Verifier {
	if validity <= 0 {
		validity = 30 * time.Second
	}
	return &Verifier{
		keys:     make(map[string][]byte),
		seen:     make(map[string]bool),
		pending:  make(map[string]Challenge),
		defaultD: validity,
	}
}

// RegisterDevice records the per-device secret key the Verifier will use to
// recompute expected attestations for deviceID. The key is copied.
func (v *Verifier) RegisterDevice(deviceID string, key []byte) error {
	if deviceID == "" {
		return ErrMalformedDescriptor
	}
	if len(key) == 0 {
		return ErrInvalidKey
	}
	k := make([]byte, len(key))
	copy(k, key)
	v.mu.Lock()
	v.keys[deviceID] = k
	v.mu.Unlock()
	return nil
}

// Challenge creates a fresh single-use challenge with the given difficulty
// (values < 1 are clamped to 1). The challenge is remembered as pending so
// Verify can confirm the response answers a challenge this Verifier issued.
func (v *Verifier) Challenge(difficulty int) (Challenge, error) {
	if difficulty < 1 {
		difficulty = 1
	}
	raw := make([]byte, nonceLen)
	if _, err := rand.Read(raw); err != nil {
		return Challenge{}, fmt.Errorf("gpuattest: failed to read nonce: %w", err)
	}
	now := time.Now()
	c := Challenge{
		Nonce:      hex.EncodeToString(raw),
		IssuedAt:   now,
		Expiry:     now.Add(v.defaultD),
		Difficulty: difficulty,
	}
	v.mu.Lock()
	v.pending[c.Nonce] = c
	v.mu.Unlock()
	return c, nil
}

// Verify checks a response against the challenge that produced its nonce. It
// returns nil only if: the nonce corresponds to a pending challenge issued by
// this Verifier, the challenge has not expired, the nonce has not been
// consumed before (single-use), the descriptor is well-formed, the device is
// registered, and the attestation matches the value recomputed from the
// registered device key. On any successful or rejected-but-matched-pending
// verification the nonce is consumed to prevent replay.
func (v *Verifier) Verify(r Response) error {
	if !r.Descriptor.wellFormed() {
		return ErrMalformedDescriptor
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
	// The nonce is now consumed regardless of outcome: a challenge is
	// single-use, so even a failed attempt burns it (prevents grinding a
	// reused nonce after a near-miss).
	v.seen[r.Nonce] = true
	delete(v.pending, r.Nonce)

	if time.Now().After(c.Expiry) {
		return ErrChallengeExpired
	}

	key, ok := v.keys[r.Descriptor.DeviceID]
	if !ok {
		return ErrUnknownDevice
	}

	expected, err := deriveAttestation(key, c.Nonce, r.Descriptor, c.Difficulty)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(r.Attestation)) != 1 {
		return ErrResponseMismatch
	}
	return nil
}
