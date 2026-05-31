// Package attestation provides clean-room TEE (Trusted Execution Environment)
// attestation document construction and verification for Helix Cluster OS.
//
// The model is inspired by confidential-compute attestation flows such as Intel
// TDX quotes and NVIDIA confidential-GPU attestation reports ("sek8s" concept):
// a workload running inside a TEE produces a signed document binding a set of
// measurements (PCR-like register values) and a verifier-supplied nonce, which a
// relying party then verifies against a trusted root key and a measurement
// policy before releasing secrets or admitting the node.
//
// # Hardware trust is OUT OF SCOPE but INTERFACED
//
// This package ships a SOFTWARE reference [Attester] that signs documents with
// crypto/ed25519. It is NOT rooted in real hardware: a software signer cannot
// prove that the measurements were produced by a genuine TEE — that requires a
// hardware-rooted quote (TDX SGX-quote / NVIDIA GPU attestation report) whose
// signing key chains to a vendor certificate authority. The software Attester
// STANDS IN for such a quote so that the surrounding verification, policy and
// freshness logic can be exercised with real cryptography.
//
// To plug in genuine hardware, implement [QuoteSigner] (and supply a trusted
// root public key to the [Verifier]) backed by a real quote-generation library;
// the document format, canonical serialization, policy evaluation and freshness
// checks in this package remain unchanged. See [QuoteSigner] for the seam.
package attestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Sentinel errors returned by the verifier. Callers may use errors.Is to branch
// on the specific failure reason.
var (
	// ErrSignatureInvalid means the document signature did not verify against
	// the trusted root public key.
	ErrSignatureInvalid = errors.New("attestation: signature invalid")
	// ErrUntrustedSigner means the document's embedded signer key does not match
	// the verifier's trusted root key.
	ErrUntrustedSigner = errors.New("attestation: untrusted signer key")
	// ErrNonceMismatch means the document nonce did not equal the expected nonce.
	ErrNonceMismatch = errors.New("attestation: nonce mismatch")
	// ErrExpired means the document is older than the permitted freshness window
	// or carries an explicit expiry that has passed.
	ErrExpired = errors.New("attestation: document expired")
	// ErrIssuedInFuture means the document IssuedAt is implausibly in the future
	// (beyond the allowed clock skew).
	ErrIssuedInFuture = errors.New("attestation: document issued in the future")
	// ErrPolicyMismatch means one or more measurements did not satisfy the policy.
	ErrPolicyMismatch = errors.New("attestation: measurement policy mismatch")
	// ErrMalformed means the document is structurally invalid (missing required
	// fields, wrong key sizes, etc.).
	ErrMalformed = errors.New("attestation: malformed document")
)

// NonceSize is the required length, in bytes, of an attestation nonce.
const NonceSize = 32

// AttestationDocument is a signed attestation statement produced inside a TEE
// (or by the software reference [Attester]).
//
// The Signature is computed over the canonical serialization of all other
// fields (see [AttestationDocument.SigningPayload]); SignerPublicKey is the
// Ed25519 public key that produced it and, in a hardware deployment, would be
// accompanied by a vendor certificate chain (modeled here by trusting the key
// directly in the [Verifier]).
type AttestationDocument struct {
	// Measurements are PCR-like named register values (e.g. "tdx.rtmr0",
	// "gpu.firmware"). Keys and values are opaque to this package; the policy
	// decides which must match.
	Measurements map[string][]byte
	// Nonce is the verifier-supplied freshness challenge echoed back by the TEE.
	Nonce []byte
	// IssuedAt is when the document was produced.
	IssuedAt time.Time
	// ExpiresAt, if non-zero, is an explicit hard expiry embedded by the issuer.
	// The verifier also enforces its own freshness window independently.
	ExpiresAt time.Time
	// Signature is the Ed25519 signature over SigningPayload.
	Signature []byte
	// SignerPublicKey is the Ed25519 public key corresponding to Signature.
	SignerPublicKey ed25519.PublicKey
}

// SigningPayload returns the canonical, deterministic byte serialization of the
// document fields that are covered by the signature. Map ordering is normalized
// by sorting keys, and every variable-length field is length-prefixed so that
// no two distinct documents can ever produce the same payload (domain
// separation against length-extension / field-confusion attacks).
//
// The Signature and SignerPublicKey fields are intentionally NOT part of the
// payload: the signature cannot cover itself, and the signer key is bound by the
// verifier comparing it to the trusted root.
func (d *AttestationDocument) SigningPayload() []byte {
	var buf bytes.Buffer
	buf.WriteString("helix-attest/v1\x00")

	// Measurements: sort keys for determinism, length-prefix key and value.
	keys := make([]string, 0, len(d.Measurements))
	for k := range d.Measurements {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeUvarint(&buf, uint64(len(keys)))
	for _, k := range keys {
		writeBytes(&buf, []byte(k))
		writeBytes(&buf, d.Measurements[k])
	}

	writeBytes(&buf, d.Nonce)

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(d.IssuedAt.UnixNano()))
	buf.Write(ts[:])
	binary.BigEndian.PutUint64(ts[:], uint64(d.ExpiresAt.UnixNano()))
	buf.Write(ts[:])

	return buf.Bytes()
}

func writeUvarint(buf *bytes.Buffer, v uint64) {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], v)
	buf.Write(tmp[:n])
}

func writeBytes(buf *bytes.Buffer, b []byte) {
	writeUvarint(buf, uint64(len(b)))
	buf.Write(b)
}

// QuoteSigner is the hardware-attestation seam. The software reference
// [Attester] implements it with crypto/ed25519; a production deployment would
// implement it with a real TDX / NVIDIA quote-generation library that returns a
// hardware-rooted signature and the corresponding (vendor-chained) public key.
//
// Implementations MUST sign the exact payload bytes passed in (the document's
// SigningPayload) so that [Verifier] can re-derive and check them.
type QuoteSigner interface {
	// SignQuote signs payload and returns the signature together with the public
	// key that verifies it.
	SignQuote(payload []byte) (signature []byte, publicKey ed25519.PublicKey, err error)
}

// Attester is the SOFTWARE reference QuoteSigner. It holds an in-process
// Ed25519 key and signs documents directly. It does NOT provide hardware-rooted
// trust; see the package doc.
type Attester struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewAttester generates a fresh software Attester with a random Ed25519 key.
func NewAttester() (*Attester, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("attestation: generate key: %w", err)
	}
	return &Attester{priv: priv, pub: pub}, nil
}

// NewAttesterFromKey builds an Attester from an existing private key.
func NewAttesterFromKey(priv ed25519.PrivateKey) (*Attester, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("attestation: bad private key size %d: %w", len(priv), ErrMalformed)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("attestation: cannot derive public key: %w", ErrMalformed)
	}
	return &Attester{priv: priv, pub: pub}, nil
}

// PublicKey returns the Attester's public key, suitable for use as a trusted
// root in [NewVerifier] for testing/single-tenant deployments.
func (a *Attester) PublicKey() ed25519.PublicKey {
	return a.pub
}

// SignQuote implements [QuoteSigner].
func (a *Attester) SignQuote(payload []byte) ([]byte, ed25519.PublicKey, error) {
	sig := ed25519.Sign(a.priv, payload)
	return sig, a.pub, nil
}

// Attest builds and signs an AttestationDocument for the given measurements and
// nonce. issuedAt is the document timestamp; validity, if > 0, sets ExpiresAt =
// issuedAt + validity (0 leaves ExpiresAt zero, deferring to the verifier's
// freshness window).
func (a *Attester) Attest(measurements map[string][]byte, nonce []byte, issuedAt time.Time, validity time.Duration) (*AttestationDocument, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("attestation: nonce must be %d bytes, got %d: %w", NonceSize, len(nonce), ErrMalformed)
	}
	// Defensive copies so later caller mutation cannot change a signed document.
	ms := make(map[string][]byte, len(measurements))
	for k, v := range measurements {
		ms[k] = append([]byte(nil), v...)
	}
	doc := &AttestationDocument{
		Measurements: ms,
		Nonce:        append([]byte(nil), nonce...),
		IssuedAt:     issuedAt,
	}
	if validity > 0 {
		doc.ExpiresAt = issuedAt.Add(validity)
	}
	sig, pub, err := a.SignQuote(doc.SigningPayload())
	if err != nil {
		return nil, fmt.Errorf("attestation: sign: %w", err)
	}
	doc.Signature = sig
	doc.SignerPublicKey = pub
	return doc, nil
}

// GenerateNonce returns a fresh cryptographically-random nonce of NonceSize
// bytes for a verifier to challenge an attester with.
func GenerateNonce() ([]byte, error) {
	n := make([]byte, NonceSize)
	if _, err := rand.Read(n); err != nil {
		return nil, fmt.Errorf("attestation: generate nonce: %w", err)
	}
	return n, nil
}

// MeasurementPolicy expresses which measurements a verifier requires.
//
// For each entry in Expected, the document MUST contain that measurement key
// with a byte-for-byte equal value. Keys listed in Required but absent from
// Expected must merely be present (any value). A document MAY carry additional
// measurements not mentioned by the policy; those are ignored.
type MeasurementPolicy struct {
	// Expected maps measurement name -> exact required value.
	Expected map[string][]byte
	// Required lists measurement names that must be present (value unconstrained).
	Required []string
}

// Evaluate checks measurements against the policy, returning ErrPolicyMismatch
// (wrapped with detail) on the first violation.
func (p MeasurementPolicy) Evaluate(measurements map[string][]byte) error {
	for name, want := range p.Expected {
		got, ok := measurements[name]
		if !ok {
			return fmt.Errorf("attestation: measurement %q absent: %w", name, ErrPolicyMismatch)
		}
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return fmt.Errorf("attestation: measurement %q value mismatch: %w", name, ErrPolicyMismatch)
		}
	}
	for _, name := range p.Required {
		if _, ok := measurements[name]; !ok {
			return fmt.Errorf("attestation: required measurement %q absent: %w", name, ErrPolicyMismatch)
		}
	}
	return nil
}

// Verifier checks attestation documents against a trusted root key, a freshness
// window, an expected nonce and a measurement policy.
//
// The trusted root is supplied directly as an Ed25519 public key. In a hardware
// deployment this would instead be (or chain to) a vendor attestation CA; the
// rest of the verification logic is identical.
type Verifier struct {
	trustedRoot ed25519.PublicKey
	// MaxAge is the freshness window: a document whose IssuedAt is older than
	// now-MaxAge is rejected. Zero disables the window (explicit ExpiresAt still
	// enforced).
	MaxAge time.Duration
	// ClockSkew tolerates a small amount of issuer/verifier clock disagreement
	// for the issued-in-future check and expiry.
	ClockSkew time.Duration
}

// NewVerifier returns a Verifier trusting the given root public key, with the
// given freshness window. ClockSkew defaults to 1 minute and may be overridden
// on the returned struct.
func NewVerifier(trustedRoot ed25519.PublicKey, maxAge time.Duration) (*Verifier, error) {
	if len(trustedRoot) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("attestation: trusted root must be %d bytes, got %d: %w", ed25519.PublicKeySize, len(trustedRoot), ErrMalformed)
	}
	return &Verifier{
		trustedRoot: append(ed25519.PublicKey(nil), trustedRoot...),
		MaxAge:      maxAge,
		ClockSkew:   time.Minute,
	}, nil
}

// Verify checks doc against the trusted root, the expectedNonce, the policy and
// freshness at time now. It returns nil only if ALL checks pass; otherwise it
// returns a wrapped sentinel error identifying the first failure.
func (v *Verifier) Verify(doc *AttestationDocument, expectedNonce []byte, policy MeasurementPolicy, now time.Time) error {
	if doc == nil {
		return fmt.Errorf("attestation: nil document: %w", ErrMalformed)
	}
	if len(doc.SignerPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("attestation: signer key bad size %d: %w", len(doc.SignerPublicKey), ErrMalformed)
	}
	if len(doc.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("attestation: signature bad size %d: %w", len(doc.Signature), ErrMalformed)
	}

	// 1. The embedded signer key must be the trusted root.
	if !bytes.Equal(doc.SignerPublicKey, v.trustedRoot) {
		return ErrUntrustedSigner
	}

	// 2. Signature must verify over the canonical payload. This is what catches
	//    any tampering with measurements / nonce / timestamps.
	if !ed25519.Verify(v.trustedRoot, doc.SigningPayload(), doc.Signature) {
		return ErrSignatureInvalid
	}

	// 3. Nonce freshness: must match the challenge the verifier issued.
	//    subtle.ConstantTimeCompare returns 1 only when both length and content
	//    match; it does not branch on the contents, avoiding a timing oracle.
	if subtle.ConstantTimeCompare(doc.Nonce, expectedNonce) != 1 {
		return ErrNonceMismatch
	}

	// 4. Time checks.
	if doc.IssuedAt.After(now.Add(v.ClockSkew)) {
		return ErrIssuedInFuture
	}
	if v.MaxAge > 0 && doc.IssuedAt.Before(now.Add(-v.MaxAge)) {
		return ErrExpired
	}
	if !doc.ExpiresAt.IsZero() && now.After(doc.ExpiresAt.Add(v.ClockSkew)) {
		return ErrExpired
	}

	// 5. Measurement policy.
	if err := policy.Evaluate(doc.Measurements); err != nil {
		return err
	}

	return nil
}
