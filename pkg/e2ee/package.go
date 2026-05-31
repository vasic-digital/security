// Package e2ee implements a post-quantum end-to-end encrypted session and
// transport for Helix Cluster OS.
//
// The crypto envelope is hybrid post-quantum:
//
//   - Key establishment via ML-KEM-768 (NIST FIPS 203) using crypto/mlkem.
//   - Symmetric session key derivation via HKDF-SHA-256 (crypto/hkdf) with a
//     domain-separation info label and a salt taken from the KEM ciphertext.
//   - AEAD record protection via AES-256-GCM (crypto/aes + crypto/cipher) with
//     a unique nonce per message (monotonic counter or random 96-bit), with
//     explicit reuse rejection.
//
// The handshake is two-peer: an initiator publishes an ephemeral ML-KEM
// encapsulation key; the responder encapsulates against it, producing the KEM
// ciphertext and shared secret; the initiator decapsulates the ciphertext to
// recover the same shared secret. Both sides then derive an identical session
// key, after which either peer can Seal and the other can Open.
package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	// SessionKeySize is the length in bytes of a derived AES-256-GCM session key.
	SessionKeySize = 32

	// NonceSize is the AES-GCM nonce length in bytes (96 bits).
	NonceSize = 12

	// kemCiphertextSize is the wire size of an ML-KEM-768 ciphertext.
	kemCiphertextSize = mlkem.CiphertextSize768

	// hkdfSaltLen is the number of leading KEM-ciphertext bytes used as the
	// HKDF salt, binding the derived key to the exact encapsulation.
	hkdfSaltLen = 16
)

// DefaultSessionInfo is the default HKDF info / domain-separation label used
// when SessionConfig.Info is empty. Distinct labels yield distinct session keys
// from the same shared secret.
const DefaultSessionInfo = "helix-e2ee-session-v1"

var (
	// ErrInvalidKeySize indicates a key argument had the wrong length.
	ErrInvalidKeySize = errors.New("e2ee: invalid key size")

	// ErrInvalidCiphertext indicates a malformed or truncated ciphertext/record.
	ErrInvalidCiphertext = errors.New("e2ee: invalid ciphertext")

	// ErrOpen indicates AEAD authentication/decryption failed (tamper, wrong
	// key, or AAD mismatch).
	ErrOpen = errors.New("e2ee: open failed")

	// ErrNonceReuse indicates a nonce was presented that had already been used
	// to seal a record on this session, which is forbidden for AES-GCM.
	ErrNonceReuse = errors.New("e2ee: nonce reuse rejected")

	// ErrNonceExhausted indicates the monotonic nonce counter has wrapped and
	// the session must be rekeyed.
	ErrNonceExhausted = errors.New("e2ee: nonce space exhausted")

	// ErrRecordTooLarge indicates a framed record exceeded the configured limit.
	ErrRecordTooLarge = errors.New("e2ee: record too large")
)

// Handshake state -----------------------------------------------------------

// Initiator is the originating peer of a handshake. It generates an ephemeral
// ML-KEM-768 decapsulation key, publishes the matching encapsulation key, and
// later decapsulates the responder's ciphertext to recover the shared secret.
type Initiator struct {
	dk   *mlkem.DecapsulationKey768
	info string
}

// SessionConfig tunes session-key derivation. The zero value is valid and uses
// DefaultSessionInfo with a random nonce strategy.
type SessionConfig struct {
	// Info is the HKDF domain-separation label. Empty uses DefaultSessionInfo.
	Info string

	// CounterNonce, when true, makes Seal use a deterministic monotonic counter
	// for nonces instead of random 96-bit nonces. Counter mode guarantees
	// uniqueness without RNG draws; random mode relies on RNG. Either way,
	// Open enforces single-use of each nonce.
	CounterNonce bool
}

// NewInitiator creates an Initiator with a fresh ephemeral ML-KEM-768 keypair.
// The provided config controls subsequent session-key derivation. A zero
// SessionConfig is acceptable.
func NewInitiator(cfg SessionConfig) (*Initiator, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("e2ee: generate ml-kem key: %w", err)
	}
	return &Initiator{dk: dk, info: infoOrDefault(cfg.Info)}, nil
}

// EncapsulationKeyBytes returns the public ML-KEM-768 encapsulation key to send
// to the responder. It is safe to transmit over an untrusted relay.
func (in *Initiator) EncapsulationKeyBytes() []byte {
	return in.dk.EncapsulationKey().Bytes()
}

// Respond performs the responder side of the handshake against the initiator's
// published encapsulation key. It returns the KEM ciphertext (to be sent back
// to the initiator) and a ready-to-use Session. cfg must match the initiator's
// derivation parameters (Info) for the keys to agree.
func Respond(encapKeyBytes []byte, cfg SessionConfig) (ciphertext []byte, sess *Session, err error) {
	ek, err := mlkem.NewEncapsulationKey768(encapKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("e2ee: parse encapsulation key: %w", err)
	}
	sharedKey, ct := ek.Encapsulate()
	sessionKey, err := deriveSessionKey(sharedKey, ct, infoOrDefault(cfg.Info))
	if err != nil {
		return nil, nil, err
	}
	s, err := newSession(sessionKey, cfg.CounterNonce)
	if err != nil {
		return nil, nil, err
	}
	return ct, s, nil
}

// Complete finishes the initiator side of the handshake by decapsulating the
// responder's ciphertext and deriving the identical session key.
func (in *Initiator) Complete(ciphertext []byte, cfg SessionConfig) (*Session, error) {
	if len(ciphertext) != kemCiphertextSize {
		return nil, fmt.Errorf("e2ee: kem ciphertext is %d bytes, want %d: %w",
			len(ciphertext), kemCiphertextSize, ErrInvalidCiphertext)
	}
	sharedKey, err := in.dk.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("e2ee: decapsulate: %w", err)
	}
	info := in.info
	if cfg.Info != "" {
		info = cfg.Info
	}
	sessionKey, err := deriveSessionKey(sharedKey, ciphertext, info)
	if err != nil {
		return nil, err
	}
	return newSession(sessionKey, cfg.CounterNonce)
}

// deriveSessionKey expands the ML-KEM shared secret into an AES-256 key using
// HKDF-SHA-256. The salt is the leading bytes of the KEM ciphertext, binding the
// session key to the exact encapsulation that produced the shared secret.
func deriveSessionKey(sharedKey, kemCiphertext []byte, info string) ([]byte, error) {
	if len(sharedKey) != mlkem.SharedKeySize {
		return nil, fmt.Errorf("e2ee: shared key is %d bytes, want %d: %w",
			len(sharedKey), mlkem.SharedKeySize, ErrInvalidKeySize)
	}
	salt := kemCiphertext
	if len(salt) > hkdfSaltLen {
		salt = salt[:hkdfSaltLen]
	}
	key, err := hkdf.Key(sha256.New, sharedKey, salt, info, SessionKeySize)
	if err != nil {
		return nil, fmt.Errorf("e2ee: hkdf derive: %w", err)
	}
	return key, nil
}

func infoOrDefault(info string) string {
	if info == "" {
		return DefaultSessionInfo
	}
	return info
}

// Session --------------------------------------------------------------------

// Session is an established AEAD channel keyed by a derived session key. It is
// safe for concurrent use: nonce issuance and reuse tracking are mutex-guarded.
type Session struct {
	aead    cipher.AEAD
	counter bool

	mu      sync.Mutex
	nextCtr uint64                       // next counter value when counter==true
	used    map[[NonceSize]byte]struct{} // nonces already consumed by Open
}

// newSession builds a Session from a 32-byte AES-256 key.
func newSession(key []byte, counter bool) (*Session, error) {
	if len(key) != SessionKeySize {
		return nil, fmt.Errorf("e2ee: session key is %d bytes, want %d: %w",
			len(key), SessionKeySize, ErrInvalidKeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("e2ee: new aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("e2ee: new gcm: %w", err)
	}
	if gcm.NonceSize() != NonceSize {
		return nil, fmt.Errorf("e2ee: unexpected gcm nonce size %d", gcm.NonceSize())
	}
	return &Session{
		aead:    gcm,
		counter: counter,
		used:    make(map[[NonceSize]byte]struct{}),
	}, nil
}

// NewSessionFromKey constructs a Session directly from a 32-byte key, bypassing
// the handshake. It is intended for testing and for callers that establish the
// session key out of band.
func NewSessionFromKey(key []byte, counter bool) (*Session, error) {
	return newSession(key, counter)
}

// SessionKey returns nothing sensitive; it exists only so tests can confirm two
// peers derived the same key without exposing the raw key material. It returns
// the AEAD's effective key fingerprint by sealing a fixed probe under a fixed
// nonce. Two sessions with identical keys produce identical fingerprints; any
// key difference changes the output. The probe nonce is reserved and never
// issued by Seal.
func (s *Session) SessionKey() []byte {
	var nonce [NonceSize]byte // all-zero reserved fingerprint nonce
	return s.aead.Seal(nil, nonce[:], []byte("helix-e2ee-fingerprint"), nil)
}

// nextNonce returns the nonce to use for the next Seal call.
func (s *Session) nextNonce() ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	if s.counter {
		s.mu.Lock()
		ctr := s.nextCtr
		if ctr == ^uint64(0) {
			s.mu.Unlock()
			return nonce, ErrNonceExhausted
		}
		s.nextCtr++
		s.mu.Unlock()
		// Reserve the all-zero nonce for SessionKey fingerprinting: counters
		// start at 1.
		ctr++
		// Big-endian counter in the trailing 8 bytes.
		nonce[4] = byte(ctr >> 56)
		nonce[5] = byte(ctr >> 48)
		nonce[6] = byte(ctr >> 40)
		nonce[7] = byte(ctr >> 32)
		nonce[8] = byte(ctr >> 24)
		nonce[9] = byte(ctr >> 16)
		nonce[10] = byte(ctr >> 8)
		nonce[11] = byte(ctr)
		return nonce, nil
	}
	for {
		if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
			return nonce, fmt.Errorf("e2ee: random nonce: %w", err)
		}
		// Avoid the reserved all-zero fingerprint nonce (vanishingly unlikely).
		if nonce != ([NonceSize]byte{}) {
			return nonce, nil
		}
	}
}

// Seal encrypts plaintext with optional additional authenticated data (aad) and
// returns a record of the form nonce(12) || ciphertext||tag. The nonce is
// unique per call for the lifetime of the session.
func (s *Session) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce, err := s.nextNonce()
	if err != nil {
		return nil, err
	}
	out := make([]byte, NonceSize, NonceSize+len(plaintext)+s.aead.Overhead())
	copy(out, nonce[:])
	out = s.aead.Seal(out, nonce[:], plaintext, aad)
	return out, nil
}

// Open authenticates and decrypts a record produced by Seal. It returns ErrOpen
// on any tamper, wrong key, or AAD mismatch, and ErrNonceReuse if the record's
// nonce was already accepted on this session (replay protection).
func (s *Session) Open(record, aad []byte) ([]byte, error) {
	if len(record) < NonceSize+s.aead.Overhead() {
		return nil, fmt.Errorf("e2ee: record is %d bytes, too short: %w",
			len(record), ErrInvalidCiphertext)
	}
	var nonce [NonceSize]byte
	copy(nonce[:], record[:NonceSize])
	ct := record[NonceSize:]

	plaintext, err := s.aead.Open(nil, nonce[:], ct, aad)
	if err != nil {
		return nil, fmt.Errorf("e2ee: %w", ErrOpen)
	}

	// Authentication succeeded; enforce single-use of this nonce. We record the
	// nonce only after successful authentication so that forged records cannot
	// poison the replay table.
	s.mu.Lock()
	if _, seen := s.used[nonce]; seen {
		s.mu.Unlock()
		return nil, ErrNonceReuse
	}
	s.used[nonce] = struct{}{}
	s.mu.Unlock()

	return plaintext, nil
}

// KeysEqual reports whether two sessions hold the same session key, in constant
// time, by comparing their key fingerprints. It is intended for tests and
// diagnostics.
func KeysEqual(a, b *Session) bool {
	fa := a.SessionKey()
	fb := b.SessionKey()
	return subtle.ConstantTimeCompare(fa, fb) == 1
}
