package e2ee

// AEAD-suite selection ---------------------------------------------------------
//
// This file adds a ChaCha20-Poly1305 AEAD variant alongside the package's
// default AES-256-GCM, selectable via SessionConfig.Suite. ChaCha20-Poly1305 is
// a software-friendly AEAD that resists cache-timing side channels on platforms
// without AES hardware acceleration; it uses a 32-byte key and a 12-byte nonce,
// matching the package's SessionKeySize and NonceSize exactly, so it slots into
// the existing Session/Seal/Open machinery without any wire-format change beyond
// the cipher in use.
//
// The implementation is golang.org/x/crypto/chacha20poly1305 (the IETF variant
// per RFC 8439), an audited external crypto library. AES-256-GCM remains the
// default for back-compatibility: a zero-value SessionConfig selects AES-GCM.

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEADSuite selects the symmetric AEAD used for record protection on a Session
// and by the deterministic SealWithKey/OpenWithKey entry points.
type AEADSuite uint8

const (
	// SuiteAES256GCM is the default AEAD: AES-256-GCM via crypto/aes +
	// crypto/cipher. The zero value of AEADSuite resolves to this suite so an
	// unset SessionConfig.Suite remains AES-256-GCM for back-compatibility.
	SuiteAES256GCM AEADSuite = 0

	// SuiteChaCha20Poly1305 selects ChaCha20-Poly1305 (RFC 8439 IETF variant)
	// via golang.org/x/crypto/chacha20poly1305. Key is 32 bytes, nonce 12 bytes.
	SuiteChaCha20Poly1305 AEADSuite = 1
)

// String renders the suite for diagnostics and error messages.
func (s AEADSuite) String() string {
	switch s {
	case SuiteAES256GCM:
		return "AES-256-GCM"
	case SuiteChaCha20Poly1305:
		return "ChaCha20-Poly1305"
	default:
		return fmt.Sprintf("AEADSuite(%d)", uint8(s))
	}
}

// newChaChaAEAD constructs a ChaCha20-Poly1305 AEAD from a 32-byte key. The
// returned AEAD has a 12-byte nonce (chacha20poly1305.NonceSize), identical to
// NonceSize, and a 16-byte tag overhead.
func newChaChaAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != SessionKeySize {
		return nil, fmt.Errorf("e2ee: chacha key is %d bytes, want %d: %w",
			len(key), SessionKeySize, ErrInvalidKeySize)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("e2ee: new chacha20poly1305: %w", err)
	}
	if aead.NonceSize() != NonceSize {
		return nil, fmt.Errorf("e2ee: unexpected chacha nonce size %d, want %d",
			aead.NonceSize(), NonceSize)
	}
	return aead, nil
}

// newAEAD builds the AEAD for the selected suite from a 32-byte key. It is the
// single dispatch point shared by Session construction and the deterministic
// SealWithKey/OpenWithKey helpers.
func newAEAD(suite AEADSuite, key []byte) (cipher.AEAD, error) {
	switch suite {
	case SuiteAES256GCM:
		return newGCMAEAD(key)
	case SuiteChaCha20Poly1305:
		return newChaChaAEAD(key)
	default:
		return nil, fmt.Errorf("e2ee: unknown AEAD suite %d: %w", uint8(suite), ErrInvalidKeySize)
	}
}
