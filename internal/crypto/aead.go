package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// AES-256-GCM nonce and tag sizes are fixed by the spec.
const (
	NonceSize = 12 // 96 bits
)

// ErrAuth indicates an authentication failure (GCM tag mismatch, wrong AAD,
// wrong nonce length, etc). Callers should treat any occurrence as a tamper
// attempt and respond with a generic error that does not distinguish causes.
var ErrAuth = errors.New("crypto: authentication failed")

// Seal encrypts plaintext with AES-256-GCM using the given KEK, AAD, and a
// freshly-generated 12-byte nonce. The returned byte slice has the format:
//
//	[nonce (12) | ciphertext+tag (N+16)]
//
// The nonce is prepended to the output so callers don't have to manage it
// separately.
func Seal(kek, plaintext, aad []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("crypto: KEK must be 32 bytes, got %d", len(kek))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: read nonce: %w", err)
	}
	// Allocate a single buffer for [nonce | ciphertext | tag] and let
	// cipher.Seal append in place.
	out := make([]byte, 0, NonceSize+len(plaintext)+aead.Overhead())
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, aad)
	return out, nil
}

// Open verifies and decrypts a ciphertext produced by Seal. The nonce is
// expected as the first NonceSize bytes of sealed.
//
// On any tamper attempt (wrong AAD, wrong nonce length, tag mismatch) Open
// returns ErrAuth. Callers should not leak the underlying cause to the
// client; log locally only.
func Open(kek, sealed, aad []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("crypto: KEK must be 32 bytes, got %d", len(kek))
	}
	if len(sealed) < NonceSize+16 {
		return nil, ErrAuth
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	nonce := sealed[:NonceSize]
	ct := sealed[NonceSize:]
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}

// AADSecret returns the AAD bound to a secret's ciphertext. V0 schema:
//
//	AAD = SHA-256(path || 0x00 || description || 0x00 || uint64_be(version))
//
// The description is included so that description edits invalidate the
// ciphertext — this is intentional, see SECURITY.md §2.7.
func AADSecret(path, description string, version uint64) [32]byte {
	var buf []byte
	buf = append(buf, []byte(path)...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte(description)...)
	buf = append(buf, 0x00)
	var ver [8]byte
	binary.BigEndian.PutUint64(ver[:], version)
	buf = append(buf, ver[:]...)
	return sha256.Sum256(buf)
}
