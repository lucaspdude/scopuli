// Package crypto provides the cryptographic primitives used by scopuli:
// Argon2id KDF for the master-password-derived KEK, AES-256-GCM AEAD for
// per-secret encryption, and HMAC-SHA-256 for the audit chain.
package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters.
// Targets ~250 ms on a modern CPU with 64 MiB memory and 3 lanes.
// Tuned to OWASP "Cheat Sheet — Password Storage" recommendations (2024).
const (
	KDFMemoryKiB  uint32 = 64 * 1024 // 64 MiB
	KDFIterations uint32 = 3
	KDFParallel   uint8  = 4
	KDFSaltLen           = 16
	KDFKeyLen            = 32 // 256 bits
)

// ErrInvalidKDFParams indicates the parameters stored in the database are
// missing, malformed, or have unsupported values.
var ErrInvalidKDFParams = errors.New("invalid KDF parameters")

// KDFParams captures the parameters used to derive a KEK. Persisted in
// meta.kdf_params so the server can re-derive on boot.
type KDFParams struct {
	MemoryKiB  uint32 `json:"m"`
	Iterations uint32 `json:"t"`
	Parallel   uint8  `json:"p"`
	KeyLen     uint32 `json:"klen"`
}

// DefaultKDFParams returns the canonical parameter set for new vaults.
func DefaultKDFParams() KDFParams {
	return KDFParams{
		MemoryKiB:  KDFMemoryKiB,
		Iterations: KDFIterations,
		Parallel:   KDFParallel,
		KeyLen:     KDFKeyLen,
	}
}

// Validate ensures params fall within safe bounds. Used when reading the
// stored params at boot, so we refuse to run on a vault whose params were
// written by a buggy / malicious older version.
func (p KDFParams) Validate() error {
	if p.MemoryKiB < 8*1024 || p.MemoryKiB > 1024*1024 {
		return fmt.Errorf("%w: memory %d KiB out of bounds [8MiB, 1GiB]", ErrInvalidKDFParams, p.MemoryKiB)
	}
	if p.Iterations < 1 || p.Iterations > 64 {
		return fmt.Errorf("%w: iterations %d out of bounds [1, 64]", ErrInvalidKDFParams, p.Iterations)
	}
	if p.Parallel < 1 || p.Parallel > 16 {
		return fmt.Errorf("%w: parallel %d out of bounds [1, 16]", ErrInvalidKDFParams, p.Parallel)
	}
	if p.KeyLen != 32 {
		return fmt.Errorf("%w: key length %d must be 32", ErrInvalidKDFParams, p.KeyLen)
	}
	return nil
}

// DeriveKEK runs Argon2id over (password, salt) with the configured params.
// Returns the 32-byte KEK.
func DeriveKEK(password string, salt []byte, p KDFParams) []byte {
	if err := p.Validate(); err != nil {
		// Programmer error — fail loud.
		panic(fmt.Errorf("crypto: %w", err))
	}
	return argon2.IDKey([]byte(password), salt, p.Iterations, p.MemoryKiB, p.Parallel, p.KeyLen)
}

// NewSalt returns a 16-byte cryptographically random salt.
func NewSalt() ([]byte, error) {
	buf := make([]byte, KDFSaltLen)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("crypto: read salt: %w", err)
	}
	return buf, nil
}
