// Package backup produces encrypted snapshot bundles and restores them.
//
// V0 uses scrypt-derived KEK to wrap a single passphrase-derived subkey,
// then ChaCha20-Poly1305 to encrypt the SQLCipher file. Bundle format:
//
//	magic:        4 bytes  "SCPB"
//	version:      1 byte   (currently 0)
//	salt:        16 bytes  Argon2id salt for the passphrase
//	nonce:       12 bytes  ChaCha20-Poly1305 nonce
//	ciphertext:  N+16 bytes (ciphertext + tag)
//
// The passphrase is prompted on stdin (or read from a file). The KEK is
// derived from the passphrase using Argon2id, then ChaCha20-Poly1305 with a
// random nonce encrypts the SQLCipher file bytes.
package backup

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Magic             = "SCPB"
	Version    byte   = 0
	SaltLen           = 16
	NonceLen          = chacha20poly1305.NonceSize
	KeyLen            = chacha20poly1305.KeySize
	MemoryKiB  uint32 = 32 * 1024 // 32 MiB
	Iterations uint32 = 3
	Parallel   uint8  = 4
)

// Snapshot reads the SQLCipher file from src and writes an encrypted bundle
// to dst using passphrase. Passphrase may be empty in the future (re-using
// the master password); V0 requires an explicit passphrase.
func Snapshot(src io.Reader, dst io.Writer, passphrase string) error {
	if passphrase == "" {
		return errors.New("backup: passphrase required")
	}
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := deriveKey(passphrase, salt)
	plain, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	ad, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := ad.Seal(nil, nonce, plain, []byte(Magic))
	header := append([]byte(Magic), Version)
	header = append(header, salt...)
	header = append(header, nonce...)
	if _, err := dst.Write(header); err != nil {
		return err
	}
	if _, err := dst.Write(sealed); err != nil {
		return err
	}
	return nil
}

// Restore reads a bundle from src and writes the decrypted SQLCipher file
// bytes to dst.
func Restore(src io.Reader, dst io.Writer, passphrase string) error {
	if passphrase == "" {
		return errors.New("backup: passphrase required")
	}
	header := make([]byte, 4+1+SaltLen+NonceLen)
	if _, err := io.ReadFull(src, header); err != nil {
		return fmt.Errorf("backup: read header: %w", err)
	}
	if string(header[:4]) != Magic {
		return fmt.Errorf("backup: bad magic %q", header[:4])
	}
	if header[4] != Version {
		return fmt.Errorf("backup: unsupported version %d", header[4])
	}
	salt := header[5 : 5+SaltLen]
	nonce := header[5+SaltLen:]
	key := deriveKey(passphrase, salt)
	ad, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	ct, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	plain, err := ad.Open(nil, nonce, ct, []byte(Magic))
	if err != nil {
		return fmt.Errorf("backup: open: %w", err)
	}
	if _, err := dst.Write(plain); err != nil {
		return err
	}
	return nil
}

func deriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, Iterations, MemoryKiB, Parallel, KeyLen)
}
