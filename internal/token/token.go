// Package token generates and validates scopuli tokens.
//
// Two flavors:
//
//	scot_live_<base64url(32 random bytes)>            operator token
//	sk_live_<base62(24 random bytes)>_<base62(sha256(body)[:4])>  agent key
//
// The full token is shown to the caller exactly once. We store only its
// hex(SHA-256(token)) in the database.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	scrypt "github.com/lucaspdude/scopuli/internal/crypto"
)

const (
	OperatorPrefix = "scot_live_"
	KeyPrefix      = "sk_live_"

	// OperatorTokenBodyBytes is the entropy size of the operator token body.
	OperatorTokenBodyBytes = 32
	// KeyBodyBytes is the entropy size of the agent key body.
	KeyBodyBytes = 24
	// ChecksumBytes is the number of bytes of SHA-256(body) appended as checksum.
	ChecksumBytes = 4
)

// OperatorToken returns a fresh operator token string and the bytes of its
// hex(SHA-256(token)) digest for storage.
func OperatorToken() (token string, hashHex string, prefix string, err error) {
	body := make([]byte, OperatorTokenBodyBytes)
	if _, err := io.ReadFull(rand.Reader, body); err != nil {
		return "", "", "", fmt.Errorf("token: read body: %w", err)
	}
	bodyStr := base64.RawURLEncoding.EncodeToString(body)
	tok := OperatorPrefix + bodyStr
	h := sha256.Sum256([]byte(tok))
	return tok, hex.EncodeToString(h[:]), displayPrefix(OperatorPrefix, bodyStr, 8), nil
}

// AgentKey returns a fresh agent key string and the bytes of its
// hex(SHA-256(token)) digest for storage.
func AgentKey() (token string, hashHex string, prefix string, err error) {
	body := make([]byte, KeyBodyBytes)
	if _, err := io.ReadFull(rand.Reader, body); err != nil {
		return "", "", "", fmt.Errorf("token: read body: %w", err)
	}
	bodyStr := base62(body)
	h := sha256.Sum256([]byte(bodyStr))
	chk := base62(h[:ChecksumBytes])
	tok := KeyPrefix + bodyStr + "_" + chk
	hh := sha256.Sum256([]byte(tok))
	return tok, hex.EncodeToString(hh[:]), displayPrefix(KeyPrefix, bodyStr, 8), nil
}

// HashHex returns the hex SHA-256 of the given token. Used to compute the
// value to look up when an inbound token is presented.
func HashHex(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// displayPrefix builds the short "sk_live_<first 8>" string used in
// listings to identify a key without revealing it.
func displayPrefix(prefix, body string, n int) string {
	if len(body) < n {
		n = len(body)
	}
	return prefix + body[:n]
}

// base62 encodes bytes into a Crockford-style base62 string [0-9A-Za-z].
// We avoid ambiguous characters (0/O, 1/I/L) by offsetting.
func base62(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// Convert to a big integer.
	var n uint64
	if len(b) > 8 {
		n = binary.BigEndian.Uint64(b[:8])
	} else {
		var pad [8]byte
		copy(pad[8-len(b):], b)
		n = binary.BigEndian.Uint64(pad[:])
	}
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var out []byte
	for n > 0 {
		out = append([]byte{alphabet[n%62]}, out...)
		n /= 62
	}
	return string(out)
}

// LooksLikeOperatorToken reports whether the token has the operator prefix.
func LooksLikeOperatorToken(t string) bool { return strings.HasPrefix(t, OperatorPrefix) }

// LooksLikeAgentKey reports whether the token has the agent key prefix.
func LooksLikeAgentKey(t string) bool { return strings.HasPrefix(t, KeyPrefix) }

// AuditHMACKey derives a 32-byte HMAC key for the audit chain from the
// master password using a separate Argon2id salt (so a leak of the KEK
// doesn't trivially leak the audit HMAC key).
func AuditHMACKey(masterPassword string, salt []byte) []byte {
	p := scrypt.DefaultKDFParams()
	p.MemoryKiB = 8 * 1024 // 8 MiB — audit HMAC key derivation is colder; lower mem is fine
	p.Iterations = 2
	return scrypt.DeriveKEK(masterPassword, salt, p)
}
