package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HMAC returns HMAC-SHA-256(key, msg).
func HMAC(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// SHA256 returns the SHA-256 digest of msg.
func SHA256(msg []byte) []byte {
	h := sha256.Sum256(msg)
	return h[:]
}
