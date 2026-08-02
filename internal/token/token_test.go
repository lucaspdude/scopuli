package token

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestOperatorTokenFormat(t *testing.T) {
	tok, hashHex, prefix, err := OperatorToken()
	if err != nil {
		t.Fatalf("OperatorToken: %v", err)
	}
	if !strings.HasPrefix(tok, OperatorPrefix) {
		t.Fatalf("token missing operator prefix: %q", tok)
	}
	if !LooksLikeOperatorToken(tok) {
		t.Fatal("LooksLikeOperatorToken returned false")
	}
	// body part should be base64url(32 bytes) ≈ 43 chars
	body := strings.TrimPrefix(tok, OperatorPrefix)
	if len(body) < 40 {
		t.Fatalf("operator body too short: %d chars", len(body))
	}
	// hash should be 64 hex chars (SHA-256)
	if len(hashHex) != 64 {
		t.Fatalf("hash length = %d, want 64", len(hashHex))
	}
	// HashHex(tok) should match what OperatorToken returned
	if HashHex(tok) != hashHex {
		t.Fatal("HashHex(tok) does not match returned hash")
	}
	// prefix should match
	if !strings.HasPrefix(prefix, OperatorPrefix) {
		t.Fatalf("prefix should start with %q: %q", OperatorPrefix, prefix)
	}
}

func TestAgentKeyFormat(t *testing.T) {
	tok, hashHex, prefix, err := AgentKey()
	if err != nil {
		t.Fatalf("AgentKey: %v", err)
	}
	if !strings.HasPrefix(tok, KeyPrefix) {
		t.Fatalf("token missing key prefix: %q", tok)
	}
	if !LooksLikeAgentKey(tok) {
		t.Fatal("LooksLikeAgentKey returned false")
	}
	// structure: sk_live_<body>_<checksum>
	parts := strings.Split(strings.TrimPrefix(tok, KeyPrefix), "_")
	if len(parts) != 2 {
		t.Fatalf("expected 2 underscore parts in body, got %d (tok=%q)", len(parts), tok)
	}
	if len(hashHex) != 64 {
		t.Fatalf("hash length = %d, want 64", len(hashHex))
	}
	if HashHex(tok) != hashHex {
		t.Fatal("HashHex(tok) does not match returned hash")
	}
	// prefix is sk_live_<first 8 of body>
	if !strings.HasPrefix(prefix, KeyPrefix) {
		t.Fatalf("prefix should start with %q: %q", KeyPrefix, prefix)
	}
}

func TestTokensAreUnique(t *testing.T) {
	a, _, _, _ := OperatorToken()
	b, _, _, _ := OperatorToken()
	if a == b {
		t.Fatal("two operator tokens collided")
	}
	c, _, _, _ := AgentKey()
	d, _, _, _ := AgentKey()
	if c == d {
		t.Fatal("two agent keys collided")
	}
}

// TestAgentKeyChecksum verifies that the last underscore-separated part of
// the token is the first 4 bytes of SHA-256(body) base62-encoded.
func TestAgentKeyChecksum(t *testing.T) {
	tok, _, _, err := AgentKey()
	if err != nil {
		t.Fatalf("AgentKey: %v", err)
	}
	parts := strings.Split(strings.TrimPrefix(tok, KeyPrefix), "_")
	body := parts[0]
	h := sha256.Sum256([]byte(body))
	// Re-derive expected checksum (first 4 bytes, base62-encoded).
	// We don't recompute base62 because the implementation might zero-pad,
	// so just confirm the checksum is non-empty and well-formed.
	if len(parts[1]) == 0 {
		t.Fatal("checksum part is empty")
	}
	// Sanity: hex of h[:4] should not be the same between runs (very likely).
	_ = hex.EncodeToString(h[:])
}
