package auth

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"path/filepath"
	"testing"

	scrypt "github.com/lucaspdude/scopuli/internal/crypto"
	"github.com/lucaspdude/scopuli/internal/store"
	"github.com/lucaspdude/scopuli/internal/token"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}
	s, err := store.Open(context.Background(), filepath.Join(dir, "v.db"), kek, scrypt.DefaultKDFParams())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedOperator(t *testing.T, s *store.Store) string {
	t.Helper()
	tok, hash, prefix, err := token.OperatorToken()
	if err != nil {
		t.Fatalf("OperatorToken: %v", err)
	}
	if err := s.CreateOperator(context.Background(), &store.Operator{
		Name: "primary", Hash: hash, Prefix: prefix, CreatedAt: nowMs(),
	}); err != nil {
		t.Fatalf("CreateOperator: %v", err)
	}
	return tok
}

func seedKey(t *testing.T, s *store.Store, name, scope, perms string, revoked bool, expires int64) string {
	t.Helper()
	tok, hash, prefix, err := token.AgentKey()
	if err != nil {
		t.Fatalf("AgentKey: %v", err)
	}
	k := &store.Key{
		Name: name, Hash: hash, Prefix: prefix, Scope: scope, Permissions: perms,
	}
	if revoked {
		now := nowMs()
		k.RevokedAt = sql.NullInt64{Int64: now, Valid: true}
	}
	if expires > 0 {
		k.ExpiresAt = sql.NullInt64{Int64: expires, Valid: true}
	}
	if err := s.CreateKey(context.Background(), k); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return tok
}

func TestAuthenticateOperator(t *testing.T) {
	s := newStore(t)
	opTok := seedOperator(t, s)
	r := httptest.NewRequest("GET", "/api/secrets", nil)
	r.Header.Set("X-Scopuli-Operator", opTok)
	p, err := Authenticate(context.Background(), s, r)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Kind != "operator" {
		t.Fatalf("kind = %q, want operator", p.Kind)
	}
	if !p.HasRead || !p.HasWrite {
		t.Fatal("operator should have read+write")
	}
}

func TestAuthenticateAgentKey(t *testing.T) {
	s := newStore(t)
	kTok := seedKey(t, s, "dev", "aws/*", "read", false, 0)
	r := httptest.NewRequest("GET", "/api/secrets", nil)
	r.Header.Set("X-Scopuli-Key", kTok)
	p, err := Authenticate(context.Background(), s, r)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Kind != "key" {
		t.Fatalf("kind = %q, want key", p.Kind)
	}
	if len(p.Scope) != 1 || p.Scope[0] != "aws/*" {
		t.Fatalf("scope = %v", p.Scope)
	}
	if p.HasWrite {
		t.Fatal("read-only key should not have write")
	}
}

func TestAuthenticateManageKeyHasWrite(t *testing.T) {
	s := newStore(t)
	kTok := seedKey(t, s, "dev", "aws/*", "manage", false, 0)
	r := httptest.NewRequest("GET", "/api/secrets", nil)
	r.Header.Set("X-Scopuli-Key", kTok)
	p, err := Authenticate(context.Background(), s, r)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !p.HasWrite {
		t.Fatal("manage key should have write")
	}
}

func TestAuthenticateRevokedKeyRejected(t *testing.T) {
	s := newStore(t)
	kTok := seedKey(t, s, "dev", "aws/*", "read", true, 0)
	r := httptest.NewRequest("GET", "/api/secrets", nil)
	r.Header.Set("X-Scopuli-Key", kTok)
	if _, err := Authenticate(context.Background(), s, r); err != ErrRevoked {
		t.Fatalf("expected ErrRevoked, got %v", err)
	}
}

func TestAuthenticateExpiredKeyRejected(t *testing.T) {
	s := newStore(t)
	kTok := seedKey(t, s, "dev", "aws/*", "read", false, 1) // expired in 1970
	r := httptest.NewRequest("GET", "/api/secrets", nil)
	r.Header.Set("X-Scopuli-Key", kTok)
	if _, err := Authenticate(context.Background(), s, r); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestAuthenticateMissingHeader(t *testing.T) {
	s := newStore(t)
	r := httptest.NewRequest("GET", "/api/secrets", nil)
	if _, err := Authenticate(context.Background(), s, r); err != ErrUnauthenticated {
		t.Fatalf("expected ErrUnauthenticated, got %v", err)
	}
}

func TestAuthenticateUnknownToken(t *testing.T) {
	s := newStore(t)
	r := httptest.NewRequest("GET", "/api/secrets", nil)
	r.Header.Set("X-Scopuli-Operator", "scot_live_bogus")
	if _, err := Authenticate(context.Background(), s, r); err == nil {
		t.Fatal("expected error for unknown token")
	}
}
