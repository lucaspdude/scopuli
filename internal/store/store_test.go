package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	scrypt "github.com/lucaspdude/scopuli/internal/crypto"
)

// newTestStore opens a fresh encrypted DB in a temp file.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	kek := bytes.Repeat([]byte{0x42}, 32)
	s, err := Open(context.Background(), dbPath, kek, scrypt.DefaultKDFParams())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenFreshDB(t *testing.T) {
	s := newTestStore(t)
	fresh, err := s.IsFresh(context.Background())
	if err != nil {
		t.Fatalf("IsFresh: %v", err)
	}
	if !fresh {
		t.Fatal("expected fresh DB to be detected")
	}
}

func TestFirstBootToggle(t *testing.T) {
	s := newTestStore(t)
	if err := s.MarkFirstBootDone(context.Background()); err != nil {
		t.Fatalf("MarkFirstBootDone: %v", err)
	}
	fresh, err := s.IsFresh(context.Background())
	if err != nil {
		t.Fatalf("IsFresh: %v", err)
	}
	if fresh {
		t.Fatal("DB should not be fresh after MarkFirstBootDone")
	}
}

func TestSecretRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := now()
	sec := &Secret{
		Path:        "aws/prod/stripe_key",
		Label:       sql.NullString{String: "Stripe production key", Valid: true},
		Ciphertext:  bytes.Repeat([]byte{0xab}, 64),
		Nonce:       bytes.Repeat([]byte{0x01}, 12),
		AAD:         bytes.Repeat([]byte{0x02}, 32),
		Tags:        "aws,prod,stripe",
		Description: "Production Stripe secret key.",
		Metadata:    `{"owner_email":"alice@example.com"}`,
		CreatedAt:   now,
		Version:     1,
	}
	if err := s.PutSecret(ctx, sec); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	got, err := s.GetSecret(ctx, sec.Path)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got.Path != sec.Path {
		t.Fatalf("path mismatch: %q vs %q", got.Path, sec.Path)
	}
	if !bytes.Equal(got.Ciphertext, sec.Ciphertext) {
		t.Fatal("ciphertext mismatch")
	}
	if got.Tags != sec.Tags {
		t.Fatalf("tags: %q vs %q", got.Tags, sec.Tags)
	}
	if got.Description != sec.Description {
		t.Fatalf("description mismatch")
	}
	if got.Metadata != sec.Metadata {
		t.Fatalf("metadata mismatch")
	}
}

func TestSecretUpsert(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sec := &Secret{
		Path:        "aws/prod/x",
		Ciphertext:  []byte("ct"),
		Nonce:       []byte("nonce_____"),
		AAD:         []byte("aad_____________________________"),
		Tags:        "v1",
		Description: "v1",
		Version:     1,
	}
	if err := s.PutSecret(ctx, sec); err != nil {
		t.Fatalf("first put: %v", err)
	}
	sec.Tags = "v2"
	sec.Description = "v2"
	sec.Version = 2
	if err := s.PutSecret(ctx, sec); err != nil {
		t.Fatalf("second put: %v", err)
	}
	got, err := s.GetSecret(ctx, "aws/prod/x")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got.Tags != "v2" || got.Description != "v2" {
		t.Fatalf("upsert did not update: tags=%q description=%q", got.Tags, got.Description)
	}
}

func TestSecretDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sec := &Secret{
		Path:       "x",
		Ciphertext: []byte("ct"),
		Nonce:      []byte("nonce_____"),
		AAD:        []byte("aad_____________________________"),
		Version:    1,
	}
	if err := s.PutSecret(ctx, sec); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	if err := s.DeleteSecret(ctx, "x"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, err := s.GetSecret(ctx, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSecretSearchFTS5(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for i, desc := range []string{
		"Production Stripe key for billing",
		"GitHub personal access token",
		"AWS root credentials",
	} {
		sec := &Secret{
			Path:        testPath(i),
			Ciphertext:  []byte("ct"),
			Nonce:       []byte("nonce_____"),
			AAD:         []byte("aad_____________________________"),
			Description: desc,
			Version:     1,
		}
		if err := s.PutSecret(ctx, sec); err != nil {
			t.Fatalf("PutSecret[%d]: %v", i, err)
		}
	}
	ids, err := s.SearchSecrets(ctx, "stripe", 10)
	if err != nil {
		t.Fatalf("SearchSecrets: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 hit for 'stripe', got %d", len(ids))
	}
}

func TestKeyCreateAndLookup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	k := &Key{
		Name:        "linus-dev",
		Hash:        "abc123",
		Prefix:      "sk_live_xxxxxx",
		Scope:       "aws/dev/*,github/lucas/*",
		Permissions: "read",
		Tags:        "dev,linus",
		Description: "Linus dev key",
		Metadata:    `{"owner":"lucas"}`,
	}
	if err := s.CreateKey(ctx, k); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	got, err := s.GetKeyByHash(ctx, "abc123")
	if err != nil {
		t.Fatalf("GetKeyByHash: %v", err)
	}
	if got.Name != "linus-dev" {
		t.Fatalf("name mismatch: %q", got.Name)
	}
	if got.Tags != "dev,linus" {
		t.Fatalf("tags mismatch")
	}
}

func TestKeyUniqueName(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	k1 := &Key{Name: "k", Hash: "h1", Prefix: "p1", Scope: "*", Permissions: "read"}
	if err := s.CreateKey(ctx, k1); err != nil {
		t.Fatalf("first CreateKey: %v", err)
	}
	k2 := &Key{Name: "k", Hash: "h2", Prefix: "p2", Scope: "*", Permissions: "read"}
	if err := s.CreateKey(ctx, k2); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestKeyRevokeAndList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, name := range []string{"a", "b", "c"} {
		k := &Key{Name: name, Hash: name + "h", Prefix: name + "p", Scope: "*", Permissions: "read"}
		if err := s.CreateKey(ctx, k); err != nil {
			t.Fatalf("CreateKey %s: %v", name, err)
		}
	}
	// Revoke b.
	b, err := s.GetKeyByName(ctx, "b")
	if err != nil {
		t.Fatalf("GetKeyByName b: %v", err)
	}
	if err := s.RevokeKey(ctx, b.ID); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	// List should hide b by default.
	live, err := s.ListKeys(ctx, false)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(live) != 2 {
		t.Fatalf("expected 2 live keys, got %d", len(live))
	}
	all, err := s.ListKeys(ctx, true)
	if err != nil {
		t.Fatalf("ListKeys all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 keys total, got %d", len(all))
	}
}

func TestFlattenMetadata(t *testing.T) {
	cases := map[string]string{
		"":                      "",
		"{}":                    "",
		`{"owner":"alice"}`:     "owner=alice",
		`{"k1":"v1","k2":"v2"}`: "k1=v1;k2=v2",
	}
	for in, want := range cases {
		got := flattenMetadata(in)
		if got != want {
			t.Errorf("flattenMetadata(%q) = %q, want %q", in, got, want)
		}
	}
}

// helpers

func testPath(i int) string {
	switch i {
	case 0:
		return "aws/prod/stripe"
	case 1:
		return "github/lucas/pat"
	default:
		return "aws/root/credentials"
	}
}
