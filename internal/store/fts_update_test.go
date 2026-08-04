package store

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	scrypt "github.com/lucaspdude/scopuli/internal/crypto"
)

// TestFTS5UpdateSyncReplacesIndex verifies that when a secret's description
// is updated via a fresh PutSecret (the same code path annotate takes),
// the FTS5 index is updated to reflect the new description and tags.
// This is the regression test for the production bug where the FTS5
// search index wasn't being updated on annotate.
func TestFTS5UpdateSyncReplacesIndex(t *testing.T) {
	dir := t.TempDir()
	kek := bytes.Repeat([]byte{0x42}, 32)
	s, err := Open(context.Background(), filepath.Join(dir, "v.db"), kek, scrypt.DefaultKDFParams())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	// Step 1: create a secret with description "alpha bravo charlie".
	sec := &Secret{
		Path:        "smoke/test-fts",
		Label:       sql.NullString{String: "", Valid: false},
		Ciphertext:  []byte("ct"),
		Nonce:       []byte("nonce_____"),
		AAD:         bytes.Repeat([]byte{0x02}, 32),
		Tags:        "t1",
		Description: "alpha bravo charlie",
		Metadata:    "{}",
		Version:     1,
	}
	if err := s.PutSecret(ctx, sec); err != nil {
		t.Fatalf("PutSecret initial: %v", err)
	}

	// Step 2: search "alpha" should match.
	ids, err := s.SearchSecrets(ctx, "alpha", 10)
	if err != nil {
		t.Fatalf("SearchSecrets alpha: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 hit for 'alpha', got %d", len(ids))
	}

	// Step 3: update the secret (this is the annotate path) with a NEW
	// description that does NOT contain "alpha".
	sec.Description = "delta echo foxtrot"
	sec.Version = 2
	if err := s.PutSecret(ctx, sec); err != nil {
		t.Fatalf("PutSecret update: %v", err)
	}

	// Step 4: search "delta" should match (new description).
	ids, err = s.SearchSecrets(ctx, "delta", 10)
	if err != nil {
		t.Fatalf("SearchSecrets delta: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("after update: expected 1 hit for 'delta', got %d (FTS5 sync is broken)", len(ids))
	}

	// Step 5: search "alpha" should NOT match (description replaced).
	ids, err = s.SearchSecrets(ctx, "alpha", 10)
	if err != nil {
		t.Fatalf("SearchSecrets alpha after update: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("after update: expected 0 hits for 'alpha' (description replaced), got %d (FTS5 sync is broken)", len(ids))
	}
}
