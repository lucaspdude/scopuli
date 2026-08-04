package store

import (
	"context"
	"testing"
)

// TestSecretSearchReflectsUpdate is a regression test: after PutSecret
// updates a secret's description, FTS5 search must match the NEW
// description and stop matching the old one.
func TestSecretSearchReflectsUpdate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sec := &Secret{
		Path:        "bench/secret-1",
		Ciphertext:  []byte("ct"),
		Nonce:       []byte("nonce_____"),
		AAD:         []byte("aad_____________________________"),
		Description: "benchmark secret number 1",
		Version:     1,
	}
	if err := s.PutSecret(ctx, sec); err != nil {
		t.Fatalf("first put: %v", err)
	}
	ids, err := s.SearchSecrets(ctx, "benchmark", 10)
	if err != nil || len(ids) != 1 {
		t.Fatalf("pre-update search 'benchmark': ids=%v err=%v", ids, err)
	}

	// Interleave an unrelated INSERT (the API writes an audit row between
	// requests in production). LastInsertId on the upsert's UPDATE arm would
	// then return that row's rowid, and the FTS row would be written at the
	// wrong rowid — invisible to search-join. This is the v0.1.x bug where
	// search stopped reflecting description updates.
	if _, err := s.DB().ExecContext(ctx, `INSERT INTO meta(k, v) VALUES ('zz_interleave', x'01')`); err != nil {
		t.Fatalf("interleave insert: %v", err)
	}

	// Update the description in place.
	sec.Description = "xyzzyplugh rotated description"
	sec.Version = 2
	if err := s.PutSecret(ctx, sec); err != nil {
		t.Fatalf("second put: %v", err)
	}
	var realID int64
	if err := s.DB().QueryRowContext(ctx, `SELECT id FROM secrets WHERE path = ?`, sec.Path).Scan(&realID); err != nil {
		t.Fatalf("select id: %v", err)
	}
	if sec.ID != realID {
		t.Fatalf("PutSecret left sec.ID=%d, real id is %d (stale LastInsertId)", sec.ID, realID)
	}

	ids, err = s.SearchSecrets(ctx, "xyzzyplugh", 10)
	if err != nil {
		t.Fatalf("post-update search 'xyzzyplugh': %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 hit for new description, got %d (ids=%v)", len(ids), ids)
	}
	ids, err = s.SearchSecrets(ctx, "benchmark", 10)
	if err != nil {
		t.Fatalf("post-update search 'benchmark': %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected 0 hits for old description, got %d (ids=%v)", len(ids), ids)
	}
}
