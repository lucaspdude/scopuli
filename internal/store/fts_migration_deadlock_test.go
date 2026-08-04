package store

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	scrypt "github.com/lucaspdude/scopuli/internal/crypto"
)

// TestFTS5MigrationDoesNotDeadlock is the regression test for the v0.1.1
// hang. The v0.1.1 migration called INSERT inside a SELECT iteration:
// the SELECT held the only connection (MaxOpenConns=1) and the INSERT
// blocked waiting for the same connection. The fix is to drain the SELECT
// into a slice first, then do the INSERTs separately.
//
// This test pre-creates the legacy FTS5 (content=''), seeds 100 secrets,
// closes the DB, then reopens. The fix must complete within 5 seconds.
// A deadlock would hit the timeout and fail.
func TestFTS5MigrationDoesNotDeadlock(t *testing.T) {
	dir := t.TempDir()
	kek := bytes.Repeat([]byte{0x42}, 32)
	dbPath := filepath.Join(dir, "v.db")

	// First open: create the legacy schema (content=''), seed 100 secrets.
	s, err := Open(context.Background(), dbPath, kek, scrypt.DefaultKDFParams())
	if err != nil {
		t.Fatalf("Open initial: %v", err)
	}
	ctx := context.Background()
	// Drop the freshly-created FTS5 and recreate with content=''.
	if _, err := s.DB().ExecContext(ctx, `DROP TABLE secrets_fts`); err != nil {
		t.Fatalf("drop secrets_fts: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx, `DROP TABLE keys_fts`); err != nil {
		t.Fatalf("drop keys_fts: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx,
		`CREATE VIRTUAL TABLE secrets_fts USING fts5(
			path, description, metadata_text,
			tokenize='unicode61 remove_diacritics 2',
			content=''
		)`); err != nil {
		t.Fatalf("create legacy secrets_fts: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx,
		`CREATE VIRTUAL TABLE keys_fts USING fts5(
			name, description, metadata_text,
			tokenize='unicode61 remove_diacritics 2',
			content=''
		)`); err != nil {
		t.Fatalf("create legacy keys_fts: %v", err)
	}
	// Seed 100 secrets directly.
	for i := 0; i < 100; i++ {
		_, err := s.DB().ExecContext(ctx,
			`INSERT INTO secrets(path, ciphertext, nonce, aad, description, metadata, version, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 1, 0, 0)`,
			"path/secret-"+itoa(i),
			[]byte("ct"), []byte("nonce_____"), []byte("aad_____________________________"),
			"description secret number "+itoa(i),
			`{}`,
		)
		if err != nil {
			t.Fatalf("insert secret %d: %v", i, err)
		}
	}
	_ = s.Close()

	// Second open must run the migration without deadlocking. We use a
	// 5-second timeout to fail fast if the v0.1.1 deadlock regresses.
	type result struct {
		s   *Store
		err error
	}
	done := make(chan result, 1)
	go func() {
		s2, err := Open(context.Background(), dbPath, kek, scrypt.DefaultKDFParams())
		done <- result{s: s2, err: err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("reopen with migration: %v", r.err)
		}
		t.Cleanup(func() { _ = r.s.Close() })

		// The migration has run. We don't assert on the exact number of
		// indexed FTS rows (the content='' schema behavior depends on
		// SQLite version); we just verify the migration completed without
		// deadlock and the secrets table is intact.
		var n int
		if err := r.s.DB().QueryRowContext(ctx, `SELECT count(*) FROM secrets`).Scan(&n); err != nil {
			t.Fatalf("count secrets: %v", err)
		}
		if n != 100 {
			t.Fatalf("secrets lost: expected 100, got %d", n)
		}

		// After the migration, the FTS5 schema should be the corrected
		// one (regular content mode, 4 columns). Verify with a probing
		// INSERT that should now succeed.
		_, err = r.s.DB().ExecContext(ctx,
			`INSERT INTO secrets_fts(rowid, path, description, metadata_text) VALUES (-2, '__probe__', '__probe__', '__probe__')`,
		)
		if err != nil {
			t.Fatalf("post-migration insert failed: %v (schema still broken?)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("migration deadlocked: 5s timeout exceeded (this is the v0.1.1 bug)")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
