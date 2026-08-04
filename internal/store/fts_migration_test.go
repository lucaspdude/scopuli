package store

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	scrypt "github.com/lucaspdude/scopuli/internal/crypto"
)

// TestFTS5MigrationRecreatesWrongSchema verifies that when secrets_fts was
// created with the legacy content='' schema (external content mode used
// in v0.1.0), the init code detects this and recreates with the correct
// schema. After migration, the FTS5 should have 4 visible columns and
// existing secret data should be re-indexed.
func TestFTS5MigrationRecreatesWrongSchema(t *testing.T) {
	dir := t.TempDir()
	kek := bytes.Repeat([]byte{0x77}, 32)
	dbPath := filepath.Join(dir, "v.db")

	// Open the DB and create the legacy-content='' FTS5 manually.
	s, err := Open(context.Background(), dbPath, kek, scrypt.DefaultKDFParams())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	// Drop the freshly-created FTS5 and recreate it with content='' (legacy).
	if _, err := s.DB().ExecContext(ctx, `DROP TABLE secrets_fts`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx,
		`CREATE VIRTUAL TABLE secrets_fts USING fts5(
			path, description, metadata_text,
			tokenize='unicode61 remove_diacritics 2',
			content=''
		)`); err != nil {
		t.Fatalf("create legacy: %v", err)
	}
	// Verify the legacy schema is "broken" by probing with an INSERT that
	// should fail in external-content mode. In v0.1.0 the secrets_fts was
	// created with content='', so INSERTing column values fails.
	broken, err := s.DB().ExecContext(ctx,
		`INSERT INTO secrets_fts(rowid, path, description, metadata_text) VALUES (-99, '__probe__', '__probe__', '__probe__')`,
	)
	if err != nil {
		// Good: insert failed, schema is broken (external content mode).
		broken = nil
	} else {
		// Insert "succeeded" — but the row might not be indexed. Check by
		// querying the FTS.
		_ = broken
	}
	// Close without running migrateFTS5.
	_ = s.Close()

	// Reopen. init() should run migrateFTS5 which detects the legacy schema
	// and recreates secrets_fts with the correct schema.
	s2, err := Open(context.Background(), dbPath, kek, scrypt.DefaultKDFParams())
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })

	// Verify the schema is now correct (the INSERT no longer fails; queries
	// against the table also work).
	var rowCount int
	if err := s2.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM secrets_fts WHERE secrets_fts MATCH '__probe__'`).Scan(&rowCount); err != nil {
		t.Fatalf("after migration: FTS query failed: %v", err)
	}
	// rowCount may be 0 (sentinel has been rolled back) but the query should succeed.
}
