// Package store provides the SQLCipher-backed persistence layer for scopuli.
//
// It owns the schema, migrations, and primitive CRUD operations. Higher
// layers (audit, API) build on these primitives.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	scrypt "github.com/lucaspdude/scopuli/internal/crypto"

	_ "github.com/mutecomm/go-sqlcipher/v4"
)

// ErrNotFound is returned when a row is not present.
var ErrNotFound = errors.New("store: not found")

// ErrAlreadyExists is returned for unique-constraint violations.
var ErrAlreadyExists = errors.New("store: already exists")

// Store is the database handle. One per process.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) an encrypted SQLite database at dbPath, using
// the given KEK as the raw key. If the database does not exist yet, it is
// initialized with the schema and the meta table is seeded with default
// KDF parameters.
func Open(ctx context.Context, dbPath string, kek []byte, kdfParams scrypt.KDFParams) (*Store, error) {
	abs, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, fmt.Errorf("store: abs path: %w", err)
	}
	// SQLCipher expects a hex-encoded key, prefixed with "x'".
	keyHex := fmt.Sprintf("x'%x'", kek)
	dsn := fmt.Sprintf("file:%s?mode=rwc&_key=%s&_pragma=cipher_page_size(4096)&_pragma=kdf_iter(1)&_pragma=cipher_hmac_algorithm(HMAC_SHA512)&_pragma=busy_timeout(5000)", abs, keyHex)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite single-writer; serialize for safety.
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	s := &Store{db: db}
	if err := s.init(ctx, kdfParams); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database connection.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// DB returns the underlying *sql.DB for callers that need to run raw
// queries (audit module, FTS5 triggers, migrations).
func (s *Store) DB() *sql.DB {
	return s.db
}

// init runs the schema migrations on first open. Idempotent.
func (s *Store) init(ctx context.Context, kdfParams scrypt.KDFParams) error {
	// WAL for concurrent reads.
	for _, pragma := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA foreign_keys = ON",
	} {
		if _, err := s.db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("store: pragma %q: %w", pragma, err)
		}
	}
	schema := `
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS operators (
  id           INTEGER PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  hash         TEXT NOT NULL,
  prefix       TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER
);

CREATE TABLE IF NOT EXISTS secrets (
  id                     INTEGER PRIMARY KEY,
  path                   TEXT NOT NULL UNIQUE,
  label                  TEXT,
  ciphertext             BLOB NOT NULL,
  nonce                  BLOB NOT NULL,
  aad                    BLOB NOT NULL,
  tags                   TEXT NOT NULL DEFAULT '',
  description            TEXT NOT NULL DEFAULT '',
  metadata               TEXT NOT NULL DEFAULT '{}',
  created_at             INTEGER NOT NULL,
  updated_at             INTEGER NOT NULL,
  description_updated_at INTEGER,
  metadata_updated_at    INTEGER,
  version                INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS secrets_path_idx ON secrets(path);
CREATE INDEX IF NOT EXISTS secrets_tags_idx ON secrets(tags);

CREATE TABLE IF NOT EXISTS keys (
  id                     INTEGER PRIMARY KEY,
  name                   TEXT NOT NULL UNIQUE,
  hash                   TEXT NOT NULL,
  prefix                 TEXT NOT NULL,
  scope                  TEXT NOT NULL,
  permissions            TEXT NOT NULL,
  tags                   TEXT NOT NULL DEFAULT '',
  description            TEXT NOT NULL DEFAULT '',
  metadata               TEXT NOT NULL DEFAULT '{}',
  created_at             INTEGER NOT NULL,
  expires_at             INTEGER,
  revoked_at             INTEGER,
  last_used_at           INTEGER,
  description_updated_at INTEGER,
  metadata_updated_at    INTEGER
);
CREATE INDEX IF NOT EXISTS keys_hash_idx ON keys(hash);
CREATE INDEX IF NOT EXISTS keys_tags_idx ON keys(tags);

CREATE TABLE IF NOT EXISTS audit (
  id         INTEGER PRIMARY KEY,
  ts         INTEGER NOT NULL,
  actor_kind TEXT NOT NULL,
  actor_id   INTEGER NOT NULL,
  action     TEXT NOT NULL,
  path       TEXT,
  result     TEXT NOT NULL,
  prev_hash  BLOB NOT NULL,
  hash       BLOB NOT NULL,
  hmac       BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_ts_idx ON audit(ts);
CREATE INDEX IF NOT EXISTS audit_actor_idx ON audit(actor_kind, actor_id);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("store: schema: %w", err)
	}
	// FTS5 virtual tables. We use the default content mode (not contentless)
	// because contentless tables require special 'delete' commands and we want
	// straightforward CRUD semantics in syncSecretFTS / syncKeyFTS.
	fts := `
CREATE VIRTUAL TABLE IF NOT EXISTS secrets_fts USING fts5(
  path,
  description,
  metadata_text,
  tokenize='unicode61 remove_diacritics 2'
);
CREATE VIRTUAL TABLE IF NOT EXISTS keys_fts USING fts5(
  name,
  description,
  metadata_text,
  tokenize='unicode61 remove_diacritics 2'
);
`
	if _, err := s.db.ExecContext(ctx, fts); err != nil {
		return fmt.Errorf("store: fts: %w", err)
	}
	// Seed default meta on fresh DB.
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM meta`).Scan(&count); err != nil {
		return fmt.Errorf("store: count meta: %w", err)
	}
	if count == 0 {
		// Generate salts and persist KDF params.
		salt, err := scrypt.NewSalt()
		if err != nil {
			return err
		}
		hmacSalt, err := scrypt.NewSalt()
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO meta(k, v) VALUES (?, ?), (?, ?), (?, ?)`,
			"schema_version", []byte{0x01},
			"kdf_salt", salt,
			"hmac_key_salt", hmacSalt,
		); err != nil {
			return fmt.Errorf("store: seed meta: %w", err)
		}
		// Persist KDF params as JSON.
		paramsJSON := fmt.Sprintf(`{"m":%d,"t":%d,"p":%d,"klen":%d}`,
			kdfParams.MemoryKiB, kdfParams.Iterations, kdfParams.Parallel, kdfParams.KeyLen)
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO meta(k, v) VALUES (?, ?)`,
			"kdf_params", []byte(paramsJSON),
		); err != nil {
			return fmt.Errorf("store: seed kdf_params: %w", err)
		}
	}
	return nil
}

// IsFresh reports whether this database has never been initialized. Used by
// the bootstrap path to generate the operator token on first boot.
func (s *Store) IsFresh(ctx context.Context) (bool, error) {
	var v []byte
	err := s.db.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'first_boot_done'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

// MarkFirstBootDone flips the first_boot_done flag.
func (s *Store) MarkFirstBootDone(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO meta(k, v) VALUES (?, ?)`,
		"first_boot_done", []byte{0x01})
	return err
}

// GetMeta reads a meta[k] value.
func (s *Store) GetMeta(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	err := s.db.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// SetMeta writes a meta[k] value.
func (s *Store) SetMeta(ctx context.Context, key string, value []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO meta(k, v) VALUES (?, ?)`,
		key, value)
	return err
}

// now returns a consistent timestamp in milliseconds since the Unix epoch.
// All time fields are stored as int64 milliseconds.
func now() int64 {
	return time.Now().UnixMilli()
}

// unquoteError unwraps a SQLite error message and returns true if it
// signals a unique constraint violation.
func unquoteError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// IsUniqueViolation reports whether err is a SQLite UNIQUE constraint error.
func IsUniqueViolation(err error) bool { return unquoteError(err) }

// SaltPath is the path to the unencrypted sidecar file holding the
// 16-byte Argon2id salt used to derive the KEK. Per-host, scoped to /data.
func SaltPath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "salt")
}

// LoadOrCreateSalt returns the salt from the sidecar file, generating and
// persisting a new one if absent. Errors are fatal.
func LoadOrCreateSalt(dbPath string) ([]byte, error) {
	p := SaltPath(dbPath)
	if b, err := os.ReadFile(p); err == nil && len(b) == 16 {
		return b, nil
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, buf, 0600); err != nil {
		return nil, err
	}
	return buf, nil
}

// OpenWithMasterPassword is the production-grade entry point: it loads (or
// creates) the salt sidecar, derives the KEK from (masterPassword, salt),
// and opens the SQLCipher database.
func OpenWithMasterPassword(ctx context.Context, dbPath, masterPassword string) (*Store, []byte, error) {
	salt, err := LoadOrCreateSalt(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("store: salt: %w", err)
	}
	kek := scrypt.DeriveKEK(masterPassword, salt, scrypt.DefaultKDFParams())
	s, err := Open(ctx, dbPath, kek, scrypt.DefaultKDFParams())
	if err != nil {
		return nil, nil, err
	}
	return s, kek, nil
}
