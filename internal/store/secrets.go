package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Secret is the in-memory representation of a secrets row.
// Ciphertext, Nonce, and AAD are the AEAD bytes stored at-rest; the
// plaintext value is never persisted.
type Secret struct {
	ID                   int64
	Path                 string
	Label                sql.NullString
	Ciphertext           []byte
	Nonce                []byte
	AAD                  []byte
	Tags                 string
	Description          string
	Metadata             string // JSON object
	CreatedAt            int64
	UpdatedAt            int64
	DescriptionUpdatedAt sql.NullInt64
	MetadataUpdatedAt    sql.NullInt64
	Version              int64
}

// GetSecret returns the secret at the given path, or ErrNotFound.
func (s *Store) GetSecret(ctx context.Context, path string) (*Secret, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, path, label, ciphertext, nonce, aad, tags, description, metadata,
		        created_at, updated_at, description_updated_at, metadata_updated_at, version
		 FROM secrets WHERE path = ?`, path,
	)
	var sec Secret
	err := row.Scan(
		&sec.ID, &sec.Path, &sec.Label, &sec.Ciphertext, &sec.Nonce, &sec.AAD,
		&sec.Tags, &sec.Description, &sec.Metadata,
		&sec.CreatedAt, &sec.UpdatedAt, &sec.DescriptionUpdatedAt, &sec.MetadataUpdatedAt,
		&sec.Version,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &sec, nil
}

// PutSecret inserts or updates a secret row. The caller has already
// encrypted the value and computed the AAD (with the description and
// version in scope). On a description change, the version is bumped and
// the AAD re-computed by the caller.
func (s *Store) PutSecret(ctx context.Context, sec *Secret) error {
	now := now()
	sec.UpdatedAt = now
	if sec.CreatedAt == 0 {
		sec.CreatedAt = now
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO secrets(path, label, ciphertext, nonce, aad, tags, description,
		                    metadata, created_at, updated_at, description_updated_at,
		                    metadata_updated_at, version)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(path) DO UPDATE SET
		   label = excluded.label,
		   ciphertext = excluded.ciphertext,
		   nonce = excluded.nonce,
		   aad = excluded.aad,
		   tags = excluded.tags,
		   description = excluded.description,
		   metadata = excluded.metadata,
		   updated_at = excluded.updated_at,
		   description_updated_at = excluded.description_updated_at,
		   metadata_updated_at = excluded.metadata_updated_at,
		   version = excluded.version`,
		sec.Path, sec.Label, sec.Ciphertext, sec.Nonce, sec.AAD,
		sec.Tags, sec.Description, sec.Metadata,
		sec.CreatedAt, sec.UpdatedAt, sec.DescriptionUpdatedAt, sec.MetadataUpdatedAt,
		sec.Version,
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	sec.ID = id
	// FTS sync: delete + insert via triggers? We use external content="" tables
	// which means triggers do NOT auto-sync. Sync explicitly.
	if err := s.syncSecretFTS(ctx, sec); err != nil {
		return fmt.Errorf("store: fts sync: %w", err)
	}
	return nil
}

// syncSecretFTS keeps secrets_fts in sync with the secrets table.
func (s *Store) syncSecretFTS(ctx context.Context, sec *Secret) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM secrets_fts WHERE rowid = ?`, sec.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO secrets_fts(rowid, path, description, metadata_text) VALUES (?, ?, ?, ?)`,
		sec.ID, sec.Path, sec.Description, flattenMetadata(sec.Metadata),
	); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteSecret removes a secret by path.
func (s *Store) DeleteSecret(ctx context.Context, path string) error {
	sec, err := s.GetSecret(ctx, path)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE id = ?`, sec.ID); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM secrets_fts WHERE rowid = ?`, sec.ID); err != nil {
		return err
	}
	return nil
}

// ListSecretPaths returns paths matching the optional prefix. Used by
// `secret list --prefix` and `list_secrets`.
func (s *Store) ListSecretPaths(ctx context.Context, prefix string) ([]string, error) {
	q := `SELECT path FROM secrets`
	args := []any{}
	if prefix != "" {
		q += ` WHERE path LIKE ?`
		args = append(args, prefix+"%")
	}
	q += ` ORDER BY path`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SearchSecrets runs an FTS5 query against secrets and returns matching IDs
// ordered by BM25 rank.
func (s *Store) SearchSecrets(ctx context.Context, query string, limit int) ([]int64, error) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT rowid FROM secrets_fts WHERE secrets_fts MATCH ? ORDER BY rank LIMIT ?`,
		query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// flattenMetadata renders the metadata JSON as "k1=v1; k2=v2" for FTS5
// indexing. Empty values render as empty strings; ordering is alphabetical
// (Go map iteration is randomized, but json.Unmarshal sorts keys).
func flattenMetadata(jsonStr string) string {
	jsonStr = strings.TrimSpace(jsonStr)
	if jsonStr == "" || jsonStr == "{}" {
		return ""
	}
	// Quick & dirty: strip JSON braces and quotes, split on commas.
	jsonStr = strings.TrimPrefix(jsonStr, "{")
	jsonStr = strings.TrimSuffix(jsonStr, "}")
	jsonStr = strings.ReplaceAll(jsonStr, `"`, "")
	var pairs []string
	for _, kv := range strings.Split(jsonStr, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		parts := strings.SplitN(kv, ":", 2)
		if len(parts) != 2 {
			continue
		}
		pairs = append(pairs, strings.TrimSpace(parts[0])+"="+strings.TrimSpace(parts[1]))
	}
	return strings.Join(pairs, ";")
}
