package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// Key is the in-memory representation of a keys row.
type Key struct {
	ID                   int64
	Name                 string
	Hash                 string
	Prefix               string
	Scope                string // CSV of glob patterns
	Permissions          string // 'read' | 'manage'
	Tags                 string
	Description          string
	Metadata             string
	CreatedAt            int64
	ExpiresAt            sql.NullInt64
	RevokedAt            sql.NullInt64
	LastUsedAt           sql.NullInt64
	DescriptionUpdatedAt sql.NullInt64
	MetadataUpdatedAt    sql.NullInt64
}

// CreateKey inserts a new key row.
func (s *Store) CreateKey(ctx context.Context, k *Key) error {
	now := now()
	k.CreatedAt = now
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO keys(name, hash, prefix, scope, permissions, tags, description,
		                 metadata, created_at, expires_at, revoked_at, last_used_at,
		                 description_updated_at, metadata_updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.Name, k.Hash, k.Prefix, k.Scope, k.Permissions, k.Tags, k.Description,
		k.Metadata, k.CreatedAt, k.ExpiresAt, k.RevokedAt, k.LastUsedAt,
		k.DescriptionUpdatedAt, k.MetadataUpdatedAt,
	)
	if err != nil {
		if IsUniqueViolation(err) {
			return ErrAlreadyExists
		}
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	k.ID = id
	return s.syncKeyFTS(ctx, k)
}

// GetKeyByName returns the key with the given name (or ErrNotFound).
func (s *Store) GetKeyByName(ctx context.Context, name string) (*Key, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, hash, prefix, scope, permissions, tags, description,
		        metadata, created_at, expires_at, revoked_at, last_used_at,
		        description_updated_at, metadata_updated_at
		 FROM keys WHERE name = ?`, name,
	)
	var k Key
	err := row.Scan(
		&k.ID, &k.Name, &k.Hash, &k.Prefix, &k.Scope, &k.Permissions,
		&k.Tags, &k.Description, &k.Metadata, &k.CreatedAt, &k.ExpiresAt,
		&k.RevokedAt, &k.LastUsedAt, &k.DescriptionUpdatedAt, &k.MetadataUpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// GetKeyByHash returns the key with the given hex hash (or ErrNotFound).
func (s *Store) GetKeyByHash(ctx context.Context, hash string) (*Key, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, hash, prefix, scope, permissions, tags, description,
		        metadata, created_at, expires_at, revoked_at, last_used_at,
		        description_updated_at, metadata_updated_at
		 FROM keys WHERE hash = ?`, hash,
	)
	var k Key
	err := row.Scan(
		&k.ID, &k.Name, &k.Hash, &k.Prefix, &k.Scope, &k.Permissions,
		&k.Tags, &k.Description, &k.Metadata, &k.CreatedAt, &k.ExpiresAt,
		&k.RevokedAt, &k.LastUsedAt, &k.DescriptionUpdatedAt, &k.MetadataUpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// UpdateKey updates mutable fields (scope, permissions, expiry, tags,
// description, metadata). revokes and last_used are handled separately.
// Description and metadata updates bump their respective *_updated_at
// timestamps.
func (s *Store) UpdateKey(ctx context.Context, k *Key) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE keys SET scope = ?, permissions = ?, expires_at = ?, tags = ?,
		                 description = ?, metadata = ?, description_updated_at = ?,
		                 metadata_updated_at = ?
		 WHERE id = ?`,
		k.Scope, k.Permissions, k.ExpiresAt, k.Tags, k.Description, k.Metadata,
		k.DescriptionUpdatedAt, k.MetadataUpdatedAt, k.ID,
	)
	if err != nil {
		return err
	}
	return s.syncKeyFTS(ctx, k)
}

// RevokeKey marks a key as revoked.
func (s *Store) RevokeKey(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE keys SET revoked_at = ? WHERE id = ?`,
		now(), id)
	return err
}

// TouchKeyLastUsed bumps the last_used_at field.
func (s *Store) TouchKeyLastUsed(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE keys SET last_used_at = ? WHERE id = ?`,
		now(), id)
	return err
}

// ListKeys returns all non-revoked keys. Used by `keys list`.
func (s *Store) ListKeys(ctx context.Context, all bool) ([]*Key, error) {
	q := `SELECT id, name, hash, prefix, scope, permissions, tags, description,
	             metadata, created_at, expires_at, revoked_at, last_used_at,
	             description_updated_at, metadata_updated_at
	      FROM keys`
	if !all {
		q += ` WHERE revoked_at IS NULL`
	}
	q += ` ORDER BY name`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Key
	for rows.Next() {
		var k Key
		if err := rows.Scan(
			&k.ID, &k.Name, &k.Hash, &k.Prefix, &k.Scope, &k.Permissions,
			&k.Tags, &k.Description, &k.Metadata, &k.CreatedAt, &k.ExpiresAt,
			&k.RevokedAt, &k.LastUsedAt, &k.DescriptionUpdatedAt, &k.MetadataUpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, &k)
	}
	return out, rows.Err()
}

// SearchKeys runs an FTS5 query against keys.
func (s *Store) SearchKeys(ctx context.Context, query string, limit int) ([]int64, error) {
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT rowid FROM keys_fts WHERE keys_fts MATCH ? ORDER BY rank LIMIT ?`,
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

// syncKeyFTS keeps keys_fts in sync.
func (s *Store) syncKeyFTS(ctx context.Context, k *Key) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM keys_fts WHERE rowid = ?`, k.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO keys_fts(rowid, name, description, metadata_text) VALUES (?, ?, ?, ?)`,
		k.ID, k.Name, k.Description, flattenMetadata(k.Metadata),
	); err != nil {
		return err
	}
	return tx.Commit()
}

// ScopeIncludes returns true if path matches any glob in the scope CSV.
func (k *Key) ScopeIncludes(path string, matcher func(pattern, path string) bool) bool {
	for _, pat := range strings.Split(k.Scope, ",") {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if matcher(pat, path) {
			return true
		}
	}
	return false
}
