package store

import (
	"context"
	"database/sql"
	"errors"
)

// Operator is the in-memory representation of an operators row.
type Operator struct {
	ID         int64
	Name       string
	Hash       string // hex(SHA-256(token))
	Prefix     string // for display only
	CreatedAt  int64
	LastUsedAt sql.NullInt64
}

// CreateOperator inserts a new operator row.
func (s *Store) CreateOperator(ctx context.Context, op *Operator) error {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO operators(name, hash, prefix, created_at) VALUES (?, ?, ?, ?)`,
		op.Name, op.Hash, op.Prefix, op.CreatedAt,
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	op.ID = id
	return nil
}

// GetOperatorByHash finds an operator by the hex hash of its token.
func (s *Store) GetOperatorByHash(ctx context.Context, hash string) (*Operator, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, hash, prefix, created_at, last_used_at FROM operators WHERE hash = ?`,
		hash,
	)
	var op Operator
	if err := row.Scan(&op.ID, &op.Name, &op.Hash, &op.Prefix, &op.CreatedAt, &op.LastUsedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &op, nil
}

// GetOperatorByName finds an operator by its name (V0 always 'primary').
func (s *Store) GetOperatorByName(ctx context.Context, name string) (*Operator, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, hash, prefix, created_at, last_used_at FROM operators WHERE name = ?`,
		name,
	)
	var op Operator
	if err := row.Scan(&op.ID, &op.Name, &op.Hash, &op.Prefix, &op.CreatedAt, &op.LastUsedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &op, nil
}

// UpdateOperatorHash rotates the operator's token hash.
func (s *Store) UpdateOperatorHash(ctx context.Context, id int64, newHash, newPrefix string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE operators SET hash = ?, prefix = ? WHERE id = ?`,
		newHash, newPrefix, id)
	return err
}

// TouchOperatorLastUsed bumps the last_used_at field.
func (s *Store) TouchOperatorLastUsed(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE operators SET last_used_at = ? WHERE id = ?`,
		now(), id)
	return err
}
