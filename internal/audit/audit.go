// Package audit implements the append-only audit chain.
//
// Each entry is:
//
//	prev_hash: SHA-256 of the previous row's hash (or 32 zero bytes for the first row)
//	hash:      SHA-256(prev_hash || canonical(entry without hash/prev_hash/hmac))
//	hmac:      HMAC-SHA-256(AUDIT_HMAC_KEY, hash)
//
// The chain is verifiable: `verify` walks the rows in id order and asserts
// that each row's hash and hmac are consistent. Tampering anywhere breaks
// the chain at the first modified row.
//
// The HMAC key is derived from the master password using a separate Argon2id
// salt (so a leak of the KEK doesn't trivially leak the audit HMAC key).
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	scrypt "github.com/lucaspdude/scopuli/internal/crypto"
	"github.com/lucaspdude/scopuli/internal/store"
)

// Entry is a single audit row.
type Entry struct {
	ID        int64
	TS        int64  // ms since epoch
	ActorKind string // 'operator' | 'key'
	ActorID   int64
	Action    string
	Path      string
	Result    string
}

// Logger writes audit entries with the chain hash + HMAC.
type Logger struct {
	store    *store.Store
	hmacKey  []byte
	zeroHash [32]byte
}

// NewLogger constructs a Logger. hmacKey is typically derived from the
// master password via token.AuditHMACKey.
func NewLogger(s *store.Store, hmacKey []byte) *Logger {
	return &Logger{store: s, hmacKey: hmacKey}
}

// Append writes a new audit entry. The hash chain is updated atomically.
// Returns the ID of the inserted row.
func (l *Logger) Append(ctx context.Context, e Entry) (int64, error) {
	tx, err := l.store.DB().BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	// Get last hash (or zero hash for first row).
	var prevHash []byte
	err = tx.QueryRowContext(ctx, `SELECT hash FROM audit ORDER BY id DESC LIMIT 1`).Scan(&prevHash)
	if errors.Is(err, sql.ErrNoRows) {
		prevHash = l.zeroHash[:]
	} else if err != nil {
		return 0, err
	}
	if len(prevHash) != 32 {
		return 0, fmt.Errorf("audit: prev hash length %d, want 32", len(prevHash))
	}

	canon, err := canonicalJSON(e)
	if err != nil {
		return 0, err
	}
	preimage := append(prevHash, canon...)
	hash := scrypt.SHA256(preimage)
	hmacVal := scrypt.HMAC(l.hmacKey, hash)

	res, err := tx.ExecContext(ctx,
		`INSERT INTO audit(ts, actor_kind, actor_id, action, path, result,
		                  prev_hash, hash, hmac)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS, e.ActorKind, e.ActorID, e.Action, nullString(e.Path), e.Result,
		prevHash, hash, hmacVal,
	)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

// Verify walks the chain and returns the first broken row (id=0 if all ok).
func (l *Logger) Verify(ctx context.Context) (ok bool, brokenID int64, expected, got []byte, err error) {
	rows, err := l.store.DB().QueryContext(ctx,
		`SELECT id, ts, actor_kind, actor_id, action, path, result, prev_hash, hash, hmac
		 FROM audit ORDER BY id`)
	if err != nil {
		return false, 0, nil, nil, err
	}
	defer rows.Close()

	var lastHash []byte = l.zeroHash[:]
	var lastID int64
	for rows.Next() {
		var e Entry
		var prevHash, hash, hmacVal []byte
		var path sql.NullString
		if err := rows.Scan(&e.ID, &e.TS, &e.ActorKind, &e.ActorID, &e.Action,
			&path, &e.Result, &prevHash, &hash, &hmacVal); err != nil {
			return false, 0, nil, nil, err
		}
		e.Path = path.String
		// prev_hash must equal previous row's hash.
		if !bytesEqual(prevHash, lastHash) {
			return false, e.ID, lastHash, prevHash, nil
		}
		canon, err := canonicalJSON(e)
		if err != nil {
			return false, e.ID, nil, nil, err
		}
		wantHash := scrypt.SHA256(append(prevHash, canon...))
		if !bytesEqual(hash, wantHash) {
			return false, e.ID, wantHash, hash, nil
		}
		wantHMAC := scrypt.HMAC(l.hmacKey, hash)
		if !bytesEqual(hmacVal, wantHMAC) {
			return false, e.ID, wantHMAC, hmacVal, nil
		}
		lastHash = hash
		lastID = e.ID
	}
	if err := rows.Err(); err != nil {
		return false, 0, nil, nil, err
	}
	_ = lastID
	return true, 0, nil, nil, nil
}

// List returns audit entries with optional filters. Used by `scopuli audit list`.
func (l *Logger) List(ctx context.Context, sinceMS, keyID int64, limit int) ([]Entry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := `SELECT id, ts, actor_kind, actor_id, action, path, result FROM audit WHERE 1=1`
	args := []any{}
	if sinceMS > 0 {
		q += ` AND ts >= ?`
		args = append(args, sinceMS)
	}
	if keyID > 0 {
		q += ` AND actor_kind = 'key' AND actor_id = ?`
		args = append(args, keyID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	return scanAuditRows(l.store.DB(), ctx, q, args...)
}

// auditFilters builds the WHERE clause (+args) shared by Query and Count.
// sinceMS filters by ts >= sinceMS, keyID filters by key actor id, and
// actionSub is a case-insensitive substring match on the action column.
func auditFilters(sinceMS, keyID int64, actionSub string) (string, []any) {
	q := ` WHERE 1=1`
	args := []any{}
	if sinceMS > 0 {
		q += ` AND ts >= ?`
		args = append(args, sinceMS)
	}
	if keyID > 0 {
		q += ` AND actor_kind = 'key' AND actor_id = ?`
		args = append(args, keyID)
	}
	if actionSub != "" {
		q += ` AND action LIKE ? ESCAPE '\'`
		args = append(args, "%"+escapeLike(actionSub)+"%")
	}
	return q, args
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// Query returns audit entries newest-first with optional filters. beforeID
// > 0 pages to entries older than that id (cursor pagination for the web
// UI, avoiding the duplicate/skip edge of ts-based paging). limit caps the
// page.
func (l *Logger) Query(ctx context.Context, beforeID, sinceMS, keyID int64, actionSub string, limit int) ([]Entry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := `SELECT id, ts, actor_kind, actor_id, action, path, result FROM audit`
	where, args := auditFilters(sinceMS, keyID, actionSub)
	q += where
	if beforeID > 0 {
		q += ` AND id < ?`
		args = append(args, beforeID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	return scanAuditRows(l.store.DB(), ctx, q, args...)
}

// Count returns the number of audit entries matching the filters.
func (l *Logger) Count(ctx context.Context, sinceMS, keyID int64, actionSub string) (int64, error) {
	q := `SELECT COUNT(*) FROM audit`
	where, args := auditFilters(sinceMS, keyID, actionSub)
	q += where
	var n int64
	err := l.store.DB().QueryRowContext(ctx, q, args...).Scan(&n)
	return n, err
}

// scanAuditRows reads audit rows from the given query into []Entry.
func scanAuditRows(db *sql.DB, ctx context.Context, q string, args ...any) ([]Entry, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var path sql.NullString
		if err := rows.Scan(&e.ID, &e.TS, &e.ActorKind, &e.ActorID, &e.Action, &path, &e.Result); err != nil {
			return nil, err
		}
		e.Path = path.String
		out = append(out, e)
	}
	return out, rows.Err()
}

// canonicalJSON produces a stable JSON encoding of the entry, with sorted
// keys and no whitespace, used to compute the chain hash.
func canonicalJSON(e Entry) ([]byte, error) {
	// Use a map with sorted keys for stability.
	m := map[string]any{
		"ts":         e.TS,
		"actor_kind": e.ActorKind,
		"actor_id":   e.ActorID,
		"action":     e.Action,
		"path":       e.Path,
		"result":     e.Result,
	}
	return json.Marshal(m)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// nullString returns a sql.NullString that is valid only when s is non-nil.
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
