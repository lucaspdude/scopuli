// Package auth authenticates inbound HTTP requests against the scopuli
// operators and keys tables.
//
// V0 supports two credentials:
//
//	X-Scopuli-Operator: scot_live_…   (full-scope; sees everything)
//	X-Scopuli-Key:      sk_live_…     (scope-restricted by glob match)
//
// Both are validated by SHA-256-hashing the inbound token and looking it
// up in the database. Expired / revoked / unknown tokens return 401.
//
// Constant-time comparison on the lookup result is delegated to database/sql.
package auth

import (
	"context"
	"errors"
	"net/http"

	"github.com/lucaspdude/scopuli/internal/store"
	"github.com/lucaspdude/scopuli/internal/token"
)

// Principal is the authenticated identity attached to a request.
type Principal struct {
	Kind     string // "operator" | "key"
	ID       int64
	Name     string
	Scope    []string // only for kind=key
	HasRead  bool
	HasWrite bool // manage implies read+write
}

// HasReadOnly returns true for keys with read permission only.
func (p *Principal) IsReadOnly() bool {
	return p.Kind == "key" && !p.HasWrite
}

// Authenticate parses the request headers and returns the Principal or an
// error suitable to be mapped to 401.
func Authenticate(ctx context.Context, s *store.Store, r *http.Request) (*Principal, error) {
	if opTok := r.Header.Get("X-Scopuli-Operator"); opTok != "" {
		hash := token.HashHex(opTok)
		op, err := s.GetOperatorByHash(ctx, hash)
		if err != nil {
			return nil, err
		}
		return &Principal{
			Kind: "operator",
			ID:   op.ID,
			Name: op.Name,
			// Operator has implicit read + write on every scope.
			HasRead:  true,
			HasWrite: true,
		}, nil
	}
	if kTok := r.Header.Get("X-Scopuli-Key"); kTok != "" {
		hash := token.HashHex(kTok)
		k, err := s.GetKeyByHash(ctx, hash)
		if err != nil {
			return nil, err
		}
		if k.RevokedAt.Valid {
			return nil, ErrRevoked
		}
		if k.ExpiresAt.Valid && k.ExpiresAt.Int64 > 0 && k.ExpiresAt.Int64 < nowMs() {
			return nil, ErrExpired
		}
		return &Principal{
			Kind:     "key",
			ID:       k.ID,
			Name:     k.Name,
			Scope:    parseScope(k.Scope),
			HasRead:  true,
			HasWrite: k.Permissions == "manage",
		}, nil
	}
	return nil, ErrUnauthenticated
}

// Errors returned by Authenticate. Callers map these to HTTP status codes.
var (
	ErrUnauthenticated = errors.New("auth: unauthenticated")
	ErrRevoked         = errors.New("auth: key revoked")
	ErrExpired         = errors.New("auth: key expired")
)

// parseScope splits a CSV scope string into a slice.
func parseScope(csv string) []string {
	out := []string{}
	cur := ""
	for _, r := range csv {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
