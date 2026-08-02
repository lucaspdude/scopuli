// Package api implements the scopuli HTTP API.
//
// Routes:
//
//	GET  /healthz
//	GET  /api/secrets?prefix=...
//	POST /api/secrets                       (operator or manage key)
//	GET  /api/secrets/{path}
//	DELETE /api/secrets/{path}              (operator or manage key)
//	POST /api/secrets/{path}/annotate
//	GET  /api/secrets/search?q=...
//	GET  /api/keys
//	POST /api/keys
//	GET  /api/keys/{name}
//	POST /api/keys/{name}/update
//	POST /api/keys/{name}/revoke
//	GET  /api/keys/search?q=...
//	GET  /api/audit?since=&key=&limit=
//	GET  /api/audit/verify
//	POST /api/operator/rotate
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/lucaspdude/scopuli/internal/audit"
	"github.com/lucaspdude/scopuli/internal/auth"
	"github.com/lucaspdude/scopuli/internal/crypto"
	"github.com/lucaspdude/scopuli/internal/metadata"
	"github.com/lucaspdude/scopuli/internal/scope"
	"github.com/lucaspdude/scopuli/internal/store"
	"github.com/lucaspdude/scopuli/internal/token"
)

// Server holds the dependencies needed by the HTTP handlers.
type Server struct {
	Store        *store.Store
	Audit        *audit.Logger
	KEK          []byte
	Bind         string
	LogLevel     string
	StartedAt    time.Time
	OperatorName string
}

// Routes builds a chi router with all scopuli endpoints.
func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(s.requestLogger)

	r.Get("/healthz", s.handleHealthz)

	r.Route("/api", func(r chi.Router) {
		r.Route("/secrets", func(r chi.Router) {
			r.With(s.requireAuth).Get("/", s.handleListSecrets)
			r.With(s.requireAuth).Post("/", s.handlePutSecret)
			r.With(s.requireAuth).Get("/search", s.handleSearchSecrets)
			r.With(s.requireAuth).Post("/annotate", s.handleAnnotateSecret)
			// Catch-all for GET / DELETE on /secrets/<path> where path may
			// contain slashes. chi's {path:*} greedy syntax is unreliable
			// across versions, so we route everything that hasn't matched
			// a literal to the path handler.
			r.With(s.requireAuth).Get("/*", s.handleGetSecretWildcard)
			r.With(s.requireAuth).Delete("/*", s.handleDeleteSecretWildcard)
		})
		r.Route("/keys", func(r chi.Router) {
			r.With(s.requireAuth).Get("/", s.handleListKeys)
			r.With(s.requireAuth).Post("/", s.handleCreateKey)
			r.With(s.requireAuth).Get("/search", s.handleSearchKeys)
			r.With(s.requireAuth).Get("/{name}", s.handleGetKey)
			r.With(s.requireAuth).Post("/{name}/update", s.handleUpdateKey)
			r.With(s.requireAuth).Post("/{name}/revoke", s.handleRevokeKey)
		})
		r.Route("/audit", func(r chi.Router) {
			r.With(s.requireOperator).Get("/", s.handleListAudit)
			r.With(s.requireOperator).Get("/verify", s.handleVerifyAudit)
		})
		r.Route("/operator", func(r chi.Router) {
			r.With(s.requireOperator).Post("/rotate", s.handleRotateOperator)
		})
	})
	return r
}

// requestLogger emits a structured slog line per request.
func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()
		next.ServeHTTP(ww, r)
		dur := time.Since(start)
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"bytes", ww.BytesWritten(),
			"duration_ms", dur.Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

// principalKey is unexported to avoid collisions with other packages.
type principalKey struct{}

// withPrincipal attaches a Principal to the request context.
func withPrincipal(r *http.Request, p *auth.Principal) *http.Request {
	ctx := context.WithValue(r.Context(), principalKey{}, p)
	return r.WithContext(ctx)
}

func principal(r *http.Request) *auth.Principal {
	v := r.Context().Value(principalKey{})
	if v == nil {
		return nil
	}
	if p, ok := v.(*auth.Principal); ok {
		return p
	}
	return nil
}

// requireAuth middleware authenticates and attaches *auth.Principal to the context.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := auth.Authenticate(r.Context(), s.Store, r)
		if err != nil {
			status := http.StatusUnauthorized
			msg := "unauthenticated"
			if errors.Is(err, auth.ErrRevoked) {
				msg = "key revoked"
			} else if errors.Is(err, auth.ErrExpired) {
				msg = "key expired"
			}
			writeErr(w, status, msg)
			return
		}
		next.ServeHTTP(w, withPrincipal(r, p))
	})
}

// requireOperator requires an operator-token auth.
func (s *Server) requireOperator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := auth.Authenticate(r.Context(), s.Store, r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "operator token required")
			return
		}
		if p.Kind != "operator" {
			writeErr(w, http.StatusForbidden, "operator only")
			return
		}
		next.ServeHTTP(w, withPrincipal(r, p))
	})
}

// --- handlers ---

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"started_at": s.StartedAt.Unix(),
		"uptime_s":   int(time.Since(s.StartedAt).Seconds()),
	})
}

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	paths, err := s.Store.ListSecretPaths(r.Context(), prefix)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list")
		return
	}
	p := principal(r)
	type item struct {
		Path        string `json:"path"`
		Label       string `json:"label,omitempty"`
		Tags        string `json:"tags,omitempty"`
		HasDesc     bool   `json:"has_description"`
		Description string `json:"description,omitempty"`
	}
	out := []item{}
	for _, pth := range paths {
		if !s.canAccessSecret(p, pth) {
			continue
		}
		sec, err := s.Store.GetSecret(r.Context(), pth)
		if err != nil {
			continue
		}
		out = append(out, item{
			Path:        sec.Path,
			Label:       sec.Label.String,
			Tags:        sec.Tags,
			HasDesc:     sec.Description != "",
			Description: sec.Description,
		})
	}
	s.auditAppend(r, p, "read.list", "", "ok")
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	pth := chi.URLParam(r, "path")
	if pth == "" {
		// Fallback: extract from URL path stripping /api/secrets/ prefix.
		pth = strings.TrimPrefix(r.URL.Path, "/api/secrets/")
		pth = strings.TrimSuffix(pth, "/")
	}
	if !s.canAccessSecret(principal(r), pth) {
		s.auditAppend(r, principal(r), "denied:out_of_scope", pth, "denied")
		writeErr(w, http.StatusForbidden, "out of scope")
		return
	}
	sec, err := s.Store.GetSecret(r.Context(), pth)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	aad := crypto.AADSecret(sec.Path, sec.Description, uint64(sec.Version))
	pt, err := crypto.Open(s.KEK, append(sec.Nonce, sec.Ciphertext...), aad[:])
	if err != nil {
		s.auditAppend(r, principal(r), "error:decrypt_failed", pth, "error")
		writeErr(w, http.StatusInternalServerError, "decrypt failed")
		return
	}
	s.auditAppend(r, principal(r), "read", pth, "ok")
	writeJSON(w, http.StatusOK, map[string]any{
		"path":        sec.Path,
		"value":       string(pt),
		"label":       sec.Label.String,
		"tags":        splitCSV(sec.Tags),
		"description": sec.Description,
		"metadata":    sec.Metadata,
		"version":     sec.Version,
	})
}

type putSecretReq struct {
	Path        string            `json:"path"`
	Value       string            `json:"value"`
	Label       string            `json:"label"`
	Tags        []string          `json:"tags"`
	Description string            `json:"description"`
	Metadata    map[string]string `json:"metadata"`
}

func (s *Server) handlePutSecret(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.Kind == "key" && !p.HasWrite {
		writeErr(w, http.StatusForbidden, "read-only key")
		return
	}
	var req putSecretReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.Path == "" {
		writeErr(w, http.StatusBadRequest, "path required")
		return
	}
	if !s.canAccessSecret(p, req.Path) {
		s.auditAppend(r, p, "denied:out_of_scope", req.Path, "denied")
		writeErr(w, http.StatusForbidden, "out of scope")
		return
	}
	tags, err := metadata.NormalizeTags(strings.Join(req.Tags, ","))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := metadata.ValidateDescription(req.Description); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	metaJSON := "{}"
	if req.Metadata != nil {
		metaJSON, err = metadata.NormalizeMetadata(toJSON(req.Metadata))
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	existing, _ := s.Store.GetSecret(r.Context(), req.Path)
	version := int64(1)
	now := time.Now().UnixMilli()
	descUpdated := sql.NullInt64{}
	metaUpdated := sql.NullInt64{}
	createdAt := now
	if existing != nil {
		version = existing.Version
		createdAt = existing.CreatedAt
	}
	if existing == nil || existing.Description != req.Description {
		version++
		descUpdated = sql.NullInt64{Int64: now, Valid: true}
	}
	if existing == nil || existing.Metadata != metaJSON {
		metaUpdated = sql.NullInt64{Int64: now, Valid: true}
	}
	aad := crypto.AADSecret(req.Path, req.Description, uint64(version))
	sealed, err := crypto.Seal(s.KEK, []byte(req.Value), aad[:])
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "encrypt failed")
		return
	}
	nonce := sealed[:crypto.NonceSize]
	ct := sealed[crypto.NonceSize:]
	sec := &store.Secret{
		Path:                 req.Path,
		Label:                sql.NullString{String: req.Label, Valid: req.Label != ""},
		Ciphertext:           ct,
		Nonce:                nonce,
		AAD:                  aad[:],
		Tags:                 tags,
		Description:          req.Description,
		Metadata:             metaJSON,
		CreatedAt:            createdAt,
		DescriptionUpdatedAt: descUpdated,
		MetadataUpdatedAt:    metaUpdated,
		Version:              version,
	}
	if err := s.Store.PutSecret(r.Context(), sec); err != nil {
		writeErr(w, http.StatusInternalServerError, "store")
		return
	}
	s.auditAppend(r, p, "write", req.Path, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteSecretWildcard(w http.ResponseWriter, r *http.Request) {
	s.handleDeleteSecret(w, r)
}

func (s *Server) handleGetSecretWildcard(w http.ResponseWriter, r *http.Request) {
	s.handleGetSecret(w, r)
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.Kind == "key" && !p.HasWrite {
		writeErr(w, http.StatusForbidden, "read-only key")
		return
	}
	pth := chi.URLParam(r, "path")
	if pth == "" {
		pth = strings.TrimPrefix(r.URL.Path, "/api/secrets/")
		pth = strings.TrimSuffix(pth, "/")
	}
	if !s.canAccessSecret(p, pth) {
		writeErr(w, http.StatusForbidden, "out of scope")
		return
	}
	if err := s.Store.DeleteSecret(r.Context(), pth); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete")
		return
	}
	s.auditAppend(r, p, "delete", pth, "ok")
	w.WriteHeader(http.StatusNoContent)
}

type annotateReq struct {
	AddTags       []string          `json:"add_tags"`
	RemoveTags    []string          `json:"remove_tags"`
	Description   *string           `json:"description,omitempty"`
	SetMetadata   map[string]string `json:"set_metadata"`
	UnsetMetadata []string          `json:"unset_metadata"`
}

func (s *Server) handleAnnotateSecret(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.Kind == "key" && !p.HasWrite {
		writeErr(w, http.StatusForbidden, "read-only key")
		return
	}
	pth := r.URL.Query().Get("path")
	if pth == "" {
		writeErr(w, http.StatusBadRequest, "path required (use ?path=...)")
		return
	}
	if !s.canAccessSecret(p, pth) {
		writeErr(w, http.StatusForbidden, "out of scope")
		return
	}
	var req annotateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	sec, err := s.Store.GetSecret(r.Context(), pth)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	now := time.Now().UnixMilli()
	newTags, err := metadata.MergeTags(sec.Tags, req.AddTags, req.RemoveTags)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	newMeta, err := metadata.MergeMetadata(sec.Metadata, req.SetMetadata, req.UnsetMetadata)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	newDesc := sec.Description
	if req.Description != nil {
		if err := metadata.ValidateDescription(*req.Description); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		newDesc = *req.Description
	}
	descChanged := newDesc != sec.Description
	metaChanged := newMeta != sec.Metadata
	if !descChanged && !metaChanged && newTags == sec.Tags {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	version := sec.Version
	if descChanged {
		version++
	}
	aad := crypto.AADSecret(sec.Path, newDesc, uint64(version))
	plain, err := crypto.Open(s.KEK, append(sec.Nonce, sec.Ciphertext...), sec.AAD)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "decrypt failed")
		return
	}
	sealed, err := crypto.Seal(s.KEK, plain, aad[:])
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "encrypt failed")
		return
	}
	sec.Ciphertext = sealed[crypto.NonceSize:]
	sec.Nonce = sealed[:crypto.NonceSize]
	sec.AAD = aad[:]
	sec.Tags = newTags
	sec.Description = newDesc
	sec.Metadata = newMeta
	sec.Version = version
	if descChanged {
		sec.DescriptionUpdatedAt = sql.NullInt64{Int64: now, Valid: true}
	}
	if metaChanged {
		sec.MetadataUpdatedAt = sql.NullInt64{Int64: now, Valid: true}
	}
	if err := s.Store.PutSecret(r.Context(), sec); err != nil {
		writeErr(w, http.StatusInternalServerError, "store")
		return
	}
	s.auditAppend(r, p, "secret.annotate", pth, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSearchSecrets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		writeErr(w, http.StatusBadRequest, "q required")
		return
	}
	ids, err := s.Store.SearchSecrets(r.Context(), q, 50)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p := principal(r)
	type item struct {
		Path        string `json:"path"`
		Label       string `json:"label"`
		Tags        string `json:"tags"`
		Description string `json:"description"`
		Metadata    string `json:"metadata"`
	}
	out := []item{}
	for _, id := range ids {
		row := s.Store.DB().QueryRowContext(r.Context(),
			`SELECT path, label, tags, description, metadata FROM secrets WHERE id = ?`, id)
		var it item
		var label sql.NullString
		if err := row.Scan(&it.Path, &label, &it.Tags, &it.Description, &it.Metadata); err != nil {
			continue
		}
		if label.Valid {
			it.Label = label.String
		}
		if !s.canAccessSecret(p, it.Path) {
			continue
		}
		out = append(out, it)
	}
	s.auditAppend(r, p, "search", q, "ok")
	writeJSON(w, http.StatusOK, out)
}

type createKeyReq struct {
	Name        string            `json:"name"`
	Scope       string            `json:"scope"`
	Permissions string            `json:"permissions"`
	ExpiresIn   string            `json:"expires_in,omitempty"`
	Tags        []string          `json:"tags"`
	Description string            `json:"description"`
	Metadata    map[string]string `json:"metadata"`
}

func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.Kind != "operator" {
		writeErr(w, http.StatusForbidden, "operator only")
		return
	}
	var req createKeyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.Name == "" || req.Scope == "" {
		writeErr(w, http.StatusBadRequest, "name and scope required")
		return
	}
	if req.Permissions != "read" && req.Permissions != "manage" {
		writeErr(w, http.StatusBadRequest, "permissions must be read or manage")
		return
	}
	tok, hash, prefix, err := token.AgentKey()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "key gen")
		return
	}
	tags, err := metadata.NormalizeTags(strings.Join(req.Tags, ","))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := metadata.ValidateDescription(req.Description); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	metaJSON := "{}"
	if req.Metadata != nil {
		metaJSON, err = metadata.NormalizeMetadata(toJSON(req.Metadata))
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	k := &store.Key{
		Name: req.Name, Hash: hash, Prefix: prefix, Scope: req.Scope,
		Permissions: req.Permissions, Tags: tags, Description: req.Description,
		Metadata: metaJSON,
	}
	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "expires_in: "+err.Error())
			return
		}
		k.ExpiresAt = sql.NullInt64{Int64: time.Now().Add(d).UnixMilli(), Valid: true}
	}
	if err := s.Store.CreateKey(r.Context(), k); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			writeErr(w, http.StatusConflict, "name exists")
			return
		}
		writeErr(w, http.StatusInternalServerError, "store")
		return
	}
	s.auditAppend(r, p, "key.create", req.Name, "ok")
	writeJSON(w, http.StatusOK, map[string]any{
		"key":         tok,
		"prefix":      prefix,
		"scope":       req.Scope,
		"permissions": req.Permissions,
		"expires_at":  k.ExpiresAt.Int64,
	})
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	keys, err := s.Store.ListKeys(r.Context(), p.Kind == "operator")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list")
		return
	}
	type item struct {
		Name        string `json:"name"`
		Prefix      string `json:"prefix"`
		Scope       string `json:"scope"`
		Permissions string `json:"permissions"`
		Tags        string `json:"tags"`
		HasDesc     bool   `json:"has_description"`
		ExpiresAt   int64  `json:"expires_at,omitempty"`
		RevokedAt   int64  `json:"revoked_at,omitempty"`
	}
	out := []item{}
	for _, k := range keys {
		if p.Kind == "key" && k.ID != p.ID {
			continue
		}
		out = append(out, item{
			Name: k.Name, Prefix: k.Prefix, Scope: k.Scope, Permissions: k.Permissions,
			Tags: k.Tags, HasDesc: k.Description != "",
			ExpiresAt: k.ExpiresAt.Int64, RevokedAt: k.RevokedAt.Int64,
		})
	}
	s.auditAppend(r, p, "key.list", "", "ok")
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetKey(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	name := chi.URLParam(r, "name")
	if p.Kind == "key" && p.Name != name {
		writeErr(w, http.StatusForbidden, "not your key")
		return
	}
	k, err := s.Store.GetKeyByName(r.Context(), name)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":        k.Name,
		"prefix":      k.Prefix,
		"scope":       k.Scope,
		"permissions": k.Permissions,
		"tags":        splitCSV(k.Tags),
		"description": k.Description,
		"metadata":    k.Metadata,
		"created_at":  k.CreatedAt,
		"expires_at":  k.ExpiresAt.Int64,
		"revoked_at":  k.RevokedAt.Int64,
	})
}

type updateKeyReq struct {
	Scope         *string           `json:"scope,omitempty"`
	Permissions   *string           `json:"permissions,omitempty"`
	ExpiresIn     *string           `json:"expires_in,omitempty"`
	AddTags       []string          `json:"add_tags"`
	RemoveTags    []string          `json:"remove_tags"`
	Description   *string           `json:"description,omitempty"`
	SetMetadata   map[string]string `json:"set_metadata"`
	UnsetMetadata []string          `json:"unset_metadata"`
}

func (s *Server) handleUpdateKey(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.Kind != "operator" {
		writeErr(w, http.StatusForbidden, "operator only")
		return
	}
	name := chi.URLParam(r, "name")
	k, err := s.Store.GetKeyByName(r.Context(), name)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	var req updateKeyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	now := time.Now().UnixMilli()
	if req.Scope != nil {
		k.Scope = *req.Scope
	}
	if req.Permissions != nil {
		if *req.Permissions != "read" && *req.Permissions != "manage" {
			writeErr(w, http.StatusBadRequest, "permissions must be read or manage")
			return
		}
		k.Permissions = *req.Permissions
	}
	if req.ExpiresIn != nil {
		d, err := time.ParseDuration(*req.ExpiresIn)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "expires_in: "+err.Error())
			return
		}
		k.ExpiresAt = sql.NullInt64{Int64: time.Now().Add(d).UnixMilli(), Valid: true}
	}
	newTags, err := metadata.MergeTags(k.Tags, req.AddTags, req.RemoveTags)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	k.Tags = newTags
	if req.Description != nil {
		if err := metadata.ValidateDescription(*req.Description); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		k.Description = *req.Description
		k.DescriptionUpdatedAt = sql.NullInt64{Int64: now, Valid: true}
	}
	newMeta, err := metadata.MergeMetadata(k.Metadata, req.SetMetadata, req.UnsetMetadata)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if newMeta != k.Metadata {
		k.Metadata = newMeta
		k.MetadataUpdatedAt = sql.NullInt64{Int64: now, Valid: true}
	}
	if err := s.Store.UpdateKey(r.Context(), k); err != nil {
		writeErr(w, http.StatusInternalServerError, "update")
		return
	}
	s.auditAppend(r, p, "key.update", name, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.Kind != "operator" {
		writeErr(w, http.StatusForbidden, "operator only")
		return
	}
	name := chi.URLParam(r, "name")
	k, err := s.Store.GetKeyByName(r.Context(), name)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err := s.Store.RevokeKey(r.Context(), k.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "revoke")
		return
	}
	s.auditAppend(r, p, "key.revoke", name, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSearchKeys(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		writeErr(w, http.StatusBadRequest, "q required")
		return
	}
	ids, err := s.Store.SearchKeys(r.Context(), q, 50)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p := principal(r)
	type item struct {
		Name        string `json:"name"`
		Scope       string `json:"scope"`
		Permissions string `json:"permissions"`
		Tags        string `json:"tags"`
		Description string `json:"description"`
		Metadata    string `json:"metadata"`
	}
	out := []item{}
	for _, id := range ids {
		row := s.Store.DB().QueryRowContext(r.Context(),
			`SELECT name, scope, permissions, tags, description, metadata FROM keys WHERE id = ?`, id)
		var it item
		if err := row.Scan(&it.Name, &it.Scope, &it.Permissions, &it.Tags, &it.Description, &it.Metadata); err != nil {
			continue
		}
		if p.Kind == "key" && it.Name != p.Name {
			continue
		}
		out = append(out, it)
	}
	s.auditAppend(r, p, "key.search", q, "ok")
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	since := parseInt64Query(r, "since", 0)
	keyName := r.URL.Query().Get("key")
	limit := int(parseInt64Query(r, "limit", 100))
	var keyID int64
	if keyName != "" {
		k, err := s.Store.GetKeyByName(r.Context(), keyName)
		if err != nil {
			writeErr(w, http.StatusNotFound, "no such key")
			return
		}
		keyID = k.ID
	}
	entries, err := s.Audit.List(r.Context(), since, keyID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list")
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	ok, brokenID, expected, got, err := s.Audit.Verify(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ok {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	w.WriteHeader(http.StatusMultiStatus)
	writeJSON(w, http.StatusMultiStatus, map[string]any{
		"ok":           false,
		"broken_at_id": brokenID,
		"expected_hex": fmt.Sprintf("%x", expected),
		"got_hex":      fmt.Sprintf("%x", got),
	})
}

func (s *Server) handleRotateOperator(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var body struct {
		NewPassword string `json:"new_master_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if body.NewPassword == "" {
		writeErr(w, http.StatusBadRequest, "new_master_password required")
		return
	}
	oldKEK := s.KEK
	salt, err := s.Store.GetMeta(r.Context(), "kdf_salt")
	if err != nil || len(salt) == 0 {
		writeErr(w, http.StatusInternalServerError, "missing kdf_salt")
		return
	}
	newKEK := crypto.DeriveKEK(body.NewPassword, salt, crypto.DefaultKDFParams())
	paths, err := s.Store.ListSecretPaths(r.Context(), "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list")
		return
	}
	for _, pth := range paths {
		sec, err := s.Store.GetSecret(r.Context(), pth)
		if err != nil {
			continue
		}
		pt, err := crypto.Open(oldKEK, append(sec.Nonce, sec.Ciphertext...), sec.AAD)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "decrypt during rotate")
			return
		}
		aad := crypto.AADSecret(sec.Path, sec.Description, uint64(sec.Version))
		sealed, err := crypto.Seal(newKEK, pt, aad[:])
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "encrypt during rotate")
			return
		}
		sec.Nonce = sealed[:crypto.NonceSize]
		sec.Ciphertext = sealed[crypto.NonceSize:]
		if err := s.Store.PutSecret(r.Context(), sec); err != nil {
			writeErr(w, http.StatusInternalServerError, "store during rotate")
			return
		}
	}
	tok, hash, prefix, _ := token.OperatorToken()
	op, err := s.Store.GetOperatorByName(r.Context(), s.OperatorName)
	if err == nil {
		_ = s.Store.UpdateOperatorHash(r.Context(), op.ID, hash, prefix)
	}
	s.auditAppend(r, p, "operator.rotate", "", "ok")
	writeJSON(w, http.StatusOK, map[string]any{"operator_token": tok})
}

// --- helpers ---

func (s *Server) canAccessSecret(p *auth.Principal, path string) bool {
	if p == nil || p.Kind == "operator" {
		return true
	}
	return scope.AnyMatch(p.Scope, path)
}

func (s *Server) auditAppend(r *http.Request, p *auth.Principal, action, path, result string) {
	if s.Audit == nil || p == nil {
		return
	}
	_, _ = s.Audit.Append(r.Context(), audit.Entry{
		TS:        time.Now().UnixMilli(),
		ActorKind: p.Kind,
		ActorID:   p.ID,
		Action:    action,
		Path:      path,
		Result:    result,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func splitCSV(csv string) []string {
	if csv == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseInt64Query(r *http.Request, key string, def int64) int64 {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	var n int64
	_, _ = fmt.Sscanf(v, "%d", &n)
	return n
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
