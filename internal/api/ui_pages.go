package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/lucaspdude/scopuli/internal/audit"
	"github.com/lucaspdude/scopuli/internal/auth"
	"github.com/lucaspdude/scopuli/internal/crypto"
)

// --- shared row types ---

type uiAuditRow struct {
	ID          int64
	TS          int64
	ActorKind   string
	Actor       string
	Action      string
	Path        string
	ResultBadge map[string]string
}

func badgeForResult(result string) map[string]string {
	switch result {
	case "ok":
		return map[string]string{"Kind": "muted", "Text": "ok"}
	default: // denied / error
		return map[string]string{"Kind": "destructive", "Text": result}
	}
}

// uiActorNames resolves key IDs to names for audit display. Operators map
// to the constant "operator" (there is only one in V0).
func (s *Server) uiActorNames(ctx context.Context) map[int64]string {
	keys, err := s.Store.ListKeys(ctx, true)
	if err != nil {
		return nil
	}
	m := make(map[int64]string, len(keys))
	for _, k := range keys {
		m[k.ID] = k.Name
	}
	return m
}

func (s *Server) uiAuditRows(ctx context.Context, entries []audit.Entry) []uiAuditRow {
	names := s.uiActorNames(ctx)
	out := make([]uiAuditRow, 0, len(entries))
	for _, e := range entries {
		actor := ""
		switch e.ActorKind {
		case "operator":
			actor = "operator"
		default:
			actor = names[e.ActorID]
			if actor == "" {
				actor = "key"
			}
		}
		out = append(out, uiAuditRow{
			ID:          e.ID,
			TS:          e.TS,
			ActorKind:   e.ActorKind,
			Actor:       actor,
			Action:      e.Action,
			Path:        e.Path,
			ResultBadge: badgeForResult(e.Result),
		})
	}
	return out
}

// --- dashboard ---

type dashboardData struct {
	Secrets     int
	ActiveKeys  int
	RevokedKeys int
	Audit24h    int
	Recent      []uiAuditRow
}

func (s *Server) handleUIDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data := dashboardData{}

	paths, err := s.Store.ListSecretPaths(ctx, "")
	if err == nil {
		data.Secrets = len(paths)
	}
	keys, err := s.Store.ListKeys(ctx, true)
	if err == nil {
		for _, k := range keys {
			if k.RevokedAt.Valid {
				data.RevokedKeys++
			} else {
				data.ActiveKeys++
			}
		}
	}
	recent, err := s.Audit.List(ctx, 0, 0, 8)
	if err == nil {
		data.Recent = s.uiAuditRows(ctx, recent)
	}
	since24h := time.Now().Add(-24 * time.Hour).UnixMilli()
	if n, err := s.Audit.Count(ctx, since24h, 0, ""); err == nil {
		data.Audit24h = int(n)
	}

	s.renderPage(w, r, uiPage{
		Title: "Dashboard", Active: "dashboard",
		Operator: s.OperatorName, Data: data,
	})
}

// --- secrets ---

type secretsData struct {
	Query    string
	Count    int
	ShowForm bool
	Form     *secretFormData
	Secrets  []uiSecretRow
}

type uiSecretRow struct {
	ID          string // css-safe element id
	Path        string
	Label       string
	Tags        []string
	Description string
	Version     int64
	UpdatedAt   int64
	Preview     string
}

type secretFormData struct {
	Editing     bool
	Path        string
	Label       string
	Tags        string
	Description string
	Metadata    string
	Alert       *uiAlert
}

// uiSecretRows decrypts each path for its masked preview (the operator has
// full scope). Rows that fail decryption are skipped and flagged in the
// audit log, mirroring the JSON API list behavior.
func (s *Server) uiSecretRows(ctx context.Context, r *http.Request, p *auth.Principal, paths []string) []uiSecretRow {
	out := make([]uiSecretRow, 0, len(paths))
	for _, pth := range paths {
		if !s.canAccessSecret(p, pth) {
			continue
		}
		sec, err := s.Store.GetSecret(ctx, pth)
		if err != nil {
			continue
		}
		aad := crypto.AADSecret(sec.Path, sec.Description, uint64(sec.Version))
		pt, err := crypto.Open(s.KEK, append(sec.Nonce, sec.Ciphertext...), aad[:])
		if err != nil {
			s.auditAppend(r, p, "error:decrypt_failed", pth, "error")
			continue
		}
		out = append(out, uiSecretRow{
			ID:          cssID(pth),
			Path:        sec.Path,
			Label:       sec.Label.String,
			Tags:        splitCSV(sec.Tags),
			Description: sec.Description,
			Version:     sec.Version,
			UpdatedAt:   sec.UpdatedAt,
			Preview:     maskSecretValue(string(pt)),
		})
	}
	return out
}

// cssID builds a stable, CSS-safe element id from a secret path.
func cssID(p string) string {
	var b strings.Builder
	for _, r := range p {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func (s *Server) handleUISecrets(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	data := s.loadSecretsData(r, q)
	s.renderPage(w, r, uiPage{
		Title: "Secrets", Active: "secrets",
		Operator: s.OperatorName, Data: data,
	})
}

// loadSecretsData builds the secrets list, optionally filtered by an FTS
// search query. Shared by the page GET and the create/edit/delete POSTs so
// mutations re-render a consistent list.
func (s *Server) loadSecretsData(r *http.Request, q string) secretsData {
	ctx := r.Context()
	p := principal(r)
	data := secretsData{Query: q}
	var paths []string
	if q != "" {
		ids, err := s.Store.SearchSecrets(ctx, q, 50)
		if err == nil {
			for _, id := range ids {
				row := s.Store.DB().QueryRowContext(ctx, `SELECT path FROM secrets WHERE id = ?`, id)
				var pth string
				if err := row.Scan(&pth); err == nil {
					paths = append(paths, pth)
				}
			}
		}
	} else {
		paths, _ = s.Store.ListSecretPaths(ctx, "")
	}
	data.Secrets = s.uiSecretRows(ctx, r, p, paths)
	data.Count = len(data.Secrets)
	return data
}

// handleUISecretForm renders the inline create/edit panel into
// #secret-form-slot. /ui/secrets/new → blank form; /ui/secrets/edit?path=
// → prefilled form.
func (s *Server) handleUISecretForm(w http.ResponseWriter, r *http.Request) {
	t := s.uiSet("secrets")
	if t == nil {
		writeErr(w, http.StatusInternalServerError, "template parse: "+s.uiErr.Error())
		return
	}
	form := &secretFormData{}
	if pth := r.URL.Query().Get("path"); pth != "" {
		sec, err := s.Store.GetSecret(r.Context(), pth)
		if err != nil {
			form.Alert = alertError("Secret not found", "It may have been deleted.")
		} else {
			form.Editing = true
			form.Path = sec.Path
			form.Label = sec.Label.String
			form.Tags = sec.Tags
			form.Description = sec.Description
			form.Metadata = sec.Metadata
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = t.ExecuteTemplate(w, "secret-form", form)
}

// handleUISecretValue reveals a secret value (htmx fragment into the row).
func (s *Server) handleUISecretValue(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	pth := strings.TrimPrefix(r.URL.Path, "/ui/secrets/value/")
	pth = strings.TrimSuffix(pth, "/")
	if !s.canAccessSecret(p, pth) {
		s.auditAppend(r, p, "denied:out_of_scope", pth, "denied")
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
		s.auditAppend(r, p, "error:decrypt_failed", pth, "error")
		writeErr(w, http.StatusInternalServerError, "decrypt failed")
		return
	}
	s.auditAppend(r, p, "read", pth, "ok")
	t := s.uiSet("secrets")
	if t == nil {
		writeErr(w, http.StatusInternalServerError, "template parse: "+s.uiErr.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = t.ExecuteTemplate(w, "reveal-value", struct{ Value string }{Value: string(pt)})
}

// --- keys ---

type keysData struct {
	Status   string // all | active | revoked
	Query    string
	ShowForm bool
	Form     *keyFormData
	NewKey   string
	Keys     []uiKeyRow
}

type uiKeyRow struct {
	Name            string
	Prefix          string
	Scope           string
	Permissions     string
	Tags            []string
	Description     string
	Revoked         bool
	Expired         bool
	PermissionBadge map[string]string
	Expires         string
	LastUsed        string
}

type keyFormData struct {
	Editing     bool
	Name        string
	Scope       string
	Permissions string
	ExpiresIn   string
	Tags        string
	Description string
	Metadata    string
	Alert       *uiAlert
}

func (s *Server) handleUIKeys(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status != "active" && status != "revoked" {
		status = "all"
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	data := s.loadKeysData(r, status, q)
	s.renderPage(w, r, uiPage{
		Title: "Keys", Active: "keys",
		Operator: s.OperatorName, Data: data,
	})
}

// loadKeysData builds the keys list with status/query filters. Shared by
// the page GET and the create/revoke/update POSTs.
func (s *Server) loadKeysData(r *http.Request, status, q string) keysData {
	ctx := r.Context()
	keys, err := s.Store.ListKeys(ctx, true)
	if err != nil {
		return keysData{Status: status, Query: q}
	}
	searchNames := map[string]bool{}
	if q != "" {
		ids, err := s.Store.SearchKeys(ctx, q, 50)
		if err == nil {
			for _, id := range ids {
				row := s.Store.DB().QueryRowContext(ctx, `SELECT name FROM keys WHERE id = ?`, id)
				var name string
				if err := row.Scan(&name); err == nil {
					searchNames[name] = true
				}
			}
		}
	}

	data := keysData{Status: status, Query: q}
	now := time.Now().UnixMilli()
	for _, k := range keys {
		if status == "active" && k.RevokedAt.Valid {
			continue
		}
		if status == "revoked" && !k.RevokedAt.Valid {
			continue
		}
		if q != "" && !searchNames[k.Name] {
			continue
		}
		expired := !k.RevokedAt.Valid && k.ExpiresAt.Valid && k.ExpiresAt.Int64 > 0 && k.ExpiresAt.Int64 < now
		row := uiKeyRow{
			Name:        k.Name,
			Prefix:      k.Prefix,
			Scope:       k.Scope,
			Permissions: k.Permissions,
			Tags:        splitCSV(k.Tags),
			Description: k.Description,
			Revoked:     k.RevokedAt.Valid,
			Expired:     expired,
		}
		if k.Permissions == "manage" {
			row.PermissionBadge = map[string]string{"Kind": "muted", "Text": "manage"}
		} else {
			row.PermissionBadge = map[string]string{"Kind": "", "Text": "read"}
		}
		if k.ExpiresAt.Valid && k.ExpiresAt.Int64 > 0 {
			row.Expires = relTime(k.ExpiresAt.Int64)
		} else {
			row.Expires = "never"
		}
		if k.LastUsedAt.Valid && k.LastUsedAt.Int64 > 0 {
			row.LastUsed = relTime(k.LastUsedAt.Int64)
		} else {
			row.LastUsed = "never"
		}
		data.Keys = append(data.Keys, row)
	}
	return data
}

// handleUIKeyForm renders the inline create/edit panel into #key-form-slot.
func (s *Server) handleUIKeyForm(w http.ResponseWriter, r *http.Request) {
	t := s.uiSet("keys")
	if t == nil {
		writeErr(w, http.StatusInternalServerError, "template parse: "+s.uiErr.Error())
		return
	}
	form := &keyFormData{Permissions: "read"}
	if name := r.URL.Query().Get("name"); name != "" {
		k, err := s.Store.GetKeyByName(r.Context(), name)
		if err != nil {
			form.Alert = alertError("Key not found", "It may have been deleted.")
		} else {
			form.Editing = true
			form.Name = k.Name
			form.Scope = k.Scope
			form.Permissions = k.Permissions
			form.Tags = k.Tags
			form.Description = k.Description
			form.Metadata = k.Metadata
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = t.ExecuteTemplate(w, "key-form", form)
}

// --- audit ---

type auditPageData struct {
	Verified  bool
	BrokenAt  int64
	Total     int
	Since     string
	FilterKey string
	Action    string
	Rows      []uiAuditRow
	HasMore   bool
	NextID    int64
}

const uiAuditPageSize = 50

func sinceMSFor(s string) int64 {
	now := time.Now()
	switch s {
	case "24h":
		return now.Add(-24 * time.Hour).UnixMilli()
	case "7d":
		return now.Add(-7 * 24 * time.Hour).UnixMilli()
	case "30d":
		return now.Add(-30 * 24 * time.Hour).UnixMilli()
	}
	return 0
}

func (s *Server) loadAuditPage(ctx context.Context, beforeID int64, since, key, action string) (auditPageData, error) {
	data := auditPageData{Since: since, FilterKey: key, Action: action}
	if since == "" {
		since = "all"
		data.Since = since
	}
	var keyID int64
	if key != "" {
		k, err := s.Store.GetKeyByName(ctx, key)
		if err != nil {
			return data, err
		}
		keyID = k.ID
	}
	entries, err := s.Audit.Query(ctx, beforeID, sinceMSFor(since), keyID, action, uiAuditPageSize)
	if err != nil {
		return data, err
	}
	if n, err := s.Audit.Count(ctx, sinceMSFor(since), keyID, action); err == nil {
		data.Total = int(n)
	}
	data.Rows = s.uiAuditRows(ctx, entries)
	data.HasMore = len(entries) == uiAuditPageSize
	if len(entries) > 0 {
		data.NextID = entries[len(entries)-1].ID
	}
	return data, nil
}

func (s *Server) handleUIAudit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	since := r.URL.Query().Get("since")
	if since == "" {
		since = "24h"
	}
	key := strings.TrimSpace(r.URL.Query().Get("key"))
	action := strings.TrimSpace(r.URL.Query().Get("action"))

	data, err := s.loadAuditPage(ctx, 0, since, key, action)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such key")
		return
	}
	// Chain verification (a full walk) runs on the audit page only.
	ok, brokenID, _, _, verr := s.Audit.Verify(ctx)
	if verr != nil {
		data.Verified = false
	} else {
		data.Verified = ok
		data.BrokenAt = brokenID
	}

	s.renderPage(w, r, uiPage{
		Title: "Audit log", Active: "audit",
		Operator: s.OperatorName, Data: data,
	})
}

// handleUIAuditOlder appends the next page of audit rows (OOB into
// #audit-tbody) and replaces the pager.
func (s *Server) handleUIAuditOlder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	before := parseInt64Query(r, "before", 0)
	if before <= 0 {
		writeErr(w, http.StatusBadRequest, "before required")
		return
	}
	since := r.URL.Query().Get("since")
	if since == "" {
		since = "all"
	}
	key := strings.TrimSpace(r.URL.Query().Get("key"))
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	data, err := s.loadAuditPage(ctx, before, since, key, action)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such key")
		return
	}
	t := s.uiSet("audit")
	if t == nil {
		writeErr(w, http.StatusInternalServerError, "template parse: "+s.uiErr.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = t.ExecuteTemplate(w, "audit-older", data)
}
