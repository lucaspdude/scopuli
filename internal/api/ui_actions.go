package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lucaspdude/scopuli/internal/crypto"
	"github.com/lucaspdude/scopuli/internal/metadata"
	"github.com/lucaspdude/scopuli/internal/store"
	"github.com/lucaspdude/scopuli/internal/token"
)

// UI mutations write through the same store + audit paths as the JSON API.
// Every handler renders the affected page fragment back into #main, with an
// alert on success and the form re-rendered (values preserved) on error.

// --- secrets ---

// handleUISecretSave creates or updates a secret. Editing is detected by
// the hidden original_path field (the path input is disabled when editing).
func (s *Server) handleUISecretSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := principal(r)

	pth := strings.TrimSpace(r.FormValue("path"))
	original := strings.TrimSpace(r.FormValue("original_path"))
	if pth == "" {
		pth = original
	}
	value := r.FormValue("value")
	label := strings.TrimSpace(r.FormValue("label"))
	tagsCSV := strings.TrimSpace(r.FormValue("tags"))
	description := r.FormValue("description")
	metaRaw := strings.TrimSpace(r.FormValue("metadata"))

	form := &secretFormData{
		Editing:     original != "",
		Path:        pth,
		Label:       label,
		Tags:        tagsCSV,
		Description: description,
		Metadata:    metaRaw,
	}

	fail := func(errMsg string) {
		data := s.loadSecretsData(r, "")
		data.ShowForm = true
		form.Alert = alertError("Could not save secret", errMsg)
		data.Form = form
		s.renderPage(w, r, uiPage{
			Title: "Secrets", Active: "secrets",
			Operator: s.OperatorName, Alert: form.Alert, Data: data,
		})
	}

	if pth == "" {
		fail("A path is required, e.g. aws/prod/stripe_key.")
		return
	}
	tags, err := metadata.NormalizeTags(tagsCSV)
	if err != nil {
		fail(err.Error())
		return
	}
	if err := metadata.ValidateDescription(description); err != nil {
		fail(err.Error())
		return
	}
	metaJSON := "{}"
	if metaRaw != "" {
		metaJSON, err = metadata.NormalizeMetadata(metaRaw)
		if err != nil {
			fail(err.Error())
			return
		}
	}

	existing, _ := s.Store.GetSecret(ctx, pth)
	if value == "" {
		if existing == nil {
			fail("A value is required for new secrets.")
			return
		}
		plain, err := crypto.Open(s.KEK, append(existing.Nonce, existing.Ciphertext...), existing.AAD)
		if err != nil {
			fail("The existing value could not be decrypted.")
			return
		}
		value = string(plain)
	}

	now := time.Now().UnixMilli()
	version := int64(1)
	descUpdated := sql.NullInt64{}
	metaUpdated := sql.NullInt64{}
	createdAt := now
	if existing != nil {
		version = existing.Version
		createdAt = existing.CreatedAt
	}
	if existing == nil || existing.Description != description {
		version++
		descUpdated = sql.NullInt64{Int64: now, Valid: true}
	}
	if existing == nil || existing.Metadata != metaJSON {
		metaUpdated = sql.NullInt64{Int64: now, Valid: true}
	}

	aad := crypto.AADSecret(pth, description, uint64(version))
	sealed, err := crypto.Seal(s.KEK, []byte(value), aad[:])
	if err != nil {
		fail("Encryption failed.")
		return
	}
	sec := &store.Secret{
		Path:                 pth,
		Label:                sql.NullString{String: label, Valid: label != ""},
		Ciphertext:           sealed[crypto.NonceSize:],
		Nonce:                sealed[:crypto.NonceSize],
		AAD:                  aad[:],
		Tags:                 tags,
		Description:          description,
		Metadata:             metaJSON,
		CreatedAt:            createdAt,
		DescriptionUpdatedAt: descUpdated,
		MetadataUpdatedAt:    metaUpdated,
		Version:              version,
	}
	if err := s.Store.PutSecret(ctx, sec); err != nil {
		fail("The secret could not be stored.")
		return
	}
	s.auditAppend(r, p, "write", pth, "ok")

	data := s.loadSecretsData(r, "")
	msg := "The secret was encrypted and stored."
	if original != "" {
		msg = "Changes were saved and the secret re-encrypted."
	}
	s.renderPage(w, r, uiPage{
		Title: "Secrets", Active: "secrets",
		Operator: s.OperatorName,
		Alert:    alertSuccess("Secret saved", msg),
		Data:     data,
	})
}

// handleUISecretDelete deletes a secret (with hx-confirm on the client).
func (s *Server) handleUISecretDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := principal(r)
	pth := strings.TrimSpace(r.FormValue("path"))
	if pth == "" {
		writeErr(w, http.StatusBadRequest, "path required")
		return
	}
	if err := s.Store.DeleteSecret(ctx, pth); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.renderPage(w, r, uiPage{
				Title: "Secrets", Active: "secrets",
				Operator: s.OperatorName,
				Alert:    alertError("Secret not found", "It may have been deleted already."),
				Data:     s.loadSecretsData(r, ""),
			})
			return
		}
		writeErr(w, http.StatusInternalServerError, "delete")
		return
	}
	s.auditAppend(r, p, "delete", pth, "ok")
	s.renderPage(w, r, uiPage{
		Title: "Secrets", Active: "secrets",
		Operator: s.OperatorName,
		Alert:    alertSuccess("Secret deleted", pth),
		Data:     s.loadSecretsData(r, ""),
	})
}

// --- keys ---

// handleUIKeySave creates or updates a key. Editing is detected by the
// hidden original_name field (the name input is disabled when editing).
func (s *Server) handleUIKeySave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := principal(r)

	name := strings.TrimSpace(r.FormValue("name"))
	original := strings.TrimSpace(r.FormValue("original_name"))
	if name == "" {
		name = original
	}
	scopeVal := strings.TrimSpace(r.FormValue("scope"))
	permissions := r.FormValue("permissions")
	expiresIn := strings.TrimSpace(r.FormValue("expires_in"))
	tagsCSV := strings.TrimSpace(r.FormValue("tags"))
	description := r.FormValue("description")
	metaRaw := strings.TrimSpace(r.FormValue("metadata"))

	form := &keyFormData{
		Editing:     original != "",
		Name:        name,
		Scope:       scopeVal,
		Permissions: permissions,
		ExpiresIn:   expiresIn,
		Tags:        tagsCSV,
		Description: description,
		Metadata:    metaRaw,
	}

	fail := func(errMsg string) {
		data := s.loadKeysData(r, "all", "")
		data.ShowForm = true
		form.Alert = alertError("Could not save key", errMsg)
		data.Form = form
		s.renderPage(w, r, uiPage{
			Title: "Keys", Active: "keys",
			Operator: s.OperatorName, Alert: form.Alert, Data: data,
		})
	}

	if name == "" {
		fail("A name is required.")
		return
	}
	if scopeVal == "" {
		fail("A scope is required, e.g. aws/*,github/* (or * for everything).")
		return
	}
	if permissions != "read" && permissions != "manage" {
		fail("Permissions must be read or manage.")
		return
	}
	tags, err := metadata.NormalizeTags(tagsCSV)
	if err != nil {
		fail(err.Error())
		return
	}
	if err := metadata.ValidateDescription(description); err != nil {
		fail(err.Error())
		return
	}
	metaJSON := "{}"
	if metaRaw != "" {
		metaJSON, err = metadata.NormalizeMetadata(metaRaw)
		if err != nil {
			fail(err.Error())
			return
		}
	}
	var expiresAt sql.NullInt64
	if expiresIn != "" {
		d, derr := parseDurationLoose(expiresIn)
		if derr != nil {
			fail("Expires in: " + derr.Error() + " (use e.g. 720h or 30d).")
			return
		}
		expiresAt = sql.NullInt64{Int64: time.Now().Add(d).UnixMilli(), Valid: true}
	}

	if form.Editing {
		k, err := s.Store.GetKeyByName(ctx, original)
		if err != nil {
			fail("Key not found.")
			return
		}
		k.Scope = scopeVal
		k.Permissions = permissions
		k.ExpiresAt = expiresAt
		k.Tags = tags
		k.Description = description
		k.DescriptionUpdatedAt = sql.NullInt64{Int64: time.Now().UnixMilli(), Valid: true}
		k.Metadata = metaJSON
		k.MetadataUpdatedAt = sql.NullInt64{Int64: time.Now().UnixMilli(), Valid: true}
		if err := s.Store.UpdateKey(ctx, k); err != nil {
			fail("The key could not be updated.")
			return
		}
		s.auditAppend(r, p, "key.update", original, "ok")
		data := s.loadKeysData(r, "all", "")
		s.renderPage(w, r, uiPage{
			Title: "Keys", Active: "keys",
			Operator: s.OperatorName,
			Alert:    alertSuccess("Key updated", original),
			Data:     data,
		})
		return
	}

	tok, hash, prefix, err := token.AgentKey()
	if err != nil {
		fail("Key generation failed.")
		return
	}
	k := &store.Key{
		Name: name, Hash: hash, Prefix: prefix, Scope: scopeVal,
		Permissions: permissions, Tags: tags, Description: description,
		Metadata: metaJSON, ExpiresAt: expiresAt,
	}
	if err := s.Store.CreateKey(ctx, k); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			fail("A key named " + name + " already exists.")
			return
		}
		fail("The key could not be stored.")
		return
	}
	s.auditAppend(r, p, "key.create", name, "ok")

	data := s.loadKeysData(r, "all", "")
	data.NewKey = tok
	s.renderPage(w, r, uiPage{
		Title: "Keys", Active: "keys",
		Operator: s.OperatorName,
		Alert:    alertSuccess("Key created", name+" — copy the token from the dialog, it is shown once."),
		Data:     data,
	})
}

// handleUIKeyRevoke revokes a key (with hx-confirm on the client).
func (s *Server) handleUIKeyRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := principal(r)
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	k, err := s.Store.GetKeyByName(ctx, name)
	if err != nil {
		s.renderPage(w, r, uiPage{
			Title: "Keys", Active: "keys",
			Operator: s.OperatorName,
			Alert:    alertError("Key not found", "It may have been deleted."),
			Data:     s.loadKeysData(r, "all", ""),
		})
		return
	}
	if err := s.Store.RevokeKey(ctx, k.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "revoke")
		return
	}
	s.auditAppend(r, p, "key.revoke", name, "ok")
	s.renderPage(w, r, uiPage{
		Title: "Keys", Active: "keys",
		Operator: s.OperatorName,
		Alert:    alertSuccess("Key revoked", name+" can no longer authenticate."),
		Data:     s.loadKeysData(r, "all", ""),
	})
}

// parseDurationLoose accepts Go durations (720h) plus day suffixes (30d).
func parseDurationLoose(s string) (time.Duration, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || days <= 0 {
			return 0, errors.New("invalid days")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return 0, errors.New("invalid duration")
}
