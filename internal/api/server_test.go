package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lucaspdude/scopuli/internal/audit"
	scrypt "github.com/lucaspdude/scopuli/internal/crypto"
	"github.com/lucaspdude/scopuli/internal/store"
	"github.com/lucaspdude/scopuli/internal/token"
)

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	kek := bytes.Repeat([]byte{0x11}, 32)
	s, err := store.Open(context.Background(), filepath.Join(dir, "v.db"), kek, scrypt.DefaultKDFParams())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	hmacSalt := bytes.Repeat([]byte{0x22}, 16)
	hmacKey := token.AuditHMACKey("master", hmacSalt)
	logger := audit.NewLogger(s, hmacKey)

	tok, hash, prefix, err := token.OperatorToken()
	if err != nil {
		t.Fatalf("OperatorToken: %v", err)
	}
	if err := s.CreateOperator(context.Background(), &store.Operator{
		Name: "primary", Hash: hash, Prefix: prefix,
	}); err != nil {
		t.Fatalf("CreateOperator: %v", err)
	}

	srv := &Server{
		Store: s, Audit: logger, KEK: kek,
		Bind: ":0", LogLevel: "info", OperatorName: "primary",
		SessionKey: UISessionKey(kek),
	}
	return srv, tok
}

func doRequest(t *testing.T, srv *Server, method, path, opTok, body string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyR *strings.Reader
	if body != "" {
		bodyR = strings.NewReader(body)
	} else {
		bodyR = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, bodyR)
	if opTok != "" {
		req.Header.Set("X-Scopuli-Operator", opTok)
	}
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	return w
}

func TestHealthzNoAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	w := doRequest(t, srv, "GET", "/healthz", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ok") {
		t.Fatalf("body = %q, want ok", w.Body.String())
	}
}

func TestSecretsCRUD(t *testing.T) {
	srv, op := newTestServer(t)

	// PUT
	body := `{"path":"aws/prod/stripe","value":"sk_live_xxx","label":"Stripe","tags":["aws","prod"],"description":"Production Stripe key","metadata":{"owner":"alice"}}`
	w := doRequest(t, srv, "POST", "/api/secrets", op, body)
	if w.Code != http.StatusNoContent {
		t.Fatalf("PUT status = %d, body=%s", w.Code, w.Body.String())
	}

	// GET
	w = doRequest(t, srv, "GET", "/api/secrets/aws/prod/stripe", op, "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["value"] != "sk_live_xxx" {
		t.Fatalf("value = %v", got["value"])
	}
	if got["description"] != "Production Stripe key" {
		t.Fatalf("description = %v", got["description"])
	}

	// LIST
	w = doRequest(t, srv, "GET", "/api/secrets", op, "")
	if w.Code != http.StatusOK {
		t.Fatalf("LIST status = %d", w.Code)
	}
	var list []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(list))
	}
	// List items carry a masked preview and tags, never the full value.
	if list[0]["value_preview"] != "sk_liv***" {
		t.Fatalf("value_preview = %v", list[0]["value_preview"])
	}
	if _, ok := list[0]["value"]; ok {
		t.Fatalf("list without reveal must not include value: %v", list[0])
	}
	if _, ok := list[0]["has_description"]; ok {
		t.Fatalf("has_description was removed from list output: %v", list[0])
	}
	if list[0]["tags"] != "aws,prod" {
		t.Fatalf("tags = %v", list[0]["tags"])
	}

	// LIST with reveal=1 returns the full plaintext.
	w = doRequest(t, srv, "GET", "/api/secrets?reveal=1", op, "")
	if w.Code != http.StatusOK {
		t.Fatalf("LIST reveal status = %d", w.Code)
	}
	var revealed []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &revealed); err != nil {
		t.Fatalf("unmarshal reveal list: %v", err)
	}
	if len(revealed) != 1 || revealed[0]["value"] != "sk_live_xxx" {
		t.Fatalf("reveal list = %v", revealed)
	}

	// DELETE
	w = doRequest(t, srv, "DELETE", "/api/secrets/aws/prod/stripe", op, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d", w.Code)
	}
	w = doRequest(t, srv, "GET", "/api/secrets/aws/prod/stripe", op, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET after delete status = %d", w.Code)
	}
}

func TestSecretsAnnotationReEncrypts(t *testing.T) {
	srv, op := newTestServer(t)

	// Create a secret.
	body := `{"path":"x","value":"v1","description":"old"}`
	w := doRequest(t, srv, "POST", "/api/secrets", op, body)
	if w.Code != http.StatusNoContent {
		t.Fatalf("PUT status = %d", w.Code)
	}

	// Annotate with new description (should bump version + re-encrypt).
	annBody := `{"description":"new"}`
	w = doRequest(t, srv, "POST", "/api/secrets/annotate?path=x", op, annBody)
	if w.Code != http.StatusNoContent {
		t.Fatalf("annotate status = %d body=%s", w.Code, w.Body.String())
	}

	// GET should return new description and the same value.
	w = doRequest(t, srv, "GET", "/api/secrets/x", op, "")
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["description"] != "new" {
		t.Fatalf("description = %v, want new", got["description"])
	}
	if got["value"] != "v1" {
		t.Fatalf("value changed: %v", got["value"])
	}
	if got["version"].(float64) < 2 {
		t.Fatalf("version = %v, want >=2", got["version"])
	}
}

func TestKeyCreateAndRevoke(t *testing.T) {
	srv, op := newTestServer(t)

	createBody := `{"name":"dev","scope":"aws/dev/*","permissions":"read","tags":["dev"],"description":"Dev key"}`
	w := doRequest(t, srv, "POST", "/api/keys", op, createBody)
	if w.Code != http.StatusOK {
		t.Fatalf("create status = %d body=%s", w.Code, w.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	keyTok, _ := created["key"].(string)
	if !strings.HasPrefix(keyTok, "sk_live_") {
		t.Fatalf("key does not have prefix: %q", keyTok)
	}

	// Use the key to list secrets (none yet).
	req := httptest.NewRequest("GET", "/api/secrets", nil)
	req.Header.Set("X-Scopuli-Key", keyTok)
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("key GET status = %d", w.Code)
	}

	// Revoke.
	w = doRequest(t, srv, "POST", "/api/keys/dev/revoke", op, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d", w.Code)
	}

	// Key should now be rejected.
	req = httptest.NewRequest("GET", "/api/secrets", nil)
	req.Header.Set("X-Scopuli-Key", keyTok)
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("after revoke: status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestAgentKeyScopeEnforced(t *testing.T) {
	srv, op := newTestServer(t)

	// Seed two secrets.
	for _, p := range []string{"aws/dev/a", "aws/prod/b"} {
		w := doRequest(t, srv, "POST", "/api/secrets", op, `{"path":"`+p+`","value":"v"}`)
		if w.Code != http.StatusNoContent {
			t.Fatalf("seed %s: %d", p, w.Code)
		}
	}

	// Issue a key scoped to aws/dev/* only.
	createBody := `{"name":"devkey","scope":"aws/dev/*","permissions":"read"}`
	w := doRequest(t, srv, "POST", "/api/keys", op, createBody)
	var created map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	keyTok, _ := created["key"].(string)

	// Allowed read.
	req := httptest.NewRequest("GET", "/api/secrets/aws/dev/a", nil)
	req.Header.Set("X-Scopuli-Key", keyTok)
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("in-scope read: status = %d body=%s", w.Code, w.Body.String())
	}

	// Denied read.
	req = httptest.NewRequest("GET", "/api/secrets/aws/prod/b", nil)
	req.Header.Set("X-Scopuli-Key", keyTok)
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope read: status = %d body=%s", w.Code, w.Body.String())
	}

	// LIST filters to allowed only.
	req = httptest.NewRequest("GET", "/api/secrets", nil)
	req.Header.Set("X-Scopuli-Key", keyTok)
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	var list []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("expected 1 in-scope secret in list, got %d: %v", len(list), list)
	}
}

func TestSearchSecretsFTS(t *testing.T) {
	srv, op := newTestServer(t)

	for i, d := range []string{"Stripe production key", "GitHub token", "AWS root"} {
		body := `{"path":"p` + string(rune('0'+i)) + `","value":"v","description":"` + d + `"}`
		w := doRequest(t, srv, "POST", "/api/secrets", op, body)
		if w.Code != http.StatusNoContent {
			t.Fatalf("seed %d: %d", i, w.Code)
		}
	}
	w := doRequest(t, srv, "GET", "/api/secrets/search?q=stripe", op, "")
	if w.Code != http.StatusOK {
		t.Fatalf("search status = %d", w.Code)
	}
	var results []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &results)
	if len(results) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(results))
	}
}

func TestAuditVerifyChain(t *testing.T) {
	srv, op := newTestServer(t)
	// Generate a few audit rows.
	_ = doRequest(t, srv, "POST", "/api/secrets", op, `{"path":"a","value":"v"}`)
	_ = doRequest(t, srv, "POST", "/api/secrets", op, `{"path":"b","value":"v"}`)
	_ = doRequest(t, srv, "GET", "/api/secrets/a", op, "")

	w := doRequest(t, srv, "GET", "/api/audit/verify", op, "")
	if w.Code != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", w.Code, w.Body.String())
	}
	var r map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &r)
	if r["ok"] != true {
		t.Fatalf("verify result = %v", r)
	}
}

func TestAgentKeyAnnotateAllowed(t *testing.T) {
	srv, op := newTestServer(t)
	// Seed
	_ = doRequest(t, srv, "POST", "/api/secrets", op, `{"path":"aws/dev/x","value":"v"}`)
	// Issue manage key scoped to aws/dev/*
	w := doRequest(t, srv, "POST", "/api/keys", op, `{"name":"dev","scope":"aws/dev/*","permissions":"manage"}`)
	var created map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	keyTok := created["key"].(string)

	// Annotate via manage key.
	req := httptest.NewRequest("POST", "/api/secrets/annotate?path=aws/dev/x", strings.NewReader(`{"add_tags":["rotated"]}`))
	req.Header.Set("X-Scopuli-Key", keyTok)
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("annotate via manage key: status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestReadOnlyKeyCannotAnnotate(t *testing.T) {
	srv, op := newTestServer(t)
	_ = doRequest(t, srv, "POST", "/api/secrets", op, `{"path":"aws/dev/x","value":"v"}`)
	w := doRequest(t, srv, "POST", "/api/keys", op, `{"name":"reader","scope":"aws/dev/*","permissions":"read"}`)
	var created map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	keyTok := created["key"].(string)

	req := httptest.NewRequest("POST", "/api/secrets/annotate?path=aws/dev/x", strings.NewReader(`{"add_tags":["foo"]}`))
	req.Header.Set("X-Scopuli-Key", keyTok)
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("read-only annotate: status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestUnauthenticatedRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	w := doRequest(t, srv, "GET", "/api/secrets", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", w.Code)
	}
}
