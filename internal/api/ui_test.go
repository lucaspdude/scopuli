package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// uiLogin performs a full-page login POST and returns the session cookie.
func uiLogin(t *testing.T, srv *Server, op string) *http.Cookie {
	t.Helper()
	form := url.Values{"token": {op}}
	req := httptest.NewRequest("POST", "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302 (body=%s)", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/ui/" {
		t.Fatalf("login redirect = %q, want /ui/", loc)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == uiSessionCookie {
			if c.HttpOnly == false {
				t.Fatal("session cookie must be HttpOnly")
			}
			return c
		}
	}
	t.Fatal("no session cookie issued")
	return nil
}

// doUI issues an htmx request (HX-Request header) with the session cookie.
func doUI(t *testing.T, srv *Server, method, path string, cookie *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	req.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	return w
}

func TestUIRootRedirect(t *testing.T) {
	srv, _ := newTestServer(t)

	// A browser (Accept: text/html) hitting the domain root goes to the UI.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/ui/" {
		t.Fatalf("root browser: status=%d location=%q, want 302 /ui/", w.Code, w.Header().Get("Location"))
	}

	// API clients keep the plain 404.
	w = doRequest(t, srv, "GET", "/", "", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("root api client: status = %d, want 404", w.Code)
	}
}

func TestUILoginPageAndSessionGuard(t *testing.T) {
	srv, op := newTestServer(t)

	// Login page renders without auth.
	w := doRequest(t, srv, "GET", "/ui/login", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /ui/login status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Master key") {
		t.Fatalf("login page missing master key field")
	}

	// Wrong master key → re-render with error, no cookie.
	form := url.Values{"token": {"scot_live_not-a-real-token"}}
	req := httptest.NewRequest("POST", "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed login status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid master key") {
		t.Fatalf("failed login should show error, got: %s", w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == uiSessionCookie {
			t.Fatal("failed login must not issue a session cookie")
		}
	}

	// Full-page GET without session → redirect to login.
	w = doRequest(t, srv, "GET", "/ui/", "", "")
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/ui/login" {
		t.Fatalf("session guard: status=%d location=%q", w.Code, w.Header().Get("Location"))
	}

	// htmx GET without session → 401 + HX-Redirect.
	req = httptest.NewRequest("GET", "/ui/", nil)
	req.Header.Set("HX-Request", "true")
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized || w.Header().Get("HX-Redirect") != "/ui/login" {
		t.Fatalf("htmx session guard: status=%d hx-redirect=%q", w.Code, w.Header().Get("HX-Redirect"))
	}

	// Correct master key → cookie + redirect.
	c := uiLogin(t, srv, op)

	// Session cookie works: dashboard renders.
	w = doUI(t, srv, "GET", "/ui/", c, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Dashboard") {
		t.Fatalf("dashboard body missing title")
	}

	// Tampered cookie → back to login.
	bad := &http.Cookie{Name: uiSessionCookie, Value: c.Value + "x", Path: "/"}
	req = httptest.NewRequest("GET", "/ui/", nil)
	req.AddCookie(bad)
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/ui/login" {
		t.Fatalf("tampered cookie: status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
}

func TestUILoginRejectsAgentKey(t *testing.T) {
	srv, op := newTestServer(t)
	// Issue an agent key via the API.
	body := `{"name":"agent","scope":"*","permissions":"read"}`
	w := doRequest(t, srv, "POST", "/api/keys", op, body)
	if w.Code != http.StatusOK {
		t.Fatalf("create key status = %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || !strings.HasPrefix(resp.Key, "sk_live_") {
		t.Fatalf("bad create key response: %v %s", err, w.Body.String())
	}

	// Agent keys must not unlock the operator console.
	form := url.Values{"token": {resp.Key}}
	req := httptest.NewRequest("POST", "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("agent-key login status = %d, want 200 with error", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid master key") {
		t.Fatalf("agent key login should be rejected, got: %s", w.Body.String())
	}
}

func TestUIMutationsRequireHX(t *testing.T) {
	srv, op := newTestServer(t)
	c := uiLogin(t, srv, op)

	// A mutation without the htmx header (e.g. a cross-site form POST) is
	// rejected even with a valid session cookie.
	form := url.Values{"path": {"x/y"}, "value": {"v"}}
	req := httptest.NewRequest("POST", "/ui/secrets", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(c)
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-htmx mutation status = %d, want 403", w.Code)
	}
}

func TestUIDashboardStats(t *testing.T) {
	srv, op := newTestServer(t)
	// Seed data through the API.
	doRequest(t, srv, "POST", "/api/secrets", op, `{"path":"aws/prod/a","value":"1"}`)
	doRequest(t, srv, "POST", "/api/secrets", op, `{"path":"aws/prod/b","value":"2"}`)
	doRequest(t, srv, "POST", "/api/keys", op, `{"name":"agent1","scope":"*","permissions":"read"}`)

	c := uiLogin(t, srv, op)
	w := doUI(t, srv, "GET", "/ui/", c, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"Dashboard", "aws/prod/a", "aws/prod/b", "key.create", "Recent activity"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard missing %q", want)
		}
	}
}

func TestUISecretsFlow(t *testing.T) {
	srv, op := newTestServer(t)
	c := uiLogin(t, srv, op)

	// Create via the UI form.
	form := url.Values{
		"path":        {"aws/prod/stripe"},
		"value":       {"sk_live_xyz123secret"},
		"label":       {"Stripe"},
		"tags":        {"aws,prod"},
		"description": {"Production Stripe key"},
		"metadata":    {`{"owner":"alice"}`},
	}
	w := doUI(t, srv, "POST", "/ui/secrets", c, form)
	if w.Code != http.StatusOK {
		t.Fatalf("create status = %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Secret saved") || !strings.Contains(w.Body.String(), "aws/prod/stripe") {
		t.Fatalf("create response missing confirmation, got: %s", w.Body.String())
	}

	// List shows the masked preview, never the value.
	w = doUI(t, srv, "GET", "/ui/secrets", c, nil)
	body := w.Body.String()
	if !strings.Contains(body, "aws/prod/stripe") || !strings.Contains(body, "sk_liv***") {
		t.Fatalf("list missing masked preview: %s", body)
	}
	if strings.Contains(body, "sk_live_xyz123secret") {
		t.Fatal("list must not expose the plaintext value")
	}

	// Reveal returns the plaintext into the row.
	w = doUI(t, srv, "GET", "/ui/secrets/value/aws/prod/stripe", c, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "sk_live_xyz123secret") {
		t.Fatalf("reveal failed: status=%d body=%s", w.Code, w.Body.String())
	}

	// A read was audited.
	w = doRequest(t, srv, "GET", "/api/audit?limit=50", op, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"read"`) {
		t.Fatalf("audit missing read entry: %s", w.Body.String())
	}

	// Validation error keeps the form and shows a message.
	form = url.Values{"path": {"x/y"}, "value": {""}}
	w = doUI(t, srv, "POST", "/ui/secrets", c, form)
	if !strings.Contains(w.Body.String(), "value is required") {
		t.Fatalf("missing validation error: %s", w.Body.String())
	}

	// Delete.
	form = url.Values{"path": {"aws/prod/stripe"}}
	w = doUI(t, srv, "POST", "/ui/secrets/delete", c, form)
	if !strings.Contains(w.Body.String(), "Secret deleted") {
		t.Fatalf("delete response: %s", w.Body.String())
	}
	w = doUI(t, srv, "GET", "/ui/secrets", c, nil)
	body = w.Body.String()
	if !strings.Contains(body, "No secrets") {
		t.Fatalf("expected empty state after delete: %s", body)
	}
	if strings.Contains(body, `id="val-aws-prod-stripe"`) {
		t.Fatalf("secret row still rendered after delete: %s", body)
	}
}

func TestUIEditSecretKeepsValueWhenBlank(t *testing.T) {
	srv, op := newTestServer(t)
	doRequest(t, srv, "POST", "/api/secrets", op, `{"path":"a/b","value":"original-value"}`)
	c := uiLogin(t, srv, op)

	// Edit: change description only, leave value blank.
	form := url.Values{
		"original_path": {"a/b"},
		"label":         {"Label"},
		"tags":          {"edited"},
		"description":   {"Changed description"},
	}
	w := doUI(t, srv, "POST", "/ui/secrets", c, form)
	if !strings.Contains(w.Body.String(), "Changes were saved") {
		t.Fatalf("edit response: %s", w.Body.String())
	}
	// Value must be untouched.
	w = doRequest(t, srv, "GET", "/api/secrets/a/b", op, "")
	if !strings.Contains(w.Body.String(), "original-value") {
		t.Fatalf("edit wiped the value: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Changed description") {
		t.Fatalf("edit did not update description: %s", w.Body.String())
	}
}

func TestUIKeysFlow(t *testing.T) {
	srv, op := newTestServer(t)
	c := uiLogin(t, srv, op)

	// Create a key via the UI form (30d expiry).
	form := url.Values{
		"name":        {"agent1"},
		"scope":       {"aws/*"},
		"permissions": {"read"},
		"expires_in":  {"30d"},
		"tags":        {"agent"},
	}
	w := doUI(t, srv, "POST", "/ui/keys", c, form)
	if w.Code != http.StatusOK {
		t.Fatalf("create key status = %d (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "Key created") {
		t.Fatalf("create key missing confirmation: %s", body)
	}
	re := regexp.MustCompile(`sk_live_[A-Za-z0-9]+_[A-Za-z0-9]{4}`)
	token := re.FindString(body)
	if token == "" {
		t.Fatalf("create key response missing the token: %s", body)
	}

	// List shows the key.
	w = doUI(t, srv, "GET", "/ui/keys", c, nil)
	body = w.Body.String()
	for _, want := range []string{"agent1", "aws/*", "read", "active"} {
		if !strings.Contains(body, want) {
			t.Fatalf("keys list missing %q: %s", want, body)
		}
	}

	// Edit via the same form (original_name) → update semantics.
	form = url.Values{
		"original_name": {"agent1"},
		"scope":         {"github/*"},
		"permissions":   {"manage"},
		"expires_in":    {""},
		"description":   {"Rotated scope"},
	}
	w = doUI(t, srv, "POST", "/ui/keys", c, form)
	if !strings.Contains(w.Body.String(), "Key updated") {
		t.Fatalf("update key response: %s", w.Body.String())
	}
	w = doRequest(t, srv, "GET", "/api/keys/agent1", op, "")
	body = w.Body.String()
	if !strings.Contains(body, "github/*") || !strings.Contains(body, "manage") {
		t.Fatalf("key not updated: %s", body)
	}

	// Revoke.
	form = url.Values{"name": {"agent1"}}
	w = doUI(t, srv, "POST", "/ui/keys/revoke", c, form)
	if !strings.Contains(w.Body.String(), "Key revoked") {
		t.Fatalf("revoke response: %s", w.Body.String())
	}
	w = doRequest(t, srv, "GET", "/api/keys/agent1", op, "")
	var keyResp struct {
		RevokedAt int64 `json:"revoked_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &keyResp); err != nil {
		t.Fatalf("bad key response: %v", err)
	}
	if keyResp.RevokedAt == 0 {
		t.Fatalf("key not revoked: %s", w.Body.String())
	}
	// The revoked key must no longer authenticate.
	req := httptest.NewRequest("GET", "/api/secrets", nil)
	req.Header.Set("X-Scopuli-Key", token)
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key auth status = %d, want 401", w.Code)
	}
}

func TestUIAuditPageAndPagination(t *testing.T) {
	srv, op := newTestServer(t)
	doRequest(t, srv, "POST", "/api/secrets", op, `{"path":"a/b","value":"v"}`)
	doRequest(t, srv, "POST", "/api/keys", op, `{"name":"k1","scope":"*","permissions":"read"}`)
	c := uiLogin(t, srv, op)

	w := doUI(t, srv, "GET", "/ui/audit", c, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("audit status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"Chain intact", "key.create", "write", "operator"} {
		if !strings.Contains(body, want) {
			t.Fatalf("audit page missing %q", want)
		}
	}

	// Cursor endpoint requires a valid cursor.
	w = doUI(t, srv, "GET", "/ui/audit/older", c, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("audit/older without before status = %d, want 400", w.Code)
	}
}

// TestUITemplatesExecute renders every template in every set with realistic
// data and fails on ANY execution error. html/template truncates output on
// error, which otherwise silently corrupts htmx fragments.
func TestUITemplatesExecute(t *testing.T) {
	srv, _ := newTestServer(t)
	sample := uiAuditRow{
		ID: 1, TS: 1786447576000, ActorKind: "key", Actor: "agent1",
		Action: "key.create", Path: "aws/prod/x", ResultBadge: badgeForResult("ok"),
	}
	pageData := map[string]any{
		"dashboard": dashboardData{Secrets: 1, ActiveKeys: 1, RevokedKeys: 0, Audit24h: 2, Recent: []uiAuditRow{sample}},
		"secrets":   secretsData{Query: "q", Count: 1, ShowForm: true, Form: &secretFormData{Editing: true, Path: "a/b", Tags: "t", Description: "d", Metadata: `{}`}, Secrets: []uiSecretRow{{ID: "a-b", Path: "a/b", Label: "L", Tags: []string{"t"}, Version: 2, UpdatedAt: 1786447576000, Preview: "sk_liv***"}}},
		"keys":      keysData{Status: "all", ShowForm: true, Form: &keyFormData{Editing: true, Name: "k", Scope: "*", Permissions: "read"}, NewKey: "sk_live_demo", Keys: []uiKeyRow{{Name: "k", Prefix: "sk_live_123", Scope: "*", Permissions: "read", Tags: []string{"t"}, PermissionBadge: map[string]string{"Kind": "", "Text": "read"}, Expires: "never", LastUsed: "never"}}},
		"audit":     auditPageData{Verified: true, Total: 3, Since: "24h", Rows: []uiAuditRow{sample}, HasMore: true, NextID: 1},
	}
	for _, name := range []string{"dashboard", "secrets", "keys", "audit"} {
		tmpl := srv.uiSet(name)
		if tmpl == nil {
			t.Fatalf("%s: nil template set (%v)", name, srv.uiErr)
		}
		page := uiPage{Title: name, Active: name, Operator: "primary",
			Alert: alertSuccess("ok", "done"), Data: pageData[name]}
		if err := tmpl.ExecuteTemplate(io.Discard, "base", page); err != nil {
			t.Fatalf("%s base: %v", name, err)
		}
		if err := tmpl.ExecuteTemplate(io.Discard, "main", page); err != nil {
			t.Fatalf("%s main: %v", name, err)
		}
	}

	login := srv.uiSet("login")
	if err := login.ExecuteTemplate(io.Discard, "login", loginData{}); err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := login.ExecuteTemplate(io.Discard, "login-card", loginData{Token: "x", Alert: alertError("bad", "nope")}); err != nil {
		t.Fatalf("login-card: %v", err)
	}

	secrets := srv.uiSet("secrets")
	if err := secrets.ExecuteTemplate(io.Discard, "secret-form", &secretFormData{Editing: true, Path: "a/b", Alert: alertError("bad", "nope")}); err != nil {
		t.Fatalf("secret-form: %v", err)
	}
	if err := secrets.ExecuteTemplate(io.Discard, "reveal-value", struct{ Value string }{Value: "<script>alert(1)</script>"}); err != nil {
		t.Fatalf("reveal-value: %v", err)
	}
	keys := srv.uiSet("keys")
	if err := keys.ExecuteTemplate(io.Discard, "key-form", &keyFormData{Alert: alertError("bad", "nope")}); err != nil {
		t.Fatalf("key-form: %v", err)
	}
	audit := srv.uiSet("audit")
	if err := audit.ExecuteTemplate(io.Discard, "audit-older", auditPageData{Rows: []uiAuditRow{sample}, HasMore: true, NextID: 1}); err != nil {
		t.Fatalf("audit-older: %v", err)
	}
}

func TestUISearchSecrets(t *testing.T) {
	srv, op := newTestServer(t)
	doRequest(t, srv, "POST", "/api/secrets", op, `{"path":"aws/prod/stripe","value":"1","description":"stripe payment key"}`)
	doRequest(t, srv, "POST", "/api/secrets", op, `{"path":"github/token","value":"2","description":"github PAT"}`)
	c := uiLogin(t, srv, op)

	w := doUI(t, srv, "GET", "/ui/secrets?q=stripe", c, nil)
	body := w.Body.String()
	if !strings.Contains(body, "aws/prod/stripe") || strings.Contains(body, "github/token") {
		t.Fatalf("search results wrong: %s", body)
	}
}
