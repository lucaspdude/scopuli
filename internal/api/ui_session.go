package api

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lucaspdude/scopuli/internal/auth"
	"github.com/lucaspdude/scopuli/internal/crypto"
)

// Web UI session handling.
//
// The UI authenticates with the master key (the operator token). Logging in
// verifies the token exactly like the API does (SHA-256 lookup against the
// operators table) and then issues an HttpOnly session cookie. The cookie
// carries the token itself, HMAC-SHA-256-signed with a key derived from the
// KEK, plus an expiry — so it cannot be forged without the KEK, it survives
// server restarts, and rotating the master password invalidates all
// sessions. The master password itself never crosses the wire (D12).

const (
	uiSessionCookie   = "scopuli_session"
	uiSessionLifetime = 30 * 24 * time.Hour
)

// UISessionKey derives the cookie-signing key from the KEK. Deriving from
// the KEK (rather than a random boot key) means sessions survive restarts
// and are automatically invalidated by `rotate-operator-token`, which
// re-derives a new KEK.
func UISessionKey(kek []byte) []byte {
	return crypto.HMAC(kek, []byte("scopuli:ui-session:v1"))
}

// issueUICookie signs the operator token into a session cookie.
func (s *Server) issueUICookie(w http.ResponseWriter, r *http.Request, operatorToken string) {
	exp := time.Now().Add(uiSessionLifetime).Unix()
	payload := []byte(fmt.Sprintf("v1|%d|%s", exp, operatorToken))
	mac := crypto.HMAC(s.SessionKey, payload)
	val := base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac)
	http.SetCookie(w, &http.Cookie{
		Name:     uiSessionCookie,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(uiSessionLifetime.Seconds()),
	})
}

func clearUICookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     uiSessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// verifyUICookie validates the session cookie and returns the operator
// token it carries, or "" when missing/invalid/expired.
func (s *Server) verifyUICookie(r *http.Request) string {
	if len(s.SessionKey) == 0 {
		return ""
	}
	c, err := r.Cookie(uiSessionCookie)
	if err != nil {
		return ""
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	want := crypto.HMAC(s.SessionKey, payload)
	if len(sig) != len(want) || subtle.ConstantTimeCompare(sig, want) != 1 {
		return ""
	}
	fields := strings.SplitN(string(payload), "|", 3)
	if len(fields) != 3 || fields[0] != "v1" {
		return ""
	}
	exp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return ""
	}
	return fields[2]
}

// requireUISession authenticates the session cookie and attaches the
// operator Principal to the request context. Unauthenticated requests are
// redirected to /ui/login (302 for full page loads, HX-Redirect for htmx).
func (s *Server) requireUISession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := s.verifyUICookie(r)
		if tok == "" {
			s.uiRedirectLogin(w, r)
			return
		}
		// Reuse the API authentication path: the operator token is looked up
		// by hash exactly like an X-Scopuli-Operator request.
		rr := r.Clone(r.Context())
		rr.Header.Set("X-Scopuli-Operator", tok)
		p, err := auth.Authenticate(r.Context(), s.Store, rr)
		if err != nil || p.Kind != "operator" {
			clearUICookie(w)
			s.uiRedirectLogin(w, r)
			return
		}
		next.ServeHTTP(w, withPrincipal(rr, p))
	})
}

func (s *Server) uiRedirectLogin(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/ui/login")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/ui/login", http.StatusFound)
}

// requireUIHX rejects UI mutations that don't come from htmx. htmx always
// sends the HX-Request header; a cross-site form POST cannot set it without
// a CORS preflight, which the server never allows. Combined with SameSite=
// Lax cookies this blocks CSRF on every UI mutation.
func requireUIHX(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("HX-Request") != "true" {
			writeErr(w, http.StatusForbidden, "ui mutations require htmx")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- login / logout ---

// loginData feeds the login template (and the htmx fragment swap).
type loginData struct {
	Token string
	Alert *uiAlert
}

func (s *Server) handleUILoginPage(w http.ResponseWriter, r *http.Request) {
	if s.verifyUICookie(r) != "" {
		http.Redirect(w, r, "/ui/", http.StatusFound)
		return
	}
	s.renderLogin(w, r, loginData{})
}

func (s *Server) handleUILogin(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimSpace(r.FormValue("token"))
	if tok == "" {
		s.renderLogin(w, r, loginData{Alert: &uiAlert{
			Kind: "error", Title: "Master key required",
			Msg: "Enter the operator token to unlock the console.",
		}})
		return
	}
	rr := r.Clone(r.Context())
	rr.Header.Set("X-Scopuli-Operator", tok)
	p, err := auth.Authenticate(r.Context(), s.Store, rr)
	if err != nil || p.Kind != "operator" {
		s.renderLogin(w, r, loginData{Token: tok, Alert: &uiAlert{
			Kind: "error", Title: "Invalid master key",
			Msg: "No operator token matches. Check for typos, or rotate the token if it was lost.",
		}})
		return
	}
	s.issueUICookie(w, r, tok)
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/ui/")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/ui/", http.StatusFound)
}

func (s *Server) handleUILogout(w http.ResponseWriter, r *http.Request) {
	clearUICookie(w)
	w.Header().Set("HX-Redirect", "/ui/login")
	w.WriteHeader(http.StatusNoContent)
}

// renderLogin renders the full login page, or just the card fragment when
// the request came from htmx (so errors swap in place without a reload).
func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, data loginData) {
	t := s.uiSet("login")
	if t == nil {
		writeErr(w, http.StatusInternalServerError, "template parse: "+s.uiErr.Error())
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		_ = t.ExecuteTemplate(w, "login-card", data)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = t.ExecuteTemplate(w, "login", data)
}
