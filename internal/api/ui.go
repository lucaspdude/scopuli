package api

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Web UI (htmx + Tailwind/shadcn styling), served from /ui/*. All pages are
// server-rendered fragments: a full page for direct navigation, the bare
// fragment for htmx swaps. Mutations write through the same store + audit
// paths as the JSON API, so CLI and UI stay consistent.

// uiPage is the data passed to the base layout. Active names both the nav
// item and the per-page template set used for rendering.
type uiPage struct {
	Title    string
	Active   string // nav id: dashboard | secrets | keys | audit
	Operator string
	Alert    *uiAlert
	Data     any
}

type uiAlert struct {
	Kind  string // "error" | "success" | "info"
	Title string
	Msg   string
}

func alertError(title, msg string) *uiAlert {
	return &uiAlert{Kind: "error", Title: title, Msg: msg}
}

func alertSuccess(title, msg string) *uiAlert {
	return &uiAlert{Kind: "success", Title: title, Msg: msg}
}

// uiFuncs provides helpers used by the templates.
func uiFuncs() template.FuncMap {
	return template.FuncMap{
		"navItem": func(id, label, href, activeID string) map[string]string {
			return map[string]string{"ID": id, "Label": label, "Href": href, "ActiveID": activeID}
		},
		"uiBadge": func(kind, text string) map[string]string {
			return map[string]string{"Kind": kind, "Text": text}
		},
		"uiEmpty": func(title, body string) map[string]string {
			return map[string]string{"Title": title, "Body": body}
		},
		"initials": func(name string) string {
			name = strings.TrimSpace(name)
			if name == "" {
				return "?"
			}
			parts := strings.Fields(name)
			if len(parts) == 1 {
				return strings.ToUpper(parts[0][:1])
			}
			return strings.ToUpper(parts[0][:1] + parts[len(parts)-1][:1])
		},
		"statusTabs": func() []map[string]string {
			return []map[string]string{
				{"ID": "all", "Label": "All"},
				{"ID": "active", "Label": "Active"},
				{"ID": "revoked", "Label": "Revoked"},
			}
		},
		"sinceTabs": func() []map[string]string {
			return []map[string]string{
				{"ID": "24h", "Label": "24h"},
				{"ID": "7d", "Label": "7d"},
				{"ID": "30d", "Label": "30d"},
				{"ID": "all", "Label": "All"},
			}
		},
		"relTime": relTime,
		"fmtTime": fmtTime,
		"urlPath": urlPath,
		"urlq":    url.QueryEscape,
	}
}

// urlPath escapes each path segment so secret paths with slashes and
// special characters survive an href/hx-get attribute.
func urlPath(p string) string {
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		parts[i] = url.PathEscape(seg)
	}
	return strings.Join(parts, "/")
}

func fmtTime(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).Format("2006-01-02 15:04")
}

func relTime(ms int64) string {
	if ms <= 0 {
		return "—"
	}
	t := time.UnixMilli(ms)
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return t.Format("2006-01-02")
	}
}

// renderPage renders a full document for direct navigation, or just the
// page fragment ({{template "main"}}) when the request came from htmx.
func (s *Server) renderPage(w http.ResponseWriter, r *http.Request, page uiPage) {
	t := s.uiSet(page.Active)
	if t == nil {
		writeErr(w, http.StatusInternalServerError, "template parse: "+s.uiErr.Error())
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		_ = t.ExecuteTemplate(w, "main", page)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = t.ExecuteTemplate(w, "base", page)
}
