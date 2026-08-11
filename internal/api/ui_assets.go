package api

import (
	"embed"
	"html/template"
	"net/http"
	"path/filepath"
	"strings"
)

// uiFS embeds the web UI (templates + static assets) into the binary so the
// distroless Docker image and the standalone binary need no extra files.
//
//go:embed assets templates
var uiFS embed.FS

// uiPages are the navigable page sets. Each set parses base.html (layout +
// shared partials) together with its page file, so the layout's
// {{template "main" .}} slot is unambiguous (html/template forbids dynamic
// template names). Login parses base.html too, for the shared icon partials.
var uiPages = []string{"dashboard", "secrets", "keys", "audit", "login"}

// uiAssetTypes maps file extensions to Content-Type.
var uiAssetTypes = map[string]string{
	".css": "text/css; charset=utf-8",
	".js":  "text/javascript; charset=utf-8",
	".svg": "image/svg+xml",
	".map": "application/json",
}

// handleUIAssets serves the embedded static assets (/ui/assets/*).
func (s *Server) handleUIAssets(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/ui/assets/")
	if name == "" || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	data, err := uiFS.ReadFile("assets/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ct := "application/octet-stream"
	if t, ok := uiAssetTypes[filepath.Ext(name)]; ok {
		ct = t
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// uiSets lazily parses the embedded per-page template sets once. Parse
// errors are programming errors (embedded files are covered by tests), so
// they're surfaced as 500s rather than panics.
func (s *Server) uiSets() (map[string]*template.Template, error) {
	s.uiOnce.Do(func() {
		s.uiSetsVal = make(map[string]*template.Template, len(uiPages))
		for _, page := range uiPages {
			t, err := template.New("ui").Funcs(uiFuncs()).ParseFS(
				uiFS, "templates/base.html", "templates/"+page+".html")
			if err != nil {
				s.uiErr = err
				return
			}
			s.uiSetsVal[page] = t
		}
	})
	return s.uiSetsVal, s.uiErr
}

// uiSet returns the parsed set for a page, or nil (with the parse error)
// when templates failed to load.
func (s *Server) uiSet(page string) *template.Template {
	sets, err := s.uiSets()
	if err != nil {
		return nil
	}
	return sets[page]
}
