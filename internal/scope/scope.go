// Package scope evaluates path-glob patterns against a target path.
// Patterns are slash-delimited and use Go's path.Match semantics for `*`.
// No `**`, no character classes, no regex. Keep the mental model small.
package scope

import (
	"path"
	"strings"
)

// Match reports whether pattern matches p. Pattern uses `*` as a wildcard
// for one path segment (no slashes). Multiple globs may be combined by the
// caller (CSV); this function matches one pattern at a time.
func Match(pattern, p string) bool {
	// path.Match returns false for patterns containing "/" that don't
	// align with the path segments. We split on "/" and match each segment.
	patParts := strings.Split(strings.Trim(pattern, "/"), "/")
	pathParts := strings.Split(strings.Trim(p, "/"), "/")
	if len(patParts) != len(pathParts) {
		return false
	}
	for i, pp := range patParts {
		ok, err := path.Match(pp, pathParts[i])
		if err != nil || !ok {
			return false
		}
	}
	return true
}

// AnyMatch returns true if p matches any pattern in the slice.
func AnyMatch(patterns []string, p string) bool {
	for _, pat := range patterns {
		if Match(pat, p) {
			return true
		}
	}
	return false
}

// Parse splits a CSV of patterns into a slice, trimming whitespace and
// dropping empty entries.
func Parse(csv string) []string {
	if csv == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}
