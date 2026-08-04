package config

import "strings"

// contains is a small helper for substring matching, used in tests.
func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}
