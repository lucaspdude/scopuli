// Package metadata validates and normalizes the metadata fields on
// secrets and keys: tags (CSV), description (Markdown), and structured
// metadata (JSON object of strings).
//
// Limits are enforced per D18/D19/D20 (DECISIONS.md):
//
//	tags:        max 20 entries, 64 chars each
//	description: max 8 KB
//	metadata:    max 32 pairs, key 64 chars, value 256 chars, must be
//	             object of strings
package metadata

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	MaxTags             = 20
	MaxTagLen           = 64
	MaxDescriptionBytes = 8 * 1024
	MaxMetadataPairs    = 32
	MaxMetadataKeyLen   = 64
	MaxMetadataValueLen = 256
)

// ErrTooManyTags is returned when more than MaxTags tags are provided.
var ErrTooManyTags = errors.New("metadata: too many tags")

// ErrTagTooLong is returned when any individual tag exceeds MaxTagLen.
var ErrTagTooLong = errors.New("metadata: tag too long")

// ErrDescriptionTooLarge is returned when description exceeds MaxDescriptionBytes.
var ErrDescriptionTooLarge = errors.New("metadata: description too large")

// ErrMetadataShape is returned when metadata is not a flat object of strings.
var ErrMetadataShape = errors.New("metadata: must be a flat JSON object of strings")

// ErrMetadataTooLarge is returned when metadata has too many pairs or any
// key/value is too long.
var ErrMetadataTooLarge = errors.New("metadata: too many pairs or keys/values too long")

// NormalizeTags trims, dedups, and validates a CSV of tags.
func NormalizeTags(csv string) (string, error) {
	if csv == "" {
		return "", nil
	}
	seen := map[string]bool{}
	var out []string
	for _, t := range strings.Split(csv, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if len(t) > MaxTagLen {
			return "", fmt.Errorf("%w: %q (%d > %d)", ErrTagTooLong, t, len(t), MaxTagLen)
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	if len(out) > MaxTags {
		return "", fmt.Errorf("%w: %d > %d", ErrTooManyTags, len(out), MaxTags)
	}
	return strings.Join(out, ","), nil
}

// ValidateDescription enforces the size cap.
func ValidateDescription(desc string) error {
	if len(desc) > MaxDescriptionBytes {
		return fmt.Errorf("%w: %d > %d", ErrDescriptionTooLarge, len(desc), MaxDescriptionBytes)
	}
	return nil
}

// NormalizeMetadata validates the metadata JSON. Returns canonical form
// (sorted keys, no whitespace).
func NormalizeMetadata(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "{}", nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return "", fmt.Errorf("%w: %v", ErrMetadataShape, err)
	}
	if m == nil {
		return "{}", nil
	}
	if len(m) > MaxMetadataPairs {
		return "", fmt.Errorf("%w: %d pairs > %d", ErrMetadataTooLarge, len(m), MaxMetadataPairs)
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if len(k) > MaxMetadataKeyLen {
			return "", fmt.Errorf("%w: key %q (%d > %d)", ErrMetadataTooLarge, k, len(k), MaxMetadataKeyLen)
		}
		// v must be a string (no nested objects, arrays, or nulls).
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("%w: key %q is not a string", ErrMetadataShape, k)
		}
		if len(s) > MaxMetadataValueLen {
			return "", fmt.Errorf("%w: value for %q (%d > %d)", ErrMetadataTooLarge, k, len(s), MaxMetadataValueLen)
		}
		out[k] = s
	}
	// json.Marshal of a map sorts keys.
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// MergeTags returns a CSV that contains base + add - remove. base is the
// existing CSV string. Order: first-seen base, then new adds.
func MergeTags(base string, add, remove []string) (string, error) {
	rm := map[string]bool{}
	for _, r := range remove {
		rm[r] = true
	}
	out := []string{}
	seen := map[string]bool{}
	for _, t := range strings.Split(base, ",") {
		t = strings.TrimSpace(t)
		if t == "" || rm[t] || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	for _, t := range add {
		t = strings.TrimSpace(t)
		if t == "" || rm[t] || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	if len(out) > MaxTags {
		return "", fmt.Errorf("%w: %d > %d", ErrTooManyTags, len(out), MaxTags)
	}
	return strings.Join(out, ","), nil
}

// MergeMetadata merges base JSON with set/unset operations. set wins over
// existing keys. unset removes keys. Returns canonical JSON.
func MergeMetadata(base string, set map[string]string, unset []string) (string, error) {
	var m map[string]any
	if base = strings.TrimSpace(base); base == "" || base == "{}" {
		m = map[string]any{}
	} else {
		if err := json.Unmarshal([]byte(base), &m); err != nil {
			return "", err
		}
	}
	if m == nil {
		m = map[string]any{}
	}
	for _, k := range unset {
		delete(m, k)
	}
	for k, v := range set {
		m[k] = v
	}
	return NormalizeMetadata(toJSON(m))
}

// toJSON renders any as JSON (best-effort).
func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
