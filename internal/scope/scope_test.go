package scope

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"*", "anything", true},
		{"*", "with/slash", false}, // * is one segment
		{"aws/*", "aws/dev", true},
		{"aws/*", "aws", false},
		{"aws/*", "aws/dev/stripe", false}, // extra segment
		{"aws/*", "gcp/dev", false},
		{"aws/dev/*", "aws/dev/stripe_key", true},
		{"aws/dev/*", "aws/prod/stripe_key", false},
		{"github/*/pat", "github/lucas/pat", true},
		{"github/*/pat", "github/team/pat", true},
		{"github/*/pat", "github/lucas/ssh", false},
		{"", "", true},
		{"", "x", false},
		{"x", "", false},
	}
	for _, c := range cases {
		got := Match(c.pattern, c.path)
		if got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestAnyMatch(t *testing.T) {
	patterns := []string{"aws/dev/*", "github/*/pat"}
	if !AnyMatch(patterns, "aws/dev/x") {
		t.Error("aws/dev/x should match")
	}
	if !AnyMatch(patterns, "github/lucas/pat") {
		t.Error("github/lucas/pat should match")
	}
	if AnyMatch(patterns, "aws/prod/x") {
		t.Error("aws/prod/x should not match")
	}
	if AnyMatch(patterns, "github/lucas/ssh") {
		t.Error("github/lucas/ssh should not match")
	}
}

func TestParse(t *testing.T) {
	cases := map[string][]string{
		"":                        nil,
		"aws/*":                   {"aws/*"},
		"aws/*,github/*":          {"aws/*", "github/*"},
		" aws/* ,, github/*/pat ": {"aws/*", "github/*/pat"},
	}
	for in, want := range cases {
		got := Parse(in)
		if len(got) != len(want) {
			t.Errorf("Parse(%q) length %d, want %d (got %v)", in, len(got), len(want), got)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("Parse(%q)[%d] = %q, want %q", in, i, got[i], want[i])
			}
		}
	}
}
