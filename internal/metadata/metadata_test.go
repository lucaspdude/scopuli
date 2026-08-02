package metadata

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestNormalizeTags(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"  ", "", false},
		{"aws", "aws", false},
		{"aws, prod, stripe", "aws,prod,stripe", false},
		{"aws,aws,aws", "aws", false}, // dedup
		{"aws,,prod", "aws,prod", false},
	}
	for _, c := range cases {
		got, err := NormalizeTags(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeTags(%q): expected error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeTags(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeTags(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeTagsLimits(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < MaxTags+1; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("tag" + strconv.Itoa(i))
	}
	if _, err := NormalizeTags(sb.String()); !errors.Is(err, ErrTooManyTags) {
		t.Fatalf("expected ErrTooManyTags, got %v", err)
	}
	long := strings.Repeat("a", MaxTagLen+1)
	if _, err := NormalizeTags(long); !errors.Is(err, ErrTagTooLong) {
		t.Fatalf("expected ErrTagTooLong, got %v", err)
	}
}

func TestValidateDescription(t *testing.T) {
	if err := ValidateDescription(""); err != nil {
		t.Errorf("empty description should be valid, got %v", err)
	}
	if err := ValidateDescription(strings.Repeat("x", MaxDescriptionBytes)); err != nil {
		t.Errorf("max-length description should be valid, got %v", err)
	}
	if err := ValidateDescription(strings.Repeat("x", MaxDescriptionBytes+1)); !errors.Is(err, ErrDescriptionTooLarge) {
		t.Errorf("expected ErrDescriptionTooLarge, got %v", err)
	}
}

func TestNormalizeMetadata(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "{}", false},
		{"{}", "{}", false},
		{`{"a":"b"}`, `{"a":"b"}`, false},
		{`{"b":"y","a":"x"}`, `{"a":"x","b":"y"}`, false}, // sorted
		{`{"a":123}`, "", true},                           // non-string value
		{`{"a":null}`, "", true},
		{`{"a":["x"]}`, "", true},
		{`"foo"`, "", true}, // not an object
		{`{"a":"b","c":"d","e":"f","g":"h","i":"j","k":"l","m":"n","o":"p","q":"r","s":"t","u":"v","w":"x","y":"z","aa":"bb","cc":"dd","ee":"ff","gg":"hh","ii":"jj","kk":"ll","mm":"nn","oo":"pp","qq":"rr","ss":"tt","uu":"vv","ww":"xx","yy":"zz","aaa":"bbb","ccc":"ddd","eee":"fff","ggg":"hhh","iii":"jjj","kkk":"lll","mmm":"nnn"}`, "", true}, // 33 pairs
	}
	for _, c := range cases {
		got, err := NormalizeMetadata(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeMetadata(%q): expected error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeMetadata(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeMetadata(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMergeTags(t *testing.T) {
	got, err := MergeTags("aws,prod", []string{"stripe", "aws"}, []string{"prod"})
	if err != nil {
		t.Fatalf("MergeTags: %v", err)
	}
	if got != "aws,stripe" {
		t.Errorf("MergeTags = %q, want %q", got, "aws,stripe")
	}
}

func TestMergeMetadata(t *testing.T) {
	got, err := MergeMetadata(
		`{"owner":"alice","team":"billing"}`,
		map[string]string{"team": "platform"},
		[]string{"owner"},
	)
	if err != nil {
		t.Fatalf("MergeMetadata: %v", err)
	}
	if got != `{"team":"platform"}` {
		t.Errorf("MergeMetadata = %q, want %q", got, `{"team":"platform"}`)
	}
}
