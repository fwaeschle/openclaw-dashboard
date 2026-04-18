package appsecrets

import (
	"strings"
	"testing"
)

func TestValidateKey(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		wantErr string // "" = no error
	}{
		{"valid simple", "FOO", ""},
		{"valid underscore start", "_INTERNAL", ""},
		{"valid digit", "A1", ""},
		{"valid realistic", "HETZNER_API_TOKEN", ""},
		{"empty", "", "key_empty"},
		{"lowercase", "foo", "key_format"},
		{"leading digit", "1FOO", "key_format"},
		{"dash", "FOO-BAR", "key_format"},
		{"space", "FOO BAR", "key_format"},
		{"equals", "FOO=", "key_format"},
		{"too long", strings.Repeat("A", 129), "key_too_long"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateKey(c.key)
			if c.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.wantErr != "" && (err == nil || err.Error() != c.wantErr) {
				t.Fatalf("got %v, want %q", err, c.wantErr)
			}
		})
	}
}

func TestValidateValue(t *testing.T) {
	cases := []struct {
		name    string
		val     string
		wantErr string
	}{
		{"single char", "a", ""},
		{"normal secret", "sk-abc-123_XYZ", ""},
		{"max length", strings.Repeat("x", 500), ""},
		{"empty", "", "value_empty"},
		{"too long", strings.Repeat("x", 501), "value_too_long"},
		{"newline", "a\nb", "value_has_newline"},
		{"carriage return", "a\rb", "value_has_newline"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateValue(c.val)
			if c.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.wantErr != "" && (err == nil || err.Error() != c.wantErr) {
				t.Fatalf("got %v, want %q", err, c.wantErr)
			}
		})
	}
}
