package appsecrets

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeTmp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestListKeys(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{"empty", "", []string{}},
		{"single", "FOO=bar\n", []string{"FOO"}},
		{"multiple", "FOO=bar\nBAZ=qux\n", []string{"BAZ", "FOO"}},
		{"with comment", "# comment\nFOO=bar\n# another\nBAZ=qux\n", []string{"BAZ", "FOO"}},
		{"with blank line", "FOO=bar\n\nBAZ=qux\n", []string{"BAZ", "FOO"}},
		{"no trailing newline", "FOO=bar", []string{"FOO"}},
		{"value with equals", "FOO=a=b=c\n", []string{"FOO"}},
		{"invalid line ignored", "not_a_kv\nFOO=bar\n", []string{"FOO"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := writeTmp(t, c.content)
			got, err := ListKeys(path)
			if err != nil {
				t.Fatalf("ListKeys: %v", err)
			}
			if !slices.Equal(got, c.want) {
				t.Fatalf("got %v, want %v (sorted)", got, c.want)
			}
		})
	}
}

func TestListKeysMissingFile(t *testing.T) {
	got, err := ListKeys("/nonexistent/file.env")
	if err != nil {
		t.Fatalf("want no error for missing file, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty slice, got %v", got)
	}
}
