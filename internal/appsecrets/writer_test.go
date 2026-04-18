package appsecrets

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b)
}

func TestSetKeyReplaces(t *testing.T) {
	path := writeTmp(t, "FOO=old\nBAR=keep\n")
	if err := SetKey(path, "FOO", "new"); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	if got := readFile(t, path); got != "FOO=new\nBAR=keep\n" {
		t.Fatalf("got %q", got)
	}
}

func TestSetKeyAppends(t *testing.T) {
	path := writeTmp(t, "BAR=keep\n")
	if err := SetKey(path, "FOO", "added"); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	if got := readFile(t, path); got != "BAR=keep\nFOO=added\n" {
		t.Fatalf("got %q", got)
	}
}

func TestSetKeyAddsMissingNewline(t *testing.T) {
	path := writeTmp(t, "BAR=keep")
	if err := SetKey(path, "FOO", "added"); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	if got := readFile(t, path); got != "BAR=keep\nFOO=added\n" {
		t.Fatalf("got %q", got)
	}
}

func TestSetKeyCreatesMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh.env")
	if err := SetKey(path, "FOO", "v"); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	if got := readFile(t, path); got != "FOO=v\n" {
		t.Fatalf("got %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("perm: got %v want 0600", info.Mode().Perm())
	}
}

func TestSetKeyDoesNotMatchInValues(t *testing.T) {
	path := writeTmp(t, "# FOO=comment\nBAR=FOO=tricky\n")
	if err := SetKey(path, "FOO", "real"); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	out := readFile(t, path)
	if !contains(out, "# FOO=comment") {
		t.Fatalf("comment dropped: %q", out)
	}
	if !contains(out, "BAR=FOO=tricky") {
		t.Fatalf("BAR dropped: %q", out)
	}
	if !contains(out, "\nFOO=real\n") {
		t.Fatalf("real FOO missing: %q", out)
	}
}

func TestSetKeyAtomicNoTmpLeft(t *testing.T) {
	path := writeTmp(t, "FOO=old\n")
	if err := SetKey(path, "FOO", "new"); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".tmp must not exist")
	}
}

func TestDeleteKeyRemovesLine(t *testing.T) {
	path := writeTmp(t, "FOO=v1\nBAR=v2\nBAZ=v3\n")
	if err := DeleteKey(path, "BAR"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	if got := readFile(t, path); got != "FOO=v1\nBAZ=v3\n" {
		t.Fatalf("got %q", got)
	}
}

func TestDeleteKeyNotFound(t *testing.T) {
	path := writeTmp(t, "FOO=v\n")
	err := DeleteKey(path, "MISSING")
	if err == nil || err.Error() != "key_not_found" {
		t.Fatalf("want key_not_found, got %v", err)
	}
}

func TestDeleteKeyValidation(t *testing.T) {
	path := writeTmp(t, "FOO=v\n")
	err := DeleteKey(path, "bad-key")
	if err == nil || err.Error() != "key_format" {
		t.Fatalf("want key_format, got %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
