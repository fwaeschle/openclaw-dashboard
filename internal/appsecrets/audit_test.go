package appsecrets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditEntryNoValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := AppendAudit(path, AuditEntry{Key: "FOO", Action: "set", Via: "dashboard", User: "fw"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	raw, _ := os.ReadFile(path)
	line := strings.TrimRight(string(raw), "\n")
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, has := m["value"]; has {
		t.Fatalf("audit must not contain value")
	}
	if _, has := m["masked"]; has {
		t.Fatalf("audit must not contain masked")
	}
	if m["key"] != "FOO" || m["action"] != "set" || m["via"] != "dashboard" || m["user"] != "fw" {
		t.Fatalf("fields wrong: %v", m)
	}
	if _, has := m["ts"]; !has {
		t.Fatalf("ts missing")
	}
}

func TestAuditAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	_ = AppendAudit(path, AuditEntry{Key: "A", Action: "set", Via: "dashboard", User: "fw"})
	_ = AppendAudit(path, AuditEntry{Key: "B", Action: "delete", Via: "dashboard", User: "fw"})
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d", len(lines))
	}
}

func TestAuditCreatesParent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deeper", "audit.jsonl")
	if err := AppendAudit(path, AuditEntry{Key: "X", Action: "set", Via: "dashboard", User: "fw"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file missing: %v", err)
	}
}
