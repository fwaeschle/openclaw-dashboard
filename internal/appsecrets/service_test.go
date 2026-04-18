package appsecrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newService(t *testing.T, reload ReloadFunc) (*Service, string, string) {
	t.Helper()
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	auditPath := filepath.Join(dir, "audit.jsonl")
	_ = os.WriteFile(envPath, []byte(""), 0o600)
	svc := NewService(Config{
		EnvPath:   envPath,
		AuditPath: auditPath,
		Reload:    reload,
	})
	return svc, envPath, auditPath
}

func TestServiceSetSuccess(t *testing.T) {
	called := false
	svc, envPath, auditPath := newService(t, func(ctx context.Context) error {
		called = true
		return nil
	})
	if err := svc.Set(context.Background(), "FOO", "bar", "fw"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !called {
		t.Fatalf("reload was not called")
	}
	out, _ := os.ReadFile(envPath)
	if !strings.Contains(string(out), "FOO=bar") {
		t.Fatalf(".env missing entry: %q", out)
	}
	audit, _ := os.ReadFile(auditPath)
	if !strings.Contains(string(audit), `"key":"FOO"`) || !strings.Contains(string(audit), `"action":"set"`) {
		t.Fatalf("audit wrong: %q", audit)
	}
	if strings.Contains(string(audit), "bar") {
		t.Fatalf("value leaked into audit")
	}
}

func TestServiceSetReloadFailureStillWritesAndAudits(t *testing.T) {
	svc, envPath, auditPath := newService(t, func(ctx context.Context) error {
		return errors.New("reload_failed: boom")
	})
	err := svc.Set(context.Background(), "NEW", "v", "fw")
	if err == nil || !strings.HasPrefix(err.Error(), "reload_failed") {
		t.Fatalf("want reload_failed error, got %v", err)
	}
	out, _ := os.ReadFile(envPath)
	if !strings.Contains(string(out), "NEW=v") {
		t.Fatalf("file not written despite reload failure: %q", out)
	}
	if _, err := os.Stat(auditPath); err != nil {
		t.Fatalf("audit missing: %v", err)
	}
}

func TestServiceSetValidationError(t *testing.T) {
	svc, envPath, _ := newService(t, func(ctx context.Context) error {
		t.Fatalf("reload must not be called on validation error")
		return nil
	})
	err := svc.Set(context.Background(), "bad", "v", "fw")
	if err == nil || err.Error() != "key_format" {
		t.Fatalf("want key_format, got %v", err)
	}
	out, _ := os.ReadFile(envPath)
	if strings.Contains(string(out), "bad=") {
		t.Fatalf(".env must not be touched on validation error: %q", out)
	}
}

func TestServiceDeleteSuccess(t *testing.T) {
	reloadCalled := false
	svc, envPath, auditPath := newService(t, func(ctx context.Context) error {
		reloadCalled = true
		return nil
	})
	_ = os.WriteFile(envPath, []byte("FOO=keep\nTO_DEL=gone\n"), 0o600)
	if err := svc.Delete(context.Background(), "TO_DEL", "fw"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !reloadCalled {
		t.Fatalf("reload not called")
	}
	out, _ := os.ReadFile(envPath)
	if strings.Contains(string(out), "TO_DEL") {
		t.Fatalf("not deleted: %q", out)
	}
	audit, _ := os.ReadFile(auditPath)
	if !strings.Contains(string(audit), `"action":"delete"`) {
		t.Fatalf("audit missing delete action: %q", audit)
	}
}

func TestServiceDeleteMissingKey(t *testing.T) {
	svc, envPath, _ := newService(t, func(ctx context.Context) error { return nil })
	_ = os.WriteFile(envPath, []byte("FOO=keep\n"), 0o600)
	err := svc.Delete(context.Background(), "MISSING", "fw")
	if err == nil || err.Error() != "key_not_found" {
		t.Fatalf("want key_not_found, got %v", err)
	}
}

func TestServiceList(t *testing.T) {
	svc, envPath, _ := newService(t, func(ctx context.Context) error { return nil })
	_ = os.WriteFile(envPath, []byte("B=2\nA=1\n"), 0o600)
	keys, err := svc.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 || keys[0] != "A" || keys[1] != "B" {
		t.Fatalf("unexpected: %v", keys)
	}
}
