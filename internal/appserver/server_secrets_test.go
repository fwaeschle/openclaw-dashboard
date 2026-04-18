package appserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mudrii/openclaw-dashboard/internal/appauth"
	appconfig "github.com/mudrii/openclaw-dashboard/internal/appconfig"
	"github.com/mudrii/openclaw-dashboard/internal/appsecrets"
)

func newAuthedTestServerWithSecrets(t *testing.T) (*Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	auditPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(envPath, []byte("HETZNER_API_TOKEN=abc\nFOO_KEY=1\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	cfg := appconfig.Default()
	cfg.AI.Enabled = false
	cfg.System.Enabled = false
	cfg.Auth.SessionSecret = "test-secret-1234567890"
	cfg.Auth.SessionMaxAge = 3600
	cfg.Auth.Users = []appconfig.AuthUser{{Username: "fw", PasswordHash: "x"}}

	indexHTML := []byte("<html><head></head><body></body></html>")
	loginHTML := []byte("<html></html>")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	refreshFn := func(ctx context.Context, d, o string, c ...appconfig.Config) error { return nil }
	srv := NewServer(dir, "1.0.0-test", cfg, "test-token", indexHTML, loginHTML, ctx, refreshFn)

	svc := appsecrets.NewService(appsecrets.Config{
		EnvPath:   envPath,
		AuditPath: auditPath,
		Reload:    func(ctx context.Context) error { return nil },
	})
	srv.WithSecrets(svc)
	return srv, envPath, auditPath
}

func authCookieFor(t *testing.T, s *Server, user string) *http.Cookie {
	t.Helper()
	return appauth.SignCookie(user, s.cfg.Auth.SessionSecret, s.cfg.Auth.SessionMaxAge)
}

func TestSecretsGetRequiresAuth(t *testing.T) {
	s, _, _ := newAuthedTestServerWithSecrets(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d body=%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("redirect got %q, want /login", loc)
	}
}

func TestSecretsGetListsKeys(t *testing.T) {
	s, _, _ := newAuthedTestServerWithSecrets(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.AddCookie(authCookieFor(t, s, "fw"))
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"FOO_KEY", "HETZNER_API_TOKEN", "Neuer Key setzen"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q", want)
		}
	}
}

func TestSecretsPostSetOK(t *testing.T) {
	s, envPath, _ := newAuthedTestServerWithSecrets(t)
	form := url.Values{"key": {"NEW_TOKEN"}, "value": {"v123"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/secrets", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(authCookieFor(t, s, "fw"))
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "flash=set%3ANEW_TOKEN") && !strings.Contains(loc, "flash=set:NEW_TOKEN") {
		t.Fatalf("location got %q", loc)
	}
	b, _ := os.ReadFile(envPath)
	if !strings.Contains(string(b), "NEW_TOKEN=v123") {
		t.Fatalf(".env: %q", b)
	}
}

func TestSecretsPostSetValidationError(t *testing.T) {
	s, _, _ := newAuthedTestServerWithSecrets(t)
	form := url.Values{"key": {"bad-key"}, "value": {"v"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/secrets", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(authCookieFor(t, s, "fw"))
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "flash=error") || !strings.Contains(loc, "key_format") {
		t.Fatalf("location got %q", loc)
	}
}

func TestSecretsPostDelete(t *testing.T) {
	s, envPath, _ := newAuthedTestServerWithSecrets(t)
	form := url.Values{"key": {"FOO_KEY"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/secrets/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(authCookieFor(t, s, "fw"))
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "flash=deleted") || !strings.Contains(loc, "FOO_KEY") {
		t.Fatalf("loc %q", loc)
	}
	b, _ := os.ReadFile(envPath)
	if strings.Contains(string(b), "FOO_KEY=") {
		t.Fatalf(".env still contains FOO_KEY: %q", b)
	}
}
