package appauth

import (
	"net/http"
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("testpass123")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "pbkdf2:") {
		t.Errorf("expected pbkdf2 prefix, got %q", hash)
	}
	parts := strings.SplitN(hash, ":", 4)
	if len(parts) != 4 {
		t.Fatalf("expected 4 parts, got %d in %q", len(parts), hash)
	}
}

func TestVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword("correct-password", hash) {
		t.Error("expected verify to succeed for correct password")
	}
	if VerifyPassword("wrong-password", hash) {
		t.Error("expected verify to fail for wrong password")
	}
}

func TestVerifyPasswordInvalidFormat(t *testing.T) {
	if VerifyPassword("test", "not-a-valid-hash") {
		t.Error("expected verify to fail for invalid hash format")
	}
	if VerifyPassword("test", "") {
		t.Error("expected verify to fail for empty hash")
	}
}

func TestVerifyPasswordDummyHash(t *testing.T) {
	if VerifyPassword("anything", DummyHash) {
		t.Error("expected verify to fail for dummy hash")
	}
}

func TestSignAndValidateCookie(t *testing.T) {
	secret := "test-secret-key-for-hmac"
	cookie := SignCookie("fw", secret, 3600)
	if cookie.Name != CookieName {
		t.Errorf("expected cookie name %q, got %q", CookieName, cookie.Name)
	}
	if !cookie.HttpOnly {
		t.Error("expected HttpOnly=true")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Error("expected SameSite=Lax")
	}

	username, err := ValidateCookie(cookie.Value, secret)
	if err != nil {
		t.Fatalf("ValidateCookie: %v", err)
	}
	if username != "fw" {
		t.Errorf("expected username 'fw', got %q", username)
	}
}

func TestValidateCookieExpired(t *testing.T) {
	cookie := SignCookie("fw", "secret", -1)
	_, err := ValidateCookie(cookie.Value, "secret")
	if err == nil {
		t.Error("expected error for expired cookie")
	}
}

func TestValidateCookieTampered(t *testing.T) {
	cookie := SignCookie("fw", "secret", 3600)
	_, err := ValidateCookie(cookie.Value+"x", "secret")
	if err == nil {
		t.Error("expected error for tampered cookie")
	}
}

func TestValidateCookieWrongSecret(t *testing.T) {
	cookie := SignCookie("fw", "secret-a", 3600)
	_, err := ValidateCookie(cookie.Value, "secret-b")
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestGenerateSessionSecret(t *testing.T) {
	s1, err := GenerateSessionSecret()
	if err != nil {
		t.Fatalf("GenerateSessionSecret: %v", err)
	}
	if len(s1) != 64 {
		t.Errorf("expected 64-char hex string, got %d chars", len(s1))
	}
	s2, _ := GenerateSessionSecret()
	if s1 == s2 {
		t.Error("expected different secrets on successive calls")
	}
}
