// Package appauth implements authentication: PBKDF2 password hashing,
// HMAC-signed session cookies, and login rate limiting.
package appauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	CookieName       = "oc_session"
	pbkdf2Iterations = 100_000
	pbkdf2KeyLen     = 32
	pbkdf2SaltLen    = 16
)

// DummyHash is used for constant-time comparison when the user doesn't exist.
var DummyHash = func() string {
	salt := strings.Repeat("00", pbkdf2SaltLen)
	key := strings.Repeat("00", pbkdf2KeyLen)
	return fmt.Sprintf("pbkdf2:%d:%s:%s", pbkdf2Iterations, salt, key)
}()

var (
	ErrInvalidCookie = errors.New("invalid session cookie")
	ErrExpiredCookie = errors.New("session expired")
)

// HashPassword generates a PBKDF2-SHA256 hash with a random salt.
// Format: pbkdf2:<iterations>:<salt_hex>:<key_hex>
func HashPassword(password string) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyLen)
	return fmt.Sprintf("pbkdf2:%d:%s:%s",
		pbkdf2Iterations,
		hex.EncodeToString(salt),
		hex.EncodeToString(key),
	), nil
}

// VerifyPassword checks a password against a stored hash.
func VerifyPassword(password, storedHash string) bool {
	parts := strings.SplitN(storedHash, ":", 4)
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations <= 0 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expectedKey, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	actualKey := pbkdf2SHA256([]byte(password), salt, iterations, len(expectedKey))
	return subtle.ConstantTimeCompare(actualKey, expectedKey) == 1
}

// pbkdf2SHA256 derives a key using PBKDF2 with HMAC-SHA256.
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	numBlocks := (keyLen + sha256.Size - 1) / sha256.Size
	dk := make([]byte, 0, numBlocks*sha256.Size)
	for block := 1; block <= numBlocks; block++ {
		dk = append(dk, pbkdf2Block(password, salt, iterations, block)...)
	}
	return dk[:keyLen]
}

func pbkdf2Block(password, salt []byte, iterations, blockNum int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write([]byte{byte(blockNum >> 24), byte(blockNum >> 16), byte(blockNum >> 8), byte(blockNum)})
	u := mac.Sum(nil)

	result := make([]byte, len(u))
	copy(result, u)

	for i := 1; i < iterations; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(u[:0])
		for j := range result {
			result[j] ^= u[j]
		}
	}
	return result
}

// SignCookie creates an HMAC-signed session cookie.
// Format: username|expiry_unix|hmac_hex
func SignCookie(username, secret string, maxAgeSec int) *http.Cookie {
	expiry := time.Now().Unix() + int64(maxAgeSec)
	payload := fmt.Sprintf("%s|%d", username, expiry)
	sig := computeHMAC(payload, secret)
	return &http.Cookie{
		Name:     CookieName,
		Value:    fmt.Sprintf("%s|%s", payload, sig),
		Path:     "/",
		MaxAge:   maxAgeSec,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// ValidateCookie validates an HMAC-signed session cookie, returning the username.
func ValidateCookie(cookieValue, secret string) (string, error) {
	parts := strings.SplitN(cookieValue, "|", 3)
	if len(parts) != 3 {
		return "", ErrInvalidCookie
	}
	username, expiryStr, sig := parts[0], parts[1], parts[2]

	payload := fmt.Sprintf("%s|%s", username, expiryStr)
	expectedSig := computeHMAC(payload, secret)
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", ErrInvalidCookie
	}

	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return "", ErrInvalidCookie
	}
	if time.Now().Unix() > expiry {
		return "", ErrExpiredCookie
	}
	return username, nil
}

// ClearCookie returns a cookie that clears the session.
func ClearCookie() *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// GenerateSessionSecret generates a cryptographically random 32-byte hex string.
func GenerateSessionSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func computeHMAC(message, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
