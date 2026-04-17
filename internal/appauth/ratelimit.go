package appauth

import (
	"sync"
	"time"
)

type loginAttempt struct {
	count       int
	windowStart time.Time
}

// LoginRateLimiter tracks login attempts per IP with a sliding window.
type LoginRateLimiter struct {
	maxAttempts int
	windowSec   int64
	mu          sync.Mutex
	attempts    map[string]*loginAttempt
}

// NewLoginRateLimiter creates a rate limiter allowing maxAttempts per windowSec seconds.
func NewLoginRateLimiter(maxAttempts int, windowSec int64) *LoginRateLimiter {
	return &LoginRateLimiter{
		maxAttempts: maxAttempts,
		windowSec:   windowSec,
		attempts:    make(map[string]*loginAttempt),
	}
}

// Allow returns true if the IP has not exceeded the rate limit.
func (rl *LoginRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	a, exists := rl.attempts[ip]

	if !exists || now.Sub(a.windowStart) > time.Duration(rl.windowSec)*time.Second {
		rl.attempts[ip] = &loginAttempt{count: 1, windowStart: now}
		return true
	}

	a.count++
	return a.count <= rl.maxAttempts
}

// Cleanup removes stale entries older than the window.
func (rl *LoginRateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Duration(rl.windowSec) * time.Second
	now := time.Now()
	for ip, a := range rl.attempts {
		if now.Sub(a.windowStart) > cutoff {
			delete(rl.attempts, ip)
		}
	}
}
