package appauth

import "testing"

func TestLoginRateLimiterAllows(t *testing.T) {
	rl := NewLoginRateLimiter(5, 300)
	for i := range 5 {
		if !rl.Allow("192.168.1.1") {
			t.Fatalf("expected allow on attempt %d", i+1)
		}
	}
}

func TestLoginRateLimiterBlocks(t *testing.T) {
	rl := NewLoginRateLimiter(5, 300)
	for range 5 {
		rl.Allow("192.168.1.1")
	}
	if rl.Allow("192.168.1.1") {
		t.Error("expected block after 5 attempts")
	}
}

func TestLoginRateLimiterPerIP(t *testing.T) {
	rl := NewLoginRateLimiter(5, 300)
	for range 5 {
		rl.Allow("192.168.1.1")
	}
	if !rl.Allow("192.168.1.2") {
		t.Error("expected allow for different IP")
	}
}
