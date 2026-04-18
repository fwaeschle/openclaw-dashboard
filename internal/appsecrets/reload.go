package appsecrets

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// ReloadFunc triggers an OpenClaw secrets reload. Returning nil means success.
// Wrapping errors as "reload_failed" is the caller's responsibility so the
// seam can be swapped in tests.
type ReloadFunc func(ctx context.Context) error

// SystemReload runs `openclaw secrets reload` with a 30s timeout.
// stderr is discarded here; callers that need it should wrap.
func SystemReload(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "openclaw", "secrets", "reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New("reload_failed: " + strings.TrimSpace(string(out)))
	}
	return nil
}
