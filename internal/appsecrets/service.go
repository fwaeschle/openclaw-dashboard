package appsecrets

import (
	"context"
	"errors"
)

// Config configures a Service instance.
type Config struct {
	EnvPath   string
	AuditPath string
	Reload    ReloadFunc // nil means no-op reload (useful for tests)
}

// Service is the orchestration seam for handlers.
type Service struct {
	cfg Config
}

// NewService returns a Service. Production wiring should set Config.Reload
// to SystemReload.
func NewService(cfg Config) *Service {
	if cfg.Reload == nil {
		cfg.Reload = func(ctx context.Context) error { return nil }
	}
	return &Service{cfg: cfg}
}

// List returns the sorted list of present keys.
func (s *Service) List() ([]string, error) {
	return ListKeys(s.cfg.EnvPath)
}

// Set creates or replaces key=value, writes an audit entry, and triggers
// a reload. Reload errors are returned but the file and audit have been
// persisted before the reload call.
func (s *Service) Set(ctx context.Context, key, value, user string) error {
	if err := SetKey(s.cfg.EnvPath, key, value); err != nil {
		return err
	}
	if err := AppendAudit(s.cfg.AuditPath, AuditEntry{
		Key:    key,
		Action: "set",
		Via:    "dashboard",
		User:   user,
	}); err != nil {
		return err
	}
	return s.cfg.Reload(ctx)
}

// Delete removes key, writes an audit entry, and triggers a reload.
func (s *Service) Delete(ctx context.Context, key, user string) error {
	if err := DeleteKey(s.cfg.EnvPath, key); err != nil {
		return err
	}
	if err := AppendAudit(s.cfg.AuditPath, AuditEntry{
		Key:    key,
		Action: "delete",
		Via:    "dashboard",
		User:   user,
	}); err != nil {
		return err
	}
	return s.cfg.Reload(ctx)
}

// ErrKeyNotFound is the sentinel for delete-on-missing.
var ErrKeyNotFound = errors.New("key_not_found")
