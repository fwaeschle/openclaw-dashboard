package appsecrets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// AuditEntry is a single audit record. Value is intentionally absent.
type AuditEntry struct {
	Ts     string `json:"ts"`
	Key    string `json:"key"`
	Action string `json:"action"`
	Via    string `json:"via"`
	User   string `json:"user"`
}

// AppendAudit appends a JSONL audit entry. Parent directories are created.
// Ts is set to the current UTC time if empty.
func AppendAudit(path string, e AuditEntry) error {
	if e.Ts == "" {
		e.Ts = time.Now().UTC().Format(time.RFC3339)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = f.Write(b)
	return err
}
