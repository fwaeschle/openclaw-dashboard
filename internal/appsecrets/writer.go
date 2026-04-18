package appsecrets

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"regexp"
)

// SetKey writes key=value to the .env at path atomically. Existing lines for
// key are replaced; if absent, key=value is appended. Missing file is created.
func SetKey(path, key, value string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	if err := ValidateValue(value); err != nil {
		return err
	}

	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	line := []byte(key + "=" + value)
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `=.*$`)
	var next []byte
	if re.Match(existing) {
		next = re.ReplaceAll(existing, line)
	} else {
		next = append([]byte{}, existing...)
		if len(next) > 0 && next[len(next)-1] != '\n' {
			next = append(next, '\n')
		}
		next = append(next, line...)
	}
	if len(next) == 0 || next[len(next)-1] != '\n' {
		next = append(next, '\n')
	}
	return writeAtomic(path, next)
}

// DeleteKey removes the line for key from .env at path atomically.
// Returns errors.New("key_not_found") if key is absent.
func DeleteKey(path, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return errors.New("key_not_found")
		}
		return err
	}
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `=.*(?:\r?\n)?`)
	if !re.Match(existing) {
		return errors.New("key_not_found")
	}
	next := re.ReplaceAll(existing, nil)
	next = bytes.ReplaceAll(next, []byte("\n\n"), []byte("\n"))
	return writeAtomic(path, next)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
