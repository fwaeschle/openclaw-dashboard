package appsecrets

import (
	"errors"
	"regexp"
)

const (
	maxKeyLen   = 128
	maxValueLen = 500
)

var keyRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// ValidateKey enforces the .env key grammar.
func ValidateKey(key string) error {
	if key == "" {
		return errors.New("key_empty")
	}
	if len(key) > maxKeyLen {
		return errors.New("key_too_long")
	}
	if !keyRe.MatchString(key) {
		return errors.New("key_format")
	}
	return nil
}

// ValidateValue enforces length and newline-free value rules.
func ValidateValue(value string) error {
	if value == "" {
		return errors.New("value_empty")
	}
	if len(value) > maxValueLen {
		return errors.New("value_too_long")
	}
	for _, r := range value {
		if r == '\n' || r == '\r' {
			return errors.New("value_has_newline")
		}
	}
	return nil
}
