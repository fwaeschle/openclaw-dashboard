package appsecrets

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
)

// ListKeys returns the sorted list of key names present in the .env at path.
// Missing file returns an empty slice with no error. Comment lines (starting
// with '#') and malformed lines are skipped.
func ListKeys(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []string{}, nil
		}
		return nil, err
	}
	defer f.Close()

	keys := make([]string, 0, 16)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := line[:eq]
		if ValidateKey(key) != nil {
			continue
		}
		keys = append(keys, key)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	slices.Sort(keys)
	return keys, nil
}
