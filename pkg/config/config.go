package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ExpandGlobs expands semicolon-separated glob patterns into a list of
// existing file paths. Patterns support ~ for home directory expansion.
func ExpandGlobs(patterns []string) ([]string, error) {
	var paths []string
	for _, pattern := range patterns {
		pattern = expandHome(pattern)
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern %q: %w", pattern, err)
		}
		paths = append(paths, matches...)
	}
	return paths, nil
}

func expandHome(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[1:])
}
