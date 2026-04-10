package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadSection reads YAML config files matching the given glob patterns,
// extracts the named section, and decodes the last match into target.
// Later files replace earlier ones entirely (last file wins).
func LoadSection(patterns []string, section string, target any) error {
	paths, err := ExpandGlobs(patterns)
	if err != nil {
		return err
	}

	// Find the last file that contains the section.
	var lastBytes []byte
	var lastPath string
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read config file %s: %w", path, err)
		}

		var raw map[string]any
		if err := yaml.Unmarshal(data, &raw); err != nil {
			continue // Skip files that don't parse as YAML maps.
		}

		sectionData, ok := raw[section]
		if !ok {
			continue
		}

		sectionBytes, err := yaml.Marshal(sectionData)
		if err != nil {
			return fmt.Errorf("failed to marshal %s section from %s: %w", section, path, err)
		}
		lastBytes = sectionBytes
		lastPath = path
	}

	if lastBytes == nil {
		return nil // No config files had this section; caller uses defaults.
	}

	if err := yaml.Unmarshal(lastBytes, target); err != nil {
		return fmt.Errorf("failed to decode %s section from %s: %w", section, lastPath, err)
	}
	return nil
}

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
