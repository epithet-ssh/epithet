package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/alecthomas/kong"
)

// defaultConfigPatterns defines where to look for config files.
var defaultConfigPatterns = []string{
	"/etc/epithet/*.toml",
	"~/.epithet/*.toml",
}

// loadCLIConfig decodes flat TOML defaults keyed by exact long flag name.
// Kong owns flag types and command selection; this loader has no command schema.
// SSH's match inputs are CLI-only, while its global flags remain configurable.
func loadCLIConfig(r io.Reader) (kong.Resolver, error) {
	values := map[string]any{}
	if _, err := toml.NewDecoder(r).Decode(&values); err != nil {
		return nil, err
	}
	return kong.ResolverFunc(func(_ *kong.Context, parent *kong.Path, flag *kong.Flag) (any, error) {
		if parent.Command != nil && parent.Command.Name == "match" {
			return nil, nil
		}
		value, ok := values[flag.Name]
		if !ok {
			return nil, nil
		}
		if flag.IsSlice() {
			if _, ok := value.([]any); !ok {
				return nil, fmt.Errorf("config key %q requires an array", flag.Name)
			}
		}
		// TOML integers are int64; Kong's counter mapper expects textual input
		// or a native int. Preserve the full value and let Kong check its range.
		if n, ok := value.(int64); ok {
			return strconv.FormatInt(n, 10), nil
		}
		return value, nil
	}), nil
}

// defaultConfigFiles keeps normal parsing and the launcher's child reparse on
// the same file order. Kong adds an explicit --config file as the last resolver.
func defaultConfigFiles() []string {
	paths, _ := expandGlobs(defaultConfigPatterns)
	return paths
}

// expandGlobs expands configured patterns into existing file paths.
// Patterns support ~ for home directory expansion.
func expandGlobs(patterns []string) ([]string, error) {
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
