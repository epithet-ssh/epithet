// Package config provides unified configuration loading for epithet.
// It supports YAML, JSON, and CUE file formats using CUE as the underlying parser.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"
	"cuelang.org/go/encoding/yaml"
)

// LoadValue loads configuration from a file and returns a CUE value.
// This allows dynamic path-based lookups without requiring Go struct definitions.
//
// For .cue files: Uses CUE's load.Instances to support CUE packages with imports and modules.
// For .yaml/.yml/.json files: Uses direct parsing for standalone data files.
// For directories: Loads all .cue files as a package (supports imports between files).
func LoadValue(path string) (cue.Value, error) {
	ctx := cuecontext.New()

	// Check if path exists
	fileInfo, err := os.Stat(path)
	if err != nil {
		return cue.Value{}, fmt.Errorf("failed to stat path: %w", err)
	}

	var val cue.Value

	// Handle directories and .cue files using load.Instances
	if fileInfo.IsDir() || strings.HasSuffix(strings.ToLower(path), ".cue") {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return cue.Value{}, fmt.Errorf("failed to resolve path: %w", err)
		}

		cfg := &load.Config{
			Dir:       filepath.Dir(absPath),
			DataFiles: true,
		}

		var args []string
		if fileInfo.IsDir() {
			args = []string{path}
		} else {
			args = []string{absPath}
		}

		instances := load.Instances(args, cfg)
		if len(instances) == 0 {
			return cue.Value{}, fmt.Errorf("no instances loaded from %s", path)
		}

		inst := instances[0]
		if inst.Err != nil {
			return cue.Value{}, fmt.Errorf("failed to load config: %w", inst.Err)
		}

		val = ctx.BuildInstance(inst)
		if err := val.Err(); err != nil {
			return cue.Value{}, fmt.Errorf("failed to build CUE value: %w", err)
		}
	} else {
		// Handle standalone data files (YAML, JSON)
		data, err := os.ReadFile(path)
		if err != nil {
			return cue.Value{}, fmt.Errorf("failed to read file: %w", err)
		}

		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".yaml", ".yml":
			// Use YAML decoder
			file, err := yaml.Extract("", data)
			if err != nil {
				return cue.Value{}, fmt.Errorf("failed to parse YAML: %w", err)
			}
			val = ctx.BuildFile(file)
		case ".json":
			// JSON can be compiled directly
			val = ctx.CompileBytes(data)
		default:
			// Try YAML as default
			file, err := yaml.Extract("", data)
			if err != nil {
				return cue.Value{}, fmt.Errorf("failed to parse file: %w", err)
			}
			val = ctx.BuildFile(file)
		}

		if err := val.Err(); err != nil {
			return cue.Value{}, fmt.Errorf("failed to build CUE value: %w", err)
		}
	}

	return val, nil
}

// LoadFromFile loads configuration from a file or directory into the specified type.
//
// For .cue files: Uses CUE's load.Instances to support CUE packages with imports and modules.
// For .yaml/.yml/.json files: Uses direct parsing for standalone data files.
// For directories: Loads all .cue files as a package (supports imports between files).
//
// Examples:
//
//	cfg, err := LoadFromFile[PolicyRulesConfig]("policy.yaml")
//	cfg, err := LoadFromFile[PolicyRulesConfig]("./config")  // loads .cue directory
func LoadFromFile[T any](path string) (*T, error) {
	val, err := LoadValue(path)
	if err != nil {
		return nil, err
	}

	// Decode into Go struct
	var config T
	if err := val.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	return &config, nil
}

// LoadAndUnifyPaths loads multiple config files and unifies them into a single CUE value.
// Supports glob patterns and mixed file types (.cue, .yaml, .yml, .json).
// Missing files are silently skipped. Returns error if files have conflicting values.
func LoadAndUnifyPaths(patterns []string) (cue.Value, error) {
	ctx := cuecontext.New()
	var values []cue.Value
	var loadedPaths []string

	for _, pattern := range patterns {
		// Expand ~ to home directory
		expanded := expandPath(pattern)

		// Handle glob patterns
		matches, err := filepath.Glob(expanded)
		if err != nil {
			continue // Invalid pattern, skip
		}
		if len(matches) == 0 {
			// Try as literal path (for non-glob patterns that don't exist)
			if _, err := os.Stat(expanded); err == nil {
				matches = []string{expanded}
			}
		}

		for _, path := range matches {
			val, err := loadSingleFile(ctx, path)
			if err != nil {
				return cue.Value{}, err
			}
			if !val.Exists() {
				continue // Skip unreadable files
			}

			values = append(values, val)
			loadedPaths = append(loadedPaths, path)
		}
	}

	if len(values) == 0 {
		// No config files found - return empty value (not an error)
		return ctx.CompileString("{}"), nil
	}

	// Unify all values
	result := values[0]
	for i, v := range values[1:] {
		result = result.Unify(v)
		if err := result.Err(); err != nil {
			return cue.Value{}, fmt.Errorf("config conflict between %s and %s: %w",
				loadedPaths[0], loadedPaths[i+1], err)
		}
	}

	return result, nil
}

// loadSingleFile loads a single config file, detecting type by extension.
// Returns empty value (not error) for unreadable files.
func loadSingleFile(ctx *cue.Context, path string) (cue.Value, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return cue.Value{}, nil // Skip unreadable files
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".cue":
		// Use CUE's native parser for .cue files
		val := ctx.CompileBytes(data, cue.Filename(path))
		if err := val.Err(); err != nil {
			return cue.Value{}, fmt.Errorf("failed to parse %s: %w", path, err)
		}
		return val, nil
	case ".yaml", ".yml":
		file, err := yaml.Extract(path, data)
		if err != nil {
			return cue.Value{}, fmt.Errorf("failed to parse %s: %w", path, err)
		}
		val := ctx.BuildFile(file)
		if err := val.Err(); err != nil {
			return cue.Value{}, fmt.Errorf("failed to build %s: %w", path, err)
		}
		return val, nil
	case ".json":
		val := ctx.CompileBytes(data, cue.Filename(path))
		if err := val.Err(); err != nil {
			return cue.Value{}, fmt.Errorf("failed to parse %s: %w", path, err)
		}
		return val, nil
	default:
		// Try YAML as fallback
		file, err := yaml.Extract(path, data)
		if err != nil {
			return cue.Value{}, fmt.Errorf("failed to parse %s: %w", path, err)
		}
		val := ctx.BuildFile(file)
		if err := val.Err(); err != nil {
			return cue.Value{}, fmt.Errorf("failed to build %s: %w", path, err)
		}
		return val, nil
	}
}

// expandPath expands ~ to the user's home directory
func expandPath(path string) string {
	if len(path) == 0 || path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if len(path) == 1 {
		return home
	}
	return filepath.Join(home, path[1:])
}
