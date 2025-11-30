// Package config provides unified configuration loading for epithet.
// It supports YAML, JSON, and CUE file formats using CUE as the underlying parser.
package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"
	"cuelang.org/go/encoding/yaml"
)

// LoadValueFromReader loads configuration from an io.Reader and returns a CUE value.
// This parses the content as YAML (which is a superset of JSON).
// For .cue files with imports, use LoadValue instead.
func LoadValueFromReader(r io.Reader) (cue.Value, error) {
	ctx := cuecontext.New()

	data, err := io.ReadAll(r)
	if err != nil {
		return cue.Value{}, fmt.Errorf("failed to read config: %w", err)
	}

	// Parse as YAML (superset of JSON)
	file, err := yaml.Extract("", data)
	if err != nil {
		return cue.Value{}, fmt.Errorf("failed to parse config: %w", err)
	}

	val := ctx.BuildFile(file)
	if err := val.Err(); err != nil {
		return cue.Value{}, fmt.Errorf("failed to build CUE value: %w", err)
	}

	return val, nil
}

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
