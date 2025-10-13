package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// SimpleConfig represents parsed configuration
type SimpleConfig struct {
	Match []string
	CaURL string
}

// LoadSimpleConfig reads a simple line-based config file
// Format:
//
//	match <pattern>
//	ca-url <url>
//
// Lines starting with # are comments
// Empty lines are ignored
func LoadSimpleConfig(path string) (*SimpleConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open config file: %w", err)
	}
	defer file.Close()

	cfg := &SimpleConfig{
		Match: []string{},
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split into directive and value
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			return nil, fmt.Errorf("line %d: invalid format, expected '<directive> <value>'", lineNum)
		}

		directive := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch directive {
		case "match":
			cfg.Match = append(cfg.Match, value)
		case "ca-url":
			if cfg.CaURL != "" {
				return nil, fmt.Errorf("line %d: ca-url can only be specified once", lineNum)
			}
			cfg.CaURL = value
		default:
			return nil, fmt.Errorf("line %d: unknown directive %q", lineNum, directive)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	return cfg, nil
}

// MergeWithFlags merges config file values with command-line flags
// - match patterns are additive (config + flags)
// - ca-url from flags replaces config value if set
func (cfg *SimpleConfig) MergeWithFlags(flagMatch []string, flagCaURL string) {
	// Match patterns are additive - config patterns + flag patterns
	cfg.Match = append(cfg.Match, flagMatch...)

	// CA URL from flag replaces config value if flag was set
	if flagCaURL != "" {
		cfg.CaURL = flagCaURL
	}
}
