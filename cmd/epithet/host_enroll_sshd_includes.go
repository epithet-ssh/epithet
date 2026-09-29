package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// globalSSHDIncludes finds include patterns in global scope, including nested
// files. Each included file has its own Match scope: OpenSSH restores the
// containing file's scope when it returns. Patterns are retained even when no
// file matches yet, so a new enrollment fragment can use an existing glob.
func globalSSHDIncludes(config []byte, goos string) ([]string, error) {
	includeDir := filepath.Dir(platformSSHDDefaults(goos, os.Getenv).configFile)
	if includeDir == "." {
		includeDir = "/etc/ssh"
	}
	var patterns []string
	var visit func([]byte, int) error
	visit = func(data []byte, depth int) error {
		if depth > 16 {
			return fmt.Errorf("sshd Include nesting exceeds 16 levels")
		}
		for _, line := range strings.Split(string(data), "\n") {
			keyword, args := sshdDirective(line)
			if keyword == "match" {
				break
			}
			if keyword != "include" {
				continue
			}
			paths, err := splitSSHDInclude(args)
			if err != nil {
				return err
			}
			for _, pattern := range paths {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(includeDir, pattern)
				}
				patterns = append(patterns, pattern)
				matches, err := filepath.Glob(pattern)
				if err != nil {
					return fmt.Errorf("invalid sshd Include pattern %q: %w", pattern, err)
				}
				for _, path := range matches {
					included, err := os.ReadFile(path)
					if err != nil {
						return fmt.Errorf("reading sshd Include %s: %w", path, err)
					}
					if err := visit(included, depth+1); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	err := visit(config, 0)
	return patterns, err
}

func sshdDirective(line string) (string, string) {
	line = strings.TrimSpace(line)
	end := strings.IndexAny(line, " \t=")
	if end < 0 {
		return strings.ToLower(line), ""
	}
	return strings.ToLower(line[:end]), strings.TrimLeft(line[end:], " \t=")
}

// splitSSHDInclude follows OpenSSH's argument quoting and escaping rules; '#'
// starts a comment only at a token boundary. It does not interpret shell syntax.
func splitSSHDInclude(args string) ([]string, error) {
	var paths []string
	for args = strings.TrimSpace(args); args != "" && args[0] != '#'; args = strings.TrimSpace(args) {
		var token strings.Builder
		var quote byte
		i := 0
		for ; i < len(args); i++ {
			c := args[i]
			if c == '\\' && i+1 < len(args) && (strings.ContainsRune(`\"'`, rune(args[i+1])) || (quote == 0 && args[i+1] == ' ')) {
				i++
				token.WriteByte(args[i])
			} else if quote == 0 && (c == ' ' || c == '\t') {
				break
			} else if quote == 0 && (c == '"' || c == '\'') {
				quote = c
			} else if quote != 0 && c == quote {
				quote = 0
			} else {
				token.WriteByte(c)
			}
		}
		if quote != 0 || token.Len() == 0 {
			return nil, fmt.Errorf("invalid sshd Include arguments %q", args)
		}
		paths = append(paths, token.String())
		args = args[i:]
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("sshd Include has no paths")
	}
	return paths, nil
}

// findIncludedSSHDEnrollment recovers custom enrollment paths after the managed
// main-file block has been removed in favor of an operator's global Include.
func findIncludedSSHDEnrollment(config []byte, goos string) (string, error) {
	patterns, err := globalSSHDIncludes(config, goos)
	if err != nil {
		return "", err
	}
	var found string
	for _, pattern := range patterns {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			return "", err
		}
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				return "", err
			}
			if !strings.HasPrefix(string(data), sshdFragmentHeader+"\n") {
				continue
			}
			if found != "" && found != path {
				return "", fmt.Errorf("multiple Epithet enrollment fragments included: %s and %s", found, path)
			}
			found = path
		}
	}
	return found, nil
}
