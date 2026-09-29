package main

import (
	"path/filepath"

	"github.com/epithet-ssh/epithet/pkg/config"
)

// Resolve paths only for enabled stores; static mode never opens managed state.
func serviceStatePath(root string, elements ...string) (string, error) {
	var err error
	if root == "" {
		root, err = config.SystemStateDir()
	} else {
		root, err = expandPath(root)
	}
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{root}, elements...)...), nil
}
