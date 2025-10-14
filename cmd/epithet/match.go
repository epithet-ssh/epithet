package main

import (
	"errors"
	"log/slog"
)

type MatchCLI struct {
}

func (a *MatchCLI) Run(logger *slog.Logger) error {
	logger.Info("match command called")
	return errors.New("`match` command not implemented yet")
}
