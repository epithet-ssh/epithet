package main

import (
	"log/slog"
)

type AgentCLI struct {
	Match []string `help:"Match patterns" short:"m"`
	CaURL string   `help:"CA URL" name:"ca-url" short:"c"`
}

func (a *AgentCLI) Run(logger *slog.Logger) error {
	logger.Info("agent command starting")
	logger.Debug("agent command received", "match", a.Match, "ca-url", a.CaURL)
	return nil
}
