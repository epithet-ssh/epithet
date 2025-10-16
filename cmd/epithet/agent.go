package main

import (
	"log/slog"
)

type AgentCLI struct {
	Match []string `help:"Match patterns" short:"m" required:"true"`
	CaURL string   `help:"CA URL" name:"ca-url" short:"c" required:"true"`
	Auth  string   `help:"Authentication command" short:"a" required:"true"`
}

func (a *AgentCLI) Run(logger *slog.Logger) error {
	logger.Debug("agent command received", "match", a.Match, "ca-url", a.CaURL, "auth", a.Auth)
	return nil
}
