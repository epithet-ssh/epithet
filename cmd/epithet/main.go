package main

import (
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
	"github.com/lmittmann/tint"
)

var cli struct {
	Verbose int      `short:"v" type:"counter" help:"Increase verbosity (-v for debug, -vv for trace)"`
	Agent   AgentCLI `cmd:"agent" help:"start the epithet agent"`
	Match   MatchCLI `cmd:"match" help:"Invoked during ssh invocation in a 'Match exec ...'"`
}

func main() {
	ktx := kong.Parse(&cli)
	logger := setupLogger()
	ktx.Bind(logger)
	err := ktx.Run()
	if err != nil {
		logger.Error("error", "error", err)
		os.Exit(1)
	}
}

func setupLogger() *slog.Logger {
	// Determine log level based on verbosity
	level := slog.LevelWarn
	switch cli.Verbose {
	case 0:
		level = slog.LevelWarn
	case 1:
		level = slog.LevelInfo
	default: // 2 or more
		level = slog.LevelDebug
	}

	logger := slog.New(tint.NewHandler(os.Stderr, &tint.Options{
		Level:      level,
		TimeFormat: "15:04:05",
	}))

	return logger
}
