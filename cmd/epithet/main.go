package main

import (
	"bufio"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/lmittmann/tint"
)

var cli struct {
	Verbose int             `short:"v" type:"counter" help:"Increase verbosity (-v for debug, -vv for trace)"`
	Config  kong.ConfigFlag `help:"Path to config file"`

	Agent AgentCLI `cmd:"agent" help:"start the epithet agent"`
	Match MatchCLI `cmd:"match" help:"Invoked during ssh invocation in a 'Match exec ...'"`
	CA    CACLI    `cmd:"ca" help:"Run the epithet CA server"`
}

func main() {
	ktx := kong.Parse(&cli, kong.Configuration(KVLoader, "~/.config/epithet/config"))
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

func KVLoader(r io.Reader) (kong.Resolver, error) {
	m := make(map[string][]string)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(strings.ReplaceAll(parts[0], "_", "-"))
		val := parts[1]
		m[key] = append(m[key], val)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return kong.ResolverFunc(func(_ *kong.Context, _ *kong.Path, f *kong.Flag) (any, error) {
		values, ok := m[f.Name]
		if !ok {
			return nil, nil
		}
		// For single value flags, return the last value
		if !f.IsSlice() {
			return values[len(values)-1], nil
		}
		// For slice flags with a single value, return it as a string
		if len(values) == 1 {
			return values[0], nil
		}
		// For slice flags with multiple values, return as comma-separated string
		// Kong will split on commas for slice types
		return strings.Join(values, ","), nil
	}), nil
}
