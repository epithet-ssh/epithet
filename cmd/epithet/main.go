package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/brianm/kongcue"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/lmittmann/tint"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var cli struct {
	Version kong.VersionFlag `short:"V" help:"Print version information"`
	Verbose int              `short:"v" type:"counter" help:"Increase verbosity (-v for debug, -vv for trace)"`
	LogFile string           `name:"log-file" help:"Path to log file (supports ~ expansion)" env:"EPITHET_LOG_FILE"`
	Config  kong.ConfigFlag  `help:"Path to config file"`

	// TLS configuration flags (global)
	Insecure  bool   `help:"Disable TLS certificate verification (NOT RECOMMENDED)" env:"EPITHET_INSECURE"`
	TLSCACert string `name:"tls-ca-cert" help:"Path to PEM file with trusted CA certificates" env:"EPITHET_TLS_CA_CERT"`

	Agent  AgentCLI        `cmd:"agent" help:"Start the epithet agent (or use 'agent inspect' to inspect state)"`
	Match  MatchCLI        `cmd:"match" help:"Invoked during ssh invocation in a 'Match exec ...'"`
	CA     CACLI           `cmd:"ca" help:"Run the epithet CA server"`
	Policy PolicyServerCLI `cmd:"policy" help:"Run the policy server with OIDC-based authorization"`
	Auth   AuthCLI         `cmd:"auth" help:"Authentication commands (OIDC, SAML, etc.)"`
}

func main() {
	// Check if we're running in Lambda mode via environment variable
	if epithetCmd := os.Getenv("EPITHET_CMD"); epithetCmd != "" {
		// Parse the command from environment (e.g., "aws ca")
		args := strings.Fields(epithetCmd)
		os.Args = append([]string{os.Args[0]}, args...)
	}

	// Load and unify config files
	configPaths := []string{
		"~/.epithet/*.yaml",
		"~/.epithet/*.yml",
		"~/.epithet/*.cue",
		"~/.epithet/*.json",
	}

	unifiedConfig, err := kongcue.LoadAndUnifyPaths(configPaths)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ktx := kong.Parse(&cli,
		kong.Vars{"version": version + " (" + commit + ", " + date + ")"},
		kong.Resolvers(kongcue.NewResolver(unifiedConfig)),
	)
	logger := setupLogger()

	// Create TLS config from global flags
	tlsCfg := tlsconfig.Config{
		Insecure:   cli.Insecure,
		CACertFile: cli.TLSCACert,
	}

	ktx.Bind(logger)
	ktx.Bind(tlsCfg)
	ktx.Bind(unifiedConfig) // Bind CUE value for commands that need full config (e.g., policy)
	err = ktx.Run()
	if err != nil {
		logger.Error("error", "error", err)
		os.Exit(1)
	}
}

// expandPath expands ~ to the user's home directory
func expandPath(path string) (string, error) {
	if path == "" {
		return path, nil
	}
	if path[0] != '~' {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, path[1:]), nil
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

	// Determine output writer
	var w io.Writer = os.Stderr
	if cli.LogFile != "" {
		path, err := expandPath(cli.LogFile)
		if err != nil {
			// Fall back to stderr if path expansion fails
			slog.Error("failed to expand log file path", "error", err)
		} else {
			// Ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				slog.Error("failed to create log directory", "error", err)
			} else {
				f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
				if err != nil {
					slog.Error("failed to open log file", "error", err)
				} else {
					w = f
				}
			}
		}
	}

	logger := slog.New(tint.NewHandler(w, &tint.Options{
		Level:      level,
		TimeFormat: "15:04:05",
	}))

	return logger
}
