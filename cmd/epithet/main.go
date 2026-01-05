package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/brianm/kongcue"
	"github.com/epithet-ssh/epithet/pkg/slogoslog"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/lmittmann/tint"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var cli struct {
	Version   kong.VersionFlag `short:"V" help:"Print version information"`
	Verbose   int              `short:"v" type:"counter" help:"Increase verbosity (-v for debug, -vv for trace)"`
	LogFile   string           `name:"log-file" help:"Path to log file (supports ~ expansion)" env:"EPITHET_LOG_FILE"`
	NativeLog bool             `name:"native-log" help:"Use native OS logging (macOS: Console.app)" env:"EPITHET_NATIVE_LOG"`
	Config    kongcue.Config   `help:"Path to config file" sep:";" default:"/etc/epithet/*.{cue,yaml,yml,json};~/.epithet/*.{cue,yaml,yml,json}"`

	// TLS configuration flags (global)
	Insecure  bool   `help:"Disable TLS certificate verification (NOT RECOMMENDED)" env:"EPITHET_INSECURE"`
	TLSCACert string `name:"tls-ca-cert" help:"Path to PEM file with trusted CA certificates" env:"EPITHET_TLS_CA_CERT"`

	Agent     AgentCLI          `cmd:"agent" help:"Start the epithet agent (or use 'agent inspect' to inspect state)"`
	Match     MatchCLI          `cmd:"match" help:"Invoked during ssh invocation in a 'Match exec ...'"`
	CA        CACLI             `cmd:"ca" help:"Run the epithet CA server"`
	Policy    PolicyServerCLI   `cmd:"policy" help:"Run the policy server with OIDC-based authorization"`
	Auth      AuthCLI           `cmd:"auth" help:"Authentication commands (OIDC, SAML, etc.)"`
	ConfigDoc kongcue.ConfigDoc `cmd:"" help:"Print the configuration file schema and docs"`
}

func main() {
	// we also allow command to be named epithet-agent and such, to imply a command
	if baseName := filepath.Base(os.Args[0]); strings.Contains(baseName, "-") {
		parts := strings.SplitN(baseName, "-", 2)
		if len(parts) == 2 {
			// Transform [epithet-policy, --woof, --meow] -> [epithet, policy, --woof, --meow]
			os.Args = append([]string{parts[0], parts[1]}, os.Args[1:]...)
		}
	}

	ktx := kong.Parse(&cli,
		kong.Vars{"version": version + " (" + commit + ", " + date + ")"},
		kong.ShortUsageOnError(),
		kongcue.AllowUnknownFields("policy.users", "policy.defaults", "policy.hosts", "policy.oidc"),
	)
	logger := setupLogger()

	// Create TLS config from global flags
	tlsCfg := tlsconfig.Config{
		Insecure:   cli.Insecure,
		CACertFile: cli.TLSCACert,
	}

	ktx.Bind(logger)
	ktx.Bind(tlsCfg)
	err := ktx.Run()
	ktx.FatalIfErrorf(err)
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
	// Determine log level based on verbosity.
	level := slog.LevelWarn
	switch cli.Verbose {
	case 0:
		level = slog.LevelWarn
	case 1:
		level = slog.LevelInfo
	default: // 2 or more
		level = slog.LevelDebug
	}

	// If native logging requested, try to use it.
	if cli.NativeLog {
		if handler := slogoslog.NewHandler(level); handler != nil {
			return slog.New(handler)
		}
		// Fall through to default handler if native not available.
		slog.Warn("native logging not available on this platform, using console")
	}

	// Determine output writer.
	var w io.Writer = os.Stderr
	if cli.LogFile != "" {
		path, err := expandPath(cli.LogFile)
		if err != nil {
			// Fall back to stderr if path expansion fails.
			slog.Error("failed to expand log file path", "error", err)
		} else {
			// Ensure parent directory exists.
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
