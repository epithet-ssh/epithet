package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"cuelang.org/go/cue"
	"github.com/alecthomas/kong"
	"github.com/epithet-ssh/epithet/pkg/config"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/lmittmann/tint"
)

var cli struct {
	Verbose int             `short:"v" type:"counter" help:"Increase verbosity (-v for debug, -vv for trace)"`
	LogFile string          `name:"log-file" help:"Path to log file (supports ~ expansion)" env:"EPITHET_LOG_FILE"`
	Config  kong.ConfigFlag `help:"Path to config file"`

	// TLS configuration flags (global)
	Insecure  bool   `help:"Disable TLS certificate verification (NOT RECOMMENDED)" env:"EPITHET_INSECURE"`
	TLSCACert string `name:"tls-ca-cert" help:"Path to PEM file with trusted CA certificates" env:"EPITHET_TLS_CA_CERT"`

	Agent   AgentCLI        `cmd:"agent" help:"start the epithet agent"`
	Match   MatchCLI        `cmd:"match" help:"Invoked during ssh invocation in a 'Match exec ...'"`
	Inspect InspectCLI      `cmd:"inspect" help:"Inspect broker state (certificates, agents)"`
	CA      CACLI           `cmd:"ca" help:"Run the epithet CA server"`
	Policy  PolicyServerCLI `cmd:"policy" help:"Run the policy server with OIDC-based authorization"`
	Auth    AuthCLI         `cmd:"auth" help:"Authentication commands (OIDC, SAML, etc.)"`
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

	unifiedConfig, err := config.LoadAndUnifyPaths(configPaths)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ktx := kong.Parse(&cli, kong.Resolvers(&cueResolver{value: unifiedConfig}))
	logger := setupLogger()

	// Create TLS config from global flags
	tlsCfg := tlsconfig.Config{
		Insecure:   cli.Insecure,
		CACertFile: cli.TLSCACert,
	}

	ktx.Bind(logger)
	ktx.Bind(tlsCfg)
	err = ktx.Run()
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


// cueResolver implements kong.Resolver using direct CUE value lookups
type cueResolver struct {
	value cue.Value
}

func (r *cueResolver) Validate(app *kong.Application) error {
	return nil
}

func (r *cueResolver) Resolve(ctx *kong.Context, parent *kong.Path, flag *kong.Flag) (any, error) {
	// Build the config path from command context
	cmdPath := getCommandPath(parent)

	// Normalize flag name: convert kebab-case to snake_case
	flagName := strings.ReplaceAll(flag.Name, "-", "_")

	// Build full path: e.g., "agent.ca_url" or just "insecure" for globals
	var cuePath string
	if len(cmdPath) == 0 {
		cuePath = flagName
	} else {
		cuePath = strings.Join(append(cmdPath, flagName), ".")
	}

	// Look up the value in CUE
	val := r.value.LookupPath(cue.ParsePath(cuePath))
	if !val.Exists() {
		return nil, nil
	}

	// Extract the value based on type
	return extractValue(val, flag.IsSlice())
}

// getCommandPath extracts the command path from kong's parent path
func getCommandPath(parent *kong.Path) []string {
	if parent == nil {
		return nil
	}

	var path []string
	for n := parent.Node(); n != nil; n = n.Parent {
		if n.Type == kong.CommandNode && n.Name != "" {
			path = append([]string{n.Name}, path...)
		}
	}
	return path
}

// extractValue extracts a Go value from a CUE value
func extractValue(val cue.Value, isSlice bool) (any, error) {
	// Handle lists/slices
	if isSlice {
		iter, err := val.List()
		if err != nil {
			// Not a list, try as single value
			str, err := val.String()
			if err != nil {
				return nil, nil
			}
			return str, nil
		}

		var items []string
		for iter.Next() {
			str, err := iter.Value().String()
			if err != nil {
				continue
			}
			items = append(items, str)
		}

		if len(items) == 0 {
			return nil, nil
		}
		if len(items) == 1 {
			return items[0], nil
		}
		return strings.Join(items, ","), nil
	}

	// Handle booleans
	if b, err := val.Bool(); err == nil {
		if b {
			return true, nil
		}
		return nil, nil // Don't return false, let kong use default
	}

	// Handle integers
	if i, err := val.Int64(); err == nil {
		if i > 0 {
			return i, nil
		}
		return nil, nil // Don't return 0, let kong use default
	}

	// Handle strings
	if str, err := val.String(); err == nil {
		if str != "" {
			return str, nil
		}
		return nil, nil
	}

	return nil, nil
}

// Ensure cueResolver implements kong.Resolver
var _ kong.Resolver = (*cueResolver)(nil)
