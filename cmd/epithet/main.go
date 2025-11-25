package main

import (
	"bufio"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/lmittmann/tint"
)

var cli struct {
	Verbose int             `short:"v" type:"counter" help:"Increase verbosity (-v for debug, -vv for trace)"`
	Config  kong.ConfigFlag `help:"Path to config file"`

	// TLS configuration flags (global)
	Insecure  bool   `help:"Disable TLS certificate verification (NOT RECOMMENDED)" env:"EPITHET_INSECURE"`
	TLSCACert string `name:"tls-ca-cert" help:"Path to PEM file with trusted CA certificates" env:"EPITHET_TLS_CA_CERT"`

	Agent   AgentCLI        `cmd:"agent" help:"start the epithet agent"`
	Match   MatchCLI        `cmd:"match" help:"Invoked during ssh invocation in a 'Match exec ...'"`
	Inspect InspectCLI      `cmd:"inspect" help:"Inspect broker state (certificates, agents)"`
	CA      CACLI           `cmd:"ca" help:"Run the epithet CA server"`
	Policy  PolicyServerCLI `cmd:"policy" help:"Run the policy server with OIDC-based authorization"`
	AWS     AWSCLI          `cmd:"aws" help:"AWS deployment commands"`
	Auth    AuthCLI         `cmd:"auth" help:"Authentication commands (OIDC, SAML, etc.)"`
}

func main() {
	// Check if we're running in Lambda mode via environment variable
	if epithetCmd := os.Getenv("EPITHET_CMD"); epithetCmd != "" {
		// Parse the command from environment (e.g., "aws ca")
		args := strings.Fields(epithetCmd)
		os.Args = append([]string{os.Args[0]}, args...)
	}

	ktx := kong.Parse(&cli, kong.Configuration(KVLoader, "~/.epithet/config"))
	logger := setupLogger()

	// Create TLS config from global flags
	tlsCfg := tlsconfig.Config{
		Insecure:   cli.Insecure,
		CACertFile: cli.TLSCACert,
	}

	ktx.Bind(logger)
	ktx.Bind(tlsCfg)
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
	// Determine config directory for template expansion
	// If r is a file, get its directory; otherwise use current directory
	configDir := "."
	if f, ok := r.(*os.File); ok {
		if path, err := expandPath(f.Name()); err == nil {
			configDir = strings.TrimSuffix(path, "/"+strings.TrimPrefix(path, "/"))
			// Get directory from full path
			if idx := strings.LastIndex(path, "/"); idx != -1 {
				configDir = path[:idx]
			}
		}
	}

	// Get home directory for template expansion
	homeDir, _ := os.UserHomeDir()

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
		val := strings.Join(parts[1:], " ") // Join all parts after the key

		// Expand templates in value
		val = expandConfigTemplates(val, configDir, homeDir)

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

// expandConfigTemplates expands template variables in config values
// Supported templates:
//
//	{config_dir} - directory containing the config file
//	{home} - user's home directory
//	{env.VAR_NAME} - environment variable
func expandConfigTemplates(val, configDir, homeDir string) string {
	// Replace {config_dir}
	val = strings.ReplaceAll(val, "{config_dir}", configDir)

	// Replace {home}
	val = strings.ReplaceAll(val, "{home}", homeDir)

	// Replace {env.VAR_NAME} with environment variables
	for {
		start := strings.Index(val, "{env.")
		if start == -1 {
			break
		}
		end := strings.Index(val[start:], "}")
		if end == -1 {
			break
		}
		end += start

		envVar := val[start+5 : end] // Extract VAR_NAME from {env.VAR_NAME}
		envVal := os.Getenv(envVar)
		val = val[:start] + envVal + val[end+1:]
	}

	return val
}
