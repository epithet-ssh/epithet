package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffcli"
	log "github.com/sirupsen/logrus"
)

func runAgentCmd(args []string) error {
	// Create flag set for agent command
	fs := flag.NewFlagSet("epithet agent", flag.ExitOnError)

	var (
		configFile = fs.String("config", "", "config file path (optional)")
		caURL      = fs.String("ca-url", "", "URL of the certificate authority")
		verbose    = fs.Int("v", 0, "log verbosity (0=warn, 1=info, 2=debug)")
	)

	// StringSlice for repeated match flags
	matchPatterns := &StringSliceFlag{}
	fs.Var(matchPatterns, "match", "hostname pattern to handle (repeatable)")

	// Create ffcli command
	cmd := &ffcli.Command{
		Name:       "agent",
		ShortUsage: "epithet agent [flags]",
		ShortHelp:  "Run the epithet agent process",
		LongHelp: `The agent command runs the main epithet agent process that manages
per-connection SSH agents.

The agent process:
- Maintains a map of connection hash → ssh-agent process
- Spawns OpenSSH ssh-agent processes for each unique connection
- Tracks certificate expiration and public keys
- Handles communication from 'epithet auth' commands
- Creates agent sockets in ~/.epithet/sockets/

Configuration precedence (highest to lowest):
1. Command-line flags
2. Environment variables (EPITHET_CA_URL, EPITHET_MATCH)
3. Config file

Config file format (one directive per line):
  match <pattern>
  ca-url <url>

Flags:
`,
		FlagSet: fs,
		Options: []ff.Option{
			ff.WithEnvVarPrefix("EPITHET"),
			ff.WithConfigFileFlag("config"),
			ff.WithConfigFileParser(ff.PlainParser),
			ff.WithAllowMissingConfigFile(true),
		},
		Exec: func(ctx context.Context, args []string) error {
			// Set log level based on -v flag
			switch *verbose {
			case 0:
				log.SetLevel(log.WarnLevel)
			case 1:
				log.SetLevel(log.InfoLevel)
			default:
				log.SetLevel(log.DebugLevel)
			}
			return runAgent(*configFile, *caURL, matchPatterns.Values)
		},
	}

	return cmd.ParseAndRun(context.Background(), args)
}

func runAgent(configFile, caURL string, matchPatterns []string) error {
	// Validate we have required configuration
	// Note: ff/v3 has already merged flags, env vars, and config file at this point
	if len(matchPatterns) == 0 {
		return fmt.Errorf("no match patterns specified (use -match flag, EPITHET_MATCH env var, or config file)")
	}
	if caURL == "" {
		return fmt.Errorf("no CA URL specified (use -ca-url flag, EPITHET_CA_URL env var, or config file)")
	}

	log.Infof("starting epithet agent")
	if configFile != "" {
		log.Infof("  config: %s", configFile)
	}
	log.Infof("  ca_url: %s", caURL)
	log.Infof("  match patterns: %d", len(matchPatterns))

	for _, pattern := range matchPatterns {
		log.Infof("    - %s", pattern)
	}

	// TODO: Implement the agent process
	// - Compile match patterns into globs
	// - Set up communication socket for auth commands
	// - Initialize connection → agent mapping
	// - Handle agent lifecycle management
	// - Clean up expired certificates and sockets

	return fmt.Errorf("agent command not yet implemented")
}

// StringSliceFlag implements flag.Value for repeated string flags
type StringSliceFlag struct {
	Values []string
}

func (s *StringSliceFlag) String() string {
	return fmt.Sprintf("%v", s.Values)
}

func (s *StringSliceFlag) Set(value string) error {
	s.Values = append(s.Values, value)
	return nil
}
