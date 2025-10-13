package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	agentMatchPatterns []string
	agentCaURL         string
	agentConfigFile    string
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run the epithet agent process",
	Long: `The agent command runs the main epithet agent process that manages
per-connection SSH agents.

The agent process:
- Maintains a map of connection hash → ssh-agent process
- Spawns OpenSSH ssh-agent processes for each unique connection
- Tracks certificate expiration and public keys
- Handles communication from 'epithet auth' commands
- Creates agent sockets in ~/.epithet/sockets/

This process should typically run in the background as a daemon.`,
	RunE: runAgent,
}

func init() {
	agentCmd.Flags().StringVar(&agentConfigFile, "config", "",
		"path to config file (if set, --match and --ca-url are optional)")

	agentCmd.Flags().StringArrayVar(&agentMatchPatterns, "match", []string{},
		"hostname pattern to handle (can be repeated, additive with config file)")

	agentCmd.Flags().StringVar(&agentCaURL, "ca-url", "",
		"URL of the certificate authority (overrides config file if set)")

	// Future flags might include:
	// - socket directory location
	// - communication socket path
	// - daemon mode flags

	rootCmd.AddCommand(agentCmd)
}

func runAgent(cmd *cobra.Command, args []string) error {
	var cfg *SimpleConfig

	// Load config file if specified
	if agentConfigFile != "" {
		var err error
		cfg, err = LoadSimpleConfig(agentConfigFile)
		if err != nil {
			return fmt.Errorf("error loading config file: %w", err)
		}
		log.Infof("loaded config from: %s", agentConfigFile)
	} else {
		cfg = &SimpleConfig{Match: []string{}}
	}

	// Merge command-line flags with config
	cfg.MergeWithFlags(agentMatchPatterns, agentCaURL)

	// Validate we have required configuration
	if len(cfg.Match) == 0 {
		return fmt.Errorf("no match patterns specified (use --match or config file)")
	}
	if cfg.CaURL == "" {
		return fmt.Errorf("no CA URL specified (use --ca-url or config file)")
	}

	log.Infof("starting epithet agent")
	log.Infof("  ca_url: %s", cfg.CaURL)
	log.Infof("  match patterns: %d", len(cfg.Match))

	for _, pattern := range cfg.Match {
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
