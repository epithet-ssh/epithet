package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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
	// Future flags might include:
	// - socket directory location
	// - communication socket path
	// - daemon mode flags

	rootCmd.AddCommand(agentCmd)
}

func runAgent(cmd *cobra.Command, args []string) error {
	log.Info("starting epithet agent")

	// TODO: Implement the agent process
	// - Set up communication socket for auth commands
	// - Initialize connection → agent mapping
	// - Handle agent lifecycle management
	// - Clean up expired certificates and sockets

	return fmt.Errorf("agent command not yet implemented")
}
