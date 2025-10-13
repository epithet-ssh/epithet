package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	authHost string
	authPort string
	authUser string
	authHash string
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Handle SSH authentication for a connection",
	Long: `The auth command is invoked by OpenSSH via Match exec to handle
certificate-based authentication for a specific connection.

It implements the 5-step workflow:
1. Check if the host should be handled by epithet
2. Check for existing, unexpired certificate
3. Set up identity socket with certificate
4. Request new certificate if needed
5. Manage certificate lifecycle

Example OpenSSH configuration:
  Match exec "epithet auth --host %h --port %p --user %r --hash %C"
      IdentityAgent ~/.epithet/sockets/%C`,
	RunE: runAuth,
}

func init() {
	authCmd.Flags().StringVar(&authHost, "host", "", "remote hostname (%h)")
	authCmd.Flags().StringVar(&authPort, "port", "", "remote port (%p)")
	authCmd.Flags().StringVar(&authUser, "user", "", "remote username (%r)")
	authCmd.Flags().StringVar(&authHash, "hash", "", "connection hash (%C)")

	authCmd.MarkFlagRequired("host")
	authCmd.MarkFlagRequired("port")
	authCmd.MarkFlagRequired("user")
	authCmd.MarkFlagRequired("hash")

	rootCmd.AddCommand(authCmd)
}

func runAuth(cmd *cobra.Command, args []string) error {
	log.Debugf("auth called for %s@%s:%s (hash: %s)", authUser, authHost, authPort, authHash)

	// TODO: Implement the 5-step authentication workflow
	// 1. Check if host should be handled by epithet
	// 2. Check for existing certificate
	// 3. Set up identity socket
	// 4. Request new certificate if needed
	// 5. Manage certificate lifecycle

	return fmt.Errorf("auth command not yet implemented")
}
