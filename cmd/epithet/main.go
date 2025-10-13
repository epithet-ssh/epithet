package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var verbosity = 0

var rootCmd = &cobra.Command{
	Use:   "epithet",
	Short: "Epithet SSH certificate authentication system",
	Long: `Epithet manages SSH certificates with per-connection agents.

It integrates with OpenSSH to provide seamless certificate-based authentication
by creating on-demand agent sockets for each unique connection.`,
	PersistentPreRun: setupLogging,
}

func main() {
	rootCmd.PersistentFlags().CountVarP(&verbosity, "verbose", "v", "increase verbosity (can be used multiple times)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func setupLogging(cmd *cobra.Command, args []string) {
	log.SetOutput(os.Stdout)

	switch verbosity {
	case 0:
		log.SetLevel(log.WarnLevel)
	case 1:
		log.SetLevel(log.InfoLevel)
	default: // 2+
		log.SetLevel(log.DebugLevel)
	}
}
