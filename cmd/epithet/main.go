package main

import (
	"flag"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
)

var verbosity int

func main() {
	// Create root flag set
	fs := flag.NewFlagSet("epithet", flag.ExitOnError)
	fs.IntVar(&verbosity, "v", 0, "log verbosity (0=warn, 1=info, 2=debug)")

	// Define subcommands
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Setup logging
	setupLogging()

	// Route to subcommands
	switch os.Args[1] {
	case "agent":
		if err := runAgentCmd(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "auth":
		if err := runAuthCmd(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `epithet - SSH certificate authentication system

Usage:
  epithet <command> [flags]

Commands:
  agent       Run the epithet agent process
  auth        Handle SSH authentication for a connection
  help        Show this help message

Flags:
  -v int      Log verbosity (0=warn, 1=info, 2=debug)

Use "epithet <command> -h" for more information about a command.
`)
}

func setupLogging() {
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
