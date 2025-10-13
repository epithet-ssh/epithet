package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"
	log "github.com/sirupsen/logrus"
)

func runAuthCmd(args []string) error {
	// Create flag set for auth command
	fs := flag.NewFlagSet("epithet auth", flag.ExitOnError)

	var (
		host    = fs.String("host", "", "remote hostname (%h)")
		port    = fs.String("port", "", "remote port (%p)")
		user    = fs.String("user", "", "remote username (%r)")
		hash    = fs.String("hash", "", "connection hash (%C)")
		verbose = fs.Int("v", 0, "log verbosity (0=warn, 1=info, 2=debug)")
	)

	// Create ffcli command
	cmd := &ffcli.Command{
		Name:       "auth",
		ShortUsage: "epithet auth --host <host> --port <port> --user <user> --hash <hash>",
		ShortHelp:  "Handle SSH authentication for a connection",
		LongHelp: `The auth command is invoked by OpenSSH via Match exec to handle
certificate-based authentication for a specific connection.

It implements the 5-step workflow:
1. Check if the host should be handled by epithet
2. Check for existing, unexpired certificate
3. Set up identity socket with certificate
4. Request new certificate if needed
5. Manage certificate lifecycle

Example OpenSSH configuration:
  Match exec "epithet auth --host %h --port %p --user %r --hash %C"
      IdentityAgent ~/.epithet/sockets/%C

Flags:
`,
		FlagSet: fs,
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
			return runAuth(*host, *port, *user, *hash)
		},
	}

	return cmd.ParseAndRun(context.Background(), args)
}

func runAuth(host, port, user, hash string) error {
	// Validate required flags
	if host == "" {
		return fmt.Errorf("--host is required")
	}
	if port == "" {
		return fmt.Errorf("--port is required")
	}
	if user == "" {
		return fmt.Errorf("--user is required")
	}
	if hash == "" {
		return fmt.Errorf("--hash is required")
	}

	log.Debugf("auth called for %s@%s:%s (hash: %s)", user, host, port, hash)

	// TODO: Implement the 5-step authentication workflow
	// 1. Check if host should be handled by epithet
	// 2. Check for existing certificate
	// 3. Set up identity socket
	// 4. Request new certificate if needed
	// 5. Manage certificate lifecycle

	return fmt.Errorf("auth command not yet implemented")
}
