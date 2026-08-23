package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
)

// AgentInspectCLI is a subcommand of AgentCLI that inspects broker state.
// It inherits CaURL and Name from the parent AgentCLI.
type AgentInspectCLI struct {
	Broker string `help:"Broker socket path (overrides config-based discovery)" short:"b"`
	JSON   bool   `help:"Output in JSON format" short:"j"`
}

func (i *AgentInspectCLI) Run(parent *AgentCLI, logger *slog.Logger) error {
	var brokerSock string

	if i.Broker != "" {
		// Explicit broker path provided.
		var err error
		brokerSock, err = expandPath(i.Broker)
		if err != nil {
			return fmt.Errorf("failed to expand broker socket path: %w", err)
		}
	} else if len(parent.CaURL) > 0 {
		// Derive socket path from the profile name (same rundir logic as
		// AgentStartCLI): the rundir is named for the profile, not the CA URLs.
		if err := validateProfileName(parent.Name); err != nil {
			return err
		}
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		brokerSock = filepath.Join(homeDir, ".epithet", "run", parent.Name, "broker.sock")
	} else {
		return fmt.Errorf("must specify either --broker or --ca-url")
	}

	// Connect to the broker over its Unix socket and send one request line.
	conn, err := net.Dial("unix", brokerSock)
	if err != nil {
		return fmt.Errorf("failed to connect to broker at %s: %w", brokerSock, err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(broker.Request{Inspect: &struct{}{}}); err != nil {
		return fmt.Errorf("failed to send inspect request: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 4096), scannerBufferSize)

	var resp *broker.InspectResponse
	for scanner.Scan() {
		var ev broker.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			return fmt.Errorf("failed to parse broker event: %w", err)
		}
		if ev.Inspect != nil {
			resp = ev.Inspect
			break
		}
		if ev.Result != nil {
			// A malformed-request denial is the only Result an Inspect
			// request can get back (the broker never returns a Match result
			// here); surface it as the RPC error it effectively is.
			return fmt.Errorf("broker error: %s", ev.Result.Error)
		}
	}
	if resp == nil {
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("broker connection error: %w", err)
		}
		return fmt.Errorf("no response received from broker")
	}

	// Output results.
	if i.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	}

	writeInspect(os.Stdout, resp, time.Now())
	return nil
}

// writeInspect writes the human-readable broker inspection output.
func writeInspect(w io.Writer, resp *broker.InspectResponse, now time.Time) {
	fmt.Fprintln(w, "Broker State")
	fmt.Fprintln(w, "============")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Socket: %s\n", resp.SocketPath)
	fmt.Fprintf(w, "Agent Dir: %s\n\n", resp.AgentSocketDir)

	fmt.Fprintf(w, "CA Endpoints (%d)\n", len(resp.CAEndpoints))
	fmt.Fprintln(w, "-----------------")
	if len(resp.CAEndpoints) == 0 {
		fmt.Fprintln(w, "  (none)")
	} else {
		for _, ep := range resp.CAEndpoints {
			status := "healthy"
			if ep.State == "open" || ep.State == "half-open" {
				status = "broken"
			}
			fmt.Fprintf(w, "  %s\n", ep.URL)
			fmt.Fprintf(w, "    Priority: %d\n", ep.Priority)
			fmt.Fprintf(w, "    Status: %s\n", status)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Agents (%d)\n", len(resp.Agents))
	fmt.Fprintln(w, "-----------")
	if len(resp.Agents) == 0 {
		fmt.Fprintln(w, "  (none)")
	} else {
		for _, ag := range resp.Agents {
			remaining := ag.ExpiresAt.Sub(now).Round(time.Second)
			status := "valid"
			if remaining < 0 {
				status = "expired"
				remaining = -remaining
			}
			proxyJump := ag.Connection.ProxyJump
			if proxyJump == "" {
				proxyJump = "(none)"
			}
			fmt.Fprintf(w, "  %s\n", ag.Hash)
			fmt.Fprintf(w, "    Host: %s\n", ag.Connection.RemoteHost)
			fmt.Fprintf(w, "    User: %s\n", ag.Connection.RemoteUser)
			fmt.Fprintf(w, "    Port: %d\n", ag.Connection.Port)
			fmt.Fprintf(w, "    ProxyJump: %s\n", proxyJump)
			fmt.Fprintf(w, "    Socket: %s\n", ag.SocketPath)
			fmt.Fprintf(w, "    Expires: %s (%s, %s)\n", ag.ExpiresAt.Format(time.RFC3339), status, remaining)

			// Parse and display certificate info.
			if ag.Certificate != "" {
				fingerprint := certFingerprint(ag.Certificate)
				fmt.Fprintf(w, "    Certificate: %s\n", fingerprint)
			}
		}
	}
}

// certFingerprint returns the SHA256 fingerprint of a certificate.
func certFingerprint(rawCert sshcert.RawCertificate) string {
	cert, err := sshcert.Parse(rawCert)
	if err != nil {
		return "(parse error)"
	}
	hash := sha256.Sum256(cert.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
}
