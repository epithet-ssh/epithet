package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	pb "github.com/epithet-ssh/epithet/pkg/brokerv1"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// AgentInspectCLI is a subcommand of AgentCLI that inspects broker state.
// It inherits CaURL from the parent AgentCLI.
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
		// Derive socket path from parent's config (same logic as AgentStartCLI).
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		instanceID := hashString(fmt.Sprintf("%v", parent.CaURL))
		brokerSock = filepath.Join(homeDir, ".epithet", "run", instanceID, "broker.sock")
	} else {
		return fmt.Errorf("must specify either --broker or --ca-url")
	}

	// Connect to broker via gRPC over Unix socket.
	conn, err := grpc.NewClient(
		"unix://"+brokerSock,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to broker at %s: %w", brokerSock, err)
	}
	defer conn.Close()

	client := pb.NewBrokerServiceClient(conn)

	// Call broker.
	resp, err := client.Inspect(context.Background(), &pb.InspectRequest{})
	if err != nil {
		return fmt.Errorf("broker RPC call failed: %w", err)
	}

	// Output results.
	if i.JSON {
		// For JSON output, convert to a simpler structure.
		output := inspectResponseToJSON(resp)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(output)
	}

	// Human-readable output.
	fmt.Printf("Broker State\n")
	fmt.Printf("============\n\n")
	fmt.Printf("Socket: %s\n", resp.SocketPath)
	fmt.Printf("Agent Dir: %s\n", resp.AgentSocketDir)
	fmt.Printf("Discovery Patterns: %v\n\n", resp.DiscoveryPatterns)

	fmt.Printf("Agents (%d)\n", len(resp.Agents))
	fmt.Printf("-----------\n")
	if len(resp.Agents) == 0 {
		fmt.Printf("  (none)\n")
	} else {
		now := time.Now()
		for _, ag := range resp.Agents {
			expiresAt := ag.ExpiresAt.AsTime()
			remaining := expiresAt.Sub(now).Round(time.Second)
			status := "valid"
			if remaining < 0 {
				status = "expired"
				remaining = -remaining
			}
			fmt.Printf("  %s\n", ag.Hash)
			fmt.Printf("    Socket: %s\n", ag.SocketPath)
			fmt.Printf("    Expires: %s (%s, %s)\n", expiresAt.Format(time.RFC3339), status, remaining)

			// Parse and display certificate info.
			if ag.Certificate != "" {
				fingerprint := certFingerprint(sshcert.RawCertificate(ag.Certificate))
				fmt.Printf("    Certificate: %s\n", fingerprint)
			}
		}
	}

	fmt.Printf("\nCertificates (%d)\n", len(resp.Certificates))
	fmt.Printf("-----------------\n")
	if len(resp.Certificates) == 0 {
		fmt.Printf("  (none)\n")
	} else {
		now := time.Now()
		for idx, certInfo := range resp.Certificates {
			printCertInfoProto(idx, certInfo, now)
		}
	}

	return nil
}

// inspectResponseJSON is a simplified structure for JSON output.
type inspectResponseJSON struct {
	SocketPath        string          `json:"socketPath"`
	AgentSocketDir    string          `json:"agentSocketDir"`
	DiscoveryPatterns []string        `json:"discoveryPatterns,omitempty"`
	Agents            []agentInfoJSON `json:"agents"`
	Certificates      []certInfoJSON  `json:"certificates"`
}

type agentInfoJSON struct {
	Hash        string    `json:"hash"`
	SocketPath  string    `json:"socketPath"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Certificate string    `json:"certificate"`
}

type certInfoJSON struct {
	Certificate string              `json:"certificate"`
	HostUsers   map[string][]string `json:"hostUsers"`
	ExpiresAt   time.Time           `json:"expiresAt"`
}

func inspectResponseToJSON(resp *pb.InspectResponse) inspectResponseJSON {
	agents := make([]agentInfoJSON, len(resp.Agents))
	for i, a := range resp.Agents {
		agents[i] = agentInfoJSON{
			Hash:        a.Hash,
			SocketPath:  a.SocketPath,
			ExpiresAt:   a.ExpiresAt.AsTime(),
			Certificate: a.Certificate,
		}
	}

	certs := make([]certInfoJSON, len(resp.Certificates))
	for i, c := range resp.Certificates {
		hostUsers := make(map[string][]string)
		for pattern, list := range c.HostUsers {
			hostUsers[pattern] = list.Values
		}
		certs[i] = certInfoJSON{
			Certificate: c.Certificate,
			HostUsers:   hostUsers,
			ExpiresAt:   c.ExpiresAt.AsTime(),
		}
	}

	return inspectResponseJSON{
		SocketPath:        resp.SocketPath,
		AgentSocketDir:    resp.AgentSocketDir,
		DiscoveryPatterns: resp.DiscoveryPatterns,
		Agents:            agents,
		Certificates:      certs,
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

// printCertInfoProto prints detailed certificate information from proto types.
func printCertInfoProto(idx int, certInfo *pb.CertInfo, now time.Time) {
	expiresAt := certInfo.ExpiresAt.AsTime()
	remaining := expiresAt.Sub(now).Round(time.Second)
	status := "valid"
	if remaining < 0 {
		status = "expired"
		remaining = -remaining
	}

	fmt.Printf("  [%d]\n", idx)

	// Parse certificate for details.
	cert, err := sshcert.Parse(sshcert.RawCertificate(certInfo.Certificate))
	if err != nil {
		fmt.Printf("    (failed to parse certificate: %v)\n", err)
		return
	}

	// Fingerprint.
	hash := sha256.Sum256(cert.Marshal())
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
	fmt.Printf("    Fingerprint: %s\n", fingerprint)

	// Identity (KeyId).
	fmt.Printf("    Identity: %s\n", cert.KeyId)

	// Principals.
	fmt.Printf("    Principals: %v\n", cert.ValidPrincipals)

	// Validity.
	validAfter := time.Unix(int64(cert.ValidAfter), 0)
	validBefore := time.Unix(int64(cert.ValidBefore), 0)
	fmt.Printf("    Valid: %s to %s (%s, %s)\n",
		validAfter.Format(time.RFC3339),
		validBefore.Format(time.RFC3339),
		status, remaining)

	// Extensions.
	if len(cert.Extensions) > 0 {
		fmt.Printf("    Extensions:\n")
		// Sort extensions for consistent output.
		var extNames []string
		for name := range cert.Extensions {
			extNames = append(extNames, name)
		}
		sort.Strings(extNames)
		for _, name := range extNames {
			fmt.Printf("      %s\n", name)
		}
	}

	// Critical options.
	if len(cert.CriticalOptions) > 0 {
		fmt.Printf("    Critical Options:\n")
		for name, value := range cert.CriticalOptions {
			if value == "" {
				fmt.Printf("      %s\n", name)
			} else {
				fmt.Printf("      %s %s\n", name, value)
			}
		}
	}

	// Policy (HostUsers).
	fmt.Printf("    Policy (HostUsers):\n")
	for pattern, list := range certInfo.HostUsers {
		fmt.Printf("      %s: %v\n", pattern, list.Values)
	}
}

// Ensure ssh.Certificate is used (for type checking).
var _ *ssh.Certificate
