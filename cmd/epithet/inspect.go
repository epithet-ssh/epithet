package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/rpc"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"golang.org/x/crypto/ssh"
)

type InspectCLI struct {
	Broker string   `help:"Broker socket path (overrides config-based discovery)" short:"b"`
	Match  []string `help:"Match patterns (used to find broker socket)" short:"m"`
	CaURL  string   `help:"CA URL (used to find broker socket)" name:"ca-url" short:"c"`
	JSON   bool     `help:"Output in JSON format" short:"j"`
}

func (i *InspectCLI) Run(logger *slog.Logger) error {
	var brokerSock string

	if i.Broker != "" {
		// Explicit broker path provided
		var err error
		brokerSock, err = expandPath(i.Broker)
		if err != nil {
			return fmt.Errorf("failed to expand broker socket path: %w", err)
		}
	} else if i.CaURL != "" {
		// Derive socket path from config (same logic as AgentCLI)
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		instanceID := hashString(i.CaURL + fmt.Sprintf("%v", i.Match))
		brokerSock = filepath.Join(homeDir, ".epithet", "run", instanceID, "broker.sock")
	} else {
		return fmt.Errorf("must specify either --broker or --ca-url (with optional --match)")
	}

	// Connect to broker
	client, err := rpc.Dial("unix", brokerSock)
	if err != nil {
		return fmt.Errorf("failed to connect to broker at %s: %w", brokerSock, err)
	}
	defer client.Close()

	// Call broker
	var resp broker.InspectResponse
	err = client.Call("Broker.Inspect", broker.InspectRequest{}, &resp)
	if err != nil {
		return fmt.Errorf("broker RPC call failed: %w", err)
	}

	// Output results
	if i.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	}

	// Human-readable output
	fmt.Printf("Broker State\n")
	fmt.Printf("============\n\n")
	fmt.Printf("Socket: %s\n", resp.SocketPath)
	fmt.Printf("Agent Dir: %s\n", resp.AgentSocketDir)
	fmt.Printf("Match Patterns: %v\n\n", resp.MatchPatterns)

	fmt.Printf("Agents (%d)\n", len(resp.Agents))
	fmt.Printf("-----------\n")
	if len(resp.Agents) == 0 {
		fmt.Printf("  (none)\n")
	} else {
		now := time.Now()
		for _, ag := range resp.Agents {
			remaining := ag.ExpiresAt.Sub(now).Round(time.Second)
			status := "valid"
			if remaining < 0 {
				status = "expired"
				remaining = -remaining
			}
			fmt.Printf("  %s\n", ag.Hash)
			fmt.Printf("    Socket: %s\n", ag.SocketPath)
			fmt.Printf("    Expires: %s (%s, %s)\n", ag.ExpiresAt.Format(time.RFC3339), status, remaining)

			// Parse and display certificate info
			if ag.Certificate != "" {
				fingerprint := certFingerprint(ag.Certificate)
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
			printCertInfo(idx, certInfo, now)
		}
	}

	return nil
}

// certFingerprint returns the SHA256 fingerprint of a certificate
func certFingerprint(rawCert sshcert.RawCertificate) string {
	cert, err := sshcert.Parse(rawCert)
	if err != nil {
		return "(parse error)"
	}
	hash := sha256.Sum256(cert.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
}

// printCertInfo prints detailed certificate information
func printCertInfo(idx int, certInfo broker.CertInfo, now time.Time) {
	remaining := certInfo.ExpiresAt.Sub(now).Round(time.Second)
	status := "valid"
	if remaining < 0 {
		status = "expired"
		remaining = -remaining
	}

	fmt.Printf("  [%d]\n", idx)

	// Parse certificate for details
	cert, err := sshcert.Parse(certInfo.Certificate)
	if err != nil {
		fmt.Printf("    (failed to parse certificate: %v)\n", err)
		return
	}

	// Fingerprint
	hash := sha256.Sum256(cert.Marshal())
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
	fmt.Printf("    Fingerprint: %s\n", fingerprint)

	// Identity (KeyId)
	fmt.Printf("    Identity: %s\n", cert.KeyId)

	// Principals
	fmt.Printf("    Principals: %v\n", cert.ValidPrincipals)

	// Validity
	validAfter := time.Unix(int64(cert.ValidAfter), 0)
	validBefore := time.Unix(int64(cert.ValidBefore), 0)
	fmt.Printf("    Valid: %s to %s (%s, %s)\n",
		validAfter.Format(time.RFC3339),
		validBefore.Format(time.RFC3339),
		status, remaining)

	// Extensions
	if len(cert.Extensions) > 0 {
		fmt.Printf("    Extensions:\n")
		// Sort extensions for consistent output
		var extNames []string
		for name := range cert.Extensions {
			extNames = append(extNames, name)
		}
		sort.Strings(extNames)
		for _, name := range extNames {
			fmt.Printf("      %s\n", name)
		}
	}

	// Critical options
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

	// Policy (HostUsers)
	fmt.Printf("    Policy (HostUsers):\n")
	for pattern, users := range certInfo.Policy.HostUsers {
		fmt.Printf("      %s: %v\n", pattern, users)
	}
}

// Ensure ssh.Certificate is used (for type checking)
var _ *ssh.Certificate
