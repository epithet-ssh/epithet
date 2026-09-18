package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"golang.org/x/crypto/ssh"
)

// AgentInspectCLI is a subcommand of AgentCLI that inspects broker state.
// It inherits Name from the parent AgentCLI.
type AgentInspectCLI struct {
	Broker   string              `help:"Broker socket path (overrides config-based discovery)" short:"b"`
	JSON     bool                `help:"Output in JSON format" short:"j" xor:"format"`
	Compact  bool                `help:"Show one line per agent (default without an ID)" xor:"format"`
	Expanded bool                `help:"Show full details (default with an ID)" xor:"format"`
	ID       wire.ConnectionHash `arg:"" optional:"" name:"id" help:"Agent ID or unique prefix"`
}

func (i *AgentInspectCLI) Run(parent *AgentCLI, logger *slog.Logger) error {
	brokerSock, err := resolveAgentBrokerSocket(parent, i.Broker)
	if err != nil {
		return err
	}

	// Connect to the broker over its Unix socket and send one request line.
	conn, err := net.Dial("unix", brokerSock)
	if err != nil {
		return fmt.Errorf("failed to connect to broker at %s: %w", brokerSock, err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(broker.Request{Inspect: &broker.InspectRequest{ID: i.ID}}); err != nil {
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
			// Inspect lookup failures and malformed requests arrive as Result errors.
			return fmt.Errorf("broker error: %s", ev.Result.Error)
		}
	}
	if resp == nil {
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("broker connection error: %w", err)
		}
		return fmt.Errorf("no response received from broker")
	}

	return i.writeOutput(os.Stdout, resp, time.Now())
}

// writeOutput applies the requested format, defaulting to compact for a list
// and expanded for an explicitly selected agent, regardless of result count.
func (i *AgentInspectCLI) writeOutput(w io.Writer, resp *broker.InspectResponse, now time.Time) error {
	if i.JSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	}

	if i.Compact || (!i.Expanded && i.ID == "") {
		writeCompactInspect(w, resp, i.ID, now)
	} else if i.ID != "" {
		writeInspectAgents(w, resp.Agents, now)
	} else {
		writeInspect(w, resp, now)
	}
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

	writeInspectAgents(w, resp.Agents, now)
}

func writeInspectAgents(w io.Writer, agents []broker.AgentInfo, now time.Time) {
	fmt.Fprintf(w, "Agents (%d)\n", len(agents))
	fmt.Fprintln(w, "-----------")
	if len(agents) == 0 {
		fmt.Fprintln(w, "  (none)")
	} else {
		for _, ag := range agents {
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

			// Parse and display the same certificate details that ssh-keygen -L
			// exposes, without requiring an external process.
			if ag.Certificate != "" {
				writeCertificate(w, ag.Certificate)
			}
		}
	}
}

func writeCertificate(w io.Writer, rawCert sshcert.RawCertificate) {
	cert, err := sshcert.Parse(rawCert)
	if err != nil {
		fmt.Fprintln(w, "    Certificate: (parse error)")
		return
	}

	certKind := "unknown certificate"
	switch cert.CertType {
	case ssh.UserCert:
		certKind = "user certificate"
	case ssh.HostCert:
		certKind = "host certificate"
	}

	fmt.Fprintln(w, "    Certificate:")
	fmt.Fprintf(w, "      Type: %s %s\n", cert.Type(), certKind)
	fmt.Fprintf(w, "      Public key: %s %s\n", keyName(cert.Key)+"-CERT", ssh.FingerprintSHA256(cert))
	fmt.Fprintf(w, "      Signing CA: %s %s", keyName(cert.SignatureKey), ssh.FingerprintSHA256(cert.SignatureKey))
	if cert.Signature != nil && cert.Signature.Format != "" {
		fmt.Fprintf(w, " (using %s)", cert.Signature.Format)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "      Key ID: %q\n", cert.KeyId)
	fmt.Fprintf(w, "      Serial: %d\n", cert.Serial)
	fmt.Fprintf(w, "      Valid: from %s to %s\n", certTime(cert.ValidAfter), certTime(cert.ValidBefore))
	writeStringList(w, "Principals", cert.ValidPrincipals)
	writeOptions(w, "Critical Options", cert.CriticalOptions)
	writeOptions(w, "Extensions", cert.Extensions)
}

func keyName(key ssh.PublicKey) string {
	if key == nil {
		return "UNKNOWN"
	}

	typeName := key.Type()
	if i := strings.Index(typeName, "-cert-v01@openssh.com"); i >= 0 {
		typeName = typeName[:i]
	}
	switch {
	case typeName == ssh.KeyAlgoED25519:
		return "ED25519"
	case typeName == ssh.KeyAlgoRSA:
		return "RSA"
	case typeName == ssh.InsecureKeyAlgoDSA:
		return "DSA"
	case strings.HasPrefix(typeName, "ecdsa-sha2-"):
		return "ECDSA"
	case strings.HasPrefix(typeName, "sk-ssh-ed25519"):
		return "ED25519-SK"
	case strings.HasPrefix(typeName, "sk-ecdsa-sha2-"):
		return "ECDSA-SK"
	default:
		return typeName
	}
}

func certTime(timestamp uint64) string {
	if timestamp == ssh.CertTimeInfinity {
		return "forever"
	}
	return time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
}

func writeStringList(w io.Writer, label string, values []string) {
	fmt.Fprintf(w, "      %s:", label)
	if len(values) == 0 {
		fmt.Fprintln(w, " (none)")
		return
	}
	fmt.Fprintln(w)
	for _, value := range values {
		fmt.Fprintf(w, "        %s\n", escapeCertificateValue(value))
	}
}

func writeOptions(w io.Writer, label string, options map[string]string) {
	if len(options) == 0 {
		fmt.Fprintf(w, "      %s: (none)\n", label)
		return
	}

	keys := make([]string, 0, len(options))
	for key := range options {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "      %s:\n", label)
	for _, key := range keys {
		fmt.Fprintf(w, "        %s", escapeCertificateValue(key))
		if options[key] != "" {
			fmt.Fprintf(w, " %s", escapeCertificateValue(options[key]))
		}
		fmt.Fprintln(w)
	}
}

// escapeCertificateValue prevents certificate-controlled strings from adding
// output lines or terminal control sequences. QuoteToGraphic keeps printable
// text readable; remove its surrounding quotes because the output structure
// already delimits each value.
func escapeCertificateValue(value string) string {
	quoted := strconv.QuoteToGraphic(value)
	return quoted[1 : len(quoted)-1]
}

// writeCompactInspect abbreviates IDs against the complete snapshot. A selected
// agent uses the supplied prefix, which the broker validated against all agents.
func writeCompactInspect(w io.Writer, resp *broker.InspectResponse, selected wire.ConnectionHash, now time.Time) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tCONNECTION\tSERIAL\tEXPIRES")
	for _, ag := range resp.Agents {
		id := ag.Hash
		if selected != "" {
			id = string(selected)
		} else {
			length := min(4, len(id))
			for _, other := range resp.Agents {
				if other.Hash == id {
					continue
				}
				for length < len(id) && strings.HasPrefix(other.Hash, id[:length]) {
					length++
				}
			}
			id = id[:length]
		}
		var connection strings.Builder
		if ag.Connection.ProxyJump != "" {
			fmt.Fprintf(&connection, "-J %s ", ag.Connection.ProxyJump)
		}
		if ag.Connection.Port != 0 && ag.Connection.Port != 22 {
			fmt.Fprintf(&connection, "-p %d ", ag.Connection.Port)
		}
		fmt.Fprintf(&connection, "%s@%s", ag.Connection.RemoteUser, ag.Connection.RemoteHost)
		serial := "-"
		if ag.Certificate != "" {
			cert, err := sshcert.Parse(ag.Certificate)
			if err == nil {
				serial = strconv.FormatUint(cert.Serial, 10)
			}
		}
		expires := "expired"
		if ag.ExpiresAt.After(now) {
			expires = ag.ExpiresAt.Sub(now).Round(time.Second).String()
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", escapeCertificateValue(id), escapeCertificateValue(connection.String()), serial, expires)
	}
	tw.Flush()
}
