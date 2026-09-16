package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestWriteInspectShowsAgentConnection(t *testing.T) {
	now := time.Date(2026, time.August, 28, 12, 0, 0, 0, time.UTC)
	resp := &broker.InspectResponse{
		SocketPath:     "/run/epithet/broker.sock",
		AgentSocketDir: "/run/epithet/agent",
		Agents: []broker.AgentInfo{{
			Hash: "connection-hash",
			Connection: policy.Connection{
				RemoteHost: "server.example.com",
				RemoteUser: "deploy",
				Port:       2222,
				ProxyJump:  "bastion.example.com",
				Hash:       "connection-hash",
			},
			SocketPath: "/run/epithet/agent/connection-hash",
			ExpiresAt:  now.Add(2 * time.Minute),
		}},
	}

	var out bytes.Buffer
	writeInspect(&out, resp, now)

	require.Contains(t, out.String(), "    Host: server.example.com\n")
	require.Contains(t, out.String(), "    User: deploy\n")
	require.Contains(t, out.String(), "    Port: 2222\n")
	require.Contains(t, out.String(), "    ProxyJump: bastion.example.com\n")
}

func TestWriteInspectShowsCertificateDetails(t *testing.T) {
	now := time.Date(2026, time.September, 1, 13, 23, 28, 0, time.UTC)
	certificate := testCertificate(t, now)
	resp := &broker.InspectResponse{
		Agents: []broker.AgentInfo{{
			Hash:        "connection-hash",
			ExpiresAt:   now.Add(6 * time.Minute),
			Certificate: certificate,
		}},
	}

	var out bytes.Buffer
	writeInspect(&out, resp, now)

	require.Contains(t, out.String(), "      Type: ssh-ed25519-cert-v01@openssh.com user certificate\n")
	require.Contains(t, out.String(), "      Public key: ED25519-CERT SHA256:")
	require.Contains(t, out.String(), "      Signing CA: ED25519 SHA256:")
	require.Contains(t, out.String(), " (using ssh-ed25519)\n")
	require.Contains(t, out.String(), "      Key ID: \"brianm@skife.org\"\n")
	require.Contains(t, out.String(), "      Serial: 2457835461539698830\n")
	require.Contains(t, out.String(), "      Valid: from 2026-09-01T13:23:28Z to 2026-09-01T13:29:28Z\n")
	require.Contains(t, out.String(), "      Principals:\n        brianm\n")
	require.Contains(t, out.String(), "      Critical Options: (none)\n")
	require.Contains(t, out.String(), "      Extensions:\n        permit-agent-forwarding\n        permit-pty\n        permit-user-rc\n")
}

func TestCertificateDetailsEscapeUntrustedValues(t *testing.T) {
	var out bytes.Buffer
	writeStringList(&out, "Principals", []string{"deploy\nadmin\x1b[2J"})
	writeOptions(&out, "Critical Options", map[string]string{
		"force\ncommand": "echo owned\x1b[2J",
	})

	require.Equal(t, "      Principals:\n"+
		"        deploy\\nadmin\\x1b[2J\n"+
		"      Critical Options:\n"+
		"        force\\ncommand echo owned\\x1b[2J\n", out.String())
}

func testCertificate(t *testing.T, now time.Time) sshcert.RawCertificate {
	t.Helper()

	_, userPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	userKey, err := ssh.NewPublicKey(userPrivate.Public())
	require.NoError(t, err)

	_, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caSigner, err := ssh.NewSignerFromKey(caPrivate)
	require.NoError(t, err)

	cert := &ssh.Certificate{
		Key:             userKey,
		Serial:          2457835461539698830,
		CertType:        ssh.UserCert,
		KeyId:           "brianm@skife.org",
		ValidPrincipals: []string{"brianm"},
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(now.Add(6 * time.Minute).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-user-rc":          "",
				"permit-agent-forwarding": "",
				"permit-pty":              "",
			},
		},
	}
	require.NoError(t, cert.SignCert(rand.Reader, caSigner))

	return sshcert.RawCertificate(ssh.MarshalAuthorizedKey(cert))
}

func TestCompactInspect(t *testing.T) {
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	certificate := testCertificate(t, now)
	resp := &broker.InspectResponse{Agents: []broker.AgentInfo{
		{Hash: "abcd1fff", Connection: policy.Connection{RemoteUser: "brianm", RemoteHost: "freki.home", Port: 22}, Certificate: certificate, ExpiresAt: now.Add(6 * time.Minute)},
		{Hash: "abcd2fff", Connection: policy.Connection{RemoteUser: "brianm", RemoteHost: "freki.tail", Port: 2222, ProxyJump: "bastion.example"}, ExpiresAt: now},
		{Hash: "ef012fff", Connection: policy.Connection{RemoteUser: "user\nname", RemoteHost: "host\tname"}, Certificate: "invalid", ExpiresAt: now.Add(-time.Millisecond)},
	}}
	var out bytes.Buffer
	writeCompactInspect(&out, resp, "", now)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 4)
	require.Equal(t, []string{"ID", "CONNECTION", "SERIAL", "EXPIRES"}, strings.Fields(lines[0]))
	require.Equal(t, []string{"abcd1", "brianm@freki.home", "2457835461539698830", "6m0s"}, strings.Fields(lines[1]))
	require.Equal(t, []string{"abcd2", "-J", "bastion.example", "-p", "2222", "brianm@freki.tail", "-", "expired"}, strings.Fields(lines[2]))
	require.Equal(t, []string{"ef01", `user\nname@host\tname`, "-", "expired"}, strings.Fields(lines[3]))
	out.Reset()
	writeCompactInspect(&out, &broker.InspectResponse{Agents: resp.Agents[:1]}, "abcd1", now)
	require.Equal(t, "abcd1", strings.Fields(strings.Split(out.String(), "\n")[1])[0])
	out.Reset()
	writeCompactInspect(&out, &broker.InspectResponse{}, "", now)
	require.Equal(t, []string{"ID", "CONNECTION", "SERIAL", "EXPIRES"}, strings.Fields(out.String()))
}

func TestInspectArguments(t *testing.T) {
	var command struct {
		Agent AgentCLI `cmd:""`
	}
	parser, err := kong.New(&command)
	require.NoError(t, err)
	_, err = parser.Parse([]string{"agent", "-c", "https://id.example.com", "inspect", "--compact", "abcd"})
	require.NoError(t, err)
	require.Equal(t, []string{"https://id.example.com"}, command.Agent.CaURL)
	require.True(t, command.Agent.Inspect.Compact)
	require.Equal(t, policy.ConnectionHash("abcd"), command.Agent.Inspect.ID)

	for _, args := range [][]string{
		{"--compact", "--json"},
		{"--expanded", "--json"},
		{"--compact", "--expanded"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var inspect AgentInspectCLI
			parser, err := kong.New(&inspect)
			require.NoError(t, err)
			_, err = parser.Parse(args)
			require.Error(t, err)
		})
	}
}

func TestInspectOutputFormats(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name   string
		args   []string
		format string
	}{
		{"list default", nil, "compact"},
		{"selected default", []string{"abcd"}, "selected"},
		{"expanded list", []string{"--expanded"}, "expanded"},
		{"compact selected", []string{"abcd", "--compact"}, "compact"},
		{"compact list", []string{"--compact"}, "compact"},
		{"expanded selected", []string{"abcd", "--expanded"}, "selected"},
		{"json list", []string{"--json"}, "json"},
		{"json selected", []string{"abcd", "--json"}, "json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var inspect AgentInspectCLI
			parser, err := kong.New(&inspect)
			require.NoError(t, err)
			_, err = parser.Parse(tc.args)
			require.NoError(t, err)
			counts := []int{0, 1, 2}
			if inspect.ID != "" {
				counts = []int{1}
			}
			for _, count := range counts {
				t.Run(fmt.Sprintf("%d agents", count), func(t *testing.T) {
					resp := &broker.InspectResponse{SocketPath: "/broker.sock"}
					for n := 0; n < count; n++ {
						resp.Agents = append(resp.Agents, broker.AgentInfo{
							Hash:       fmt.Sprintf("abcd%d", n),
							Connection: policy.Connection{RemoteHost: "server.example.com", RemoteUser: "deploy", Port: 22},
							ExpiresAt:  now.Add(time.Minute),
						})
					}
					var out bytes.Buffer
					require.NoError(t, inspect.writeOutput(&out, resp, now))
					switch tc.format {
					case "compact":
						lines := strings.Split(strings.TrimSpace(out.String()), "\n")
						require.Len(t, lines, count+1)
						require.Equal(t, []string{"ID", "CONNECTION", "SERIAL", "EXPIRES"}, strings.Fields(lines[0]))
					case "expanded":
						require.Contains(t, out.String(), "Broker State\n")
						require.Contains(t, out.String(), fmt.Sprintf("Agents (%d)\n", count))
						if count > 0 {
							require.Contains(t, out.String(), "    Host: server.example.com\n")
						}
					case "selected":
						require.NotContains(t, out.String(), "Broker State")
						require.Contains(t, out.String(), "    Host: server.example.com\n")
					case "json":
						var decoded broker.InspectResponse
						require.NoError(t, json.Unmarshal(out.Bytes(), &decoded))
						require.Equal(t, resp.SocketPath, decoded.SocketPath)
						require.Len(t, decoded.Agents, count)
					}
				})
			}
		})
	}
}
