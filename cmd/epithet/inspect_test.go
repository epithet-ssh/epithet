package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

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
