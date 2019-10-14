package agent

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ory/dockertest"
	"github.com/stretchr/testify/require"
)

func TestBasics(t *testing.T) {
	a, err := Start()
	require.NoError(t, err)

	server, err := startServer()
	require.NoError(t, err)
	defer server.Close()

	err = a.UseCredential(Credential{
		PrivateKey:  []byte(privateKey),
		Certificate: []byte(certificate),
	})
	require.NoError(t, err)

	out, err := server.ssh(a, "ls", "/etc/ssh/")

	fmt.Printf(out)
	require.NoError(t, err)

	require.Contains(t, out, "sshd_config")
	require.Contains(t, out, "auth_principals")
	require.Contains(t, out, "ca.pub")

	err = a.Close()
	require.NoError(t, err)

	_, err = os.Stat(a.AuthSocketPath())
	if !os.IsNotExist(err) {
		t.Fatalf("auth socket not cleaned up after cancel: %s", a.AuthSocketPath())
	}
}

func fixEnv(path string, env []string) []string {
	newEnv := []string{}
	for _, line := range env {
		if !strings.HasPrefix(line, "SSH_AUTH_SOCK=") {
			newEnv = append(newEnv, line)
		}
	}
	return append(newEnv, fmt.Sprintf("SSH_AUTH_SOCK=%s", path))
}

type sshServer struct {
	*dockertest.Resource
}

func (s sshServer) Port() string {
	return s.GetPort("22/tcp")
}

func (s sshServer) ssh(a *Agent, args ...string) (string, error) {
	argv := []string{"-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no", "-p", s.Port(), "root@localhost"}
	for _, v := range args {
		argv = append(argv, v)
	}
	cmd := exec.Command("ssh", argv...)
	cmd.Env = fixEnv(a.AuthSocketPath(), os.Environ())
	bs, err := cmd.CombinedOutput()
	return string(bs), err
}

func startServer() (*sshServer, error) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}
	// pulls an image, creates a container based on it and runs it
	resource, err := pool.Run("brianm/epithet-test-sshd", "4", []string{})
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}

	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	if err := pool.Retry(func() error {
		port := resource.GetPort("22/tcp")

		conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%s", port))
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}); err != nil {
		return nil, fmt.Errorf("Could not connect to docker: %w", err)
	}

	return &sshServer{resource}, err
}

const privateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD+94OTJVooGNj9LO4lPwobX9zIvisccuNeTpBMsQO+UgAAAJjcBY813AWP
NQAAAAtzc2gtZWQyNTUxOQAAACD+94OTJVooGNj9LO4lPwobX9zIvisccuNeTpBMsQO+Ug
AAAEC6GR1iGMhzhphbnsAIN44Wpn8AZzAQTWh/gdHaKzfOg/73g5MlWigY2P0s7iU/Chtf
3Mi+Kxxy415OkEyxA75SAAAAD2JyaWFubW5Ac2N1ZmZpbgECAwQFBg==
-----END OPENSSH PRIVATE KEY-----`

const certificate = `ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAID4AIPoWH60yQ3Ay6V9oYBBALFVszirLToisufG6hGaLAAAAIP73g5MlWigY2P0s7iU/Chtf3Mi+Kxxy415OkEyxA75SAAAAAAAAAAAAAAABAAAABmJyaWFubQAAAAoAAAAGYnJpYW5tAAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQDNH7zWoDN/0GHOqMq8E4l0xehxI4bqcqp4FmjMoGp1gb1VYl+G/KWoRufzamCvVvX37oGfTlIi/0wW/mCFPtVv9Dg6nWGVRz6rECv4hjF4TcxgXIXbVLw70Lwy0FNhc9bX13D+4Z8UkaP94c0s79nbtfW7w82jvnCXwWYh9odr+PX9tSZOCJvWgoGd0/pMbyLp/7EapGByu+fxqx4Xyb89RVtCpBBZrZ7xOqPV5wD5BjHfrCREqcdeV8jzzQkxDUclPjbFga4WWUMEFz3lr8b14yPl0m5ANCRFz2RX7jp8xKiL8gz7V0K37ZX5vHaGgaDHgQbmRvq7BkaGWRYELyzJAAABDwAAAAdzc2gtcnNhAAABALpCd/eBkQig/ap5wCJQEfx9xMhNMPa0Fn4+b2F80dHBKly9xZAM68h/sKIrJZe17xspFbe0gDNs7RkFtBnK6iLG5VZSNIzwsxGJ63J/w1DMrz1t1gJQNCDfzpznNJOc4MhcbF6HdF+kYA11DIN/lST1Th80l7EM9Q4NVChA5J2bDiSUso5oMN+RkUJRiCBjc6UG9BiJt3c3B2cUuvjSEtU/jRrR6sCH+klICOUSsscOToiFxjtsL4wmogMD+TS9e7CpgJBX8cxZP1pZ2bY5qik27llPS1YAtroEbE4OliqZQ35wLqHsmMYYg5LDTFhd+HOu1fGSaemeh92CaGvOyAQ= brianmn@scuffin`
