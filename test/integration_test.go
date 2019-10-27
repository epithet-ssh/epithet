package test

import (
	"fmt"
	"log"
	"net"
	"net/http/httptest"
	"os/exec"
	"testing"

	"github.com/brianm/epithet/pkg/agent"
	"github.com/brianm/epithet/pkg/ca"
	"github.com/brianm/epithet/pkg/caclient"
	"github.com/brianm/epithet/pkg/caserver"
	"github.com/ory/dockertest"
	"github.com/stretchr/testify/require"
)

func Test_EndToEnd(t *testing.T) {
	require := require.New(t)

	sshd, err := startSSHD()
	require.NoError(err)
	defer sshd.Close()

	c, err := ca.New(_caPubKey, _caPrivKey)
	require.NoError(err)

	cad, err := startCAServer(c)
	require.NoError(err)
	defer cad.Close()

	cac := caclient.New(cad.srv.URL)

	a, err := agent.Start(cac)
	require.NoError(err)
	defer a.Close()

	conn, err := net.Dial("unix", a.AuthnSocketPath())
	require.NoError(err)

	_, err = conn.Write([]byte("test-token"))
	require.NoError(err)
	conn.Close()

	out, err := sshd.ssh(a, "ls", "/etc/ssh/")
	require.NoError(err)

	require.Contains(out, "sshd_config")
	require.Contains(out, "auth_principals")
	require.Contains(out, "ca.pub")
}

type caServer struct {
	c   *ca.CA
	srv *httptest.Server
}

func startCAServer(c *ca.CA) (*caServer, error) {
	handler := caserver.New(c)
	srv := httptest.NewServer(handler)

	cas := caServer{
		c:   c,
		srv: srv,
	}

	return &cas, nil
}

func (c *caServer) Close() {
	c.srv.Close()
}

type sshServer struct {
	*dockertest.Resource
}

func startSSHD() (*sshServer, error) {
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

func (s sshServer) Port() string {
	return s.GetPort("22/tcp")
}

func (s sshServer) ssh(a *agent.Agent, args ...string) (string, error) {
	argv := []string{
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", fmt.Sprintf("IdentityAgent=%s", a.AgentSocketPath()),
		"-p", s.Port(),
		"root@localhost"}

	argv = append(argv, args...)
	cmd := exec.Command("ssh", argv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, out)
	}
	return string(out), err
}

const _caPubKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNH7zWoDN/0GHOqMq8E4l0xehxI4bqcqp4FmjMoGp1gb1VYl+G/KWoRufzamCvVvX37oGfTlIi/0wW/mCFPtVv9Dg6nWGVRz6rECv4hjF4TcxgXIXbVLw70Lwy0FNhc9bX13D+4Z8UkaP94c0s79nbtfW7w82jvnCXwWYh9odr+PX9tSZOCJvWgoGd0/pMbyLp/7EapGByu+fxqx4Xyb89RVtCpBBZrZ7xOqPV5wD5BjHfrCREqcdeV8jzzQkxDUclPjbFga4WWUMEFz3lr8b14yPl0m5ANCRFz2RX7jp8xKiL8gz7V0K37ZX5vHaGgaDHgQbmRvq7BkaGWRYELyzJ user-ca`

const _caPrivKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAzR+81qAzf9BhzqjKvBOJdMXocSOG6nKqeBZozKBqdYG9VWJfhvyl
qEbn82pgr1b19+6Bn05SIv9MFv5ghT7Vb/Q4Op1hlUc+qxAr+IYxeE3MYFyF21S8O9C8Mt
BTYXPW19dw/uGfFJGj/eHNLO/Z27X1u8PNo75wl8FmIfaHa/j1/bUmTgib1oKBndP6TG8i
6f+xGqRgcrvn8aseF8m/PUVbQqQQWa2e8Tqj1ecA+QYx36wkRKnHXlfI880JMQ1HJT42xY
GuFllDBBc95a/G9eMj5dJuQDQkRc9kV+46fMSoi/IM+1dCt+2V+bx2hoGgx4EG5kb6uwZG
hlkWBC8syQAAA8DxizNB8YszQQAAAAdzc2gtcnNhAAABAQDNH7zWoDN/0GHOqMq8E4l0xe
hxI4bqcqp4FmjMoGp1gb1VYl+G/KWoRufzamCvVvX37oGfTlIi/0wW/mCFPtVv9Dg6nWGV
Rz6rECv4hjF4TcxgXIXbVLw70Lwy0FNhc9bX13D+4Z8UkaP94c0s79nbtfW7w82jvnCXwW
Yh9odr+PX9tSZOCJvWgoGd0/pMbyLp/7EapGByu+fxqx4Xyb89RVtCpBBZrZ7xOqPV5wD5
BjHfrCREqcdeV8jzzQkxDUclPjbFga4WWUMEFz3lr8b14yPl0m5ANCRFz2RX7jp8xKiL8g
z7V0K37ZX5vHaGgaDHgQbmRvq7BkaGWRYELyzJAAAAAwEAAQAAAQEAx28PJEG4MJIDNnHI
Q1pfb8in+bCIEVSRR5bKKAHj4AHXerfdlxn3WoguJu2LuY68MWWUY7Y7h8leSpDieUqhLG
tvbBXudbxCQwHDLqwSVxyVFC+A+cIGDcYh5OnF199PyKWwODBXgiEkJ8ituv4sfEEK/Zcf
Tg/v2qxvx5+xBRjZOMclfhFvtv+QxsE+yFH9+KZvrtv0GsEHTnCD1FsY1Vh6vZhBBjFNFo
JtKw5KIiXGdmMv9s6cUT4DClG31M2QnvbppQhLrxxdLAGTB0Dr7ldtBZdauhKhPo1TaJMg
3EQZ7IYoyBeCedOagAKb0GW68FW0Tmy73HaRfU8dZgnaDQAAAIAncC8GP72UgX7zxJ19Go
/tpmKyQvtrOjtmZAja0/y+bePYwHllvTfPLEo5NOeiLv8fDTTIPETUMmihywstyU2TPbWq
pgRjXCv36QGYlviKfjja1uIwd9KLJRKavI3kp+0uz6ZJFxrez0i7GCR0Tu2rX+RGrjLj2V
mY+eCroW+y5AAAAIEA5+Hl9hU2Sbx8j6Ohgeyn9eFfVTafRttMg2wMQVNW0MzMj0DibSKT
Fi55TwSANSXMQ/uL3eW6ZcHcxKQCxT2KzTz7QiR3qE2uad9EQx3N6XWKxDoPlDgrlUktcH
nYy4rmJe7HVL7FpBuFUxsfrlgVclrxClA/lZq8mP9CutlZBYcAAACBAOJ1XnwElJpDxwWY
HEM250mpK26m4oxkjBMIx/lLC1DST+vMU2k/N801xi6Rb1MravliiuK0jHZlJO4DL816GV
lTe2/oE0W4DNt/J1ypylVLVL2E2EKqQqHbYmXQ87EFdp8OanAu6F29pRdKstTbYkGk6lET
lYB3IqmowLJ7ac8vAAAAB3VzZXItY2EBAgM=
-----END OPENSSH PRIVATE KEY-----
`
