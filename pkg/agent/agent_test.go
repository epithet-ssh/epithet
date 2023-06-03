package agent_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"testing"

	rpc "github.com/epithet-ssh/epithet/internal/agent"
	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/ory/dockertest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authnService struct {
	rpc.UnimplementedAgentServiceServer
}

func (s *authnService) Authenticate(ctx context.Context, req *rpc.AuthnRequest) (*rpc.AuthnResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "no!")
}

func TestGRPC_Stuff(t *testing.T) {
	tmp, err := ioutil.TempFile("", "TestGRPC_Stuff.*")
	require.NoError(t, err)
	err = os.Remove(tmp.Name())
	require.NoError(t, err)
	defer os.Remove(tmp.Name())

	as := authnService{}

	lis, err := net.Listen("unix", tmp.Name())
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	defer grpcServer.GracefulStop()

	rpc.RegisterAgentServiceServer(grpcServer, &as)
	go grpcServer.Serve(lis)

	client, err := rpc.NewClient(tmp.Name())
	require.NoError(t, err)

	_, err = client.Authenticate(context.Background(), &rpc.AuthnRequest{
		Token: "hello world",
	})
	require.Error(t, err)
	s, ok := status.FromError(err)
	require.True(t, ok)

	require.Equal(t, codes.PermissionDenied, s.Code())
}

func TestBasics(t *testing.T) {
	a, err := agent.Start(nil)
	require.NoError(t, err)

	server, err := startSSHD()
	require.NoError(t, err)
	defer server.Close()

	err = a.UseCredential(agent.Credential{
		PrivateKey:  sshcert.RawPrivateKey(_userPrivateKey),
		Certificate: sshcert.RawCertificate(_userCert),
	})
	require.NoError(t, err)

	out, err := server.ssh(a, "ls", "/etc/ssh/")

	fmt.Printf(out)
	require.NoError(t, err)

	require.Contains(t, out, "sshd_config")
	require.Contains(t, out, "auth_principals")
	require.Contains(t, out, "ca.pub")

	a.Close()
	_, err = os.Stat(a.AgentSocketPath())
	if !os.IsNotExist(err) {
		t.Fatalf("auth socket not cleaned up after cancel: %s", a.AgentSocketPath())
	}
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
	return string(out), err
}

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

const _userPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD+94OTJVooGNj9LO4lPwobX9zIvisccuNeTpBMsQO+UgAAAJjcBY813AWP
NQAAAAtzc2gtZWQyNTUxOQAAACD+94OTJVooGNj9LO4lPwobX9zIvisccuNeTpBMsQO+Ug
AAAEC6GR1iGMhzhphbnsAIN44Wpn8AZzAQTWh/gdHaKzfOg/73g5MlWigY2P0s7iU/Chtf
3Mi+Kxxy415OkEyxA75SAAAAD2JyaWFubW5Ac2N1ZmZpbgECAwQFBg==
-----END OPENSSH PRIVATE KEY-----`

const _userCert = `ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAID4AIPoWH60yQ3Ay6V9oYBBALFVszirLToisufG6hGaLAAAAIP73g5MlWigY2P0s7iU/Chtf3Mi+Kxxy415OkEyxA75SAAAAAAAAAAAAAAABAAAABmJyaWFubQAAAAoAAAAGYnJpYW5tAAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQDNH7zWoDN/0GHOqMq8E4l0xehxI4bqcqp4FmjMoGp1gb1VYl+G/KWoRufzamCvVvX37oGfTlIi/0wW/mCFPtVv9Dg6nWGVRz6rECv4hjF4TcxgXIXbVLw70Lwy0FNhc9bX13D+4Z8UkaP94c0s79nbtfW7w82jvnCXwWYh9odr+PX9tSZOCJvWgoGd0/pMbyLp/7EapGByu+fxqx4Xyb89RVtCpBBZrZ7xOqPV5wD5BjHfrCREqcdeV8jzzQkxDUclPjbFga4WWUMEFz3lr8b14yPl0m5ANCRFz2RX7jp8xKiL8gz7V0K37ZX5vHaGgaDHgQbmRvq7BkaGWRYELyzJAAABDwAAAAdzc2gtcnNhAAABALpCd/eBkQig/ap5wCJQEfx9xMhNMPa0Fn4+b2F80dHBKly9xZAM68h/sKIrJZe17xspFbe0gDNs7RkFtBnK6iLG5VZSNIzwsxGJ63J/w1DMrz1t1gJQNCDfzpznNJOc4MhcbF6HdF+kYA11DIN/lST1Th80l7EM9Q4NVChA5J2bDiSUso5oMN+RkUJRiCBjc6UG9BiJt3c3B2cUuvjSEtU/jRrR6sCH+klICOUSsscOToiFxjtsL4wmogMD+TS9e7CpgJBX8cxZP1pZ2bY5qik27llPS1YAtroEbE4OliqZQ35wLqHsmMYYg5LDTFhd+HOu1fGSaemeh92CaGvOyAQ= brianmn@scuffin`
