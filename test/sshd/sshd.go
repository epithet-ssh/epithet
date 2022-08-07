package sshd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/agent"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type sshServer struct {
	container testcontainers.Container
}

func dockerContext() string {
	dir, _ := os.Getwd()
	for path.Base(dir) != "epithet" {
		dir = path.Dir(dir)
	}
	return path.Join(dir, "test/test_sshd")
}

func StartSSHD(ctx context.Context) (*sshServer, error) {

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context: dockerContext(),
		},
		ExposedPorts: []string{"2222/tcp"},
		WaitingFor:   wait.ForListeningPort("2222/tcp"),
	}

	server, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to start dockerized sshd: %w", err)
	}

	return &sshServer{
		container: server,
	}, nil
}

func (s *sshServer) Port(ctx context.Context) (string, error) {
	port, err := s.container.MappedPort(ctx, "2222/tcp")
	if err != nil {
		return "", fmt.Errorf("unable to find mapped port: %w", err)
	}
	return port.Port(), nil
}

func (s *sshServer) Host(ctx context.Context) (string, error) {
	host, err := s.container.Host(ctx)
	if err != nil {
		return "", fmt.Errorf("unable to find host: %w", err)
	}
	return host, nil
}

func (s *sshServer) Close(ctx context.Context) error {
	return s.container.Terminate(ctx)
}

func (s *sshServer) Ssh(ctx context.Context, a *agent.Agent, args ...string) (string, error) {
	port, err := s.Port(ctx)
	if err != nil {
		return "", err
	}
	host, err := s.Host(ctx)
	if err != nil {
		return "", err
	}

	argv := []string{
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", fmt.Sprintf("IdentityAgent=%s", a.AgentSocketPath()),
		"-p", port,
		"-vv",
		fmt.Sprintf("root@%s", host),
	}
	ss := strings.Join(argv, " ")
	fmt.Println(ss)
	argv = append(argv, args...)
	cmd := exec.Command("ssh", argv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, out)
	}
	return string(out), err
}
