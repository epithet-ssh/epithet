package sshd

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/user"
	"text/template"

	"github.com/epithet-ssh/epithet/pkg/agent"
)

type sshServer struct {
	dir  string
	port int
	user string
}

func StartSSHD(caPubKey string) (*sshServer, error) {
	// make a temp dir
	dir, err := os.MkdirTemp("", "epithet_test_sshd")
	if err != nil {
		return nil, fmt.Errorf("unable to start sshd: %w", err)
	}

	// generate host key
	cmd := exec.Command("ssh-keygen", "-q", "-N", `""`, "-t", "rsa", "-b", "4096", "-f", "ssh_host_rsa_key")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("unable to generate hostkey: %w", err)
	}

	// find username to use
	user, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("unable to find current user: %w", err)
	}

	// find available high port
	port, err := availablePort()
	if err != nil {
		return nil, fmt.Errorf("unable to find available port: %w", err)
	}

	// write CA pubkey
	ioutil.WriteFile(fmt.Sprintf("%s/ca.pub", dir), []byte(caPubKey), 0644)

	// generate and write sshd config
	tmpl := template.Must(template.New("sshdConfig").Parse(sshdConfigTemplate))
	sshd_config, err := os.Create(fmt.Sprintf("%s/sshd_config", dir))
	if err != nil {
		return nil, fmt.Errorf("unable to create sshd_config: %w", err)
	}
	defer sshd_config.Close()

	err = tmpl.Execute(sshd_config, map[string]string{"Prefix": dir, "Port": fmt.Sprintf("%d", port)})
	if err != nil {
		return nil, fmt.Errorf("error generating sshd_config: %w", err)
	}

	// make auth principals

	// start sshd

	// save reference to child sshd process

	return &sshServer{
		dir:  dir,
		port: port,
		user: user.Username,
	}, nil
}

func (s *sshServer) Port() int {
	return s.port
}

func (s *sshServer) Dir() string {
	return s.dir
}

func (s *sshServer) User() string {
	return s.user
}

func (s *sshServer) Close() error {
	err := os.RemoveAll(s.dir)
	if err != nil {
		return fmt.Errorf("unable to cleanup: %w", err)
	}
	return nil
}

func (s *sshServer) Ssh(a *agent.Agent, args ...string) (string, error) {
	argv := []string{
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", fmt.Sprintf("IdentityAgent=%s", a.AgentSocketPath()),
		"-p", fmt.Sprintf("%d", s.Port()),
		"root@localhost"}

	argv = append(argv, args...)
	cmd := exec.Command("ssh", argv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, out)
	}
	return string(out), err
}

func availablePort() (int, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	err = listener.Close()
	if err != nil {
		return 0, err
	}

	return port, nil
}

const sshdConfigTemplate = `
ListenAddress 127.0.0.1
Port {{ .Port }}
HostKey {{ .Prefix }}/ssh_host_rsa_key
LogLevel DEBUG3
ChallengeResponseAuthentication no
UsePAM no
PrintMotd no
PidFile {{ .Prefix }}/sshd.pid
AcceptEnv LANG LC_*

TrustedUserCAKeys {{ .Prefix }}/ca.pub
AuthorizedPrincipalsFile {{ .Prefix }}/auth_principals/%u
`
