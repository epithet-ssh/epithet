package sshd

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"text/template"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
)

type sshServer struct {
	dir  string
	port int
	user string
	cmd  *exec.Cmd
}

func StartSSHD(caPubKey string) (*sshServer, error) {
	// make a temp dir
	dir, err := os.MkdirTemp("", "epithet_test_sshd")
	if err != nil {
		return nil, fmt.Errorf("unable to start sshd: %w", err)
	}
	log.Printf("starting in %s\n", dir)

	// generate host key
	cmd := exec.Command("ssh-keygen", "-q", "-N", ``, "-t", "ed25519", "-f", "ssh_host_key")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("unable to generate hostkey: %w", err)
	}

	err = os.Chmod(fmt.Sprintf("%s/ssh_host_key", dir), 0600)
	if err != nil {
		return nil, fmt.Errorf("unable to set permissions on ssh_host_key: %w", err)
	}
	err = os.Chmod(fmt.Sprintf("%s/ssh_host_key.pub", dir), 0600)
	if err != nil {
		return nil, fmt.Errorf("unable to set permissions on ssh_host_key.pub: %w", err)
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
	err = os.Mkdir(fmt.Sprintf("%s/auth_principals", dir), 0700)
	if err != nil {
		return nil, fmt.Errorf("unable to create auth_principals dir: %w", err)
	}

	err = os.WriteFile(fmt.Sprintf("%s/auth_principals/%s", dir, user.Username), []byte("pe\n"), 0644)
	if err != nil {
		return nil, fmt.Errorf("unable to generate auth_principals/$USER: %w", err)
	}

	// start sshd
	sshd_path, err := exec.LookPath("sshd")
	if err != nil {
		return nil, fmt.Errorf("cannot find sshd on $PATH: %w", err)
	}
	sshd_path, err = filepath.Abs(sshd_path)
	if err != nil {
		return nil, fmt.Errorf("cannot find absolute path to sshd: %w", err)
	}

	sshd_cmd := exec.Command(sshd_path, "-D", "-f", fmt.Sprintf("%s/sshd_config", dir))
	sshd_cmd.Dir = dir
	sshd_cmd.Stdout = os.Stdout
	sshd_cmd.Stderr = os.Stderr
	err = sshd_cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("unable to start sshd: %w", err)
	}

	// wait til server answers on port (5 seconds max)
	for start := time.Now(); time.Since(start) < time.Second*5; {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			break
		}
	}
	if err != nil {
		sshd_cmd.Process.Kill()
		return nil, fmt.Errorf("sshd failed to start")
	}

	// save reference to child sshd process

	return &sshServer{
		dir:  dir,
		port: port,
		user: user.Username,
		cmd:  sshd_cmd,
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

	err := s.cmd.Process.Kill()
	if err != nil {
		return fmt.Errorf("unable to kill sshd: %w", err)
	}

	err = os.RemoveAll(s.dir)
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
		//"-vv",
		fmt.Sprintf("%s@localhost", s.User())}

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
Protocol 2
ListenAddress 127.0.0.1
Port {{ .Port }}
HostKey {{ .Prefix }}/ssh_host_key
LogLevel DEBUG3
UsePAM no
PrintMotd no
PidFile {{ .Prefix }}/sshd.pid
AcceptEnv LANG LC_*
PermitRootLogin yes

TrustedUserCAKeys {{ .Prefix }}/ca.pub
AuthorizedPrincipalsFile {{ .Prefix }}/auth_principals/%u
`

/*
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin yes
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
UsePAM no

TrustedUserCAKeys /etc/ssh/ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
*/
