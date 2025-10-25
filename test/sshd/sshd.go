package sshd

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/epithet-ssh/epithet/pkg/agent"
	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
)

// safeBuffer is a thread-safe wrapper around bytes.Buffer
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sb *safeBuffer) Write(p []byte) (n int, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.Write(p)
}

func (sb *safeBuffer) String() string {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return sb.buf.String()
}

type Server struct {
	User     string
	Path     string
	Port     int
	caPubKey sshcert.RawPublicKey
	cmd      *exec.Cmd
	Output   safeBuffer
}

// Start starts an sshd server as the current user, and returns a Server.
// The ssh server will be running in a temporary directory, and will process
// requests on a random port.
//
// It will only process a single ssh connection before terminating.
func Start(caPubKey sshcert.RawPublicKey) (*Server, error) {
	user, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("could not get current user: %w", err)
	}

	tmp_dir, err := os.MkdirTemp("", "epithet-sshd")
	if err != nil {
		return nil, fmt.Errorf("could not create temp dir for ssh root: %w", err)
	}

	port, err := findPort()
	if err != nil {
		return nil, fmt.Errorf("could not find a free port for sshd: %w", err)
	}

	s := &Server{
		User:     user.Username,
		Path:     tmp_dir,
		Port:     port,
		caPubKey: caPubKey,
		cmd:      nil,
		Output:   safeBuffer{},
	}

	log.Printf("Starting sshd in %s", tmp_dir)

	err = generateConfigs(s)
	if err != nil {
		return nil, fmt.Errorf("could not generate configs: %w", err)
	}

	err = s.start()
	if err != nil {
		return nil, fmt.Errorf("could not start sshd: %w", err)
	}

	return s, nil
}

func (s *Server) start() error {
	// /path/to/sshd -d -D -f /path/to/sshd_config
	sshd_path, err := exec.LookPath("sshd")
	if err != nil {
		return fmt.Errorf("could not find sshd: %w", err)
	}

	cmd := exec.Command(sshd_path, "-D", "-d", "-f", s.Path+"/sshd_config")
	s.cmd = cmd
	cmd.Stderr = &s.Output
	cmd.Stdout = &s.Output

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("could not start sshd: %w", err)
	}

	// Wait for "Server listening on" to be written to errb
	for i := 0; i < 100; i++ {
		if strings.Contains(s.Output.String(), "Server listening on") {
			i = 1000
		}
		time.Sleep(time.Millisecond * 100)
	}
	if !strings.Contains(s.Output.String(), "Server listening on") {
		cmd.Process.Kill()
		cmd.Wait()
		return fmt.Errorf("sshd did not start: %s", s.Output.String())
	}

	return nil
}

func (s *Server) Close() error {
	err := os.RemoveAll(s.Path)
	if err != nil {
		return fmt.Errorf("could not remove temp dir: %w", err)
	}
	err = s.cmd.Process.Signal(os.Interrupt)
	if err != nil {
		return fmt.Errorf("could not interrupt sshd: %w", err)
	}
	err = s.cmd.Wait()
	if err != nil {
		return fmt.Errorf("could not wait for sshd to exit: %w", err)
	}

	log.Print("sshd exited")

	return nil
}

// Ssh connects to the SSH server using the provided agent (v1 API)
func (s *Server) Ssh(a *agent.Agent) (string, error) {
	ssh_path, err := exec.LookPath("ssh")
	if err != nil {
		return "", fmt.Errorf("could not find ssh: %w", err)
	}

	argv := []string{
		"-v",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-F", "/dev/null",
		"-o", fmt.Sprintf("IdentityAgent=%s", a.AgentSocketPath()),
		"-p", strconv.Itoa(s.Port),
		s.User + "@localhost"}

	cmd := exec.Command(ssh_path, argv...)
	out := bytes.Buffer{}
	cmd.Stderr = &out
	cmd.Stdout = &out

	err = cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("could not run ssh: %w", err)
	}
	return out.String(), nil
}

// SshWithBroker connects to the SSH server using the broker's per-connection agent (v2 API).
// It computes the connection hash and uses the appropriate agent socket from the broker.
func (s *Server) SshWithBroker(b *broker.Broker) (string, error) {
	ssh_path, err := exec.LookPath("ssh")
	if err != nil {
		return "", fmt.Errorf("could not find ssh: %w", err)
	}

	// Get local hostname
	localHost, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("could not get hostname: %w", err)
	}

	// Compute the connection hash (%C in OpenSSH)
	// OpenSSH computes this as: hash of "%l%h%p%r%j" (local host, remote host, port, remote user, jump)
	hashInput := fmt.Sprintf("%slocalhost%d%s", localHost, s.Port, s.User)
	hash := sha256.Sum256([]byte(hashInput))
	connectionHash := policy.ConnectionHash(hex.EncodeToString(hash[:])[:16]) // Use first 16 chars like OpenSSH

	// Get the agent socket path from the broker
	agentSocket := b.AgentSocketPath(connectionHash)

	argv := []string{
		"-v",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-F", "/dev/null",
		"-o", fmt.Sprintf("IdentityAgent=%s", agentSocket),
		"-p", strconv.Itoa(s.Port),
		s.User + "@localhost"}

	cmd := exec.Command(ssh_path, argv...)
	out := bytes.Buffer{}
	cmd.Stderr = &out
	cmd.Stdout = &out

	err = cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("could not run ssh: %w", err)
	}
	return out.String(), nil
}

//go:embed sshd_config.tmpl
var sshd_config string

//go:embed command.sh
var command_sh []byte

func generateConfigs(s *Server) error {
	sshd_config := template.Must(template.New("sshd_config").Parse(sshd_config))
	sshd_config_file, err := os.Create(s.Path + "/sshd_config")
	if err != nil {
		return fmt.Errorf("could not create sshd_config: %w", err)
	}
	defer sshd_config_file.Close()
	sshd_config.Execute(sshd_config_file, s)

	err = os.Mkdir(s.Path+"/auth_principals", 0700)
	if err != nil {
		return fmt.Errorf("could not create auth_principals dir: %w", err)
	}

	err = os.WriteFile(s.Path+"/auth_principals/"+s.User, []byte("a\nb"), 0600)
	if err != nil {
		return fmt.Errorf("could not create authorized_keys file: %w", err)
	}

	err = os.WriteFile(s.Path+"/ca.pub", []byte(s.caPubKey), 0600)
	if err != nil {
		return fmt.Errorf("could not create ca.pub file: %w", err)
	}

	hostPubKey, hostPrivKey, err := sshcert.GenerateKeys()
	if err != nil {
		return fmt.Errorf("could not generate host keys: %w", err)
	}
	err = os.WriteFile(s.Path+"/ssh_host_ed25519_key.pub", []byte(hostPubKey), 0600)
	if err != nil {
		return fmt.Errorf("could not create ssh_host_ed25519_key.pub file: %w", err)
	}
	err = os.WriteFile(s.Path+"/ssh_host_ed25519_key", []byte(hostPrivKey), 0600)
	if err != nil {
		return fmt.Errorf("could not create ssh_host_ed25519_key file: %w", err)
	}

	err = os.WriteFile(s.Path+"/command.sh", command_sh, 0700)
	if err != nil {
		return fmt.Errorf("could not create command.sh file: %w", err)
	}

	return nil
}

func findPort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, fmt.Errorf("could not resolve localhost:0: %w", err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("could not listen on localhost:0: %w", err)
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port, nil
}
