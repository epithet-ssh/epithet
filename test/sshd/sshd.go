package sshd

import (
	_ "embed"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"text/template"
)

type Server struct {
	bin  string
	User string
	Path string
	Port int
}

// Start starts an sshd server as the current user, and returns a Server.
// The ssh server will be running in a temporary directory, and will process
// requests on a random port.
//
// It will only process a single ssh connection before terminating.
func Start() (*Server, error) {
	sshd_path, err := exec.LookPath("sshd")
	if err != nil {
		return nil, fmt.Errorf("could not find sshd: %w", err)
	}

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
		sshd_path,
		user.Username,
		tmp_dir,
		port,
	}

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
	// cmd := exec.Command(sshd_path, "-D", "-d", "-f", "0")
	// fmt.Println(cmd.String())
	return nil
}

func (s *Server) Close() error {
	err := os.RemoveAll(s.Path)
	if err != nil {
		return fmt.Errorf("could not remove temp dir: %w", err)
	}
	return nil
}

//go:embed sshd_config.tmpl
var sshd_config string

func generateConfigs(s *Server) error {
	sshd_config := template.Must(template.New("sshd_config").Parse(sshd_config))
	sshd_config_file, err := os.Create(s.Path + "/sshd_config")
	if err != nil {
		return fmt.Errorf("could not create sshd_config: %w", err)
	}

	err = os.Mkdir(s.Path+"/auth_principals", 0700)
	if err != nil {
		return fmt.Errorf("could not create auth_principals dir: %w", err)
	}

	sshd_config.Execute(sshd_config_file, s)

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
