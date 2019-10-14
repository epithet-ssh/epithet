package agent

import (
	"fmt"
	"io"
	"log"
	"net"
	"testing"

	"github.com/gliderlabs/ssh"
)

func TestBasics(t *testing.T) {

	ssh.Handle(func(s ssh.Session) {
		io.WriteString(s, fmt.Sprintf("Hello %s\n", s.User()))
	})

	port := freePort()
	log.Printf("starting ssh server on port %s", port)
	log.Fatal(ssh.ListenAndServe(port, nil))
}

func freePort() string {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		log.Fatalf("unable to find free port: %v", err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatalf("unable to find free port: %v", err)
	}
	defer l.Close()
	return fmt.Sprintf(":%d", l.Addr().(*net.TCPAddr).Port)
}
