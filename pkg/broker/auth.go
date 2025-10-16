package broker

import (
	"bytes"
	"errors"
	"os/exec"
	"sync"

	"github.com/cbroglie/mustache"
)

// Auth represents a configured hook
type Auth struct {
	cmdLine string
	lock    sync.Mutex
	state   []byte
}

// New creates a new hook with an unparsed command line. The line
// will be
func New(cmdLine string) *Auth {
	return &Auth{
		cmdLine: cmdLine,
		state:   []byte{},
	}
}

// Run the hook. if an exit value other than 0 occurs, the combined
// output will be returned in the error.
func (h *Auth) Run(attrs any) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	out, err := mustache.Render(h.cmdLine, attrs)
	if err != nil {
		return err
	}

	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	cmd := exec.Command("sh", "-c", out)
	cmd.Stdin = bytes.NewReader(h.state)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return errors.New(stderr.String())
	}
	h.state = stdout.Bytes()

	return nil
}
