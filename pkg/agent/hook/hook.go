package hook

import (
	"bytes"
	"errors"
	"os/exec"
	"sync"

	"github.com/cbroglie/mustache"
)

// Authenticate is the `authenticate` hook
const Authenticate = "authenticate"

// Start is the `start` hook
const Start = "start"

// Hook represents a configured hook
type Hook struct {
	cmdLine string
	lock    sync.Mutex
	state   []byte
}

// New creates a new hook with an unparsed command line. The line
// will be
func New(cmdLine string) *Hook {
	return &Hook{
		cmdLine: cmdLine,
		state:   []byte{},
	}
}

// Run the hook. if an exit value other than 0 occurs, the combined
// output will be returned in the error.
func (h *Hook) Run(attrs interface{}) error {
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
		return errors.New(string(stderr.Bytes()))
	}
	h.state = stdout.Bytes()

	return nil
}
