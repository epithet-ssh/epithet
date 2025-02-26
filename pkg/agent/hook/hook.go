package hook

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"sync"

	"github.com/cbroglie/mustache"
)

// NeedAuth is the `need_cert` hook
const NeedAuth = "need_auth"

// Start is the `start` hook
const Start = "start"

// Hook represents a configured hook
type Hook struct {
	cmdLine string
	lock    sync.Mutex
	state   string
}

// New creates a new hook with an unparsed command line. The line
// will be
func New(cmdLine string) *Hook {
	return &Hook{
		cmdLine: cmdLine,
		state:   "",
	}
}

// State returns the current token/state
func (a *Hook) State() string {
	return a.state
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
	cmd.Stdin = strings.NewReader(h.state)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return errors.New(string(stderr.Bytes()))
	}
	h.state = string(stdout.Bytes())

	return nil
}
