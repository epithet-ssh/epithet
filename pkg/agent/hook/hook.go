package hook

import (
	"errors"
	"os/exec"

	"github.com/cbroglie/mustache"
)

// NeedAuth is the `need_cert` hook
const NeedAuth = "need_auth"

// Start is the `start` hook
const Start = "start"

// Hook represents a configured hook
type Hook struct {
	cmdLine string
}

// New creates a new hook with an unparsed command line. The line
// will be
func New(cmdLine string) *Hook {
	return &Hook{cmdLine: cmdLine}
}

// Run the hook. if an exit value other than 0 occurs, the combined
// output will be returned in the error.
func (h *Hook) Run(attrs interface{}) error {
	out, err := mustache.Render(h.cmdLine, attrs)
	if err != nil {
		return err
	}
	cmd := exec.Command("sh", "-c", out)
	rs, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(string(rs))
	}
	return nil
}
