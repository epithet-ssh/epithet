package plugin

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
)

// Plugins work by passing in values on the command line, serialized using base64
// and reading responses out on stderr.
// This leaves stdin/stdout available for interaction by the user, to
// enter credentials or such

// Run runs the plugin
func Run(input []byte, plugin ...string) ([]byte, error) {
	c := plugin[0]
	args := plugin[1:]

	in := base64.StdEncoding.EncodeToString(input)

	args = append(args, in)

	cmd := exec.Command(c, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin

	err := cmd.Run()
	if err != nil {
		return nil, err
	}
	return stderr.Bytes(), nil
}
