package broker

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"

	"github.com/cbroglie/mustache"
	"github.com/markdingo/netstring"
)

// Protocol keys for keyed netstrings
const (
	keyState = 's' // State blob (opaque, managed by auth plugin)
	keyToken = 't' // Authentication token (to be sent to CA)
	keyError = 'e' // Error message (human-readable auth failure reason)
)

// AuthOutput represents the result of an auth command invocation
type authOutput struct {
	Token string // Authentication token (mutually exclusive with Error)
	State []byte // Updated state blob (optional)
	Error string // Auth failure message (mutually exclusive with Token)
}

// Auth represents a configured authentication command.
//
// Concurrency: Auth is safe for concurrent use. All public methods use internal locking.
//
// Locking invariants:
//   - lock protects: state, token
//   - Token() reads token under lock
//   - Run() holds lock for entire auth command execution and state update (atomic operation)
//   - cmdLine is immutable after NewAuth()
type Auth struct {
	cmdLine string     // Immutable after NewAuth()
	lock    sync.Mutex // Protects state and token
	state   []byte     // Protected by lock
	token   string     // Protected by lock
}

// NewAuth creates a new Auth with an unparsed command line.
func NewAuth(cmdLine string) *Auth {
	return &Auth{
		cmdLine: cmdLine,
		state:   []byte{},
		token:   "",
	}
}

// Token returns the current authentication token, or empty string if not authenticated.
func (h *Auth) Token() string {
	h.lock.Lock()
	defer h.lock.Unlock()
	return h.token
}

// encodeAuthInput encodes state for auth command stdin.
// If state is empty, returns empty netstring "0:,"
// Otherwise returns state with 's' key as keyed netstring
func encodeAuthInput(state []byte) ([]byte, error) {
	var buf bytes.Buffer
	enc := netstring.NewEncoder(&buf)

	if len(state) == 0 {
		// Empty netstring for initial authentication (no key)
		if err := enc.Encode(netstring.NoKey, []byte{}); err != nil {
			return nil, fmt.Errorf("failed to encode empty state: %w", err)
		}
	} else {
		// State with 's' key
		if err := enc.EncodeBytes(keyState, state); err != nil {
			return nil, fmt.Errorf("failed to encode state: %w", err)
		}
	}

	return buf.Bytes(), nil
}

// decodeAuthOutput parses auth command stdout.
// Reads keyed netstrings until EOF, validating protocol rules.
func decodeAuthOutput(stdout []byte) (*authOutput, error) {
	if len(stdout) == 0 {
		return nil, errors.New("auth command returned empty output")
	}

	dec := netstring.NewDecoder(bytes.NewReader(stdout))
	output := &authOutput{}
	hasToken := false
	hasError := false

	for {
		key, value, err := dec.DecodeKeyed()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid netstring format: %w", err)
		}

		switch key {
		case keyState:
			output.State = value

		case keyToken:
			if hasToken {
				return nil, errors.New("protocol violation: multiple token fields")
			}
			if hasError {
				return nil, errors.New("protocol violation: cannot have both token and error")
			}
			output.Token = string(value)
			hasToken = true

		case keyError:
			if hasError {
				return nil, errors.New("protocol violation: multiple error fields")
			}
			if hasToken {
				return nil, errors.New("protocol violation: cannot have both token and error")
			}
			output.Error = string(value)
			hasError = true

		default:
			// Unknown keys are ignored for forward compatibility
		}
	}

	// Validate that we got either a token or an error
	if !hasToken && !hasError {
		return nil, errors.New("protocol violation: must have either token or error field and not both")
	}

	return output, nil
}

// Run executes the auth command with the current state and updates state based on output.
// Returns AuthOutput containing token/error and updated state.
// The command line is rendered as a mustache template with the provided attrs.
func (h *Auth) Run(attrs any) (string, error) {
	h.lock.Lock()
	defer h.lock.Unlock()

	// Render the command line template
	cmdLine, err := mustache.Render(h.cmdLine, attrs)
	if err != nil {
		return "", fmt.Errorf("failed to render command template: %w", err)
	}

	// Encode input (current state)
	input, err := encodeAuthInput(h.state)
	if err != nil {
		return "", fmt.Errorf("failed to encode auth input: %w", err)
	}

	// Execute the auth command
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("sh", "-c", cmdLine)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		// Non-zero exit is an unexpected error (not auth failure)
		return "", fmt.Errorf("auth command failed: %w: %s", err, stderr.String())
	}

	// Decode the output
	output, err := decodeAuthOutput(stdout.Bytes())
	if err != nil {
		return "", fmt.Errorf("failed to decode auth output: %w", err)
	}

	if output.Error != "" {
		// error reported from auth plugin!
		return "", errors.New(output.Error)
	}

	// Update stored state (even if empty - plugin might be clearing state)
	h.state = output.State

	// Store the token
	h.token = output.Token

	return output.Token, nil
}
