package broker

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/cbroglie/mustache"
	"github.com/epithet-ssh/epithet/pkg/caclient"
)

// MaxStateBlobSize is the maximum size of the state blob (10 MiB).
// This prevents malicious or buggy auth plugins from exhausting memory.
const MaxStateBlobSize = 10 * 1024 * 1024

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

// ClearToken clears the stored authentication token.
// Keeps the state intact (refresh token may still be valid).
// Used when receiving HTTP 401 from CA to force re-authentication.
func (h *Auth) ClearToken() {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.token = ""
}

// Run executes the auth command with the current state and updates state based on output.
// Returns the authentication token on success.
// The command line is rendered as a mustache template with the provided attrs.
//
// Protocol:
//   - stdin: current state bytes (empty on first call)
//   - stdout: authentication token (raw bytes)
//   - fd 3: new state bytes (max MaxStateBlobSize)
//   - stderr: error messages on failure
//   - exit 0: success, non-zero: failure
func (h *Auth) Run(attrs any) (string, error) {
	h.lock.Lock()
	defer h.lock.Unlock()

	// Render the command line template
	cmdLine, err := mustache.Render(h.cmdLine, attrs)
	if err != nil {
		return "", fmt.Errorf("failed to render command template: %w", err)
	}

	// Set up pipes for fd 3 (state output)
	stateReader, stateWriter, err := os.Pipe()
	if err != nil {
		return "", fmt.Errorf("failed to create state pipe: %w", err)
	}
	defer stateReader.Close()

	// Execute the auth command
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("sh", "-c", cmdLine)
	cmd.Stdin = bytes.NewReader(h.state)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.ExtraFiles = []*os.File{stateWriter} // fd 3 in child process

	if err := cmd.Start(); err != nil {
		stateWriter.Close()
		return "", fmt.Errorf("failed to start auth command: %w", err)
	}

	// Close write end in parent so we can detect EOF
	stateWriter.Close()

	// Read new state from fd 3 (with size limit)
	newState, err := io.ReadAll(io.LimitReader(stateReader, MaxStateBlobSize+1))
	if err != nil {
		cmd.Wait() // Clean up process
		return "", fmt.Errorf("failed to read state from fd 3: %w", err)
	}

	// Check if state exceeds limit
	if len(newState) > MaxStateBlobSize {
		cmd.Wait() // Clean up process
		return "", fmt.Errorf("state blob exceeds maximum size of %d bytes", MaxStateBlobSize)
	}

	// Wait for command to complete
	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("auth command failed: %w: %s", err, stderr.String())
	}

	// Extract token from stdout
	token := stdout.Bytes()
	if len(token) == 0 {
		return "", fmt.Errorf("auth command returned empty token")
	}

	// Update stored state
	h.state = newState

	// Store the token (base64url encoded to preserve arbitrary bytes)
	h.token = base64.RawURLEncoding.EncodeToString(token)

	return h.token, nil
}

// AuthConfigToCommand converts a bootstrap auth config to an executable command string.
// For type="oidc": constructs "<executable> auth oidc --issuer X --client-id Y --scopes Z"
// For type="command": returns the command as-is (substituting "epithet" with os.Executable())
// Returns an error if the auth type is unknown or if os.Executable() fails.
func AuthConfigToCommand(auth caclient.BootstrapAuth) (string, error) {
	switch auth.Type {
	case "oidc":
		// Construct the OIDC auth command
		executable, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("failed to get executable path: %w", err)
		}

		// Build command: <executable> auth oidc --issuer X --client-id Y --scopes A,B,C
		parts := []string{
			executable,
			"auth", "oidc",
			"--issuer", auth.Issuer,
			"--client-id", auth.ClientID,
		}

		if len(auth.Scopes) > 0 {
			parts = append(parts, "--scopes", strings.Join(auth.Scopes, ","))
		}

		return strings.Join(parts, " "), nil

	case "command":
		// Use the command as-is, substituting "epithet" with the current executable
		if auth.Command == "" {
			return "", fmt.Errorf("command auth type requires non-empty command")
		}

		executable, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("failed to get executable path: %w", err)
		}

		// Replace "epithet" with the actual executable path
		// This allows bootstrap configs to use "epithet" as a placeholder
		cmd := strings.ReplaceAll(auth.Command, "epithet", executable)
		return cmd, nil

	default:
		return "", fmt.Errorf("unknown auth type: %s", auth.Type)
	}
}
