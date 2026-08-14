package broker

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cbroglie/mustache"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// MaxStateBlobSize is the maximum size of the state blob (10 MiB).
// This prevents malicious or buggy auth plugins from exhausting memory.
const MaxStateBlobSize = 10 * 1024 * 1024

// commandWaitDelay bounds how long we wait for the auth command's pipes to
// close after the command is killed (e.g. orphaned grandchildren holding fds).
const commandWaitDelay = 5 * time.Second

// Auth represents a configured authentication command.
//
// Concurrency: Auth is safe for concurrent use. Concurrent Run() calls are
// coalesced (singleflight): the first caller starts the auth command, later
// callers join the in-flight attempt, receive a replay of its user-visible
// output so far, and share its result. The auth command is killed when every
// caller waiting on it has canceled its context.
//
// Locking invariants:
//   - lock protects: state, token, inflight
//   - the flight goroutine snapshots state at start and writes state/token
//     back under lock on success; no other Run can start while it is in flight
//   - cmdLine is immutable after NewAuth()
type Auth struct {
	cmdLine  string      // Immutable after NewAuth()
	lock     sync.Mutex  // Protects state, token, inflight
	state    []byte      // Protected by lock
	token    string      // Protected by lock
	inflight *authFlight // Protected by lock; non-nil while an auth command runs
}

// authFlight is a single in-flight execution of the auth command, shared by
// every Run() caller that is waiting on it.
type authFlight struct {
	mu      sync.Mutex
	output  bytes.Buffer      // Accumulated user-visible output, replayed to joiners
	writers map[int]io.Writer // Live user-output writers, keyed by waiter id
	nextID  int
	waiters   int                // Callers currently waiting on this flight
	abandoned bool               // Set when the last waiter cancels; no new joiners
	cancel    context.CancelFunc // Kills the auth command; called when waiters drops to 0

	done  chan struct{} // Closed when the flight finishes; token/err valid after
	token string
	err   error
}

// Write broadcasts user-visible output from the auth command to every
// attached caller and records it for replay to late joiners.
func (f *authFlight) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.output.Write(p)
	for _, w := range f.writers {
		// Best effort: a dead writer is dropped when its waiter detaches.
		_, _ = w.Write(p)
	}
	return len(p), nil
}

// attach registers a caller waiting on this flight. Output produced so far
// (e.g. the "visit this URL" message) is replayed to userOutput. Returns
// ok=false without attaching if the flight has been abandoned (its auth
// command is already being killed); the caller should wait for it to finish
// and start a fresh one.
func (f *authFlight) attach(userOutput io.Writer) (id int, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.abandoned {
		return 0, false
	}
	id = f.nextID
	f.nextID++
	f.waiters++
	if userOutput != nil {
		if f.output.Len() > 0 {
			_, _ = userOutput.Write(f.output.Bytes())
		}
		f.writers[id] = userOutput
	}
	return id, true
}

// detach removes a caller. When the last caller detaches before the flight
// finishes, the auth command is killed — nobody is left to use its result.
func (f *authFlight) detach(id int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.writers, id)
	f.waiters--
	if f.waiters == 0 {
		f.abandoned = true
		f.cancel()
	}
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
// If userOutput is non-nil, user-visible progress from fd 4 is written to it.
//
// If an auth command is already in flight, Run joins it instead of starting
// another: userOutput receives a replay of the in-flight command's progress
// (e.g. the pending auth URL) and Run returns that command's result. Joiners
// share the in-flight command's rendered command line; attrs only affect the
// caller that starts a flight.
//
// Canceling ctx abandons this caller's wait. The auth command itself is
// killed only when every waiting caller has canceled.
//
// Protocol:
//   - stdin: current state bytes (empty on first call)
//   - stdout (fd 1): authentication token (raw bytes)
//   - stderr (fd 2): error messages (captured, included in errors on failure)
//   - fd 3: new state bytes (max MaxStateBlobSize)
//   - fd 4: user-visible progress (e.g., "Visit https://... and enter code ABC-123")
//   - exit 0: success, non-zero: failure
func (h *Auth) Run(ctx context.Context, attrs any, userOutput io.Writer) (string, error) {
	// Render the command line template.
	cmdLine, err := mustache.Render(h.cmdLine, attrs)
	if err != nil {
		return "", fmt.Errorf("failed to render command template: %w", err)
	}

	for {
		h.lock.Lock()
		flight := h.inflight
		if flight == nil {
			// The flight's context is deliberately detached from ctx: its
			// lifetime is governed by the set of waiters, not any single caller.
			flightCtx, cancel := context.WithCancel(context.Background())
			flight = &authFlight{
				writers: make(map[int]io.Writer),
				cancel:  cancel,
				done:    make(chan struct{}),
			}
			h.inflight = flight
			// Attach before starting the command so the flight cannot be
			// abandoned out from under its first waiter.
			id, _ := flight.attach(userOutput)
			go h.runFlight(flightCtx, cmdLine, h.state, flight)
			h.lock.Unlock()
			return h.wait(ctx, flight, id)
		}
		id, ok := flight.attach(userOutput)
		h.lock.Unlock()
		if ok {
			return h.wait(ctx, flight, id)
		}

		// The flight was abandoned (its command is being killed). Wait for it
		// to wind down, then start a fresh attempt.
		select {
		case <-flight.done:
		case <-ctx.Done():
			return "", fmt.Errorf("authentication canceled: %w", ctx.Err())
		}
	}
}

// wait blocks until the flight finishes or ctx is canceled, detaching the
// caller from the flight either way.
func (h *Auth) wait(ctx context.Context, flight *authFlight, id int) (string, error) {
	defer flight.detach(id)
	select {
	case <-flight.done:
		return flight.token, flight.err
	case <-ctx.Done():
		return "", fmt.Errorf("authentication canceled: %w", ctx.Err())
	}
}

// runFlight executes the auth command and publishes the result to the flight.
func (h *Auth) runFlight(ctx context.Context, cmdLine string, state []byte, flight *authFlight) {
	token, newState, err := execute(ctx, cmdLine, state, flight)

	h.lock.Lock()
	if err == nil {
		h.state = newState
		h.token = token
	}
	h.inflight = nil
	h.lock.Unlock()

	flight.token = token
	flight.err = err
	close(flight.done)
}

// execute runs the auth command once, wiring up the plugin protocol fds.
// Canceling ctx kills the command's entire process group.
func execute(ctx context.Context, cmdLine string, state []byte, userOutput io.Writer) (string, []byte, error) {
	// Set up pipe for fd 3 (state output).
	stateReader, stateWriter, err := os.Pipe()
	if err != nil {
		return "", nil, fmt.Errorf("failed to create state pipe: %w", err)
	}
	defer stateReader.Close()

	// Set up pipe for fd 4 (user-visible output).
	userReader, userWriter, err := os.Pipe()
	if err != nil {
		stateWriter.Close()
		return "", nil, fmt.Errorf("failed to create user output pipe: %w", err)
	}
	defer userReader.Close()

	// Execute the auth command.
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "sh", "-c", cmdLine)
	cmd.Stdin = bytes.NewReader(state)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.ExtraFiles = []*os.File{stateWriter, userWriter} // fd 3, fd 4 in child process
	// Run the command in its own process group and kill the whole group on
	// cancel: descendants (e.g. a spawned browser helper) hold the fd 3/4
	// write ends, and killing only the shell would leave our pipe reads
	// blocked until those descendants exit.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = commandWaitDelay

	if err := cmd.Start(); err != nil {
		stateWriter.Close()
		userWriter.Close()
		return "", nil, fmt.Errorf("failed to start auth command: %w", err)
	}

	// Close write ends in parent so we can detect EOF.
	stateWriter.Close()
	userWriter.Close()

	// Copy user output to caller's writer in background.
	userOutputDone := make(chan error, 1)
	go func() {
		if userOutput != nil {
			_, err := io.Copy(userOutput, userReader)
			userOutputDone <- err
		} else {
			io.Copy(io.Discard, userReader) // Drain to avoid blocking.
			userOutputDone <- nil
		}
	}()

	// Read new state from fd 3 (with size limit).
	newState, err := io.ReadAll(io.LimitReader(stateReader, MaxStateBlobSize+1))
	if err != nil {
		cmd.Wait() // Clean up process.
		<-userOutputDone
		return "", nil, fmt.Errorf("failed to read state from fd 3: %w", err)
	}

	// Check if state exceeds limit.
	if len(newState) > MaxStateBlobSize {
		cmd.Wait() // Clean up process.
		<-userOutputDone
		return "", nil, fmt.Errorf("state blob exceeds maximum size of %d bytes", MaxStateBlobSize)
	}

	// Wait for user output copying to complete.
	if err := <-userOutputDone; err != nil {
		cmd.Wait() // Clean up process.
		return "", nil, fmt.Errorf("failed to copy user output: %w", err)
	}

	// Wait for command to complete.
	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return "", nil, fmt.Errorf("auth command canceled: %w", ctx.Err())
		}
		return "", nil, fmt.Errorf("auth command failed: %w: %s", err, stderr.String())
	}

	// Extract token from stdout.
	token := stdout.Bytes()
	if len(token) == 0 {
		return "", nil, fmt.Errorf("auth command returned empty token")
	}

	// Return the token (base64url encoded to preserve arbitrary bytes).
	return base64.RawURLEncoding.EncodeToString(token), newState, nil
}

// AuthConfigToCommand converts a bootstrap auth config to an executable command string.
// For type="oidc": constructs "<executable> auth oidc --issuer X --client-id Y --scopes Z"
// For type="command": returns the command as-is (substituting "epithet" with os.Executable())
// Returns an error if the auth type is unknown or if os.Executable() fails.
func AuthConfigToCommand(auth wire.AuthConfig) (string, error) {
	switch auth.Type {
	case "oidc":
		// Construct the OIDC auth command
		executable, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("failed to get executable path: %w", err)
		}

		// Build command: <executable> auth oidc --issuer X --client-id Y [--client-secret Z] --scopes A,B,C
		parts := []string{
			executable,
			"auth", "oidc",
			"--issuer", auth.Issuer,
			"--client-id", auth.ClientID,
		}

		if auth.ClientSecret != "" {
			parts = append(parts, "--client-secret", auth.ClientSecret)
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
