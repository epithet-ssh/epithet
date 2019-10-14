package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"

	log "github.com/sirupsen/logrus"

	"go.uber.org/atomic"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var errAgentStopped error = errors.New("agent has been stopped")

// IsAgentStopped lets you test if an error indicates that the agent has been stopped
func IsAgentStopped(err error) bool {
	return errors.Is(err, errAgentStopped)
}

// Option configures the agent
type Option interface {
	apply(*Agent) error
}

type optionFunc func(*Agent) error

func (f optionFunc) apply(a *Agent) error {
	return f(a)
}

// WithAuthSocketPath specifies the SSH_AUTH_SOCK path to create
func WithAuthSocketPath(path string) Option {
	return optionFunc(func(a *Agent) error {
		a.authSocketPath = path
		return nil
	})
}

// WithContext specifies a context.Context that agent will use
// and which can be cancelled, triggering the agent to top
func WithContext(ctx context.Context) Option {
	return optionFunc(func(a *Agent) error {
		go func() {
			select {
			case <-ctx.Done():
				a.Close()
			}
		}()
		return nil
	})
}

// Agent represents our agent
type Agent struct {
	running        *atomic.Bool
	keyring        agent.Agent
	authSocketPath string
	listener       net.Listener
}

// AuthSocketPath returns the path for the SSH_AUTH_SOCKET
func (a *Agent) AuthSocketPath() string {
	return a.authSocketPath
}

// Start creates and starts an SSH Agent
func Start(options ...Option) (*Agent, error) {
	keyring := agent.NewKeyring()
	a := &Agent{
		keyring: keyring,
		running: atomic.NewBool(true),
	}

	for _, o := range options {
		o.apply(a)
	}

	if a.authSocketPath == "" {
		f, err := ioutil.TempFile("", "epithet-agent.*")
		if err != nil {
			a.Close()
			return nil, fmt.Errorf("unable to create agent socket: %w", err)
		}
		a.authSocketPath = f.Name()
		f.Close()
		os.Remove(f.Name())
	}

	listener, err := net.Listen("unix", a.authSocketPath)
	if err != nil {
		a.Close()
		return nil, fmt.Errorf("unable to listen on %s: %w", a.authSocketPath, err)
	}

	err = os.Chmod(a.authSocketPath, 0600)
	if err != nil {
		a.Close()
		return nil, fmt.Errorf("unable to set permissions on auth socket: %w", err)
	}
	a.listener = listener
	go a.loop(listener)

	return a, nil
}

// Running reports on whether the current agent is healthy
func (a *Agent) Running() bool {
	return a.running.Load()
}

// Close stops the agent and cleansup after it
func (a *Agent) Close() error {
	a.running.Store(false)
	_ = a.listener.Close() //ignore error

	return nil
}

// UseCredential the credentials on the agemnt
func (a *Agent) UseCredential(c Credential) error {
	if !a.Running() {
		return errAgentStopped
	}

	oldKeys, err := a.keyring.List()
	if err != nil {
		a.Close()
		return fmt.Errorf("unable to list current credentials: %w", err)
	}

	pk, _, _, _, err := ssh.ParseAuthorizedKey(c.Certificate)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)

	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return fmt.Errorf("error certificate is not a certificate: %w", err)

	}

	priv, err := ssh.ParseRawPrivateKey(c.PrivateKey)
	if err != nil {
		return fmt.Errorf("error parsing private key: %w", err)
	}
	err = a.keyring.Add(agent.AddedKey{
		PrivateKey:  priv,
		Certificate: cert,
	})
	if err != nil {
		a.Close()
		return fmt.Errorf("unable to add new credential: %w", err)
	}

	for _, k := range oldKeys {
		err = a.keyring.Remove(k)
		if err != nil {
			a.Close()
			return fmt.Errorf("Unable to remove old credential: %w", err)
		}
	}

	return nil
}

// Credential contains the private key and certificate in pem form
type Credential struct {
	PrivateKey  []byte
	Certificate []byte
}

func (a *Agent) loop(listener net.Listener) {
	for a.running.Load() {
		conn, err := listener.Accept()
		if err != nil {
			// nothing we can do on this loop
			if conn != nil {
				conn.Close()
			}
			if !a.running.Load() {
				// we are shutting down, just return
				return
			}
			log.Warnf("error on accept from SSH_AUTH_SOCK listener: %v", err)
		}
		go func() {
			err := agent.ServeAgent(a.keyring, conn)
			if err != nil && err != io.EOF {
				log.Warnf("error from ssh-agent: %v", err)
				_ = conn.Close()
				// ignoring close erros
			}
		}()
	}
}
