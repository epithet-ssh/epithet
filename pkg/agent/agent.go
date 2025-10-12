package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var errAgentStopped = errors.New("agent has been stopped")

// Agent represents an SSH agent that manages certificates
type Agent struct {
	keyring  agent.Agent
	caClient *caclient.Client
	ctx      context.Context

	agentSocketPath string
	agentListener   net.Listener

	publicKey  sshcert.RawPublicKey
	privateKey sshcert.RawPrivateKey

	lock      sync.Mutex
	done      chan struct{}
	closeOnce sync.Once
}

// Start creates and starts an SSH agent that listens on the specified socket path.
// If agentSocketPath is empty, a temporary socket will be created.
// The agent will automatically close when the context is cancelled.
func Start(ctx context.Context, caClient *caclient.Client, agentSocketPath string) (*Agent, error) {
	keyring := agent.NewKeyring()
	a := &Agent{
		ctx:             ctx,
		agentSocketPath: agentSocketPath,
		keyring:         keyring,
		caClient:        caClient,
		done:            make(chan struct{}),
	}

	pub, priv, err := sshcert.GenerateKeys()
	if err != nil {
		return nil, err
	}
	a.privateKey = priv
	a.publicKey = pub

	if a.ctx == nil {
		a.ctx = context.Background()
	}

	err = a.startAgentListener()
	if err != nil {
		return nil, err
	}

	context.AfterFunc(ctx, func() {
		a.Close()
	})

	return a, nil
}

// Credential contains the private key and certificate in PEM format
type Credential struct {
	PrivateKey  sshcert.RawPrivateKey
	Certificate sshcert.RawCertificate
}

// UseCredential replaces the current credentials in the agent with the provided credential
func (a *Agent) UseCredential(c Credential) error {
	if !a.Running() {
		return errAgentStopped
	}

	log.Debug("replacing credentials")
	oldKeys, err := a.keyring.List()
	if err != nil {
		a.Close()
		return fmt.Errorf("unable to list current credentials: %w", err)
	}

	cert, err := sshcert.Parse(c.Certificate)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)
	}

	priv, err := ssh.ParseRawPrivateKey([]byte(c.PrivateKey))
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
			return fmt.Errorf("unable to remove old credential: %w", err)
		}
	}
	return nil
}

func (a *Agent) startAgentListener() error {
	if a.agentSocketPath == "" {
		f, err := os.CreateTemp("", "epithet-agent.*")
		if err != nil {
			a.Close()
			return fmt.Errorf("unable to create agent socket: %w", err)
		}
		a.agentSocketPath = f.Name()
		f.Close()
		os.Remove(f.Name())
	}

	os.Remove(a.agentSocketPath) // Remove socket if it exists
	agentListener, err := net.Listen("unix", a.agentSocketPath)
	if err != nil {
		a.Close()
		return fmt.Errorf("unable to listen on %s: %w", a.agentSocketPath, err)
	}

	err = os.Chmod(a.agentSocketPath, 0600)
	if err != nil {
		a.Close()
		return fmt.Errorf("unable to set permissions on agent socket: %w", err)
	}
	a.agentListener = agentListener
	go a.listenAndServeAgent(agentListener)
	return nil
}

func (a *Agent) listenAndServeAgent(listener net.Listener) {
	for a.Running() {
		conn, err := listener.Accept()
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			if !a.Running() {
				// Agent is shutting down
				return
			}
			log.Warnf("error on accept from SSH_AUTH_SOCK listener: %v", err)
			continue
		}
		go a.serveAgent(conn)
	}
}

func (a *Agent) serveAgent(conn net.Conn) {
	defer conn.Close()

	log.Debug("new connection to agent")
	err := agent.ServeAgent(a.keyring, conn)
	if err != nil && err != io.EOF {
		log.Warnf("error from ssh-agent: %v", err)
	}
}

// AgentSocketPath returns the path to the agent's Unix socket
func (a *Agent) AgentSocketPath() string {
	return a.agentSocketPath
}

// IsAgentStopped returns true if the error indicates that the agent has been stopped
func IsAgentStopped(err error) bool {
	return errors.Is(err, errAgentStopped)
}

// Running returns true if the agent is currently running and accepting connections
func (a *Agent) Running() bool {
	select {
	case <-a.Done():
		return false
	default:
		return true
	}
}

// Done returns a channel that is closed when the agent has been closed and cleanup is complete.
// This can be used with select statements or waitgroups to know when the agent is fully stopped.
func (a *Agent) Done() <-chan struct{} {
	return a.done
}

// Close stops the agent and cleans up resources. Safe to call multiple times.
func (a *Agent) Close() {
	a.closeOnce.Do(func() {
		if a.agentListener != nil {
			_ = a.agentListener.Close() // Ignore error
		}
		close(a.done)
	})
}
