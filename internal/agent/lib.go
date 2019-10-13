package agent

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Config provides the configuration for the SSH Agent
type Config struct {
	AuthSocketPath string
}

// Agent represents our agent
type Agent struct {
	cancel  context.CancelFunc
	keyring agent.Agent
	ctx     context.Context
}

// Running reports on whether the current agent is healthy
func (a *Agent) Running() bool {
	return a.ctx.Err() != nil
}

// UseCredential the credentials on the agemnt
func (a *Agent) UseCredential(c Credential) error {
	oldKeys, err := a.keyring.List()
	if err != nil {
		a.cancel()
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
		a.cancel()
		return fmt.Errorf("unable to add new credential: %w", err)
	}

	for _, k := range oldKeys {
		err = a.keyring.Remove(k)
		if err != nil {
			a.cancel()
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

// Start creates and starts an SSH Agent
// cancel the passed in context to stop the agent
func Start(ctx context.Context, config Config) (*Agent, error) {
	ctx, cancel := context.WithCancel(ctx)
	listener, err := net.Listen("unix", config.AuthSocketPath)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("unable to listen on %s: %w", config.AuthSocketPath, err)
	}

	err = os.Chmod(config.AuthSocketPath, 0600)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("unable to set permissions on auth socket: %w", err)
	}

	keyring := agent.NewKeyring()
	a := &Agent{
		cancel:  cancel,
		keyring: keyring,
		ctx:     ctx,
	}
	go a.startLoop(listener)

	return a, nil
}

func (a *Agent) startLoop(listener net.Listener) {
	for a.ctx.Err() == nil {
		conn, err := listener.Accept()
		if err != nil {
			if a.ctx.Err() != nil {
				// context is cancelled, exit the loop
				return
			}
		}
		go func() {
			err := agent.ServeAgent(a.keyring, conn)
			if err != nil && err != io.EOF {
				log.Printf("error from ssh-agent: %v", err)
				_ = conn.Close()
				// ignoring close erros
			}
		}()
	}
}
