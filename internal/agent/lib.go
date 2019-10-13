package agent

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Config provides the configuration for the SSH Agent
type Config struct {
	AuthSocketPath string
}

// Credential contains the private key and certificate in pem form
type Credential struct {
	PrivateKey  []byte
	Certificate []byte
}

// Start creates and starts an SSH Agent
// cancel the passed in context to stop the agent
func Start(ctx context.Context, config Config) (context.Context, chan<- Credential, error) {
	ctx, cancel := context.WithCancel(ctx)
	listener, err := net.Listen("unix", config.AuthSocketPath)
	if err != nil {
		cancel()
		return ctx, nil, fmt.Errorf("unable to listen on %s: %w", config.AuthSocketPath, err)
	}

	keyring := agent.NewKeyring()

	creds := make(chan Credential, 1)
	go startLoop(ctx, listener, keyring)
	go credentialLoop(ctx, creds, keyring, cancel)

	return ctx, creds, nil
}

func credentialLoop(ctx context.Context, creds chan Credential, keyring agent.Agent, cancel context.CancelFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-creds:
			oldKeys, err := keyring.List()
			if err != nil {
				log.Printf("unable to list keys in agent: %v", err)
				cancel()
				continue
			}

			pk, _, _, _, err := ssh.ParseAuthorizedKey(c.Certificate)
			if err != nil {
				log.Printf("error parsing certificate: %v", err)
				cancel()
			}
			cert, ok := pk.(*ssh.Certificate)
			if !ok {
				log.Printf("error certificate is not a certificate: %v", err)
				cancel()
			}

			priv, err := ssh.ParseRawPrivateKey(c.PrivateKey)
			if err != nil {
				log.Printf("error parsing private key: %v", err)
				close(creds)
			}
			keyring.Add(agent.AddedKey{
				PrivateKey:  priv,
				Certificate: cert,
			})

			for _, k := range oldKeys {
				keyring.Remove(k)
			}
		}
	}

}

func startLoop(ctx context.Context, listener net.Listener, keyring agent.Agent) {
	for ctx.Err() == nil {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				// context is cancelled, exit the loop
				return
			}

		}
		go func() {
			err := agent.ServeAgent(keyring, conn)
			if err != nil && err != io.EOF {
				log.Printf("error from ssh-agent: %v", err)
				_ = conn.Close()
				// ignoring close erros
			}
		}()
	}
}
