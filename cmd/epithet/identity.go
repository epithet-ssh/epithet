package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/policyserver/oidc"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/wire"
)

// AgentIdentityCLI authenticates the running agent and reports its identity.
type AgentIdentityCLI struct {
	Broker string `help:"Broker socket path (overrides profile discovery)" short:"b"`
}

func (c *AgentIdentityCLI) Run(parent *AgentCLI) error {
	socket, err := resolveAgentBrokerSocket(parent, c.Broker)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	return c.run(ctx, socket, os.Stdout, os.Stderr)
}

func (c *AgentIdentityCLI) run(ctx context.Context, socket string, out, progress io.Writer) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return fmt.Errorf("cannot connect to agent at %s; start it with epithet agent: %w", socket, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := json.NewEncoder(conn).Encode(broker.Request{Identity: &struct{}{}}); err != nil {
		return fmt.Errorf("sending identity request: %w", err)
	}
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 4096), scannerBufferSize)
	for scanner.Scan() {
		var event broker.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return fmt.Errorf("reading agent identity: %w", err)
		}
		if event.Output != "" {
			if _, err := io.WriteString(progress, event.Output); err != nil {
				return err
			}
		}
		if event.Identity != nil {
			if event.Identity.Error != "" {
				return fmt.Errorf("agent identity: %s", event.Identity.Error)
			}
			if event.Identity.Identity == nil {
				return fmt.Errorf("agent returned no identity")
			}
			return json.NewEncoder(out).Encode(event.Identity.Identity)
		}
		if event.Result != nil {
			return fmt.Errorf("agent identity: %s (restart the agent if it predates identity support)", event.Result.Error)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading agent identity: %w", err)
	}
	return fmt.Errorf("agent closed connection without an identity")
}

// makeAgentIdentityVerifier uses the running agent's discovery configuration.
// OIDC discovery happens on demand; starting an agent does not require login.
func makeAgentIdentityVerifier(auth wire.AuthConfig, tlsCfg tlsconfig.Config) broker.IdentityVerifier {
	var mu sync.Mutex
	var cached *oidc.Validator
	getValidator := func(ctx context.Context) (*oidc.Validator, error) {
		mu.Lock()
		defer mu.Unlock()
		if cached != nil {
			return cached, nil
		}
		v, err := oidc.NewValidator(ctx, oidc.Config{
			Issuer: auth.Issuer, ClientID: auth.ClientID,
			UserIDClaim: auth.UserIDClaim, TLSConfig: tlsCfg,
		})
		if err == nil {
			cached = v // Reuse the HTTP connection pool and signing-key cache.
		}
		return v, err // Failed discovery is retried by the next request.
	}
	return func(ctx context.Context, token string) (*broker.Identity, error) {
		validator, err := getValidator(ctx)
		if err != nil {
			return nil, err
		}
		claims, err := validator.Validate(ctx, token)
		if err != nil {
			return nil, err
		}
		return &broker.Identity{ID: claims.UserID, Issuer: claims.Issuer, Subject: claims.Subject}, nil
	}
}
