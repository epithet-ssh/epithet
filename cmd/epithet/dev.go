package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type DevCLI struct {
	Policy PolicyCLI `cmd:"policy" help:"Run a development policy server"`
}

type PolicyCLI struct {
	Principals []string `help:"principals to assign (can be specified multiple times)" short:"p" required:"true"`
	Port       int      `help:"port to listen on" short:"P" default:"9999"`
	Mode       string   `help:"policy mode: allow-all, deny-all" short:"m" default:"allow-all" enum:"allow-all,deny-all"`
	Identity   string   `help:"identity to assign in certificates" short:"i" default:"steve"`
	Expiration string   `help:"certificate expiration duration (e.g., 1m, 5m, 1h)" short:"e" default:"1m"`
	CAPubkey   string   `help:"CA public key (URL like http://localhost:8080, file path, or literal SSH key)" required:"true"`
}

// devPolicyEvaluator implements policyserver.PolicyEvaluator for the dev policy server
type devPolicyEvaluator struct {
	mode       string
	principals []string
	identity   string
	expiration time.Duration
	logger     *slog.Logger
}

func (e *devPolicyEvaluator) Evaluate(token string, conn policy.Connection) (*policyserver.Response, error) {
	// Policy decision based on mode
	switch e.mode {
	case "allow-all":
		e.logger.Info("policy decision: approved (allow-all mode)",
			"remote_user", conn.RemoteUser,
			"remote_host", conn.RemoteHost,
			"port", conn.Port)

		return &policyserver.Response{
			CertParams: ca.CertParams{
				Identity:   e.identity,
				Names:      e.principals,
				Expiration: e.expiration,
				Extensions: map[string]string{
					"permit-agent-forwarding": "",
					"permit-pty":              "",
					"permit-user-rc":          "",
				},
			},
			Policy: policy.Policy{
				HostPattern: "*",
			},
		}, nil

	case "deny-all":
		e.logger.Info("policy decision: denied (deny-all mode)",
			"remote_user", conn.RemoteUser,
			"remote_host", conn.RemoteHost,
			"port", conn.Port)

		return nil, policyserver.Forbidden("Policy denied by dev policy server (deny-all mode)")

	default:
		return nil, policyserver.InternalError(fmt.Sprintf("Unknown mode: %s", e.mode))
	}
}

// resolveCAPubkey resolves the CA public key from a URL, file path, or literal key
func resolveCAPubkey(input string) (string, error) {
	// Check if it's a URL
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		resp, err := http.Get(input)
		if err != nil {
			return "", fmt.Errorf("failed to fetch CA public key from URL %s: %w", input, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return "", fmt.Errorf("failed to fetch CA public key from URL %s: status %d", input, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read CA public key from URL %s: %w", input, err)
		}

		return strings.TrimSpace(string(body)), nil
	}

	// Check if it's a file path (exists on filesystem)
	if _, err := os.Stat(input); err == nil {
		body, err := os.ReadFile(input)
		if err != nil {
			return "", fmt.Errorf("failed to read CA public key from file %s: %w", input, err)
		}
		return strings.TrimSpace(string(body)), nil
	}

	// Assume it's a literal SSH public key
	// Basic validation: should start with ssh-
	if !strings.HasPrefix(input, "ssh-") && !strings.HasPrefix(input, "ecdsa-") {
		return "", fmt.Errorf("CA public key does not appear to be a valid SSH key (should start with ssh-* or ecdsa-*), not a valid URL, and file does not exist: %s", input)
	}

	return input, nil
}

func (c *PolicyCLI) Run(logger *slog.Logger) error {
	// Parse expiration duration
	expiration, err := time.ParseDuration(c.Expiration)
	if err != nil {
		return fmt.Errorf("invalid expiration duration %q: %w", c.Expiration, err)
	}

	// Resolve CA public key
	caPubkey, err := resolveCAPubkey(c.CAPubkey)
	if err != nil {
		return err
	}

	// Create policy evaluator
	evaluator := &devPolicyEvaluator{
		mode:       c.Mode,
		principals: c.Principals,
		identity:   c.Identity,
		expiration: expiration,
		logger:     logger,
	}

	// Create policy server handler
	handler := policyserver.NewHandler(policyserver.Config{
		CAPublicKey: sshcert.RawPublicKey(caPubkey),
		Evaluator:   evaluator,
	})

	// Set up router with middleware
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Post("/", handler)

	addr := fmt.Sprintf(":%d", c.Port)
	logger.Info("starting dev policy server",
		"addr", addr,
		"mode", c.Mode,
		"principals", c.Principals,
		"identity", c.Identity,
		"expiration", expiration,
		"ca_pubkey", caPubkey)
	return http.ListenAndServe(addr, r)
}
