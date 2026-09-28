package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/epithet-ssh/epithet/pkg/policyserver/writpolicy"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/epithet-ssh/epithet/pkg/writ"
	"github.com/epithet-ssh/epithet/pkg/writ/diag"
)

// PolicyConfig is shared by CA startup and offline policy validation.
type PolicyConfig struct {
	PolicyFile string `help:"Path to the writ policy file" name:"policy-file"`
	// <review>
	// Outside scope of this change, but do we want to allow multiple policy files?
	// </review>

	Extension map[string]string `help:"Certificate extension for issued certs (name=value, repeatable; default permit-pty, permit-agent-forwarding, permit-user-rc)" name:"certificate-extension"`

	DefaultExpiration string `help:"Default certificate expiration when no rule sets a ttl (e.g., 5m)" name:"certificate-default-ttl"`
}

type PolicyCLI struct {
	PolicyConfig `embed:""`
	Check        bool `help:"Validate the policy, then exit" name:"check"`
}

func (c *PolicyCLI) Run(logger *slog.Logger) error {
	if _, err := c.buildEvaluator(logger); err != nil {
		return err
	}
	fmt.Println("policy OK")
	return nil
}

// buildEvaluator loads the writ policy and wires
// the evaluator with an empty plugin registry — a policy that names any
// requirement, flag, or notify target therefore fails here, at
// startup, naming what is missing. Shared by --check and the server
// path; reload is a process restart.
func (c *PolicyConfig) buildEvaluator(logger *slog.Logger) (*writpolicy.Evaluator, error) {
	if c.PolicyFile == "" {
		return nil, fmt.Errorf("policy-file is required (via --policy-file flag or ca.policy-file in config)")
	}
	src, err := os.ReadFile(c.PolicyFile)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	pol, diags := writ.Load(string(src))
	for _, d := range diag.Warnings(diags) {
		logger.Warn("policy warning", "pos", fmt.Sprintf("%s:%s", c.PolicyFile, d.Pos), "msg", d.Msg)
	}
	if pol == nil {
		errs := diag.Errors(diags)
		for _, d := range errs {
			fmt.Fprintf(os.Stderr, "%s:%s: error: %s\n", c.PolicyFile, d.Pos, d.Msg)
		}
		return nil, fmt.Errorf("policy %s has %d error(s)", c.PolicyFile, len(errs))
	}

	opts := writpolicy.Options{}
	if len(c.Extension) > 0 {
		opts.Extensions = c.Extension
	}
	if c.DefaultExpiration != "" {
		d, err := time.ParseDuration(c.DefaultExpiration)
		if err != nil {
			return nil, fmt.Errorf("invalid certificate-default-ttl: %w", err)
		}
		opts.DefaultTTL = d
	}

	eval, warnings, err := writpolicy.New(pol, &writpolicy.Registry{}, opts)
	if err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	for _, w := range warnings {
		logger.Warn("policy warning", "msg", w)
	}

	logger.Info("policy loaded",
		"policy_file", c.PolicyFile,
		"allow_rules", len(pol.Allows),
		"deny_rules", len(pol.Denies))
	return eval, nil
}

// resolveCAPubkey resolves the CA public key from a URL, file path, or literal key.
func resolveCAPubkey(input string, tlsCfg tlsconfig.Config, logger *slog.Logger) (string, error) {
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		if err := tlsCfg.ValidateURL(input); err != nil {
			return "", err
		}

		httpClient, err := tlsconfig.NewHTTPClient(tlsCfg)
		if err != nil {
			return "", fmt.Errorf("failed to create HTTP client: %w", err)
		}

		if logger != nil {
			logger.Debug("http request", "method", "GET", "url", input)
		}

		start := time.Now()
		resp, err := httpClient.Get(input)
		duration := time.Since(start)
		if err != nil {
			if logger != nil {
				logger.Debug("http request failed", "method", "GET", "url", input, "duration_ms", duration.Milliseconds(), "error", err)
			}
			return "", fmt.Errorf("failed to fetch CA public key from URL %s: %w", input, err)
		}
		defer resp.Body.Close()

		if logger != nil {
			logger.Debug("http response", "method", "GET", "url", input, "status", resp.StatusCode, "duration_ms", duration.Milliseconds())
		}

		if resp.StatusCode != 200 {
			return "", fmt.Errorf("failed to fetch CA public key from URL %s: status %d", input, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read CA public key from URL %s: %w", input, err)
		}

		return strings.TrimSpace(string(body)), nil
	}

	if _, err := os.Stat(input); err == nil {
		body, err := os.ReadFile(input)
		if err != nil {
			return "", fmt.Errorf("failed to read CA public key from file %s: %w", input, err)
		}
		return strings.TrimSpace(string(body)), nil
	}

	if !strings.HasPrefix(input, "ssh-") && !strings.HasPrefix(input, "ecdsa-") {
		return "", fmt.Errorf("CA public key does not appear to be a valid SSH key (should start with ssh-* or ecdsa-*), not a valid URL, and file does not exist: %s", input)
	}

	return input, nil
}
