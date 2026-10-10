package main

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/epithet-ssh/epithet/pkg/writ"
	"github.com/epithet-ssh/epithet/pkg/writ/diag"
	"github.com/epithet-ssh/epithet/pkg/writpolicy"
)

// PolicyConfig is shared by CA startup and offline policy validation.
type PolicyConfig struct {
	PolicyFile string            `help:"Path to the writ policy file" name:"policy-file"`
	Extension  map[string]string `help:"Certificate extension for issued certs (name=value, repeatable; default permit-pty, permit-agent-forwarding, permit-user-rc)" name:"certificate-extension"`

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
