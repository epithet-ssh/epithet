// Package writ is the facade over the writ policy language frontend:
// parse, check, and lower to the IL in one call. The language packages
// beneath it (parser, compile, il, eval) are server-free by design —
// they are destined for extraction into a standalone module shared
// with the writ server (SPEC §12.11).
package writ

import (
	"github.com/epithet-ssh/epithet/pkg/writ/compile"
	"github.com/epithet-ssh/epithet/pkg/writ/diag"
	"github.com/epithet-ssh/epithet/pkg/writ/il"
	"github.com/epithet-ssh/epithet/pkg/writ/parser"
)

// Load parses and compiles policy source. The policy is non-nil iff no
// error-severity diagnostics were produced; warnings ride along either
// way and never block.
func Load(src string) (*il.Policy, []diag.Diagnostic) {
	file, diags := parser.Parse(src)
	pol, cdiags := compile.Compile(file)
	diags = append(diags, cdiags...)
	if diag.HasErrors(diags) {
		return nil, diags
	}
	return pol, diags
}
