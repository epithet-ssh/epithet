// Package writ compiles policy source into validated IL. Parsing, syntax trees,
// and static checks are private implementation details of Load; evaluation and
// programmatic IL construction remain separate packages.
package writ

import (
	"github.com/epithet-ssh/epithet/pkg/writ/diag"
	"github.com/epithet-ssh/epithet/pkg/writ/il"
)

// Load parses and compiles policy source. The policy is non-nil iff no
// error-severity diagnostics were produced; warnings ride along either
// way and never block.
func Load(src string) (*il.Policy, []diag.Diagnostic) {
	file, diags := parse(src)
	pol, cdiags := compile(file)
	diags = append(diags, cdiags...)
	if diag.HasErrors(diags) {
		return nil, diags
	}
	return pol, diags
}
