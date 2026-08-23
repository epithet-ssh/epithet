// Package diag holds source positions and diagnostics for the writ
// policy language. It is deliberately tiny and dependency-free: every
// other writ package reports through it.
package diag

import "fmt"

// Pos is a 1-based line/column source position.
type Pos struct {
	Line int
	Col  int
}

func (p Pos) String() string {
	return fmt.Sprintf("%d:%d", p.Line, p.Col)
}

// Severity distinguishes errors (block compilation) from warnings
// (reported, never blocking).
type Severity int

const (
	Error Severity = iota
	Warning
)

func (s Severity) String() string {
	if s == Warning {
		return "warning"
	}
	return "error"
}

// Diagnostic is one reported problem, anchored to a source position.
type Diagnostic struct {
	Pos      Pos
	Severity Severity
	Msg      string
}

func (d Diagnostic) String() string {
	return fmt.Sprintf("%s: %s: %s", d.Pos, d.Severity, d.Msg)
}

// Errorf builds an error-severity diagnostic.
func Errorf(pos Pos, format string, args ...any) Diagnostic {
	return Diagnostic{Pos: pos, Severity: Error, Msg: fmt.Sprintf(format, args...)}
}

// Warnf builds a warning-severity diagnostic.
func Warnf(pos Pos, format string, args ...any) Diagnostic {
	return Diagnostic{Pos: pos, Severity: Warning, Msg: fmt.Sprintf(format, args...)}
}

// HasErrors reports whether any diagnostic in ds is error-severity.
func HasErrors(ds []Diagnostic) bool {
	for _, d := range ds {
		if d.Severity == Error {
			return true
		}
	}
	return false
}

// Errors returns only the error-severity diagnostics.
func Errors(ds []Diagnostic) []Diagnostic {
	var out []Diagnostic
	for _, d := range ds {
		if d.Severity == Error {
			out = append(out, d)
		}
	}
	return out
}

// Warnings returns only the warning-severity diagnostics.
func Warnings(ds []Diagnostic) []Diagnostic {
	var out []Diagnostic
	for _, d := range ds {
		if d.Severity == Warning {
			out = append(out, d)
		}
	}
	return out
}
