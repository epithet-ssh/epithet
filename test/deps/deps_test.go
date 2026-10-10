// Package deps pins the layering between client, wire and server packages.
// The agent, broker and CA client must never link a server or storage package.
// Shared fact contracts and clients stay independent of their implementations.
package deps_test

import (
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const module = "github.com/epithet-ssh/epithet/"

// deps returns the full transitive import closure of pkg, excluding pkg itself.
func deps(t *testing.T, pkg string) []string {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", pkg)
	cmd.Dir = "../.."
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "go list -deps %s: %s", pkg, out)
	self := module + strings.TrimPrefix(pkg, "./")
	var result []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if line != "" && line != self {
			result = append(result, line)
		}
	}
	return result
}

func TestClientPackagesDoNotLinkServers(t *testing.T) {
	forbidden := []string{
		module + "pkg/ca",
		module + "pkg/caserver",
		module + "pkg/facts/control",
		module + "pkg/facts/server",
		module + "pkg/facts/inventory",
		module + "pkg/facts/directory",
		module + "pkg/facts/storage",
		module + "pkg/writpolicy",
		"modernc.org/sqlite",
		"github.com/elimity-com/scim",
		"gopkg.in/yaml.v3",
	}
	for _, pkg := range []string{"./pkg/agent", "./pkg/broker", "./pkg/caclient", "./pkg/facts"} {
		t.Run(pkg, func(t *testing.T) {
			for _, dep := range deps(t, pkg) {
				for _, bad := range forbidden {
					if dep == bad || strings.HasPrefix(dep, bad+"/") {
						t.Errorf("%s depends on %s; shared contracts and clients must not link service implementations", pkg, dep)
					}
				}
			}
		})
	}
}

func TestWireContractsAreLeaves(t *testing.T) {
	allowed := map[string][]string{
		// wire validates host names and principal realms, both leaf packages.
		"./pkg/wire": {module + "pkg/hostpattern", module + "pkg/principal", module + "pkg/sshcert"},
	}
	for pkg, ok := range allowed {
		t.Run(pkg, func(t *testing.T) {
			for _, dep := range deps(t, pkg) {
				if strings.HasPrefix(dep, module) && !slices.Contains(ok, dep) {
					t.Errorf("%s depends on %s; it must stay a leaf so clients and servers can both import it", pkg, dep)
				}
			}
		})
	}
}

// Fact clients and the public control frontend must be usable without linking
// the built-in handlers or SQLite stores, including through indirect imports.
func TestFactClientsAndControlDoNotLinkBuiltInServices(t *testing.T) {
	for _, pkg := range []string{"./pkg/facts", "./pkg/facts/control", "./pkg/ca"} {
		t.Run(pkg, func(t *testing.T) {
			for _, dep := range deps(t, pkg) {
				for _, bad := range []string{
					module + "pkg/facts/server",
					module + "pkg/facts/storage",
					module + "pkg/facts/inventory",
					module + "pkg/facts/directory",
					"modernc.org/sqlite",
					"github.com/elimity-com/scim",
				} {
					if dep == bad || strings.HasPrefix(dep, bad+"/") {
						t.Errorf("%s depends on %s; built-in service implementations belong behind pkg/facts/server", pkg, dep)
					}
				}
			}
		})
	}
}
