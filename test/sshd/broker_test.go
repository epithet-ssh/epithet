package sshd_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/epithet-ssh/epithet/pkg/broker"
	"github.com/epithet-ssh/epithet/pkg/ca"
	"github.com/epithet-ssh/epithet/pkg/caclient"
	"github.com/epithet-ssh/epithet/pkg/caserver"
	"github.com/epithet-ssh/epithet/pkg/oidctest"
	"github.com/epithet-ssh/epithet/pkg/policy"
	"github.com/epithet-ssh/epithet/pkg/policyserver"
	"github.com/epithet-ssh/epithet/pkg/policyserver/evaluator"
	"github.com/epithet-ssh/epithet/pkg/policyserver/oidc"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/wire"
	"github.com/epithet-ssh/epithet/test/sshd"
	"github.com/lmittmann/tint"
	"github.com/stretchr/testify/require"
)

// fullStack bundles the real broker -> CA -> policy -> JWKS pipeline plus a
// live sshd fixture, so both TestBrokerEndToEnd and the tag-gating test can
// share the same wiring.
type fullStack struct {
	broker       *broker.Broker
	sshdServer   *sshd.Server
	brokerSocket string
	agentDir     string
}

// startFullStack wires a real ca.CA, a real policyserver.NewHandler (a real
// oidc.Validator against idp + a real evaluator - not a stub that approves
// everything), and a real broker, then starts an sshd fixture. The policy
// authorizes the current OS user - the account ssh will actually connect as
// - on any host; the real evaluator carries only that exact principal on the
// issued certificate (see Task 11b), so the sshd fixture's
// AuthorizedPrincipalsFile is written to match (test/sshd/sshd.go).
func startFullStack(t *testing.T, ctx context.Context) *fullStack {
	t.Helper()
	logger := testLogger(t)

	currentUser, err := user.Current()
	require.NoError(t, err)

	caPublicKey, caPrivateKey, err := sshcert.GenerateKeys()
	require.NoError(t, err)

	idp := oidctest.New(t)
	validator, err := oidc.NewValidator(ctx, oidc.Config{
		Issuer:   idp.Issuer(),
		ClientID: oidctest.ClientID,
	})
	require.NoError(t, err)

	policyCfg := &policyserver.PolicyConfig{
		Users: map[string][]string{
			oidctest.TokenEmail: {"member"},
		},
		Defaults: &policyserver.Rules{
			Allow:      map[string][]string{currentUser.Username: {"member"}},
			Expiration: "5m",
			Extensions: map[string]string{"permit-pty": ""},
		},
		Hosts: map[string]*policyserver.Rules{"*": {}},
	}

	policyHandler, err := policyserver.NewHandler(policyserver.Config{
		CAPublicKey: caPublicKey,
		Validator:   validator,
		Evaluator:   evaluator.NewForTesting(policyCfg),
		Discovery: &wire.Discovery{Auth: &wire.AuthConfig{
			Issuer:   idp.Issuer(),
			ClientID: oidctest.ClientID,
		}},
	})
	require.NoError(t, err)
	policyServer := httptest.NewServer(policyHandler)
	t.Cleanup(policyServer.Close)

	// Create CA.
	caInstance, err := ca.New(caPrivateKey, policyServer.URL)
	require.NoError(t, err)

	casrv := caserver.New(caInstance, logger, nil)
	mux := http.NewServeMux()
	mux.Handle("/", casrv.Handler())
	mux.Handle("/discovery", casrv.DiscoveryHandler())
	caHTTPServer := httptest.NewServer(mux)
	t.Cleanup(caHTTPServer.Close)

	// TokenFunc mints a real JWT via the in-process fake IdP.
	tokenFn := func(ctx context.Context, out io.Writer, force bool) (string, error) {
		return idp.MintIDToken(oidctest.TokenEmail, time.Now().Add(time.Hour)), nil
	}

	// Short paths to avoid Unix socket path length limits (~104 bytes on macOS).
	tmpDir := shortTempDir(t)
	brokerSocketPath := tmpDir + "/b.sock"
	agentSocketDir := tmpDir + "/a"

	caEndpoints := []caclient.CAEndpoint{{URL: caHTTPServer.URL, Priority: caclient.DefaultPriority}}
	caClient, err := caclient.New(caEndpoints)
	require.NoError(t, err)

	b, err := broker.New(*logger, brokerSocketPath, tokenFn, caClient, agentSocketDir)
	require.NoError(t, err)

	go func() {
		err := b.Serve(ctx)
		if err != nil && err != context.Canceled {
			t.Logf("broker serve error: %v", err)
		}
	}()
	t.Cleanup(b.Close)
	<-b.Ready()

	sshdServer, err := sshd.Start(caPublicKey)
	require.NoError(t, err)
	t.Cleanup(func() { sshdServer.Close() })
	t.Logf("SSHD started on port %d", sshdServer.Port)

	return &fullStack{
		broker:       b,
		sshdServer:   sshdServer,
		brokerSocket: brokerSocketPath,
		agentDir:     agentSocketDir,
	}
}

// TestBrokerEndToEnd tests the complete flow:
//  1. Start broker wired to a real CA and a real policy server (real OIDC
//     validator against a fake IdP + real evaluator) - JWTs are actually
//     verified, not rubber-stamped by a stub.
//  2. Broker requests a certificate from the CA, which in turn asks the real
//     policy server to evaluate the request.
//  3. Broker creates a per-connection agent.
//  4. SSH connects using the broker's agent and authenticates via cert.
func TestBrokerEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stack := startFullStack(t, ctx)

	// Simulate what `epithet match` would do over the wire: call
	// MatchWithUserOutput directly (TestBrokerEndToEnd_TagGatedSSHConfig
	// below drives the real subprocess/wire path instead).
	conn := policy.Connection{
		RemoteHost: "localhost",
		RemoteUser: stack.sshdServer.User,
		Port:       uint(stack.sshdServer.Port),
		ProxyJump:  "",
		Hash:       computeConnectionHash(t, stack.sshdServer),
	}

	resp := stack.broker.MatchWithUserOutput(ctx, conn, nil)
	t.Logf("Match response: Allow=%v, Error=%s", resp.Allow, resp.Error)
	require.True(t, resp.Allow, "broker should allow connection: %s", resp.Error)

	// Now try to SSH using the broker's agent.
	out, err := stack.sshdServer.SshWithBroker(stack.broker)
	if err != nil {
		t.Logf("SSH output:\n%s", out)
		t.Logf("SSHD output:\n%s", stack.sshdServer.Output.String())
	}
	require.NoError(t, err, "SSH connection should succeed")

	t.Logf("SSH succeeded! Output:\n%s", out)
}

// TestBrokerEndToEnd_TagGatedSSHConfig drives the real end-to-end path from
// ssh itself: an ssh_config "Match tagged epithet-test exec" block (the same
// shape `epithet agent`'s generateSSHConfig produces, see Task 12) invokes
// the built epithet binary, which dials the real broker over its Unix
// socket, gets a real certificate, and hands it to ssh via IdentityAgent.
//
// It asserts two things:
//  1. ssh to a host tagged "epithet-test" authenticates via the minted cert.
//  2. ssh to a host that was never tagged never invokes `epithet match` at
//     all - proven not by trusting that the connection merely failed (it
//     would fail anyway, since its target port is closed), but by pointing
//     that host's Match-tagged block at a "poison" broker socket whose
//     listener fails the test the instant anything dials it. If OpenSSH's
//     tag gating were ever broken (e.g. exec always fired regardless of
//     Tag), this is what would catch it.
func TestBrokerEndToEnd_TagGatedSSHConfig(t *testing.T) {
	requireSSHTagSupport(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stack := startFullStack(t, ctx)

	// Build the epithet binary; the generated config's exec line invokes it
	// exactly as a real profile would.
	tmpDir := shortTempDir(t)
	epithetBin := filepath.Join(tmpDir, "epithet")
	buildOut, err := exec.Command("go", "build", "-o", epithetBin, "../../cmd/epithet").CombinedOutput()
	require.NoError(t, err, "build epithet: %s", buildOut)

	const tag = "epithet-test"

	// --- Untagged case: a poison broker that fails the test if dialed. ---
	tripwireSock := tmpDir + "/tripwire.sock"
	tripwireLn, err := net.Listen("unix", tripwireSock)
	require.NoError(t, err)
	t.Cleanup(func() { tripwireLn.Close() })
	go func() {
		conn, err := tripwireLn.Accept()
		if err == nil {
			conn.Close()
			t.Error("epithet match dialed the broker for a host that was never tagged")
		}
	}()

	poisonConfigPath := tmpDir + "/poison-ssh-config.conf"
	writeGeneratedConfig(t, poisonConfigPath, tag, epithetBin, tripwireSock, tmpDir+"/poison-agent")

	// A closed TCP port: connecting here fails fast (connection refused)
	// regardless of whether epithet match ran, so this alone proves nothing
	// - the tripwire above is what actually proves the gating held.
	closedPort := closedTCPPort(t)

	untaggedConfigPath := tmpDir + "/untagged-client-ssh-config"
	writeClientConfig(t, untaggedConfigPath, fmt.Sprintf(`Host untagged.test
    HostName 127.0.0.1
    Port %d
    User nobody
    # deliberately untagged

Include %s
`, closedPort, poisonConfigPath))

	sshUntagged := exec.CommandContext(ctx, "ssh", "-F", untaggedConfigPath, "untagged.test")
	untaggedOut, _ := sshUntagged.CombinedOutput()
	t.Logf("untagged ssh output:\n%s", untaggedOut)

	// --- Tagged case: the real broker; ssh should authenticate via cert. ---
	realConfigPath := tmpDir + "/real-ssh-config.conf"
	writeGeneratedConfig(t, realConfigPath, tag, epithetBin, stack.brokerSocket, stack.agentDir)

	taggedConfigPath := tmpDir + "/tagged-client-ssh-config"
	writeClientConfig(t, taggedConfigPath, fmt.Sprintf(`Host tagged.test
    HostName localhost
    Port %d
    User %s
    Tag %s

Include %s
`, stack.sshdServer.Port, stack.sshdServer.User, tag, realConfigPath))

	sshTagged := exec.CommandContext(ctx, "ssh", "-F", taggedConfigPath, "tagged.test")
	taggedOut, err := sshTagged.CombinedOutput()
	t.Logf("tagged ssh output:\n%s", taggedOut)
	t.Logf("sshd output:\n%s", stack.sshdServer.Output.String())
	require.NoError(t, err, "ssh to the tagged host should authenticate via the minted cert")
	require.Contains(t, string(taggedOut), "hello from sshd", "the tagged connection should reach the fixture's ForceCommand")
}

func testLogger(t *testing.T) *slog.Logger {
	return slog.New(tint.NewHandler(t.Output(), &tint.Options{
		Level:      slog.LevelDebug,
		TimeFormat: "15:04:05",
	}))
}

func computeConnectionHash(t *testing.T, s *sshd.Server) policy.ConnectionHash {
	// This must match the hash computation in SshWithBroker
	localHost, err := os.Hostname()
	require.NoError(t, err)

	hashInput := fmt.Sprintf("%slocalhost%d%s", localHost, s.Port, s.User)
	hash := sha256.Sum256([]byte(hashInput))
	return policy.ConnectionHash(hex.EncodeToString(hash[:])[:16])
}

// shortTempDir creates a short temporary directory suitable for Unix
// sockets. Unix sockets have a path length limit (~104 bytes on macOS), so
// this uses /tmp with a short random suffix instead of t.TempDir(), whose
// path includes the full test name and can be too long.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sb")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// closedTCPPort binds an ephemeral TCP port and immediately releases it, so
// connecting to it fails fast with "connection refused" instead of hanging.
func closedTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// writeGeneratedConfig writes an ssh_config snippet in the same shape
// `epithet agent`'s generateSSHConfig produces (cmd/epithet/agent.go, Task
// 12): a Match-tagged block whose exec line invokes epithetBin's `match`
// subcommand, gated on tag, pointing at brokerSock.
func writeGeneratedConfig(t *testing.T, path, tag, epithetBin, brokerSock, agentDir string) {
	t.Helper()
	content := fmt.Sprintf(`Match tagged %s exec "%s match --host '%%h' --port '%%p' --user '%%r' --jump '%%j' --hash '%%C' --broker '%s'"
    IdentityAgent %s/%%C
`, tag, epithetBin, brokerSock, agentDir)
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
}

// writeClientConfig writes an ssh_config used directly via `ssh -F`, with
// UserKnownHostsFile/StrictHostKeyChecking/ConnectTimeout defaults common to
// both the tagged and untagged cases, followed by body (the Host block(s)
// and Include line specific to that case).
func writeClientConfig(t *testing.T, path, body string) {
	t.Helper()
	content := "Host *\n" +
		"    UserKnownHostsFile /dev/null\n" +
		"    StrictHostKeyChecking no\n" +
		"    ConnectTimeout 5\n" +
		"\n" + body
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
}

// requireSSHTagSupport skips the test unless the installed ssh supports the
// Tag keyword / "Match tagged" criterion, added in OpenSSH 9.4.
func requireSSHTagSupport(t *testing.T) {
	t.Helper()
	out, err := exec.Command("ssh", "-V").CombinedOutput()
	if err != nil {
		t.Fatalf("could not run ssh -V: %v: %s", err, out)
	}
	major, minor, ok := parseOpenSSHVersion(string(out))
	if !ok {
		t.Skipf("could not parse ssh -V output, skipping: %s", out)
	}
	if major < 9 || (major == 9 && minor < 4) {
		t.Skip("OpenSSH 9.4+ required for Tag")
	}
}

var openSSHVersionRE = regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)

func parseOpenSSHVersion(s string) (major, minor int, ok bool) {
	m := openSSHVersionRE.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, false
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	return major, minor, true
}
