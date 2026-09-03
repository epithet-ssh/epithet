package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/hostid"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestHostEnrollCreatesHostIDAndCAPublicKey(t *testing.T) {
	pub := newTestCAPublicKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Link", `<enroll>; rel="https://epithet.dev/rel/enroll"`)
		fmt.Fprintf(w, "%s test-ca\n", strings.TrimSpace(string(pub)))
	}))
	t.Cleanup(server.Close)

	dir := filepath.Join(t.TempDir(), "state")
	cmd := HostEnrollCLI{
		CAURL:        server.URL,
		HostIDFile:   filepath.Join(dir, "host-id"),
		CAPubkeyFile: filepath.Join(dir, "ca.pub"),
	}
	result, err := cmd.enrollState(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	require.True(t, result.HostIDCreated)
	require.True(t, result.CAPublicKeyCreated)
	require.Equal(t, pub, result.CAPublicKey)
	require.Equal(t, server.URL, result.CAFinalURL)
	require.Equal(t, []string{`<enroll>; rel="https://epithet.dev/rel/enroll"`}, result.AdvertisedLinkFields)

	storedID, err := hostid.ReadFile(cmd.HostIDFile)
	require.NoError(t, err)
	require.Equal(t, result.HostID, storedID)
	storedKey, err := os.ReadFile(cmd.CAPubkeyFile)
	require.NoError(t, err)
	require.Equal(t, string(pub), string(storedKey))
	requireFileMode(t, cmd.HostIDFile, 0o644)
	requireFileMode(t, cmd.CAPubkeyFile, 0o644)
}

func TestHostEnrollRerunIsIdempotent(t *testing.T) {
	pub := newTestCAPublicKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, pub)
	}))
	t.Cleanup(server.Close)

	dir := filepath.Join(t.TempDir(), "state")
	cmd := HostEnrollCLI{
		CAURL:        server.URL,
		HostIDFile:   filepath.Join(dir, "host-id"),
		CAPubkeyFile: filepath.Join(dir, "ca.pub"),
	}
	first, err := cmd.enrollState(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	second, err := cmd.enrollState(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	require.Equal(t, first.HostID, second.HostID)
	require.False(t, second.HostIDCreated)
	require.False(t, second.CAPublicKeyCreated)
}

func TestHostEnrollRejectsConflictingCAWithoutCreatingHostID(t *testing.T) {
	fetched := newTestCAPublicKey(t)
	existing := newTestCAPublicKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fetched)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	hostIDPath := filepath.Join(dir, "host-id")
	caKeyPath := filepath.Join(dir, "ca.pub")
	require.NoError(t, os.WriteFile(caKeyPath, []byte(existing), 0o644))
	cmd := HostEnrollCLI{CAURL: server.URL, HostIDFile: hostIDPath, CAPubkeyFile: caKeyPath}

	_, err := cmd.enrollState(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.ErrorContains(t, err, "conflicts with the key returned by the CA")
	_, err = os.Stat(hostIDPath)
	require.ErrorIs(t, err, os.ErrNotExist)
	data, err := os.ReadFile(caKeyPath)
	require.NoError(t, err)
	require.Equal(t, string(existing), string(data))
}

func TestHostEnrollInvalidResponseLeavesHostStateAbsent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not an SSH key")
	}))
	t.Cleanup(server.Close)

	dir := filepath.Join(t.TempDir(), "state")
	cmd := HostEnrollCLI{
		CAURL:        server.URL,
		HostIDFile:   filepath.Join(dir, "host-id"),
		CAPubkeyFile: filepath.Join(dir, "ca.pub"),
	}
	_, err := cmd.enrollState(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.ErrorContains(t, err, "invalid SSH public key")
	_, err = os.Stat(dir)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestHostEnrollFailedRequestLeavesHostStateAbsent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close()

	dir := filepath.Join(t.TempDir(), "state")
	cmd := HostEnrollCLI{
		CAURL:        url,
		HostIDFile:   filepath.Join(dir, "host-id"),
		CAPubkeyFile: filepath.Join(dir, "epithet-ca.pub"),
	}
	_, err := cmd.enrollState(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.Error(t, err)
	_, err = os.Stat(dir)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestHostEnrollDefaultsCAKeyBesideOverriddenHostID(t *testing.T) {
	hostIDPath := filepath.Join(t.TempDir(), "custom", "identity")
	cmd := HostEnrollCLI{HostIDFile: hostIDPath}

	gotHostID, gotCAKey, err := cmd.paths()
	require.NoError(t, err)
	require.Equal(t, hostIDPath, gotHostID)
	require.Equal(t, filepath.Join(filepath.Dir(hostIDPath), "epithet-ca.pub"), gotCAKey)
}

func TestHostEnrollCompletesLocalSSHDEnrollment(t *testing.T) {
	pub := newTestCAPublicKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, pub)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	mainPath := filepath.Join(dir, "ssh", "sshd_config")
	fragmentPath := filepath.Join(dir, "ssh", "sshd_config.d", "60-epithet.conf")
	require.NoError(t, os.MkdirAll(filepath.Dir(mainPath), 0o755))
	require.NoError(t, os.WriteFile(mainPath, []byte("Port 22\n"), 0o600))
	runner := &recordingSSHDRunner{}
	env := &sshdEnvironment{
		goos:       "linux",
		getenv:     func(string) string { return "" },
		executable: func() (string, error) { return "/test/epithet", nil },
		runner:     runner,
	}
	cmd := HostEnrollCLI{
		CAURL:                           server.URL,
		HostIDFile:                      filepath.Join(dir, "state", "host-id"),
		CAPubkeyFile:                    filepath.Join(dir, "state", "epithet-ca.pub"),
		PrincipalMode:                   principal.SchemeV1,
		SSHDConfigFile:                  mainPath,
		SSHDFragmentFile:                fragmentPath,
		SSHDBinary:                      "/test/sshd",
		EpithetBinary:                   "/test/epithet",
		AuthorizedPrincipalsCommandUser: "nobody",
		ReloadCommand:                   "/test/reload",
		ReloadArgs:                      []string{"reload", "sshd"},
		sshdEnv:                         env,
	}

	result, err := cmd.enroll(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	require.NotEmpty(t, result.HostID)
	requireFileMode(t, cmd.HostIDFile, 0o644)
	requireFileMode(t, cmd.CAPubkeyFile, 0o644)
	requireFileContents(t, mainPath, sshdMainBegin+"\nInclude \""+fragmentPath+"\"\n"+sshdMainEnd+"\n\nPort 22\n")
	fragment, err := os.ReadFile(fragmentPath)
	require.NoError(t, err)
	require.Contains(t, string(fragment), "AuthorizedPrincipalsCommand")
	require.Len(t, runner.calls, 4)
}

func TestHostEnrollRerunRecoversCustomStateFromSSHDConfiguration(t *testing.T) {
	pub := newTestCAPublicKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, pub)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	mainPath := filepath.Join(dir, "ssh", "sshd_config")
	fragmentPath := filepath.Join(dir, "custom-ssh", "epithet.conf")
	hostIDPath := filepath.Join(dir, "custom-state", "machine-identity")
	caKeyPath := filepath.Join(dir, "custom-trust", "epithet-ca.pub")
	require.NoError(t, os.MkdirAll(filepath.Dir(mainPath), 0o755))
	require.NoError(t, os.WriteFile(mainPath, []byte("Port 22\n"), 0o600))

	firstRunner := &recordingSSHDRunner{}
	env := &sshdEnvironment{
		goos:       "linux",
		getenv:     func(string) string { return "" },
		executable: func() (string, error) { return "/test/epithet", nil },
		runner:     firstRunner,
	}
	firstCommand := HostEnrollCLI{
		CAURL:                           server.URL,
		HostIDFile:                      hostIDPath,
		CAPubkeyFile:                    caKeyPath,
		PrincipalMode:                   principal.SchemeV1,
		SSHDConfigFile:                  mainPath,
		SSHDFragmentFile:                fragmentPath,
		SSHDBinary:                      "/test/sshd",
		EpithetBinary:                   "/test/epithet",
		AuthorizedPrincipalsCommandUser: "nobody",
		ReloadCommand:                   "/test/reload",
		sshdEnv:                         env,
	}
	first, err := firstCommand.enroll(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)

	secondRunner := &recordingSSHDRunner{}
	env.runner = secondRunner
	secondCommand := HostEnrollCLI{
		CAURL:                           server.URL,
		SSHDConfigFile:                  mainPath,
		AuthorizedPrincipalsCommandUser: "nobody",
		sshdEnv:                         env,
	}
	second, err := secondCommand.enroll(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	require.Equal(t, first.HostID, second.HostID)
	require.False(t, second.HostIDCreated)
	require.False(t, second.CAPublicKeyCreated)
	require.Equal(t, hostIDPath, secondCommand.HostIDFile)
	require.Equal(t, caKeyPath, secondCommand.CAPubkeyFile)
	require.Equal(t, fragmentPath, secondCommand.SSHDFragmentFile)
	require.Len(t, secondRunner.calls, 1, "an unchanged rerun validates but does not reload sshd")
}

func newTestCAPublicKey(t *testing.T) sshcert.RawPublicKey {
	t.Helper()
	pub, _, err := sshcert.GenerateKeys()
	require.NoError(t, err)
	return pub
}

func requireFileMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, mode, info.Mode().Perm())
}
