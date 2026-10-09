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

	"github.com/alecthomas/kong"
	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/epithet-ssh/epithet/pkg/sshcert"
	"github.com/epithet-ssh/epithet/pkg/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestHostEnrollCLIModelAllowsPlatformDependentPrincipalModeDefault(t *testing.T) {
	var cmd HostEnrollCLI
	parser, err := kong.New(&cmd)
	require.NoError(t, err)
	_, err = parser.Parse([]string{"--ca", "https://ca.example/", "--principal-realm", "fleet"})
	require.NoError(t, err)
	require.Equal(t, "fleet", cmd.PrincipalRealm)
}

func TestHostEnrollExplicitRealmPreservesExistingState(t *testing.T) {
	pub := newTestCAPublicKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, pub)
	}))
	t.Cleanup(server.Close)
	for _, tc := range []struct{ name, requested, failure string }{
		{"matching", "fleet", ""},
		{"conflicting", "other", "conflicts with the installed realm"},
		{"invalid", "not a realm", "invalid principal-realm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cmd := HostEnrollCLI{CAURL: server.URL, PrincipalRealm: tc.requested, RealmFile: filepath.Join(dir, "realm"), CAPubkeyFile: filepath.Join(dir, "ca.pub")}
			require.NoError(t, os.WriteFile(cmd.RealmFile, []byte("fleet\n"), 0644))
			state, err := cmd.prepareState(t.Context(), nil, tlsconfig.Config{Insecure: true})
			if tc.failure != "" {
				require.ErrorContains(t, err, tc.failure)
			} else {
				require.NoError(t, err)
				require.Equal(t, principal.Realm("fleet"), state.Realm)
			}
			requireFileContents(t, cmd.RealmFile, "fleet\n")
			require.NoFileExists(t, cmd.CAPubkeyFile)
		})
	}
}

func TestHostEnrollRejectsUnknownPrincipalModeBeforeCreatingState(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	sshdConfig := filepath.Join(root, "sshd_config")
	require.NoError(t, os.WriteFile(sshdConfig, nil, 0o600))
	cmd := HostEnrollCLI{
		CAURL:          "https://ca.example.com/",
		RealmFile:      filepath.Join(dir, "realm"),
		CAPubkeyFile:   filepath.Join(dir, "epithet-ca.pub"),
		PrincipalMode:  "mystery",
		SSHDConfigFile: sshdConfig,
		sshdEnv: &sshdEnvironment{
			goos:       "linux",
			getenv:     func(string) string { return "" },
			executable: func() (string, error) { return "/test/epithet", nil },
		},
	}

	_, err := cmd.enroll(context.Background(), nil, tlsconfig.Config{})
	require.ErrorContains(t, err, `unknown principal mode "mystery"`)
	_, err = os.Stat(dir)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestHostEnrollCreatesRealmAndCAPublicKey(t *testing.T) {
	pub := newTestCAPublicKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Link", `<enroll>; rel="https://epithet.dev/rel/enroll"`)
		fmt.Fprintf(w, "%s test-ca\n", strings.TrimSpace(string(pub)))
	}))
	t.Cleanup(server.Close)

	dir := filepath.Join(t.TempDir(), "state")
	cmd := HostEnrollCLI{
		CAURL:        server.URL,
		RealmFile:    filepath.Join(dir, "realm"),
		CAPubkeyFile: filepath.Join(dir, "ca.pub"),
	}
	result, err := cmd.prepareState(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	require.NoDirExists(t, dir, "preparation must not install state")
	reviewedRealm := result.Realm
	require.NoError(t, result.install(nil))
	require.Equal(t, reviewedRealm, result.Realm)
	require.True(t, result.RealmCreated)
	require.True(t, result.CAPublicKeyCreated)
	require.Equal(t, pub, result.CAPublicKey)
	require.Equal(t, server.URL, result.CAFinalURL)
	require.Equal(t, []string{`<enroll>; rel="https://epithet.dev/rel/enroll"`}, result.AdvertisedLinkFields)

	storedRealm, err := principal.ReadRealmFile(cmd.RealmFile)
	require.NoError(t, err)
	require.Equal(t, result.Realm, storedRealm)
	storedKey, err := os.ReadFile(cmd.CAPubkeyFile)
	require.NoError(t, err)
	require.Equal(t, string(pub), string(storedKey))
	requireFileMode(t, cmd.RealmFile, 0o644)
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
		RealmFile:    filepath.Join(dir, "realm"),
		CAPubkeyFile: filepath.Join(dir, "ca.pub"),
	}
	first, err := cmd.prepareState(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	require.NoError(t, first.install(nil))
	second, err := cmd.prepareState(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	require.NoError(t, second.install(nil))
	require.Equal(t, first.Realm, second.Realm)
	require.False(t, second.RealmCreated)
	require.False(t, second.CAPublicKeyCreated)
}

func TestHostEnrollRejectsConflictingCAWithoutCreatingRealm(t *testing.T) {
	fetched := newTestCAPublicKey(t)
	existing := newTestCAPublicKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, fetched)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	realmPath := filepath.Join(dir, "realm")
	caKeyPath := filepath.Join(dir, "ca.pub")
	require.NoError(t, os.WriteFile(caKeyPath, []byte(existing), 0o644))
	cmd := HostEnrollCLI{CAURL: server.URL, RealmFile: realmPath, CAPubkeyFile: caKeyPath}

	_, err := cmd.prepareState(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.ErrorContains(t, err, "conflicts with the key returned by the CA")
	_, err = os.Stat(realmPath)
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
		RealmFile:    filepath.Join(dir, "realm"),
		CAPubkeyFile: filepath.Join(dir, "ca.pub"),
	}
	_, err := cmd.prepareState(context.Background(), nil, tlsconfig.Config{Insecure: true})
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
		RealmFile:    filepath.Join(dir, "realm"),
		CAPubkeyFile: filepath.Join(dir, "epithet-ca.pub"),
	}
	_, err := cmd.prepareState(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.Error(t, err)
	_, err = os.Stat(dir)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestHostEnrollDefaultsCAKeyBesideOverriddenRealm(t *testing.T) {
	realmPath := filepath.Join(t.TempDir(), "custom", "realm")
	cmd := HostEnrollCLI{RealmFile: realmPath}

	gotRealm, gotCAKey, err := cmd.paths()
	require.NoError(t, err)
	require.Equal(t, realmPath, gotRealm)
	require.Equal(t, filepath.Join(filepath.Dir(realmPath), "epithet-ca.pub"), gotCAKey)
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
		RealmFile:                       filepath.Join(dir, "state", "realm"),
		CAPubkeyFile:                    filepath.Join(dir, "state", "epithet-ca.pub"),
		PrincipalMode:                   principal.SchemeV1,
		SSHDConfigFile:                  mainPath,
		SSHDFragmentFile:                fragmentPath,
		SSHDBinary:                      "/test/sshd",
		EpithetBinary:                   "/test/epithet",
		AuthorizedPrincipalsCommandUser: "nobody",
		sshdEnv:                         env,
	}

	result, err := cmd.enroll(context.Background(), nil, tlsconfig.Config{Insecure: true})
	require.NoError(t, err)
	require.NotEmpty(t, result.Realm)
	requireFileMode(t, cmd.RealmFile, 0o644)
	requireFileMode(t, cmd.CAPubkeyFile, 0o644)
	requireFileContents(t, mainPath, sshdMainBegin+"\nInclude \""+fragmentPath+"\"\n"+sshdMainEnd+"\n\nPort 22\n")
	fragment, err := os.ReadFile(fragmentPath)
	require.NoError(t, err)
	require.Contains(t, string(fragment), "AuthorizedPrincipalsCommand")
	require.Len(t, runner.calls, 5)
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
	realmPath := filepath.Join(dir, "custom-state", "principal-realm")
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
		RealmFile:                       realmPath,
		CAPubkeyFile:                    caKeyPath,
		PrincipalMode:                   principal.SchemeV1,
		SSHDConfigFile:                  mainPath,
		SSHDFragmentFile:                fragmentPath,
		SSHDBinary:                      "/test/sshd",
		EpithetBinary:                   "/test/epithet",
		AuthorizedPrincipalsCommandUser: "nobody",
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
	require.Equal(t, first.Realm, second.Realm)
	require.False(t, second.RealmCreated)
	require.False(t, second.CAPublicKeyCreated)
	require.Equal(t, realmPath, second.RealmFile)
	require.Equal(t, caKeyPath, second.CAPubkeyFile)
	require.Empty(t, secondCommand.RealmFile, "resolving existing state must not mutate CLI options")
	require.Empty(t, secondCommand.CAPubkeyFile)
	require.Empty(t, secondCommand.SSHDFragmentFile)
	require.Len(t, secondRunner.calls, 2, "an unchanged rerun validates but does not reload sshd")
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

func TestEnrollmentInstallRejectsRealmChangedDuringReview(t *testing.T) {
	dir := t.TempDir()
	state := &hostEnrollment{
		Realm:        "reviewed-realm",
		RealmFile:    filepath.Join(dir, "realm"),
		CAPubkeyFile: filepath.Join(dir, "ca.pub"),
		CAPublicKey:  newTestCAPublicKey(t),
	}
	require.NoError(t, os.WriteFile(state.RealmFile, []byte("another-realm\n"), 0o644))
	require.ErrorContains(t, state.install(nil), "changed since preparation")
	requireFileContents(t, state.RealmFile, "another-realm\n")
	require.NoFileExists(t, state.CAPubkeyFile)
}
