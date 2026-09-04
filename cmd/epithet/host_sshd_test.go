package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/stretchr/testify/require"
)

type recordedSSHDCommand struct {
	name string
	args []string
}

type recordingSSHDRunner struct {
	calls []recordedSSHDCommand
	run   func(int, string, []string) ([]byte, error)
}

func (r *recordingSSHDRunner) CombinedOutput(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, recordedSSHDCommand{name: name, args: append([]string(nil), args...)})
	if r.run == nil {
		return nil, nil
	}
	return r.run(len(r.calls), name, args)
}

func TestPlatformSSHDDefaultsCoverSupportedSystems(t *testing.T) {
	wantReload := map[string]string{
		"linux":     "systemctl",
		"dragonfly": "service",
		"freebsd":   "service",
		"netbsd":    "/etc/rc.d/sshd",
		"openbsd":   "rcctl",
		"darwin":    "launchctl",
		"aix":       "refresh",
		"illumos":   "svcadm",
		"solaris":   "svcadm",
		"windows":   "powershell.exe",
	}
	getenv := func(name string) string {
		switch name {
		case "ProgramData":
			return `C:\ProgramData`
		case "SystemRoot":
			return `C:\Windows`
		default:
			return ""
		}
	}
	for goos, reload := range wantReload {
		t.Run(goos, func(t *testing.T) {
			got := platformSSHDDefaults(goos, getenv)
			require.NotEmpty(t, got.configFile)
			require.NotEmpty(t, got.fragmentFile)
			require.NotEmpty(t, got.sshdBinary)
			require.NotEmpty(t, got.reloads)
			require.Equal(t, reload, got.reloads[0][0].name)
		})
	}
}

func TestWindowsDefaultsToAccountNameAndRejectsHashedPrincipals(t *testing.T) {
	env := &sshdEnvironment{
		goos: "windows",
		getenv: func(name string) string {
			if name == "ProgramData" {
				return `C:\ProgramData`
			}
			return ""
		},
		executable: func() (string, error) { return `C:\epithet.exe`, nil },
	}
	settings, err := (&HostEnrollCLI{}).resolveSSHDSettings(env)
	require.NoError(t, err)
	require.Equal(t, accountNamePrincipalMode, settings.principalMode)

	_, err = (&HostEnrollCLI{PrincipalMode: principal.SchemeV1}).resolveSSHDSettings(env)
	require.ErrorContains(t, err, "not supported by Windows OpenSSH")
}

func TestUnknownPlatformAcceptsCompleteOverrides(t *testing.T) {
	env := &sshdEnvironment{
		goos:       "unsupported-os",
		getenv:     func(string) string { return "" },
		executable: func() (string, error) { return "/opt/epithet", nil },
	}
	cmd := &HostEnrollCLI{
		SSHDConfigFile:                  "/opt/ssh/sshd_config",
		SSHDFragmentFile:                "/opt/ssh/sshd_config.d/60-epithet.conf",
		SSHDBinary:                      "/opt/ssh/sbin/sshd",
		EpithetBinary:                   "/opt/epithet",
		AuthorizedPrincipalsCommandUser: "nobody",
		ReloadCommand:                   "/opt/ssh/reload",
	}
	settings, err := cmd.resolveSSHDSettings(env)
	require.NoError(t, err)
	require.Equal(t, "/opt/ssh/sshd_config", settings.configFile)
	require.Equal(t, "/opt/ssh/reload", settings.reloadCandidates[0][0].name)
}

func TestRenderSSHDFragmentDestinationBound(t *testing.T) {
	settings := &sshdSettings{
		epithetBinary: "/opt/Epithet Bin/epithet",
		principalMode: principal.SchemeV1,
		commandUser:   "nobody",
	}
	got, err := renderSSHDFragment(settings, "/var/lib/epithet/domain", "/var/lib/epithet/epithet-ca.pub", "linux")
	require.NoError(t, err)
	require.Equal(t, `# Managed by epithet host enroll. DO NOT EDIT.
# principal-mode: epithet-principal-v1
# domain-file: "/var/lib/epithet/domain"
# ca-pubkey-file: "/var/lib/epithet/epithet-ca.pub"
TrustedUserCAKeys "/var/lib/epithet/epithet-ca.pub"
AuthorizedPrincipalsCommand /opt/Epithet\ Bin/epithet host authorized-principals --domain-file "/var/lib/epithet/domain" %u
AuthorizedPrincipalsCommandUser nobody
`, string(got))
	commandLine := strings.Split(string(got), "\n")[5]
	require.True(t, strings.HasPrefix(commandLine, "AuthorizedPrincipalsCommand /"),
		"OpenSSH requires the command value itself to begin with an absolute path")
}

func TestRenderSSHDFragmentAccountNameOmitsPrincipalCommand(t *testing.T) {
	settings := &sshdSettings{principalMode: accountNamePrincipalMode}
	got, err := renderSSHDFragment(settings, "/state/domain", "/state/epithet-ca.pub", "linux")
	require.NoError(t, err)
	require.Contains(t, string(got), "TrustedUserCAKeys")
	require.NotContains(t, string(got), "AuthorizedPrincipalsCommand")
}

func TestRenderSSHDFragmentEscapesPercentTokensInPaths(t *testing.T) {
	settings := &sshdSettings{
		epithetBinary: "/opt/%d/epithet",
		principalMode: principal.SchemeV1,
		commandUser:   "nobody",
	}
	got, err := renderSSHDFragment(settings, "/state/%h/domain", "/state/epithet-ca.pub", "linux")
	require.NoError(t, err)
	require.Contains(t, string(got), `/opt/%%d/epithet`)
	require.Contains(t, string(got), `"/state/%%h/domain" %u`)
}

func TestEscapeSSHDCommandPathRejectsNonAbsolutePath(t *testing.T) {
	_, err := escapeSSHDCommandPath("usr/local/bin/epithet")
	require.ErrorContains(t, err, "not an absolute path")
}

func TestRenderManagedSSHDMainIsIdempotent(t *testing.T) {
	original := []byte("Port 22\nPermitRootLogin no\n")
	first, err := renderManagedSSHDMain(original, "/etc/ssh/sshd_config.d/60-epithet.conf", "linux")
	require.NoError(t, err)
	second, err := renderManagedSSHDMain(first, "/etc/ssh/sshd_config.d/60-epithet.conf", "linux")
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.True(t, strings.HasPrefix(string(first), sshdMainBegin+"\nInclude "))
	require.Contains(t, string(first), string(original))
}

func TestAdoptExistingSSHDEnrollmentRecoversDurableChoices(t *testing.T) {
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "ssh", "sshd_config")
	fragmentPath := filepath.Join(dir, "custom", "epithet.conf")
	domainPath := filepath.Join(dir, "identity", "domain")
	caKeyPath := filepath.Join(dir, "trust", "epithet-ca.pub")
	require.NoError(t, os.MkdirAll(filepath.Dir(mainPath), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(fragmentPath), 0o755))
	mainConfig, err := renderManagedSSHDMain([]byte("Port 22\n"), fragmentPath, "linux")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(mainPath, mainConfig, 0o600))
	fragment, err := renderSSHDFragment(&sshdSettings{
		epithetBinary: "/opt/epithet",
		principalMode: principal.SchemeV1,
		commandUser:   "nobody",
	}, domainPath, caKeyPath, "linux")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(fragmentPath, fragment, 0o644))

	cmd := &HostEnrollCLI{SSHDConfigFile: mainPath}
	env := &sshdEnvironment{goos: "linux", getenv: func(string) string { return "" }}
	require.NoError(t, cmd.adoptExistingSSHDEnrollment(env))
	require.Equal(t, fragmentPath, cmd.SSHDFragmentFile)
	require.Equal(t, domainPath, cmd.DomainFile)
	require.Equal(t, caKeyPath, cmd.CAPubkeyFile)
	require.Equal(t, principal.SchemeV1, cmd.PrincipalMode)
}

func TestAdoptExistingSSHDEnrollmentKeepsExplicitIdentityOverrideTogether(t *testing.T) {
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "ssh", "sshd_config")
	fragmentPath := filepath.Join(dir, "ssh", "epithet.conf")
	require.NoError(t, os.MkdirAll(filepath.Dir(mainPath), 0o755))
	mainConfig, err := renderManagedSSHDMain([]byte("Port 22\n"), fragmentPath, "linux")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(mainPath, mainConfig, 0o600))
	fragment, err := renderSSHDFragment(&sshdSettings{principalMode: accountNamePrincipalMode}, "/old/domain", "/old/epithet-ca.pub", "linux")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(fragmentPath, fragment, 0o644))

	cmd := &HostEnrollCLI{SSHDConfigFile: mainPath, DomainFile: "/new/domain"}
	env := &sshdEnvironment{goos: "linux", getenv: func(string) string { return "" }}
	require.NoError(t, cmd.adoptExistingSSHDEnrollment(env))
	require.Equal(t, "/new/domain", cmd.DomainFile)
	require.Empty(t, cmd.CAPubkeyFile, "a new explicit domain file must use its own default CA-key path")
	require.Equal(t, accountNamePrincipalMode, cmd.PrincipalMode)
}

func TestConfigureSSHDInstallsValidCandidateAndIsIdempotent(t *testing.T) {
	cmd, enrollment, env, runner, mainPath, fragmentPath := newSSHDConfigurationTest(t)

	require.NoError(t, cmd.configureSSHD(context.Background(), enrollment, env))
	require.Len(t, runner.calls, 4)
	require.Equal(t, "/test/sshd", runner.calls[0].name)
	resolvedMainPath, err := filepath.EvalSymlinks(mainPath)
	require.NoError(t, err)
	require.Equal(t, []string{"-t", "-f", resolvedMainPath}, runner.calls[0].args)
	require.Equal(t, "/test/reload", runner.calls[3].name)
	require.Equal(t, []string{"reload", "sshd"}, runner.calls[3].args)

	main, err := os.ReadFile(mainPath)
	require.NoError(t, err)
	require.Contains(t, string(main), `Include "`+fragmentPath+`"`)
	require.Contains(t, string(main), "Port 22\n")
	fragment, err := os.ReadFile(fragmentPath)
	require.NoError(t, err)
	require.Contains(t, string(fragment), "TrustedUserCAKeys")
	require.Contains(t, string(fragment), "AuthorizedPrincipalsCommand")
	requireFileMode(t, mainPath, 0o600)
	requireFileMode(t, fragmentPath, 0o644)

	secondRunner := &recordingSSHDRunner{}
	env.runner = secondRunner
	require.NoError(t, cmd.configureSSHD(context.Background(), enrollment, env))
	require.Len(t, secondRunner.calls, 1, "unchanged valid configuration must not be reloaded")
}

func TestConfigureSSHDRejectsCandidateWithoutChangingFiles(t *testing.T) {
	cmd, enrollment, env, runner, mainPath, fragmentPath := newSSHDConfigurationTest(t)
	runner.run = func(call int, _ string, _ []string) ([]byte, error) {
		if call == 2 {
			return []byte("bad candidate"), errors.New("exit status 1")
		}
		return nil, nil
	}

	err := cmd.configureSSHD(context.Background(), enrollment, env)
	require.ErrorContains(t, err, "candidate sshd configuration is invalid")
	requireFileContents(t, mainPath, "Port 22\n")
	_, statErr := os.Stat(fragmentPath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestConfigureSSHDRollsBackFailedInstalledValidation(t *testing.T) {
	cmd, enrollment, env, runner, mainPath, fragmentPath := newSSHDConfigurationTest(t)
	runner.run = func(call int, _ string, _ []string) ([]byte, error) {
		if call == 3 {
			return []byte("installed config failed"), errors.New("exit status 1")
		}
		return nil, nil
	}

	err := cmd.configureSSHD(context.Background(), enrollment, env)
	require.ErrorContains(t, err, "installed sshd configuration is invalid")
	requireFileContents(t, mainPath, "Port 22\n")
	_, statErr := os.Stat(fragmentPath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestConfigureSSHDRollsBackAndReloadsAfterReloadFailure(t *testing.T) {
	cmd, enrollment, env, runner, mainPath, fragmentPath := newSSHDConfigurationTest(t)
	reloadCalls := 0
	runner.run = func(_ int, name string, _ []string) ([]byte, error) {
		if name == "/test/reload" {
			reloadCalls++
			if reloadCalls == 1 {
				return []byte("reload failed"), errors.New("exit status 1")
			}
		}
		return nil, nil
	}

	err := cmd.configureSSHD(context.Background(), enrollment, env)
	require.ErrorContains(t, err, "reloading sshd with enrolled configuration")
	require.Equal(t, 2, reloadCalls, "the restored configuration must be reloaded")
	requireFileContents(t, mainPath, "Port 22\n")
	_, statErr := os.Stat(fragmentPath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestConfigureSSHDRefusesUnmanagedFragment(t *testing.T) {
	cmd, enrollment, env, runner, mainPath, fragmentPath := newSSHDConfigurationTest(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(fragmentPath), 0o755))
	require.NoError(t, os.WriteFile(fragmentPath, []byte("# belongs to the operator\n"), 0o644))

	err := cmd.configureSSHD(context.Background(), enrollment, env)
	require.ErrorContains(t, err, "is not managed by Epithet")
	require.Empty(t, runner.calls)
	requireFileContents(t, mainPath, "Port 22\n")
	requireFileContents(t, fragmentPath, "# belongs to the operator\n")
}

func newSSHDConfigurationTest(t *testing.T) (*HostEnrollCLI, *hostEnrollment, *sshdEnvironment, *recordingSSHDRunner, string, string) {
	t.Helper()
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
	cmd := &HostEnrollCLI{
		PrincipalMode:                   principal.SchemeV1,
		SSHDConfigFile:                  mainPath,
		SSHDFragmentFile:                fragmentPath,
		SSHDBinary:                      "/test/sshd",
		EpithetBinary:                   "/test/epithet",
		AuthorizedPrincipalsCommandUser: "nobody",
		ReloadCommand:                   "/test/reload",
		ReloadArgs:                      []string{"reload", "sshd"},
	}
	enrollment := &hostEnrollment{
		DomainFile:   filepath.Join(dir, "state", "domain"),
		CAPubkeyFile: filepath.Join(dir, "state", "epithet-ca.pub"),
	}
	return cmd, enrollment, env, runner, mainPath, fragmentPath
}

func requireFileContents(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, want, string(got))
}
