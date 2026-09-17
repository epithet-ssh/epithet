package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/epithet-ssh/epithet/pkg/principal"
	"github.com/stretchr/testify/require"
)

func TestRenderManagedSSHDMainReusesGlobalIncludes(t *testing.T) {
	// Keep even relative patterns away from the machine's real drop-ins.
	includeDir := "/etc/ssh/epithet-test-" + filepath.Base(t.TempDir())
	fragment := includeDir + "/60-epithet.conf"
	for _, tc := range []struct {
		name, config string
		covered      bool
	}{
		{"wildcard", "Include /etc/ssh/sshd_config.d/*.conf\n", true},
		{"quoted and case insensitive", "  iNcLuDe \"/etc/ssh/sshd_config.d/*.conf\" # drop-ins\n", true},
		{"relative", "Include sshd_config.d/*.conf\n", true},
		{"multiple paths", "Include /nonexistent/*.conf /etc/ssh/sshd_config.d/*.conf\n", true},
		{"explicit", "Include /etc/ssh/sshd_config.d/60-epithet.conf\n", true},
		{"commented", "# Include /etc/ssh/sshd_config.d/*.conf\n", false},
		{"conditional", "Match User alice\n Include /etc/ssh/sshd_config.d/*.conf\n", false},
		{"match all", "Match all\nInclude /etc/ssh/sshd_config.d/*.conf\n", false},
		{"different glob", "Include /etc/ssh/sshd_config.d/10-*.conf\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.config = strings.ReplaceAll(tc.config, "sshd_config.d", filepath.Base(includeDir))
			got, err := renderManagedSSHDMain([]byte(tc.config), fragment, "linux")
			require.NoError(t, err)
			if tc.covered {
				require.Equal(t, tc.config, string(got))
			} else {
				require.True(t, strings.HasPrefix(string(got), sshdMainBegin))
				require.True(t, strings.HasSuffix(string(got), tc.config))
			}
		})
	}
}

func TestGlobalSSHDIncludesNestedScope(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested.conf")
	fragment := filepath.Join(dir, "drop ins", "60-epithet.conf")
	for _, tc := range []struct {
		name, nested, main string
		covered            bool
	}{
		{"nested global", fmt.Sprintf("Include %q\n", filepath.Join(filepath.Dir(fragment), "*.conf")), fmt.Sprintf("Include %q\n", nested), true},
		{"nested conditional", fmt.Sprintf("Match User alice\nInclude %q\n", filepath.Join(filepath.Dir(fragment), "*.conf")), fmt.Sprintf("Include %q\n", nested), false},
		{"scope restored", "Match User alice\n", fmt.Sprintf("Include %q\nInclude %q\n", nested, filepath.Join(filepath.Dir(fragment), "*.conf")), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(nested, []byte(tc.nested), 0o600))
			got, err := renderManagedSSHDMain([]byte(tc.main), fragment, "linux")
			require.NoError(t, err)
			require.Equal(t, tc.covered, string(got) == tc.main)
		})
	}
	require.NoError(t, os.WriteFile(nested, []byte(fmt.Sprintf("Include %q\n", nested)), 0o600))
	_, err := renderManagedSSHDMain([]byte(fmt.Sprintf("Include %q\n", nested)), fragment, "linux")
	require.ErrorContains(t, err, "nesting")
}

func TestConfigureSSHDReusesIncludeAndRecoversEnrollment(t *testing.T) {
	cmd, enrollment, env, runner, mainPath, fragmentPath := newSSHDConfigurationTest(t)
	original := fmt.Sprintf("# Drop-ins\nInclude %q\nPort 22\n", filepath.Join(filepath.Dir(fragmentPath), "*.conf"))
	// Simulate an existing enrollment with the formerly unconditional block.
	oldMain, err := prependSSHDEnrollmentInclude([]byte(original), fragmentPath, "linux")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(mainPath, oldMain, 0o600))
	require.NoError(t, configureSSHD(context.Background(), enrollment, mustSSHDSettings(t, cmd, env), env))
	requireFileContents(t, mainPath, original)

	rerun := &HostEnrollCLI{SSHDConfigFile: mainPath}
	require.NoError(t, rerun.adoptExistingSSHDEnrollment(env))
	require.Equal(t, fragmentPath, rerun.SSHDFragmentFile)
	require.Equal(t, enrollment.DomainFile, rerun.DomainFile)
	require.Equal(t, enrollment.CAPubkeyFile, rerun.CAPubkeyFile)
	require.Equal(t, principal.SchemeV1, rerun.PrincipalMode)

	runner.calls = nil
	require.NoError(t, configureSSHD(context.Background(), enrollment, mustSSHDSettings(t, cmd, env), env))
	require.Len(t, runner.calls, 2)
	requireFileContents(t, mainPath, original)
}

func TestConfigureSSHDConflictRollsBackBeforeReload(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) {
			cmd, enrollment, env, runner, mainPath, fragmentPath := newSSHDConfigurationTest(t)
			original := fmt.Sprintf("TrustedUserCAKeys /other/ca.pub\nInclude %q\n", filepath.Join(filepath.Dir(fragmentPath), "*.conf"))
			require.NoError(t, os.WriteFile(mainPath, []byte(original), 0o600))
			var oldFragment []byte
			if existing {
				var err error
				oldFragment, err = renderSSHDFragment(mustSSHDSettings(t, cmd, env), "/old/domain", "/old/ca.pub", "linux")
				require.NoError(t, err)
				require.NoError(t, os.MkdirAll(filepath.Dir(fragmentPath), 0o755))
				require.NoError(t, os.WriteFile(fragmentPath, oldFragment, 0o644))
			}
			err := configureSSHD(context.Background(), enrollment, mustSSHDSettings(t, cmd, env), env)
			require.ErrorContains(t, err, "sshd enrollment conflict: effective trustedusercakeys")
			requireFileContents(t, mainPath, original)
			if existing {
				requireFileContents(t, fragmentPath, string(oldFragment))
			} else {
				_, err = os.Stat(fragmentPath)
				require.ErrorIs(t, err, os.ErrNotExist)
			}
			for _, call := range runner.calls {
				require.NotEqual(t, "/test/reload", call.name)
			}
		})
	}
}

func TestSSHDEnrollmentWithOpenSSH(t *testing.T) {
	binary, err := exec.LookPath("sshd")
	if err != nil {
		t.Skip("sshd is not installed")
	}
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	key := filepath.Join(t.TempDir(), "hostkey")
	output, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput()
	require.NoError(t, err, "%s", output)
	for _, conflict := range []string{"", "TrustedUserCAKeys /other/ca.pub", "AuthorizedPrincipalsCommand /other/helper\nAuthorizedPrincipalsCommandUser nobody", "AuthorizedPrincipalsCommandUser root"} {
		t.Run(conflict, func(t *testing.T) {
			cmd, enrollment, env, runner, mainPath, fragmentPath := newSSHDConfigurationTest(t)
			cmd.SSHDBinary = binary
			// Real paths with spaces exercise quoting in both Include and -T output.
			cmd.SSHDFragmentFile = filepath.Join(filepath.Dir(fragmentPath), "drop ins", "60-epithet.conf")
			cmd.EpithetBinary = "/opt/Epithet Bin/epithet"
			enrollment.DomainFile = filepath.Join(filepath.Dir(mainPath), "state dir", "domain")
			enrollment.CAPubkeyFile = filepath.Join(filepath.Dir(mainPath), "state dir", "ca.pub")
			dropins := filepath.Dir(cmd.SSHDFragmentFile)
			require.NoError(t, os.MkdirAll(dropins, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(dropins, "10-existing.conf"), []byte(conflict+"\n"), 0o644))
			original := fmt.Sprintf("Include %q\n", filepath.Join(dropins, "*.conf"))
			require.NoError(t, os.WriteFile(mainPath, []byte(original), 0o600))
			reloads := 0
			runner.run = func(_ int, name string, args []string) ([]byte, error) {
				if name == "/test/reload" {
					reloads++
					return nil, nil
				}
				return exec.Command(name, append(args, "-h", key)...).CombinedOutput()
			}
			err := configureSSHD(context.Background(), enrollment, mustSSHDSettings(t, cmd, env), env)
			if conflict == "" {
				require.NoError(t, err)
				require.Equal(t, 1, reloads)
			} else {
				require.ErrorContains(t, err, "sshd enrollment conflict")
				require.Zero(t, reloads)
			}
			requireFileContents(t, mainPath, original)
		})
	}
}
