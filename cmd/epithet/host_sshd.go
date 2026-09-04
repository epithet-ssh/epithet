package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/epithet-ssh/epithet/pkg/principal"
)

const (
	accountNamePrincipalMode = "account-name"
	sshdFragmentHeader       = "# Managed by epithet host enroll. DO NOT EDIT."
	sshdMainBegin            = "# BEGIN epithet host enrollment"
	sshdMainEnd              = "# END epithet host enrollment"
)

type sshdEnrollmentMetadata struct {
	principalMode string
	domainFile    string
	caPubkeyFile  string
}

type sshdCommandRunner interface {
	CombinedOutput(context.Context, string, ...string) ([]byte, error)
}

type execSSHDCommandRunner struct{}

func (execSSHDCommandRunner) CombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type sshdEnvironment struct {
	goos           string
	getenv         func(string) string
	executable     func() (string, error)
	runner         sshdCommandRunner
	validateAccess func(string, string, string, string, bool) error
}

func newSystemSSHDEnvironment() *sshdEnvironment {
	return &sshdEnvironment{
		goos:           runtime.GOOS,
		getenv:         os.Getenv,
		executable:     os.Executable,
		runner:         execSSHDCommandRunner{},
		validateAccess: validateAuthorizedPrincipalsAccess,
	}
}

type sshdSettings struct {
	configFile       string
	fragmentFile     string
	sshdBinary       string
	epithetBinary    string
	principalMode    string
	commandUser      string
	reloadCandidates []sshdCommandSequence
}

type sshdCommand struct {
	name string
	args []string
}

type sshdCommandSequence []sshdCommand

type sshdPlatformDefaults struct {
	configFile   string
	fragmentFile string
	sshdBinary   string
	reloads      []sshdCommandSequence
}

func platformSSHDDefaults(goos string, getenv func(string) string) sshdPlatformDefaults {
	unix := sshdPlatformDefaults{
		configFile:   "/etc/ssh/sshd_config",
		fragmentFile: "/etc/ssh/sshd_config.d/60-epithet.conf",
		sshdBinary:   "/usr/sbin/sshd",
	}
	switch goos {
	case "linux":
		unix.reloads = []sshdCommandSequence{
			{{name: "systemctl", args: []string{"reload", "sshd"}}},
			{{name: "systemctl", args: []string{"reload", "ssh"}}},
			{{name: "service", args: []string{"sshd", "reload"}}},
			{{name: "service", args: []string{"ssh", "reload"}}},
		}
		return unix
	case "dragonfly", "freebsd":
		unix.reloads = []sshdCommandSequence{
			{{name: "service", args: []string{"sshd", "reload"}}},
			{{name: "/etc/rc.d/sshd", args: []string{"reload"}}},
		}
		return unix
	case "openbsd":
		unix.reloads = []sshdCommandSequence{
			{{name: "rcctl", args: []string{"reload", "sshd"}}},
		}
		return unix
	case "netbsd":
		unix.reloads = []sshdCommandSequence{
			{{name: "/etc/rc.d/sshd", args: []string{"reload"}}},
			{{name: "service", args: []string{"sshd", "reload"}}},
		}
		return unix
	case "darwin":
		unix.reloads = []sshdCommandSequence{
			{{name: "launchctl", args: []string{"kickstart", "-k", "system/com.openssh.sshd"}}},
		}
		return unix
	case "illumos", "solaris":
		unix.sshdBinary = "/usr/lib/ssh/sshd"
		unix.reloads = []sshdCommandSequence{
			{{name: "svcadm", args: []string{"restart", "svc:/network/ssh:default"}}},
		}
		return unix
	case "aix":
		unix.reloads = []sshdCommandSequence{
			{{name: "refresh", args: []string{"-s", "sshd"}}},
		}
		return unix
	case "windows":
		programData := getenv("ProgramData")
		if programData == "" {
			return sshdPlatformDefaults{}
		}
		sshDir := filepath.Join(programData, "ssh")
		systemRoot := getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = `C:\Windows`
		}
		return sshdPlatformDefaults{
			configFile:   filepath.Join(sshDir, "sshd_config"),
			fragmentFile: filepath.Join(sshDir, "sshd_config.d", "60-epithet.conf"),
			sshdBinary:   filepath.Join(systemRoot, "System32", "OpenSSH", "sshd.exe"),
			reloads: []sshdCommandSequence{{{
				name: "powershell.exe",
				args: []string{"-NoProfile", "-NonInteractive", "-Command", "Restart-Service -Name sshd -ErrorAction Stop"},
			}}},
		}
	default:
		return sshdPlatformDefaults{}
	}
}

func (c *HostEnrollCLI) resolveSSHDSettings(env *sshdEnvironment) (*sshdSettings, error) {
	defaults := platformSSHDDefaults(env.goos, env.getenv)

	configFile, err := resolveEnrollmentPath(c.SSHDConfigFile, defaults.configFile, "sshd configuration file")
	if err != nil {
		return nil, err
	}
	fragmentFile, err := resolveEnrollmentPath(c.SSHDFragmentFile, defaults.fragmentFile, "sshd fragment file")
	if err != nil {
		return nil, err
	}
	sshdBinary, err := resolveEnrollmentPath(c.SSHDBinary, defaults.sshdBinary, "sshd binary")
	if err != nil {
		return nil, err
	}

	epithetBinary := c.EpithetBinary
	if epithetBinary == "" {
		epithetBinary, err = env.executable()
		if err != nil {
			return nil, fmt.Errorf("resolving epithet executable: %w", err)
		}
	}
	epithetBinary, err = absoluteExpandedPath(epithetBinary)
	if err != nil {
		return nil, fmt.Errorf("resolving epithet executable: %w", err)
	}

	mode := c.PrincipalMode
	if mode == "" {
		if env.goos == "windows" {
			mode = accountNamePrincipalMode
		} else {
			mode = principal.SchemeV1
		}
	}
	if mode != principal.SchemeV1 && mode != accountNamePrincipalMode {
		return nil, fmt.Errorf("unknown principal mode %q", mode)
	}
	if env.goos == "windows" && mode == principal.SchemeV1 {
		return nil, fmt.Errorf("principal mode %q is not supported by Windows OpenSSH; use %q", mode, accountNamePrincipalMode)
	}
	if mode == principal.SchemeV1 {
		if err := validateSSHDValue(c.AuthorizedPrincipalsCommandUser); err != nil {
			return nil, fmt.Errorf("invalid authorized-principals-command-user: %w", err)
		}
	}

	reloads := defaults.reloads
	if c.ReloadCommand != "" {
		reloads = []sshdCommandSequence{{{
			name: c.ReloadCommand,
			args: append([]string(nil), c.ReloadArgs...),
		}}}
	} else if len(c.ReloadArgs) != 0 {
		return nil, fmt.Errorf("reload-arg requires reload-command")
	}
	if len(reloads) == 0 {
		return nil, fmt.Errorf("no default sshd reload command for %s; use --reload-command and repeat --reload-arg for its arguments", env.goos)
	}

	return &sshdSettings{
		configFile:       configFile,
		fragmentFile:     fragmentFile,
		sshdBinary:       sshdBinary,
		epithetBinary:    epithetBinary,
		principalMode:    mode,
		commandUser:      c.AuthorizedPrincipalsCommandUser,
		reloadCandidates: reloads,
	}, nil
}

func resolveEnrollmentPath(override, fallback, description string) (string, error) {
	path := override
	if path == "" {
		path = fallback
	}
	if path == "" {
		return "", fmt.Errorf("no default %s for this platform; provide an explicit override", description)
	}
	resolved, err := absoluteExpandedPath(path)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", description, err)
	}
	return resolved, nil
}

func absoluteExpandedPath(path string) (string, error) {
	path, err := expandPath(path)
	if err != nil {
		return "", err
	}
	return filepath.Abs(path)
}

// adoptExistingSSHDEnrollment recovers the durable enrollment choices recorded
// in an existing Epithet-managed sshd fragment. This must run before paths() so
// that a CA-URL-only rerun does not create a second principal domain at a platform
// default path.
func (c *HostEnrollCLI) adoptExistingSSHDEnrollment(env *sshdEnvironment) error {
	defaults := platformSSHDDefaults(env.goos, env.getenv)
	configFile, err := resolveEnrollmentPath(c.SSHDConfigFile, defaults.configFile, "sshd configuration file")
	if err != nil {
		return err
	}
	configFile, err = filepath.EvalSymlinks(configFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("resolving sshd configuration file %s: %w", configFile, err)
	}
	mainConfig, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("reading %s: %w", configFile, err)
	}
	fragmentFile, managed, err := managedSSHDFragmentPath(mainConfig)
	if err != nil {
		return fmt.Errorf("reading Epithet enrollment from %s: %w", configFile, err)
	}
	if !managed {
		return nil
	}
	fragmentSnapshot, err := snapshotSSHDFile(fragmentFile, true)
	if err != nil {
		return err
	}
	metadata, err := parseSSHDEnrollmentMetadata(fragmentSnapshot.data)
	if err != nil {
		return fmt.Errorf("reading Epithet enrollment from %s: %w", fragmentFile, err)
	}

	if c.SSHDFragmentFile == "" {
		c.SSHDFragmentFile = fragmentFile
	}
	if c.DomainFile == "" {
		c.DomainFile = metadata.domainFile
		if c.CAPubkeyFile == "" {
			c.CAPubkeyFile = metadata.caPubkeyFile
		}
	}
	if c.PrincipalMode == "" {
		c.PrincipalMode = metadata.principalMode
	}
	return nil
}

func (c *HostEnrollCLI) configureSSHD(ctx context.Context, enrollment *hostEnrollment, env *sshdEnvironment) error {
	settings, err := c.resolveSSHDSettings(env)
	if err != nil {
		return err
	}
	settings.configFile, err = filepath.EvalSymlinks(settings.configFile)
	if err != nil {
		return fmt.Errorf("resolving sshd configuration file %s: %w", settings.configFile, err)
	}
	domainPath, err := absoluteExpandedPath(enrollment.DomainFile)
	if err != nil {
		return fmt.Errorf("resolving enrolled principal-domain path: %w", err)
	}
	caKeyPath, err := absoluteExpandedPath(enrollment.CAPubkeyFile)
	if err != nil {
		return fmt.Errorf("resolving enrolled CA public-key path: %w", err)
	}
	if env.validateAccess != nil {
		if err := env.validateAccess(
			settings.epithetBinary,
			domainPath,
			caKeyPath,
			settings.commandUser,
			settings.principalMode == principal.SchemeV1,
		); err != nil {
			return err
		}
	}

	fragment, err := renderSSHDFragment(settings, domainPath, caKeyPath, env.goos)
	if err != nil {
		return err
	}
	mainSnapshot, err := snapshotSSHDFile(settings.configFile, true)
	if err != nil {
		return err
	}
	fragmentSnapshot, err := snapshotSSHDFile(settings.fragmentFile, false)
	if err != nil {
		return err
	}
	if fragmentSnapshot.exists && !bytes.HasPrefix(fragmentSnapshot.data, []byte(sshdFragmentHeader+"\n")) {
		return fmt.Errorf("sshd fragment %s already exists and is not managed by Epithet", settings.fragmentFile)
	}

	mainConfig, err := renderManagedSSHDMain(mainSnapshot.data, settings.fragmentFile, env.goos)
	if err != nil {
		return fmt.Errorf("updating %s: %w", settings.configFile, err)
	}
	mainChanged := !bytes.Equal(mainSnapshot.data, mainConfig)
	fragmentChanged := !fragmentSnapshot.exists || !bytes.Equal(fragmentSnapshot.data, fragment)

	// Establish that rollback returns to a valid configuration before touching
	// either managed file.
	if err := validateSSHD(ctx, env.runner, settings.sshdBinary, settings.configFile); err != nil {
		return fmt.Errorf("existing sshd configuration is invalid: %w", err)
	}
	if !mainChanged && !fragmentChanged {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(settings.fragmentFile), 0o755); err != nil {
		return fmt.Errorf("creating sshd fragment directory: %w", err)
	}
	tempFragment, err := writeSSHDTemp(settings.fragmentFile, fragment, 0o644)
	if err != nil {
		return err
	}
	defer os.Remove(tempFragment)
	validationMain, err := renderManagedSSHDMain(mainSnapshot.data, tempFragment, env.goos)
	if err != nil {
		return err
	}
	tempMain, err := writeSSHDTemp(settings.configFile, validationMain, mainSnapshot.mode)
	if err != nil {
		return err
	}
	defer os.Remove(tempMain)
	if err := validateSSHD(ctx, env.runner, settings.sshdBinary, tempMain); err != nil {
		return fmt.Errorf("candidate sshd configuration is invalid: %w", err)
	}

	if fragmentChanged {
		if err := replaceSSHDFile(settings.fragmentFile, fragment, 0o644); err != nil {
			return err
		}
	}
	if mainChanged {
		if err := replaceSSHDFile(settings.configFile, mainConfig, mainSnapshot.mode); err != nil {
			rollbackErr := restoreSSHDFile(fragmentSnapshot)
			return errors.Join(err, rollbackErr)
		}
	}

	rollback := func() error {
		return errors.Join(restoreSSHDFile(mainSnapshot), restoreSSHDFile(fragmentSnapshot))
	}
	if err := validateSSHD(ctx, env.runner, settings.sshdBinary, settings.configFile); err != nil {
		return errors.Join(fmt.Errorf("installed sshd configuration is invalid: %w", err), rollback())
	}
	if err := reloadSSHD(ctx, env.runner, settings.reloadCandidates); err != nil {
		restoreErr := rollback()
		primary := fmt.Errorf("reloading sshd with enrolled configuration: %w", err)
		if restoreErr != nil {
			return errors.Join(primary, fmt.Errorf("restoring prior sshd files: %w", restoreErr))
		}
		if validateErr := validateSSHD(ctx, env.runner, settings.sshdBinary, settings.configFile); validateErr != nil {
			return errors.Join(primary, fmt.Errorf("validating restored sshd configuration: %w", validateErr))
		}
		if reloadErr := reloadSSHD(ctx, env.runner, settings.reloadCandidates); reloadErr != nil {
			return errors.Join(primary, fmt.Errorf("reloading restored sshd configuration: %w", reloadErr))
		}
		return primary
	}
	return nil
}

func renderSSHDFragment(settings *sshdSettings, domainPath, caKeyPath, goos string) ([]byte, error) {
	domainMetadata, err := quoteSSHDToken(normalizeSSHDPath(domainPath, goos))
	if err != nil {
		return nil, fmt.Errorf("rendering principal-domain metadata: %w", err)
	}
	caToken, err := quoteSSHDToken(normalizeSSHDPath(caKeyPath, goos))
	if err != nil {
		return nil, fmt.Errorf("rendering CA public-key path: %w", err)
	}
	var b strings.Builder
	fmt.Fprintln(&b, sshdFragmentHeader)
	fmt.Fprintf(&b, "# principal-mode: %s\n", settings.principalMode)
	fmt.Fprintf(&b, "# domain-file: %s\n", domainMetadata)
	fmt.Fprintf(&b, "# ca-pubkey-file: %s\n", caToken)
	fmt.Fprintf(&b, "TrustedUserCAKeys %s\n", caToken)
	if settings.principalMode == principal.SchemeV1 {
		binaryToken, err := escapeSSHDCommandPath(escapeSSHDPercent(normalizeSSHDPath(settings.epithetBinary, goos)))
		if err != nil {
			return nil, fmt.Errorf("rendering epithet executable path: %w", err)
		}
		domainToken, err := quoteSSHDToken(escapeSSHDPercent(normalizeSSHDPath(domainPath, goos)))
		if err != nil {
			return nil, fmt.Errorf("rendering principal-domain path: %w", err)
		}
		fmt.Fprintf(&b, "AuthorizedPrincipalsCommand %s host authorized-principals --domain-file %s %%u\n", binaryToken, domainToken)
		fmt.Fprintf(&b, "AuthorizedPrincipalsCommandUser %s\n", settings.commandUser)
	}
	return []byte(b.String()), nil
}

func managedSSHDFragmentPath(config []byte) (string, bool, error) {
	if _, err := stripManagedSSHDMain(config); err != nil {
		return "", false, err
	}
	begin := sshdMainBegin + "\n"
	if !strings.HasPrefix(string(config), begin) {
		return "", false, nil
	}
	endAt := strings.Index(string(config[len(begin):]), sshdMainEnd+"\n")
	if endAt < 0 {
		return "", false, fmt.Errorf("Epithet managed block has no end marker")
	}
	body := string(config[len(begin) : len(begin)+endAt])
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "Include ") {
		return "", false, fmt.Errorf("Epithet managed block does not contain exactly one Include directive")
	}
	path, err := strconv.Unquote(strings.TrimPrefix(lines[0], "Include "))
	if err != nil || path == "" || !filepath.IsAbs(path) {
		return "", false, fmt.Errorf("Epithet managed Include path is invalid")
	}
	return path, true, nil
}

func parseSSHDEnrollmentMetadata(fragment []byte) (sshdEnrollmentMetadata, error) {
	lines := strings.Split(string(fragment), "\n")
	if len(lines) < 4 || lines[0] != sshdFragmentHeader {
		return sshdEnrollmentMetadata{}, fmt.Errorf("fragment is not managed by Epithet")
	}
	mode, ok := strings.CutPrefix(lines[1], "# principal-mode: ")
	if !ok || (mode != principal.SchemeV1 && mode != accountNamePrincipalMode) {
		return sshdEnrollmentMetadata{}, fmt.Errorf("fragment has invalid principal-mode metadata")
	}
	domainFile, err := parseSSHDMetadataPath(lines[2], "# domain-file: ")
	if err != nil {
		return sshdEnrollmentMetadata{}, err
	}
	caPubkeyFile, err := parseSSHDMetadataPath(lines[3], "# ca-pubkey-file: ")
	if err != nil {
		return sshdEnrollmentMetadata{}, err
	}
	return sshdEnrollmentMetadata{
		principalMode: mode,
		domainFile:    domainFile,
		caPubkeyFile:  caPubkeyFile,
	}, nil
}

func parseSSHDMetadataPath(line, prefix string) (string, error) {
	value, ok := strings.CutPrefix(line, prefix)
	if !ok {
		return "", fmt.Errorf("fragment is missing %s metadata", strings.TrimSuffix(strings.TrimPrefix(prefix, "# "), ": "))
	}
	path, err := strconv.Unquote(value)
	if err != nil || path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("fragment has invalid %s metadata", strings.TrimSuffix(strings.TrimPrefix(prefix, "# "), ": "))
	}
	return path, nil
}

func normalizeSSHDPath(path, goos string) string {
	if goos == "windows" {
		return filepath.ToSlash(path)
	}
	return path
}

func escapeSSHDPercent(value string) string {
	return strings.ReplaceAll(value, "%", "%%")
}

// escapeSSHDCommandPath leaves the leading slash visible because OpenSSH
// validates AuthorizedPrincipalsCommand as an absolute path before it splits
// the command into arguments. Quoting the entire path would make the first
// character a quote and fail validation. Backslash escapes preserve paths that
// contain spaces or other sshd_config token delimiters.
func escapeSSHDCommandPath(value string) (string, error) {
	if !strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("command is not an absolute path")
	}
	var b strings.Builder
	for _, r := range value {
		if r < ' ' || r == 0x7f {
			return "", fmt.Errorf("value contains a control character")
		}
		if r == ' ' || r == '\\' || r == '\'' || r == '"' || r == '#' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String(), nil
}

func validateSSHDValue(value string) error {
	if value == "" {
		return fmt.Errorf("value is empty")
	}
	for _, r := range value {
		if r <= ' ' || r == 0x7f || r == '"' || r == '\\' || r == '#' {
			return fmt.Errorf("value contains whitespace, control characters, or sshd_config metacharacters")
		}
	}
	return nil
}

func quoteSSHDToken(value string) (string, error) {
	for _, r := range value {
		if r < ' ' || r == 0x7f {
			return "", fmt.Errorf("value contains a control character")
		}
	}
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`, nil
}

func renderManagedSSHDMain(original []byte, fragmentPath, goos string) ([]byte, error) {
	base, err := stripManagedSSHDMain(original)
	if err != nil {
		return nil, err
	}
	token, err := quoteSSHDToken(normalizeSSHDPath(fragmentPath, goos))
	if err != nil {
		return nil, err
	}
	block := sshdMainBegin + "\nInclude " + token + "\n" + sshdMainEnd + "\n\n"
	return append([]byte(block), base...), nil
}

func stripManagedSSHDMain(config []byte) ([]byte, error) {
	begin := []byte(sshdMainBegin + "\n")
	end := []byte(sshdMainEnd + "\n")
	if !bytes.HasPrefix(config, begin) {
		if bytes.Contains(config, []byte(sshdMainBegin)) || bytes.Contains(config, []byte(sshdMainEnd)) {
			return nil, fmt.Errorf("found malformed or misplaced Epithet managed block")
		}
		return append([]byte(nil), config...), nil
	}
	endAt := bytes.Index(config[len(begin):], end)
	if endAt < 0 {
		return nil, fmt.Errorf("Epithet managed block has no end marker")
	}
	after := config[len(begin)+endAt+len(end):]
	if bytes.HasPrefix(after, []byte("\n")) {
		after = after[1:]
	}
	if bytes.Contains(after, []byte(sshdMainBegin)) || bytes.Contains(after, []byte(sshdMainEnd)) {
		return nil, fmt.Errorf("found more than one Epithet managed block")
	}
	return append([]byte(nil), after...), nil
}

type sshdFileSnapshot struct {
	path   string
	exists bool
	data   []byte
	mode   os.FileMode
}

func snapshotSSHDFile(path string, required bool) (sshdFileSnapshot, error) {
	linkInfo, err := os.Lstat(path)
	if err == nil && linkInfo.Mode()&os.ModeSymlink != 0 {
		return sshdFileSnapshot{}, fmt.Errorf("managed sshd file %s must not be a symbolic link", path)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return sshdFileSnapshot{}, fmt.Errorf("statting %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && !required {
		return sshdFileSnapshot{path: path, mode: 0o644}, nil
	}
	if err != nil {
		return sshdFileSnapshot{}, fmt.Errorf("reading %s: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return sshdFileSnapshot{}, fmt.Errorf("statting %s: %w", path, err)
	}
	return sshdFileSnapshot{path: path, exists: true, data: data, mode: info.Mode().Perm()}, nil
}

func writeSSHDTemp(target string, data []byte, mode os.FileMode) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(target), ".epithet-sshd-*")
	if err != nil {
		return "", fmt.Errorf("creating temporary sshd configuration beside %s: %w", target, err)
	}
	path := f.Name()
	remove := true
	defer func() {
		_ = f.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		return "", fmt.Errorf("setting permissions on %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("syncing %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("closing %s: %w", path, err)
	}
	remove = false
	return path, nil
}

func replaceSSHDFile(path string, data []byte, mode os.FileMode) error {
	temp, err := writeSSHDTemp(path, data, mode)
	if err != nil {
		return err
	}
	defer os.Remove(temp)
	if err := os.Rename(temp, path); err != nil {
		return fmt.Errorf("installing sshd configuration %s: %w", path, err)
	}
	if err := syncEnrollmentDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("syncing sshd configuration directory %s: %w", filepath.Dir(path), err)
	}
	return nil
}

func restoreSSHDFile(snapshot sshdFileSnapshot) error {
	if snapshot.exists {
		if err := replaceSSHDFile(snapshot.path, snapshot.data, snapshot.mode); err != nil {
			return fmt.Errorf("restoring %s: %w", snapshot.path, err)
		}
		return nil
	}
	if err := os.Remove(snapshot.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing newly installed %s: %w", snapshot.path, err)
	}
	return syncEnrollmentDirectory(filepath.Dir(snapshot.path))
}

func validateSSHD(ctx context.Context, runner sshdCommandRunner, binary, config string) error {
	output, err := runner.CombinedOutput(ctx, binary, "-t", "-f", config)
	if err != nil {
		return commandFailure(binary, []string{"-t", "-f", config}, output, err)
	}
	return nil
}

func reloadSSHD(ctx context.Context, runner sshdCommandRunner, candidates []sshdCommandSequence) error {
	var failures []error
	for _, sequence := range candidates {
		failed := false
		for _, command := range sequence {
			output, err := runner.CombinedOutput(ctx, command.name, command.args...)
			if err != nil {
				failures = append(failures, commandFailure(command.name, command.args, output, err))
				failed = true
				break
			}
		}
		if !failed {
			return nil
		}
	}
	return errors.Join(failures...)
}

func commandFailure(name string, args []string, output []byte, err error) error {
	message := strings.TrimSpace(string(output))
	if message == "" {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, message)
}
