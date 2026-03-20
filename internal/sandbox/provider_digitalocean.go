package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// DigitalOceanProvider implements Provider by shelling out to the doctl CLI.
type DigitalOceanProvider struct {
	SSHKey string
	Size   string
	// StateDir is the .hal directory path, needed to look up the droplet IP
	// from sandbox state for SSH connections.
	StateDir string

	// cmdContext builds an *exec.Cmd. Defaults to exec.CommandContext.
	// Override in tests to capture args without running the real CLI.
	cmdContext func(ctx context.Context, name string, args ...string) *exec.Cmd

	// lookPath checks whether a binary exists on PATH. Defaults to exec.LookPath.
	// Override in tests to avoid environment-dependent PATH lookups.
	lookPath func(file string) (string, error)
}

// commandContext returns the configured command builder, defaulting to
// exec.CommandContext.
func (d *DigitalOceanProvider) commandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	if d.cmdContext != nil {
		return d.cmdContext(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...)
}

// ensureDoctl checks that doctl is available on PATH.
func (d *DigitalOceanProvider) ensureDoctl() error {
	lookPath := exec.LookPath
	if d.lookPath != nil {
		lookPath = d.lookPath
	}
	if _, err := lookPath("doctl"); err != nil {
		return fmt.Errorf("doctl not found: install from https://docs.digitalocean.com/reference/doctl/how-to/install/ and run 'doctl auth init'")
	}
	return nil
}

// wrapDoctlError wraps a doctl command error with stderr output.
func wrapDoctlError(op string, err error, stderr string) error {
	if exitErr, ok := err.(*exec.ExitError); ok {
		msg := strings.TrimSpace(stderr)
		if msg != "" {
			return fmt.Errorf("doctl %s failed with exit code %d: %s: %w", op, exitErr.ExitCode(), msg, err)
		}
		return fmt.Errorf("doctl %s failed with exit code %d: %w", op, exitErr.ExitCode(), err)
	}
	return fmt.Errorf("doctl %s failed: %w", op, err)
}

// generateDOCloudInit creates a cloud-init YAML that writes env vars to
// /root/.env (quoted, safe for special chars), then runs setup.sh to bootstrap
// the full dev environment.
func generateDOCloudInit(env map[string]string) string {
	var b strings.Builder
	b.WriteString("#cloud-config\n")
	b.WriteString("write_files:\n")
	b.WriteString("  - path: /root/.env\n")
	b.WriteString("    permissions: \"0600\"\n")
	b.WriteString("    content: |\n")

	// Sort keys for deterministic output
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		b.WriteString(fmt.Sprintf("      %s=%q\n", k, env[k]))
	}

	b.WriteString("runcmd:\n")
	b.WriteString("  - |\n")
	b.WriteString("    set -a\n")
	b.WriteString("    . /root/.env\n")
	b.WriteString("    set +a\n")
	b.WriteString("    curl -fsSL https://raw.githubusercontent.com/jywlabs/hal/main/sandbox/setup.sh | bash\n")
	b.WriteString("  - |\n")
	b.WriteString("    if [ -n \"${TAILSCALE_AUTHKEY:-}\" ]; then\n")
	b.WriteString("      tailscaled --tun=userspace-networking --statedir=/var/lib/tailscale &\n")
	b.WriteString("      sleep 3\n")
	b.WriteString("      tailscale up --authkey=\"$TAILSCALE_AUTHKEY\" --ssh --hostname=\"${TAILSCALE_HOSTNAME:-hal-sandbox}\"\n")
	b.WriteString("    fi\n")

	return b.String()
}

// buildDOCreateArgs constructs the argument list for doctl compute droplet create.
// The env map is used to generate a cloud-init file; the returned args reference
// the given userDataFile path.
func buildDOCreateArgs(name, size, sshKey, userDataFile string) []string {
	return []string{
		"compute", "droplet", "create", name,
		"--size", size,
		"--image", "ubuntu-24-04-x64",
		"--ssh-keys", sshKey,
		"--user-data-file", userDataFile,
		"--wait",
	}
}

func parseDODropletInfo(output string) (id string, ip string) {
	fields := strings.Fields(strings.TrimSpace(output))
	switch len(fields) {
	case 0:
		return "", ""
	case 1:
		return fields[0], ""
	default:
		return fields[0], fields[1]
	}
}

func isNumericDropletID(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func (d *DigitalOceanProvider) resolveDropletTarget(name string) string {
	target := strings.TrimSpace(name)
	if target == "" || isNumericDropletID(target) || strings.TrimSpace(d.StateDir) == "" {
		return target
	}

	state, err := LoadState(d.StateDir)
	if err != nil {
		return target
	}
	if state.Provider != "digitalocean" || strings.TrimSpace(state.WorkspaceID) == "" {
		return target
	}
	if state.Name != target {
		return target
	}
	return strings.TrimSpace(state.WorkspaceID)
}

func (d *DigitalOceanProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*SandboxResult, error) {
	if err := d.ensureDoctl(); err != nil {
		return nil, err
	}

	// Generate cloud-init user-data file
	cloudInit := generateDOCloudInit(env)
	tmpFile, err := os.CreateTemp("", "hal-do-cloud-init-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud-init temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(cloudInit); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("failed to write cloud-init: %w", err)
	}
	tmpFile.Close()

	// Run doctl compute droplet create
	args := buildDOCreateArgs(name, d.Size, d.SSHKey, tmpFile.Name())
	createCmd := d.commandContext(ctx, "doctl", args...)
	var stderrBuf bytes.Buffer
	createCmd.Stdout = out
	createCmd.Stderr = io.MultiWriter(out, &stderrBuf)

	if err := createCmd.Run(); err != nil {
		return nil, wrapDoctlError("compute droplet create", err, stderrBuf.String())
	}

	// Get droplet ID and public IP for persisted state + follow-up lifecycle ops.
	ipCmd := d.commandContext(ctx, "doctl", "compute", "droplet", "get", name,
		"--format", "ID,PublicIPv4",
		"--no-header",
	)
	var ipBuf bytes.Buffer
	var ipStderr bytes.Buffer
	ipCmd.Stdout = &ipBuf
	ipCmd.Stderr = io.MultiWriter(out, &ipStderr)

	if err := ipCmd.Run(); err != nil {
		return nil, wrapDoctlError("compute droplet get", err, ipStderr.String())
	}

	id, ip := parseDODropletInfo(ipBuf.String())
	if strings.TrimSpace(ip) == "" {
		return nil, fmt.Errorf("doctl compute droplet get returned no PublicIPv4 for %q", name)
	}
	return &SandboxResult{ID: id, Name: name, IP: ip}, nil
}

func (d *DigitalOceanProvider) Stop(ctx context.Context, name string, out io.Writer) error {
	if err := d.ensureDoctl(); err != nil {
		return err
	}

	target := d.resolveDropletTarget(name)
	cmd := d.commandContext(ctx, "doctl", "compute", "droplet-action", "shutdown", target)
	var stderrBuf bytes.Buffer
	cmd.Stdout = out
	cmd.Stderr = io.MultiWriter(out, &stderrBuf)

	if err := cmd.Run(); err != nil {
		return wrapDoctlError("compute droplet-action shutdown", err, stderrBuf.String())
	}
	return nil
}

func (d *DigitalOceanProvider) Delete(ctx context.Context, name string, out io.Writer) error {
	if err := d.ensureDoctl(); err != nil {
		return err
	}

	target := d.resolveDropletTarget(name)
	cmd := d.commandContext(ctx, "doctl", "compute", "droplet", "delete", target, "--force")
	var stderrBuf bytes.Buffer
	cmd.Stdout = out
	cmd.Stderr = io.MultiWriter(out, &stderrBuf)

	if err := cmd.Run(); err != nil {
		return wrapDoctlError("compute droplet delete", err, stderrBuf.String())
	}
	return nil
}

func (d *DigitalOceanProvider) Status(ctx context.Context, name string, out io.Writer) error {
	if err := d.ensureDoctl(); err != nil {
		return err
	}

	target := d.resolveDropletTarget(name)
	cmd := d.commandContext(ctx, "doctl", "compute", "droplet", "get", target,
		"--format", "ID,Name,Status,PublicIPv4",
	)
	var stderrBuf bytes.Buffer
	cmd.Stdout = out
	cmd.Stderr = io.MultiWriter(out, &stderrBuf)

	if err := cmd.Run(); err != nil {
		return wrapDoctlError("compute droplet get", err, stderrBuf.String())
	}
	return nil
}

func (d *DigitalOceanProvider) SSH(name string) (*exec.Cmd, error) {
	if err := d.ensureDoctl(); err != nil {
		return nil, err
	}

	state, err := LoadState(d.StateDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load sandbox state: %w", err)
	}
	if state.IP == "" {
		return nil, fmt.Errorf("no IP address found in sandbox state for %q", name)
	}

	cmd := exec.Command("ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"root@"+state.IP,
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func (d *DigitalOceanProvider) Exec(name string, args []string) (*exec.Cmd, error) {
	if err := d.ensureDoctl(); err != nil {
		return nil, err
	}

	state, err := LoadState(d.StateDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load sandbox state: %w", err)
	}
	if state.IP == "" {
		return nil, fmt.Errorf("no IP address found in sandbox state for %q", name)
	}

	cmdArgs := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"root@" + state.IP,
		"--",
	}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("ssh", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}
