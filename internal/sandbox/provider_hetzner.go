package sandbox

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// HetznerProvider implements Provider by shelling out to the hcloud CLI and ssh.
type HetznerProvider struct {
	SSHKey     string
	ServerType string
	Image      string
	// StateDir is the .hal directory path, needed to look up the server IP
	// from sandbox state for SSH connections.
	StateDir string

	// cmdContext builds an *exec.Cmd. Defaults to exec.CommandContext.
	// Override in tests to capture args without running the real CLI.
	cmdContext func(ctx context.Context, name string, args ...string) *exec.Cmd
}

// commandContext returns the configured command builder, defaulting to
// exec.CommandContext.
func (h *HetznerProvider) commandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	if h.cmdContext != nil {
		return h.cmdContext(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...)
}

// generateCloudInit creates a cloud-init YAML that writes env vars to
// /root/.env (base64-encoded to avoid YAML special char issues), then runs
// setup.sh to bootstrap the full dev environment.
func generateCloudInit(env map[string]string) string {
	envContent := buildHetznerEnvFileContent(env)
	encoded := base64.StdEncoding.EncodeToString([]byte(envContent))

	var b strings.Builder
	b.WriteString("#cloud-config\n")
	b.WriteString("write_files:\n")
	b.WriteString("  - path: /root/.env\n")
	b.WriteString("    permissions: \"0600\"\n")
	b.WriteString("    encoding: b64\n")
	b.WriteString("    content: ")
	b.WriteString(encoded)
	b.WriteString("\n")

	b.WriteString("runcmd:\n")
	b.WriteString("  - |\n")
	b.WriteString("    set -a\n")
	b.WriteString("    . /root/.env\n")
	b.WriteString("    set +a\n")
	b.WriteString("    curl -fsSL https://raw.githubusercontent.com/jywlabs/hal/main/sandbox/setup.sh | bash\n")
	b.WriteString("  - |\n")
	b.WriteString("    set -a\n")
	b.WriteString("    . /root/.env\n")
	b.WriteString("    set +a\n")
	b.WriteString("    if [ -n \"${TAILSCALE_AUTHKEY:-}\" ]; then\n")
	b.WriteString("      tailscaled --tun=userspace-networking --statedir=/var/lib/tailscale &\n")
	b.WriteString("      sleep 3\n")
	b.WriteString("      tailscale up --authkey=\"$TAILSCALE_AUTHKEY\" --ssh --hostname=\"${TAILSCALE_HOSTNAME:-hal-sandbox}\"\n")
	b.WriteString("    fi\n")

	return b.String()
}

func buildHetznerEnvFileContent(env map[string]string) string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		escaped := strings.ReplaceAll(env[k], "'", "'\\''")
		b.WriteString(fmt.Sprintf("%s='%s'\n", k, escaped))
	}
	return b.String()
}

func (h *HetznerProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*SandboxResult, error) {
	if strings.TrimSpace(h.Image) == "" {
		return nil, fmt.Errorf("hetzner image is required; run `hal sandbox setup` to configure sandbox.hetzner.image")
	}

	// Generate cloud-init user-data file
	cloudInit := generateCloudInit(env)
	tmpFile, err := os.CreateTemp("", "hal-cloud-init-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud-init temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(cloudInit); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("failed to write cloud-init: %w", err)
	}
	tmpFile.Close()

	// Run hcloud server create
	createCmd := h.commandContext(ctx, "hcloud", "server", "create",
		"--name", name,
		"--type", h.ServerType,
		"--image", h.Image,
		"--ssh-key", h.SSHKey,
		"--user-data-file", tmpFile.Name(),
	)
	createCmd.Stdout = out
	createCmd.Stderr = out

	if err := createCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("hcloud server create failed with exit code %d: %w", exitErr.ExitCode(), err)
		}
		return nil, fmt.Errorf("hcloud server create failed: %w", err)
	}

	// Get the server IP
	ipCmd := h.commandContext(ctx, "hcloud", "server", "ip", name)
	var ipBuf bytes.Buffer
	ipCmd.Stdout = &ipBuf
	ipCmd.Stderr = out

	if err := ipCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("hcloud server ip failed with exit code %d: %w", exitErr.ExitCode(), err)
		}
		return nil, fmt.Errorf("hcloud server ip failed: %w", err)
	}

	ip := strings.TrimSpace(ipBuf.String())
	return &SandboxResult{Name: name, IP: ip}, nil
}

func (h *HetznerProvider) Stop(ctx context.Context, name string, out io.Writer) error {
	cmd := h.commandContext(ctx, "hcloud", "server", "shutdown", name)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("hcloud server shutdown failed with exit code %d: %w", exitErr.ExitCode(), err)
		}
		return fmt.Errorf("hcloud server shutdown failed: %w", err)
	}
	return nil
}

func (h *HetznerProvider) Delete(ctx context.Context, name string, out io.Writer) error {
	cmd := h.commandContext(ctx, "hcloud", "server", "delete", name)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("hcloud server delete failed with exit code %d: %w", exitErr.ExitCode(), err)
		}
		return fmt.Errorf("hcloud server delete failed: %w", err)
	}
	return nil
}

func (h *HetznerProvider) SSH(name string) (*exec.Cmd, error) {
	state, err := LoadState(h.StateDir)
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

func (h *HetznerProvider) Exec(name string, args []string) (*exec.Cmd, error) {
	state, err := LoadState(h.StateDir)
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

func (h *HetznerProvider) Status(ctx context.Context, name string, out io.Writer) error {
	cmd := h.commandContext(ctx, "hcloud", "server", "describe", name)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("hcloud server describe failed with exit code %d: %w", exitErr.ExitCode(), err)
		}
		return fmt.Errorf("hcloud server describe failed: %w", err)
	}
	return nil
}
