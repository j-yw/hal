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
	"time"
)

// HetznerProvider implements Provider by shelling out to the hcloud CLI and ssh.
type HetznerProvider struct {
	SSHKey            string
	ServerType        string
	Image             string
	TailscaleLockdown bool

	// cmdContext builds an *exec.Cmd. Defaults to exec.CommandContext.
	// Override in tests to capture args without running the real CLI.
	cmdContext func(ctx context.Context, name string, args ...string) *exec.Cmd

	// sshContext builds SSH commands for post-create tailscale IP lookup.
	sshContext func(ctx context.Context, name string, args ...string) *exec.Cmd

	// sleep delays between tailscale IP lookup retries.
	sleep func(time.Duration)
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
func generateCloudInit(env map[string]string, tailscaleLockdown bool) string {
	envContent := buildHetznerEnvFileContent(withLockdownEnv(env, tailscaleLockdown))
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

	// Install and configure Tailscale FIRST (before setup.sh which takes minutes).
	// hal polls for /root/.tailscale-ip via SSH, so this must complete quickly.
	// NOTE: do NOT enable UFW here — hal needs public IP SSH access to read the file.
	// Lockdown is applied by hal after it reads the Tailscale IP.
	b.WriteString("runcmd:\n")
	b.WriteString("  - |\n")
	b.WriteString("    set -a\n")
	b.WriteString("    . /root/.env\n")
	b.WriteString("    set +a\n")
	b.WriteString("    if [ -n \"${TAILSCALE_AUTHKEY:-}\" ]; then\n")
	b.WriteString("      curl -fsSL https://tailscale.com/install.sh | sh\n")
	b.WriteString("      tailscaled --tun=userspace-networking --statedir=/var/lib/tailscale &\n")
	b.WriteString("      sleep 3\n")
	b.WriteString("      tailscale up --authkey=\"$TAILSCALE_AUTHKEY\" --ssh --hostname=\"${TAILSCALE_HOSTNAME:-hal-sandbox}\"\n")
	b.WriteString("      tailscale ip -4 > /root/.tailscale-ip\n")
	b.WriteString("    fi\n")
	b.WriteString("  - |\n")
	b.WriteString("    set -a\n")
	b.WriteString("    . /root/.env\n")
	b.WriteString("    set +a\n")
	b.WriteString("    curl -fsSL https://raw.githubusercontent.com/j-yw/hal/main/sandbox/setup.sh | bash\n")

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

	safeOut := synchronizedWriter(out)

	// Generate cloud-init user-data file
	cloudInit := generateCloudInit(env, h.TailscaleLockdown)
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
	createCmd.Stdout = safeOut
	createCmd.Stderr = safeOut

	if err := createCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("hcloud server create failed with exit code %d: %w", exitErr.ExitCode(), err)
		}
		return nil, fmt.Errorf("hcloud server create failed: %w", err)
	}

	// Server exists on Hetzner from this point — clean up on any failure.
	cleanupServer := func(reason string) {
		fmt.Fprintf(safeOut, "Cleaning up %s after failure (%s)...\n", name, reason)
		delCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		delCmd := h.commandContext(delCtx, "hcloud", "server", "delete", name)
		delCmd.Stdout = io.Discard
		delCmd.Stderr = io.Discard
		if delErr := delCmd.Run(); delErr != nil {
			fmt.Fprintf(safeOut, "Warning: failed to clean up server %s: %v (delete manually with: hcloud server delete %s)\n", name, delErr, name)
		} else {
			fmt.Fprintf(safeOut, "Cleaned up server %s\n", name)
		}
	}

	// Get the server IP
	ipCmd := h.commandContext(ctx, "hcloud", "server", "ip", name)
	var ipBuf bytes.Buffer
	ipCmd.Stdout = &ipBuf
	ipCmd.Stderr = safeOut

	if err := ipCmd.Run(); err != nil {
		cleanupServer("failed to get server IP")
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("hcloud server ip failed with exit code %d: %w", exitErr.ExitCode(), err)
		}
		return nil, fmt.Errorf("hcloud server ip failed: %w", err)
	}

	ip := strings.TrimSpace(ipBuf.String())
	result := &SandboxResult{Name: name, IP: ip}
	if h.TailscaleLockdown {
		if ip == "" {
			cleanupServer("missing public IP for tailscale")
			return nil, fmt.Errorf("failed to fetch tailscale IP in lockdown mode: missing public IP")
		}
		fmt.Fprintf(safeOut, "Waiting for Tailscale on %s (cloud-init may take a few minutes)...\n", name)
		tailscaleIP, err := fetchTailscaleIPWithProgress(ctx, "root", ip, h.sshContext, h.sleep, 18, 10*time.Second, safeOut)
		if err != nil {
			cleanupServer("tailscale IP unavailable")
			return nil, fmt.Errorf("failed to fetch tailscale IP in lockdown mode: %w", err)
		}
		result.TailscaleIP = tailscaleIP

		// Apply firewall lockdown AFTER reading the Tailscale IP.
		fmt.Fprintf(safeOut, "Applying firewall lockdown on %s...\n", name)
		lockdownScript := "ufw allow in on tailscale0 && ufw allow in on tailscale0 proto udp to any port 60000:61000 && ufw deny 22/tcp && ufw --force enable"
		sshFn := h.sshContext
		if sshFn == nil {
			sshFn = exec.CommandContext
		}
		sshCmd := sshFn(ctx, "ssh",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "ConnectTimeout=10",
			fmt.Sprintf("root@%s", ip),
			lockdownScript,
		)
		var lockStderr bytes.Buffer
		sshCmd.Stdout = safeOut
		sshCmd.Stderr = &lockStderr
		if err := sshCmd.Run(); err != nil {
			fmt.Fprintf(safeOut, "Warning: firewall lockdown failed on %s: %v (apply manually)\n", name, err)
		}
	}
	return result, nil
}

func (h *HetznerProvider) Stop(ctx context.Context, info *ConnectInfo, out io.Writer) error {
	name := ""
	if info != nil {
		name = strings.TrimSpace(info.Name)
	}
	if name == "" {
		return fmt.Errorf("sandbox name is required")
	}

	safeOut := synchronizedWriter(out)
	cmd := h.commandContext(ctx, "hcloud", "server", "shutdown", name)
	cmd.Stdout = safeOut
	cmd.Stderr = safeOut
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("hcloud server shutdown failed with exit code %d: %w", exitErr.ExitCode(), err)
		}
		return fmt.Errorf("hcloud server shutdown failed: %w", err)
	}
	return nil
}

func (h *HetznerProvider) Delete(ctx context.Context, info *ConnectInfo, out io.Writer) error {
	name := ""
	if info != nil {
		name = strings.TrimSpace(info.Name)
	}
	if name == "" {
		return fmt.Errorf("sandbox name is required")
	}

	safeOut := synchronizedWriter(out)
	cmd := h.commandContext(ctx, "hcloud", "server", "delete", name)
	cmd.Stdout = safeOut
	cmd.Stderr = safeOut
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("hcloud server delete failed with exit code %d: %w", exitErr.ExitCode(), err)
		}
		return fmt.Errorf("hcloud server delete failed: %w", err)
	}
	return nil
}

func (h *HetznerProvider) SSH(info *ConnectInfo) (*exec.Cmd, error) {
	ip := ""
	if info != nil {
		ip = strings.TrimSpace(info.IP)
	}
	if ip == "" {
		return nil, fmt.Errorf("sandbox IP is required")
	}

	cmd := exec.Command("ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"root@"+ip,
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func (h *HetznerProvider) Exec(info *ConnectInfo, args []string) (*exec.Cmd, error) {
	ip := ""
	if info != nil {
		ip = strings.TrimSpace(info.IP)
	}
	if ip == "" {
		return nil, fmt.Errorf("sandbox IP is required")
	}

	cmdArgs := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"root@" + ip,
		"--",
	}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("ssh", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func (h *HetznerProvider) Status(ctx context.Context, info *ConnectInfo, out io.Writer) error {
	name := ""
	if info != nil {
		name = strings.TrimSpace(info.Name)
	}
	if name == "" {
		return fmt.Errorf("sandbox name is required")
	}

	safeOut := synchronizedWriter(out)
	cmd := h.commandContext(ctx, "hcloud", "server", "describe", name)
	cmd.Stdout = safeOut
	cmd.Stderr = safeOut
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("hcloud server describe failed with exit code %d: %w", exitErr.ExitCode(), err)
		}
		return fmt.Errorf("hcloud server describe failed: %w", err)
	}
	return nil
}
