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

// LightsailProvider implements Provider by shelling out to the aws lightsail CLI.
type LightsailProvider struct {
	Region            string
	AvailabilityZone  string
	Bundle            string
	KeyPairName       string
	TailscaleLockdown bool
	// StateDir is the .hal directory path, needed to look up the instance IP
	// from sandbox state for SSH connections.
	StateDir string

	// cmdContext builds an *exec.Cmd. Defaults to exec.CommandContext.
	// Override in tests to capture args without running the real CLI.
	cmdContext func(ctx context.Context, name string, args ...string) *exec.Cmd

	// sshContext builds SSH commands for post-create tailscale IP lookup.
	sshContext func(ctx context.Context, name string, args ...string) *exec.Cmd

	// sleep delays between tailscale IP lookup retries.
	sleep func(time.Duration)

	// lookPath checks whether a binary exists on PATH. Defaults to exec.LookPath.
	lookPath func(file string) (string, error)
}

func (l *LightsailProvider) commandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	if l.cmdContext != nil {
		return l.cmdContext(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...)
}

func (l *LightsailProvider) ensureAWS() error {
	lookPath := exec.LookPath
	if l.lookPath != nil {
		lookPath = l.lookPath
	}
	if _, err := lookPath("aws"); err != nil {
		return fmt.Errorf("aws CLI not found: install with 'brew install awscli' and run 'aws configure'")
	}
	return nil
}

func wrapAWSError(op string, err error, stderr string) error {
	if exitErr, ok := err.(*exec.ExitError); ok {
		msg := strings.TrimSpace(stderr)
		if msg != "" {
			return fmt.Errorf("aws lightsail %s failed with exit code %d: %s: %w", op, exitErr.ExitCode(), msg, err)
		}
		return fmt.Errorf("aws lightsail %s failed with exit code %d: %w", op, exitErr.ExitCode(), err)
	}
	return fmt.Errorf("aws lightsail %s failed: %w", op, err)
}

// generateLightsailCloudInit creates a cloud-init YAML that writes env vars to
// /root/.env (base64-encoded to avoid YAML special char issues), then runs setup.sh.
func generateLightsailCloudInit(env map[string]string, tailscaleLockdown bool) string {
	envContent := buildLightsailEnvFileContent(withLockdownEnv(env, tailscaleLockdown))
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
	b.WriteString("      tailscale ip -4 > /root/.tailscale-ip\n")
	b.WriteString("      if [ \"$TAILSCALE_LOCKDOWN\" = \"true\" ]; then\n")
	b.WriteString("        ufw allow in on tailscale0\n")
	b.WriteString("        ufw allow in on tailscale0 proto udp to any port 60000:61000\n")
	b.WriteString("        ufw deny 22/tcp\n")
	b.WriteString("        ufw --force enable\n")
	b.WriteString("      fi\n")
	b.WriteString("    fi\n")

	return b.String()
}

func buildLightsailEnvFileContent(env map[string]string) string {
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

func buildLightsailCreateArgs(name, az, bundle, keyPair, userDataFile string) []string {
	return []string{
		"lightsail", "create-instances",
		"--instance-names", name,
		"--availability-zone", az,
		"--blueprint-id", "ubuntu_22_04",
		"--bundle-id", bundle,
		"--key-pair-name", keyPair,
		"--user-data-file", userDataFile,
	}
}

func (l *LightsailProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*SandboxResult, error) {
	if err := l.ensureAWS(); err != nil {
		return nil, err
	}

	az := l.AvailabilityZone
	if az == "" {
		region := l.Region
		if region == "" {
			region = "us-east-1"
		}
		az = region + "a"
	}

	bundle := l.Bundle
	if bundle == "" {
		bundle = "small_3_0"
	}

	// Generate cloud-init
	cloudInit := generateLightsailCloudInit(env, l.TailscaleLockdown)
	tmpFile, err := os.CreateTemp("", "hal-lightsail-cloud-init-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud-init temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(cloudInit); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("failed to write cloud-init: %w", err)
	}
	tmpFile.Close()

	// Create instance
	args := buildLightsailCreateArgs(name, az, bundle, l.KeyPairName, tmpFile.Name())
	createCmd := l.commandContext(ctx, "aws", args...)
	var stderrBuf bytes.Buffer
	createCmd.Stdout = out
	createCmd.Stderr = io.MultiWriter(out, &stderrBuf)

	if err := createCmd.Run(); err != nil {
		return nil, wrapAWSError("create-instances", err, stderrBuf.String())
	}

	// Poll for running state and public IP (Lightsail doesn't have --wait)
	var ip string
	for i := 0; i < 30; i++ {
		ipCmd := l.commandContext(ctx, "aws",
			"lightsail", "get-instance",
			"--instance-name", name,
			"--query", "instance.publicIpAddress",
			"--output", "text",
		)
		var ipBuf bytes.Buffer
		var ipStderr bytes.Buffer
		ipCmd.Stdout = &ipBuf
		ipCmd.Stderr = &ipStderr

		if err := ipCmd.Run(); err == nil {
			candidate := strings.TrimSpace(ipBuf.String())
			if candidate != "" && candidate != "None" && candidate != "null" {
				ip = candidate
				break
			}
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out waiting for instance %q to get a public IP", name)
		case <-time.After(5 * time.Second):
		}
	}

	if ip == "" {
		return nil, fmt.Errorf("instance %q created but no public IP assigned after polling", name)
	}

	fmt.Fprintf(out, "Instance %s ready at %s\n", name, ip)
	result := &SandboxResult{ID: name, Name: name, IP: ip}
	if l.TailscaleLockdown {
		tailscaleIP, err := fetchTailscaleIP(ctx, "ubuntu", ip, l.sshContext, l.sleep, 9, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch tailscale IP in lockdown mode: %w", err)
		}
		result.TailscaleIP = tailscaleIP
	}
	return result, nil
}

func (l *LightsailProvider) Stop(ctx context.Context, name string, out io.Writer) error {
	if err := l.ensureAWS(); err != nil {
		return err
	}

	cmd := l.commandContext(ctx, "aws", "lightsail", "stop-instance", "--instance-name", name)
	var stderrBuf bytes.Buffer
	cmd.Stdout = out
	cmd.Stderr = io.MultiWriter(out, &stderrBuf)

	if err := cmd.Run(); err != nil {
		return wrapAWSError("stop-instance", err, stderrBuf.String())
	}
	return nil
}

func (l *LightsailProvider) Delete(ctx context.Context, name string, out io.Writer) error {
	if err := l.ensureAWS(); err != nil {
		return err
	}

	cmd := l.commandContext(ctx, "aws", "lightsail", "delete-instance",
		"--instance-name", name,
		"--force-delete-add-ons",
	)
	var stderrBuf bytes.Buffer
	cmd.Stdout = out
	cmd.Stderr = io.MultiWriter(out, &stderrBuf)

	if err := cmd.Run(); err != nil {
		return wrapAWSError("delete-instance", err, stderrBuf.String())
	}
	return nil
}

func (l *LightsailProvider) Status(ctx context.Context, name string, out io.Writer) error {
	if err := l.ensureAWS(); err != nil {
		return err
	}

	cmd := l.commandContext(ctx, "aws", "lightsail", "get-instance",
		"--instance-name", name,
		"--query", "instance.{Name:name,State:state.name,IP:publicIpAddress,Blueprint:blueprintId,Bundle:bundleId}",
		"--output", "table",
	)
	var stderrBuf bytes.Buffer
	cmd.Stdout = out
	cmd.Stderr = io.MultiWriter(out, &stderrBuf)

	if err := cmd.Run(); err != nil {
		return wrapAWSError("get-instance", err, stderrBuf.String())
	}
	return nil
}

func (l *LightsailProvider) SSH(name string) (*exec.Cmd, error) {
	state, err := LoadState(l.StateDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load sandbox state: %w", err)
	}
	ip := preferredIP(state)
	if ip == "" {
		return nil, fmt.Errorf("no IP address found in sandbox state for %q", name)
	}

	// Lightsail Ubuntu instances use the 'ubuntu' user
	cmd := exec.Command("ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"ubuntu@"+ip,
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func (l *LightsailProvider) Exec(name string, args []string) (*exec.Cmd, error) {
	state, err := LoadState(l.StateDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load sandbox state: %w", err)
	}
	ip := preferredIP(state)
	if ip == "" {
		return nil, fmt.Errorf("no IP address found in sandbox state for %q", name)
	}

	cmdArgs := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"ubuntu@" + ip,
		"--",
	}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("ssh", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}
