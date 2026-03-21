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

// generateLightsailCloudInit creates a shell script that writes env vars to
// /root/.env (base64-encoded), then runs setup.sh and optionally configures Tailscale.
// NOTE: Lightsail wraps user-data inside its own #!/bin/sh startup script, so
// cloud-config YAML does NOT work. We must provide a plain shell script instead.
func generateLightsailCloudInit(env map[string]string, tailscaleLockdown bool) string {
	envContent := buildLightsailEnvFileContent(withLockdownEnv(env, tailscaleLockdown))
	encoded := base64.StdEncoding.EncodeToString([]byte(envContent))

	var b strings.Builder
	// Write env file from base64
	b.WriteString("echo '")
	b.WriteString(encoded)
	b.WriteString("' | base64 -d > /root/.env\n")
	b.WriteString("chmod 600 /root/.env\n")

	// Source env vars
	b.WriteString("set -a\n")
	b.WriteString(". /root/.env\n")
	b.WriteString("set +a\n")

	// Install and configure Tailscale FIRST (before setup.sh which takes minutes).
	// hal polls for /root/.tailscale-ip via SSH, so this must complete quickly.
	// NOTE: do NOT enable UFW here — hal needs public IP SSH access to read the file.
	// Lockdown is applied by hal after it reads the Tailscale IP.
	b.WriteString("if [ -n \"${TAILSCALE_AUTHKEY:-}\" ]; then\n")
	b.WriteString("  curl -fsSL https://tailscale.com/install.sh | sh\n")
	b.WriteString("  tailscaled --tun=userspace-networking --statedir=/var/lib/tailscale &\n")
	b.WriteString("  sleep 3\n")
	b.WriteString("  tailscale up --authkey=\"$TAILSCALE_AUTHKEY\" --ssh --hostname=\"${TAILSCALE_HOSTNAME:-hal-sandbox}\"\n")
	b.WriteString("  tailscale ip -4 > /root/.tailscale-ip\n")
	b.WriteString("fi\n")

	// Run full setup (system packages, Node.js, Go, etc.) — this takes a while
	b.WriteString("curl -fsSL https://raw.githubusercontent.com/j-yw/hal/main/sandbox/setup.sh | bash\n")

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

func buildLightsailCreateArgs(name, az, bundle, keyPair, userDataFilePath string) []string {
	return []string{
		"lightsail", "create-instances",
		"--instance-names", name,
		"--availability-zone", az,
		"--blueprint-id", "ubuntu_22_04",
		"--bundle-id", bundle,
		"--key-pair-name", keyPair,
		"--user-data", "file://" + userDataFilePath,
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

	// Create instance (Lightsail --user-data requires file:// prefix for file paths)
	safeOut := synchronizedWriter(out)
	args := buildLightsailCreateArgs(name, az, bundle, l.KeyPairName, tmpFile.Name())
	createCmd := l.commandContext(ctx, "aws", args...)
	var stderrBuf bytes.Buffer
	createCmd.Stdout = safeOut
	createCmd.Stderr = io.MultiWriter(safeOut, &stderrBuf)

	if err := createCmd.Run(); err != nil {
		return nil, wrapAWSError("create-instances", err, stderrBuf.String())
	}

	// Instance exists on AWS from this point — clean up on any failure.
	cleanupInstance := func(reason string) {
		fmt.Fprintf(safeOut, "Cleaning up %s after failure (%s)...\n", name, reason)
		delCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		delCmd := l.commandContext(delCtx, "aws", "lightsail", "delete-instance",
			"--instance-name", name, "--force-delete-add-ons")
		delCmd.Stdout = io.Discard
		delCmd.Stderr = io.Discard
		if delErr := delCmd.Run(); delErr != nil {
			fmt.Fprintf(safeOut, "Warning: failed to clean up instance %s: %v (delete manually with: aws lightsail delete-instance --instance-name %s)\n", name, delErr, name)
		} else {
			fmt.Fprintf(safeOut, "Cleaned up instance %s\n", name)
		}
	}

	// Poll for running state and public IP (Lightsail doesn't have --wait)
	fmt.Fprintf(safeOut, "Waiting for %s public IP...\n", name)
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

		fmt.Fprintf(safeOut, "  Polling IP for %s (%d/30)...\n", name, i+1)

		select {
		case <-ctx.Done():
			cleanupInstance("timed out waiting for public IP")
			return nil, fmt.Errorf("timed out waiting for instance %q to get a public IP", name)
		case <-time.After(5 * time.Second):
		}
	}

	if ip == "" {
		cleanupInstance("no public IP assigned")
		return nil, fmt.Errorf("instance %q created but no public IP assigned after polling", name)
	}

	fmt.Fprintf(safeOut, "Instance %s ready at %s\n", name, ip)
	result := &SandboxResult{ID: name, Name: name, IP: ip}
	if l.TailscaleLockdown {
		fmt.Fprintf(safeOut, "Waiting for Tailscale on %s (cloud-init may take a few minutes)...\n", name)
		tailscaleIP, err := fetchTailscaleIPWithProgress(ctx, "ubuntu", ip, l.sshContext, l.sleep, 18, 10*time.Second, safeOut)
		if err != nil {
			cleanupInstance("tailscale IP unavailable")
			return nil, fmt.Errorf("failed to fetch tailscale IP in lockdown mode: %w", err)
		}
		result.TailscaleIP = tailscaleIP

		// Apply firewall lockdown AFTER reading the Tailscale IP.
		// The user-data script intentionally skips lockdown so hal can
		// SSH via the public IP to read /root/.tailscale-ip first.
		fmt.Fprintf(safeOut, "Applying firewall lockdown on %s...\n", name)
		lockdownScript := "sudo ufw allow in on tailscale0 && sudo ufw allow in on tailscale0 proto udp to any port 60000:61000 && sudo ufw deny 22/tcp && sudo ufw --force enable"
		sshFn := l.sshContext
		if sshFn == nil {
			sshFn = exec.CommandContext
		}
		sshCmd := sshFn(ctx, "ssh",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "ConnectTimeout=10",
			fmt.Sprintf("ubuntu@%s", ip),
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

func (l *LightsailProvider) Stop(ctx context.Context, info *ConnectInfo, out io.Writer) error {
	if err := l.ensureAWS(); err != nil {
		return err
	}

	name := ""
	if info != nil {
		name = strings.TrimSpace(info.Name)
	}
	if name == "" {
		return fmt.Errorf("sandbox name is required")
	}

	safeOut := synchronizedWriter(out)
	cmd := l.commandContext(ctx, "aws", "lightsail", "stop-instance", "--instance-name", name)
	var stderrBuf bytes.Buffer
	cmd.Stdout = safeOut
	cmd.Stderr = io.MultiWriter(safeOut, &stderrBuf)

	if err := cmd.Run(); err != nil {
		return wrapAWSError("stop-instance", err, stderrBuf.String())
	}
	return nil
}

func (l *LightsailProvider) Delete(ctx context.Context, info *ConnectInfo, out io.Writer) error {
	if err := l.ensureAWS(); err != nil {
		return err
	}

	name := ""
	if info != nil {
		name = strings.TrimSpace(info.Name)
	}
	if name == "" {
		return fmt.Errorf("sandbox name is required")
	}

	safeOut := synchronizedWriter(out)
	cmd := l.commandContext(ctx, "aws", "lightsail", "delete-instance",
		"--instance-name", name,
		"--force-delete-add-ons",
	)
	var stderrBuf bytes.Buffer
	cmd.Stdout = safeOut
	cmd.Stderr = io.MultiWriter(safeOut, &stderrBuf)

	if err := cmd.Run(); err != nil {
		return wrapAWSError("delete-instance", err, stderrBuf.String())
	}
	return nil
}

func (l *LightsailProvider) Status(ctx context.Context, info *ConnectInfo, out io.Writer) error {
	if err := l.ensureAWS(); err != nil {
		return err
	}

	name := ""
	if info != nil {
		name = strings.TrimSpace(info.Name)
	}
	if name == "" {
		return fmt.Errorf("sandbox name is required")
	}

	safeOut := synchronizedWriter(out)
	cmd := l.commandContext(ctx, "aws", "lightsail", "get-instance",
		"--instance-name", name,
		"--query", "instance.{Name:name,State:state.name,IP:publicIpAddress,Blueprint:blueprintId,Bundle:bundleId}",
		"--output", "table",
	)
	var stderrBuf bytes.Buffer
	cmd.Stdout = safeOut
	cmd.Stderr = io.MultiWriter(safeOut, &stderrBuf)

	if err := cmd.Run(); err != nil {
		return wrapAWSError("get-instance", err, stderrBuf.String())
	}
	return nil
}

func (l *LightsailProvider) SSH(info *ConnectInfo) (*exec.Cmd, error) {
	ip := ""
	if info != nil {
		ip = strings.TrimSpace(info.IP)
	}
	if ip == "" {
		return nil, fmt.Errorf("sandbox IP is required")
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

func (l *LightsailProvider) Exec(info *ConnectInfo, args []string) (*exec.Cmd, error) {
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
