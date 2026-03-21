package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func preferredIP(state *SandboxState) string {
	return PreferredIP(state)
}

func withLockdownEnv(env map[string]string, lockdown bool) map[string]string {
	out := make(map[string]string, len(env)+1)
	for k, v := range env {
		out[k] = v
	}
	if lockdown {
		out["TAILSCALE_LOCKDOWN"] = "true"
	} else {
		out["TAILSCALE_LOCKDOWN"] = "false"
	}
	return out
}

func fetchTailscaleIP(ctx context.Context, user, publicIP string, runSSH func(context.Context, string, ...string) *exec.Cmd, sleepFn func(time.Duration), attempts int, delay time.Duration) (string, error) {
	if attempts <= 0 {
		attempts = 1
	}
	if sleepFn == nil {
		sleepFn = time.Sleep
	}
	if runSSH == nil {
		runSSH = exec.CommandContext
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		remoteReadCmd := []string{"cat", "/root/.tailscale-ip"}
		if user != "root" {
			remoteReadCmd = []string{"sudo", "cat", "/root/.tailscale-ip"}
		}

		sshArgs := []string{
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "ConnectTimeout=10",
			fmt.Sprintf("%s@%s", user, publicIP),
		}
		sshArgs = append(sshArgs, remoteReadCmd...)

		cmd := runSSH(ctx, "ssh", sshArgs...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err == nil {
			ip := strings.TrimSpace(stdout.String())
			if ip != "" {
				return ip, nil
			}
			lastErr = fmt.Errorf("empty tailscale ip")
		} else {
			lastErr = fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}

		if i < attempts-1 {
			sleepFn(delay)
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("failed to fetch tailscale ip")
	}
	return "", lastErr
}
