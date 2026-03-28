package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestGenerateLightsailCloudInit_WithEnvVars(t *testing.T) {
	env := map[string]string{
		"GIT_TOKEN": "ghp_abc",
		"API_KEY":   "sk-123",
	}

	script := generateLightsailCloudInit(env, false)

	// Lightsail wraps user-data in its own shell script, so we generate
	// a plain shell script (NOT cloud-config YAML).
	if strings.HasPrefix(script, "#cloud-config") {
		t.Error("Lightsail cloud-init must NOT use #cloud-config (Lightsail wraps user-data in a shell script)")
	}
	if !strings.Contains(script, "base64 -d > /root/.env") {
		t.Error("script should decode base64 env to /root/.env")
	}
	if !strings.Contains(script, "setup.sh") {
		t.Error("script should run setup.sh")
	}

	// Verify env file content
	content := buildLightsailEnvFileContent(env)
	if !strings.Contains(content, "API_KEY='sk-123'") {
		t.Errorf("env content should contain API_KEY, got: %s", content)
	}
	if !strings.Contains(content, "GIT_TOKEN='ghp_abc'") {
		t.Errorf("env content should contain GIT_TOKEN, got: %s", content)
	}
	apiIdx := strings.Index(content, "API_KEY=")
	gitIdx := strings.Index(content, "GIT_TOKEN=")
	if apiIdx > gitIdx {
		t.Error("env vars should be sorted: API_KEY before GIT_TOKEN")
	}
}

func TestGenerateLightsailCloudInit_EmptyEnv(t *testing.T) {
	script := generateLightsailCloudInit(nil, false)
	if strings.HasPrefix(script, "#cloud-config") {
		t.Error("Lightsail cloud-init must NOT use #cloud-config")
	}
	if !strings.Contains(script, "setup.sh") {
		t.Error("script should run setup.sh")
	}
}

func TestBuildLightsailCreateArgs(t *testing.T) {
	args := buildLightsailCreateArgs("my-instance", "us-east-1a", "small_3_0", "my-key", "/tmp/cloud-init.yaml")
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "lightsail create-instances") {
		t.Errorf("args should contain 'lightsail create-instances', got: %s", joined)
	}
	if !strings.Contains(joined, "--instance-names my-instance") {
		t.Errorf("args should contain '--instance-names my-instance', got: %s", joined)
	}
	if !strings.Contains(joined, "--availability-zone us-east-1a") {
		t.Errorf("args should contain '--availability-zone us-east-1a', got: %s", joined)
	}
	if !strings.Contains(joined, "--blueprint-id ubuntu_22_04") {
		t.Errorf("args should contain '--blueprint-id ubuntu_22_04', got: %s", joined)
	}
	if !strings.Contains(joined, "--bundle-id small_3_0") {
		t.Errorf("args should contain '--bundle-id small_3_0', got: %s", joined)
	}
	if !strings.Contains(joined, "--key-pair-name my-key") {
		t.Errorf("args should contain '--key-pair-name my-key', got: %s", joined)
	}
	if !strings.Contains(joined, "--user-data file:///tmp/cloud-init.yaml") {
		t.Errorf("args should contain '--user-data file:///tmp/cloud-init.yaml', got: %s", joined)
	}
}

func TestLightsailProvider_SSH_WithConnectInfoIP(t *testing.T) {
	p := &LightsailProvider{}
	cmd, err := p.SSH(&ConnectInfo{Name: "test-dev", IP: "44.203.78.182"})
	if err != nil {
		t.Fatalf("SSH() error: %v", err)
	}

	args := strings.Join(cmd.Args, " ")
	if !strings.Contains(args, "ubuntu@44.203.78.182") {
		t.Errorf("SSH cmd should contain ubuntu@44.203.78.182, got: %s", args)
	}
	if !strings.Contains(args, "StrictHostKeyChecking=no") {
		t.Errorf("SSH cmd should contain StrictHostKeyChecking=no, got: %s", args)
	}
}

func TestLightsailProvider_Exec_WithConnectInfoIP(t *testing.T) {
	p := &LightsailProvider{}
	cmd, err := p.Exec(&ConnectInfo{Name: "test-dev", IP: "44.203.78.182"}, []string{"ls", "-la"})
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}

	args := strings.Join(cmd.Args, " ")
	if !strings.Contains(args, "ubuntu@44.203.78.182") {
		t.Errorf("Exec cmd should contain ubuntu@44.203.78.182, got: %s", args)
	}
	if !strings.Contains(args, "-- ls -la") {
		t.Errorf("Exec cmd should contain '-- ls -la', got: %s", args)
	}
}

func TestLightsailProvider_SSH_MissingIP(t *testing.T) {
	p := &LightsailProvider{}
	_, err := p.SSH(&ConnectInfo{Name: "test-dev"})
	if err == nil {
		t.Fatal("SSH() should error when IP is empty")
	}
	if !strings.Contains(err.Error(), "sandbox IP is required") {
		t.Errorf("error should mention missing IP, got: %v", err)
	}
}

func TestLightsailProvider_Exec_MissingIP(t *testing.T) {
	p := &LightsailProvider{}
	_, err := p.Exec(&ConnectInfo{Name: "test-dev"}, []string{"ls"})
	if err == nil {
		t.Fatal("Exec() should error when IP is empty")
	}
	if !strings.Contains(err.Error(), "sandbox IP is required") {
		t.Errorf("error should mention missing IP, got: %v", err)
	}
}

func TestLightsailProvider_Create_LockdownFailsWhenFirewallLockdownFails(t *testing.T) {
	var calls [][]string
	sshCalls := 0

	p := &LightsailProvider{
		KeyPairName:       "test-key",
		TailscaleLockdown: true,
		sleep:             func(time.Duration) {},
		lookPath: func(file string) (string, error) {
			return "/usr/bin/aws", nil
		},
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			calls = append(calls, append([]string{name}, args...))
			if len(args) >= 2 && args[0] == "lightsail" && args[1] == "get-instance" {
				return exec.CommandContext(ctx, "echo", "10.20.30.40")
			}
			return exec.CommandContext(ctx, "true")
		},
		sshContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			sshCalls++
			if sshCalls == 1 {
				return exec.CommandContext(ctx, "echo", "100.64.0.99")
			}
			return exec.CommandContext(ctx, "sh", "-c", "exit 1")
		},
	}

	var out bytes.Buffer
	_, err := p.Create(context.Background(), "test-instance", nil, &out)
	if err == nil {
		t.Fatal("Create() expected error when firewall lockdown fails in lockdown mode, got nil")
	}
	if !strings.Contains(err.Error(), "failed to apply firewall lockdown in lockdown mode") {
		t.Errorf("error %q should mention lockdown firewall failure", err.Error())
	}

	var sawCleanupDelete bool
	for _, call := range calls {
		if strings.Join(call, " ") == "aws lightsail delete-instance --instance-name test-instance --force-delete-add-ons" {
			sawCleanupDelete = true
			break
		}
	}
	if !sawCleanupDelete {
		t.Fatalf("expected cleanup delete call after lockdown failure, calls=%v", calls)
	}
}
