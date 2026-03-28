package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestGenerateCloudInit_WithEnvVars(t *testing.T) {
	env := map[string]string{
		"GIT_TOKEN": "ghp_abc",
		"API_KEY":   "sk-123",
	}
	yaml := generateCloudInit(env, false)

	// Verify cloud-config header
	if !strings.HasPrefix(yaml, "#cloud-config\n") {
		t.Error("cloud-init should start with #cloud-config")
	}

	// Verify base64 encoding and runcmd
	if !strings.Contains(yaml, "encoding: b64") {
		t.Error("cloud-init should use base64 encoding")
	}
	if !strings.Contains(yaml, "runcmd:") {
		t.Error("cloud-init should have runcmd section")
	}
	if !strings.Contains(yaml, "setup.sh") {
		t.Error("cloud-init runcmd should run setup.sh")
	}

	// Verify env file content
	content := buildHetznerEnvFileContent(env)
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

func TestGenerateCloudInit_EmptyEnv(t *testing.T) {
	yaml := generateCloudInit(nil, false)
	if !strings.HasPrefix(yaml, "#cloud-config\n") {
		t.Error("cloud-init should start with #cloud-config")
	}
	if !strings.Contains(yaml, "runcmd:") {
		t.Error("cloud-init should have packages section even with no env vars")
	}
}

func TestHetznerProvider_Create_VerifiesArgs(t *testing.T) {
	var calls [][]string

	hp := &HetznerProvider{
		SSHKey:     "my-ssh-key",
		ServerType: "cx22",
		Image:      "ubuntu-24.04",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			calls = append(calls, append([]string{name}, args...))
			// First call (server create) succeeds, second call (server ip) returns an IP
			if len(calls) == 1 {
				return exec.CommandContext(ctx, "true")
			}
			return exec.CommandContext(ctx, "echo", "10.0.0.42")
		},
	}

	var out bytes.Buffer
	env := map[string]string{"GIT_TOKEN": "ghp_abc"}
	result, err := hp.Create(context.Background(), "test-server", env, &out)
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}

	// Verify result
	if result.Name != "test-server" {
		t.Errorf("result.Name = %q, want %q", result.Name, "test-server")
	}
	if result.IP != "10.0.0.42" {
		t.Errorf("result.IP = %q, want %q", result.IP, "10.0.0.42")
	}

	// Should have made 2 calls: server create + server ip
	if len(calls) != 2 {
		t.Fatalf("expected 2 CLI calls, got %d", len(calls))
	}

	// First call: hcloud server create
	createArgs := calls[0]
	if createArgs[0] != "hcloud" {
		t.Errorf("create call[0] = %q, want %q", createArgs[0], "hcloud")
	}
	createStr := strings.Join(createArgs[1:], " ")
	for _, want := range []string{"server", "create", "--name", "test-server", "--type", "cx22", "--image", "ubuntu-24.04", "--ssh-key", "my-ssh-key", "--user-data-file"} {
		if !strings.Contains(createStr, want) {
			t.Errorf("create args %q missing %q", createStr, want)
		}
	}

	// Second call: hcloud server ip
	ipArgs := calls[1]
	wantIpArgs := []string{"hcloud", "server", "ip", "test-server"}
	if len(ipArgs) != len(wantIpArgs) {
		t.Fatalf("ip args = %v, want %v", ipArgs, wantIpArgs)
	}
	for i, want := range wantIpArgs {
		if ipArgs[i] != want {
			t.Errorf("ipArgs[%d] = %q, want %q", i, ipArgs[i], want)
		}
	}
}

func TestHetznerProvider_Create_ServerCreateFails(t *testing.T) {
	hp := &HetznerProvider{
		SSHKey:     "key",
		ServerType: "cx22",
		Image:      "ubuntu-24.04",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "sh", "-c", "exit 1")
		},
	}

	var out bytes.Buffer
	result, err := hp.Create(context.Background(), "test", nil, &out)
	if err == nil {
		t.Fatal("Create() expected error, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result on failure, got %+v", result)
	}
	if !strings.Contains(err.Error(), "hcloud server create failed") {
		t.Errorf("error %q should mention 'hcloud server create failed'", err.Error())
	}
}

func TestHetznerProvider_Create_RequiresImage(t *testing.T) {
	called := false
	hp := &HetznerProvider{
		SSHKey:     "key",
		ServerType: "cx22",
		Image:      "",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			called = true
			return exec.CommandContext(ctx, "true")
		},
	}

	var out bytes.Buffer
	result, err := hp.Create(context.Background(), "test", nil, &out)
	if err == nil {
		t.Fatal("Create() expected error when image is missing, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
	if !strings.Contains(err.Error(), "hetzner image is required") {
		t.Errorf("error %q should mention missing image", err.Error())
	}
	if called {
		t.Fatal("expected hcloud command not to run when image is missing")
	}
}

func TestHetznerProvider_Create_ServerIPFails(t *testing.T) {
	callCount := 0
	hp := &HetznerProvider{
		SSHKey:     "key",
		ServerType: "cx22",
		Image:      "ubuntu-24.04",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			callCount++
			if callCount == 1 {
				return exec.CommandContext(ctx, "true") // create succeeds
			}
			return exec.CommandContext(ctx, "sh", "-c", "exit 1") // ip fails
		},
	}

	var out bytes.Buffer
	result, err := hp.Create(context.Background(), "test", nil, &out)
	if err == nil {
		t.Fatal("Create() expected error, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result, got %+v", result)
	}
	if !strings.Contains(err.Error(), "hcloud server ip failed") {
		t.Errorf("error %q should mention 'hcloud server ip failed'", err.Error())
	}
}

func TestHetznerProvider_Create_LockdownFailsWhenFirewallLockdownFails(t *testing.T) {
	var calls [][]string
	sshCalls := 0

	hp := &HetznerProvider{
		SSHKey:            "key",
		ServerType:        "cx22",
		Image:             "ubuntu-24.04",
		TailscaleLockdown: true,
		sleep:             func(time.Duration) {},
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			calls = append(calls, append([]string{name}, args...))
			if len(args) >= 2 && args[0] == "server" && args[1] == "ip" {
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
	_, err := hp.Create(context.Background(), "test-server", nil, &out)
	if err == nil {
		t.Fatal("Create() expected error when firewall lockdown fails in lockdown mode, got nil")
	}
	if !strings.Contains(err.Error(), "failed to apply firewall lockdown in lockdown mode") {
		t.Errorf("error %q should mention lockdown firewall failure", err.Error())
	}

	var sawCleanupDelete bool
	for _, call := range calls {
		if strings.Join(call, " ") == "hcloud server delete test-server" {
			sawCleanupDelete = true
			break
		}
	}
	if !sawCleanupDelete {
		t.Fatalf("expected cleanup delete call after lockdown failure, calls=%v", calls)
	}
}

func TestHetznerProvider_Stop_Success(t *testing.T) {
	var capturedArgs []string
	hp := &HetznerProvider{
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "echo", "shutting down")
		},
	}

	var out bytes.Buffer
	err := hp.Stop(context.Background(), &ConnectInfo{Name: "my-server"}, &out)
	if err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}

	wantArgs := []string{"hcloud", "server", "shutdown", "my-server"}
	if len(capturedArgs) != len(wantArgs) {
		t.Fatalf("got args %v, want %v", capturedArgs, wantArgs)
	}
	for i, want := range wantArgs {
		if capturedArgs[i] != want {
			t.Errorf("args[%d] = %q, want %q", i, capturedArgs[i], want)
		}
	}
}

func TestHetznerProvider_Stop_Failure(t *testing.T) {
	hp := &HetznerProvider{
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "sh", "-c", "exit 1")
		},
	}

	var out bytes.Buffer
	err := hp.Stop(context.Background(), &ConnectInfo{Name: "my-server"}, &out)
	if err == nil {
		t.Fatal("Stop() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "hcloud server shutdown failed") {
		t.Errorf("error %q should contain 'hcloud server shutdown failed'", err.Error())
	}
}

func TestHetznerProvider_Delete_Success(t *testing.T) {
	var capturedArgs []string
	hp := &HetznerProvider{
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "echo", "deleted")
		},
	}

	var out bytes.Buffer
	err := hp.Delete(context.Background(), &ConnectInfo{Name: "my-server"}, &out)
	if err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}

	wantArgs := []string{"hcloud", "server", "delete", "my-server"}
	if len(capturedArgs) != len(wantArgs) {
		t.Fatalf("got args %v, want %v", capturedArgs, wantArgs)
	}
	for i, want := range wantArgs {
		if capturedArgs[i] != want {
			t.Errorf("args[%d] = %q, want %q", i, capturedArgs[i], want)
		}
	}
}

func TestHetznerProvider_Delete_Failure(t *testing.T) {
	hp := &HetznerProvider{
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "sh", "-c", "exit 1")
		},
	}

	var out bytes.Buffer
	err := hp.Delete(context.Background(), &ConnectInfo{Name: "my-server"}, &out)
	if err == nil {
		t.Fatal("Delete() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "hcloud server delete failed") {
		t.Errorf("error %q should contain 'hcloud server delete failed'", err.Error())
	}
}

func TestHetznerProvider_Status_Success(t *testing.T) {
	var capturedArgs []string
	hp := &HetznerProvider{
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "echo", "running")
		},
	}

	var out bytes.Buffer
	err := hp.Status(context.Background(), &ConnectInfo{Name: "my-server"}, &out)
	if err != nil {
		t.Fatalf("Status() unexpected error: %v", err)
	}

	wantArgs := []string{"hcloud", "server", "describe", "my-server"}
	if len(capturedArgs) != len(wantArgs) {
		t.Fatalf("got args %v, want %v", capturedArgs, wantArgs)
	}
	for i, want := range wantArgs {
		if capturedArgs[i] != want {
			t.Errorf("args[%d] = %q, want %q", i, capturedArgs[i], want)
		}
	}
}

func TestHetznerProvider_Status_Failure(t *testing.T) {
	hp := &HetznerProvider{
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "sh", "-c", "exit 1")
		},
	}

	var out bytes.Buffer
	err := hp.Status(context.Background(), &ConnectInfo{Name: "my-server"}, &out)
	if err == nil {
		t.Fatal("Status() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "hcloud server describe failed") {
		t.Errorf("error %q should contain 'hcloud server describe failed'", err.Error())
	}
}

func TestHetznerProvider_SSH(t *testing.T) {
	hp := &HetznerProvider{}

	cmd, err := hp.SSH(&ConnectInfo{Name: "test-server", IP: "10.0.0.42"})
	if err != nil {
		t.Fatalf("SSH() unexpected error: %v", err)
	}

	// Verify args: ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.0.0.42
	wantArgs := []string{"ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "root@10.0.0.42"}
	if len(cmd.Args) != len(wantArgs) {
		t.Fatalf("got args %v, want %v", cmd.Args, wantArgs)
	}
	for i, want := range wantArgs {
		if cmd.Args[i] != want {
			t.Errorf("Args[%d] = %q, want %q", i, cmd.Args[i], want)
		}
	}

	// Verify stdio is attached
	if cmd.Stdin == nil {
		t.Error("Stdin should be set")
	}
	if cmd.Stdout == nil {
		t.Error("Stdout should be set")
	}
	if cmd.Stderr == nil {
		t.Error("Stderr should be set")
	}
}

func TestHetznerProvider_SSH_NoIP(t *testing.T) {
	hp := &HetznerProvider{}

	_, err := hp.SSH(&ConnectInfo{Name: "test-server"})
	if err == nil {
		t.Fatal("SSH() expected error for missing IP, got nil")
	}
	if !strings.Contains(err.Error(), "sandbox IP is required") {
		t.Errorf("error %q should mention 'sandbox IP is required'", err.Error())
	}
}

func TestHetznerProvider_Exec(t *testing.T) {
	hp := &HetznerProvider{}

	cmd, err := hp.Exec(&ConnectInfo{Name: "test-server", IP: "10.0.0.42"}, []string{"ls", "-la"})
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}

	wantArgs := []string{"ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "root@10.0.0.42", "--", "ls", "-la"}
	if len(cmd.Args) != len(wantArgs) {
		t.Fatalf("got args %v, want %v", cmd.Args, wantArgs)
	}
	for i, want := range wantArgs {
		if cmd.Args[i] != want {
			t.Errorf("Args[%d] = %q, want %q", i, cmd.Args[i], want)
		}
	}
}

func TestHetznerProvider_Exec_NoIP(t *testing.T) {
	hp := &HetznerProvider{}

	_, err := hp.Exec(&ConnectInfo{Name: "test-server"}, []string{"ls"})
	if err == nil {
		t.Fatal("Exec() expected error for missing IP, got nil")
	}
	if !strings.Contains(err.Error(), "sandbox IP is required") {
		t.Errorf("error %q should mention 'sandbox IP is required'", err.Error())
	}
}
