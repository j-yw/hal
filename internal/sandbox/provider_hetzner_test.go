package sandbox

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
)

func TestGenerateCloudInit_WithEnvVars(t *testing.T) {
	env := map[string]string{
		"GIT_TOKEN": "ghp_abc",
		"API_KEY":   "sk-123",
	}
	yaml := generateCloudInit(env)

	// Verify cloud-config header
	if !strings.HasPrefix(yaml, "#cloud-config\n") {
		t.Error("cloud-init should start with #cloud-config")
	}

	// Verify env vars present (sorted alphabetically)
	if !strings.Contains(yaml, "API_KEY=sk-123") {
		t.Error("cloud-init should contain API_KEY=sk-123")
	}
	if !strings.Contains(yaml, "GIT_TOKEN=ghp_abc") {
		t.Error("cloud-init should contain GIT_TOKEN=ghp_abc")
	}

	// Verify API_KEY comes before GIT_TOKEN (sorted)
	apiIdx := strings.Index(yaml, "API_KEY=sk-123")
	gitIdx := strings.Index(yaml, "GIT_TOKEN=ghp_abc")
	if apiIdx > gitIdx {
		t.Error("env vars should be sorted: API_KEY before GIT_TOKEN")
	}

	// Verify packages section
	if !strings.Contains(yaml, "packages:") {
		t.Error("cloud-init should have packages section")
	}
	for _, pkg := range []string{"git", "curl", "wget", "jq"} {
		if !strings.Contains(yaml, "- "+pkg) {
			t.Errorf("cloud-init should install %s", pkg)
		}
	}
}

func TestGenerateCloudInit_EmptyEnv(t *testing.T) {
	yaml := generateCloudInit(nil)
	if !strings.HasPrefix(yaml, "#cloud-config\n") {
		t.Error("cloud-init should start with #cloud-config")
	}
	if !strings.Contains(yaml, "packages:") {
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

func TestHetznerProvider_Stop_Success(t *testing.T) {
	var capturedArgs []string
	hp := &HetznerProvider{
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "echo", "shutting down")
		},
	}

	var out bytes.Buffer
	err := hp.Stop(context.Background(), "my-server", &out)
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
	err := hp.Stop(context.Background(), "my-server", &out)
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
	err := hp.Delete(context.Background(), "my-server", &out)
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
	err := hp.Delete(context.Background(), "my-server", &out)
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
	err := hp.Status(context.Background(), "my-server", &out)
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
	err := hp.Status(context.Background(), "my-server", &out)
	if err == nil {
		t.Fatal("Status() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "hcloud server describe failed") {
		t.Errorf("error %q should contain 'hcloud server describe failed'", err.Error())
	}
}

// writeHetznerState creates a sandbox.json with the given IP in a temp .hal dir.
func writeHetznerState(t *testing.T, ip string) string {
	t.Helper()
	dir := t.TempDir()
	state := &SandboxState{
		Name:     "test-server",
		Provider: "hetzner",
		IP:       ip,
	}
	if err := SaveState(dir, state); err != nil {
		t.Fatalf("failed to save test state: %v", err)
	}
	return dir
}

func TestHetznerProvider_SSH(t *testing.T) {
	stateDir := writeHetznerState(t, "10.0.0.42")
	hp := &HetznerProvider{StateDir: stateDir}

	cmd, err := hp.SSH("test-server")
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
	stateDir := writeHetznerState(t, "")
	hp := &HetznerProvider{StateDir: stateDir}

	_, err := hp.SSH("test-server")
	if err == nil {
		t.Fatal("SSH() expected error for missing IP, got nil")
	}
	if !strings.Contains(err.Error(), "no IP address") {
		t.Errorf("error %q should mention 'no IP address'", err.Error())
	}
}

func TestHetznerProvider_SSH_NoState(t *testing.T) {
	hp := &HetznerProvider{StateDir: t.TempDir()}

	_, err := hp.SSH("test-server")
	if err == nil {
		t.Fatal("SSH() expected error for missing state, got nil")
	}
}

func TestHetznerProvider_Exec(t *testing.T) {
	stateDir := writeHetznerState(t, "10.0.0.42")
	hp := &HetznerProvider{StateDir: stateDir}

	cmd, err := hp.Exec("test-server", []string{"ls", "-la"})
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
	stateDir := writeHetznerState(t, "")
	hp := &HetznerProvider{StateDir: stateDir}

	_, err := hp.Exec("test-server", []string{"ls"})
	if err == nil {
		t.Fatal("Exec() expected error for missing IP, got nil")
	}
	if !strings.Contains(err.Error(), "no IP address") {
		t.Errorf("error %q should mention 'no IP address'", err.Error())
	}
}
