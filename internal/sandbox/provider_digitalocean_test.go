package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateDOCloudInit_WithEnvVars(t *testing.T) {
	env := map[string]string{
		"GIT_TOKEN": "ghp_abc",
		"API_KEY":   "sk-123",
	}
	yaml := generateDOCloudInit(env)

	if !strings.HasPrefix(yaml, "#cloud-config\n") {
		t.Error("cloud-init should start with #cloud-config")
	}

	if !strings.Contains(yaml, "API_KEY=sk-123") {
		t.Error("cloud-init should contain API_KEY=sk-123")
	}
	if !strings.Contains(yaml, "GIT_TOKEN=ghp_abc") {
		t.Error("cloud-init should contain GIT_TOKEN=ghp_abc")
	}

	// Verify sorted order
	apiIdx := strings.Index(yaml, "API_KEY=sk-123")
	gitIdx := strings.Index(yaml, "GIT_TOKEN=ghp_abc")
	if apiIdx > gitIdx {
		t.Error("env vars should be sorted: API_KEY before GIT_TOKEN")
	}

	if !strings.Contains(yaml, "packages:") {
		t.Error("cloud-init should have packages section")
	}
	for _, pkg := range []string{"git", "curl", "wget", "jq"} {
		if !strings.Contains(yaml, "- "+pkg) {
			t.Errorf("cloud-init should install %s", pkg)
		}
	}
}

func TestGenerateDOCloudInit_EmptyEnv(t *testing.T) {
	yaml := generateDOCloudInit(nil)
	if !strings.HasPrefix(yaml, "#cloud-config\n") {
		t.Error("cloud-init should start with #cloud-config")
	}
	if !strings.Contains(yaml, "packages:") {
		t.Error("cloud-init should have packages section even with no env vars")
	}
}

func TestBuildDOCreateArgs(t *testing.T) {
	args := buildDOCreateArgs("my-droplet", "s-2vcpu-4gb", "ab:cd:ef:12:34", "/tmp/cloud-init.yaml")

	// Verify all required flags
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "compute droplet create my-droplet") {
		t.Errorf("args should contain 'compute droplet create my-droplet', got: %s", joined)
	}
	if !strings.Contains(joined, "--size s-2vcpu-4gb") {
		t.Errorf("args should contain '--size s-2vcpu-4gb', got: %s", joined)
	}
	if !strings.Contains(joined, "--image ubuntu-24-04-x64") {
		t.Errorf("args should contain '--image ubuntu-24-04-x64', got: %s", joined)
	}
	if !strings.Contains(joined, "--ssh-keys ab:cd:ef:12:34") {
		t.Errorf("args should contain '--ssh-keys ab:cd:ef:12:34', got: %s", joined)
	}
	if !strings.Contains(joined, "--user-data-file /tmp/cloud-init.yaml") {
		t.Errorf("args should contain '--user-data-file /tmp/cloud-init.yaml', got: %s", joined)
	}
	if !strings.Contains(joined, "--wait") {
		t.Errorf("args should contain '--wait', got: %s", joined)
	}
}

func TestDigitalOceanProvider_Create_VerifiesArgs(t *testing.T) {
	var calls [][]string

	dp := &DigitalOceanProvider{
		SSHKey: "ab:cd:ef:12:34",
		Size:   "s-2vcpu-4gb",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			calls = append(calls, append([]string{name}, args...))
			// First call (droplet create) succeeds, second call (droplet get) returns IP
			if len(calls) == 1 {
				return exec.CommandContext(ctx, "true")
			}
			return exec.CommandContext(ctx, "echo", "10.20.30.40")
		},
	}

	var out bytes.Buffer
	env := map[string]string{"API_KEY": "sk-test"}
	result, err := dp.Create(context.Background(), "test-droplet", env, &out)
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}

	if result.Name != "test-droplet" {
		t.Errorf("result.Name = %q, want %q", result.Name, "test-droplet")
	}
	if result.IP != "10.20.30.40" {
		t.Errorf("result.IP = %q, want %q", result.IP, "10.20.30.40")
	}

	// Should have made 2 calls: droplet create + droplet get
	if len(calls) != 2 {
		t.Fatalf("expected 2 CLI calls, got %d", len(calls))
	}

	// First call: doctl compute droplet create
	createArgs := calls[0]
	if createArgs[0] != "doctl" {
		t.Errorf("create call[0] = %q, want %q", createArgs[0], "doctl")
	}
	createJoined := strings.Join(createArgs, " ")
	if !strings.Contains(createJoined, "compute droplet create test-droplet") {
		t.Errorf("create args should contain 'compute droplet create test-droplet', got: %s", createJoined)
	}
	if !strings.Contains(createJoined, "--size s-2vcpu-4gb") {
		t.Errorf("create args should contain '--size s-2vcpu-4gb', got: %s", createJoined)
	}
	if !strings.Contains(createJoined, "--image ubuntu-24-04-x64") {
		t.Errorf("create args should contain '--image ubuntu-24-04-x64', got: %s", createJoined)
	}
	if !strings.Contains(createJoined, "--ssh-keys ab:cd:ef:12:34") {
		t.Errorf("create args should contain '--ssh-keys ab:cd:ef:12:34', got: %s", createJoined)
	}
	if !strings.Contains(createJoined, "--user-data-file") {
		t.Errorf("create args should contain '--user-data-file', got: %s", createJoined)
	}
	if !strings.Contains(createJoined, "--wait") {
		t.Errorf("create args should contain '--wait', got: %s", createJoined)
	}

	// Second call: doctl compute droplet get
	getArgs := calls[1]
	getJoined := strings.Join(getArgs, " ")
	if !strings.Contains(getJoined, "compute droplet get test-droplet") {
		t.Errorf("get args should contain 'compute droplet get test-droplet', got: %s", getJoined)
	}
	if !strings.Contains(getJoined, "--format PublicIPv4") {
		t.Errorf("get args should contain '--format PublicIPv4', got: %s", getJoined)
	}
	if !strings.Contains(getJoined, "--no-header") {
		t.Errorf("get args should contain '--no-header', got: %s", getJoined)
	}
}

func TestDigitalOceanProvider_Stop_VerifiesArgs(t *testing.T) {
	var capturedArgs []string

	dp := &DigitalOceanProvider{
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "true")
		},
	}

	var out bytes.Buffer
	err := dp.Stop(context.Background(), "my-droplet", &out)
	if err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}

	joined := strings.Join(capturedArgs, " ")
	if !strings.Contains(joined, "doctl compute droplet-action shutdown my-droplet") {
		t.Errorf("stop args should contain 'doctl compute droplet-action shutdown my-droplet', got: %s", joined)
	}
}

func TestDigitalOceanProvider_Delete_VerifiesArgs(t *testing.T) {
	var capturedArgs []string

	dp := &DigitalOceanProvider{
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "true")
		},
	}

	var out bytes.Buffer
	err := dp.Delete(context.Background(), "my-droplet", &out)
	if err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}

	joined := strings.Join(capturedArgs, " ")
	if !strings.Contains(joined, "doctl compute droplet delete my-droplet") {
		t.Errorf("delete args should contain 'doctl compute droplet delete my-droplet', got: %s", joined)
	}
	if !strings.Contains(joined, "--force") {
		t.Errorf("delete args should contain '--force', got: %s", joined)
	}
}

func TestDigitalOceanProvider_Status_VerifiesArgs(t *testing.T) {
	var capturedArgs []string

	dp := &DigitalOceanProvider{
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "echo", "status output")
		},
	}

	var out bytes.Buffer
	err := dp.Status(context.Background(), "my-droplet", &out)
	if err != nil {
		t.Fatalf("Status() unexpected error: %v", err)
	}

	joined := strings.Join(capturedArgs, " ")
	if !strings.Contains(joined, "doctl compute droplet get my-droplet") {
		t.Errorf("status args should contain 'doctl compute droplet get my-droplet', got: %s", joined)
	}
	if !strings.Contains(joined, "--format ID,Name,Status,PublicIPv4") {
		t.Errorf("status args should contain '--format ID,Name,Status,PublicIPv4', got: %s", joined)
	}
}

func TestDigitalOceanProvider_DoctlNotFound(t *testing.T) {
	// Save original PATH and set empty to ensure doctl is not found
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", "")
	t.Cleanup(func() { os.Setenv("PATH", origPath) })

	dp := &DigitalOceanProvider{
		SSHKey:   "ab:cd:ef",
		Size:     "s-2vcpu-4gb",
		StateDir: t.TempDir(),
	}

	ctx := context.Background()
	var out bytes.Buffer

	// Test all methods return "doctl not found"
	_, createErr := dp.Create(ctx, "test", nil, &out)
	if createErr == nil || !strings.Contains(createErr.Error(), "doctl not found") {
		t.Errorf("Create() error = %v, want 'doctl not found'", createErr)
	}

	stopErr := dp.Stop(ctx, "test", &out)
	if stopErr == nil || !strings.Contains(stopErr.Error(), "doctl not found") {
		t.Errorf("Stop() error = %v, want 'doctl not found'", stopErr)
	}

	deleteErr := dp.Delete(ctx, "test", &out)
	if deleteErr == nil || !strings.Contains(deleteErr.Error(), "doctl not found") {
		t.Errorf("Delete() error = %v, want 'doctl not found'", deleteErr)
	}

	statusErr := dp.Status(ctx, "test", &out)
	if statusErr == nil || !strings.Contains(statusErr.Error(), "doctl not found") {
		t.Errorf("Status() error = %v, want 'doctl not found'", statusErr)
	}

	_, sshErr := dp.SSH("test")
	if sshErr == nil || !strings.Contains(sshErr.Error(), "doctl not found") {
		t.Errorf("SSH() error = %v, want 'doctl not found'", sshErr)
	}

	_, execErr := dp.Exec("test", []string{"ls"})
	if execErr == nil || !strings.Contains(execErr.Error(), "doctl not found") {
		t.Errorf("Exec() error = %v, want 'doctl not found'", execErr)
	}
}

func TestDigitalOceanProvider_SSH_WithState(t *testing.T) {
	stateDir := t.TempDir()

	state := &SandboxState{
		Name:     "my-droplet",
		Provider: "digitalocean",
		IP:       "10.20.30.40",
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "sandbox.json"), data, 0644); err != nil {
		t.Fatalf("write state: %v", err)
	}

	dp := &DigitalOceanProvider{
		StateDir: stateDir,
	}

	cmd, err := dp.SSH("my-droplet")
	if err != nil {
		t.Fatalf("SSH() unexpected error: %v", err)
	}

	args := strings.Join(cmd.Args, " ")
	if !strings.Contains(args, "ssh") {
		t.Errorf("SSH cmd should start with ssh, got: %s", args)
	}
	if !strings.Contains(args, "root@10.20.30.40") {
		t.Errorf("SSH cmd should contain root@10.20.30.40, got: %s", args)
	}
	if !strings.Contains(args, "StrictHostKeyChecking=no") {
		t.Errorf("SSH cmd should contain StrictHostKeyChecking=no, got: %s", args)
	}
}

func TestDigitalOceanProvider_Exec_WithState(t *testing.T) {
	stateDir := t.TempDir()

	state := &SandboxState{
		Name:     "my-droplet",
		Provider: "digitalocean",
		IP:       "10.20.30.40",
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "sandbox.json"), data, 0644); err != nil {
		t.Fatalf("write state: %v", err)
	}

	dp := &DigitalOceanProvider{
		StateDir: stateDir,
	}

	cmd, err := dp.Exec("my-droplet", []string{"ls", "-la"})
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}

	args := strings.Join(cmd.Args, " ")
	if !strings.Contains(args, "root@10.20.30.40") {
		t.Errorf("Exec cmd should contain root@10.20.30.40, got: %s", args)
	}
	if !strings.Contains(args, "-- ls -la") {
		t.Errorf("Exec cmd should contain '-- ls -la', got: %s", args)
	}
}

func TestDigitalOceanProvider_SSH_MissingIP(t *testing.T) {
	stateDir := t.TempDir()

	state := &SandboxState{
		Name:     "my-droplet",
		Provider: "digitalocean",
		IP:       "",
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "sandbox.json"), data, 0644); err != nil {
		t.Fatalf("write state: %v", err)
	}

	dp := &DigitalOceanProvider{
		StateDir: stateDir,
	}

	_, err = dp.SSH("my-droplet")
	if err == nil {
		t.Fatal("SSH() expected error for missing IP, got nil")
	}
	if !strings.Contains(err.Error(), "no IP address") {
		t.Errorf("SSH() error %q should mention missing IP", err.Error())
	}
}

func TestDigitalOceanProvider_SSH_MissingState(t *testing.T) {
	dp := &DigitalOceanProvider{
		StateDir: t.TempDir(), // empty dir, no sandbox.json
	}

	_, err := dp.SSH("my-droplet")
	if err == nil {
		t.Fatal("SSH() expected error for missing state, got nil")
	}
	if !strings.Contains(err.Error(), "sandbox state") {
		t.Errorf("SSH() error %q should mention sandbox state", err.Error())
	}
}

func TestProviderFromConfig_DigitalOcean(t *testing.T) {
	cfg := ProviderConfig{
		DigitalOceanSSHKey: "ab:cd:ef:12:34",
		DigitalOceanSize:   "s-4vcpu-8gb",
		StateDir:           "/tmp/test-hal",
	}
	p, err := ProviderFromConfig("digitalocean", cfg)
	if err != nil {
		t.Fatalf("ProviderFromConfig(digitalocean) unexpected error: %v", err)
	}
	dp, ok := p.(*DigitalOceanProvider)
	if !ok {
		t.Fatalf("expected *DigitalOceanProvider, got %T", p)
	}
	if dp.SSHKey != "ab:cd:ef:12:34" {
		t.Errorf("SSHKey = %q, want %q", dp.SSHKey, "ab:cd:ef:12:34")
	}
	if dp.Size != "s-4vcpu-8gb" {
		t.Errorf("Size = %q, want %q", dp.Size, "s-4vcpu-8gb")
	}
	if dp.StateDir != "/tmp/test-hal" {
		t.Errorf("StateDir = %q, want %q", dp.StateDir, "/tmp/test-hal")
	}
}

func TestDigitalOceanProvider_Create_StderrOnFailure(t *testing.T) {
	dp := &DigitalOceanProvider{
		SSHKey: "ab:cd:ef",
		Size:   "s-2vcpu-4gb",
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			// Simulate doctl failure with stderr output
			return exec.CommandContext(ctx, "sh", "-c", "echo 'droplet create failed: quota exceeded' >&2; exit 1")
		},
	}

	var out bytes.Buffer
	_, err := dp.Create(context.Background(), "test-droplet", nil, &out)
	if err == nil {
		t.Fatal("Create() expected error on doctl failure, got nil")
	}
	if !strings.Contains(err.Error(), "quota exceeded") {
		t.Errorf("error %q should contain stderr message 'quota exceeded'", err.Error())
	}
}
