package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func doctlLookPathStub(file string) (string, error) {
	if file == "doctl" {
		return "/usr/bin/doctl", nil
	}
	return "", exec.ErrNotFound
}

func TestGenerateDOCloudInit_WithEnvVars(t *testing.T) {
	env := map[string]string{
		"GIT_TOKEN": "ghp_abc",
		"API_KEY":   "sk-123",
	}
	yaml := generateDOCloudInit(env, false)

	if !strings.HasPrefix(yaml, "#cloud-config\n") {
		t.Error("cloud-init should start with #cloud-config")
	}
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
	content := buildEnvFileContent(env)
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

func TestGenerateDOCloudInit_EmptyEnv(t *testing.T) {
	yaml := generateDOCloudInit(nil, false)
	if !strings.HasPrefix(yaml, "#cloud-config\n") {
		t.Error("cloud-init should start with #cloud-config")
	}
	if !strings.Contains(yaml, "runcmd:") {
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
		SSHKey:   "ab:cd:ef:12:34",
		Size:     "s-2vcpu-4gb",
		lookPath: doctlLookPathStub,
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			calls = append(calls, append([]string{name}, args...))
			// First call (droplet create) succeeds, second call (droplet get) returns ID and IP.
			if len(calls) == 1 {
				return exec.CommandContext(ctx, "true")
			}
			return exec.CommandContext(ctx, "echo", "123456789 10.20.30.40")
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
	if result.ID != "123456789" {
		t.Errorf("result.ID = %q, want %q", result.ID, "123456789")
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
	if !strings.Contains(getJoined, "--format ID,PublicIPv4") {
		t.Errorf("get args should contain '--format ID,PublicIPv4', got: %s", getJoined)
	}
	if !strings.Contains(getJoined, "--no-header") {
		t.Errorf("get args should contain '--no-header', got: %s", getJoined)
	}
}

func TestDigitalOceanProvider_Stop_VerifiesArgs(t *testing.T) {
	var capturedArgs []string

	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "true")
		},
	}

	var out bytes.Buffer
	err := dp.Stop(context.Background(), &ConnectInfo{Name: "my-droplet", WorkspaceID: "123456789"}, &out)
	if err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}

	joined := strings.Join(capturedArgs, " ")
	if !strings.Contains(joined, "doctl compute droplet-action shutdown 123456789") {
		t.Errorf("stop args should contain 'doctl compute droplet-action shutdown 123456789', got: %s", joined)
	}
}

func TestDigitalOceanProvider_Delete_VerifiesArgs(t *testing.T) {
	var capturedArgs []string

	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "true")
		},
	}

	var out bytes.Buffer
	err := dp.Delete(context.Background(), &ConnectInfo{Name: "my-droplet", WorkspaceID: "123456789"}, &out)
	if err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}

	joined := strings.Join(capturedArgs, " ")
	if !strings.Contains(joined, "doctl compute droplet delete 123456789") {
		t.Errorf("delete args should contain 'doctl compute droplet delete 123456789', got: %s", joined)
	}
	if !strings.Contains(joined, "--force") {
		t.Errorf("delete args should contain '--force', got: %s", joined)
	}
}

func TestDigitalOceanProvider_Status_VerifiesArgs(t *testing.T) {
	var capturedArgs []string

	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "echo", "status output")
		},
	}

	var out bytes.Buffer
	err := dp.Status(context.Background(), &ConnectInfo{Name: "my-droplet", WorkspaceID: "123456789"}, &out)
	if err != nil {
		t.Fatalf("Status() unexpected error: %v", err)
	}

	joined := strings.Join(capturedArgs, " ")
	if !strings.Contains(joined, "doctl compute droplet get 123456789") {
		t.Errorf("status args should contain 'doctl compute droplet get 123456789', got: %s", joined)
	}
	if !strings.Contains(joined, "--format ID,Name,Status,PublicIPv4") {
		t.Errorf("status args should contain '--format ID,Name,Status,PublicIPv4', got: %s", joined)
	}
}

func TestDigitalOceanProvider_RequiresWorkspaceIDForLifecycleOps(t *testing.T) {
	tests := []struct {
		name string
		run  func(*DigitalOceanProvider) error
	}{
		{
			name: "stop",
			run: func(p *DigitalOceanProvider) error {
				return p.Stop(context.Background(), &ConnectInfo{Name: "my-droplet"}, &bytes.Buffer{})
			},
		},
		{
			name: "delete",
			run: func(p *DigitalOceanProvider) error {
				return p.Delete(context.Background(), &ConnectInfo{Name: "my-droplet"}, &bytes.Buffer{})
			},
		},
		{
			name: "status",
			run: func(p *DigitalOceanProvider) error {
				return p.Status(context.Background(), &ConnectInfo{Name: "my-droplet"}, &bytes.Buffer{})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var called bool
			dp := &DigitalOceanProvider{
				lookPath: doctlLookPathStub,
				cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
					called = true
					return exec.CommandContext(ctx, "true")
				},
			}

			err := tt.run(dp)
			if err == nil {
				t.Fatalf("expected error for missing workspace ID")
			}
			if !strings.Contains(err.Error(), "sandbox workspace ID is required") {
				t.Fatalf("error = %q, want missing workspace ID message", err.Error())
			}
			if called {
				t.Fatalf("expected no doctl invocation when workspace ID is missing")
			}
		})
	}
}

func TestDigitalOceanProvider_DoctlNotFound(t *testing.T) {
	// Save original PATH and set empty to ensure doctl is not found
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", "")
	t.Cleanup(func() { os.Setenv("PATH", origPath) })

	dp := &DigitalOceanProvider{
		SSHKey: "ab:cd:ef",
		Size:   "s-2vcpu-4gb",
	}

	ctx := context.Background()
	var out bytes.Buffer

	// Test all methods return "doctl not found"
	_, createErr := dp.Create(ctx, "test", nil, &out)
	if createErr == nil || !strings.Contains(createErr.Error(), "doctl not found") {
		t.Errorf("Create() error = %v, want 'doctl not found'", createErr)
	}

	stopErr := dp.Stop(ctx, &ConnectInfo{Name: "test"}, &out)
	if stopErr == nil || !strings.Contains(stopErr.Error(), "doctl not found") {
		t.Errorf("Stop() error = %v, want 'doctl not found'", stopErr)
	}

	deleteErr := dp.Delete(ctx, &ConnectInfo{Name: "test"}, &out)
	if deleteErr == nil || !strings.Contains(deleteErr.Error(), "doctl not found") {
		t.Errorf("Delete() error = %v, want 'doctl not found'", deleteErr)
	}

	statusErr := dp.Status(ctx, &ConnectInfo{Name: "test"}, &out)
	if statusErr == nil || !strings.Contains(statusErr.Error(), "doctl not found") {
		t.Errorf("Status() error = %v, want 'doctl not found'", statusErr)
	}

	_, sshErr := dp.SSH(&ConnectInfo{Name: "test"})
	if sshErr == nil || !strings.Contains(sshErr.Error(), "doctl not found") {
		t.Errorf("SSH() error = %v, want 'doctl not found'", sshErr)
	}

	_, execErr := dp.Exec(&ConnectInfo{Name: "test"}, []string{"ls"})
	if execErr == nil || !strings.Contains(execErr.Error(), "doctl not found") {
		t.Errorf("Exec() error = %v, want 'doctl not found'", execErr)
	}
}

func TestDigitalOceanProvider_SSH_WithConnectInfoIP(t *testing.T) {
	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
	}

	cmd, err := dp.SSH(&ConnectInfo{Name: "my-droplet", IP: "10.20.30.40"})
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

func TestDigitalOceanProvider_Exec_WithConnectInfoIP(t *testing.T) {
	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
	}

	cmd, err := dp.Exec(&ConnectInfo{Name: "my-droplet", IP: "10.20.30.40"}, []string{"ls", "-la"})
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
	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
	}

	_, err := dp.SSH(&ConnectInfo{Name: "my-droplet"})
	if err == nil {
		t.Fatal("SSH() expected error for missing IP, got nil")
	}
	if !strings.Contains(err.Error(), "sandbox IP is required") {
		t.Errorf("SSH() error %q should mention missing IP", err.Error())
	}
}

func TestDigitalOceanProvider_SSH_ResolvesIPFromWorkspaceID(t *testing.T) {
	var capturedArgs []string
	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "echo", "123456789 10.20.30.40")
		},
	}

	cmd, err := dp.SSH(&ConnectInfo{Name: "my-droplet", WorkspaceID: "123456789"})
	if err != nil {
		t.Fatalf("SSH() unexpected error: %v", err)
	}

	joinedLookup := strings.Join(capturedArgs, " ")
	if !strings.Contains(joinedLookup, "doctl compute droplet get 123456789") {
		t.Fatalf("SSH() lookup args = %q, want droplet lookup by workspace ID", joinedLookup)
	}
	if !strings.Contains(joinedLookup, "--format ID,PublicIPv4") {
		t.Fatalf("SSH() lookup args = %q, want PublicIPv4 format request", joinedLookup)
	}

	joinedSSH := strings.Join(cmd.Args, " ")
	if !strings.Contains(joinedSSH, "root@10.20.30.40") {
		t.Fatalf("SSH() command = %q, want resolved IP", joinedSSH)
	}
}

func TestDigitalOceanProvider_Exec_MissingIP(t *testing.T) {
	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
	}

	_, err := dp.Exec(&ConnectInfo{Name: "my-droplet"}, []string{"ls"})
	if err == nil {
		t.Fatal("Exec() expected error for missing IP, got nil")
	}
	if !strings.Contains(err.Error(), "sandbox IP is required") {
		t.Errorf("Exec() error %q should mention missing IP", err.Error())
	}
}

func TestDigitalOceanProvider_Exec_ResolvesIPFromWorkspaceID(t *testing.T) {
	var capturedArgs []string
	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = append([]string{name}, args...)
			return exec.CommandContext(ctx, "echo", "123456789 10.20.30.40")
		},
	}

	cmd, err := dp.Exec(&ConnectInfo{Name: "my-droplet", WorkspaceID: "123456789"}, []string{"ls"})
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}

	joinedLookup := strings.Join(capturedArgs, " ")
	if !strings.Contains(joinedLookup, "doctl compute droplet get 123456789") {
		t.Fatalf("Exec() lookup args = %q, want droplet lookup by workspace ID", joinedLookup)
	}
	if !strings.Contains(joinedLookup, "--format ID,PublicIPv4") {
		t.Fatalf("Exec() lookup args = %q, want PublicIPv4 format request", joinedLookup)
	}

	joinedExec := strings.Join(cmd.Args, " ")
	if !strings.Contains(joinedExec, "root@10.20.30.40") {
		t.Fatalf("Exec() command = %q, want resolved IP", joinedExec)
	}
}

func TestProviderFromConfig_DigitalOcean(t *testing.T) {
	cfg := ProviderConfig{
		DigitalOceanSSHKey: "ab:cd:ef:12:34",
		DigitalOceanSize:   "s-4vcpu-8gb",
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
}

func TestDigitalOceanProvider_Create_StderrOnFailure(t *testing.T) {
	dp := &DigitalOceanProvider{
		SSHKey:   "ab:cd:ef",
		Size:     "s-2vcpu-4gb",
		lookPath: doctlLookPathStub,
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

func TestDigitalOceanProvider_Create_ErrorsWhenPublicIPMissing(t *testing.T) {
	var calls [][]string

	dp := &DigitalOceanProvider{
		SSHKey:   "ab:cd:ef:12:34",
		Size:     "s-2vcpu-4gb",
		lookPath: doctlLookPathStub,
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			calls = append(calls, append([]string{name}, args...))
			if len(calls) == 1 {
				return exec.CommandContext(ctx, "true")
			}
			// Simulate doctl returning only droplet ID with no PublicIPv4 value.
			return exec.CommandContext(ctx, "echo", "123456789")
		},
	}

	var out bytes.Buffer
	_, err := dp.Create(context.Background(), "test-droplet", nil, &out)
	if err == nil {
		t.Fatal("Create() expected error when PublicIPv4 is missing, got nil")
	}
	if !strings.Contains(err.Error(), "no PublicIPv4") {
		t.Errorf("error %q should mention missing PublicIPv4", err.Error())
	}
}

func TestDigitalOceanProvider_Create_LockdownFailsWhenTailscaleIPUnavailable(t *testing.T) {
	dp := &DigitalOceanProvider{
		SSHKey:            "ab:cd:ef:12:34",
		Size:              "s-2vcpu-4gb",
		TailscaleLockdown: true,
		lookPath:          doctlLookPathStub,
		sleep:             func(time.Duration) {},
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			if len(args) >= 3 && args[0] == "compute" && args[1] == "droplet" && args[2] == "create" {
				return exec.CommandContext(ctx, "true")
			}
			if len(args) >= 3 && args[0] == "compute" && args[1] == "droplet" && args[2] == "get" {
				return exec.CommandContext(ctx, "echo", "123456789 10.20.30.40")
			}
			return exec.CommandContext(ctx, "true")
		},
		sshContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "false")
		},
	}

	var out bytes.Buffer
	_, err := dp.Create(context.Background(), "test-droplet", nil, &out)
	if err == nil {
		t.Fatal("Create() expected error when tailscale IP lookup fails in lockdown mode, got nil")
	}
	if !strings.Contains(err.Error(), "failed to fetch tailscale IP in lockdown mode") {
		t.Errorf("error %q should mention lockdown tailscale IP failure", err.Error())
	}
}

func TestDigitalOceanProvider_Create_LockdownFailsWhenFirewallLockdownFails(t *testing.T) {
	var calls [][]string
	sshCalls := 0

	dp := &DigitalOceanProvider{
		SSHKey:            "ab:cd:ef:12:34",
		Size:              "s-2vcpu-4gb",
		TailscaleLockdown: true,
		lookPath:          doctlLookPathStub,
		sleep:             func(time.Duration) {},
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			calls = append(calls, append([]string{name}, args...))
			if len(args) >= 3 && args[0] == "compute" && args[1] == "droplet" && args[2] == "get" {
				return exec.CommandContext(ctx, "echo", "123456789 10.20.30.40")
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
	_, err := dp.Create(context.Background(), "test-droplet", nil, &out)
	if err == nil {
		t.Fatal("Create() expected error when firewall lockdown fails in lockdown mode, got nil")
	}
	if !strings.Contains(err.Error(), "failed to apply firewall lockdown in lockdown mode") {
		t.Errorf("error %q should mention lockdown firewall failure", err.Error())
	}

	var sawCleanupDelete bool
	for _, call := range calls {
		if strings.Join(call, " ") == "doctl compute droplet delete 123456789 --force" {
			sawCleanupDelete = true
			break
		}
	}
	if !sawCleanupDelete {
		t.Fatalf("expected cleanup delete call after lockdown failure, calls=%v", calls)
	}
}
