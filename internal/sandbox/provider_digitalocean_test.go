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

func TestGenerateDOCloudInit_LockdownDoesNotClosePublicSSHBeforeHalReadsTailscaleIP(t *testing.T) {
	yaml := generateDOCloudInit(map[string]string{"TAILSCALE_AUTHKEY": "tskey-auth-test"}, true)

	if !strings.Contains(yaml, "if tailscale up --authkey=\"$TAILSCALE_AUTHKEY\" --ssh --hostname=\"${TAILSCALE_HOSTNAME:-hal-sandbox}\" && tailscale ip -4 > /root/.tailscale-ip && [ -s /root/.tailscale-ip ]; then") {
		t.Fatalf("Tailscale IP write should be gated on a successful Tailscale join:\n%s", yaml)
	}
	for _, want := range []string{
		"tailscale ip -4 > /root/.tailscale-ip",
		"rm -f /root/.tailscale-ip",
	} {
		if !strings.Contains(yaml, want) {
			t.Fatalf("cloud-init missing %q:\n%s", want, yaml)
		}
	}
	for _, forbidden := range []string{
		"apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y ufw",
		"ufw allow in on tailscale0",
		"ufw allow proto tcp from 100.64.0.0/10 to any port 22",
		"ufw deny 22/tcp",
		"ufw --force enable",
		"touch /root/.hal-tailscale-lockdown",
	} {
		if strings.Contains(yaml, forbidden) {
			t.Fatalf("cloud-init must leave lockdown to Hal after IP capture; found %q:\n%s", forbidden, yaml)
		}
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
	var calls [][]string

	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			calls = append(calls, append([]string{name}, args...))
			if len(args) >= 4 && args[0] == "compute" && args[1] == "droplet" && args[2] == "get" {
				return exec.CommandContext(ctx, "echo", "off")
			}
			return exec.CommandContext(ctx, "true")
		},
	}

	var out bytes.Buffer
	err := dp.Stop(context.Background(), &ConnectInfo{Name: "my-droplet", WorkspaceID: "123456789"}, &out)
	if err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %v, want shutdown and status check", calls)
	}

	shutdownJoined := strings.Join(calls[0], " ")
	if !strings.Contains(shutdownJoined, "doctl compute droplet-action shutdown 123456789 --wait") {
		t.Errorf("stop args should contain shutdown --wait, got: %s", shutdownJoined)
	}
	statusJoined := strings.Join(calls[1], " ")
	if !strings.Contains(statusJoined, "doctl compute droplet get 123456789") || !strings.Contains(statusJoined, "--format Status") {
		t.Errorf("status args should check droplet status, got: %s", statusJoined)
	}
}

func TestDigitalOceanProvider_Stop_FallsBackToPowerOffWhenShutdownLeavesDropletRunning(t *testing.T) {
	var calls [][]string

	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			calls = append(calls, append([]string{name}, args...))
			if len(args) >= 4 && args[0] == "compute" && args[1] == "droplet" && args[2] == "get" {
				return exec.CommandContext(ctx, "echo", "active")
			}
			return exec.CommandContext(ctx, "true")
		},
	}

	if err := dp.Stop(context.Background(), &ConnectInfo{Name: "my-droplet", WorkspaceID: "123456789"}, &bytes.Buffer{}); err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("calls = %v, want shutdown, status check, power-off fallback", calls)
	}
	fallbackJoined := strings.Join(calls[2], " ")
	if !strings.Contains(fallbackJoined, "doctl compute droplet-action power-off 123456789 --wait") {
		t.Fatalf("fallback args = %q, want power-off --wait", fallbackJoined)
	}
}

func TestDigitalOceanProvider_Start_VerifiesArgsAndRefreshesIP(t *testing.T) {
	var calls [][]string

	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			calls = append(calls, append([]string{name}, args...))
			if len(args) >= 4 && args[0] == "compute" && args[1] == "droplet" && args[2] == "get" {
				return exec.CommandContext(ctx, "echo", "10.20.30.40")
			}
			return exec.CommandContext(ctx, "true")
		},
	}

	result, err := dp.Start(context.Background(), &ConnectInfo{Name: "my-droplet", WorkspaceID: "123456789"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}
	if result == nil || result.Status != StatusRunning || result.IP != "10.20.30.40" {
		t.Fatalf("result = %+v, want running with refreshed IP", result)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %v, want power-on and droplet get", calls)
	}
	powerJoined := strings.Join(calls[0], " ")
	if !strings.Contains(powerJoined, "doctl compute droplet-action power-on 123456789 --wait") {
		t.Fatalf("power-on args = %q, want power-on with --wait", powerJoined)
	}
	getJoined := strings.Join(calls[1], " ")
	if !strings.Contains(getJoined, "doctl compute droplet get 123456789") || !strings.Contains(getJoined, "--format PublicIPv4") {
		t.Fatalf("get args = %q, want public IP refresh", getJoined)
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

func TestDigitalOceanProvider_LifecycleOpsLookupWorkspaceIDFromName(t *testing.T) {
	tests := []struct {
		name string
		run  func(*DigitalOceanProvider, *ConnectInfo) error
	}{
		{
			name: "stop",
			run: func(p *DigitalOceanProvider, info *ConnectInfo) error {
				return p.Stop(context.Background(), info, &bytes.Buffer{})
			},
		},
		{
			name: "start",
			run: func(p *DigitalOceanProvider, info *ConnectInfo) error {
				_, err := p.Start(context.Background(), info, &bytes.Buffer{})
				return err
			},
		},
		{
			name: "delete",
			run: func(p *DigitalOceanProvider, info *ConnectInfo) error {
				return p.Delete(context.Background(), info, &bytes.Buffer{})
			},
		},
		{
			name: "status",
			run: func(p *DigitalOceanProvider, info *ConnectInfo) error {
				return p.Status(context.Background(), info, &bytes.Buffer{})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			dp := &DigitalOceanProvider{
				lookPath: doctlLookPathStub,
				cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
					calls = append(calls, strings.Join(append([]string{name}, args...), " "))
					return exec.CommandContext(ctx, "printf", "123456789\n")
				},
			}

			info := &ConnectInfo{Name: "my-droplet"}
			err := tt.run(dp, info)
			if err != nil {
				t.Fatalf("unexpected error for name fallback: %v", err)
			}
			if info.WorkspaceID != "123456789" {
				t.Fatalf("WorkspaceID = %q, want resolved droplet ID", info.WorkspaceID)
			}
			if len(calls) < 2 {
				t.Fatalf("doctl calls = %d, want lookup plus lifecycle call", len(calls))
			}
			if !strings.Contains(calls[0], "compute droplet get my-droplet --format ID --no-header") {
				t.Fatalf("first call = %q, want droplet ID lookup by name", calls[0])
			}
			if !strings.Contains(calls[1], "123456789") {
				t.Fatalf("second call = %q, want lifecycle command to use resolved ID", calls[1])
			}
		})
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
				return p.Stop(context.Background(), &ConnectInfo{}, &bytes.Buffer{})
			},
		},
		{
			name: "start",
			run: func(p *DigitalOceanProvider) error {
				_, err := p.Start(context.Background(), &ConnectInfo{}, &bytes.Buffer{})
				return err
			},
		},
		{
			name: "delete",
			run: func(p *DigitalOceanProvider) error {
				return p.Delete(context.Background(), &ConnectInfo{}, &bytes.Buffer{})
			},
		},
		{
			name: "status",
			run: func(p *DigitalOceanProvider) error {
				return p.Status(context.Background(), &ConnectInfo{}, &bytes.Buffer{})
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
				t.Fatalf("expected no doctl invocation when workspace ID and name are missing")
			}
		})
	}
}

func TestDigitalOceanProvider_DoctlNotFoundForLifecycleCommands(t *testing.T) {
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

	_, startErr := dp.Start(ctx, &ConnectInfo{Name: "test"}, &out)
	if startErr == nil || !strings.Contains(startErr.Error(), "doctl not found") {
		t.Errorf("Start() error = %v, want 'doctl not found'", startErr)
	}

	deleteErr := dp.Delete(ctx, &ConnectInfo{Name: "test"}, &out)
	if deleteErr == nil || !strings.Contains(deleteErr.Error(), "doctl not found") {
		t.Errorf("Delete() error = %v, want 'doctl not found'", deleteErr)
	}

	statusErr := dp.Status(ctx, &ConnectInfo{Name: "test"}, &out)
	if statusErr == nil || !strings.Contains(statusErr.Error(), "doctl not found") {
		t.Errorf("Status() error = %v, want 'doctl not found'", statusErr)
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

	wantArgs := []string{"ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes", "-o", "NumberOfPasswordPrompts=0", "-o", "LogLevel=ERROR", "root@10.20.30.40", "'ls' '-la'"}
	if len(cmd.Args) != len(wantArgs) {
		t.Fatalf("got args %v, want %v", cmd.Args, wantArgs)
	}
	for i, want := range wantArgs {
		if cmd.Args[i] != want {
			t.Errorf("Args[%d] = %q, want %q", i, cmd.Args[i], want)
		}
	}
}

func TestDigitalOceanProvider_SSH_LockdownPrefersTailscaleHostname(t *testing.T) {
	dp := &DigitalOceanProvider{
		TailscaleLockdown: true,
		lookPath:          doctlLookPathStub,
	}

	cmd, err := dp.SSH(&ConnectInfo{
		Name:              "my-droplet",
		IP:                "164.90.190.11",
		TailscaleIP:       "100.64.0.44",
		TailscaleHostname: "hal-dev-019ecfc3",
		TailscaleLockdown: true,
	})
	if err != nil {
		t.Fatalf("SSH() unexpected error: %v", err)
	}

	args := strings.Join(cmd.Args, " ")
	if !strings.Contains(args, "root@hal-dev-019ecfc3") {
		t.Fatalf("SSH cmd should contain root@hal-dev-019ecfc3, got: %s", args)
	}
	if strings.Contains(args, "root@164.90.190.11") {
		t.Fatalf("SSH cmd should not use public IP in lockdown mode, got: %s", args)
	}
	if strings.Contains(args, "root@100.64.0.44") {
		t.Fatalf("SSH cmd should not use Tailscale IP ahead of hostname in lockdown mode, got: %s", args)
	}
}

func TestDigitalOceanProvider_SSH_GlobalLockdownDoesNotOverrideInstanceConnectionState(t *testing.T) {
	dp := &DigitalOceanProvider{
		TailscaleLockdown: true,
		lookPath:          doctlLookPathStub,
	}

	cmd, err := dp.SSH(&ConnectInfo{
		Name:              "my-droplet",
		IP:                "164.90.190.11",
		TailscaleHostname: "hal-dev-019ecfc3",
	})
	if err != nil {
		t.Fatalf("SSH() unexpected error: %v", err)
	}

	args := strings.Join(cmd.Args, " ")
	if !strings.Contains(args, "root@164.90.190.11") {
		t.Fatalf("SSH cmd should contain root@164.90.190.11, got: %s", args)
	}
	if strings.Contains(args, "root@hal-dev-019ecfc3") {
		t.Fatalf("SSH cmd should not use hostname unless instance is lockdown-enabled, got: %s", args)
	}
}

func TestDigitalOceanProvider_SSH_MissingIP(t *testing.T) {
	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
	}

	_, err := dp.SSH(&ConnectInfo{})
	if err == nil {
		t.Fatal("SSH() expected error for missing IP, got nil")
	}
	if !strings.Contains(err.Error(), "sandbox IP is required") {
		t.Errorf("SSH() error %q should mention missing IP", err.Error())
	}
}

func TestDigitalOceanProvider_SSH_ResolvesIPFromWorkspaceID(t *testing.T) {
	var calls [][]string
	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			calls = append(calls, append([]string{name}, args...))
			return exec.CommandContext(ctx, "echo", "10.20.30.40")
		},
	}

	cmd, err := dp.SSH(&ConnectInfo{Name: "my-droplet", WorkspaceID: "123456789"})
	if err != nil {
		t.Fatalf("SSH() unexpected error: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("SSH() doctl calls = %d, want 1", len(calls))
	}
	lookupArgs := strings.Join(calls[0], " ")
	if !strings.Contains(lookupArgs, "doctl compute droplet get 123456789 --format PublicIPv4 --no-header") {
		t.Fatalf("SSH() lookup args = %q", lookupArgs)
	}
	if got := strings.Join(cmd.Args, " "); !strings.Contains(got, "root@10.20.30.40") {
		t.Fatalf("SSH() command = %q, want resolved IP", got)
	}
}

func TestDigitalOceanProvider_Exec_MissingIP(t *testing.T) {
	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
	}

	_, err := dp.Exec(&ConnectInfo{}, []string{"ls"})
	if err == nil {
		t.Fatal("Exec() expected error for missing IP, got nil")
	}
	if !strings.Contains(err.Error(), "sandbox IP is required") {
		t.Errorf("Exec() error %q should mention missing IP", err.Error())
	}
}

func TestDigitalOceanProvider_Exec_ResolvesIPFromName(t *testing.T) {
	var calls [][]string
	dp := &DigitalOceanProvider{
		lookPath: doctlLookPathStub,
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			calls = append(calls, append([]string{name}, args...))
			return exec.CommandContext(ctx, "echo", "10.20.30.40")
		},
	}

	cmd, err := dp.Exec(&ConnectInfo{Name: "my-droplet"}, []string{"ls"})
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("Exec() doctl calls = %d, want 1", len(calls))
	}
	lookupArgs := strings.Join(calls[0], " ")
	if !strings.Contains(lookupArgs, "doctl compute droplet get my-droplet --format PublicIPv4 --no-header") {
		t.Fatalf("Exec() lookup args = %q", lookupArgs)
	}
	if got := strings.Join(cmd.Args, " "); !strings.Contains(got, "root@10.20.30.40") {
		t.Fatalf("Exec() command = %q, want resolved IP", got)
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

func TestDigitalOceanProvider_Create_LockdownCleansUpWhenTailscaleIPUnavailable(t *testing.T) {
	var calls [][]string
	dp := &DigitalOceanProvider{
		SSHKey:            "ab:cd:ef:12:34",
		Size:              "s-2vcpu-4gb",
		TailscaleLockdown: true,
		lookPath:          doctlLookPathStub,
		sleep:             func(time.Duration) {},
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			calls = append(calls, append([]string{name}, args...))
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
	result, err := dp.Create(context.Background(), "test-droplet", nil, &out)
	if err == nil {
		t.Fatal("Create() expected error when tailscale IP lookup fails in lockdown mode, got nil")
	}
	if result != nil {
		t.Fatalf("Create() result = %#v, want nil on lockdown verification failure", result)
	}
	if !strings.Contains(err.Error(), "failed to fetch tailscale IP in lockdown mode") {
		t.Fatalf("error = %q, want tailscale IP failure", err.Error())
	}
	if !strings.Contains(out.String(), "Cleaning up test-droplet after failure (tailscale IP unavailable)") {
		t.Fatalf("output missing cleanup message: %q", out.String())
	}
	var deleted bool
	for _, call := range calls {
		if strings.Join(call, " ") == "doctl compute droplet delete 123456789 --force" {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("Create() should delete droplet on Tailscale verification failure, calls=%v", calls)
	}
}

func TestDigitalOceanProvider_Create_LockdownCleansUpWhenTailscaleHostnameVerificationFails(t *testing.T) {
	var calls [][]string
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
			return exec.CommandContext(ctx, "false")
		},
	}

	var out bytes.Buffer
	result, err := dp.Create(context.Background(), "test-droplet", map[string]string{"TAILSCALE_HOSTNAME": "hal-test-droplet-1234"}, &out)
	if err == nil {
		t.Fatal("Create() expected error when hostname verification fails, got nil")
	}
	if result != nil {
		t.Fatalf("Create() result = %#v, want nil on lockdown verification failure", result)
	}
	if !strings.Contains(err.Error(), "hostname \"hal-test-droplet-1234\"") {
		t.Fatalf("error = %q, want hostname verification failure", err.Error())
	}
	if !strings.Contains(out.String(), "Verifying Tailscale hostname hal-test-droplet-1234") {
		t.Fatalf("output missing hostname verification: %q", out.String())
	}
	if !strings.Contains(out.String(), "Falling back to public SSH") {
		t.Fatalf("output missing public SSH fallback: %q", out.String())
	}
	if !strings.Contains(out.String(), "Cleaning up test-droplet after failure (tailscale IP unavailable)") {
		t.Fatalf("output missing cleanup message: %q", out.String())
	}
	var deleted bool
	for _, call := range calls {
		if strings.Join(call, " ") == "doctl compute droplet delete 123456789 --force" {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("Create() should delete droplet when hostname and public IP verification fail, calls=%v", calls)
	}
}

func TestDigitalOceanTailscaleHostnameAttemptsPreferFastFallback(t *testing.T) {
	if digitalOceanTailscaleHostnameAttempts <= 0 {
		t.Fatalf("digitalOceanTailscaleHostnameAttempts = %d, want positive", digitalOceanTailscaleHostnameAttempts)
	}
	if digitalOceanTailscalePublicAttempts < 36 {
		t.Fatalf("digitalOceanTailscalePublicAttempts = %d, want enough budget for cloud-init Tailscale setup", digitalOceanTailscalePublicAttempts)
	}
	if digitalOceanTailscaleHostnameAttempts > 3 {
		t.Fatalf("digitalOceanTailscaleHostnameAttempts = %d, want fast fallback to public SSH", digitalOceanTailscaleHostnameAttempts)
	}
	if digitalOceanTailscaleHostnameAttempts >= digitalOceanTailscalePublicAttempts {
		t.Fatalf("hostname attempts = %d, public attempts = %d; hostname should be an opportunistic preflight", digitalOceanTailscaleHostnameAttempts, digitalOceanTailscalePublicAttempts)
	}
}

func TestDigitalOceanProvider_Create_LockdownFallsBackToPublicIPWhenHostnameUnavailable(t *testing.T) {
	var publicCatCalls int
	var hostnameCatCalls int

	dp := &DigitalOceanProvider{
		SSHKey:            "ab:cd:ef:12:34",
		Size:              "s-2vcpu-4gb",
		TailscaleLockdown: true,
		lookPath:          doctlLookPathStub,
		sleep:             func(time.Duration) {},
		cmdContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			if len(args) >= 3 && args[0] == "compute" && args[1] == "droplet" && args[2] == "get" {
				return exec.CommandContext(ctx, "echo", "123456789 10.20.30.40")
			}
			return exec.CommandContext(ctx, "true")
		},
		sshContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "root@hal-test-droplet-1234") && strings.Contains(joined, "cat /root/.tailscale-ip") {
				hostnameCatCalls++
				return exec.CommandContext(ctx, "false")
			}
			if strings.Contains(joined, "root@10.20.30.40") && strings.Contains(joined, "cat /root/.tailscale-ip") {
				publicCatCalls++
				return exec.CommandContext(ctx, "echo", "100.64.0.99")
			}
			return exec.CommandContext(ctx, "true")
		},
	}

	var out bytes.Buffer
	result, err := dp.Create(context.Background(), "test-droplet", map[string]string{"TAILSCALE_HOSTNAME": "hal-test-droplet-1234"}, &out)
	if err != nil {
		t.Fatalf("Create() unexpected error when public IP succeeds after hostname fallback: %v", err)
	}
	if result == nil || result.TailscaleIP != "100.64.0.99" {
		t.Fatalf("Create() result = %#v, want Tailscale IP from public fallback", result)
	}
	if hostnameCatCalls != digitalOceanTailscaleHostnameAttempts {
		t.Fatalf("Create() hostname lookups = %d, want %d before public fallback", hostnameCatCalls, digitalOceanTailscaleHostnameAttempts)
	}
	if publicCatCalls != 1 {
		t.Fatalf("Create() public IP Tailscale lookups = %d, want 1", publicCatCalls)
	}
	if !strings.Contains(out.String(), "Falling back to public SSH") {
		t.Fatalf("output missing public SSH fallback: %q", out.String())
	}
}

func TestDigitalOceanProvider_Create_LockdownPreservesDropletWhenTailscaleHostnameVerified(t *testing.T) {
	var calls [][]string
	var sshCalls [][]string
	var publicCatCalls int
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
			sshCalls = append(sshCalls, append([]string{name}, args...))
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "root@10.20.30.40") && strings.Contains(joined, "cat /root/.tailscale-ip") {
				publicCatCalls++
				return exec.CommandContext(ctx, "false")
			}
			if strings.Contains(joined, "root@hal-test-droplet-1234") {
				return exec.CommandContext(ctx, "echo", "100.64.0.99")
			}
			return exec.CommandContext(ctx, "false")
		},
	}

	var out bytes.Buffer
	result, err := dp.Create(context.Background(), "test-droplet", map[string]string{"TAILSCALE_HOSTNAME": "hal-test-droplet-1234"}, &out)
	if err != nil {
		t.Fatalf("Create() unexpected error when Tailscale hostname is verified: %v", err)
	}
	if result == nil || result.TailscaleIP != "100.64.0.99" {
		t.Fatalf("Create() result = %#v, want verified Tailscale IP", result)
	}
	if !strings.Contains(out.String(), "Verifying Tailscale hostname hal-test-droplet-1234") {
		t.Fatalf("output missing hostname verification: %q", out.String())
	}
	if publicCatCalls != 0 {
		t.Fatalf("Create() public IP Tailscale lookups = %d, want 0 when hostname succeeds", publicCatCalls)
	}
	for _, call := range sshCalls {
		if strings.Contains(strings.Join(call, " "), "ufw deny 22/tcp") {
			t.Fatalf("Create() should not apply public-IP firewall lockdown after hostname verification, sshCalls=%v", sshCalls)
		}
	}
	for _, call := range calls {
		if strings.Join(call, " ") == "doctl compute droplet delete 123456789 --force" {
			t.Fatalf("Create() should preserve droplet with verified Tailscale hostname, calls=%v", calls)
		}
	}
}

func TestDigitalOceanProvider_Create_LockdownVerifiesFirewallViaTailscaleIPBeforeHostname(t *testing.T) {
	var calls [][]string
	var verifyTargets []string

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
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "root@hal-test-droplet-1234") && strings.Contains(joined, "cat /root/.tailscale-ip"):
				return exec.CommandContext(ctx, "sh", "-c", "exit 1")
			case strings.Contains(joined, "root@10.20.30.40") && strings.Contains(joined, "cat /root/.tailscale-ip"):
				return exec.CommandContext(ctx, "echo", "100.64.0.99")
			case strings.Contains(joined, "root@10.20.30.40") && strings.Contains(joined, "ufw deny 22/tcp"):
				return exec.CommandContext(ctx, "sh", "-c", "exit 1")
			case strings.Contains(joined, "root@100.64.0.99") && strings.Contains(joined, digitalOceanLockdownMarker):
				verifyTargets = append(verifyTargets, "100.64.0.99")
				return exec.CommandContext(ctx, "true")
			case strings.Contains(joined, "root@hal-test-droplet-1234") && strings.Contains(joined, digitalOceanLockdownMarker):
				verifyTargets = append(verifyTargets, "hal-test-droplet-1234")
				return exec.CommandContext(ctx, "sh", "-c", "exit 1")
			default:
				return exec.CommandContext(ctx, "sh", "-c", "exit 1")
			}
		},
	}

	var out bytes.Buffer
	result, err := dp.Create(context.Background(), "test-droplet", map[string]string{"TAILSCALE_HOSTNAME": "hal-test-droplet-1234"}, &out)
	if err != nil {
		t.Fatalf("Create() unexpected error when firewall lockdown verifies over Tailscale IP: %v", err)
	}
	if result == nil || result.TailscaleIP != "100.64.0.99" {
		t.Fatalf("Create() result = %#v, want verified Tailscale IP", result)
	}
	if !strings.Contains(out.String(), "Warning: could not verify Tailscale hostname hal-test-droplet-1234") {
		t.Fatalf("output missing hostname failure warning before public fallback: %q", out.String())
	}
	if !strings.Contains(out.String(), "Verified firewall lockdown via Tailscale after public SSH closed") {
		t.Fatalf("output missing Tailscale IP verification: %q", out.String())
	}
	if len(verifyTargets) == 0 || verifyTargets[0] != "100.64.0.99" {
		t.Fatalf("lockdown verify targets = %v, want Tailscale IP before hostname", verifyTargets)
	}
	for _, call := range calls {
		if strings.Join(call, " ") == "doctl compute droplet delete 123456789 --force" {
			t.Fatalf("Create() should preserve droplet when Tailscale IP verification succeeds, calls=%v", calls)
		}
	}
}

func TestDigitalOceanProvider_Create_LockdownCleansUpWhenFirewallLockdownFails(t *testing.T) {
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
	result, err := dp.Create(context.Background(), "test-droplet", nil, &out)
	if err == nil {
		t.Fatal("Create() expected error when firewall lockdown cannot be verified, got nil")
	}
	if result != nil {
		t.Fatalf("Create() result = %#v, want nil on lockdown failure", result)
	}
	if !strings.Contains(err.Error(), "failed to apply firewall lockdown in lockdown mode") {
		t.Fatalf("error = %q, want firewall lockdown failure", err.Error())
	}
	if !strings.Contains(out.String(), "Cleaning up test-droplet after failure (firewall lockdown failed)") {
		t.Fatalf("output missing cleanup message: %q", out.String())
	}

	var deleted bool
	for _, call := range calls {
		if strings.Join(call, " ") == "doctl compute droplet delete 123456789 --force" {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("Create() should delete droplet when firewall lockdown cannot be verified, calls=%v", calls)
	}
}
