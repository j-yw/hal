package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

// mockSSHProvider implements sandbox.Provider for SSH tests.
type mockSSHProvider struct {
	sshCmd    *exec.Cmd
	sshErr    error
	execCmd   *exec.Cmd
	execErr   error
	sshCalls  []sshCall
	execCalls []mockExecCall
}

type sshCall struct {
	Info *sandbox.ConnectInfo
}

type mockExecCall struct {
	Info *sandbox.ConnectInfo
	Args []string
}

func (m *mockSSHProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}
func (m *mockSSHProvider) Stop(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}
func (m *mockSSHProvider) Delete(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}
func (m *mockSSHProvider) Status(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}

func (m *mockSSHProvider) SSH(info *sandbox.ConnectInfo) (*exec.Cmd, error) {
	m.sshCalls = append(m.sshCalls, sshCall{Info: info})
	if m.sshErr != nil {
		return nil, m.sshErr
	}
	if m.sshCmd != nil {
		return m.sshCmd, nil
	}
	ip := "10.0.0.1"
	if info != nil && info.IP != "" {
		ip = info.IP
	}
	cmd := exec.Command("ssh", "root@"+ip)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func (m *mockSSHProvider) Exec(info *sandbox.ConnectInfo, args []string) (*exec.Cmd, error) {
	m.execCalls = append(m.execCalls, mockExecCall{Info: info, Args: args})
	if m.execErr != nil {
		return nil, m.execErr
	}
	if m.execCmd != nil {
		return m.execCmd, nil
	}
	ip := "10.0.0.1"
	if info != nil && info.IP != "" {
		ip = info.IP
	}
	cmdArgs := append([]string{"root@" + ip, "--"}, args...)
	cmd := exec.Command("ssh", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

// setupSSHTest registers a sandbox in the global registry and configures
// injectable vars for test isolation.
func setupSSHTest(t *testing.T, instances ...*sandbox.SandboxState) {
	t.Helper()
	tmpDir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", tmpDir)

	if err := sandbox.EnsureGlobalDir(); err != nil {
		t.Fatalf("ensure global dir: %v", err)
	}

	for _, inst := range instances {
		if err := sandbox.SaveInstance(inst); err != nil {
			t.Fatalf("save instance %q: %v", inst.Name, err)
		}
	}

	// Restore injectable vars on cleanup
	origLoad := sandboxSSHLoadInstance
	origResolve := sandboxSSHResolveProvider
	t.Cleanup(func() {
		sandboxSSHLoadInstance = origLoad
		sandboxSSHResolveProvider = origResolve
	})

	sandboxSSHLoadInstance = sandbox.LoadInstance
}

func TestRunSandboxSSH_InteractiveMode(t *testing.T) {
	setupSSHTest(t, &sandbox.SandboxState{
		Name:      "my-sandbox",
		Provider:  "daytona",
		IP:        "10.0.0.1",
		CreatedAt: time.Now(),
		Status:    sandbox.StatusRunning,
	})

	mock := &mockSSHProvider{}
	lastSSHCmd = nil
	var out bytes.Buffer

	err := runSandboxSSHWithDeps([]string{"my-sandbox"}, &out, mock, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.sshCalls) != 1 {
		t.Fatalf("expected 1 SSH call, got %d", len(mock.sshCalls))
	}
	if mock.sshCalls[0].Info.Name != "my-sandbox" {
		t.Errorf("SSH info.Name = %q, want %q", mock.sshCalls[0].Info.Name, "my-sandbox")
	}
	if mock.sshCalls[0].Info.IP != "10.0.0.1" {
		t.Errorf("SSH info.IP = %q, want %q", mock.sshCalls[0].Info.IP, "10.0.0.1")
	}

	if lastSSHCmd == nil {
		t.Fatal("expected lastSSHCmd to be set")
	}
	if !strings.Contains(strings.Join(lastSSHCmd.Args, " "), "ssh") {
		t.Errorf("expected SSH command, got %v", lastSSHCmd.Args)
	}
}

func TestRunSandboxSSH_InteractiveWithTailscaleIP(t *testing.T) {
	setupSSHTest(t, &sandbox.SandboxState{
		Name:        "my-sandbox",
		Provider:    "hetzner",
		IP:          "10.0.0.1",
		TailscaleIP: "100.64.0.5",
		CreatedAt:   time.Now(),
		Status:      sandbox.StatusRunning,
	})

	mock := &mockSSHProvider{}
	lastSSHCmd = nil

	err := runSandboxSSHWithDeps([]string{"my-sandbox"}, io.Discard, mock, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.sshCalls) != 1 {
		t.Fatalf("expected 1 SSH call, got %d", len(mock.sshCalls))
	}
	// PreferredIP should choose TailscaleIP over IP
	if mock.sshCalls[0].Info.IP != "100.64.0.5" {
		t.Errorf("SSH info.IP = %q, want %q (tailscale preferred)", mock.sshCalls[0].Info.IP, "100.64.0.5")
	}
}

func TestRunSandboxSSH_ExecMode(t *testing.T) {
	setupSSHTest(t, &sandbox.SandboxState{
		Name:      "my-sandbox",
		Provider:  "hetzner",
		IP:        "10.0.0.42",
		CreatedAt: time.Now(),
		Status:    sandbox.StatusRunning,
	})

	mock := &mockSSHProvider{}
	lastSSHCmd = nil

	err := runSandboxSSHWithDeps([]string{"my-sandbox", "--", "ls", "-la"}, io.Discard, mock, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.execCalls) != 1 {
		t.Fatalf("expected 1 Exec call, got %d", len(mock.execCalls))
	}
	if mock.execCalls[0].Info.Name != "my-sandbox" {
		t.Errorf("Exec info.Name = %q, want %q", mock.execCalls[0].Info.Name, "my-sandbox")
	}
	if mock.execCalls[0].Info.IP != "10.0.0.42" {
		t.Errorf("Exec info.IP = %q, want %q", mock.execCalls[0].Info.IP, "10.0.0.42")
	}
	wantArgs := []string{"ls", "-la"}
	if len(mock.execCalls[0].Args) != len(wantArgs) {
		t.Fatalf("Exec args = %v, want %v", mock.execCalls[0].Args, wantArgs)
	}
	for i, want := range wantArgs {
		if mock.execCalls[0].Args[i] != want {
			t.Errorf("Exec args[%d] = %q, want %q", i, mock.execCalls[0].Args[i], want)
		}
	}

	if lastSSHCmd == nil {
		t.Fatal("expected lastSSHCmd to be set")
	}
}

func TestRunSandboxSSH_AutoResolveSingle(t *testing.T) {
	setupSSHTest(t, &sandbox.SandboxState{
		Name:      "only-one",
		Provider:  "daytona",
		IP:        "10.0.0.1",
		CreatedAt: time.Now(),
		Status:    sandbox.StatusRunning,
	})

	mock := &mockSSHProvider{}
	var out bytes.Buffer

	err := runSandboxSSHWithDeps(nil, &out, mock, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should auto-select and print hint
	if !strings.Contains(out.String(), `connecting to only active sandbox "only-one"`) {
		t.Errorf("output %q should contain auto-connect hint", out.String())
	}

	if len(mock.sshCalls) != 1 {
		t.Fatalf("expected 1 SSH call, got %d", len(mock.sshCalls))
	}
	if mock.sshCalls[0].Info.Name != "only-one" {
		t.Errorf("SSH info.Name = %q, want %q", mock.sshCalls[0].Info.Name, "only-one")
	}
}

func TestRunSandboxSSH_AutoResolveNone(t *testing.T) {
	setupSSHTest(t) // No instances

	mock := &mockSSHProvider{}

	err := runSandboxSSHWithDeps(nil, io.Discard, mock, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no running sandboxes") {
		t.Errorf("error %q should contain 'no running sandboxes'", err.Error())
	}
}

func TestRunSandboxSSH_AutoResolveMultiple(t *testing.T) {
	setupSSHTest(t,
		&sandbox.SandboxState{
			Name:      "api-backend",
			Provider:  "daytona",
			IP:        "10.0.0.1",
			CreatedAt: time.Now(),
			Status:    sandbox.StatusRunning,
		},
		&sandbox.SandboxState{
			Name:      "frontend",
			Provider:  "hetzner",
			IP:        "10.0.0.2",
			CreatedAt: time.Now(),
			Status:    sandbox.StatusRunning,
		},
	)

	mock := &mockSSHProvider{}

	err := runSandboxSSHWithDeps(nil, io.Discard, mock, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "multiple sandboxes found") {
		t.Errorf("error %q should contain 'multiple sandboxes found'", err.Error())
	}
	if !strings.Contains(err.Error(), "api-backend") || !strings.Contains(err.Error(), "frontend") {
		t.Errorf("error %q should list sandbox names", err.Error())
	}
}

func TestRunSandboxSSH_NameNotFound(t *testing.T) {
	setupSSHTest(t) // No instances

	mock := &mockSSHProvider{}

	err := runSandboxSSHWithDeps([]string{"nonexistent"}, io.Discard, mock, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), `sandbox "nonexistent" not found`) {
		t.Errorf("error %q should contain not-found message", err.Error())
	}
}

func TestRunSandboxSSH_SSHError(t *testing.T) {
	setupSSHTest(t, &sandbox.SandboxState{
		Name:      "my-sandbox",
		Provider:  "hetzner",
		IP:        "10.0.0.1",
		CreatedAt: time.Now(),
		Status:    sandbox.StatusRunning,
	})

	mock := &mockSSHProvider{sshErr: fmt.Errorf("no IP in state")}

	err := runSandboxSSHWithDeps([]string{"my-sandbox"}, io.Discard, mock, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "building SSH command") {
		t.Errorf("error %q should contain 'building SSH command'", err.Error())
	}
}

func TestRunSandboxSSH_ExecError(t *testing.T) {
	setupSSHTest(t, &sandbox.SandboxState{
		Name:      "my-sandbox",
		Provider:  "hetzner",
		IP:        "10.0.0.1",
		CreatedAt: time.Now(),
		Status:    sandbox.StatusRunning,
	})

	mock := &mockSSHProvider{execErr: fmt.Errorf("exec failed")}

	err := runSandboxSSHWithDeps([]string{"my-sandbox", "--", "ls"}, io.Discard, mock, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "building exec command") {
		t.Errorf("error %q should contain 'building exec command'", err.Error())
	}
}

func TestRunSandboxSSH_ProviderResolveError(t *testing.T) {
	setupSSHTest(t, &sandbox.SandboxState{
		Name:      "my-sandbox",
		Provider:  "hetzner",
		IP:        "10.0.0.1",
		CreatedAt: time.Now(),
		Status:    sandbox.StatusRunning,
	})

	// Inject a failing provider resolver
	sandboxSSHResolveProvider = func(name string) (sandbox.Provider, error) {
		return nil, fmt.Errorf("no config found")
	}

	err := runSandboxSSHWithDeps([]string{"my-sandbox"}, io.Discard, nil, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "resolving provider") {
		t.Errorf("error %q should contain 'resolving provider'", err.Error())
	}
}

func TestRunSandboxSSH_ExecWithAutoResolve(t *testing.T) {
	setupSSHTest(t, &sandbox.SandboxState{
		Name:      "only-one",
		Provider:  "daytona",
		IP:        "10.0.0.1",
		CreatedAt: time.Now(),
		Status:    sandbox.StatusRunning,
	})

	mock := &mockSSHProvider{}
	var out bytes.Buffer

	// No name, just "-- ls -la"
	err := runSandboxSSHWithDeps([]string{"--", "ls", "-la"}, &out, mock, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should auto-select and print hint
	if !strings.Contains(out.String(), `connecting to only active sandbox "only-one"`) {
		t.Errorf("output %q should contain auto-connect hint", out.String())
	}

	// Should call Exec (not SSH) since we have remote args
	if len(mock.execCalls) != 1 {
		t.Fatalf("expected 1 Exec call, got %d", len(mock.execCalls))
	}
	if mock.execCalls[0].Info.Name != "only-one" {
		t.Errorf("Exec info.Name = %q, want %q", mock.execCalls[0].Info.Name, "only-one")
	}
}

func TestRunSandboxSSH_ConnectInfoUsesPreferredIP(t *testing.T) {
	setupSSHTest(t, &sandbox.SandboxState{
		Name:        "my-sandbox",
		Provider:    "hetzner",
		IP:          "10.0.0.1",
		TailscaleIP: "100.64.0.5",
		CreatedAt:   time.Now(),
		Status:      sandbox.StatusRunning,
	})

	mock := &mockSSHProvider{}

	err := runSandboxSSHWithDeps([]string{"my-sandbox", "--", "echo", "test"}, io.Discard, mock, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.execCalls) != 1 {
		t.Fatalf("expected 1 Exec call, got %d", len(mock.execCalls))
	}
	// PreferredIP should choose TailscaleIP
	if mock.execCalls[0].Info.IP != "100.64.0.5" {
		t.Errorf("Exec info.IP = %q, want %q (tailscale preferred)", mock.execCalls[0].Info.IP, "100.64.0.5")
	}
}

func TestRunSandboxSSH_AutoMigratesLegacyState(t *testing.T) {
	setupSSHTest(t, &sandbox.SandboxState{
		Name:      "my-sandbox",
		Provider:  "daytona",
		IP:        "10.0.0.1",
		CreatedAt: time.Now(),
		Status:    sandbox.StatusRunning,
	})

	origMigrate := sandboxMigrate
	t.Cleanup(func() {
		sandboxMigrate = origMigrate
	})

	called := false
	sandboxMigrate = func(projectDir string, out io.Writer) error {
		called = true
		if projectDir != "." {
			t.Fatalf("projectDir = %q, want %q", projectDir, ".")
		}
		return nil
	}

	mock := &mockSSHProvider{}

	if err := runSandboxSSHWithDeps([]string{"my-sandbox"}, io.Discard, mock, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !called {
		t.Fatal("expected legacy sandbox migration to run")
	}
}

func TestParseSSHArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantName   string
		wantRemote []string
	}{
		{
			name:       "no args",
			args:       nil,
			wantName:   "",
			wantRemote: nil,
		},
		{
			name:       "empty args",
			args:       []string{},
			wantName:   "",
			wantRemote: nil,
		},
		{
			name:       "name only",
			args:       []string{"my-sandbox"},
			wantName:   "my-sandbox",
			wantRemote: nil,
		},
		{
			name:       "name with dash-dash and command",
			args:       []string{"my-sandbox", "--", "ls", "-la"},
			wantName:   "my-sandbox",
			wantRemote: []string{"ls", "-la"},
		},
		{
			name:       "dash-dash only (no name)",
			args:       []string{"--", "ls"},
			wantName:   "",
			wantRemote: []string{"ls"},
		},
		{
			name:       "only dash-dash",
			args:       []string{"--"},
			wantName:   "",
			wantRemote: nil,
		},
		{
			name:       "flag-like first arg ignored as name",
			args:       []string{"--help"},
			wantName:   "",
			wantRemote: nil,
		},
		{
			name:       "name with empty command after dash-dash",
			args:       []string{"my-sandbox", "--"},
			wantName:   "my-sandbox",
			wantRemote: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotRemote := parseSSHArgs(tt.args)
			if gotName != tt.wantName {
				t.Errorf("name = %q, want %q", gotName, tt.wantName)
			}
			if len(gotRemote) != len(tt.wantRemote) {
				t.Fatalf("remote = %v, want %v", gotRemote, tt.wantRemote)
			}
			for i := range tt.wantRemote {
				if gotRemote[i] != tt.wantRemote[i] {
					t.Errorf("remote[%d] = %q, want %q", i, gotRemote[i], tt.wantRemote[i])
				}
			}
		})
	}
}

func TestResolveSSHTarget_ByName(t *testing.T) {
	setupSSHTest(t, &sandbox.SandboxState{
		Name:      "my-sandbox",
		Provider:  "daytona",
		IP:        "10.0.0.1",
		CreatedAt: time.Now(),
		Status:    sandbox.StatusRunning,
	})

	instance, hint, err := resolveSSHTarget("my-sandbox")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hint != "" {
		t.Errorf("expected no hint for explicit name, got %q", hint)
	}
	if instance.Name != "my-sandbox" {
		t.Errorf("Name = %q, want %q", instance.Name, "my-sandbox")
	}
}

func TestResolveSSHTarget_AutoResolveSingle(t *testing.T) {
	setupSSHTest(t, &sandbox.SandboxState{
		Name:      "only-one",
		Provider:  "daytona",
		IP:        "10.0.0.1",
		CreatedAt: time.Now(),
		Status:    sandbox.StatusRunning,
	})

	instance, hint, err := resolveSSHTarget("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(hint, `connecting to only active sandbox "only-one"`) {
		t.Errorf("hint %q should contain auto-connect message", hint)
	}
	if instance.Name != "only-one" {
		t.Errorf("Name = %q, want %q", instance.Name, "only-one")
	}
}

func TestResolveSSHTarget_AutoResolveNone(t *testing.T) {
	setupSSHTest(t)

	_, _, err := resolveSSHTarget("")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no running sandboxes") {
		t.Errorf("error %q should contain 'no running sandboxes'", err.Error())
	}
}

func TestResolveSSHTarget_AutoResolveMultiple(t *testing.T) {
	setupSSHTest(t,
		&sandbox.SandboxState{
			Name:      "alpha",
			Provider:  "daytona",
			IP:        "10.0.0.1",
			CreatedAt: time.Now(),
			Status:    sandbox.StatusRunning,
		},
		&sandbox.SandboxState{
			Name:      "beta",
			Provider:  "hetzner",
			IP:        "10.0.0.2",
			CreatedAt: time.Now(),
			Status:    sandbox.StatusRunning,
		},
	)

	_, _, err := resolveSSHTarget("")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "multiple sandboxes found") {
		t.Errorf("error %q should contain 'multiple sandboxes found'", err.Error())
	}
	if !strings.Contains(err.Error(), "alpha") || !strings.Contains(err.Error(), "beta") {
		t.Errorf("error %q should list sandbox names", err.Error())
	}
}

func TestResolveSSHTarget_AutoResolveIgnoresStopped(t *testing.T) {
	setupSSHTest(t, &sandbox.SandboxState{
		Name:      "stopped-only",
		Provider:  "daytona",
		IP:        "10.0.0.1",
		CreatedAt: time.Now(),
		Status:    sandbox.StatusStopped,
	})

	_, _, err := resolveSSHTarget("")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no running sandboxes") {
		t.Errorf("error %q should contain 'no running sandboxes'", err.Error())
	}
}

func TestResolveSSHTarget_ByNameWrapsLoadError(t *testing.T) {
	setupSSHTest(t)

	origLoad := sandboxSSHLoadInstance
	t.Cleanup(func() {
		sandboxSSHLoadInstance = origLoad
	})
	sandboxSSHLoadInstance = func(string) (*sandbox.SandboxState, error) {
		return nil, fmt.Errorf("parse sandbox %q: bad json", "broken")
	}

	_, _, err := resolveSSHTarget("broken")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), `load sandbox "broken"`) {
		t.Errorf("error %q should contain wrapped load message", err.Error())
	}
	if !strings.Contains(err.Error(), "bad json") {
		t.Errorf("error %q should preserve underlying error details", err.Error())
	}
}
