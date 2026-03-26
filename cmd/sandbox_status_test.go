package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

// mockStatusProvider implements sandbox.Provider for status tests.
type mockStatusProvider struct {
	statusCalls []*sandbox.ConnectInfo
	statusErr   error
	statusOut   string
}

func (m *mockStatusProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}
func (m *mockStatusProvider) Stop(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}
func (m *mockStatusProvider) Delete(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}
func (m *mockStatusProvider) SSH(info *sandbox.ConnectInfo) (*exec.Cmd, error) { return nil, nil }
func (m *mockStatusProvider) Exec(info *sandbox.ConnectInfo, args []string) (*exec.Cmd, error) {
	return nil, nil
}

func (m *mockStatusProvider) Status(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	m.statusCalls = append(m.statusCalls, info)
	if m.statusOut != "" {
		fmt.Fprint(out, m.statusOut)
	}
	return m.statusErr
}

func setupStatusTest(t *testing.T) (cleanup func()) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", dir)
	if err := sandbox.EnsureGlobalDir(); err != nil {
		t.Fatal(err)
	}
	return func() {}
}

func saveStatusTestInstance(t *testing.T, inst *sandbox.SandboxState) {
	t.Helper()
	if err := sandbox.ForceWriteInstance(inst); err != nil {
		t.Fatal(err)
	}
}

func TestRunSandboxStatus_DetailedView(t *testing.T) {
	setupStatusTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	created := now.Add(-3 * time.Hour)
	origNow := sandboxStatusNow
	sandboxStatusNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxStatusNow = origNow })

	saveStatusTestInstance(t, &sandbox.SandboxState{
		ID:                "01234567-89ab-7cde-8f01-234567890abc",
		Name:              "my-sandbox",
		Provider:          "hetzner",
		WorkspaceID:       "ws-123",
		IP:                "203.0.113.1",
		TailscaleIP:       "100.64.0.1",
		TailscaleHostname: "hal-my-sandbox",
		Status:            sandbox.StatusRunning,
		CreatedAt:         created,
		AutoShutdown:      true,
		IdleHours:         48,
		Size:              "cx22",
		Repo:              "github.com/example/repo",
	})

	mock := &mockStatusProvider{}
	var out bytes.Buffer

	err := runSandboxStatusWithDeps("my-sandbox", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()

	// Identity
	assertContains(t, output, "Name:       my-sandbox")
	assertContains(t, output, "ID:         01234567-89ab-7cde-8f01-234567890abc")
	assertContains(t, output, "Provider:   hetzner")
	assertContains(t, output, "Status:     running")
	assertContains(t, output, "Live query: ok")

	// Networking
	assertContains(t, output, "Public IP:          203.0.113.1")
	assertContains(t, output, "Tailscale IP:       100.64.0.1")
	assertContains(t, output, "Tailscale Hostname: hal-my-sandbox")
	assertContains(t, output, "Active SSH IP:      100.64.0.1")
	assertContains(t, output, "Workspace ID:       ws-123")

	// Lifecycle
	assertContains(t, output, "Created:")
	assertContains(t, output, "3h ago")

	// Config
	assertContains(t, output, "Auto-shutdown: on (48h idle)")
	assertContains(t, output, "Size:          cx22")

	// Labels
	assertContains(t, output, "Repo:       github.com/example/repo")

	// Provider was queried with correct ConnectInfo
	if len(mock.statusCalls) != 1 {
		t.Fatalf("expected 1 status call, got %d", len(mock.statusCalls))
	}
	if mock.statusCalls[0].Name != "my-sandbox" {
		t.Errorf("status call name = %q, want %q", mock.statusCalls[0].Name, "my-sandbox")
	}
	// PreferredIP should be TailscaleIP
	if mock.statusCalls[0].IP != "100.64.0.1" {
		t.Errorf("status call IP = %q, want %q (tailscale preferred)", mock.statusCalls[0].IP, "100.64.0.1")
	}
}

func TestRunSandboxStatus_LiveQueryFailed(t *testing.T) {
	setupStatusTest(t)

	saveStatusTestInstance(t, &sandbox.SandboxState{
		Name:      "fail-sandbox",
		Provider:  "hetzner",
		IP:        "203.0.113.2",
		Status:    sandbox.StatusRunning,
		CreatedAt: time.Now(),
	})

	mock := &mockStatusProvider{statusErr: fmt.Errorf("connection refused")}
	var out bytes.Buffer

	err := runSandboxStatusWithDeps("fail-sandbox", &out, mock)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	assertContains(t, err.Error(), `live sandbox status for "fail-sandbox"`)
	assertContains(t, err.Error(), "connection refused")

	output := out.String()
	assertContains(t, output, "Status:     running")
	assertContains(t, output, "Live query: failed (connection refused)")
}

func TestRunSandboxStatus_UsesProviderReportedStatus(t *testing.T) {
	setupStatusTest(t)

	saveStatusTestInstance(t, &sandbox.SandboxState{
		Name:      "live-stopped",
		Provider:  "digitalocean",
		ID:        "droplet-123",
		Status:    sandbox.StatusRunning,
		CreatedAt: time.Now(),
	})

	mock := &mockStatusProvider{statusOut: "Status: off"}
	var out bytes.Buffer

	err := runSandboxStatusWithDeps("live-stopped", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	assertContains(t, output, "Status:     stopped")
	assertContains(t, output, "Live query: ok")
}

func TestRunSandboxStatus_PersistsProviderReportedStatus(t *testing.T) {
	setupStatusTest(t)

	saveStatusTestInstance(t, &sandbox.SandboxState{
		Name:      "persisted-status",
		Provider:  "daytona",
		Status:    sandbox.StatusRunning,
		CreatedAt: time.Now(),
	})

	mock := &mockStatusProvider{statusOut: "Status: off"}
	var out bytes.Buffer

	if err := runSandboxStatusWithDeps("persisted-status", &out, mock); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	loaded, err := sandbox.LoadInstance("persisted-status")
	if err != nil {
		t.Fatalf("LoadInstance() unexpected error: %v", err)
	}
	if loaded.Status != sandbox.StatusStopped {
		t.Fatalf("loaded status = %q, want %q", loaded.Status, sandbox.StatusStopped)
	}
}

func TestRunSandboxStatus_ContinuesWhenLocalSyncFails(t *testing.T) {
	projectDir := t.TempDir()
	t.Chdir(projectDir)
	t.Setenv("HAL_CONFIG_HOME", filepath.Join(projectDir, "config"))
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", projectDir)
	if err := sandbox.EnsureGlobalDir(); err != nil {
		t.Fatal(err)
	}

	halDir := filepath.Join(projectDir, template.HalDir)
	if err := os.MkdirAll(filepath.Join(halDir, template.SandboxFile), 0o755); err != nil {
		t.Fatalf("MkdirAll sandbox path: %v", err)
	}

	saveStatusTestInstance(t, &sandbox.SandboxState{
		ID:        "id-1",
		Name:      "warn-box",
		Provider:  "daytona",
		Status:    sandbox.StatusRunning,
		CreatedAt: time.Now(),
	})

	mock := &mockStatusProvider{statusOut: "Status: off"}
	var out bytes.Buffer

	if err := runSandboxStatusWithDeps("warn-box", &out, mock); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	assertContains(t, output, "Live query: ok")
	assertContains(t, output, "Warning:")
	assertContains(t, output, "local sandbox state sync failed")

	loaded, err := sandbox.LoadInstance("warn-box")
	if err != nil {
		t.Fatalf("LoadInstance() unexpected error: %v", err)
	}
	if loaded.Status != sandbox.StatusStopped {
		t.Fatalf("loaded status = %q, want %q", loaded.Status, sandbox.StatusStopped)
	}
}

func TestRunSandboxStatus_NotFound(t *testing.T) {
	setupStatusTest(t)

	var out bytes.Buffer
	err := runSandboxStatusWithDeps("nonexistent", &out, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	assertContains(t, err.Error(), `sandbox "nonexistent" not found in registry`)
}

func TestRunSandboxStatus_LoadInstanceError(t *testing.T) {
	setupStatusTest(t)

	origLoad := sandboxStatusLoadInstance
	sandboxStatusLoadInstance = func(name string) (*sandbox.SandboxState, error) {
		return nil, fmt.Errorf("parse sandbox %q: invalid character", name)
	}
	t.Cleanup(func() { sandboxStatusLoadInstance = origLoad })

	var out bytes.Buffer
	err := runSandboxStatusWithDeps("broken", &out, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	assertContains(t, err.Error(), `load sandbox "broken" from registry`)
	assertContains(t, err.Error(), `parse sandbox "broken"`)
	if strings.Contains(err.Error(), "not found in registry") {
		t.Fatalf("expected parse error to be preserved, got %q", err.Error())
	}
}

func TestRunSandboxStatus_ProviderResolveError(t *testing.T) {
	setupStatusTest(t)

	saveStatusTestInstance(t, &sandbox.SandboxState{
		Name:      "test-sb",
		Provider:  "hetzner",
		Status:    sandbox.StatusRunning,
		CreatedAt: time.Now(),
	})

	origResolve := sandboxStatusResolveProvider
	sandboxStatusResolveProvider = func(name string) (sandbox.Provider, error) {
		return nil, fmt.Errorf("no hetzner credentials")
	}
	t.Cleanup(func() { sandboxStatusResolveProvider = origResolve })

	var out bytes.Buffer
	err := runSandboxStatusWithDeps("test-sb", &out, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	assertContains(t, err.Error(), "resolving provider")
	assertContains(t, err.Error(), "no hetzner credentials")
}

func TestRunSandboxStatus_AutoMigratesLegacyState(t *testing.T) {
	setupStatusTest(t)

	origMigrate := sandboxMigrate
	t.Cleanup(func() {
		sandboxMigrate = origMigrate
	})
	sandboxMigrate = func(projectDir string, out io.Writer) error {
		if projectDir != "." {
			t.Fatalf("projectDir = %q, want %q", projectDir, ".")
		}
		return sandbox.SaveInstance(&sandbox.SandboxState{
			Name:      "migrated-box",
			Provider:  "daytona",
			Status:    sandbox.StatusRunning,
			CreatedAt: time.Now(),
		})
	}

	mock := &mockStatusProvider{}
	var out bytes.Buffer

	if err := runSandboxStatusWithDeps("migrated-box", &out, mock); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.statusCalls) != 1 {
		t.Fatalf("expected 1 provider status call, got %d", len(mock.statusCalls))
	}
	assertContains(t, out.String(), "Name:       migrated-box")
}

func TestRunSandboxStatus_MinimalFields(t *testing.T) {
	setupStatusTest(t)

	saveStatusTestInstance(t, &sandbox.SandboxState{
		Name:      "minimal",
		Provider:  "daytona",
		Status:    sandbox.StatusRunning,
		CreatedAt: time.Now(),
	})

	mock := &mockStatusProvider{}
	var out bytes.Buffer

	err := runSandboxStatusWithDeps("minimal", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	assertContains(t, output, "Name:       minimal")
	assertContains(t, output, "Provider:   daytona")
	assertContains(t, output, "Public IP:          —")
	assertContains(t, output, "Tailscale IP:       —")
	assertContains(t, output, "Auto-shutdown: off")

	// Should NOT contain labels section when no repo/snapshot
	if strings.Contains(output, "Labels:") {
		t.Error("output should not contain Labels section for minimal instance")
	}
	// Should NOT contain Tailscale Hostname when empty
	if strings.Contains(output, "Tailscale Hostname:") {
		t.Error("output should not contain Tailscale Hostname when empty")
	}
}

func TestRunSandboxStatus_StoppedInstance(t *testing.T) {
	setupStatusTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	created := now.Add(-24 * time.Hour)
	stopped := now.Add(-2 * time.Hour)
	origNow := sandboxStatusNow
	sandboxStatusNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxStatusNow = origNow })

	saveStatusTestInstance(t, &sandbox.SandboxState{
		Name:      "stopped-sb",
		Provider:  "digitalocean",
		IP:        "198.51.100.1",
		Status:    sandbox.StatusStopped,
		CreatedAt: created,
		StoppedAt: &stopped,
		Size:      "s-2vcpu-4gb",
	})

	mock := &mockStatusProvider{}
	var out bytes.Buffer

	err := runSandboxStatusWithDeps("stopped-sb", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	assertContains(t, output, "Status:     stopped")
	assertContains(t, output, "Stopped:")
	assertContains(t, output, "2h ago")
	assertContains(t, output, "Created:")
	assertContains(t, output, "1d ago")
	assertContains(t, output, "Size:          s-2vcpu-4gb")
}

func TestRunSandboxStatus_WithSnapshotID(t *testing.T) {
	setupStatusTest(t)

	saveStatusTestInstance(t, &sandbox.SandboxState{
		Name:       "snap-sb",
		Provider:   "hetzner",
		Status:     sandbox.StatusRunning,
		CreatedAt:  time.Now(),
		SnapshotID: "snap-42",
	})

	mock := &mockStatusProvider{}
	var out bytes.Buffer

	err := runSandboxStatusWithDeps("snap-sb", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	assertContains(t, output, "Labels:")
	assertContains(t, output, "Snapshot:   snap-42")
}

func TestRunSandboxStatus_NoArgsListDelegation(t *testing.T) {
	setupStatusTest(t)

	// Save some instances so list has data
	saveStatusTestInstance(t, &sandbox.SandboxState{
		Name:      "sb-one",
		Provider:  "hetzner",
		Status:    sandbox.StatusRunning,
		CreatedAt: time.Now(),
	})
	saveStatusTestInstance(t, &sandbox.SandboxState{
		Name:      "sb-two",
		Provider:  "daytona",
		Status:    sandbox.StatusStopped,
		CreatedAt: time.Now(),
	})

	var out bytes.Buffer
	// Calling runSandboxList directly (what the no-args path delegates to)
	err := runSandboxList(&out, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	// Should have table columns from list command
	assertContains(t, output, "NAME")
	assertContains(t, output, "PROVIDER")
	assertContains(t, output, "STATUS")
	assertContains(t, output, "sb-one")
	assertContains(t, output, "sb-two")
	assertContains(t, output, "2 sandboxes")
}

func TestRunSandboxStatus_NoArgsEmptyRegistry(t *testing.T) {
	setupStatusTest(t)

	var out bytes.Buffer
	err := runSandboxList(&out, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertContains(t, out.String(), "No sandboxes found")
}

func TestRunSandboxStatus_CostDisplay(t *testing.T) {
	setupStatusTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	created := now.Add(-10 * time.Hour)
	origNow := sandboxStatusNow
	sandboxStatusNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxStatusNow = origNow })

	saveStatusTestInstance(t, &sandbox.SandboxState{
		Name:      "cost-sb",
		Provider:  "hetzner",
		Status:    sandbox.StatusRunning,
		CreatedAt: created,
		Size:      "cx22",
	})

	mock := &mockStatusProvider{}
	var out bytes.Buffer

	err := runSandboxStatusWithDeps("cost-sb", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	assertContains(t, output, "Est. cost:")
	assertContains(t, output, "$")
}

func TestRunSandboxStatus_PublicIPPreferred(t *testing.T) {
	setupStatusTest(t)

	saveStatusTestInstance(t, &sandbox.SandboxState{
		Name:      "public-ip-sb",
		Provider:  "hetzner",
		IP:        "203.0.113.5",
		Status:    sandbox.StatusRunning,
		CreatedAt: time.Now(),
	})

	mock := &mockStatusProvider{}
	var out bytes.Buffer

	err := runSandboxStatusWithDeps("public-ip-sb", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	assertContains(t, output, "Public IP:          203.0.113.5")
	assertContains(t, output, "Active SSH IP:      203.0.113.5")
	assertContains(t, output, "Tailscale IP:       —")
}

func TestSandboxStatusCommand_AcceptsOptionalName(t *testing.T) {
	// Verify command accepts 0 or 1 args
	if err := sandboxStatusCmd.Args(sandboxStatusCmd, []string{}); err != nil {
		t.Fatalf("status should accept 0 args: %v", err)
	}
	if err := sandboxStatusCmd.Args(sandboxStatusCmd, []string{"my-sandbox"}); err != nil {
		t.Fatalf("status should accept 1 arg: %v", err)
	}
	if err := sandboxStatusCmd.Args(sandboxStatusCmd, []string{"a", "b"}); err == nil {
		t.Fatal("status should reject 2 args")
	}
}

func TestSandboxStatusCommand_Metadata(t *testing.T) {
	if sandboxStatusCmd.Use == "" {
		t.Error("Use must be set")
	}
	if sandboxStatusCmd.Short == "" {
		t.Error("Short must be set")
	}
	if sandboxStatusCmd.Long == "" {
		t.Error("Long must be set")
	}
	if sandboxStatusCmd.Example == "" {
		t.Error("Example must be set")
	}
	if !strings.Contains(sandboxStatusCmd.Example, "hal sandbox status") {
		t.Error("Example should include full command path")
	}
}

// assertContains is a test helper that checks if output contains a substring.
func assertContains(t *testing.T, output, want string) {
	t.Helper()
	if !strings.Contains(output, want) {
		t.Errorf("output does not contain %q\noutput:\n%s", want, output)
	}
}
