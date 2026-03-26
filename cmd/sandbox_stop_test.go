package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

// mockStopProvider implements sandbox.Provider for stop tests.
// Supports per-name error injection via stopErrByName for concurrent tests.
type mockStopProvider struct {
	mu            sync.Mutex
	stopCalls     []string
	stopErr       error
	stopErrByName map[string]error
}

func (m *mockStopProvider) sortedStopCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	sorted := make([]string, len(m.stopCalls))
	copy(sorted, m.stopCalls)
	sort.Strings(sorted)
	return sorted
}

func (m *mockStopProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}

func (m *mockStopProvider) Stop(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	m.mu.Lock()
	if info != nil {
		m.stopCalls = append(m.stopCalls, info.Name)
	} else {
		m.stopCalls = append(m.stopCalls, "")
	}
	m.mu.Unlock()

	// Per-name error injection takes precedence over global stopErr
	if m.stopErrByName != nil && info != nil {
		if err, ok := m.stopErrByName[info.Name]; ok {
			return err
		}
	}
	return m.stopErr
}

func (m *mockStopProvider) Delete(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}

func (m *mockStopProvider) SSH(info *sandbox.ConnectInfo) (*exec.Cmd, error) { return nil, nil }
func (m *mockStopProvider) Exec(info *sandbox.ConnectInfo, args []string) (*exec.Cmd, error) {
	return nil, nil
}

func (m *mockStopProvider) Status(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}

func setupStopGlobalRegistry(t *testing.T, instances []*sandbox.SandboxState) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", dir)
	if err := sandbox.EnsureGlobalDir(); err != nil {
		t.Fatal(err)
	}
	for _, inst := range instances {
		if err := sandbox.ForceWriteInstance(inst); err != nil {
			t.Fatal(err)
		}
	}
}

func TestResolveStopTargets_ExplicitNames(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "frontend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "worker-01", Provider: "hetzner", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
	})

	tests := []struct {
		name      string
		args      []string
		wantNames []string
		wantErr   string
	}{
		{
			name:      "single explicit name",
			args:      []string{"api-backend"},
			wantNames: []string{"api-backend"},
		},
		{
			name:      "multiple explicit names",
			args:      []string{"frontend", "api-backend"},
			wantNames: []string{"api-backend", "frontend"}, // sorted
		},
		{
			name:      "duplicate names are de-duplicated",
			args:      []string{"frontend", "frontend", "api-backend"},
			wantNames: []string{"api-backend", "frontend"},
		},
		{
			name:    "stopped sandbox targeted by name returns error",
			args:    []string{"worker-01"},
			wantErr: "is not running",
		},
		{
			name:    "unknown name returns error",
			args:    []string{"does-not-exist"},
			wantErr: "not found in registry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, _, err := resolveStopTargets(tt.args, false, "")

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			gotNames := make([]string, len(targets))
			for i, tgt := range targets {
				gotNames[i] = tgt.Name
			}
			if len(gotNames) != len(tt.wantNames) {
				t.Fatalf("got %d targets %v, want %d %v", len(gotNames), gotNames, len(tt.wantNames), tt.wantNames)
			}
			for i, want := range tt.wantNames {
				if gotNames[i] != want {
					t.Errorf("target[%d] = %q, want %q", i, gotNames[i], want)
				}
			}
		})
	}
}

func TestResolveStopTargets_AllFlag(t *testing.T) {
	tests := []struct {
		name      string
		instances []*sandbox.SandboxState
		wantNames []string
		wantErr   string
	}{
		{
			name: "returns all running sandboxes",
			instances: []*sandbox.SandboxState{
				{Name: "backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
				{Name: "frontend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
				{Name: "stopped-one", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
			},
			wantNames: []string{"backend", "frontend"},
		},
		{
			name: "no running sandboxes returns error",
			instances: []*sandbox.SandboxState{
				{Name: "stopped-one", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
			},
			wantErr: "no running sandboxes",
		},
		{
			name:      "empty registry returns error",
			instances: nil,
			wantErr:   "no running sandboxes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupStopGlobalRegistry(t, tt.instances)

			targets, _, err := resolveStopTargets(nil, true, "")

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			gotNames := make([]string, len(targets))
			for i, tgt := range targets {
				gotNames[i] = tgt.Name
			}
			if len(gotNames) != len(tt.wantNames) {
				t.Fatalf("got %d targets %v, want %d %v", len(gotNames), gotNames, len(tt.wantNames), tt.wantNames)
			}
			for i, want := range tt.wantNames {
				if gotNames[i] != want {
					t.Errorf("target[%d] = %q, want %q", i, gotNames[i], want)
				}
			}
		})
	}
}

func TestResolveStopTargets_PatternFlag(t *testing.T) {
	tests := []struct {
		name      string
		instances []*sandbox.SandboxState
		pattern   string
		wantNames []string
		wantErr   string
	}{
		{
			name: "matches running sandboxes by pattern",
			instances: []*sandbox.SandboxState{
				{Name: "worker-01", Provider: "hetzner", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
				{Name: "worker-02", Provider: "hetzner", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
				{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
			},
			pattern:   "worker-*",
			wantNames: []string{"worker-01", "worker-02"},
		},
		{
			name: "skips stopped sandboxes even if pattern matches",
			instances: []*sandbox.SandboxState{
				{Name: "worker-01", Provider: "hetzner", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
				{Name: "worker-02", Provider: "hetzner", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
			},
			pattern:   "worker-*",
			wantNames: []string{"worker-01"},
		},
		{
			name: "no matches returns error",
			instances: []*sandbox.SandboxState{
				{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
			},
			pattern: "worker-*",
			wantErr: "no running sandboxes matching pattern",
		},
		{
			name:      "invalid pattern returns error",
			instances: []*sandbox.SandboxState{},
			pattern:   "[invalid",
			wantErr:   "invalid pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupStopGlobalRegistry(t, tt.instances)

			targets, _, err := resolveStopTargets(nil, false, tt.pattern)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			gotNames := make([]string, len(targets))
			for i, tgt := range targets {
				gotNames[i] = tgt.Name
			}
			if len(gotNames) != len(tt.wantNames) {
				t.Fatalf("got %d targets %v, want %d %v", len(gotNames), gotNames, len(tt.wantNames), tt.wantNames)
			}
			for i, want := range tt.wantNames {
				if gotNames[i] != want {
					t.Errorf("target[%d] = %q, want %q", i, gotNames[i], want)
				}
			}
		})
	}
}

func TestResolveStopTargets_AutoSelect(t *testing.T) {
	tests := []struct {
		name      string
		instances []*sandbox.SandboxState
		wantNames []string
		wantHint  string
		wantErr   string
	}{
		{
			name: "single running sandbox auto-selects with hint",
			instances: []*sandbox.SandboxState{
				{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
				{Name: "stopped-one", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
			},
			wantNames: []string{"my-sandbox"},
			wantHint:  `Stopping only running sandbox "my-sandbox"...`,
		},
		{
			name: "zero running sandboxes returns error",
			instances: []*sandbox.SandboxState{
				{Name: "stopped-one", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
			},
			wantErr: "no running sandboxes",
		},
		{
			name:      "empty registry returns error",
			instances: nil,
			wantErr:   "no running sandboxes",
		},
		{
			name: "multiple running sandboxes returns error with choices",
			instances: []*sandbox.SandboxState{
				{Name: "frontend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
				{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
				{Name: "worker-01", Provider: "hetzner", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
			},
			wantErr: "multiple running sandboxes found: api-backend, frontend, worker-01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupStopGlobalRegistry(t, tt.instances)

			targets, hint, err := resolveStopTargets(nil, false, "")

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			gotNames := make([]string, len(targets))
			for i, tgt := range targets {
				gotNames[i] = tgt.Name
			}
			if len(gotNames) != len(tt.wantNames) {
				t.Fatalf("got %d targets %v, want %d %v", len(gotNames), gotNames, len(tt.wantNames), tt.wantNames)
			}
			for i, want := range tt.wantNames {
				if gotNames[i] != want {
					t.Errorf("target[%d] = %q, want %q", i, gotNames[i], want)
				}
			}

			if tt.wantHint != "" && hint != tt.wantHint {
				t.Errorf("hint = %q, want %q", hint, tt.wantHint)
			}
		})
	}
}

func TestRunSandboxStop_ExplicitName(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockStopProvider{}
	var out bytes.Buffer

	err := runSandboxStop([]string{"my-sandbox"}, false, "", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.stopCalls) != 1 {
		t.Fatalf("expected 1 Stop call, got %d", len(mock.stopCalls))
	}
	if mock.stopCalls[0] != "my-sandbox" {
		t.Errorf("Stop name = %q, want %q", mock.stopCalls[0], "my-sandbox")
	}
	if !strings.Contains(out.String(), "Stopped my-sandbox") {
		t.Errorf("output %q missing stopped message", out.String())
	}
}

func TestRunSandboxStop_MultipleNames(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "frontend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockStopProvider{}
	var out bytes.Buffer

	err := runSandboxStop([]string{"frontend", "api-backend"}, false, "", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Concurrent execution — use sorted calls for deterministic assertions
	sorted := mock.sortedStopCalls()
	if len(sorted) != 2 {
		t.Fatalf("expected 2 Stop calls, got %d", len(sorted))
	}
	if sorted[0] != "api-backend" {
		t.Errorf("Stop[0] = %q, want %q", sorted[0], "api-backend")
	}
	if sorted[1] != "frontend" {
		t.Errorf("Stop[1] = %q, want %q", sorted[1], "frontend")
	}
}

func TestRunSandboxStop_AutoSelectSingleRunning(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "only-one", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockStopProvider{}
	var out bytes.Buffer

	err := runSandboxStop(nil, false, "", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.stopCalls) != 1 {
		t.Fatalf("expected 1 Stop call, got %d", len(mock.stopCalls))
	}
	if mock.stopCalls[0] != "only-one" {
		t.Errorf("Stop name = %q, want %q", mock.stopCalls[0], "only-one")
	}
	if !strings.Contains(out.String(), `Stopping only running sandbox "only-one"`) {
		t.Errorf("output %q missing auto-select hint", out.String())
	}
}

func TestRunSandboxStop_NoRunningError(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "stopped-one", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
	})

	var out bytes.Buffer
	err := runSandboxStop(nil, false, "", &out, &mockStopProvider{})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no running sandboxes") {
		t.Errorf("error %q does not contain 'no running sandboxes'", err.Error())
	}
}

func TestRunSandboxStop_MultipleRunningError(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "frontend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	var out bytes.Buffer
	err := runSandboxStop(nil, false, "", &out, &mockStopProvider{})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "api-backend") {
		t.Errorf("error %q missing 'api-backend'", err.Error())
	}
	if !strings.Contains(err.Error(), "frontend") {
		t.Errorf("error %q missing 'frontend'", err.Error())
	}
}

func TestRunSandboxStop_AllFlag(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "frontend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "stopped-one", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
	})

	mock := &mockStopProvider{}
	var out bytes.Buffer

	err := runSandboxStop(nil, true, "", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sorted := mock.sortedStopCalls()
	if len(sorted) != 2 {
		t.Fatalf("expected 2 Stop calls, got %d", len(sorted))
	}
	if sorted[0] != "api-backend" {
		t.Errorf("Stop[0] = %q, want %q", sorted[0], "api-backend")
	}
	if sorted[1] != "frontend" {
		t.Errorf("Stop[1] = %q, want %q", sorted[1], "frontend")
	}
}

func TestRunSandboxStop_PatternFlag(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "worker-01", Provider: "hetzner", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "worker-02", Provider: "hetzner", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockStopProvider{}
	var out bytes.Buffer

	err := runSandboxStop(nil, false, "worker-*", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sorted := mock.sortedStopCalls()
	if len(sorted) != 2 {
		t.Fatalf("expected 2 Stop calls, got %d", len(sorted))
	}
	if sorted[0] != "worker-01" {
		t.Errorf("Stop[0] = %q, want %q", sorted[0], "worker-01")
	}
	if sorted[1] != "worker-02" {
		t.Errorf("Stop[1] = %q, want %q", sorted[1], "worker-02")
	}
}

func TestRunSandboxStop_ProviderStopFails(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockStopProvider{stopErr: fmt.Errorf("connection timeout")}
	var out bytes.Buffer

	err := runSandboxStop([]string{"my-sandbox"}, false, "", &out, mock)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "sandbox stop failed") {
		t.Errorf("error %q does not contain 'sandbox stop failed'", err.Error())
	}
}

func TestRunSandboxStop_PrintsStoppingMessage(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-box", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockStopProvider{}
	var out bytes.Buffer

	err := runSandboxStop([]string{"my-box"}, false, "", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), `Stopping sandbox "my-box"`) {
		t.Errorf("output %q missing stopping message", out.String())
	}
}

func TestRunSandboxStop_AutoMigratesLegacyState(t *testing.T) {
	setupStopGlobalRegistry(t, nil)

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

	mock := &mockStopProvider{}
	var out bytes.Buffer

	if err := runSandboxStop(nil, false, "", &out, mock); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sorted := mock.sortedStopCalls()
	if len(sorted) != 1 {
		t.Fatalf("expected 1 Stop call, got %d", len(sorted))
	}
	if sorted[0] != "migrated-box" {
		t.Fatalf("Stop target = %q, want %q", sorted[0], "migrated-box")
	}
}

func TestResolveStopTargets_DedupAndSort(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "charlie", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "alpha", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "bravo", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	// Provide names out of order with duplicates
	targets, _, err := resolveStopTargets([]string{"charlie", "alpha", "bravo", "charlie", "alpha"}, false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(targets) != 3 {
		t.Fatalf("got %d targets, want 3", len(targets))
	}
	wantOrder := []string{"alpha", "bravo", "charlie"}
	for i, want := range wantOrder {
		if targets[i].Name != want {
			t.Errorf("target[%d] = %q, want %q", i, targets[i].Name, want)
		}
	}
}

func TestSandboxStopCommand_Flags(t *testing.T) {
	cmd := sandboxStopCmd

	if f := cmd.Flags().Lookup("all"); f == nil {
		t.Error("missing --all flag")
	}
	if f := cmd.Flags().Lookup("pattern"); f == nil {
		t.Error("missing --pattern flag")
	}
	if cmd.Use != "stop [NAME ...]" {
		t.Errorf("Use = %q, want %q", cmd.Use, "stop [NAME ...]")
	}
}

// --- US-037: Execution and Registry Update Tests ---

func TestRunSandboxStop_UpdatesRegistryStatusAndStoppedAt(t *testing.T) {
	createdAt := time.Date(2026, 3, 21, 10, 0, 0, 0, time.UTC)
	stoppedTime := time.Date(2026, 3, 21, 14, 30, 0, 0, time.UTC)

	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: createdAt},
	})

	// Inject deterministic time
	origNow := sandboxStopNow
	sandboxStopNow = func() time.Time { return stoppedTime }
	t.Cleanup(func() { sandboxStopNow = origNow })

	mock := &mockStopProvider{}
	var out bytes.Buffer

	err := runSandboxStop([]string{"my-sandbox"}, false, "", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify registry was updated
	inst, err := sandbox.LoadInstance("my-sandbox")
	if err != nil {
		t.Fatalf("failed to load instance: %v", err)
	}
	if inst.Status != sandbox.StatusStopped {
		t.Errorf("Status = %q, want %q", inst.Status, sandbox.StatusStopped)
	}
	if inst.StoppedAt == nil {
		t.Fatal("StoppedAt is nil, expected non-nil")
	}
	if !inst.StoppedAt.Equal(stoppedTime) {
		t.Errorf("StoppedAt = %v, want %v", *inst.StoppedAt, stoppedTime)
	}
}

func TestRunSandboxStop_ConcurrentMultipleTargets(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "frontend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "worker-01", Provider: "hetzner", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockStopProvider{}
	var out bytes.Buffer

	err := runSandboxStop([]string{"api-backend", "frontend", "worker-01"}, false, "", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sorted := mock.sortedStopCalls()
	if len(sorted) != 3 {
		t.Fatalf("expected 3 Stop calls, got %d", len(sorted))
	}
	want := []string{"api-backend", "frontend", "worker-01"}
	for i, name := range want {
		if sorted[i] != name {
			t.Errorf("sorted call[%d] = %q, want %q", i, sorted[i], name)
		}
	}

	// Verify each target has result line in output
	output := out.String()
	for _, name := range want {
		if !strings.Contains(output, "Stopped "+name) {
			t.Errorf("output missing result line for %q", name)
		}
	}
}

func TestRunSandboxStop_ConcurrentUpdatesRegistry(t *testing.T) {
	stoppedTime := time.Date(2026, 3, 21, 15, 0, 0, 0, time.UTC)

	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "alpha", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "bravo", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	origNow := sandboxStopNow
	sandboxStopNow = func() time.Time { return stoppedTime }
	t.Cleanup(func() { sandboxStopNow = origNow })

	mock := &mockStopProvider{}
	var out bytes.Buffer

	err := runSandboxStop([]string{"alpha", "bravo"}, false, "", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both should be updated in registry
	for _, name := range []string{"alpha", "bravo"} {
		inst, err := sandbox.LoadInstance(name)
		if err != nil {
			t.Fatalf("failed to load %q: %v", name, err)
		}
		if inst.Status != sandbox.StatusStopped {
			t.Errorf("%s Status = %q, want %q", name, inst.Status, sandbox.StatusStopped)
		}
		if inst.StoppedAt == nil {
			t.Errorf("%s StoppedAt is nil", name)
		} else if !inst.StoppedAt.Equal(stoppedTime) {
			t.Errorf("%s StoppedAt = %v, want %v", name, *inst.StoppedAt, stoppedTime)
		}
	}
}

func TestRunSandboxStop_PartialFailurePreservesSuccessfulUpdates(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "alpha", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "bravo", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "charlie", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockStopProvider{
		stopErrByName: map[string]error{
			"bravo": fmt.Errorf("connection timeout"),
		},
	}
	var out bytes.Buffer

	err := runSandboxStop([]string{"alpha", "bravo", "charlie"}, false, "", &out, mock)

	// Should return non-zero (error)
	if err == nil {
		t.Fatal("expected error for partial failure, got nil")
	}
	if !strings.Contains(err.Error(), "1/3 sandbox stops failed") {
		t.Errorf("error %q does not match expected format", err.Error())
	}

	// alpha and charlie should be stopped in registry
	for _, name := range []string{"alpha", "charlie"} {
		inst, err := sandbox.LoadInstance(name)
		if err != nil {
			t.Fatalf("failed to load %q: %v", name, err)
		}
		if inst.Status != sandbox.StatusStopped {
			t.Errorf("%s Status = %q, want %q", name, inst.Status, sandbox.StatusStopped)
		}
	}

	// bravo should remain running
	bravo, err := sandbox.LoadInstance("bravo")
	if err != nil {
		t.Fatalf("failed to load bravo: %v", err)
	}
	if bravo.Status != sandbox.StatusRunning {
		t.Errorf("bravo Status = %q, want %q (should remain running after failure)", bravo.Status, sandbox.StatusRunning)
	}

	// Output should have result lines for each
	output := out.String()
	if !strings.Contains(output, "Stopped alpha") {
		t.Error("output missing success line for alpha")
	}
	if !strings.Contains(output, "Failed bravo") {
		t.Error("output missing failure line for bravo")
	}
	if !strings.Contains(output, "Stopped charlie") {
		t.Error("output missing success line for charlie")
	}
}

func TestRunSandboxStop_AllFailsExitsNonZero(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "alpha", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "bravo", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockStopProvider{stopErr: fmt.Errorf("provider down")}
	var out bytes.Buffer

	err := runSandboxStop(nil, true, "", &out, mock)
	if err == nil {
		t.Fatal("expected error when all targets fail, got nil")
	}
	if !strings.Contains(err.Error(), "2/2 sandbox stops failed") {
		t.Errorf("error %q does not match expected format", err.Error())
	}

	// Both should remain running in registry
	for _, name := range []string{"alpha", "bravo"} {
		inst, err := sandbox.LoadInstance(name)
		if err != nil {
			t.Fatalf("failed to load %q: %v", name, err)
		}
		if inst.Status != sandbox.StatusRunning {
			t.Errorf("%s Status = %q, want running", name, inst.Status)
		}
	}
}

func TestRunSandboxStop_SingleTargetResultLine(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockStopProvider{}
	var out bytes.Buffer

	err := runSandboxStop([]string{"my-sandbox"}, false, "", &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Stopped my-sandbox") {
		t.Errorf("output %q missing result line", output)
	}
}

func TestRunSandboxStop_SingleTargetFailResultLine(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockStopProvider{stopErr: fmt.Errorf("timeout")}
	var out bytes.Buffer

	err := runSandboxStop([]string{"my-sandbox"}, false, "", &out, mock)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "sandbox stop failed") {
		t.Errorf("error %q missing expected text", err.Error())
	}
}

func TestRunSandboxStop_MultipleTargetsResultLines(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "alpha", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "bravo", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "charlie", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockStopProvider{
		stopErrByName: map[string]error{
			"bravo": fmt.Errorf("network error"),
		},
	}
	var out bytes.Buffer

	_ = runSandboxStop([]string{"alpha", "bravo", "charlie"}, false, "", &out, mock)

	output := out.String()
	// Each target should have exactly one result line
	if !strings.Contains(output, "Stopped alpha") {
		t.Error("output missing 'Stopped alpha'")
	}
	if !strings.Contains(output, "Failed bravo: network error") {
		t.Error("output missing 'Failed bravo: network error'")
	}
	if !strings.Contains(output, "Stopped charlie") {
		t.Error("output missing 'Stopped charlie'")
	}
}

func TestRunSandboxStop_AllSuccessExitsZero(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "alpha", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "bravo", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockStopProvider{}
	var out bytes.Buffer

	err := runSandboxStop(nil, true, "", &out, mock)
	if err != nil {
		t.Fatalf("expected nil error when all succeed, got: %v", err)
	}
}

func TestUpdateStoppedState(t *testing.T) {
	stoppedTime := time.Date(2026, 3, 21, 16, 0, 0, 0, time.UTC)

	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "test-box", Provider: "hetzner", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	origNow := sandboxStopNow
	sandboxStopNow = func() time.Time { return stoppedTime }
	t.Cleanup(func() { sandboxStopNow = origNow })

	target := &sandbox.SandboxState{Name: "test-box", Provider: "hetzner", Status: sandbox.StatusRunning}
	err := updateStoppedState(target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify in-memory struct was updated
	if target.Status != sandbox.StatusStopped {
		t.Errorf("Status = %q, want %q", target.Status, sandbox.StatusStopped)
	}
	if target.StoppedAt == nil || !target.StoppedAt.Equal(stoppedTime) {
		t.Errorf("StoppedAt = %v, want %v", target.StoppedAt, stoppedTime)
	}

	// Verify persisted state
	loaded, err := sandbox.LoadInstance("test-box")
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}
	if loaded.Status != sandbox.StatusStopped {
		t.Errorf("persisted Status = %q, want %q", loaded.Status, sandbox.StatusStopped)
	}
	if loaded.StoppedAt == nil || !loaded.StoppedAt.Equal(stoppedTime) {
		t.Errorf("persisted StoppedAt = %v, want %v", loaded.StoppedAt, stoppedTime)
	}
}
