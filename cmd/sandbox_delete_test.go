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

// mockDeleteProvider implements sandbox.Provider for delete tests.
// Thread-safe for concurrent usage.
type mockDeleteProvider struct {
	mu             sync.Mutex
	deleteCalls    []string
	deleteErr      error
	deleteErrByName map[string]error
}

func (m *mockDeleteProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}

func (m *mockDeleteProvider) Stop(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}

func (m *mockDeleteProvider) Delete(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	name := ""
	if info != nil {
		name = info.Name
	}
	m.deleteCalls = append(m.deleteCalls, name)

	// Per-name error injection for partial failure tests
	if m.deleteErrByName != nil {
		if err, ok := m.deleteErrByName[name]; ok {
			return err
		}
	}
	return m.deleteErr
}

func (m *mockDeleteProvider) sortedDeleteCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	sorted := make([]string, len(m.deleteCalls))
	copy(sorted, m.deleteCalls)
	sort.Strings(sorted)
	return sorted
}

func (m *mockDeleteProvider) SSH(info *sandbox.ConnectInfo) (*exec.Cmd, error) { return nil, nil }
func (m *mockDeleteProvider) Exec(info *sandbox.ConnectInfo, args []string) (*exec.Cmd, error) {
	return nil, nil
}

func (m *mockDeleteProvider) Status(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}

func setupDeleteGlobalRegistry(t *testing.T, instances []*sandbox.SandboxState) {
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

func TestResolveDeleteTargets_ExplicitNames(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
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
			name:      "stopped sandbox can be targeted by name",
			args:      []string{"worker-01"},
			wantNames: []string{"worker-01"},
		},
		{
			name:    "unknown name returns error",
			args:    []string{"does-not-exist"},
			wantErr: "not found in registry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, _, err := resolveDeleteTargets(tt.args, false, "")

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

func TestResolveDeleteTargets_AllFlag(t *testing.T) {
	tests := []struct {
		name      string
		instances []*sandbox.SandboxState
		wantNames []string
		wantErr   string
	}{
		{
			name: "returns all sandboxes including stopped",
			instances: []*sandbox.SandboxState{
				{Name: "backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
				{Name: "frontend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
				{Name: "stopped-one", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
			},
			wantNames: []string{"backend", "frontend", "stopped-one"},
		},
		{
			name:      "empty registry returns error",
			instances: nil,
			wantErr:   "no sandboxes found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupDeleteGlobalRegistry(t, tt.instances)

			targets, _, err := resolveDeleteTargets(nil, true, "")

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

func TestResolveDeleteTargets_PatternFlag(t *testing.T) {
	tests := []struct {
		name      string
		instances []*sandbox.SandboxState
		pattern   string
		wantNames []string
		wantErr   string
	}{
		{
			name: "matches sandboxes by pattern",
			instances: []*sandbox.SandboxState{
				{Name: "worker-01", Provider: "hetzner", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
				{Name: "worker-02", Provider: "hetzner", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
				{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
			},
			pattern:   "worker-*",
			wantNames: []string{"worker-01", "worker-02"}, // includes stopped
		},
		{
			name: "no matches returns error",
			instances: []*sandbox.SandboxState{
				{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
			},
			pattern: "worker-*",
			wantErr: "no sandboxes matching pattern",
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
			setupDeleteGlobalRegistry(t, tt.instances)

			targets, _, err := resolveDeleteTargets(nil, false, tt.pattern)

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

func TestResolveDeleteTargets_AutoSelect(t *testing.T) {
	tests := []struct {
		name      string
		instances []*sandbox.SandboxState
		wantNames []string
		wantHint  string
		wantErr   string
	}{
		{
			name: "single sandbox auto-selects with hint",
			instances: []*sandbox.SandboxState{
				{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
			},
			wantNames: []string{"my-sandbox"},
			wantHint:  `Deleting only sandbox "my-sandbox"...`,
		},
		{
			name:      "zero sandboxes returns error",
			instances: nil,
			wantErr:   "no sandboxes found",
		},
		{
			name: "multiple sandboxes returns error with choices",
			instances: []*sandbox.SandboxState{
				{Name: "frontend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
				{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
				{Name: "worker-01", Provider: "hetzner", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
			},
			wantErr: "multiple sandboxes found: api-backend, frontend, worker-01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupDeleteGlobalRegistry(t, tt.instances)

			targets, hint, err := resolveDeleteTargets(nil, false, "")

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

func TestConfirmDeleteAll(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{name: "y confirms", input: "y\n", expect: true},
		{name: "yes confirms", input: "yes\n", expect: true},
		{name: "Y confirms", input: "Y\n", expect: true},
		{name: "YES confirms", input: "YES\n", expect: true},
		{name: "n declines", input: "n\n", expect: false},
		{name: "empty declines", input: "\n", expect: false},
		{name: "random text declines", input: "maybe\n", expect: false},
		{name: "EOF declines", input: "", expect: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := strings.NewReader(tt.input)
			var out bytes.Buffer
			got := confirmDeleteAll(in, &out)
			if got != tt.expect {
				t.Errorf("confirmDeleteAll(%q) = %v, want %v", tt.input, got, tt.expect)
			}
			if !strings.Contains(out.String(), "Delete all sandboxes? [y/N]") {
				t.Errorf("output %q missing prompt text", out.String())
			}
		})
	}
}

func TestRunSandboxDelete_ExplicitName(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	var out bytes.Buffer

	err := runSandboxDelete([]string{"my-sandbox"}, false, false, "", nil, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.deleteCalls) != 1 {
		t.Fatalf("expected 1 Delete call, got %d", len(mock.deleteCalls))
	}
	if mock.deleteCalls[0] != "my-sandbox" {
		t.Errorf("Delete name = %q, want %q", mock.deleteCalls[0], "my-sandbox")
	}
	if !strings.Contains(out.String(), "Deleted my-sandbox") {
		t.Errorf("output %q missing deleted message", out.String())
	}
}

func TestRunSandboxDelete_MultipleNames(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "frontend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	var out bytes.Buffer

	err := runSandboxDelete([]string{"frontend", "api-backend"}, false, false, "", nil, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Concurrent execution: use sorted assertions
	sorted := mock.sortedDeleteCalls()
	if len(sorted) != 2 {
		t.Fatalf("expected 2 Delete calls, got %d", len(sorted))
	}
	if sorted[0] != "api-backend" {
		t.Errorf("Delete[0] = %q, want %q", sorted[0], "api-backend")
	}
	if sorted[1] != "frontend" {
		t.Errorf("Delete[1] = %q, want %q", sorted[1], "frontend")
	}
}

func TestRunSandboxDelete_AutoSelectSingleSandbox(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "only-one", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	var out bytes.Buffer

	err := runSandboxDelete(nil, false, false, "", nil, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.deleteCalls) != 1 {
		t.Fatalf("expected 1 Delete call, got %d", len(mock.deleteCalls))
	}
	if mock.deleteCalls[0] != "only-one" {
		t.Errorf("Delete name = %q, want %q", mock.deleteCalls[0], "only-one")
	}
	if !strings.Contains(out.String(), `Deleting only sandbox "only-one"`) {
		t.Errorf("output %q missing auto-select hint", out.String())
	}
}

func TestRunSandboxDelete_NoSandboxesError(t *testing.T) {
	setupDeleteGlobalRegistry(t, nil)

	var out bytes.Buffer
	err := runSandboxDelete(nil, false, false, "", nil, &out, &mockDeleteProvider{})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no sandboxes found") {
		t.Errorf("error %q does not contain 'no sandboxes found'", err.Error())
	}
}

func TestRunSandboxDelete_MultipleSandboxesError(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "frontend", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
	})

	var out bytes.Buffer
	err := runSandboxDelete(nil, false, false, "", nil, &out, &mockDeleteProvider{})

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

func TestRunSandboxDelete_AllFlagWithYes(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "frontend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "stopped-one", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	var out bytes.Buffer

	err := runSandboxDelete(nil, true, true, "", nil, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All 3 sandboxes should be deleted (including stopped); concurrent, use sorted
	sorted := mock.sortedDeleteCalls()
	if len(sorted) != 3 {
		t.Fatalf("expected 3 Delete calls, got %d", len(sorted))
	}
	if sorted[0] != "api-backend" {
		t.Errorf("Delete[0] = %q, want %q", sorted[0], "api-backend")
	}
	if sorted[1] != "frontend" {
		t.Errorf("Delete[1] = %q, want %q", sorted[1], "frontend")
	}
	if sorted[2] != "stopped-one" {
		t.Errorf("Delete[2] = %q, want %q", sorted[2], "stopped-one")
	}
}

func TestRunSandboxDelete_AllFlagPromptConfirms(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	in := strings.NewReader("y\n")
	var out bytes.Buffer

	err := runSandboxDelete(nil, true, false, "", in, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.deleteCalls) != 1 {
		t.Fatalf("expected 1 Delete call, got %d", len(mock.deleteCalls))
	}
	if !strings.Contains(out.String(), "Delete all sandboxes? [y/N]") {
		t.Errorf("output %q missing confirmation prompt", out.String())
	}
}

func TestRunSandboxDelete_AllFlagPromptDeclines(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	in := strings.NewReader("n\n")
	var out bytes.Buffer

	err := runSandboxDelete(nil, true, false, "", in, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should NOT have called Delete
	if len(mock.deleteCalls) != 0 {
		t.Fatalf("expected 0 Delete calls, got %d", len(mock.deleteCalls))
	}
	if !strings.Contains(out.String(), "Aborted.") {
		t.Errorf("output %q missing abort message", out.String())
	}
}

func TestRunSandboxDelete_AllFlagPromptEOF(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	in := strings.NewReader("") // EOF
	var out bytes.Buffer

	err := runSandboxDelete(nil, true, false, "", in, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// EOF should be treated as decline
	if len(mock.deleteCalls) != 0 {
		t.Fatalf("expected 0 Delete calls, got %d", len(mock.deleteCalls))
	}
	if !strings.Contains(out.String(), "Aborted.") {
		t.Errorf("output %q missing abort message", out.String())
	}
}

func TestRunSandboxDelete_PatternFlag(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "worker-01", Provider: "hetzner", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "worker-02", Provider: "hetzner", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
		{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	var out bytes.Buffer

	err := runSandboxDelete(nil, false, false, "worker-*", nil, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both worker sandboxes should be deleted (including stopped); concurrent
	sorted := mock.sortedDeleteCalls()
	if len(sorted) != 2 {
		t.Fatalf("expected 2 Delete calls, got %d", len(sorted))
	}
	if sorted[0] != "worker-01" {
		t.Errorf("Delete[0] = %q, want %q", sorted[0], "worker-01")
	}
	if sorted[1] != "worker-02" {
		t.Errorf("Delete[1] = %q, want %q", sorted[1], "worker-02")
	}
}

func TestRunSandboxDelete_ProviderDeleteFails(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{deleteErr: fmt.Errorf("API error: sandbox not found")}
	var out bytes.Buffer

	err := runSandboxDelete([]string{"my-sandbox"}, false, false, "", nil, &out, mock)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "sandbox delete failed") {
		t.Errorf("error %q does not contain 'sandbox delete failed'", err.Error())
	}
}

func TestRunSandboxDelete_PrintsDeletingMessage(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-box", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	var out bytes.Buffer

	err := runSandboxDelete([]string{"my-box"}, false, false, "", nil, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), `Deleting sandbox "my-box"`) {
		t.Errorf("output %q missing deleting message", out.String())
	}
	if !strings.Contains(out.String(), "Deleted my-box") {
		t.Errorf("output %q missing deleted result line", out.String())
	}
}

func TestResolveDeleteTargets_DedupAndSort(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "charlie", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "alpha", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
		{Name: "bravo", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	// Provide names out of order with duplicates
	targets, _, err := resolveDeleteTargets([]string{"charlie", "alpha", "bravo", "charlie", "alpha"}, false, "")
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

func TestSandboxDeleteCommand_Flags(t *testing.T) {
	cmd := sandboxDeleteCmd

	if f := cmd.Flags().Lookup("all"); f == nil {
		t.Error("missing --all flag")
	}
	if f := cmd.Flags().Lookup("yes"); f == nil {
		t.Error("missing --yes flag")
	} else if f.Shorthand != "y" {
		t.Errorf("--yes shorthand = %q, want %q", f.Shorthand, "y")
	}
	if f := cmd.Flags().Lookup("pattern"); f == nil {
		t.Error("missing --pattern flag")
	}
	if cmd.Use != "delete [NAME ...]" {
		t.Errorf("Use = %q, want %q", cmd.Use, "delete [NAME ...]")
	}
}

func TestRunSandboxDelete_AllFlagNoSandboxes(t *testing.T) {
	setupDeleteGlobalRegistry(t, nil)

	var out bytes.Buffer
	err := runSandboxDelete(nil, true, true, "", nil, &out, &mockDeleteProvider{})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no sandboxes found") {
		t.Errorf("error %q does not contain 'no sandboxes found'", err.Error())
	}
}

func TestRunSandboxDelete_AutoSelectStoppedSandbox(t *testing.T) {
	// Delete auto-select works on all sandboxes, not just running
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "stopped-only", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	var out bytes.Buffer

	err := runSandboxDelete(nil, false, false, "", nil, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.deleteCalls) != 1 {
		t.Fatalf("expected 1 Delete call, got %d", len(mock.deleteCalls))
	}
	if mock.deleteCalls[0] != "stopped-only" {
		t.Errorf("Delete name = %q, want %q", mock.deleteCalls[0], "stopped-only")
	}
}

// --- US-038: Delete Execution and Registry Updates ---

func TestRunSandboxDelete_RegistryRemovalAfterSuccess(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	var out bytes.Buffer

	err := runSandboxDelete([]string{"my-sandbox"}, false, false, "", nil, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify sandbox was removed from registry
	_, loadErr := sandbox.LoadInstance("my-sandbox")
	if loadErr == nil {
		t.Fatal("expected registry entry to be removed after successful delete, but it still exists")
	}
}

func TestRunSandboxDelete_RegistryPreservedOnProviderFailure(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{deleteErr: fmt.Errorf("API error: not found")}
	var out bytes.Buffer

	err := runSandboxDelete([]string{"my-sandbox"}, false, false, "", nil, &out, mock)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Verify sandbox remains in registry when provider.Delete fails
	inst, loadErr := sandbox.LoadInstance("my-sandbox")
	if loadErr != nil {
		t.Fatalf("expected registry entry to be preserved, got load error: %v", loadErr)
	}
	if inst.Name != "my-sandbox" {
		t.Errorf("loaded Name = %q, want %q", inst.Name, "my-sandbox")
	}
}

func TestRunSandboxDelete_ConcurrentMultipleTargets(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "alpha", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "bravo", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "charlie", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	var out bytes.Buffer

	err := runSandboxDelete(nil, true, true, "", nil, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All 3 should be deleted concurrently
	sorted := mock.sortedDeleteCalls()
	if len(sorted) != 3 {
		t.Fatalf("expected 3 Delete calls, got %d", len(sorted))
	}
	wantNames := []string{"alpha", "bravo", "charlie"}
	for i, want := range wantNames {
		if sorted[i] != want {
			t.Errorf("Delete[%d] = %q, want %q", i, sorted[i], want)
		}
	}

	// All should be removed from registry
	for _, name := range wantNames {
		if _, err := sandbox.LoadInstance(name); err == nil {
			t.Errorf("expected %q to be removed from registry", name)
		}
	}
}

func TestRunSandboxDelete_ConcurrentRegistryUpdates(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "api-backend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "frontend", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	var out bytes.Buffer

	err := runSandboxDelete([]string{"api-backend", "frontend"}, false, false, "", nil, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both should be removed from registry
	if _, err := sandbox.LoadInstance("api-backend"); err == nil {
		t.Error("expected api-backend to be removed from registry")
	}
	if _, err := sandbox.LoadInstance("frontend"); err == nil {
		t.Error("expected frontend to be removed from registry")
	}
}

func TestRunSandboxDelete_PartialFailurePreservesSuccesses(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "alpha", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "bravo", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "charlie", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{
		deleteErrByName: map[string]error{
			"bravo": fmt.Errorf("API timeout"),
		},
	}
	var out bytes.Buffer

	err := runSandboxDelete(nil, true, true, "", nil, &out, mock)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "1/3 sandbox deletes failed") {
		t.Errorf("error %q does not match expected format", err.Error())
	}

	// alpha and charlie should be removed (success), bravo should remain (failed)
	if _, loadErr := sandbox.LoadInstance("alpha"); loadErr == nil {
		t.Error("expected alpha to be removed from registry")
	}
	if _, loadErr := sandbox.LoadInstance("bravo"); loadErr != nil {
		t.Error("expected bravo to remain in registry after failure")
	}
	if _, loadErr := sandbox.LoadInstance("charlie"); loadErr == nil {
		t.Error("expected charlie to be removed from registry")
	}
}

func TestRunSandboxDelete_AllFailExitsNonZero(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "alpha", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "bravo", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{deleteErr: fmt.Errorf("service unavailable")}
	var out bytes.Buffer

	err := runSandboxDelete(nil, true, true, "", nil, &out, mock)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "2/2 sandbox deletes failed") {
		t.Errorf("error %q does not match expected format", err.Error())
	}

	// Both should remain in registry
	if _, loadErr := sandbox.LoadInstance("alpha"); loadErr != nil {
		t.Error("expected alpha to remain in registry after failure")
	}
	if _, loadErr := sandbox.LoadInstance("bravo"); loadErr != nil {
		t.Error("expected bravo to remain in registry after failure")
	}
}

func TestRunSandboxDelete_AllSuccessExitsZero(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "alpha", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "bravo", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	var out bytes.Buffer

	err := runSandboxDelete(nil, true, true, "", nil, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both should be removed
	if _, loadErr := sandbox.LoadInstance("alpha"); loadErr == nil {
		t.Error("expected alpha to be removed from registry")
	}
	if _, loadErr := sandbox.LoadInstance("bravo"); loadErr == nil {
		t.Error("expected bravo to be removed from registry")
	}
}

func TestRunSandboxDelete_SingleTargetResultLine(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	var out bytes.Buffer

	err := runSandboxDelete([]string{"my-sandbox"}, false, false, "", nil, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), "Deleted my-sandbox") {
		t.Errorf("output %q missing result line", out.String())
	}
}

func TestRunSandboxDelete_MultiTargetResultLines(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "alpha", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "bravo", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{}
	var out bytes.Buffer

	err := runSandboxDelete(nil, true, true, "", nil, &out, mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Deleted alpha") {
		t.Errorf("output %q missing result line for alpha", output)
	}
	if !strings.Contains(output, "Deleted bravo") {
		t.Errorf("output %q missing result line for bravo", output)
	}
}

func TestRunSandboxDelete_PartialFailureResultLines(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "alpha", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "bravo", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{
		deleteErrByName: map[string]error{
			"bravo": fmt.Errorf("API error"),
		},
	}
	var out bytes.Buffer

	err := runSandboxDelete(nil, true, true, "", nil, &out, mock)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	output := out.String()
	if !strings.Contains(output, "Deleted alpha") {
		t.Errorf("output %q missing success line for alpha", output)
	}
	if !strings.Contains(output, "Failed bravo: API error") {
		t.Errorf("output %q missing failure line for bravo", output)
	}
}

func TestRunSandboxDelete_SingleTargetProviderFailureNoRegistryRemoval(t *testing.T) {
	setupDeleteGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "my-sandbox", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})

	mock := &mockDeleteProvider{deleteErr: fmt.Errorf("connection refused")}
	var out bytes.Buffer

	err := runSandboxDelete([]string{"my-sandbox"}, false, false, "", nil, &out, mock)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "sandbox delete failed") {
		t.Errorf("error %q does not contain 'sandbox delete failed'", err.Error())
	}

	// Registry entry should be preserved
	inst, loadErr := sandbox.LoadInstance("my-sandbox")
	if loadErr != nil {
		t.Fatalf("expected registry entry to be preserved, got: %v", loadErr)
	}
	if inst.Name != "my-sandbox" {
		t.Errorf("loaded Name = %q, want %q", inst.Name, "my-sandbox")
	}
}
