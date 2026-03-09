package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

type sandboxStopCall struct {
	called    bool
	apiKey    string
	serverURL string
	nameOrID  string
}

func fakeSandboxStopper(returnErr error) (sandboxStopper, *sandboxStopCall) {
	call := &sandboxStopCall{}
	fn := func(ctx context.Context, apiKey, serverURL, nameOrID string, out io.Writer) error {
		call.called = true
		call.apiKey = apiKey
		call.serverURL = serverURL
		call.nameOrID = nameOrID
		return returnErr
	}
	return fn, call
}

func setupStopTest(t *testing.T, dir string, apiKey, serverURL string) {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	cfg := &compound.DaytonaConfig{APIKey: apiKey, ServerURL: serverURL}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
}

func setupStopTestWithState(t *testing.T, dir string, apiKey, serverURL string, state *sandbox.SandboxState) {
	t.Helper()
	setupStopTest(t, dir, apiKey, serverURL)
	halDir := filepath.Join(dir, template.HalDir)
	if err := sandbox.SaveState(halDir, state); err != nil {
		t.Fatal(err)
	}
}

func TestRunSandboxStop(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string)
		stopName   string
		stopperErr error
		wantErr    string
		wantOutput string
		checkFn    func(t *testing.T, dir string, call *sandboxStopCall)
	}{
		{
			name: "stops sandbox from state file",
			setup: func(t *testing.T, dir string) {
				setupStopTestWithState(t, dir, "test-key", "https://api.example.com", &sandbox.SandboxState{
					Name:        "hal-feature-auth",
					SnapshotID:  "snap-123",
					WorkspaceID: "sb-001",
					Status:      "STARTED",
					CreatedAt:   time.Now(),
				})
			},
			wantOutput: `Sandbox "hal-feature-auth" stopped.`,
			checkFn: func(t *testing.T, dir string, call *sandboxStopCall) {
				if !call.called {
					t.Error("stopper was not called")
				}
				if call.apiKey != "test-key" {
					t.Errorf("apiKey = %q, want %q", call.apiKey, "test-key")
				}
				if call.serverURL != "https://api.example.com" {
					t.Errorf("serverURL = %q, want %q", call.serverURL, "https://api.example.com")
				}
				if call.nameOrID != "hal-feature-auth" {
					t.Errorf("nameOrID = %q, want %q", call.nameOrID, "hal-feature-auth")
				}
				// Verify state was updated to STOPPED
				halDir := filepath.Join(dir, template.HalDir)
				state, err := sandbox.LoadState(halDir)
				if err != nil {
					t.Fatalf("failed to load state: %v", err)
				}
				if state.Status != "STOPPED" {
					t.Errorf("state.Status = %q, want %q", state.Status, "STOPPED")
				}
			},
		},
		{
			name: "stops sandbox with explicit --name flag without mutating active state",
			setup: func(t *testing.T, dir string) {
				setupStopTestWithState(t, dir, "key2", "", &sandbox.SandboxState{
					Name:        "hal-feature-auth",
					SnapshotID:  "snap-123",
					WorkspaceID: "sb-001",
					Status:      "STARTED",
					CreatedAt:   time.Now(),
				})
			},
			stopName:   "my-custom-sandbox",
			wantOutput: `Sandbox "my-custom-sandbox" stopped.`,
			checkFn: func(t *testing.T, dir string, call *sandboxStopCall) {
				if call.nameOrID != "my-custom-sandbox" {
					t.Errorf("nameOrID = %q, want %q", call.nameOrID, "my-custom-sandbox")
				}
				halDir := filepath.Join(dir, template.HalDir)
				state, err := sandbox.LoadState(halDir)
				if err != nil {
					t.Fatalf("failed to load state: %v", err)
				}
				if state.Status != "STARTED" {
					t.Errorf("state.Status = %q, want %q", state.Status, "STARTED")
				}
			},
		},
		{
			name: "stops sandbox with explicit workspace id and updates active state",
			setup: func(t *testing.T, dir string) {
				setupStopTestWithState(t, dir, "key2", "", &sandbox.SandboxState{
					Name:        "hal-feature-auth",
					SnapshotID:  "snap-123",
					WorkspaceID: "sb-001",
					Status:      "STARTED",
					CreatedAt:   time.Now(),
				})
			},
			stopName:   "sb-001",
			wantOutput: `Sandbox "sb-001" stopped.`,
			checkFn: func(t *testing.T, dir string, call *sandboxStopCall) {
				if call.nameOrID != "sb-001" {
					t.Errorf("nameOrID = %q, want %q", call.nameOrID, "sb-001")
				}
				halDir := filepath.Join(dir, template.HalDir)
				state, err := sandbox.LoadState(halDir)
				if err != nil {
					t.Fatalf("failed to load state: %v", err)
				}
				if state.Status != "STOPPED" {
					t.Errorf("state.Status = %q, want %q", state.Status, "STOPPED")
				}
			},
		},
		{
			name: "error when .hal/ does not exist",
			setup: func(t *testing.T, dir string) {
				// don't create .hal/
			},
			wantErr: ".hal/ not found",
		},
		{
			name: "error when no sandbox state and no --name",
			setup: func(t *testing.T, dir string) {
				setupStopTest(t, dir, "key3", "")
			},
			wantErr: "no active sandbox",
		},
		{
			name: "error when SDK stop fails",
			setup: func(t *testing.T, dir string) {
				setupStopTestWithState(t, dir, "key4", "", &sandbox.SandboxState{
					Name:        "test-sandbox",
					SnapshotID:  "snap-456",
					WorkspaceID: "sb-002",
					Status:      "STARTED",
					CreatedAt:   time.Now(),
				})
			},
			stopperErr: fmt.Errorf("API error: sandbox not found"),
			wantErr:    "sandbox stop failed",
		},
		{
			name: "prints stopping message",
			setup: func(t *testing.T, dir string) {
				setupStopTestWithState(t, dir, "key5", "", &sandbox.SandboxState{
					Name:        "my-box",
					SnapshotID:  "snap-789",
					WorkspaceID: "sb-003",
					Status:      "STARTED",
					CreatedAt:   time.Now(),
				})
			},
			wantOutput: `Stopping sandbox "my-box"`,
		},
		{
			name: "preserves other state fields after stop",
			setup: func(t *testing.T, dir string) {
				setupStopTestWithState(t, dir, "key6", "", &sandbox.SandboxState{
					Name:        "preserved-sandbox",
					SnapshotID:  "snap-aaa",
					WorkspaceID: "sb-004",
					Status:      "STARTED",
					CreatedAt:   time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
				})
			},
			wantOutput: `Sandbox "preserved-sandbox" stopped.`,
			checkFn: func(t *testing.T, dir string, call *sandboxStopCall) {
				halDir := filepath.Join(dir, template.HalDir)
				state, err := sandbox.LoadState(halDir)
				if err != nil {
					t.Fatalf("failed to load state: %v", err)
				}
				if state.Name != "preserved-sandbox" {
					t.Errorf("state.Name = %q, want %q", state.Name, "preserved-sandbox")
				}
				if state.SnapshotID != "snap-aaa" {
					t.Errorf("state.SnapshotID = %q, want %q", state.SnapshotID, "snap-aaa")
				}
				if state.WorkspaceID != "sb-004" {
					t.Errorf("state.WorkspaceID = %q, want %q", state.WorkspaceID, "sb-004")
				}
				if state.Status != "STOPPED" {
					t.Errorf("state.Status = %q, want %q", state.Status, "STOPPED")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if tt.setup != nil {
				tt.setup(t, dir)
			}

			stopper, call := fakeSandboxStopper(tt.stopperErr)
			var out bytes.Buffer

			err := runSandboxStop(dir, tt.stopName, &out, stopper)

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

			if tt.wantOutput != "" && !strings.Contains(out.String(), tt.wantOutput) {
				t.Errorf("output %q does not contain %q", out.String(), tt.wantOutput)
			}

			if tt.checkFn != nil {
				tt.checkFn(t, dir, call)
			}
		})
	}
}

func TestRunSandboxStop_EnsureAuthCalled(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	// Save empty API key to config
	cfg := &compound.DaytonaConfig{APIKey: "", ServerURL: ""}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}

	stopper, _ := fakeSandboxStopper(nil)
	var out bytes.Buffer

	err := runSandboxStop(dir, "test-sandbox", &out, stopper)

	// Should fail because EnsureAuth will try interactive setup with os.Stdin
	// which doesn't have data, but the key will remain empty
	if err == nil {
		t.Fatal("expected error for empty API key, got nil")
	}
}
