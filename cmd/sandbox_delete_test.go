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

type sandboxDeleteCall struct {
	called    bool
	apiKey    string
	serverURL string
	nameOrID  string
}

func fakeSandboxDeleter(returnErr error) (sandboxDeleter, *sandboxDeleteCall) {
	call := &sandboxDeleteCall{}
	fn := func(ctx context.Context, apiKey, serverURL, nameOrID string, out io.Writer) error {
		call.called = true
		call.apiKey = apiKey
		call.serverURL = serverURL
		call.nameOrID = nameOrID
		return returnErr
	}
	return fn, call
}

func setupDeleteTest(t *testing.T, dir string, apiKey, serverURL string) {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	cfg := &compound.DaytonaConfig{APIKey: apiKey, ServerURL: serverURL}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
}

func setupDeleteTestWithState(t *testing.T, dir string, apiKey, serverURL string, state *sandbox.SandboxState) {
	t.Helper()
	setupDeleteTest(t, dir, apiKey, serverURL)
	halDir := filepath.Join(dir, template.HalDir)
	if err := sandbox.SaveState(halDir, state); err != nil {
		t.Fatal(err)
	}
}

func TestRunSandboxDelete(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string)
		deleteName string
		deleterErr error
		wantErr    string
		wantOutput string
		checkFn    func(t *testing.T, dir string, call *sandboxDeleteCall)
	}{
		{
			name: "deletes sandbox from state file",
			setup: func(t *testing.T, dir string) {
				setupDeleteTestWithState(t, dir, "test-key", "https://api.example.com", &sandbox.SandboxState{
					Name:        "hal-feature-auth",
					SnapshotID:  "snap-123",
					WorkspaceID: "sb-001",
					Status:      "STARTED",
					CreatedAt:   time.Now(),
				})
			},
			wantOutput: `Sandbox "hal-feature-auth" deleted.`,
			checkFn: func(t *testing.T, dir string, call *sandboxDeleteCall) {
				if !call.called {
					t.Error("deleter was not called")
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
				// Verify sandbox.json was removed
				halDir := filepath.Join(dir, template.HalDir)
				_, err := sandbox.LoadState(halDir)
				if err == nil {
					t.Error("expected sandbox.json to be removed, but LoadState succeeded")
				}
			},
		},
		{
			name: "keeps active state when deleting a different sandbox with --name",
			setup: func(t *testing.T, dir string) {
				setupDeleteTestWithState(t, dir, "key2", "", &sandbox.SandboxState{
					Name:        "hal-feature-auth",
					SnapshotID:  "snap-123",
					WorkspaceID: "sb-001",
					Status:      "STARTED",
					CreatedAt:   time.Now(),
				})
			},
			deleteName: "my-custom-sandbox",
			wantOutput: `Sandbox "my-custom-sandbox" deleted.`,
			checkFn: func(t *testing.T, dir string, call *sandboxDeleteCall) {
				if call.nameOrID != "my-custom-sandbox" {
					t.Errorf("nameOrID = %q, want %q", call.nameOrID, "my-custom-sandbox")
				}
				// sandbox.json should be preserved because the active sandbox is different.
				halDir := filepath.Join(dir, template.HalDir)
				state, err := sandbox.LoadState(halDir)
				if err != nil {
					t.Fatalf("expected sandbox.json to be preserved, but LoadState failed: %v", err)
				}
				if state.Name != "hal-feature-auth" {
					t.Errorf("state.Name = %q, want %q", state.Name, "hal-feature-auth")
				}
			},
		},
		{
			name: "removes active state when deleting by explicit workspace ID",
			setup: func(t *testing.T, dir string) {
				setupDeleteTestWithState(t, dir, "key2", "", &sandbox.SandboxState{
					Name:        "hal-feature-auth",
					SnapshotID:  "snap-123",
					WorkspaceID: "sb-001",
					Status:      "STARTED",
					CreatedAt:   time.Now(),
				})
			},
			deleteName: "sb-001",
			wantOutput: `Sandbox "sb-001" deleted.`,
			checkFn: func(t *testing.T, dir string, call *sandboxDeleteCall) {
				if call.nameOrID != "sb-001" {
					t.Errorf("nameOrID = %q, want %q", call.nameOrID, "sb-001")
				}
				halDir := filepath.Join(dir, template.HalDir)
				_, err := sandbox.LoadState(halDir)
				if err == nil {
					t.Error("expected sandbox.json to be removed, but LoadState succeeded")
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
				setupDeleteTest(t, dir, "key3", "")
			},
			wantErr: "no active sandbox",
		},
		{
			name: "error when SDK delete fails",
			setup: func(t *testing.T, dir string) {
				setupDeleteTestWithState(t, dir, "key4", "", &sandbox.SandboxState{
					Name:        "test-sandbox",
					SnapshotID:  "snap-456",
					WorkspaceID: "sb-002",
					Status:      "STARTED",
					CreatedAt:   time.Now(),
				})
			},
			deleterErr: fmt.Errorf("API error: sandbox not found"),
			wantErr:    "sandbox delete failed",
		},
		{
			name: "prints deleting message",
			setup: func(t *testing.T, dir string) {
				setupDeleteTestWithState(t, dir, "key5", "", &sandbox.SandboxState{
					Name:        "my-box",
					SnapshotID:  "snap-789",
					WorkspaceID: "sb-003",
					Status:      "STARTED",
					CreatedAt:   time.Now(),
				})
			},
			wantOutput: `Deleting sandbox "my-box"`,
		},
		{
			name: "sandbox.json not removed on SDK error",
			setup: func(t *testing.T, dir string) {
				setupDeleteTestWithState(t, dir, "key6", "", &sandbox.SandboxState{
					Name:        "keep-state",
					SnapshotID:  "snap-aaa",
					WorkspaceID: "sb-004",
					Status:      "STARTED",
					CreatedAt:   time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC),
				})
			},
			deleterErr: fmt.Errorf("API error: timeout"),
			wantErr:    "sandbox delete failed",
			checkFn: func(t *testing.T, dir string, call *sandboxDeleteCall) {
				// sandbox.json should still exist since delete failed
				halDir := filepath.Join(dir, template.HalDir)
				state, err := sandbox.LoadState(halDir)
				if err != nil {
					t.Fatalf("expected sandbox.json to be preserved, but LoadState failed: %v", err)
				}
				if state.Name != "keep-state" {
					t.Errorf("state.Name = %q, want %q", state.Name, "keep-state")
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

			deleter, call := fakeSandboxDeleter(tt.deleterErr)
			var out bytes.Buffer

			err := runSandboxDelete(dir, tt.deleteName, &out, deleter)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				if tt.checkFn != nil {
					tt.checkFn(t, dir, call)
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

func TestRunSandboxDelete_EnsureAuthCalled(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	// Save empty API key to config
	cfg := &compound.DaytonaConfig{APIKey: "", ServerURL: ""}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}

	deleter, _ := fakeSandboxDeleter(nil)
	var out bytes.Buffer

	err := runSandboxDelete(dir, "test-sandbox", &out, deleter)

	// Should fail because EnsureAuth will try interactive setup with os.Stdin
	// which doesn't have data, but the key will remain empty
	if err == nil {
		t.Fatal("expected error for empty API key, got nil")
	}
}
