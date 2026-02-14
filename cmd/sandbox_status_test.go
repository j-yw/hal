package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

type sandboxStatusCall struct {
	called    bool
	apiKey    string
	serverURL string
	nameOrID  string
}

func fakeSandboxStatusFetcher(returnStatus *sandbox.SandboxStatus, returnErr error) (sandboxStatusFetcher, *sandboxStatusCall) {
	call := &sandboxStatusCall{}
	fn := func(ctx context.Context, apiKey, serverURL, nameOrID string) (*sandbox.SandboxStatus, error) {
		call.called = true
		call.apiKey = apiKey
		call.serverURL = serverURL
		call.nameOrID = nameOrID
		if returnErr != nil {
			return nil, returnErr
		}
		return returnStatus, nil
	}
	return fn, call
}

func setupStatusTest(t *testing.T, dir string, apiKey, serverURL string) {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	cfg := &compound.DaytonaConfig{APIKey: apiKey, ServerURL: serverURL}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
}

func setupStatusTestWithState(t *testing.T, dir string, apiKey, serverURL string, state *sandbox.SandboxState) {
	t.Helper()
	setupStatusTest(t, dir, apiKey, serverURL)
	halDir := filepath.Join(dir, template.HalDir)
	if err := sandbox.SaveState(halDir, state); err != nil {
		t.Fatal(err)
	}
}

func TestRunSandboxStatus(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(t *testing.T, dir string)
		statusName   string
		fetchStatus  *sandbox.SandboxStatus
		fetchErr     error
		wantErr      string
		wantOutput   string
		noWantOutput string
		checkFn      func(t *testing.T, dir string, call *sandboxStatusCall)
	}{
		{
			name: "shows status from state file",
			setup: func(t *testing.T, dir string) {
				setupStatusTestWithState(t, dir, "test-key", "https://api.example.com", &sandbox.SandboxState{
					Name:        "hal-feature-auth",
					SnapshotID:  "snap-123",
					WorkspaceID: "sb-001",
					Status:      "STARTED",
					CreatedAt:   time.Date(2026, 2, 14, 10, 30, 0, 0, time.UTC),
				})
			},
			fetchStatus: &sandbox.SandboxStatus{Name: "hal-feature-auth", Status: "STARTED"},
			wantOutput:  "Name:       hal-feature-auth",
			checkFn: func(t *testing.T, dir string, call *sandboxStatusCall) {
				if !call.called {
					t.Error("fetcher was not called")
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
			},
		},
		{
			name: "shows live status from API",
			setup: func(t *testing.T, dir string) {
				setupStatusTestWithState(t, dir, "key2", "", &sandbox.SandboxState{
					Name:        "hal-feature-auth",
					SnapshotID:  "snap-123",
					WorkspaceID: "sb-001",
					Status:      "STARTED",
					CreatedAt:   time.Date(2026, 2, 14, 10, 30, 0, 0, time.UTC),
				})
			},
			fetchStatus: &sandbox.SandboxStatus{Name: "hal-feature-auth", Status: "STOPPED"},
			wantOutput:  "Status:     STOPPED",
		},
		{
			name: "shows SnapshotID and CreatedAt from local state",
			setup: func(t *testing.T, dir string) {
				setupStatusTestWithState(t, dir, "key3", "", &sandbox.SandboxState{
					Name:        "my-sandbox",
					SnapshotID:  "snap-abc",
					WorkspaceID: "sb-002",
					Status:      "STARTED",
					CreatedAt:   time.Date(2026, 2, 14, 10, 30, 0, 0, time.UTC),
				})
			},
			fetchStatus: &sandbox.SandboxStatus{Name: "my-sandbox", Status: "STARTED"},
			wantOutput:  "SnapshotID: snap-abc",
		},
		{
			name: "shows CreatedAt from local state",
			setup: func(t *testing.T, dir string) {
				setupStatusTestWithState(t, dir, "key4", "", &sandbox.SandboxState{
					Name:        "my-sandbox",
					SnapshotID:  "snap-abc",
					WorkspaceID: "sb-002",
					Status:      "STARTED",
					CreatedAt:   time.Date(2026, 2, 14, 10, 30, 0, 0, time.UTC),
				})
			},
			fetchStatus: &sandbox.SandboxStatus{Name: "my-sandbox", Status: "STARTED"},
			wantOutput:  "CreatedAt:  2026-02-14 10:30:00",
		},
		{
			name: "uses explicit --name flag",
			setup: func(t *testing.T, dir string) {
				setupStatusTestWithState(t, dir, "key5", "", &sandbox.SandboxState{
					Name:        "hal-feature-auth",
					SnapshotID:  "snap-123",
					WorkspaceID: "sb-001",
					Status:      "STARTED",
					CreatedAt:   time.Now(),
				})
			},
			statusName:   "custom-sandbox",
			fetchStatus:  &sandbox.SandboxStatus{Name: "custom-sandbox", Status: "STARTED"},
			wantOutput:   "Name:       custom-sandbox",
			noWantOutput: "SnapshotID:",
			checkFn: func(t *testing.T, dir string, call *sandboxStatusCall) {
				if call.nameOrID != "custom-sandbox" {
					t.Errorf("nameOrID = %q, want %q", call.nameOrID, "custom-sandbox")
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
				setupStatusTest(t, dir, "key6", "")
			},
			wantErr: "no active sandbox",
		},
		{
			name: "error when SDK fetch fails",
			setup: func(t *testing.T, dir string) {
				setupStatusTestWithState(t, dir, "key7", "", &sandbox.SandboxState{
					Name:        "test-sandbox",
					SnapshotID:  "snap-456",
					WorkspaceID: "sb-003",
					Status:      "STARTED",
					CreatedAt:   time.Now(),
				})
			},
			fetchErr: fmt.Errorf("API error: sandbox not found"),
			wantErr:  "fetching sandbox status",
		},
		{
			name: "descriptive message when no active sandbox",
			setup: func(t *testing.T, dir string) {
				setupStatusTest(t, dir, "key8", "")
			},
			wantErr: "sandbox.json does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if tt.setup != nil {
				tt.setup(t, dir)
			}

			fetcher, call := fakeSandboxStatusFetcher(tt.fetchStatus, tt.fetchErr)
			var out bytes.Buffer

			err := runSandboxStatus(dir, tt.statusName, &out, fetcher)

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

			if tt.noWantOutput != "" && strings.Contains(out.String(), tt.noWantOutput) {
				t.Errorf("output %q should not contain %q", out.String(), tt.noWantOutput)
			}

			if tt.checkFn != nil {
				tt.checkFn(t, dir, call)
			}
		})
	}
}

func TestRunSandboxStatus_EnsureAuthCalled(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	// Save empty API key to config
	cfg := &compound.DaytonaConfig{APIKey: "", ServerURL: ""}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}

	fetcher, _ := fakeSandboxStatusFetcher(&sandbox.SandboxStatus{Name: "test", Status: "STARTED"}, nil)
	var out bytes.Buffer

	err := runSandboxStatus(dir, "test-sandbox", &out, fetcher)

	// Should fail because EnsureAuth will try interactive setup with os.Stdin
	// which doesn't have data, but the key will remain empty
	if err == nil {
		t.Fatal("expected error for empty API key, got nil")
	}
}
