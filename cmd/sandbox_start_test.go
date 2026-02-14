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

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

type sandboxStartCall struct {
	called     bool
	apiKey     string
	serverURL  string
	name       string
	snapshotID string
}

func fakeSandboxStarter(returnResult *sandbox.CreateSandboxResult, returnErr error) (sandboxStarter, *sandboxStartCall) {
	call := &sandboxStartCall{}
	fn := func(ctx context.Context, apiKey, serverURL, name, snapshotID string, out io.Writer) (*sandbox.CreateSandboxResult, error) {
		call.called = true
		call.apiKey = apiKey
		call.serverURL = serverURL
		call.name = name
		call.snapshotID = snapshotID
		return returnResult, returnErr
	}
	return fn, call
}

func setupStartTest(t *testing.T, dir string, apiKey, serverURL string) {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	cfg := &compound.DaytonaConfig{APIKey: apiKey, ServerURL: serverURL}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
}

func fakeBranchResolver(branch string, err error) branchResolver {
	return func() (string, error) {
		return branch, err
	}
}

func TestRunSandboxStart(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string)
		sandboxName string
		snapshotID string
		branch     string
		branchErr  error
		resultID   string
		resultName string
		resultStatus string
		starterErr error
		wantErr    string
		wantOutput string
		checkFn    func(t *testing.T, dir string, call *sandboxStartCall)
	}{
		{
			name: "starts sandbox with name from git branch",
			setup: func(t *testing.T, dir string) {
				setupStartTest(t, dir, "test-key", "https://api.example.com")
			},
			snapshotID:   "snap-123",
			branch:       "hal/feature-auth",
			resultID:     "sb-001",
			resultName:   "hal-feature-auth",
			resultStatus: "STARTED",
			wantOutput:   "Sandbox started: hal-feature-auth",
			checkFn: func(t *testing.T, dir string, call *sandboxStartCall) {
				if !call.called {
					t.Error("starter was not called")
				}
				if call.apiKey != "test-key" {
					t.Errorf("apiKey = %q, want %q", call.apiKey, "test-key")
				}
				if call.serverURL != "https://api.example.com" {
					t.Errorf("serverURL = %q, want %q", call.serverURL, "https://api.example.com")
				}
				if call.name != "hal-feature-auth" {
					t.Errorf("name = %q, want %q", call.name, "hal-feature-auth")
				}
				if call.snapshotID != "snap-123" {
					t.Errorf("snapshotID = %q, want %q", call.snapshotID, "snap-123")
				}
				// Verify state was saved
				halDir := filepath.Join(dir, template.HalDir)
				state, err := sandbox.LoadState(halDir)
				if err != nil {
					t.Fatalf("failed to load saved state: %v", err)
				}
				if state.Name != "hal-feature-auth" {
					t.Errorf("state.Name = %q, want %q", state.Name, "hal-feature-auth")
				}
				if state.SnapshotID != "snap-123" {
					t.Errorf("state.SnapshotID = %q, want %q", state.SnapshotID, "snap-123")
				}
				if state.WorkspaceID != "sb-001" {
					t.Errorf("state.WorkspaceID = %q, want %q", state.WorkspaceID, "sb-001")
				}
				if state.Status != "STARTED" {
					t.Errorf("state.Status = %q, want %q", state.Status, "STARTED")
				}
			},
		},
		{
			name: "uses explicit --name flag",
			setup: func(t *testing.T, dir string) {
				setupStartTest(t, dir, "key2", "")
			},
			sandboxName:  "my-sandbox",
			snapshotID:   "snap-456",
			resultID:     "sb-002",
			resultName:   "my-sandbox",
			resultStatus: "STARTED",
			wantOutput:   "Sandbox started: my-sandbox",
			checkFn: func(t *testing.T, dir string, call *sandboxStartCall) {
				if call.name != "my-sandbox" {
					t.Errorf("name = %q, want %q", call.name, "my-sandbox")
				}
			},
		},
		{
			name: "branch with nested slashes",
			setup: func(t *testing.T, dir string) {
				setupStartTest(t, dir, "key3", "")
			},
			snapshotID:   "snap-789",
			branch:       "feature/auth/oauth",
			resultID:     "sb-003",
			resultName:   "feature-auth-oauth",
			resultStatus: "STARTED",
			wantOutput:   "Sandbox started: feature-auth-oauth",
			checkFn: func(t *testing.T, dir string, call *sandboxStartCall) {
				if call.name != "feature-auth-oauth" {
					t.Errorf("name = %q, want %q", call.name, "feature-auth-oauth")
				}
			},
		},
		{
			name: "error when .hal/ does not exist",
			setup: func(t *testing.T, dir string) {
				// don't create .hal/
			},
			snapshotID: "snap-123",
			wantErr:    ".hal/ not found",
		},
		{
			name: "error when snapshot flag is missing",
			setup: func(t *testing.T, dir string) {
				setupStartTest(t, dir, "key4", "")
			},
			sandboxName: "my-sandbox",
			snapshotID:  "",
			wantErr:     "--snapshot flag is required",
		},
		{
			name: "error when git branch cannot be determined",
			setup: func(t *testing.T, dir string) {
				setupStartTest(t, dir, "key5", "")
			},
			snapshotID: "snap-123",
			branchErr:  fmt.Errorf("not on a branch"),
			wantErr:    "could not determine sandbox name from git branch",
		},
		{
			name: "error when sandbox creation fails",
			setup: func(t *testing.T, dir string) {
				setupStartTest(t, dir, "key6", "")
			},
			sandboxName: "my-sandbox",
			snapshotID:  "snap-123",
			starterErr:  fmt.Errorf("API error: quota exceeded"),
			wantErr:     "sandbox creation failed",
		},
		{
			name: "prints starting message with sandbox name and snapshot",
			setup: func(t *testing.T, dir string) {
				setupStartTest(t, dir, "key7", "")
			},
			sandboxName:  "test-box",
			snapshotID:   "snap-abc",
			resultID:     "sb-004",
			resultName:   "test-box",
			resultStatus: "STARTED",
			wantOutput:   `Starting sandbox "test-box" from snapshot "snap-abc"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if tt.setup != nil {
				tt.setup(t, dir)
			}

			var result *sandbox.CreateSandboxResult
			if tt.starterErr == nil && tt.resultID != "" {
				result = &sandbox.CreateSandboxResult{
					ID:     tt.resultID,
					Name:   tt.resultName,
					Status: tt.resultStatus,
				}
			}

			starter, call := fakeSandboxStarter(result, tt.starterErr)
			var out bytes.Buffer

			var getBranch branchResolver
			if tt.branch != "" || tt.branchErr != nil {
				getBranch = fakeBranchResolver(tt.branch, tt.branchErr)
			}

			err := runSandboxStart(dir, tt.sandboxName, tt.snapshotID, &out, starter, getBranch)

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

func TestRunSandboxStart_EnsureAuthCalled(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	// Save empty API key to config
	cfg := &compound.DaytonaConfig{APIKey: "", ServerURL: ""}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}

	result := &sandbox.CreateSandboxResult{ID: "sb-id", Name: "test", Status: "STARTED"}
	starter, _ := fakeSandboxStarter(result, nil)
	var out bytes.Buffer
	getBranch := fakeBranchResolver("main", nil)

	err := runSandboxStart(dir, "test", "snap-123", &out, starter, getBranch)

	// Should fail because EnsureAuth will try interactive setup with os.Stdin
	// which doesn't have data, but the key will remain empty
	if err == nil {
		t.Fatal("expected error for empty API key, got nil")
	}
}
