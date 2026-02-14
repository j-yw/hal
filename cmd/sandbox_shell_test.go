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

type shellConnectCall struct {
	called    bool
	apiKey    string
	serverURL string
	nameOrID  string
}

func fakeShellConnector(returnConn *sandbox.ShellConnection, returnErr error) (shellConnector, *shellConnectCall) {
	call := &shellConnectCall{}
	fn := func(ctx context.Context, apiKey, serverURL, nameOrID string) (*sandbox.ShellConnection, error) {
		call.called = true
		call.apiKey = apiKey
		call.serverURL = serverURL
		call.nameOrID = nameOrID
		if returnErr != nil {
			return nil, returnErr
		}
		return returnConn, nil
	}
	return fn, call
}

func setupShellTest(t *testing.T, dir string, apiKey, serverURL string) {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	cfg := &compound.DaytonaConfig{APIKey: apiKey, ServerURL: serverURL}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
}

func setupShellTestWithState(t *testing.T, dir string, apiKey, serverURL string, state *sandbox.SandboxState) {
	t.Helper()
	setupShellTest(t, dir, apiKey, serverURL)
	halDir := filepath.Join(dir, template.HalDir)
	if err := sandbox.SaveState(halDir, state); err != nil {
		t.Fatal(err)
	}
}

func TestRunSandboxShell(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string)
		shellName  string
		connResult *sandbox.ShellConnection
		connErr    error
		wantErr    string
		wantOutput string
		checkFn    func(t *testing.T, dir string, call *shellConnectCall)
	}{
		{
			name: "connects to sandbox from state file",
			setup: func(t *testing.T, dir string) {
				setupShellTestWithState(t, dir, "test-key", "https://api.example.com", &sandbox.SandboxState{
					Name:        "hal-feature-auth",
					SnapshotID:  "snap-123",
					WorkspaceID: "sb-001",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			connResult: &sandbox.ShellConnection{SandboxName: "hal-feature-auth"},
			wantOutput: `Connected to sandbox "hal-feature-auth"`,
			checkFn: func(t *testing.T, dir string, call *shellConnectCall) {
				if !call.called {
					t.Error("connector was not called")
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
			name: "connects with explicit --name flag",
			setup: func(t *testing.T, dir string) {
				setupShellTestWithState(t, dir, "key2", "", &sandbox.SandboxState{
					Name:        "hal-feature-auth",
					SnapshotID:  "snap-123",
					WorkspaceID: "sb-001",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			shellName:  "custom-sandbox",
			connResult: &sandbox.ShellConnection{SandboxName: "custom-sandbox"},
			wantOutput: `Connected to sandbox "custom-sandbox"`,
			checkFn: func(t *testing.T, dir string, call *shellConnectCall) {
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
				setupShellTest(t, dir, "key3", "")
			},
			wantErr: "no active sandbox",
		},
		{
			name: "error when sandbox not running",
			setup: func(t *testing.T, dir string) {
				setupShellTestWithState(t, dir, "key4", "", &sandbox.SandboxState{
					Name:        "test-sandbox",
					SnapshotID:  "snap-456",
					WorkspaceID: "sb-002",
					Status:      "stopped",
					CreatedAt:   time.Now(),
				})
			},
			connErr: fmt.Errorf("sandbox \"test-sandbox\" is not running (current state: stopped)"),
			wantErr: "shell connection failed",
		},
		{
			name: "error when SDK connection fails",
			setup: func(t *testing.T, dir string) {
				setupShellTestWithState(t, dir, "key5", "", &sandbox.SandboxState{
					Name:        "test-sandbox",
					SnapshotID:  "snap-789",
					WorkspaceID: "sb-003",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			connErr: fmt.Errorf("API error: connection refused"),
			wantErr: "shell connection failed",
		},
		{
			name: "prints connecting message",
			setup: func(t *testing.T, dir string) {
				setupShellTestWithState(t, dir, "key6", "", &sandbox.SandboxState{
					Name:        "my-box",
					SnapshotID:  "snap-aaa",
					WorkspaceID: "sb-004",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			connResult: &sandbox.ShellConnection{SandboxName: "my-box"},
			wantOutput: `Connecting to sandbox "my-box"`,
		},
		{
			name: "passes correct credentials to connector",
			setup: func(t *testing.T, dir string) {
				setupShellTestWithState(t, dir, "my-api-key", "https://custom.api.io", &sandbox.SandboxState{
					Name:        "creds-test",
					SnapshotID:  "snap-bbb",
					WorkspaceID: "sb-005",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			connResult: &sandbox.ShellConnection{SandboxName: "creds-test"},
			checkFn: func(t *testing.T, dir string, call *shellConnectCall) {
				if call.apiKey != "my-api-key" {
					t.Errorf("apiKey = %q, want %q", call.apiKey, "my-api-key")
				}
				if call.serverURL != "https://custom.api.io" {
					t.Errorf("serverURL = %q, want %q", call.serverURL, "https://custom.api.io")
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

			connector, call := fakeShellConnector(tt.connResult, tt.connErr)
			var out bytes.Buffer

			err := runSandboxShell(dir, tt.shellName, &out, connector)

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

func TestRunSandboxShell_EnsureAuthCalled(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	// Save empty API key to config
	cfg := &compound.DaytonaConfig{APIKey: "", ServerURL: ""}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}

	connector, _ := fakeShellConnector(&sandbox.ShellConnection{SandboxName: "test"}, nil)
	var out bytes.Buffer

	err := runSandboxShell(dir, "test-sandbox", &out, connector)

	// Should fail because EnsureAuth will try interactive setup with os.Stdin
	// which doesn't have data, but the key will remain empty
	if err == nil {
		t.Fatal("expected error for empty API key, got nil")
	}
}
