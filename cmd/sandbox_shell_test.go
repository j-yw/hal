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

type forwardCall struct {
	called bool
	conn   *sandbox.ShellConnection
}

func fakeShellForwarder(result *sandbox.ForwardShellIOResult, returnErr error) (shellForwarder, *forwardCall) {
	call := &forwardCall{}
	fn := func(ctx context.Context, conn *sandbox.ShellConnection, stdin io.Reader, stdout io.Writer) (*sandbox.ForwardShellIOResult, error) {
		call.called = true
		call.conn = conn
		if returnErr != nil {
			return nil, returnErr
		}
		return result, nil
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
		fwdResult  *sandbox.ForwardShellIOResult
		fwdErr     error
		wantErr    string
		wantOutput string
		checkFn    func(t *testing.T, dir string, call *shellConnectCall, fwd *forwardCall)
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
			fwdResult:  &sandbox.ForwardShellIOResult{ExitCode: 0},
			wantOutput: `Connected to sandbox "hal-feature-auth"`,
			checkFn: func(t *testing.T, dir string, call *shellConnectCall, fwd *forwardCall) {
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
			fwdResult:  &sandbox.ForwardShellIOResult{ExitCode: 0},
			wantOutput: `Connected to sandbox "custom-sandbox"`,
			checkFn: func(t *testing.T, dir string, call *shellConnectCall, fwd *forwardCall) {
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
			fwdResult:  &sandbox.ForwardShellIOResult{ExitCode: 0},
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
			fwdResult:  &sandbox.ForwardShellIOResult{ExitCode: 0},
			checkFn: func(t *testing.T, dir string, call *shellConnectCall, fwd *forwardCall) {
				if call.apiKey != "my-api-key" {
					t.Errorf("apiKey = %q, want %q", call.apiKey, "my-api-key")
				}
				if call.serverURL != "https://custom.api.io" {
					t.Errorf("serverURL = %q, want %q", call.serverURL, "https://custom.api.io")
				}
			},
		},
		{
			name: "forwarder is called with connection",
			setup: func(t *testing.T, dir string) {
				setupShellTestWithState(t, dir, "key7", "", &sandbox.SandboxState{
					Name:        "fwd-test",
					SnapshotID:  "snap-ccc",
					WorkspaceID: "sb-006",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			connResult: &sandbox.ShellConnection{SandboxName: "fwd-test"},
			fwdResult:  &sandbox.ForwardShellIOResult{ExitCode: 0},
			checkFn: func(t *testing.T, dir string, call *shellConnectCall, fwd *forwardCall) {
				if !fwd.called {
					t.Error("forwarder was not called")
				}
				if fwd.conn == nil {
					t.Error("forwarder received nil connection")
				}
				if fwd.conn.SandboxName != "fwd-test" {
					t.Errorf("forwarder conn name = %q, want %q", fwd.conn.SandboxName, "fwd-test")
				}
			},
		},
		{
			name: "session closed prints message and returns error",
			setup: func(t *testing.T, dir string) {
				setupShellTestWithState(t, dir, "key8", "", &sandbox.SandboxState{
					Name:        "closed-test",
					SnapshotID:  "snap-ddd",
					WorkspaceID: "sb-007",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			connResult: &sandbox.ShellConnection{SandboxName: "closed-test"},
			fwdResult:  &sandbox.ForwardShellIOResult{ExitCode: 1, SessionClosed: true},
			wantErr:    "exit code 1",
			wantOutput: "session closed",
		},
			{
				name: "forwarder error is propagated",
				setup: func(t *testing.T, dir string) {
					setupShellTestWithState(t, dir, "key9", "", &sandbox.SandboxState{
						Name:        "err-test",
					SnapshotID:  "snap-eee",
					WorkspaceID: "sb-008",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			connResult: &sandbox.ShellConnection{SandboxName: "err-test"},
				fwdErr:     fmt.Errorf("PTY read error"),
				wantErr:    "shell session error",
			},
			{
				name: "nil forwarder result returns error",
				setup: func(t *testing.T, dir string) {
					setupShellTestWithState(t, dir, "key10", "", &sandbox.SandboxState{
						Name:        "nil-result-test",
						SnapshotID:  "snap-ggg",
						WorkspaceID: "sb-010",
						Status:      "started",
						CreatedAt:   time.Now(),
					})
				},
				connResult: &sandbox.ShellConnection{SandboxName: "nil-result-test"},
				fwdResult:  nil,
				wantErr:    "shell session returned no result",
			},
			{
				name: "clean disconnect returns no error",
				setup: func(t *testing.T, dir string) {
					setupShellTestWithState(t, dir, "key11", "", &sandbox.SandboxState{
						Name:        "clean-test",
						SnapshotID:  "snap-fff",
						WorkspaceID: "sb-009",
						Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			connResult: &sandbox.ShellConnection{SandboxName: "clean-test"},
			fwdResult:  &sandbox.ForwardShellIOResult{ExitCode: 0, SessionClosed: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if tt.setup != nil {
				tt.setup(t, dir)
			}

			connector, connCall := fakeShellConnector(tt.connResult, tt.connErr)
			forwarder, fwdCall := fakeShellForwarder(tt.fwdResult, tt.fwdErr)
			var out bytes.Buffer

			err := runSandboxShell(dir, tt.shellName, strings.NewReader(""), &out, connector, forwarder)

			// For session closed case, check output before error assertion
			if tt.wantOutput != "" && strings.Contains(out.String(), tt.wantOutput) {
				// output check passed
			} else if tt.wantOutput != "" {
				t.Errorf("output %q does not contain %q", out.String(), tt.wantOutput)
			}

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

			if tt.checkFn != nil {
				tt.checkFn(t, dir, connCall, fwdCall)
			}
		})
	}
}

func TestRunSandboxShell_NonZeroExitWithoutSessionClosedReturnsError(t *testing.T) {
	dir := t.TempDir()
	setupShellTestWithState(t, dir, "key", "https://api.example.com", &sandbox.SandboxState{
		Name:        "nonzero-exit-test",
		SnapshotID:  "snap-nonzero",
		WorkspaceID: "sb-nonzero",
		Status:      "started",
		CreatedAt:   time.Now(),
	})

	connector, _ := fakeShellConnector(&sandbox.ShellConnection{SandboxName: "nonzero-exit-test"}, nil)
	forwarder, _ := fakeShellForwarder(&sandbox.ForwardShellIOResult{ExitCode: 2, SessionClosed: false}, nil)
	var out bytes.Buffer

	err := runSandboxShell(dir, "", strings.NewReader(""), &out, connector, forwarder)
	if err == nil {
		t.Fatal("expected non-zero exit code error, got nil")
	}
	if !strings.Contains(err.Error(), "exit code 2") {
		t.Errorf("error %q does not contain %q", err.Error(), "exit code 2")
	}
	if strings.Contains(out.String(), "session closed") {
		t.Errorf("output should not contain session closed message, got %q", out.String())
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
	forwarder, _ := fakeShellForwarder(&sandbox.ForwardShellIOResult{ExitCode: 0}, nil)
	var out bytes.Buffer

	err := runSandboxShell(dir, "test-sandbox", strings.NewReader(""), &out, connector, forwarder)

	// Should fail because EnsureAuth will try interactive setup with os.Stdin
	// which doesn't have data, but the key will remain empty
	if err == nil {
		t.Fatal("expected error for empty API key, got nil")
	}
}
