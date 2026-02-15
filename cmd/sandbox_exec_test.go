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

type execCall struct {
	called    bool
	apiKey    string
	serverURL string
	nameOrID  string
	command   string
}

func fakeExecutor(returnResult *sandbox.ExecResult, returnErr error) (sandboxExecutor, *execCall) {
	call := &execCall{}
	fn := func(ctx context.Context, apiKey, serverURL, nameOrID, command string) (*sandbox.ExecResult, error) {
		call.called = true
		call.apiKey = apiKey
		call.serverURL = serverURL
		call.nameOrID = nameOrID
		call.command = command
		if returnErr != nil {
			return nil, returnErr
		}
		return returnResult, nil
	}
	return fn, call
}

func setupExecTest(t *testing.T, dir string, apiKey, serverURL string) {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	cfg := &compound.DaytonaConfig{APIKey: apiKey, ServerURL: serverURL}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
}

func setupExecTestWithState(t *testing.T, dir string, apiKey, serverURL string, state *sandbox.SandboxState) {
	t.Helper()
	setupExecTest(t, dir, apiKey, serverURL)
	halDir := filepath.Join(dir, template.HalDir)
	if err := sandbox.SaveState(halDir, state); err != nil {
		t.Fatal(err)
	}
}

func TestRunSandboxExec(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string)
		execName   string
		args       []string
		execResult *sandbox.ExecResult
		execErr    error
		wantErr    string
		wantOutput string
		wantExit   int
		checkFn    func(t *testing.T, call *execCall)
	}{
		{
			name: "executes command via state file sandbox",
			setup: func(t *testing.T, dir string) {
				setupExecTestWithState(t, dir, "test-key", "https://api.example.com", &sandbox.SandboxState{
					Name:        "hal-feature-auth",
					SnapshotID:  "snap-123",
					WorkspaceID: "sb-001",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			args:       []string{"echo", "hello"},
			execResult: &sandbox.ExecResult{ExitCode: 0, Output: "hello\n"},
			wantOutput: "hello\n",
			checkFn: func(t *testing.T, call *execCall) {
				if !call.called {
					t.Error("executor was not called")
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
				if call.command != "echo hello" {
					t.Errorf("command = %q, want %q", call.command, "echo hello")
				}
			},
		},
		{
			name: "executes with explicit --name flag",
			setup: func(t *testing.T, dir string) {
				setupExecTestWithState(t, dir, "key2", "", &sandbox.SandboxState{
					Name:        "hal-feature-auth",
					SnapshotID:  "snap-123",
					WorkspaceID: "sb-001",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			execName:   "custom-sandbox",
			args:       []string{"ls", "-la"},
			execResult: &sandbox.ExecResult{ExitCode: 0, Output: "total 0\n"},
			wantOutput: "total 0\n",
			checkFn: func(t *testing.T, call *execCall) {
				if call.nameOrID != "custom-sandbox" {
					t.Errorf("nameOrID = %q, want %q", call.nameOrID, "custom-sandbox")
				}
				if call.command != "ls -la" {
					t.Errorf("command = %q, want %q", call.command, "ls -la")
				}
			},
		},
		{
			name: "propagates non-zero exit code",
			setup: func(t *testing.T, dir string) {
				setupExecTestWithState(t, dir, "key3", "", &sandbox.SandboxState{
					Name:        "exit-test",
					SnapshotID:  "snap-456",
					WorkspaceID: "sb-002",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			args:       []string{"false"},
			execResult: &sandbox.ExecResult{ExitCode: 1, Output: ""},
			wantExit:   1,
		},
		{
			name: "streams stderr output",
			setup: func(t *testing.T, dir string) {
				setupExecTestWithState(t, dir, "key4", "", &sandbox.SandboxState{
					Name:        "stderr-test",
					SnapshotID:  "snap-789",
					WorkspaceID: "sb-003",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			args:       []string{"cat", "/nonexistent"},
			execResult: &sandbox.ExecResult{ExitCode: 1, Output: "cat: /nonexistent: No such file or directory\n"},
			wantOutput: "cat: /nonexistent: No such file or directory\n",
			wantExit:   1,
		},
		{
			name: "error when .hal/ does not exist",
			setup: func(t *testing.T, dir string) {
				// don't create .hal/
			},
			args:    []string{"echo", "hello"},
			wantErr: ".hal/ not found",
		},
		{
			name: "error when no sandbox state and no --name",
			setup: func(t *testing.T, dir string) {
				setupExecTest(t, dir, "key5", "")
			},
			args:    []string{"echo", "hello"},
			wantErr: "no active sandbox",
		},
		{
			name: "error when sandbox not running",
			setup: func(t *testing.T, dir string) {
				setupExecTestWithState(t, dir, "key6", "", &sandbox.SandboxState{
					Name:        "stopped-box",
					SnapshotID:  "snap-aaa",
					WorkspaceID: "sb-004",
					Status:      "stopped",
					CreatedAt:   time.Now(),
				})
			},
			args:    []string{"echo", "hello"},
			execErr: fmt.Errorf("sandbox \"stopped-box\" is not running (current state: stopped)"),
			wantErr: "exec failed",
		},
		{
			name: "error when SDK call fails",
			setup: func(t *testing.T, dir string) {
				setupExecTestWithState(t, dir, "key7", "", &sandbox.SandboxState{
					Name:        "err-test",
					SnapshotID:  "snap-bbb",
					WorkspaceID: "sb-005",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			args:    []string{"some-command"},
			execErr: fmt.Errorf("API error: timeout"),
			wantErr: "exec failed",
		},
		{
			name: "passes correct credentials",
			setup: func(t *testing.T, dir string) {
				setupExecTestWithState(t, dir, "my-api-key", "https://custom.api.io", &sandbox.SandboxState{
					Name:        "creds-test",
					SnapshotID:  "snap-ccc",
					WorkspaceID: "sb-006",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			args:       []string{"whoami"},
			execResult: &sandbox.ExecResult{ExitCode: 0, Output: "root\n"},
			wantOutput: "root\n",
			checkFn: func(t *testing.T, call *execCall) {
				if call.apiKey != "my-api-key" {
					t.Errorf("apiKey = %q, want %q", call.apiKey, "my-api-key")
				}
				if call.serverURL != "https://custom.api.io" {
					t.Errorf("serverURL = %q, want %q", call.serverURL, "https://custom.api.io")
				}
			},
		},
		{
			name: "joins multiple args into single command",
			setup: func(t *testing.T, dir string) {
				setupExecTestWithState(t, dir, "key8", "", &sandbox.SandboxState{
					Name:        "args-test",
					SnapshotID:  "snap-ddd",
					WorkspaceID: "sb-007",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			args:       []string{"grep", "-r", "TODO", "/workspace"},
			execResult: &sandbox.ExecResult{ExitCode: 0, Output: "found\n"},
			wantOutput: "found\n",
			checkFn: func(t *testing.T, call *execCall) {
				if call.command != "grep -r TODO /workspace" {
					t.Errorf("command = %q, want %q", call.command, "grep -r TODO /workspace")
				}
			},
		},
		{
			name: "preserves argument boundaries with shell quoting",
			setup: func(t *testing.T, dir string) {
				setupExecTestWithState(t, dir, "key9", "", &sandbox.SandboxState{
					Name:        "quoted-args-test",
					SnapshotID:  "snap-eee",
					WorkspaceID: "sb-008",
					Status:      "started",
					CreatedAt:   time.Now(),
				})
			},
			args:       []string{"printf", "%s", "hello world; rm -rf /", "it's ok"},
			execResult: &sandbox.ExecResult{ExitCode: 0, Output: "ignored\n"},
			checkFn: func(t *testing.T, call *execCall) {
				want := "printf %s 'hello world; rm -rf /' 'it'\"'\"'s ok'"
				if call.command != want {
					t.Errorf("command = %q, want %q", call.command, want)
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

			executor, execCallResult := fakeExecutor(tt.execResult, tt.execErr)
			var out bytes.Buffer

			exitCode, err := runSandboxExec(dir, tt.execName, tt.args, &out, executor)

			if tt.wantOutput != "" {
				if !strings.Contains(out.String(), tt.wantOutput) {
					t.Errorf("output %q does not contain %q", out.String(), tt.wantOutput)
				}
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

			if exitCode != tt.wantExit {
				t.Errorf("exit code = %d, want %d", exitCode, tt.wantExit)
			}

			if tt.checkFn != nil {
				tt.checkFn(t, execCallResult)
			}
		})
	}
}

func TestShellCommandFromArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "keeps safe args unquoted",
			args: []string{"grep", "-r", "TODO", "/workspace"},
			want: "grep -r TODO /workspace",
		},
		{
			name: "quotes args with spaces",
			args: []string{"echo", "hello world"},
			want: "echo 'hello world'",
		},
		{
			name: "quotes single quote safely",
			args: []string{"echo", "it's"},
			want: "echo 'it'\"'\"'s'",
		},
		{
			name: "quotes empty args",
			args: []string{"printf", "%s", ""},
			want: "printf %s ''",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shellCommandFromArgs(tt.args)
			if got != tt.want {
				t.Fatalf("shellCommandFromArgs(%v) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

func TestRunSandboxExec_EnsureAuthCalled(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	// Save empty API key to config
	cfg := &compound.DaytonaConfig{APIKey: "", ServerURL: ""}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}

	executor, _ := fakeExecutor(&sandbox.ExecResult{ExitCode: 0, Output: ""}, nil)
	var out bytes.Buffer

	_, err := runSandboxExec(dir, "test-sandbox", []string{"echo", "hello"}, &out, executor)

	// Should fail because EnsureAuth will try interactive setup with os.Stdin
	// which doesn't have data, but the key will remain empty
	if err == nil {
		t.Fatal("expected error for empty API key, got nil")
	}
}
