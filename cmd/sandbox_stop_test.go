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

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

// mockStopProvider implements sandbox.Provider for stop tests.
type mockStopProvider struct {
	stopCalls []string
	stopErr   error
}

func (m *mockStopProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}

func (m *mockStopProvider) Stop(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	if info != nil {
		m.stopCalls = append(m.stopCalls, info.Name)
	} else {
		m.stopCalls = append(m.stopCalls, "")
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

func setupStopTestWithState(t *testing.T, dir string, state *sandbox.SandboxState) {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	// Write sandbox config for provider resolution
	sandboxCfg := &compound.SandboxConfig{
		Provider: state.Provider,
		Env:      map[string]string{},
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}
	if err := sandbox.SaveState(halDir, state); err != nil {
		t.Fatal(err)
	}
}

func TestRunSandboxStop(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string)
		stopErr    error
		wantErr    string
		wantOutput string
		checkFn    func(t *testing.T, mock *mockStopProvider)
	}{
		{
			name: "stops sandbox from state file",
			setup: func(t *testing.T, dir string) {
				setupStopTestWithState(t, dir, &sandbox.SandboxState{
					Name:      "hal-feature-auth",
					Provider:  "daytona",
					CreatedAt: time.Now(),
				})
			},
			wantOutput: `Sandbox "hal-feature-auth" stopped.`,
			checkFn: func(t *testing.T, mock *mockStopProvider) {
				if len(mock.stopCalls) != 1 {
					t.Fatalf("expected 1 Stop call, got %d", len(mock.stopCalls))
				}
				if mock.stopCalls[0] != "hal-feature-auth" {
					t.Errorf("Stop name = %q, want %q", mock.stopCalls[0], "hal-feature-auth")
				}
			},
		},
		{
			name: "error when no sandbox state exists",
			setup: func(t *testing.T, dir string) {
				halDir := filepath.Join(dir, template.HalDir)
				os.MkdirAll(halDir, 0755)
			},
			wantErr: "no active sandbox",
		},
		{
			name: "error when sandbox state is invalid",
			setup: func(t *testing.T, dir string) {
				halDir := filepath.Join(dir, template.HalDir)
				if err := os.MkdirAll(halDir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(halDir, template.SandboxFile), []byte("{"), 0644); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "loading sandbox state",
		},
		{
			name: "error when provider stop fails",
			setup: func(t *testing.T, dir string) {
				setupStopTestWithState(t, dir, &sandbox.SandboxState{
					Name:      "test-sandbox",
					Provider:  "daytona",
					CreatedAt: time.Now(),
				})
			},
			stopErr: fmt.Errorf("connection timeout"),
			wantErr: "sandbox stop failed",
		},
		{
			name: "prints stopping message",
			setup: func(t *testing.T, dir string) {
				setupStopTestWithState(t, dir, &sandbox.SandboxState{
					Name:      "my-box",
					Provider:  "daytona",
					CreatedAt: time.Now(),
				})
			},
			wantOutput: `Stopping sandbox "my-box"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, dir)
			}

			mock := &mockStopProvider{stopErr: tt.stopErr}
			var out bytes.Buffer

			err := runSandboxStopWithDeps(dir, &out, mock)

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
				tt.checkFn(t, mock)
			}
		})
	}
}
