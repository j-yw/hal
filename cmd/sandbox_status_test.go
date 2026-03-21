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

// mockStatusProvider implements sandbox.Provider for status tests.
type mockStatusProvider struct {
	statusCalls []string
	statusErr   error
	statusOut   string // output to write to the writer
}

func (m *mockStatusProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}
func (m *mockStatusProvider) Stop(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}
func (m *mockStatusProvider) Delete(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}
func (m *mockStatusProvider) SSH(info *sandbox.ConnectInfo) (*exec.Cmd, error) { return nil, nil }
func (m *mockStatusProvider) Exec(info *sandbox.ConnectInfo, args []string) (*exec.Cmd, error) {
	return nil, nil
}

func (m *mockStatusProvider) Status(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	if info != nil {
		m.statusCalls = append(m.statusCalls, info.Name)
	} else {
		m.statusCalls = append(m.statusCalls, "")
	}
	if m.statusOut != "" {
		fmt.Fprint(out, m.statusOut)
	}
	return m.statusErr
}

func setupStatusTestWithState(t *testing.T, dir string, state *sandbox.SandboxState) {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
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

func TestRunSandboxStatus(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string)
		statusErr  error
		statusOut  string
		wantErr    string
		wantOutput []string
		checkFn    func(t *testing.T, mock *mockStatusProvider)
	}{
		{
			name: "shows status with provider and name header",
			setup: func(t *testing.T, dir string) {
				setupStatusTestWithState(t, dir, &sandbox.SandboxState{
					Name:      "hal-feature",
					Provider:  "daytona",
					CreatedAt: time.Now(),
				})
			},
			statusOut:  "Status: STARTED\n",
			wantOutput: []string{"Sandbox: hal-feature", "provider: daytona"},
			checkFn: func(t *testing.T, mock *mockStatusProvider) {
				if len(mock.statusCalls) != 1 {
					t.Fatalf("expected 1 Status call, got %d", len(mock.statusCalls))
				}
				if mock.statusCalls[0] != "hal-feature" {
					t.Errorf("Status name = %q, want %q", mock.statusCalls[0], "hal-feature")
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
			name: "error when provider status fails",
			setup: func(t *testing.T, dir string) {
				setupStatusTestWithState(t, dir, &sandbox.SandboxState{
					Name:      "test-sb",
					Provider:  "hetzner",
					CreatedAt: time.Now(),
				})
			},
			statusErr: fmt.Errorf("server not found"),
			wantErr:   "fetching sandbox status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, dir)
			}

			mock := &mockStatusProvider{statusErr: tt.statusErr, statusOut: tt.statusOut}
			var out bytes.Buffer

			err := runSandboxStatusWithDeps(dir, &out, mock)

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
			for _, want := range tt.wantOutput {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output %q does not contain %q", out.String(), want)
				}
			}
			if tt.checkFn != nil {
				tt.checkFn(t, mock)
			}
		})
	}
}
