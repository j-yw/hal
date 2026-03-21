package cmd

import (
	"bytes"
	"context"
	"errors"
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

// mockDeleteProvider implements sandbox.Provider for delete tests.
type mockDeleteProvider struct {
	deleteCalls []string
	deleteErr   error
}

func (m *mockDeleteProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}

func (m *mockDeleteProvider) Stop(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}

func (m *mockDeleteProvider) Delete(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	if info != nil {
		m.deleteCalls = append(m.deleteCalls, info.Name)
	} else {
		m.deleteCalls = append(m.deleteCalls, "")
	}
	return m.deleteErr
}

func (m *mockDeleteProvider) SSH(info *sandbox.ConnectInfo) (*exec.Cmd, error) { return nil, nil }
func (m *mockDeleteProvider) Exec(info *sandbox.ConnectInfo, args []string) (*exec.Cmd, error) {
	return nil, nil
}

func (m *mockDeleteProvider) Status(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}

func setupDeleteTestWithState(t *testing.T, dir string, state *sandbox.SandboxState) {
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

func TestRunSandboxDelete(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string)
		deleteErr  error
		wantErr    string
		wantOutput string
		checkFn    func(t *testing.T, dir string, mock *mockDeleteProvider)
	}{
		{
			name: "deletes sandbox and removes state",
			setup: func(t *testing.T, dir string) {
				setupDeleteTestWithState(t, dir, &sandbox.SandboxState{
					Name:      "hal-feature-auth",
					Provider:  "daytona",
					CreatedAt: time.Now(),
				})
			},
			wantOutput: `Sandbox "hal-feature-auth" deleted.`,
			checkFn: func(t *testing.T, dir string, mock *mockDeleteProvider) {
				if len(mock.deleteCalls) != 1 {
					t.Fatalf("expected 1 Delete call, got %d", len(mock.deleteCalls))
				}
				if mock.deleteCalls[0] != "hal-feature-auth" {
					t.Errorf("Delete name = %q, want %q", mock.deleteCalls[0], "hal-feature-auth")
				}
				// State should be removed
				halDir := filepath.Join(dir, template.HalDir)
				_, err := sandbox.LoadState(halDir)
				if err == nil {
					t.Error("expected sandbox.json to be removed, but LoadState succeeded")
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
			name: "error when provider delete fails",
			setup: func(t *testing.T, dir string) {
				setupDeleteTestWithState(t, dir, &sandbox.SandboxState{
					Name:      "test-sandbox",
					Provider:  "daytona",
					CreatedAt: time.Now(),
				})
			},
			deleteErr: fmt.Errorf("API error: sandbox not found"),
			wantErr:   "sandbox delete failed",
			checkFn: func(t *testing.T, dir string, mock *mockDeleteProvider) {
				// State should be preserved on failure
				halDir := filepath.Join(dir, template.HalDir)
				_, err := sandbox.LoadState(halDir)
				if err != nil {
					t.Error("expected sandbox.json to be preserved on failure")
				}
			},
		},
		{
			name: "prints deleting message",
			setup: func(t *testing.T, dir string) {
				setupDeleteTestWithState(t, dir, &sandbox.SandboxState{
					Name:      "my-box",
					Provider:  "daytona",
					CreatedAt: time.Now(),
				})
			},
			wantOutput: `Deleting sandbox "my-box"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, dir)
			}

			mock := &mockDeleteProvider{deleteErr: tt.deleteErr}
			var out bytes.Buffer

			err := runSandboxDeleteWithDeps(dir, &out, "", mock)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				if tt.checkFn != nil {
					tt.checkFn(t, dir, mock)
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
				tt.checkFn(t, dir, mock)
			}
		})
	}
}

func TestSandboxDeleteCommandFlags(t *testing.T) {
	nameFlag := sandboxDeleteCmd.Flags().Lookup("name")
	if nameFlag == nil {
		t.Fatal("--name flag should exist")
	}
	if nameFlag.Shorthand != "n" {
		t.Fatalf("--name shorthand = %q, want %q", nameFlag.Shorthand, "n")
	}
}

func TestRunSandboxDelete_RemovesStateWhenDeletingByWorkspaceID(t *testing.T) {
	dir := t.TempDir()
	setupDeleteTestWithState(t, dir, &sandbox.SandboxState{
		Name:        "hal-feature-auth",
		Provider:    "daytona",
		WorkspaceID: "ws-12345",
		CreatedAt:   time.Now(),
	})

	mock := &mockDeleteProvider{}
	var out bytes.Buffer

	err := runSandboxDeleteWithDeps(dir, &out, "ws-12345", mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.deleteCalls) != 1 {
		t.Fatalf("expected 1 Delete call, got %d", len(mock.deleteCalls))
	}
	if mock.deleteCalls[0] != "hal-feature-auth" {
		t.Fatalf("Delete called with %q, want %q", mock.deleteCalls[0], "hal-feature-auth")
	}

	halDir := filepath.Join(dir, template.HalDir)
	if _, err := sandbox.LoadState(halDir); err == nil {
		t.Fatal("expected sandbox state to be removed after workspace-id delete")
	}
}

func TestResolveDeleteProvider_UsesStateProviderForWorkspaceID(t *testing.T) {
	state := &sandbox.SandboxState{
		Name:        "hal-feature-auth",
		WorkspaceID: "ws-12345",
		Provider:    "daytona",
	}

	expectedProvider := &mockDeleteProvider{}
	fallbackErr := errors.New("configured provider mismatch")
	stateResolverCalls := 0
	nameResolverCalls := 0

	provider, err := resolveDeleteProvider(
		".",
		"ws-12345",
		state,
		func(_ string, gotState *sandbox.SandboxState) (sandbox.Provider, error) {
			stateResolverCalls++
			if gotState != state {
				t.Fatalf("state resolver got unexpected state pointer")
			}
			return expectedProvider, nil
		},
		func(_ string, _ string) (sandbox.Provider, error) {
			nameResolverCalls++
			return nil, fallbackErr
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != expectedProvider {
		t.Fatal("expected provider from state resolver")
	}
	if stateResolverCalls != 1 {
		t.Fatalf("state resolver calls = %d, want 1", stateResolverCalls)
	}
	if nameResolverCalls != 0 {
		t.Fatalf("name resolver calls = %d, want 0", nameResolverCalls)
	}
}
