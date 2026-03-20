package cmd

import (
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

// mockSSHProvider implements sandbox.Provider for SSH tests.
type mockSSHProvider struct {
	sshCmd     *exec.Cmd
	sshErr     error
	execCmd    *exec.Cmd
	execErr    error
	sshCalls   []string
	execCalls  []mockExecCall
}

type mockExecCall struct {
	Name string
	Args []string
}

func (m *mockSSHProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}
func (m *mockSSHProvider) Stop(ctx context.Context, name string, out io.Writer) error   { return nil }
func (m *mockSSHProvider) Delete(ctx context.Context, name string, out io.Writer) error { return nil }
func (m *mockSSHProvider) Status(ctx context.Context, name string, out io.Writer) error { return nil }

func (m *mockSSHProvider) SSH(name string) (*exec.Cmd, error) {
	m.sshCalls = append(m.sshCalls, name)
	if m.sshErr != nil {
		return nil, m.sshErr
	}
	if m.sshCmd != nil {
		return m.sshCmd, nil
	}
	// Default: return a simple command
	cmd := exec.Command("ssh", "root@10.0.0.1")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func (m *mockSSHProvider) Exec(name string, args []string) (*exec.Cmd, error) {
	m.execCalls = append(m.execCalls, mockExecCall{Name: name, Args: args})
	if m.execErr != nil {
		return nil, m.execErr
	}
	if m.execCmd != nil {
		return m.execCmd, nil
	}
	cmdArgs := append([]string{"root@10.0.0.1", "--"}, args...)
	cmd := exec.Command("ssh", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func setupSSHTestWithState(t *testing.T, dir string, state *sandbox.SandboxState) {
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

func TestRunSandboxSSH_InteractiveMode(t *testing.T) {
	dir := t.TempDir()
	setupSSHTestWithState(t, dir, &sandbox.SandboxState{
		Name:      "my-sandbox",
		Provider:  "daytona",
		CreatedAt: time.Now(),
	})

	mock := &mockSSHProvider{}
	lastSSHCmd = nil

	// testMode=true so we don't actually exec
	err := runSandboxSSH(dir, nil, io.Discard, mock, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.sshCalls) != 1 {
		t.Fatalf("expected 1 SSH call, got %d", len(mock.sshCalls))
	}
	if mock.sshCalls[0] != "my-sandbox" {
		t.Errorf("SSH name = %q, want %q", mock.sshCalls[0], "my-sandbox")
	}

	if lastSSHCmd == nil {
		t.Fatal("expected lastSSHCmd to be set")
	}
	if !strings.Contains(strings.Join(lastSSHCmd.Args, " "), "ssh") {
		t.Errorf("expected SSH command, got %v", lastSSHCmd.Args)
	}
}

func TestRunSandboxSSH_ExecMode(t *testing.T) {
	dir := t.TempDir()
	setupSSHTestWithState(t, dir, &sandbox.SandboxState{
		Name:      "my-sandbox",
		Provider:  "hetzner",
		IP:        "10.0.0.42",
		CreatedAt: time.Now(),
	})

	mock := &mockSSHProvider{}
	lastSSHCmd = nil

	err := runSandboxSSH(dir, []string{"--", "ls", "-la"}, io.Discard, mock, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.execCalls) != 1 {
		t.Fatalf("expected 1 Exec call, got %d", len(mock.execCalls))
	}
	if mock.execCalls[0].Name != "my-sandbox" {
		t.Errorf("Exec name = %q, want %q", mock.execCalls[0].Name, "my-sandbox")
	}
	wantArgs := []string{"ls", "-la"}
	if len(mock.execCalls[0].Args) != len(wantArgs) {
		t.Fatalf("Exec args = %v, want %v", mock.execCalls[0].Args, wantArgs)
	}
	for i, want := range wantArgs {
		if mock.execCalls[0].Args[i] != want {
			t.Errorf("Exec args[%d] = %q, want %q", i, mock.execCalls[0].Args[i], want)
		}
	}

	if lastSSHCmd == nil {
		t.Fatal("expected lastSSHCmd to be set")
	}
}

func TestRunSandboxSSH_NoState(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	mock := &mockSSHProvider{}
	err := runSandboxSSH(dir, nil, io.Discard, mock, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no active sandbox") {
		t.Errorf("error %q should contain 'no active sandbox'", err.Error())
	}
}

func TestRunSandboxSSH_InvalidState(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(halDir, template.SandboxFile), []byte("{"), 0644); err != nil {
		t.Fatal(err)
	}

	mock := &mockSSHProvider{}
	err := runSandboxSSH(dir, nil, io.Discard, mock, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "loading sandbox state") {
		t.Errorf("error %q should contain 'loading sandbox state'", err.Error())
	}
}

func TestRunSandboxSSH_SSHError(t *testing.T) {
	dir := t.TempDir()
	setupSSHTestWithState(t, dir, &sandbox.SandboxState{
		Name:      "my-sandbox",
		Provider:  "hetzner",
		CreatedAt: time.Now(),
	})

	mock := &mockSSHProvider{sshErr: fmt.Errorf("no IP in state")}
	err := runSandboxSSH(dir, nil, io.Discard, mock, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "building SSH command") {
		t.Errorf("error %q should contain 'building SSH command'", err.Error())
	}
}

func TestStripDashDash(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"with --", []string{"--", "ls", "-la"}, []string{"ls", "-la"}},
		{"without --", []string{"ls", "-la"}, []string{"ls", "-la"}},
		{"only --", []string{"--"}, []string{}},
		{"nil", nil, nil},
		{"empty", []string{}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripDashDash(tt.args)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
