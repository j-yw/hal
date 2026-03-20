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

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

// mockProvider implements sandbox.Provider for testing.
type mockProvider struct {
	createResult *sandbox.SandboxResult
	createErr    error
	createCalls  []mockCreateCall
}

type mockCreateCall struct {
	Name string
	Env  map[string]string
}

func (m *mockProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*sandbox.SandboxResult, error) {
	m.createCalls = append(m.createCalls, mockCreateCall{Name: name, Env: env})
	return m.createResult, m.createErr
}

func (m *mockProvider) Stop(ctx context.Context, name string, out io.Writer) error {
	return nil
}

func (m *mockProvider) Delete(ctx context.Context, name string, out io.Writer) error {
	return nil
}

func (m *mockProvider) SSH(name string) (*exec.Cmd, error) {
	return nil, nil
}

func (m *mockProvider) Exec(name string, args []string) (*exec.Cmd, error) {
	return nil, nil
}

func (m *mockProvider) Status(ctx context.Context, name string, out io.Writer) error {
	return nil
}

func setupStartTest(t *testing.T, dir string) {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Write a minimal config
	sandboxCfg := &compound.SandboxConfig{
		Provider: "daytona",
		Env:      map[string]string{},
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}
}

func fakeBranchResolver(branch string, err error) branchResolver {
	return func() (string, error) {
		return branch, err
	}
}

func TestRunSandboxStart_Success(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "hal-feature-auth"},
	}

	var out bytes.Buffer
	err := runSandboxStartWithDeps(dir, "", nil, &out, mock, fakeBranchResolver("hal/feature-auth", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.createCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(mock.createCalls))
	}
	if mock.createCalls[0].Name != "hal-feature-auth" {
		t.Errorf("Create name = %q, want %q", mock.createCalls[0].Name, "hal-feature-auth")
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

	// Verify output mentions provider
	if !strings.Contains(out.String(), "Sandbox started") {
		t.Errorf("output missing 'Sandbox started': %q", out.String())
	}
}

func TestRunSandboxStart_ExplicitName(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "my-sandbox"},
	}

	err := runSandboxStartWithDeps(dir, "my-sandbox", nil, io.Discard, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.createCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(mock.createCalls))
	}
	if mock.createCalls[0].Name != "my-sandbox" {
		t.Errorf("Create name = %q, want %q", mock.createCalls[0].Name, "my-sandbox")
	}
}

func TestRunSandboxStart_EnvVarsFromConfig(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	sandboxCfg := &compound.SandboxConfig{
		Provider: "daytona",
		Env: map[string]string{
			"GIT_TOKEN": "ghp_from_config",
			"API_KEY":   "sk-from-config",
		},
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb"},
	}

	// CLI env overrides config
	cliEnv := map[string]string{"API_KEY": "sk-from-cli"}

	err := runSandboxStartWithDeps(dir, "sb", cliEnv, io.Discard, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.createCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(mock.createCalls))
	}
	env := mock.createCalls[0].Env
	if env["GIT_TOKEN"] != "ghp_from_config" {
		t.Errorf("GIT_TOKEN = %q, want from config", env["GIT_TOKEN"])
	}
	if env["API_KEY"] != "sk-from-cli" {
		t.Errorf("API_KEY = %q, want from CLI override", env["API_KEY"])
	}
}

func TestRunSandboxStart_ProviderAndIPSaved(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	sandboxCfg := &compound.SandboxConfig{
		Provider: "hetzner",
		Env:      map[string]string{},
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "my-server", IP: "10.0.0.42"},
	}

	var out bytes.Buffer
	err := runSandboxStartWithDeps(dir, "my-server", nil, &out, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, err := sandbox.LoadState(halDir)
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}
	if state.Provider != "hetzner" {
		t.Errorf("state.Provider = %q, want %q", state.Provider, "hetzner")
	}
	if state.IP != "10.0.0.42" {
		t.Errorf("state.IP = %q, want %q", state.IP, "10.0.0.42")
	}
	if !strings.Contains(out.String(), "hetzner") {
		t.Errorf("output should mention provider: %q", out.String())
	}
}

func TestRunSandboxStart_CreateFailure(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createErr: fmt.Errorf("quota exceeded"),
	}

	err := runSandboxStartWithDeps(dir, "sb", nil, io.Discard, mock, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "sandbox creation failed") {
		t.Errorf("error %q should contain 'sandbox creation failed'", err.Error())
	}
}

func TestRunSandboxStart_BranchFailure(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{}

	err := runSandboxStartWithDeps(dir, "", nil, io.Discard, mock, fakeBranchResolver("", fmt.Errorf("not on a branch")))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "could not determine sandbox name from git branch") {
		t.Errorf("error %q missing branch failure text", err.Error())
	}
}

func TestRunSandboxStart_HalDirMissing(t *testing.T) {
	dir := t.TempDir()

	err := runSandboxStartWithDeps(dir, "sb", nil, io.Discard, nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), ".hal/ not found") {
		t.Errorf("error %q should mention .hal/", err.Error())
	}
}

func TestSandboxStartCommandFlags(t *testing.T) {
	if sandboxStartCmd.Flags().Lookup("name") == nil {
		t.Fatal("--name flag should exist")
	}
	if sandboxStartCmd.Flags().Lookup("env") == nil {
		t.Fatal("--env flag should exist")
	}
}
