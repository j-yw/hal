package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

func TestRunSandboxMigrate_NoActionsReportsNothing(t *testing.T) {
	originalMigrate := sandboxMigrate
	t.Cleanup(func() { sandboxMigrate = originalMigrate })

	sandboxMigrate = func(projectDir string, out io.Writer) error {
		// No output emitted → no actions taken.
		return nil
	}

	var out bytes.Buffer
	if err := runSandboxMigrate(".", &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Nothing to migrate\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestRunSandboxMigrate_ForwardsMigrationOutput(t *testing.T) {
	originalMigrate := sandboxMigrate
	t.Cleanup(func() { sandboxMigrate = originalMigrate })

	sandboxMigrate = func(projectDir string, out io.Writer) error {
		fmt.Fprintln(out, "Migrated sandbox config to /home/user/.config/hal/sandbox-config.yaml")
		return nil
	}

	var out bytes.Buffer
	if err := runSandboxMigrate(".", &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Migrated sandbox config to /home/user/.config/hal/sandbox-config.yaml\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestRunSandboxMigrate_ReturnsError(t *testing.T) {
	originalMigrate := sandboxMigrate
	t.Cleanup(func() { sandboxMigrate = originalMigrate })

	sandboxMigrate = func(projectDir string, out io.Writer) error {
		return fmt.Errorf("read project sandbox config: permission denied")
	}

	var out bytes.Buffer
	err := runSandboxMigrate(".", &out)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error = %q, want to contain %q", err.Error(), "permission denied")
	}

	if out.Len() != 0 {
		t.Fatalf("expected no output on error, got %q", out.String())
	}
}

func TestRunSandboxMigrate_NonInteractive(t *testing.T) {
	// Verify migrate command does not read from stdin — it's non-interactive.
	originalMigrate := sandboxMigrate
	t.Cleanup(func() { sandboxMigrate = originalMigrate })

	sandboxMigrate = func(projectDir string, out io.Writer) error {
		return nil
	}

	var out bytes.Buffer
	// No stdin provided — command should not block or fail.
	if err := runSandboxMigrate(".", &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunSandboxMigrate_PassesProjectDir(t *testing.T) {
	originalMigrate := sandboxMigrate
	t.Cleanup(func() { sandboxMigrate = originalMigrate })

	var capturedDir string
	sandboxMigrate = func(projectDir string, out io.Writer) error {
		capturedDir = projectDir
		return nil
	}

	var out bytes.Buffer
	if err := runSandboxMigrate("/some/project", &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedDir != "/some/project" {
		t.Fatalf("projectDir = %q, want %q", capturedDir, "/some/project")
	}
}

func TestRunSandboxMigrate_IntegrationWithRealMigrate(t *testing.T) {
	// Use real sandbox.Migrate to verify end-to-end behavior.
	originalMigrate := sandboxMigrate
	t.Cleanup(func() { sandboxMigrate = originalMigrate })
	sandboxMigrate = sandbox.Migrate

	globalHome := filepath.Join(t.TempDir(), "hal-global")
	t.Setenv("HAL_CONFIG_HOME", globalHome)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", t.TempDir())

	projectDir := t.TempDir()

	// Case 1: No local config → "Nothing to migrate"
	var out bytes.Buffer
	if err := runSandboxMigrate(projectDir, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.String() != "Nothing to migrate\n" {
		t.Fatalf("expected 'Nothing to migrate', got %q", out.String())
	}

	// Case 2: Create local config with sandbox section → migration happens
	halDir := filepath.Join(projectDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	configContent := `sandbox:
  provider: hetzner
  hetzner:
    sshKey: my-key
`
	if err := os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte(configContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	out.Reset()
	if err := runSandboxMigrate(projectDir, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), "Migrated sandbox config") {
		t.Fatalf("expected migration output, got %q", out.String())
	}

	// Case 3: Run again → no-op since global config now exists
	out.Reset()
	if err := runSandboxMigrate(projectDir, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.String() != "Nothing to migrate\n" {
		t.Fatalf("expected 'Nothing to migrate' on repeat, got %q", out.String())
	}
}

func TestSandboxMigrateCommand_Metadata(t *testing.T) {
	cmd := sandboxMigrateCmd
	if cmd.Use != "migrate" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "migrate")
	}
	if cmd.Short == "" {
		t.Fatal("Short is empty")
	}
	if cmd.Long == "" {
		t.Fatal("Long is empty")
	}
	if cmd.Example == "" {
		t.Fatal("Example is empty")
	}
	if !strings.Contains(cmd.Example, "hal sandbox migrate") {
		t.Fatalf("Example should contain command path, got %q", cmd.Example)
	}
}
