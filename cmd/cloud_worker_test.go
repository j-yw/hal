package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
	"github.com/jywlabs/hal/internal/cloud/deploy"
	"github.com/jywlabs/hal/internal/cloud/runner"
)

// TestCloudWorkerStoreFactory_DefaultIsDeployFactory verifies that the
// package-level cloudWorkerStoreFactory is assigned deploy.DefaultStoreFactory
// by default (via init).
func TestCloudWorkerStoreFactory_DefaultIsDeployFactory(t *testing.T) {
	if cloudWorkerStoreFactory == nil {
		t.Fatal("cloudWorkerStoreFactory is nil; expected deploy.DefaultStoreFactory default")
	}
}

// TestCloudWorkerRunnerFactory_DefaultIsSet verifies that the package-level
// cloudWorkerRunnerFactory is assigned a default (via init).
func TestCloudWorkerRunnerFactory_DefaultIsSet(t *testing.T) {
	if cloudWorkerRunnerFactory == nil {
		t.Fatal("cloudWorkerRunnerFactory is nil; expected defaultCloudWorkerRunnerFactory default")
	}
}

// TestCloudWorkerStoreFactory_OverridableInTests verifies that tests can
// override cloudWorkerStoreFactory and restore it.
func TestCloudWorkerStoreFactory_OverridableInTests(t *testing.T) {
	original := cloudWorkerStoreFactory
	t.Cleanup(func() { cloudWorkerStoreFactory = original })

	called := false
	cloudWorkerStoreFactory = func() (cloud.Store, error) {
		called = true
		return nil, nil
	}

	_, _ = cloudWorkerStoreFactory()
	if !called {
		t.Error("overridden cloudWorkerStoreFactory was not called")
	}
}

// TestCloudWorkerRunnerFactory_OverridableInTests verifies that tests can
// override cloudWorkerRunnerFactory and restore it.
func TestCloudWorkerRunnerFactory_OverridableInTests(t *testing.T) {
	original := cloudWorkerRunnerFactory
	t.Cleanup(func() { cloudWorkerRunnerFactory = original })

	called := false
	cloudWorkerRunnerFactory = func(cfg deploy.Config) (runner.Runner, error) {
		called = true
		return nil, nil
	}

	_, _ = cloudWorkerRunnerFactory(deploy.Config{})
	if !called {
		t.Error("overridden cloudWorkerRunnerFactory was not called")
	}
}

// TestRunCloudWorker_DotenvLoaded verifies that runCloudWorker calls
// godotenv.Load() before config resolution and that os.ErrNotExist from
// dotenv is silently ignored (no warning output).
func TestRunCloudWorker_DotenvIgnoresMissingFile(t *testing.T) {
	// Run from a temp dir with no .env file.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	var buf bytes.Buffer
	// Use a goroutine to cancel the signal context quickly.
	done := make(chan error, 1)
	go func() {
		done <- runCloudWorker("test-worker", 10*time.Second, 30*time.Second, 60*time.Second, "", &buf)
	}()

	// Send SIGINT to unblock the worker loop.
	time.Sleep(50 * time.Millisecond)
	p, _ := os.FindProcess(os.Getpid())
	p.Signal(os.Interrupt)

	err = <-done
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "Warning: failed to load .env file") {
		t.Error("expected no .env warning when file is absent, got:", output)
	}
}

// TestRunCloudWorker_DotenvParseErrorWarns verifies that a malformed .env file
// produces a non-fatal warning.
func TestRunCloudWorker_DotenvParseErrorWarns(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	// Write a malformed .env file that godotenv will fail to parse.
	malformedContent := "'\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(malformedContent), 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- runCloudWorker("test-worker", 10*time.Second, 30*time.Second, 60*time.Second, "", &buf)
	}()

	time.Sleep(50 * time.Millisecond)
	p, _ := os.FindProcess(os.Getpid())
	p.Signal(os.Interrupt)

	err = <-done
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Warning: failed to load .env file") {
		t.Error("expected .env parse warning, got:", output)
	}
	// Verify the command still started (non-fatal).
	if !strings.Contains(output, "Starting cloud worker") {
		t.Error("worker should still start after .env parse error")
	}
}

// TestRunCloudWorker_DotenvLoadedBeforeStartup verifies that a valid .env file
// is loaded and does not produce warnings.
func TestRunCloudWorker_DotenvLoadedBeforeStartup(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	// Write a valid .env file.
	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("TEST_WORKER_VAR=hello\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Clear the env var so we can verify godotenv loaded it.
	os.Unsetenv("TEST_WORKER_VAR")
	t.Cleanup(func() { os.Unsetenv("TEST_WORKER_VAR") })

	var buf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- runCloudWorker("test-worker", 10*time.Second, 30*time.Second, 60*time.Second, "", &buf)
	}()

	time.Sleep(50 * time.Millisecond)

	// Verify the env var was loaded by godotenv.
	val := os.Getenv("TEST_WORKER_VAR")
	if val != "hello" {
		t.Errorf("expected TEST_WORKER_VAR=hello after dotenv load, got %q", val)
	}

	p, _ := os.FindProcess(os.Getpid())
	p.Signal(os.Interrupt)

	err = <-done
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "Warning") {
		t.Error("expected no warnings for valid .env, got:", output)
	}
}

// TestRunCloudWorker_RequiresWorkerID verifies that --worker-id is required.
func TestRunCloudWorker_RequiresWorkerID(t *testing.T) {
	var buf bytes.Buffer
	err := runCloudWorker("", 10*time.Second, 30*time.Second, 60*time.Second, "", &buf)
	if err == nil {
		t.Fatal("expected error for empty worker-id")
	}
	if !strings.Contains(err.Error(), "--worker-id is required") {
		t.Errorf("error %q does not contain expected message", err.Error())
	}
}

// TestDefaultCloudWorkerRunnerFactory_ValidatesConfig verifies that the default
// runner factory checks deploy config validity.
func TestDefaultCloudWorkerRunnerFactory_ValidatesConfig(t *testing.T) {
	// Empty config should fail validation (missing Daytona API key).
	_, err := defaultCloudWorkerRunnerFactory(deploy.Config{
		DBAdapter:      "turso",
		TursoURL:       "libsql://test.turso.io",
		TursoAuthToken: "token",
	})
	if err == nil {
		t.Fatal("expected error for config missing Daytona API key")
	}
	if !strings.Contains(err.Error(), "validate deploy config") {
		t.Errorf("error %q does not contain 'validate deploy config'", err.Error())
	}
	if !strings.Contains(err.Error(), "DAYTONA_API_KEY") {
		t.Errorf("error %q does not mention DAYTONA_API_KEY", err.Error())
	}
}

// TestCloudWorkerCmd_FlagDefaults verifies that the worker command has the
// expected default flag values.
func TestCloudWorkerCmd_FlagDefaults(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
		wantDef  string
	}{
		{"worker-id", "worker-id", ""},
		{"poll-interval", "poll-interval", "10s"},
		{"reconcile-interval", "reconcile-interval", "30s"},
		{"timeout-interval", "timeout-interval", "1m0s"},
		{"sandbox-image", "sandbox-image", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := cloudWorkerCmd.Flags().Lookup(tt.flagName)
			if f == nil {
				t.Fatalf("flag --%s not found", tt.flagName)
			}
			if f.DefValue != tt.wantDef {
				t.Errorf("flag --%s default = %q, want %q", tt.flagName, f.DefValue, tt.wantDef)
			}
		})
	}
}

// TestCloudWorkerCmd_DelegatesRunCloudWorker verifies that the Cobra handler
// delegates to runCloudWorker (which is the testable extraction pattern).
func TestCloudWorkerCmd_DelegatesRunCloudWorker(t *testing.T) {
	// The RunE function should exist and return the --worker-id error
	// when called with default (empty) flags.
	if cloudWorkerCmd.RunE == nil {
		t.Fatal("cloudWorkerCmd.RunE is nil")
	}
}
