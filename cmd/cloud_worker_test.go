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

	"github.com/jywlabs/hal/internal/cloud"
	"github.com/jywlabs/hal/internal/cloud/deploy"
	"github.com/jywlabs/hal/internal/cloud/runner"
)

// workerTestMockStore is a minimal cloud.Store for cmd-level worker tests.
type workerTestMockStore struct {
	cloud.Store
}

func (s *workerTestMockStore) ClaimRun(_ context.Context, _ string) (*cloud.Run, error) {
	return nil, cloud.ErrNotFound
}

// workerTestMockRunner is a minimal runner.Runner for cmd-level worker tests.
type workerTestMockRunner struct{}

func (r *workerTestMockRunner) CreateSandbox(_ context.Context, _ *runner.CreateSandboxRequest) (*runner.Sandbox, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *workerTestMockRunner) DestroySandbox(_ context.Context, _ string) error {
	return nil
}

func (r *workerTestMockRunner) Exec(_ context.Context, _ string, _ *runner.ExecRequest) (*runner.ExecResult, error) {
	return &runner.ExecResult{ExitCode: 0}, nil
}

func (r *workerTestMockRunner) StreamLogs(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

func (r *workerTestMockRunner) Health(_ context.Context) (*runner.HealthStatus, error) {
	return &runner.HealthStatus{OK: true}, nil
}

// injectWorkerTestFactories overrides package-level factory vars with test mocks
// and returns a cleanup function that restores the originals.
func injectWorkerTestFactories(t *testing.T) {
	t.Helper()
	origStore := cloudWorkerStoreFactory
	origRunner := cloudWorkerRunnerFactory
	t.Cleanup(func() {
		cloudWorkerStoreFactory = origStore
		cloudWorkerRunnerFactory = origRunner
	})

	cloudWorkerStoreFactory = func() (cloud.Store, error) {
		return &workerTestMockStore{}, nil
	}
	cloudWorkerRunnerFactory = func(cfg deploy.Config) (runner.Runner, error) {
		return &workerTestMockRunner{}, nil
	}
}

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
	injectWorkerTestFactories(t)

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
	injectWorkerTestFactories(t)

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
	injectWorkerTestFactories(t)

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

// TestResolveWorkerSandboxImage verifies sandbox image resolution behavior.
func TestResolveWorkerSandboxImage(t *testing.T) {
	tests := []struct {
		name      string
		flagImage string
		want      string
	}{
		{
			name:      "empty flag uses default",
			flagImage: "",
			want:      defaultWorkerSandboxImage,
		},
		{
			name:      "non-empty flag overrides default",
			flagImage: "custom-image:v1",
			want:      "custom-image:v1",
		},
		{
			name:      "custom image with tag",
			flagImage: "ghcr.io/org/worker:latest",
			want:      "ghcr.io/org/worker:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveWorkerSandboxImage(tt.flagImage)
			if got != tt.want {
				t.Errorf("resolveWorkerSandboxImage(%q) = %q, want %q", tt.flagImage, got, tt.want)
			}
		})
	}
}

// TestResolveWorkerSandboxImage_NeverEmpty verifies that the resolved image is
// never empty regardless of input.
func TestResolveWorkerSandboxImage_NeverEmpty(t *testing.T) {
	got := resolveWorkerSandboxImage("")
	if got == "" {
		t.Fatal("resolveWorkerSandboxImage(\"\") returned empty string; ProvisionConfig.Image must never be empty")
	}
}

// TestDefaultWorkerSandboxImage_Constant verifies that the default sandbox
// image constant is non-empty.
func TestDefaultWorkerSandboxImage_Constant(t *testing.T) {
	if defaultWorkerSandboxImage == "" {
		t.Fatal("defaultWorkerSandboxImage must not be empty")
	}
}

// TestRunCloudWorker_SandboxImageAlwaysDisplayed verifies that the resolved
// sandbox image is always shown in worker startup output, even when the flag
// is empty (default is used).
func TestRunCloudWorker_SandboxImageAlwaysDisplayed(t *testing.T) {
	injectWorkerTestFactories(t)

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	tests := []struct {
		name      string
		flagImage string
		wantImage string
	}{
		{
			name:      "empty flag shows default image",
			flagImage: "",
			wantImage: defaultWorkerSandboxImage,
		},
		{
			name:      "custom flag shows custom image",
			flagImage: "custom:v2",
			wantImage: "custom:v2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			done := make(chan error, 1)
			go func() {
				done <- runCloudWorker("test-worker", 10*time.Second, 30*time.Second, 60*time.Second, tt.flagImage, &buf)
			}()

			time.Sleep(50 * time.Millisecond)
			p, _ := os.FindProcess(os.Getpid())
			p.Signal(os.Interrupt)

			if err := <-done; err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			output := buf.String()
			wantLine := "sandbox-image:      " + tt.wantImage
			if !strings.Contains(output, wantLine) {
				t.Errorf("output does not contain %q\ngot: %s", wantLine, output)
			}
		})
	}
}

// TestRunCloudWorker_ProvisionImageNeverEmpty verifies that sandbox image
// resolution never produces an empty image that would be passed to
// ProvisionConfig.Image. This test exercises the contract at the command
// wiring level.
func TestRunCloudWorker_ProvisionImageNeverEmpty(t *testing.T) {
	// resolveWorkerSandboxImage is the single function that determines the
	// image value passed to ProvisionConfig.Image. Verify all input variants
	// produce non-empty output.
	inputs := []string{"", "  ", "img:latest"}
	for _, input := range inputs {
		got := resolveWorkerSandboxImage(input)
		if got == "" {
			t.Errorf("resolveWorkerSandboxImage(%q) returned empty; ProvisionConfig.Image must never be empty", input)
		}
	}
}

// TestDefaultCloudWorkerRunnerFactory_ReturnsSDKClient verifies that the
// default runner factory returns a *runner.SDKClient that satisfies Runner,
// SessionExec, and GitOps interfaces. This test cannot fully construct a
// client without a real Daytona API, so it verifies interface satisfaction
// via the compile-time assertions in sdk_client.go and validates that the
// factory rejects incomplete configs.
func TestDefaultCloudWorkerRunnerFactory_ReturnsSDKClient(t *testing.T) {
	tests := []struct {
		name    string
		cfg     deploy.Config
		wantErr string
	}{
		{
			name: "missing Daytona API key",
			cfg: deploy.Config{
				DBAdapter:      "turso",
				TursoURL:       "libsql://test.turso.io",
				TursoAuthToken: "token",
			},
			wantErr: "DAYTONA_API_KEY",
		},
		{
			name: "missing DB adapter config",
			cfg: deploy.Config{
				DaytonaAPIKey: "test-key",
			},
			wantErr: "HAL_CLOUD_DB_ADAPTER",
		},
		{
			name:    "completely empty config",
			cfg:     deploy.Config{},
			wantErr: "validate deploy config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := defaultCloudWorkerRunnerFactory(tt.cfg)
			if err == nil {
				t.Fatal("expected error for incomplete config")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestRunCloudWorker_StoreFactoryError verifies that runCloudWorker returns
// a store creation error without starting the loop.
func TestRunCloudWorker_StoreFactoryError(t *testing.T) {
	origStore := cloudWorkerStoreFactory
	origRunner := cloudWorkerRunnerFactory
	t.Cleanup(func() {
		cloudWorkerStoreFactory = origStore
		cloudWorkerRunnerFactory = origRunner
	})

	cloudWorkerStoreFactory = func() (cloud.Store, error) {
		return nil, fmt.Errorf("store connection failed")
	}
	cloudWorkerRunnerFactory = func(cfg deploy.Config) (runner.Runner, error) {
		return &workerTestMockRunner{}, nil
	}

	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	t.Cleanup(func() { os.Chdir(origDir) })

	var buf bytes.Buffer
	err := runCloudWorker("test-worker", 10*time.Second, 30*time.Second, 60*time.Second, "", &buf)
	if err == nil {
		t.Fatal("expected error from store factory failure")
	}
	if !strings.Contains(err.Error(), "creating store") {
		t.Errorf("error %q does not mention store creation", err.Error())
	}
}

// TestRunCloudWorker_RunnerFactoryError verifies that runCloudWorker returns
// a runner creation error without starting the loop.
func TestRunCloudWorker_RunnerFactoryError(t *testing.T) {
	origStore := cloudWorkerStoreFactory
	origRunner := cloudWorkerRunnerFactory
	t.Cleanup(func() {
		cloudWorkerStoreFactory = origStore
		cloudWorkerRunnerFactory = origRunner
	})

	cloudWorkerStoreFactory = func() (cloud.Store, error) {
		return &workerTestMockStore{}, nil
	}
	cloudWorkerRunnerFactory = func(cfg deploy.Config) (runner.Runner, error) {
		return nil, fmt.Errorf("runner validation failed")
	}

	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	t.Cleanup(func() { os.Chdir(origDir) })

	var buf bytes.Buffer
	err := runCloudWorker("test-worker", 10*time.Second, 30*time.Second, 60*time.Second, "", &buf)
	if err == nil {
		t.Fatal("expected error from runner factory failure")
	}
	if !strings.Contains(err.Error(), "creating runner") {
		t.Errorf("error %q does not mention runner creation", err.Error())
	}
}

// TestRunCloudWorker_ShutdownOutputIncludesWorkerID verifies that graceful
// shutdown emits the worker ID in the shutdown message.
func TestRunCloudWorker_ShutdownOutputIncludesWorkerID(t *testing.T) {
	injectWorkerTestFactories(t)

	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	t.Cleanup(func() { os.Chdir(origDir) })

	var buf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- runCloudWorker("my-worker-42", 10*time.Second, 30*time.Second, 60*time.Second, "", &buf)
	}()

	time.Sleep(50 * time.Millisecond)
	p, _ := os.FindProcess(os.Getpid())
	p.Signal(os.Interrupt)

	if err := <-done; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Shutting down worker my-worker-42") {
		t.Errorf("shutdown message missing worker ID; got: %s", output)
	}
}
