//go:build worker_integration
// +build worker_integration

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	workerIntegrationEndpointEnv      = "HAL_WORKER_INTEGRATION_ENDPOINT"
	workerIntegrationHostNameEnv      = "HAL_WORKER_INTEGRATION_HOST_NAME"
	workerIntegrationRuntimeDriverEnv = "HAL_WORKER_INTEGRATION_RUNTIME_DRIVER"
	workerIntegrationImageEnv         = "HAL_WORKER_INTEGRATION_IMAGE"
)

type workerIntegrationConfig struct {
	Endpoint      string
	HostName      string
	RuntimeDriver string
	Image         string
}

func TestWorkerIntegrationRootlessPodmanExecutionThroughSharedResolver(t *testing.T) {
	cfg := requireWorkerIntegrationConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	host := &sandbox.SandboxHost{
		ID:                "worker-integration",
		Name:              cfg.HostName,
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          cfg.Endpoint,
		SupportedRuntimes: []string{sandboxruntime.DriverRootlessPodman},
	}
	driver, err := sandboxWorkerRuntimeDriverFromTarget(sandboxWorkerRuntimeRequest{
		Target: sandboxruntime.Target{
			Runtime: sandboxruntime.RuntimeState{
				Driver:         cfg.RuntimeDriver,
				Image:          cfg.Image,
				WorkerID:       host.ID,
				IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			},
		},
		Host: host,
	}, sandboxWorkerRuntimeDriverFactories{})
	if err != nil {
		t.Fatalf("sandboxWorkerRuntimeDriverFromTarget() error = %v", err)
	}

	targetName := fmt.Sprintf("hal-worker-it-%d-%d", os.Getpid(), time.Now().UnixNano())
	target, err := driver.Create(ctx, sandboxruntime.CreateRequest{Name: targetName})
	if err != nil {
		t.Fatalf("Create() through worker-backed resolver failed: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if target != nil && target.Status == sandbox.StatusRunning {
			stopped, stopErr := driver.Stop(cleanupCtx, sandboxruntime.LifecycleRequest{Target: *target})
			if stopErr == nil {
				target = stopped
			}
		}
		if target != nil {
			_ = driver.Delete(cleanupCtx, sandboxruntime.LifecycleRequest{Target: *target})
		}
	})

	assertWorkerIntegrationTarget(t, target, targetName, sandbox.StatusStopped, cfg.Image)

	target, err = driver.Start(ctx, sandboxruntime.LifecycleRequest{Target: *target})
	if err != nil {
		t.Fatalf("Start() through worker-backed resolver failed: %v", err)
	}
	assertWorkerIntegrationTarget(t, target, targetName, sandbox.StatusRunning, cfg.Image)

	const marker = "hal-worker-integration-exec"
	var stdout bytes.Buffer
	result, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: *target,
		Args:   []string{"sh", "-c", "printf " + marker},
		Stdout: &stdout,
	})
	if err != nil {
		t.Fatalf("Exec() through worker-backed resolver failed: %v", err)
	}
	if result == nil {
		t.Fatal("Exec() result is nil")
	}
	if result.ExitCode != 0 {
		t.Fatalf("Exec() exit code = %d, want 0", result.ExitCode)
	}
	if got := stdout.String(); got != marker {
		t.Fatalf("Exec() stdout = %q, want %q", got, marker)
	}

	target, err = driver.Stop(ctx, sandboxruntime.LifecycleRequest{Target: *target})
	if err != nil {
		t.Fatalf("Stop() through worker-backed resolver failed: %v", err)
	}
	assertWorkerIntegrationTarget(t, target, targetName, sandbox.StatusStopped, cfg.Image)

	if err := driver.Delete(ctx, sandboxruntime.LifecycleRequest{Target: *target}); err != nil {
		t.Fatalf("Delete() through worker-backed resolver failed: %v", err)
	}
	target = nil
}

func requireWorkerIntegrationConfig(t *testing.T) workerIntegrationConfig {
	t.Helper()

	cfg := workerIntegrationConfig{
		Endpoint:      strings.TrimSpace(os.Getenv(workerIntegrationEndpointEnv)),
		HostName:      strings.TrimSpace(os.Getenv(workerIntegrationHostNameEnv)),
		RuntimeDriver: strings.TrimSpace(os.Getenv(workerIntegrationRuntimeDriverEnv)),
		Image:         strings.TrimSpace(os.Getenv(workerIntegrationImageEnv)),
	}
	var missing []string
	if cfg.Endpoint == "" {
		missing = append(missing, workerIntegrationEndpointEnv)
	}
	if cfg.HostName == "" {
		missing = append(missing, workerIntegrationHostNameEnv)
	}
	if cfg.RuntimeDriver == "" {
		missing = append(missing, workerIntegrationRuntimeDriverEnv)
	}
	if cfg.Image == "" {
		missing = append(missing, workerIntegrationImageEnv)
	}
	if len(missing) > 0 {
		t.Skipf("worker integration environment is incomplete; set %s to run", strings.Join(missing, ", "))
	}
	if cfg.RuntimeDriver != sandboxruntime.DriverRootlessPodman {
		t.Skipf("%s=%q; worker integration currently exercises only %s", workerIntegrationRuntimeDriverEnv, cfg.RuntimeDriver, sandboxruntime.DriverRootlessPodman)
	}
	return cfg
}

func assertWorkerIntegrationTarget(t *testing.T, target *sandboxruntime.Target, name, status, image string) {
	t.Helper()
	if target == nil {
		t.Fatal("target is nil")
	}
	if target.Name != name {
		t.Fatalf("target name = %q, want %q", target.Name, name)
	}
	if target.Status != status {
		t.Fatalf("target status = %q, want %q", target.Status, status)
	}
	if target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("target runtime driver = %q, want %q", target.Runtime.Driver, sandboxruntime.DriverRootlessPodman)
	}
	if target.Runtime.Image != image {
		t.Fatalf("target image = %q, want %q", target.Runtime.Image, image)
	}
	if target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
		t.Fatalf("target isolation = %q, want %q", target.Runtime.IsolationLevel, sandbox.SandboxIsolationLevelContainer)
	}
	if strings.TrimSpace(target.Runtime.RuntimeID) == "" {
		t.Fatalf("target runtime id is empty: %#v", target)
	}
}
