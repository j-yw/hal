//go:build podman_integration
// +build podman_integration

package rootlesspodman_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
)

func TestPodmanIntegrationLifecycleExecAndCopy(t *testing.T) {
	image := strings.TrimSpace(os.Getenv("HAL_PODMAN_TEST_IMAGE"))
	if image == "" {
		t.Skip("HAL_PODMAN_TEST_IMAGE is unset; set it to a locally available image to run Podman integration tests")
	}
	podmanPath := podmanIntegrationExecutable(t)
	requireLocalPodmanImage(t, podmanPath, image)

	runner := rootlesspodman.DefaultCommandRunner{}
	driver := rootlesspodman.New(rootlesspodman.Options{
		LifecycleRunner: runner,
		ExecRunner:      runner,
		CopyRunner:      runner,
		PodmanPath:      podmanPath,
		Image:           image,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	containerName := fmt.Sprintf("hal-podman-it-%d-%d", os.Getpid(), time.Now().UnixNano())
	target, err := driver.Create(ctx, sandboxruntime.CreateRequest{Name: containerName})
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = driver.Delete(cleanupCtx, sandboxruntime.LifecycleRequest{Target: *target})
	})
	assertPodmanIntegrationTarget(t, target, image, sandbox.StatusStopped)
	assertNoForbiddenPodmanIntegrationConfig(t, podmanPath, podmanIntegrationTargetRef(target))

	target, err = driver.Start(ctx, sandboxruntime.LifecycleRequest{Target: *target})
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	assertPodmanIntegrationTarget(t, target, image, sandbox.StatusRunning)

	target, err = driver.Inspect(ctx, sandboxruntime.InspectRequest{Target: *target})
	if err != nil {
		t.Fatalf("Inspect() failed: %v", err)
	}
	assertPodmanIntegrationTarget(t, target, image, sandbox.StatusRunning)

	var execOut bytes.Buffer
	execResult, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: *target,
		Args:   []string{"sh", "-c", "printf rootless-podman-exec"},
		Stdout: &execOut,
	})
	if err != nil {
		t.Fatalf("Exec() failed: %v", err)
	}
	if execResult.ExitCode != 0 {
		t.Fatalf("Exec() exit code = %d, want 0", execResult.ExitCode)
	}
	if got := execOut.String(); got != "rootless-podman-exec" {
		t.Fatalf("Exec() stdout = %q, want rootless-podman-exec", got)
	}

	tempDir := t.TempDir()
	localInput := filepath.Join(tempDir, "podman-input.txt")
	if err := os.WriteFile(localInput, []byte("copy-payload\n"), 0o644); err != nil {
		t.Fatalf("write local input: %v", err)
	}
	containerInput := "/workspace/hal-podman-input.txt"
	containerOutput := "/workspace/hal-podman-output.txt"
	if err := driver.CopyIn(ctx, sandboxruntime.CopyRequest{
		Target:          *target,
		SourcePath:      localInput,
		DestinationPath: containerInput,
	}); err != nil {
		t.Fatalf("CopyIn() failed: %v", err)
	}
	if _, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: *target,
		Args:   []string{"sh", "-c", "cat /workspace/hal-podman-input.txt > /workspace/hal-podman-output.txt"},
	}); err != nil {
		t.Fatalf("Exec() after CopyIn failed: %v", err)
	}
	localOutput := filepath.Join(tempDir, "podman-output.txt")
	if err := driver.CopyOut(ctx, sandboxruntime.CopyRequest{
		Target:          *target,
		SourcePath:      containerOutput,
		DestinationPath: localOutput,
	}); err != nil {
		t.Fatalf("CopyOut() failed: %v", err)
	}
	output, err := os.ReadFile(localOutput)
	if err != nil {
		t.Fatalf("read copied output: %v", err)
	}
	if got := string(output); got != "copy-payload\n" {
		t.Fatalf("CopyOut() content = %q, want copy-payload", got)
	}

	target, err = driver.Stop(ctx, sandboxruntime.LifecycleRequest{Target: *target})
	if err != nil {
		t.Fatalf("Stop() failed: %v", err)
	}
	assertPodmanIntegrationTarget(t, target, image, sandbox.StatusStopped)

	target, err = driver.Inspect(ctx, sandboxruntime.InspectRequest{Target: *target})
	if err != nil {
		t.Fatalf("Inspect() after Stop failed: %v", err)
	}
	assertPodmanIntegrationTarget(t, target, image, sandbox.StatusStopped)

	if err := driver.Delete(ctx, sandboxruntime.LifecycleRequest{Target: *target}); err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}
	deleted = true
}

func podmanIntegrationExecutable(t *testing.T) string {
	t.Helper()
	if podmanPath := strings.TrimSpace(os.Getenv("HAL_PODMAN_PATH")); podmanPath != "" {
		return podmanPath
	}
	podmanPath, err := exec.LookPath(rootlesspodman.DefaultPodmanExecutable)
	if err != nil {
		t.Skip("podman executable not found; skipping Podman integration test")
	}
	return podmanPath
}

func requireLocalPodmanImage(t *testing.T, podmanPath, image string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, podmanPath, "image", "exists", image)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return
	}
	if ctx.Err() != nil {
		t.Skipf("podman image exists timed out; skipping Podman integration test: %v", ctx.Err())
	}
	var execErr *exec.Error
	if errors.As(err, &execErr) {
		t.Skipf("podman executable %q is unavailable: %v", podmanPath, execErr)
	}
	t.Skipf("HAL_PODMAN_TEST_IMAGE %q is not available locally; pull it manually before running this integration test (%s)", image, podmanIntegrationDetail(output, err))
}

func assertPodmanIntegrationTarget(t *testing.T, target *sandboxruntime.Target, image, status string) {
	t.Helper()
	if target == nil {
		t.Fatal("target is nil")
	}
	if target.Status != status {
		t.Fatalf("target status = %q, want %q", target.Status, status)
	}
	if target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("runtime driver = %q, want %q", target.Runtime.Driver, sandboxruntime.DriverRootlessPodman)
	}
	if target.Runtime.Image != image {
		t.Fatalf("runtime image = %q, want %q", target.Runtime.Image, image)
	}
	if target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
		t.Fatalf("runtime isolation = %q, want %q", target.Runtime.IsolationLevel, sandbox.SandboxIsolationLevelContainer)
	}
	if podmanIntegrationTargetRef(target) == "" {
		t.Fatalf("target has no runtime reference: %#v", target)
	}
}

func assertNoForbiddenPodmanIntegrationConfig(t *testing.T, podmanPath, targetRef string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, podmanPath, "inspect", targetRef)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("podman inspect %q failed while checking integration container config: %v", targetRef, err)
	}
	lowerOutput := strings.ToLower(string(output))
	for _, forbidden := range []string{"--privileged", "/var/run/docker.sock", "/run/docker.sock", "docker.sock"} {
		if strings.Contains(lowerOutput, forbidden) {
			t.Fatalf("integration container inspect output contains forbidden token %q", forbidden)
		}
	}

	var entries []struct {
		HostConfig struct {
			Privileged bool `json:"Privileged"`
		} `json:"HostConfig"`
	}
	if err := json.Unmarshal(output, &entries); err != nil {
		t.Fatalf("unmarshal podman inspect output: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("podman inspect returned no container entries")
	}
	if entries[0].HostConfig.Privileged {
		t.Fatal("integration container is privileged")
	}
}

func podmanIntegrationTargetRef(target *sandboxruntime.Target) string {
	if target == nil {
		return ""
	}
	for _, value := range []string{target.Runtime.RuntimeID, target.ID, target.Name} {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func podmanIntegrationDetail(output []byte, err error) string {
	detail := strings.TrimSpace(string(output))
	if detail == "" && err != nil {
		detail = err.Error()
	}
	detail = strings.Join(strings.Fields(detail), " ")
	if len(detail) > 200 {
		detail = detail[:200] + "..."
	}
	return detail
}
