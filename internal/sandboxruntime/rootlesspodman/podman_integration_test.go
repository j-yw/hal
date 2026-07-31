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
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
)

func TestL7PreparedLinuxRootlessPodmanRawPacketCapabilityProof(t *testing.T) {
	for _, marker := range []string{
		"HAL_NETWORK_ENFORCEMENT_LIVE",
		"HAL_NETWORK_ENFORCEMENT_LIVE_PROXY",
		"HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL",
		"HAL_L7_LINUX_NETWORK_INTEGRATION",
	} {
		if os.Getenv(marker) != "1" {
			t.Fatalf("%s=1 is required for the selected prepared-Linux L7 capability proof", marker)
		}
	}
	image := strings.TrimSpace(os.Getenv("HAL_PODMAN_TEST_IMAGE"))
	if image == "" {
		t.Fatal("HAL_PODMAN_TEST_IMAGE must name an already-local image for the selected prepared-Linux L7 capability proof")
	}
	podmanPath := strings.TrimSpace(os.Getenv("HAL_PODMAN_PATH"))
	if podmanPath == "" {
		var err error
		podmanPath, err = exec.LookPath(rootlesspodman.DefaultPodmanExecutable)
		if err != nil {
			t.Fatal("Podman is required for the selected prepared-Linux L7 capability proof")
		}
	}
	imageCtx, imageCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer imageCancel()
	if output, err := exec.CommandContext(imageCtx, podmanPath, "image", "exists", image).CombinedOutput(); err != nil {
		t.Fatalf("selected prepared-Linux L7 image prerequisite failed: %s", podmanIntegrationDetail(output, err))
	}

	runner := rootlesspodman.DefaultCommandRunner{}
	session := newFakeNetworkTopologySession(nil)
	identity := testNetworkTopologyIdentity()
	driver := rootlesspodman.New(rootlesspodman.Options{
		LifecycleRunner:       runner,
		PodmanPath:            podmanPath,
		Image:                 image,
		WorkDir:               "/",
		JobExecutionSupported: true,
		NetworkTopologyFactory: &fakeNetworkTopologyFactory{preparation: rootlesspodman.NetworkTopologyPreparation{
			Identity: identity, CreateArgs: testPastaCreateArgs(), Session: session,
		}},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	containerName := fmt.Sprintf("hal-l7-cap-proof-%d-%d", os.Getpid(), time.Now().UnixNano())
	target, err := driver.Create(ctx, sandboxruntime.CreateRequest{Name: containerName})
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}
	exactCreatedContainerID := target.Runtime.RuntimeID
	cleanupTarget := *target
	deletePending := true
	t.Cleanup(func() {
		cleanupErr := runL7PodmanExactContainerCleanup(deletePending, func() error {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			return driver.Delete(cleanupCtx, sandboxruntime.LifecycleRequest{Target: cleanupTarget})
		}, func() error {
			absenceCtx, absenceCancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer absenceCancel()
			return proveL7PodmanExactContainerAbsent(absenceCtx, podmanPath, exactCreatedContainerID)
		})
		if cleanupErr != nil {
			t.Errorf("selected prepared-Linux L7 exact-container cleanup failed: %v", cleanupErr)
		}
	})
	if !validL7PodmanExactContainerID(exactCreatedContainerID) {
		t.Fatal("Create() did not return an exact full Podman container ID")
	}
	session.mu.Lock()
	session.proof.RuntimeID = target.Runtime.RuntimeID
	session.mu.Unlock()
	target, err = driver.Start(ctx, sandboxruntime.LifecycleRequest{Target: *target})
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	cleanupTarget = *target
	correlation := networkenforcement.EnforcementCorrelation{
		SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkerID: identity.WorkerID,
		RuntimeID: identity.RuntimeGenerationID, PlanID: identity.PlanID, PolicySnapshotID: identity.PolicySnapshotID,
		ProxySessionID: identity.ProxySessionID, ProxyGenerationID: identity.ProxyGenerationID,
		TopologyGenerationID: identity.TopologyGenerationID, RuleGenerationID: identity.RuleGenerationID,
	}
	verifier := rootlesspodman.NewPodmanRawPacketIsolationVerifier(rootlesspodman.PodmanRawPacketIsolationVerifierOptions{
		LifecycleRunner: runner, PodmanPath: podmanPath, Identity: identity, Target: *target,
	})
	proof, err := verifier.VerifyRawPacketIsolation(ctx, correlation)
	if err != nil {
		t.Fatalf("VerifyRawPacketIsolation() failed: %v", err)
	}
	if !networkenforcement.RawPacketIsolationProofMatches(proof, correlation) {
		t.Fatalf("VerifyRawPacketIsolation() proof = %#v, want exact live correlation", proof)
	}
	if err := driver.Delete(ctx, sandboxruntime.LifecycleRequest{Target: *target}); err != nil {
		t.Fatal("Delete() failed for selected prepared-Linux L7 exact container")
	}
	deletePending = false
}

func proveL7PodmanExactContainerAbsent(ctx context.Context, podmanPath, exactContainerID string) error {
	return proveL7PodmanExactContainerAbsentWithRunner(ctx, podmanPath, exactContainerID, func(runCtx context.Context, executable string, args ...string) (int, error) {
		err := exec.CommandContext(runCtx, executable, args...).Run()
		if err == nil {
			return 0, nil
		}
		if runCtx.Err() != nil {
			return -1, runCtx.Err()
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return -1, err
	})
}

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
		WorkDir:         "/",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	containerName := fmt.Sprintf("hal-podman-it-%d-%d", os.Getpid(), time.Now().UnixNano())
	target, err := driver.Create(ctx, sandboxruntime.CreateRequest{Name: containerName})
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}
	cleanupTarget := *target
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = driver.Delete(cleanupCtx, sandboxruntime.LifecycleRequest{Target: cleanupTarget})
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
		Args:   []string{"sh", "-c", "printf %s \"$HAL_PODMAN_EXEC_CANARY\""},
		Env:    map[string]string{"HAL_PODMAN_EXEC_CANARY": "rootless-podman-exec"},
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
	containerInput := "/tmp/hal-podman-input.txt"
	containerOutput := "/tmp/hal-podman-output.txt"
	if err := driver.CopyIn(ctx, sandboxruntime.CopyRequest{
		Target:          *target,
		SourcePath:      localInput,
		DestinationPath: containerInput,
	}); err != nil {
		t.Fatalf("CopyIn() failed: %v", err)
	}
	if _, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: *target,
		Args:   []string{"sh", "-c", "cat /tmp/hal-podman-input.txt > /tmp/hal-podman-output.txt"},
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

func TestPodmanIntegrationCancellationStopsOnlyExecWorkload(t *testing.T) {
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
		PodmanPath:      podmanPath,
		Image:           image,
		WorkDir:         "/",
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	containerName := fmt.Sprintf("hal-podman-cancel-it-%d-%d", os.Getpid(), time.Now().UnixNano())
	target, err := driver.Create(ctx, sandboxruntime.CreateRequest{Name: containerName})
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}
	cleanupTarget := *target
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = driver.Delete(cleanupCtx, sandboxruntime.LifecycleRequest{Target: cleanupTarget})
	})
	target, err = driver.Start(ctx, sandboxruntime.LifecycleRequest{Target: *target})
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	const readyPath = "/tmp/hal-podman-cancellation-ready"
	workloadMarker := fmt.Sprintf("hal-podman-cancel-workload-%d-%d", os.Getpid(), time.Now().UnixNano())
	execCtx, cancelExec := context.WithCancel(ctx)
	type execOutcome struct {
		result *sandboxruntime.ExecResult
		err    error
	}
	execResultCh := make(chan execOutcome, 1)
	go func() {
		execResult, execErr := driver.Exec(execCtx, sandboxruntime.ExecRequest{
			Target:                               *target,
			Args:                                 []string{"sh", "-c", "trap '' TERM; : > " + readyPath + "; while :; do sleep 1; done", workloadMarker},
			RequireProcessGroupCancellationProof: true,
		})
		execResultCh <- execOutcome{result: execResult, err: execErr}
	}()
	waitForPodmanIntegrationFile(t, ctx, podmanPath, podmanIntegrationTargetRef(target), readyPath)

	cancelExec()
	select {
	case outcome := <-execResultCh:
		if !errors.Is(outcome.err, context.Canceled) {
			t.Fatalf("Exec() cancellation error = %v, want context.Canceled", outcome.err)
		}
		if outcome.result == nil || outcome.result.Cancellation == nil || !outcome.result.Cancellation.ProcessGroupTerminated {
			t.Fatalf("Exec() cancellation result = %#v, want proven process-group termination", outcome.result)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Exec() did not return after cancellation")
	}
	inspectCtx, inspectCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer inspectCancel()
	target, err = driver.Inspect(inspectCtx, sandboxruntime.InspectRequest{Target: *target})
	if err != nil {
		t.Fatalf("Inspect() after cancellation failed: %v", err)
	}
	if target.Status != sandbox.StatusRunning {
		t.Fatalf("container status after cancellation = %q, want %q", target.Status, sandbox.StatusRunning)
	}
	assertPodmanIntegrationWorkloadAbsent(t, inspectCtx, podmanPath, podmanIntegrationTargetRef(target), workloadMarker)
}

func TestPodmanIntegrationCancellationTamperDoesNotProduceFalseProof(t *testing.T) {
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
		PodmanPath:      podmanPath,
		Image:           image,
		WorkDir:         "/",
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	containerName := fmt.Sprintf("hal-podman-cancel-tamper-it-%d-%d", os.Getpid(), time.Now().UnixNano())
	target, err := driver.Create(ctx, sandboxruntime.CreateRequest{Name: containerName})
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}
	cleanupTarget := *target
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = driver.Delete(cleanupCtx, sandboxruntime.LifecycleRequest{Target: cleanupTarget})
	})
	target, err = driver.Start(ctx, sandboxruntime.LifecycleRequest{Target: *target})
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	const tamperReadyPath = "/tmp/hal-podman-cancellation-tamper-ready"
	execCtx, cancelExec := context.WithCancel(ctx)
	type execOutcome struct {
		result *sandboxruntime.ExecResult
		err    error
	}
	execResultCh := make(chan execOutcome, 1)
	go func() {
		execResult, execErr := driver.Exec(execCtx, sandboxruntime.ExecRequest{
			Target: *target,
			Args: []string{"sh", "-c", `
(
	while :; do
		for state_dir in /tmp/.hal-exec-*; do
			[ -d "$state_dir" ] || continue
			[ -p "$state_dir/cancel" ] || continue
			rm -f "$state_dir/cancel" || continue
			mkfifo "$state_dir/cancel" || continue
			: > /tmp/hal-podman-cancellation-tamper-ready
			IFS= read -r ignored < "$state_dir/cancel" || true
			rm -f "$state_dir/cancel"
			rmdir "$state_dir" 2>/dev/null || true
			exit 0
		done
		sleep 0.01
	done
) &
trap '' TERM
while :; do sleep 1; done
`},
			RequireProcessGroupCancellationProof: true,
		})
		execResultCh <- execOutcome{result: execResult, err: execErr}
	}()
	waitForPodmanIntegrationFile(t, ctx, podmanPath, podmanIntegrationTargetRef(target), tamperReadyPath)

	cancelExec()
	select {
	case outcome := <-execResultCh:
		if !errors.Is(outcome.err, context.Canceled) {
			t.Fatalf("Exec() cancellation error = %v, want context.Canceled", outcome.err)
		}
		if outcome.result == nil {
			t.Fatal("Exec() cancellation result = nil")
		}
		if outcome.result.Cancellation != nil && outcome.result.Cancellation.ProcessGroupTerminated {
			t.Fatalf("tampered cancellation returned false process-group proof: %#v", outcome.result.Cancellation)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Exec() did not return after tampered cancellation")
	}
}

func waitForPodmanIntegrationFile(t *testing.T, ctx context.Context, podmanPath, targetRef, path string) {
	t.Helper()
	for {
		if err := ctx.Err(); err != nil {
			t.Fatalf("wait for Podman exec readiness: %v", err)
		}
		if err := exec.CommandContext(ctx, podmanPath, "exec", targetRef, "test", "-f", path).Run(); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func assertPodmanIntegrationWorkloadAbsent(t *testing.T, ctx context.Context, podmanPath, targetRef, marker string) {
	t.Helper()
	output, err := exec.CommandContext(ctx, podmanPath, "exec", targetRef, "ps", "-eo", "pid,ppid,pgid,sid,args").Output()
	if err != nil {
		t.Fatalf("inspect Podman exec workload after cancellation: %v", err)
	}
	if strings.Contains(string(output), marker) {
		t.Fatal("canceled Podman exec workload remained active")
	}
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
