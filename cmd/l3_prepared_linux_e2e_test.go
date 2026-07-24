//go:build linux && podman_integration && l3_recovery_e2e

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

const (
	l3PreparedLinuxImageEnv         = "HAL_PODMAN_TEST_IMAGE"
	l3PreparedLinuxHelperEnv        = "HAL_L3_E2E_SUBMIT_HELPER"
	l3PreparedLinuxHelperSocketEnv  = "HAL_L3_E2E_SUBMIT_SOCKET"
	l3PreparedLinuxHelperSignalEnv  = "HAL_L3_E2E_SUBMIT_SIGNAL"
	l3PreparedLinuxHelperStoreEnv   = "HAL_L3_E2E_SUBMIT_STORE"
	l3PreparedLinuxHelperRuntimeEnv = "HAL_L3_E2E_SUBMIT_RUNTIME"
	l3PreparedLinuxHelperTargetEnv  = "HAL_L3_E2E_SUBMIT_TARGET"
	l3PreparedLinuxWorkerID         = "worker-l3-prepared-linux"
	l3PreparedLinuxExecutionID      = "run-l3-prepared-linux"
	l3PreparedLinuxLeaseID          = "lease-l3-prepared-linux"
	l3PreparedLinuxWorkDir          = "/workspace"
)

type l3PreparedLinuxWorker struct {
	service *sandboxworker.Service
	cancel  context.CancelFunc
	done    chan error
}

func TestL3PreparedLinuxRecoveryE2E(t *testing.T) {
	image, podmanPath := requireL3PreparedLinuxPrerequisites(t)
	testCtx, testCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer testCancel()

	configRoot := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", configRoot)
	socketRoot, err := os.MkdirTemp("/tmp", "hal-l3-e2e-")
	if err != nil {
		t.Fatalf("create private worker socket directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(socketRoot); err != nil {
			t.Errorf("remove private worker socket directory: %v", err)
		}
	})
	socketPath := filepath.Join(socketRoot, "worker.sock")
	jobStateDir := filepath.Join(socketRoot, "jobs")

	runner := rootlesspodman.DefaultCommandRunner{}
	driver := rootlesspodman.New(rootlesspodman.Options{
		LifecycleRunner:       runner,
		ExecRunner:            runner,
		CopyRunner:            runner,
		PodmanPath:            podmanPath,
		Image:                 image,
		WorkDir:               "/",
		JobExecutionSupported: true,
	})
	registry, err := sandboxworker.NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("create rootless worker registry: %v", err)
	}

	sandboxName := fmt.Sprintf("hal-l3-e2e-%d", os.Getpid())
	target, err := driver.Create(testCtx, sandboxruntime.CreateRequest{Name: sandboxName})
	if err != nil {
		t.Fatalf("create rootless Podman target: %v", err)
	}
	createdTarget := *target
	target, err = driver.Start(testCtx, sandboxruntime.LifecycleRequest{Target: createdTarget})
	if err != nil {
		cleanupL3PreparedLinuxTarget(t, driver, podmanPath, createdTarget)
		t.Fatalf("start rootless Podman target: %v", err)
	}
	target.Runtime.WorkerID = l3PreparedLinuxWorkerID
	targetDeleted := false
	t.Cleanup(func() {
		if targetDeleted {
			return
		}
		cleanupL3PreparedLinuxTarget(t, driver, podmanPath, *target)
	})
	requireL3PreparedLinuxContainerTools(t, testCtx, driver, *target)
	initializeL3PreparedLinuxWorkspace(t, testCtx, driver, *target)

	worker := startL3PreparedLinuxWorker(t, socketPath, jobStateDir, registry)
	workerStopped := false
	t.Cleanup(func() {
		if !workerStopped {
			stopL3PreparedLinuxWorker(t, worker)
		}
	})

	host := &sandbox.SandboxHost{
		ID:                l3PreparedLinuxWorkerID,
		Name:              l3PreparedLinuxWorkerID,
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix://" + socketPath,
		SupportedRuntimes: []string{sandboxruntime.DriverRootlessPodman},
		Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 1},
	}
	if err := sandbox.ForceWriteHost(host); err != nil {
		t.Fatalf("persist durable worker host: %v", err)
	}
	instance := &sandbox.SandboxState{
		ID:        "sandbox-l3-prepared-linux",
		Name:      sandboxName,
		Provider:  sandboxruntime.DriverRootlessPodman,
		Status:    sandbox.StatusRunning,
		CreatedAt: time.Now().UTC(),
		Host: &sandbox.SandboxHost{
			ID:   host.ID,
			Name: host.Name,
			Kind: host.Kind,
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			RuntimeID:      target.Runtime.RuntimeID,
			Image:          image,
			WorkerID:       l3PreparedLinuxWorkerID,
		},
	}
	if err := sandbox.ForceWriteInstance(instance); err != nil {
		t.Fatalf("persist durable sandbox: %v", err)
	}

	executionStore := sandboxexecution.NewStore(filepath.Join(configRoot, "l3-executions"))
	originalDefaultStore := sandboxL3DefaultStore
	sandboxL3DefaultStore = func() (sandboxexecution.Store, error) { return executionStore, nil }
	t.Cleanup(func() { sandboxL3DefaultStore = originalDefaultStore })

	leaseStore := sandbox.NewSandboxLeaseStore(nil)
	lease, err := leaseStore.Acquire(sandbox.SandboxLeaseAcquireRequest{
		ID:          l3PreparedLinuxLeaseID,
		SandboxID:   instance.ID,
		SandboxName: sandboxName,
		ResourceKey: "runtime:" + target.Runtime.RuntimeID,
		Holder:      "l3-prepared-linux",
		Purpose:     sandbox.SandboxLeasePurposeRun,
		RunID:       l3PreparedLinuxExecutionID,
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("acquire exact durable lease: %v", err)
	}
	manifest := &sandboxexecution.Manifest{
		ID:          l3PreparedLinuxExecutionID,
		Purpose:     sandboxexecution.PurposeRun,
		SandboxName: sandboxName,
		WorkDir:     l3PreparedLinuxWorkDir,
		Status:      sandboxexecution.StatusRunning,
		StartedAt:   time.Now().UTC(),
		Host: &sandbox.SandboxHost{
			ID:   host.ID,
			Name: host.Name,
			Kind: host.Kind,
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			RuntimeID:      target.Runtime.RuntimeID,
			Image:          image,
			WorkerID:       l3PreparedLinuxWorkerID,
		},
		Lease: &sandbox.SandboxLeaseRef{
			ID:            lease.ID,
			HostID:        host.ID,
			HostName:      host.Name,
			RuntimeDriver: sandboxruntime.DriverRootlessPodman,
			ResourceKey:   lease.ResourceKey,
			Purpose:       lease.Purpose,
			RunID:         lease.RunID,
			AcquiredAt:    lease.AcquiredAt,
			ExpiresAt:     lease.ExpiresAt,
		},
	}
	if err := executionStore.SaveManifest(manifest); err != nil {
		t.Fatalf("persist pre-admission execution manifest: %v", err)
	}

	acceptedSignal := filepath.Join(socketRoot, "accepted-and-persisted")
	helper := startL3PreparedLinuxSubmitter(t, socketPath, executionStore.Root(), acceptedSignal, *target)
	helperStopped := false
	t.Cleanup(func() {
		if helperStopped {
			return
		}
		_ = helper.Process.Kill()
		_ = helper.Wait()
	})
	waitForL3PreparedLinuxSignal(t, acceptedSignal)
	persistedBeforeLoss, err := executionStore.LoadManifest(l3PreparedLinuxExecutionID)
	if err != nil {
		t.Fatalf("load accepted job manifest before initiating process loss: %v", err)
	}
	if persistedBeforeLoss.WorkerJob == nil {
		t.Fatal("accepted worker job reference was not durable before initiating process loss")
	}
	if persistedBeforeLoss.WorkerJob.SubmissionKey != sandboxWorkerJobSubmissionKey(l3PreparedLinuxExecutionID) {
		t.Fatalf("durable submission identity = %q, want execution ID hash", persistedBeforeLoss.WorkerJob.SubmissionKey)
	}
	jobID := persistedBeforeLoss.WorkerJob.JobID
	client := newL3PreparedLinuxClient(t, socketPath)
	runningJob := waitForL3PreparedLinuxJobState(t, testCtx, client, jobID, sandboxworker.JobStateRunning)
	persistedRunning, err := executionStore.LoadManifest(l3PreparedLinuxExecutionID)
	if err != nil {
		t.Fatalf("load running job manifest before initiating process loss: %v", err)
	}
	if persistedRunning.WorkerJob == nil || persistedRunning.WorkerJob.JobID != jobID {
		t.Fatalf(
			"running worker job link present/matched = %t/%t, want true/true",
			persistedRunning.WorkerJob != nil,
			persistedRunning.WorkerJob != nil && persistedRunning.WorkerJob.JobID == jobID,
		)
	}
	status, err := client.Status(testCtx)
	if err != nil {
		t.Fatalf("read active worker status: %v", err)
	}
	if status.Capacity.ActiveSandboxes != 1 {
		t.Fatalf("activeSandboxes while admitted job runs = %d, want 1", status.Capacity.ActiveSandboxes)
	}

	if err := helper.Process.Kill(); err != nil {
		t.Fatalf("kill initiating client process: %v", err)
	}
	if err := helper.Wait(); err == nil {
		t.Fatal("initiating client process exited successfully after forced loss")
	}
	helperStopped = true

	resolvedJob, err := client.JobResolve(testCtx, sandboxworker.JobResolveRequest{
		ContractVersion: sandboxworker.JobContractVersion,
		SubmissionID:    l3PreparedLinuxExecutionID,
	})
	if err != nil {
		t.Fatalf("resolve admitted job after initiating process loss: %v", err)
	}
	if resolvedJob.ID != runningJob.ID || resolvedJob.SubmissionKey != sandboxWorkerJobSubmissionKey(l3PreparedLinuxExecutionID) {
		t.Fatalf(
			"resolved job identity matched ID/submission = %t/%t, want true/true",
			resolvedJob.ID == runningJob.ID,
			resolvedJob.SubmissionKey == sandboxWorkerJobSubmissionKey(l3PreparedLinuxExecutionID),
		)
	}

	_, discoveredByName, err := selectSandboxL3Execution(sandboxName, "", sandboxL3SelectionObserve)
	if err != nil {
		t.Fatalf("rediscover execution by sandbox name: %v", err)
	}
	_, discoveredByRun, err := selectSandboxL3Execution(sandboxName, l3PreparedLinuxExecutionID, sandboxL3SelectionObserve)
	if err != nil {
		t.Fatalf("rediscover execution by sandbox name and run ID: %v", err)
	}
	if discoveredByName.ID != l3PreparedLinuxExecutionID || discoveredByRun.ID != l3PreparedLinuxExecutionID {
		t.Fatalf("rediscovered executions = %q/%q, want %q", discoveredByName.ID, discoveredByRun.ID, l3PreparedLinuxExecutionID)
	}

	var statusJSON bytes.Buffer
	if err := runSandboxL3StatusJSON(testCtx, sandboxName, true, &statusJSON); err != nil {
		t.Fatalf("read live operator status: %v", err)
	}
	var projected sandboxL3StatusResponse
	if err := json.Unmarshal(statusJSON.Bytes(), &projected); err != nil {
		t.Fatalf("decode live operator status: %v", err)
	}
	if projected.ContractVersion != sandboxStatusContractVersion || projected.Source != "live" ||
		projected.Execution == nil || !projected.Execution.Active ||
		projected.Execution.RunID != l3PreparedLinuxExecutionID {
		t.Fatalf(
			"live operator status contract/source/run/active = %q/%q/%q/%t",
			projected.ContractVersion,
			projected.Source,
			l3RecoveryExecutionID(projected.Execution),
			projected.Execution != nil && projected.Execution.Active,
		)
	}

	followCtx, followCancel := context.WithTimeout(testCtx, 30*time.Second)
	defer followCancel()
	var stdout, stderr bytes.Buffer
	if err := runSandboxL3Logs(followCtx, sandboxName, l3PreparedLinuxExecutionID, true, &stdout, &stderr); err != nil {
		t.Fatalf("follow and drain bounded worker logs: %v", err)
	}
	if got := stdout.String(); !strings.Contains(got, "l3-job-start") || !strings.Contains(got, "l3-job-done") {
		t.Fatalf("followed stdout = %q, want complete start-to-finish log", got)
	}
	terminalJob := waitForL3PreparedLinuxTerminalJob(t, testCtx, client, jobID)
	if terminalJob.State != sandboxworker.JobStateSucceeded {
		t.Fatalf("terminal job state = %q, want succeeded", terminalJob.State)
	}
	assertL3PreparedLinuxBoundedTerminalDrain(t, testCtx, client, terminalJob)

	for attempt := 0; attempt < 2; attempt++ {
		var recoveryOutput bytes.Buffer
		if err := runSandboxL3RecoveryObservation(testCtx, sandboxName, l3PreparedLinuxExecutionID, true, &recoveryOutput); err != nil {
			t.Fatalf("retry-safe recovery/sync-out attempt %d: %v", attempt+1, err)
		}
		if !strings.Contains(recoveryOutput.String(), "finalization completed") {
			t.Fatalf("recovery/sync-out attempt %d output = %q", attempt+1, recoveryOutput.String())
		}
	}

	finalManifest, err := executionStore.LoadManifest(l3PreparedLinuxExecutionID)
	if err != nil {
		t.Fatalf("load finalized execution manifest: %v", err)
	}
	assertL3PreparedLinuxFinalization(t, finalManifest)
	assertL3PreparedLinuxRecoveredArtifacts(t, executionStore, finalManifest)
	finalLease, err := leaseStore.Load(l3PreparedLinuxLeaseID)
	if err != nil {
		t.Fatalf("load released durable lease: %v", err)
	}
	if finalLease.Status != sandbox.SandboxLeaseStatusReleased {
		t.Fatalf("durable lease status = %q, want %q", finalLease.Status, sandbox.SandboxLeaseStatusReleased)
	}
	allLeases, err := leaseStore.List()
	if err != nil {
		t.Fatalf("list durable leases: %v", err)
	}
	if len(allLeases) != 1 || allLeases[0].ID != l3PreparedLinuxLeaseID {
		firstID := ""
		if len(allLeases) > 0 {
			firstID = allLeases[0].ID
		}
		t.Fatalf("durable lease count/first ID = %d/%q, want 1/%q", len(allLeases), firstID, l3PreparedLinuxLeaseID)
	}
	status, err = client.Status(testCtx)
	if err != nil {
		t.Fatalf("read converged worker status: %v", err)
	}
	if status.Capacity.ActiveSandboxes != 0 {
		t.Fatalf("terminal activeSandboxes = %d, want 0", status.Capacity.ActiveSandboxes)
	}

	stopL3PreparedLinuxWorker(t, worker)
	workerStopped = true
	restarted := restartL3PreparedLinuxWorker(t, socketPath, jobStateDir, registry)
	restartedStopped := false
	t.Cleanup(func() {
		if !restartedStopped {
			stopL3PreparedLinuxWorker(t, restarted)
		}
	})
	restartedClient := newL3PreparedLinuxClient(t, socketPath)
	restartedJob, err := restartedClient.JobStatus(testCtx, sandboxworker.JobStatusRequest{
		ContractVersion: sandboxworker.JobContractVersion,
		JobID:           jobID,
	})
	if err != nil {
		t.Fatalf("read job after daemon restart: %v", err)
	}
	switch restartedJob.State {
	case sandboxworker.JobStateSucceeded, sandboxworker.JobStateFailed, sandboxworker.JobStateCanceled:
	case sandboxworker.JobStateUnknown, sandboxworker.JobStateInterrupted:
	default:
		t.Fatalf("daemon restart state = %q, want proven terminal or conservative unknown/interrupted", restartedJob.State)
	}
	if restartedJob.State == sandboxworker.JobStateRunning || restartedJob.State == sandboxworker.JobStateQueued {
		t.Fatalf("daemon restart falsely reported active state %q", restartedJob.State)
	}
	restartedStatus, err := restartedClient.Status(testCtx)
	if err != nil {
		t.Fatalf("read restarted worker status: %v", err)
	}
	if restartedStatus.Capacity.ActiveSandboxes != 0 {
		t.Fatalf("restarted activeSandboxes = %d, want 0", restartedStatus.Capacity.ActiveSandboxes)
	}
	assertL3PreparedLinuxCommandRanOnce(t, testCtx, driver, *target)

	stopL3PreparedLinuxWorker(t, restarted)
	restartedStopped = true
	if err := driver.Delete(testCtx, sandboxruntime.LifecycleRequest{Target: *target}); err != nil {
		t.Fatalf("delete rootless Podman target: %v", err)
	}
	assertL3PreparedLinuxContainerAbsent(t, testCtx, podmanPath, target.Runtime.RuntimeID)
	targetDeleted = true
}

func TestL3PreparedLinuxSubmitterHelper(t *testing.T) {
	if os.Getenv(l3PreparedLinuxHelperEnv) != "1" {
		return
	}
	socketPath := strings.TrimSpace(os.Getenv(l3PreparedLinuxHelperSocketEnv))
	signalPath := strings.TrimSpace(os.Getenv(l3PreparedLinuxHelperSignalEnv))
	storeRoot := strings.TrimSpace(os.Getenv(l3PreparedLinuxHelperStoreEnv))
	runtimeID := strings.TrimSpace(os.Getenv(l3PreparedLinuxHelperRuntimeEnv))
	targetName := strings.TrimSpace(os.Getenv(l3PreparedLinuxHelperTargetEnv))
	runtimeTarget := sandboxruntime.Target{
		ID:   runtimeID,
		Name: targetName,
		Runtime: sandboxruntime.RuntimeState{
			Driver:    sandboxruntime.DriverRootlessPodman,
			RuntimeID: runtimeID,
			WorkerID:  l3PreparedLinuxWorkerID,
		},
	}
	runtimeDriver, err := sandboxWorkerRuntimeDriverFromTarget(sandboxWorkerRuntimeRequest{
		Target: runtimeTarget,
		Host: &sandbox.SandboxHost{
			ID:                l3PreparedLinuxWorkerID,
			Name:              l3PreparedLinuxWorkerID,
			Kind:              sandbox.SandboxHostKindWorker,
			Endpoint:          "unix://" + socketPath,
			SupportedRuntimes: []string{sandboxruntime.DriverRootlessPodman},
		},
	}, sandboxWorkerRuntimeDriverFactories{})
	if err != nil {
		t.Fatalf("create production worker runtime driver: %v", err)
	}
	clientDriver, ok := runtimeDriver.(sandboxWorkerJobDriver)
	if !ok {
		t.Fatalf("production worker runtime driver %T lacks durable job support", runtimeDriver)
	}
	store := sandboxexecution.NewStore(storeRoot)
	var signalOnce sync.Once
	var signalErr error
	err = runSandboxWorkerJob(context.Background(), sandboxWorkerJobRunRequest{
		ExecutionID: l3PreparedLinuxExecutionID,
		Driver:      clientDriver,
		HostID:      l3PreparedLinuxWorkerID,
		Target:      runtimeTarget,
		Command: sandboxexec.CommandRequest{
			Command: []string{"sh", "-c", `set -eu
cd /workspace
printf 'l3-job-start\n'
printf x >> l3-run-count
sleep 5
mkdir -p .hal/reports
printf '{"branchName":"l3-live"}\n' > .hal/prd.json
printf 'L3 prepared Linux complete\n' > .hal/progress.txt
printf 'recovered output\n' > l3-output.txt
printf 'changed by daemon-owned job\n' >> tracked.txt
printf 'operator recovery report\n' > .hal/reports/l3-report.txt
printf 'l3-job-done\n'`},
			WorkDir: l3PreparedLinuxWorkDir,
			Stdout:  io.Discard,
			Stderr:  io.Discard,
		},
		Persist: func(reference *sandboxexecution.WorkerJobReference) error {
			if err := persistSandboxWorkerJobUpdate(
				store,
				l3PreparedLinuxExecutionID,
				reference,
				true,
				time.Now().UTC(),
			); err != nil {
				return err
			}
			signalOnce.Do(func() {
				signalErr = os.WriteFile(signalPath, []byte("persisted\n"), 0o600)
			})
			return signalErr
		},
	})
	t.Fatalf("production worker job path returned before initiating client loss: %v", err)
}

func requireL3PreparedLinuxPrerequisites(t *testing.T) (string, string) {
	t.Helper()
	image := strings.TrimSpace(os.Getenv(l3PreparedLinuxImageEnv))
	if image == "" {
		t.Fatalf("%s is required and must name an existing local image", l3PreparedLinuxImageEnv)
	}
	podmanPath, err := exec.LookPath(rootlesspodman.DefaultPodmanExecutable)
	if err != nil {
		t.Fatalf("rootless Podman executable is required: %v", err)
	}
	rootless, err := exec.Command(podmanPath, "info", "--format", "{{.Host.Security.Rootless}}").Output()
	if err != nil || strings.TrimSpace(string(rootless)) != "true" {
		t.Fatal("working same-user rootless Podman service is required")
	}
	if err := exec.Command(podmanPath, "image", "exists", image).Run(); err != nil {
		t.Fatal("required local Podman image is unavailable")
	}
	return image, podmanPath
}

func requireL3PreparedLinuxContainerTools(
	t *testing.T,
	ctx context.Context,
	driver *rootlesspodman.Driver,
	target sandboxruntime.Target,
) {
	t.Helper()
	result, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: target,
		Args: []string{"sh", "-c", `set -eu
for tool in sh setsid ps awk git tar grep; do
	command -v "$tool" >/dev/null
done
ps -eo pgid=,args= >/dev/null
setsid --wait sh -c 'exit 0'
tar --help 2>&1 | grep -- --null >/dev/null`},
	})
	if err != nil || result == nil || result.ExitCode != 0 {
		t.Fatalf(
			"prepared image lacks required L3 shell/process/git/tar tools: result present=%t exit=%d error=%v",
			result != nil,
			l3PreparedLinuxExitCode(result),
			err,
		)
	}
}

func initializeL3PreparedLinuxWorkspace(
	t *testing.T,
	ctx context.Context,
	driver *rootlesspodman.Driver,
	target sandboxruntime.Target,
) {
	t.Helper()
	result, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: target,
		Args: []string{"sh", "-c", `set -eu
mkdir -p /workspace/.hal
cd /workspace
git init -q
git config user.name "L3 Acceptance"
git config user.email "l3@example.invalid"
printf 'baseline\n' > tracked.txt
git add tracked.txt
git commit -qm baseline`},
	})
	if err != nil || result == nil || result.ExitCode != 0 {
		t.Fatalf(
			"initialize prepared workspace: result present=%t exit=%d error=%v",
			result != nil,
			l3PreparedLinuxExitCode(result),
			err,
		)
	}
}

func startL3PreparedLinuxWorker(
	t *testing.T,
	socketPath, jobStateDir string,
	registry *sandboxworker.DriverRegistry,
) *l3PreparedLinuxWorker {
	t.Helper()
	daemonCtx, cancel := context.WithCancel(context.Background())
	service, err := sandboxworker.NewService(sandboxworker.ServiceOptions{
		WorkerID:    l3PreparedLinuxWorkerID,
		HostKind:    sandboxworker.HostKindLocal,
		SocketPath:  socketPath,
		Registry:    registry,
		JobContext:  daemonCtx,
		JobStateDir: jobStateDir,
		Capacity:    sandboxworker.WorkerCapacity{MaxConcurrentSandboxes: 1},
	})
	if err != nil {
		cancel()
		t.Fatalf("start durable worker service: %v", err)
	}
	server, err := sandboxworker.NewServer(sandboxworker.ServerOptions{
		SocketPath: socketPath,
		Handler:    service,
	})
	if err != nil {
		cancel()
		service.Close()
		t.Fatalf("create private worker server: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe(daemonCtx) }()
	waitForL3PreparedLinuxSocket(t, socketPath, done)
	return &l3PreparedLinuxWorker{service: service, cancel: cancel, done: done}
}

func restartL3PreparedLinuxWorker(
	t *testing.T,
	socketPath, jobStateDir string,
	registry *sandboxworker.DriverRegistry,
) *l3PreparedLinuxWorker {
	t.Helper()
	return startL3PreparedLinuxWorker(t, socketPath, jobStateDir, registry)
}

func stopL3PreparedLinuxWorker(t *testing.T, worker *l3PreparedLinuxWorker) {
	t.Helper()
	if worker == nil {
		return
	}
	worker.cancel()
	if err := <-worker.done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("stop worker server: %v", err)
	}
	worker.service.Close()
}

func waitForL3PreparedLinuxSocket(t *testing.T, socketPath string, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Lstat(socketPath); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("worker server stopped before socket readiness: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("private worker socket was not created")
}

func startL3PreparedLinuxSubmitter(
	t *testing.T,
	socketPath, storeRoot, signalPath string,
	target sandboxruntime.Target,
) *exec.Cmd {
	t.Helper()
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve acceptance test executable: %v", err)
	}
	var output bytes.Buffer
	helper := exec.Command(testBinary,
		"-test.run=^TestL3PreparedLinuxSubmitterHelper$",
		"-test.timeout=45s",
	)
	helper.Env = append(os.Environ(),
		l3PreparedLinuxHelperEnv+"=1",
		l3PreparedLinuxHelperSocketEnv+"="+socketPath,
		l3PreparedLinuxHelperSignalEnv+"="+signalPath,
		l3PreparedLinuxHelperStoreEnv+"="+storeRoot,
		l3PreparedLinuxHelperRuntimeEnv+"="+target.Runtime.RuntimeID,
		l3PreparedLinuxHelperTargetEnv+"="+target.Name,
	)
	helper.Stdout = &output
	helper.Stderr = &output
	if err := helper.Start(); err != nil {
		t.Fatalf("start initiating client process: %v", err)
	}
	return helper
}

func waitForL3PreparedLinuxSignal(t *testing.T, signalPath string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(signalPath); err == nil && info.Mode().IsRegular() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("production submitter did not signal durable accepted-job persistence")
}

func newL3PreparedLinuxClient(t *testing.T, socketPath string) *sandboxworker.Client {
	t.Helper()
	client, err := sandboxworker.NewClient(sandboxworker.ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("create worker client: %v", err)
	}
	return client
}

func waitForL3PreparedLinuxJobState(
	t *testing.T,
	ctx context.Context,
	client *sandboxworker.Client,
	jobID, want string,
) *sandboxworker.Job {
	t.Helper()
	for ctx.Err() == nil {
		job, err := client.JobStatus(ctx, sandboxworker.JobStatusRequest{
			ContractVersion: sandboxworker.JobContractVersion,
			JobID:           jobID,
		})
		if err != nil {
			t.Fatalf("read worker job status: %v", err)
		}
		if job.State == want {
			return job
		}
		if sandboxL3TerminalJobState(job.State) {
			t.Fatalf("worker job reached terminal state %q before %q", job.State, want)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("worker job did not reach state %q: %v", want, ctx.Err())
	return nil
}

func waitForL3PreparedLinuxTerminalJob(
	t *testing.T,
	ctx context.Context,
	client *sandboxworker.Client,
	jobID string,
) *sandboxworker.Job {
	t.Helper()
	for ctx.Err() == nil {
		job, err := client.JobStatus(ctx, sandboxworker.JobStatusRequest{
			ContractVersion: sandboxworker.JobContractVersion,
			JobID:           jobID,
		})
		if err != nil {
			t.Fatalf("read terminal worker job status: %v", err)
		}
		if sandboxL3TerminalJobState(job.State) {
			return job
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("worker job did not become terminal: %v", ctx.Err())
	return nil
}

func assertL3PreparedLinuxBoundedTerminalDrain(
	t *testing.T,
	ctx context.Context,
	client *sandboxworker.Client,
	job *sandboxworker.Job,
) {
	t.Helper()
	cursor := uint64(0)
	for cursor < job.LogCursor {
		page, err := client.JobLogs(ctx, sandboxworker.JobLogsRequest{
			ContractVersion: sandboxworker.JobContractVersion,
			JobID:           job.ID,
			Cursor:          cursor,
			LimitBytes:      sandboxworker.DefaultJobLogReadBytes,
		})
		if err != nil {
			t.Fatalf("read bounded terminal log page: %v", err)
		}
		pageBytes := 0
		for _, record := range page.Records {
			pageBytes += len(record.Data)
		}
		if int64(pageBytes) > sandboxworker.DefaultJobLogReadBytes {
			t.Fatalf("terminal log page bytes = %d, exceeds bound %d", pageBytes, sandboxworker.DefaultJobLogReadBytes)
		}
		if page.NextCursor <= cursor {
			t.Fatalf("terminal log drain stalled at cursor %d of %d", cursor, job.LogCursor)
		}
		cursor = page.NextCursor
	}
	if cursor < job.LogCursor {
		t.Fatalf("terminal log cursor = %d, want at least %d", cursor, job.LogCursor)
	}
}

func assertL3PreparedLinuxFinalization(t *testing.T, manifest *sandboxexecution.Manifest) {
	t.Helper()
	if manifest.Status != sandboxexecution.StatusSucceeded || manifest.FinishedAt == nil ||
		manifest.Finalization == nil || manifest.Finalization.State != sandboxexecution.FinalizationStateCompleted ||
		!manifest.Finalization.SyncOutRequested ||
		manifest.Finalization.TerminalJobState != sandboxworker.JobStateSucceeded {
		t.Fatalf(
			"finalized status/finished/finalization/sync-out/terminal = %q/%t/%q/%t/%q",
			manifest.Status,
			manifest.FinishedAt != nil,
			l3PreparedLinuxFinalizationState(manifest),
			manifest.Finalization != nil && manifest.Finalization.SyncOutRequested,
			l3PreparedLinuxTerminalState(manifest),
		)
	}
	checkpoints := manifest.Finalization.Checkpoints
	if !checkpoints.Artifacts.Completed || !checkpoints.SyncOut.Completed ||
		!checkpoints.LeaseRelease.Completed || !checkpoints.TerminalPublication.Completed {
		t.Fatalf(
			"finalization checkpoints artifacts/sync-out/lease/publication = %t/%t/%t/%t",
			checkpoints.Artifacts.Completed,
			checkpoints.SyncOut.Completed,
			checkpoints.LeaseRelease.Completed,
			checkpoints.TerminalPublication.Completed,
		)
	}
	if manifest.SyncOut == nil || manifest.SyncOutApply != nil {
		t.Fatalf(
			"sync-out handoff/apply present = %t/%t, want true/false",
			manifest.SyncOut != nil,
			manifest.SyncOutApply != nil,
		)
	}
}

func assertL3PreparedLinuxRecoveredArtifacts(
	t *testing.T,
	store sandboxexecution.Store,
	manifest *sandboxexecution.Manifest,
) {
	t.Helper()
	if manifest.ArtifactMetadata == nil {
		t.Fatal("finalized manifest has no recovered artifact metadata")
	}
	byID := make(map[string]sandboxexecution.ArtifactMetadataEntry)
	for _, artifact := range manifest.ArtifactMetadata.Collected {
		if _, exists := byID[artifact.ID]; exists {
			t.Fatalf("recovered artifact %q was duplicated across retry", artifact.ID)
		}
		byID[artifact.ID] = artifact
	}
	for _, id := range []string{
		"prd",
		"progress",
		"recovery-patch",
		"reports-archive",
		"uncommitted-diff",
		"untracked-archive",
		"untracked-list",
	} {
		artifact, exists := byID[id]
		if !exists || strings.TrimSpace(artifact.StoredPath) == "" {
			t.Fatalf("recovered artifact %q exists/has payload = %t/%t, want true/true", id, exists, strings.TrimSpace(artifact.StoredPath) != "")
		}
	}
	assertL3PreparedLinuxStoredPayloadContains(t, store, manifest.ID, byID["prd"].StoredPath, `"l3-live"`)
	assertL3PreparedLinuxStoredPayloadContains(t, store, manifest.ID, byID["recovery-patch"].StoredPath, "tracked.txt")
	assertL3PreparedLinuxStoredPayloadContains(t, store, manifest.ID, byID["untracked-list"].StoredPath, "l3-output.txt")
}

func assertL3PreparedLinuxStoredPayloadContains(
	t *testing.T,
	store sandboxexecution.Store,
	executionID, storedPath, want string,
) {
	t.Helper()
	file, err := store.OpenStoredFile(executionID, storedPath)
	if err != nil {
		t.Fatalf("open recovered payload %q: %v", storedPath, err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("read recovered payload %q: %v", storedPath, err)
	}
	if !bytes.Contains(data, []byte(want)) {
		t.Fatalf("recovered payload %q does not contain %q", storedPath, want)
	}
}

func assertL3PreparedLinuxCommandRanOnce(
	t *testing.T,
	ctx context.Context,
	driver *rootlesspodman.Driver,
	target sandboxruntime.Target,
) {
	t.Helper()
	result, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: target,
		Args:   []string{"sh", "-c", `test "$(cat /workspace/l3-run-count)" = x`},
	})
	if err != nil || result == nil || result.ExitCode != 0 {
		t.Fatalf(
			"daemon restart reran or lost single-run marker: result present=%t exit=%d error=%v",
			result != nil,
			l3PreparedLinuxExitCode(result),
			err,
		)
	}
}

func cleanupL3PreparedLinuxTarget(
	t *testing.T,
	driver *rootlesspodman.Driver,
	podmanPath string,
	target sandboxruntime.Target,
) {
	t.Helper()
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := driver.Delete(cleanupCtx, sandboxruntime.LifecycleRequest{Target: target}); err != nil {
		t.Errorf("delete rootless Podman target during cleanup: %v", err)
	}
	assertL3PreparedLinuxContainerAbsent(t, cleanupCtx, podmanPath, target.Runtime.RuntimeID)
}

func assertL3PreparedLinuxContainerAbsent(
	t *testing.T,
	ctx context.Context,
	podmanPath, runtimeID string,
) {
	t.Helper()
	command := exec.CommandContext(
		ctx,
		podmanPath,
		"container", "exists",
		strings.TrimSpace(runtimeID),
	)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	err := command.Run()
	if err == nil {
		t.Errorf("owned rootless Podman container still exists after deletion")
		return
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Errorf("verify owned rootless Podman container absence: command failed without an exit status")
		return
	}
	exitCode := exitErr.ExitCode()
	if exitCode == 1 {
		return
	}
	t.Errorf("verify owned rootless Podman container absence: exit status = %d, want 1", exitCode)
}

func l3PreparedLinuxExitCode(result *sandboxruntime.ExecResult) int {
	if result == nil {
		return -1
	}
	return result.ExitCode
}

func l3PreparedLinuxFinalizationState(manifest *sandboxexecution.Manifest) sandboxexecution.FinalizationState {
	if manifest == nil || manifest.Finalization == nil {
		return ""
	}
	return manifest.Finalization.State
}

func l3PreparedLinuxTerminalState(manifest *sandboxexecution.Manifest) string {
	if manifest == nil || manifest.Finalization == nil {
		return ""
	}
	return manifest.Finalization.TerminalJobState
}
