//go:build linux && podman_integration

package sandboxworker_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

const (
	l2RestartHelperEnabledEnv = "HAL_L2_RESTART_HELPER"
	l2RestartHelperSocketEnv  = "HAL_L2_RESTART_SOCKET"
	l2RestartHelperStateEnv   = "HAL_L2_RESTART_STATE"
	l2RestartHelperPodmanEnv  = "HAL_L2_RESTART_PODMAN"
)

func TestWorkerJobPodmanIntegrationSurvivesClientDisconnect(t *testing.T) {
	image := strings.TrimSpace(os.Getenv("HAL_PODMAN_TEST_IMAGE"))
	if image == "" {
		t.Skip("HAL_PODMAN_TEST_IMAGE is unset")
	}
	podmanPath, err := exec.LookPath(rootlesspodman.DefaultPodmanExecutable)
	if err != nil {
		t.Fatalf("find rootless Podman: %v", err)
	}
	if err := exec.Command(podmanPath, "info", "--format", "json").Run(); err != nil {
		t.Fatalf("rootless Podman is unavailable: %v", err)
	}
	if err := exec.Command(podmanPath, "image", "exists", image).Run(); err != nil {
		t.Fatalf("required local Podman image is unavailable: %v", err)
	}

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
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}

	testCtx, testCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer testCancel()
	target, err := driver.Create(testCtx, sandboxruntime.CreateRequest{
		Name: fmt.Sprintf("hal-l2-job-live-%d-%d", os.Getpid(), time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatalf("create rootless target: %v", err)
	}
	createdTarget := *target
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = driver.Delete(cleanupCtx, sandboxruntime.LifecycleRequest{Target: createdTarget})
	})
	target, err = driver.Start(testCtx, sandboxruntime.LifecycleRequest{Target: *target})
	if err != nil {
		t.Fatalf("start rootless target: %v", err)
	}

	root := t.TempDir()
	socketPath := filepath.Join(root, "worker.sock")
	stateDir := filepath.Join(root, "jobs")
	daemonCtx, daemonCancel := context.WithCancel(context.Background())
	defer daemonCancel()
	service, err := sandboxworker.NewService(sandboxworker.ServiceOptions{
		WorkerID:    "worker-l2-live",
		HostKind:    sandboxworker.HostKindLocal,
		SocketPath:  socketPath,
		Registry:    registry,
		JobContext:  daemonCtx,
		JobStateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	server, err := sandboxworker.NewServer(sandboxworker.ServerOptions{
		SocketPath: socketPath,
		Handler:    service,
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.ListenAndServe(daemonCtx) }()
	waitForWorkerJobSocket(t, socketPath)

	client, err := sandboxworker.NewClient(sandboxworker.ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	canary := "l2-live-secret-canary"
	submitCtx, submitCancel := context.WithCancel(context.Background())
	job, err := client.JobStart(submitCtx, sandboxruntime.DriverRootlessPodman, sandboxworker.JobStartRequest{
		ContractVersion: sandboxworker.JobContractVersion,
		SubmissionID:    "l2-live-submission",
		Exec: sandboxworker.ExecRequest{
			OperationID: "l2-live-job",
			Target: sandboxworker.Target{
				ID:   target.ID,
				Name: target.Name,
				Runtime: sandboxworker.RuntimeTarget{
					Driver:    target.Runtime.Driver,
					RuntimeID: target.Runtime.RuntimeID,
				},
			},
			Args:             []string{"sh", "-c", `sleep 1; printf 'live:%s\n' "$L2_JOB_CANARY"`},
			Env:              map[string]string{"L2_JOB_CANARY": canary},
			StdoutLimitBytes: sandboxworker.MaxExecStdoutCaptureBytes,
			StderrLimitBytes: sandboxworker.MaxExecStderrCaptureBytes,
		},
	})
	submitCancel()
	if err != nil {
		t.Fatalf("JobStart() error: %v", err)
	}

	statusClient, err := sandboxworker.NewClient(sandboxworker.ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewClient(status) error: %v", err)
	}
	terminal := waitForLiveWorkerJob(t, statusClient, job.ID)
	if terminal.State != sandboxworker.JobStateSucceeded {
		t.Fatalf("terminal job state = %q, want succeeded", terminal.State)
	}
	logs, err := statusClient.JobLogs(testCtx, sandboxworker.JobLogsRequest{
		ContractVersion: sandboxworker.JobContractVersion,
		JobID:           job.ID,
		LimitBytes:      sandboxworker.DefaultJobLogReadBytes,
	})
	if err != nil {
		t.Fatalf("JobLogs() error: %v", err)
	}
	var output strings.Builder
	for _, record := range logs.Records {
		output.WriteString(record.Data)
	}
	if strings.Contains(output.String(), canary) || !strings.Contains(output.String(), "[redacted]") {
		t.Fatalf("redacted live logs = %q", output.String())
	}
	if state, err := os.ReadFile(filepath.Join(stateDir, job.ID, "job.json")); err != nil {
		t.Fatalf("read durable job state: %v", err)
	} else if strings.Contains(string(state), canary) {
		t.Fatal("durable job state exposed secret canary")
	}
	if logsData, err := os.ReadFile(filepath.Join(stateDir, job.ID, "logs.json")); err != nil {
		t.Fatalf("read durable job logs: %v", err)
	} else if strings.Contains(string(logsData), canary) {
		t.Fatal("durable job logs exposed secret canary")
	}

	if err := driver.Delete(testCtx, sandboxruntime.LifecycleRequest{Target: *target}); err != nil {
		t.Fatalf("delete rootless target: %v", err)
	}
	deleted = true
	daemonCancel()
	if err := <-serveDone; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("worker server shutdown: %v", err)
	}
}

func TestWorkerJobPodmanIntegrationCrashRestartDoesNotRerun(t *testing.T) {
	image := strings.TrimSpace(os.Getenv("HAL_PODMAN_TEST_IMAGE"))
	if image == "" {
		t.Skip("HAL_PODMAN_TEST_IMAGE is unset")
	}
	podmanPath, err := exec.LookPath(rootlesspodman.DefaultPodmanExecutable)
	if err != nil {
		t.Fatalf("find rootless Podman: %v", err)
	}
	if err := exec.Command(podmanPath, "info", "--format", "json").Run(); err != nil {
		t.Fatalf("rootless Podman is unavailable: %v", err)
	}
	if err := exec.Command(podmanPath, "image", "exists", image).Run(); err != nil {
		t.Fatalf("required local Podman image is unavailable: %v", err)
	}

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
	testCtx, testCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer testCancel()
	target, err := driver.Create(testCtx, sandboxruntime.CreateRequest{
		Name: fmt.Sprintf("hal-l2-restart-live-%d-%d", os.Getpid(), time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatalf("create rootless target: %v", err)
	}
	createdTarget := *target
	deleted := false
	t.Cleanup(func() {
		if deleted {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = driver.Delete(cleanupCtx, sandboxruntime.LifecycleRequest{Target: createdTarget})
	})
	target, err = driver.Start(testCtx, sandboxruntime.LifecycleRequest{Target: *target})
	if err != nil {
		t.Fatalf("start rootless target: %v", err)
	}

	root := t.TempDir()
	socketPath := filepath.Join(root, "worker.sock")
	stateDir := filepath.Join(root, "jobs")
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	var helperOutput bytes.Buffer
	helper := exec.Command(testBinary,
		"-test.run=^TestWorkerJobPodmanIntegrationCrashHelper$",
		"-test.timeout=60s",
	)
	helper.Env = append(os.Environ(),
		l2RestartHelperEnabledEnv+"=1",
		l2RestartHelperSocketEnv+"="+socketPath,
		l2RestartHelperStateEnv+"="+stateDir,
		l2RestartHelperPodmanEnv+"="+podmanPath,
	)
	helper.Stdout = &helperOutput
	helper.Stderr = &helperOutput
	if err := helper.Start(); err != nil {
		t.Fatalf("start crash helper: %v", err)
	}
	helperStopped := false
	t.Cleanup(func() {
		if helperStopped {
			return
		}
		_ = helper.Process.Kill()
		_ = helper.Wait()
	})
	waitForWorkerJobSocket(t, socketPath)

	client, err := sandboxworker.NewClient(sandboxworker.ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	job, err := client.JobStart(testCtx, sandboxruntime.DriverRootlessPodman, sandboxworker.JobStartRequest{
		ContractVersion: sandboxworker.JobContractVersion,
		SubmissionID:    "l2-live-restart-submission",
		Exec: sandboxworker.ExecRequest{
			OperationID: "l2-live-restart-job",
			Target: sandboxworker.Target{
				ID:   target.ID,
				Name: target.Name,
				Runtime: sandboxworker.RuntimeTarget{
					Driver:    target.Runtime.Driver,
					RuntimeID: target.Runtime.RuntimeID,
				},
			},
			Args:             []string{"sh", "-c", `printf x >>/tmp/hal-l2-restart-count; sleep 30`},
			StdoutLimitBytes: sandboxworker.MaxExecStdoutCaptureBytes,
			StderrLimitBytes: sandboxworker.MaxExecStderrCaptureBytes,
		},
	})
	if err != nil {
		t.Fatalf("JobStart() error: %v", err)
	}
	waitForLiveWorkerJobState(t, client, job.ID, sandboxworker.JobStateRunning)
	waitForLiveRuntimeMarker(t, driver, *target)

	if err := helper.Process.Kill(); err != nil {
		t.Fatalf("kill worker helper: %v", err)
	}
	if err := helper.Wait(); err == nil {
		t.Fatal("crash helper exited successfully after forced termination")
	}
	helperStopped = true

	restarted, err := sandboxworker.NewService(sandboxworker.ServiceOptions{
		WorkerID:    "worker-l2-restart-live",
		HostKind:    sandboxworker.HostKindLocal,
		Registry:    &sandboxworker.DriverRegistry{},
		JobStateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("restart worker service: %v; helper output: %s", err, helperOutput.String())
	}
	defer restarted.Close()
	status := restarted.JobStatusResponse("restart-status", sandboxworker.JobStatusRequest{
		ContractVersion: sandboxworker.JobContractVersion,
		JobID:           job.ID,
	})
	if !status.OK || status.Job == nil {
		t.Fatalf("restart status = %#v error=%#v", status, status.Error)
	}
	if status.Job.State != sandboxworker.JobStateUnknown &&
		status.Job.State != sandboxworker.JobStateInterrupted {
		t.Fatalf("restart state = %q, want unknown or interrupted", status.Job.State)
	}
	if status.Job.State == sandboxworker.JobStateRunning ||
		status.Job.State == sandboxworker.JobStateSucceeded {
		t.Fatalf("restart falsely claimed execution state %q", status.Job.State)
	}

	result, err := driver.Exec(testCtx, sandboxruntime.ExecRequest{
		Target: *target,
		Args:   []string{"sh", "-c", `test "$(cat /tmp/hal-l2-restart-count)" = x`},
	})
	if err != nil || result == nil || result.ExitCode != 0 {
		t.Fatalf("restart rerun marker check result=%#v error=%v", result, err)
	}

	if err := driver.Delete(testCtx, sandboxruntime.LifecycleRequest{Target: *target}); err != nil {
		t.Fatalf("delete rootless target: %v", err)
	}
	deleted = true
}

func TestWorkerJobPodmanIntegrationCrashHelper(t *testing.T) {
	if os.Getenv(l2RestartHelperEnabledEnv) != "1" {
		return
	}
	socketPath := strings.TrimSpace(os.Getenv(l2RestartHelperSocketEnv))
	stateDir := strings.TrimSpace(os.Getenv(l2RestartHelperStateEnv))
	podmanPath := strings.TrimSpace(os.Getenv(l2RestartHelperPodmanEnv))
	runner := rootlesspodman.DefaultCommandRunner{}
	driver := rootlesspodman.New(rootlesspodman.Options{
		ExecRunner:            runner,
		PodmanPath:            podmanPath,
		WorkDir:               "/",
		JobExecutionSupported: true,
	})
	registry, err := sandboxworker.NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := sandboxworker.NewService(sandboxworker.ServiceOptions{
		WorkerID:    "worker-l2-restart-live",
		HostKind:    sandboxworker.HostKindLocal,
		SocketPath:  socketPath,
		Registry:    registry,
		JobContext:  context.Background(),
		JobStateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	server, err := sandboxworker.NewServer(sandboxworker.ServerOptions{
		SocketPath: socketPath,
		Handler:    service,
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	if err := server.ListenAndServe(context.Background()); err != nil {
		t.Fatalf("ListenAndServe() error: %v", err)
	}
}

func waitForWorkerJobSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("worker socket was not created")
}

func waitForLiveWorkerJob(t *testing.T, client *sandboxworker.Client, jobID string) *sandboxworker.Job {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		job, err := client.JobStatus(ctx, sandboxworker.JobStatusRequest{
			ContractVersion: sandboxworker.JobContractVersion,
			JobID:           jobID,
		})
		if err != nil {
			t.Fatalf("JobStatus() error: %v", err)
		}
		switch job.State {
		case sandboxworker.JobStateSucceeded, sandboxworker.JobStateFailed, sandboxworker.JobStateCanceled, sandboxworker.JobStateInterrupted, sandboxworker.JobStateUnknown:
			return job
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("worker job did not reach a terminal state")
	return nil
}

func waitForLiveWorkerJobState(t *testing.T, client *sandboxworker.Client, jobID, state string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		job, err := client.JobStatus(ctx, sandboxworker.JobStatusRequest{
			ContractVersion: sandboxworker.JobContractVersion,
			JobID:           jobID,
		})
		if err != nil {
			t.Fatalf("JobStatus() error: %v", err)
		}
		if job.State == state {
			return
		}
		if job.State == sandboxworker.JobStateSucceeded ||
			job.State == sandboxworker.JobStateFailed ||
			job.State == sandboxworker.JobStateCanceled ||
			job.State == sandboxworker.JobStateInterrupted ||
			job.State == sandboxworker.JobStateUnknown {
			t.Fatalf("worker job reached terminal state %q before %q", job.State, state)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("worker job did not reach state %q", state)
}

func waitForLiveRuntimeMarker(t *testing.T, driver *rootlesspodman.Driver, target sandboxruntime.Target) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		result, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
			Target: target,
			Args:   []string{"sh", "-c", `test "$(cat /tmp/hal-l2-restart-count 2>/dev/null)" = x`},
		})
		if err == nil && result != nil && result.ExitCode == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("live worker job did not create its single-run marker")
}
