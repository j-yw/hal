//go:build linux && podman_integration

package sandboxworker_test

import (
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

func TestWorkerJobPodmanIntegrationCapacityFailureAndCancellation(t *testing.T) {
	image := strings.TrimSpace(os.Getenv("HAL_PODMAN_TEST_IMAGE"))
	if image == "" {
		t.Skip("HAL_PODMAN_TEST_IMAGE is unset")
	}
	if err := exec.Command("podman", "image", "exists", image).Run(); err != nil {
		t.Fatalf("required local Podman image is unavailable: %v", err)
	}
	runner := rootlesspodman.DefaultCommandRunner{}
	driver := rootlesspodman.New(rootlesspodman.Options{
		LifecycleRunner: runner, ExecRunner: runner, CopyRunner: runner,
		Image: image, WorkDir: "/", JobExecutionSupported: true,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	target, err := driver.Create(ctx, sandboxruntime.CreateRequest{
		Name: fmt.Sprintf("hal-l2-capacity-live-%d-%d", os.Getpid(), time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatalf("create rootless target: %v", err)
	}
	cleanupTarget := *target
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		if err := driver.Delete(cleanupCtx, sandboxruntime.LifecycleRequest{Target: cleanupTarget}); err != nil {
			t.Errorf("delete owned rootless target: %v", err)
		}
	})
	target, err = driver.Start(ctx, sandboxruntime.LifecycleRequest{Target: *target})
	if err != nil {
		t.Fatalf("start rootless target: %v", err)
	}
	registry, err := sandboxworker.NewDriverRegistry(driver)
	if err != nil {
		t.Fatal(err)
	}
	socketPath := liveWorkerJobSocketPath(t)
	daemonCtx, daemonCancel := context.WithCancel(context.Background())
	service, err := sandboxworker.NewService(sandboxworker.ServiceOptions{
		WorkerID: "worker-l2-capacity-live", HostKind: sandboxworker.HostKindLocal,
		SocketPath: socketPath, Registry: registry, JobContext: daemonCtx,
		JobStateDir: filepath.Join(t.TempDir(), "jobs"),
		Capacity:    sandboxworker.WorkerCapacity{MaxConcurrentSandboxes: 1},
	})
	if err != nil {
		daemonCancel()
		t.Fatal(err)
	}
	server, err := sandboxworker.NewServer(sandboxworker.ServerOptions{SocketPath: socketPath, Handler: service})
	if err != nil {
		daemonCancel()
		service.Close()
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.ListenAndServe(daemonCtx) }()
	t.Cleanup(func() {
		daemonCancel()
		service.Close()
		select {
		case err := <-serveDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("worker shutdown: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("worker did not stop")
		}
	})
	waitForWorkerJobSocket(t, socketPath)
	client, err := sandboxworker.NewClient(sandboxworker.ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatal(err)
	}
	start := func(id, script string) (*sandboxworker.Job, error) {
		return client.JobStart(ctx, sandboxruntime.DriverRootlessPodman, sandboxworker.JobStartRequest{
			ContractVersion: sandboxworker.JobContractVersion, SubmissionID: id,
			Exec: sandboxworker.ExecRequest{
				OperationID: id,
				Target: sandboxworker.Target{
					ID: target.ID, Name: target.Name,
					Runtime: sandboxworker.RuntimeTarget{Driver: target.Runtime.Driver, RuntimeID: target.Runtime.RuntimeID},
				},
				Args:             []string{"sh", "-c", script},
				StdoutLimitBytes: sandboxworker.MaxExecStdoutCaptureBytes,
				StderrLimitBytes: sandboxworker.MaxExecStderrCaptureBytes,
			},
		})
	}
	first, err := start("capacity-running", "printf 'capacity-ready\\n'; sleep 60")
	if err != nil {
		t.Fatalf("start first job: %v", err)
	}
	waitForLiveWorkerJobState(t, client, first.ID, sandboxworker.JobStateRunning)
	waitForLiveWorkerLog(t, ctx, client, first.ID, "capacity-ready")
	if got := service.Status().Capacity.ActiveSandboxes; got != 1 {
		t.Fatalf("active sandboxes while running = %d, want 1", got)
	}
	_, err = start("capacity-rejected", "touch /tmp/hal-capacity-rejected-must-not-run")
	var protocolErr *sandboxworker.ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Code != sandboxworker.ErrorCodeCapacityExceeded {
		t.Fatalf("second admission = %v, want capacity_exceeded", err)
	}
	if _, err := client.JobCancel(ctx, sandboxworker.JobCancelRequest{
		ContractVersion: sandboxworker.JobContractVersion, JobID: first.ID,
	}); err != nil {
		t.Fatalf("cancel running job: %v", err)
	}
	if terminal := waitForLiveWorkerJob(t, client, first.ID); terminal.State != sandboxworker.JobStateCanceled {
		t.Fatalf("canceled job state = %q", terminal.State)
	}
	failed, err := start("capacity-failed", "printf 'expected-failure\\n' >&2; exit 7")
	if err != nil {
		t.Fatalf("capacity was not released after cancellation: %v", err)
	}
	terminal := waitForLiveWorkerJob(t, client, failed.ID)
	if terminal.State != sandboxworker.JobStateFailed || terminal.ExitCode == nil || *terminal.ExitCode != 7 {
		t.Fatalf("failed job state/exit = %q/%v, want failed/7", terminal.State, terminal.ExitCode)
	}
	waitForLiveWorkerLog(t, ctx, client, failed.ID, "expected-failure")
	last, err := start("capacity-reused", "test ! -e /tmp/hal-capacity-rejected-must-not-run && printf 'capacity-reused\\n'")
	if err != nil {
		t.Fatalf("capacity was not released after failure: %v", err)
	}
	if terminal := waitForLiveWorkerJob(t, client, last.ID); terminal.State != sandboxworker.JobStateSucceeded {
		t.Fatalf("reused sandbox job state = %q", terminal.State)
	}
	if got := service.Status().Capacity.ActiveSandboxes; got != 0 {
		t.Fatalf("active sandboxes after terminal jobs = %d, want 0", got)
	}
}

func waitForLiveWorkerLog(t *testing.T, ctx context.Context, client *sandboxworker.Client, jobID, marker string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		logs, err := client.JobLogs(ctx, sandboxworker.JobLogsRequest{
			ContractVersion: sandboxworker.JobContractVersion, JobID: jobID,
			LimitBytes: sandboxworker.DefaultJobLogReadBytes,
		})
		if err != nil {
			t.Fatalf("read worker logs: %v", err)
		}
		for _, record := range logs.Records {
			if strings.Contains(record.Data, marker) {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("expected worker output did not arrive")
}
