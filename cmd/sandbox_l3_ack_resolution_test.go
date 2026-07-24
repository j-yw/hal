package cmd

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestL3RecoveryResolvesLostAcknowledgementAndPersistsBeforeObservation(t *testing.T) {
	for _, commandName := range []string{"recover", "sync-out"} {
		t.Run(commandName, func(t *testing.T) {
			script := &l3WorkerScript{
				jobState:         sandboxworker.JobStateRunning,
				panicOnForbidden: true,
				pages:            map[uint64]sandboxworker.JobLogsResponse{},
			}
			harness := newL3WorkerHarness(t, script)
			harness.seed("alpha", "run-alpha", "")

			store, err := sandboxexecution.DefaultStore()
			if err != nil {
				t.Fatalf("open execution store: %v", err)
			}
			script.beforeJobStatus = func() {
				manifest, loadErr := store.LoadManifest("run-alpha")
				if loadErr != nil {
					panic(loadErr)
				}
				if manifest.WorkerJob == nil ||
					manifest.WorkerJob.JobID != "job-resolved" ||
					manifest.Finalization == nil ||
					manifest.Finalization.State != sandboxexecution.FinalizationStatePending {
					panic("resolved job and pending finalization were not durable before observation")
				}
			}

			_, _, err = runL3SandboxLeaf(
				context.Background(),
				commandName,
				[]string{"alpha", "--run", "run-alpha"},
			)
			if err == nil || !strings.Contains(err.Error(), "job_not_terminal") {
				t.Fatalf("%s error = %v, want active-job handoff", commandName, err)
			}
			manifest, err := store.LoadManifest("run-alpha")
			if err != nil {
				t.Fatalf("load resolved manifest: %v", err)
			}
			if manifest.WorkerJob == nil ||
				manifest.WorkerJob.JobID != "job-resolved" ||
				manifest.WorkerJob.SubmissionKey != sandboxWorkerJobSubmissionKey("run-alpha") {
				t.Fatalf("resolved WorkerJob = %#v", manifest.WorkerJob)
			}
			if manifest.Finalization == nil ||
				manifest.Finalization.State != sandboxexecution.FinalizationStatePending ||
				manifest.Finalization.SyncOutRequested != (commandName == "sync-out") {
				t.Fatalf("pending finalization = %#v", manifest.Finalization)
			}
			requests, forbidden := script.snapshot()
			if len(forbidden) != 0 {
				t.Fatalf("forbidden worker operations = %v", forbidden)
			}
			if len(requests) != 2 ||
				requests[0].operation != sandboxworker.OperationJobResolve ||
				requests[1].operation != sandboxworker.OperationJobStatus {
				t.Fatalf("worker requests = %#v, want resolve then status only", requests)
			}
		})
	}
}

func TestL3RecoveryResolutionFailsClosedWithoutManifestMutation(t *testing.T) {
	now := time.Date(2026, 7, 25, 5, 0, 0, 0, time.UTC)
	validResolved := func() *sandboxworker.Job {
		started := now.Add(time.Second)
		return &sandboxworker.Job{
			ContractVersion: sandboxworker.JobContractVersion,
			ID:              "job-resolved",
			SubmissionKey:   sandboxWorkerJobSubmissionKey("run-alpha"),
			WorkerID:        "worker-l3",
			HostID:          "worker-l3",
			RuntimeDriver:   sandboxworker.RuntimeDriverRootlessPodman,
			RuntimeID:       "runtime-l3",
			State:           sandboxworker.JobStateRunning,
			SubmittedAt:     now,
			StartedAt:       &started,
			HeartbeatAt:     &started,
		}
	}
	tests := []struct {
		name       string
		mutate     func(*sandboxworker.Job)
		resolveErr *sandboxworker.Error
	}{
		{
			name: "not found",
			resolveErr: &sandboxworker.Error{
				Code:    sandboxworker.ErrorCodeJobNotFound,
				Message: "worker job was not found",
			},
		},
		{name: "submission", mutate: func(job *sandboxworker.Job) { job.SubmissionKey = sandboxWorkerJobSubmissionKey("other-run") }},
		{name: "job", mutate: func(job *sandboxworker.Job) { job.ID = "" }},
		{name: "worker", mutate: func(job *sandboxworker.Job) { job.WorkerID = "worker-other" }},
		{name: "host", mutate: func(job *sandboxworker.Job) { job.HostID = "worker-other" }},
		{name: "runtime driver", mutate: func(job *sandboxworker.Job) { job.RuntimeDriver = sandboxworker.RuntimeDriverMicroVM }},
		{name: "runtime", mutate: func(job *sandboxworker.Job) { job.RuntimeID = "runtime-other" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := validResolved()
			if tt.mutate != nil {
				tt.mutate(job)
			}
			script := &l3WorkerScript{
				jobState:         sandboxworker.JobStateRunning,
				resolveJob:       job,
				resolveError:     tt.resolveErr,
				panicOnForbidden: true,
				pages:            map[uint64]sandboxworker.JobLogsResponse{},
			}
			harness := newL3WorkerHarness(t, script)
			harness.seed("alpha", "run-alpha", "")
			leaseStore := seedL3RecoveryLease(t, "run-alpha", "alpha")
			before := append([]byte(nil), harness.manifestBytes()...)

			_, _, err := runL3SandboxLeaf(
				context.Background(),
				"recover",
				[]string{"alpha", "--run", "run-alpha"},
			)
			if err == nil {
				t.Fatal("recovery unexpectedly accepted invalid resolution")
			}
			after := harness.manifestBytes()
			if string(after) != string(before) {
				t.Fatalf("resolution failure mutated manifest\nbefore:\n%s\nafter:\n%s", before, after)
			}
			requests, forbidden := script.snapshot()
			if len(forbidden) != 0 {
				t.Fatalf("forbidden worker operations = %v", forbidden)
			}
			if len(requests) != 1 || requests[0].operation != sandboxworker.OperationJobResolve {
				t.Fatalf("worker requests = %#v, want read-only resolution only", requests)
			}
			lease, leaseErr := leaseStore.Load("lease-run-alpha")
			if leaseErr != nil {
				t.Fatalf("load exact lease: %v", leaseErr)
			}
			if lease.Status != sandbox.SandboxLeaseStatusActive {
				t.Fatalf("resolution failure released lease: %#v", lease)
			}
			for _, marker := range []string{"/home/", "/tmp/", "TOKEN=", "https://"} {
				if strings.Contains(err.Error(), marker) {
					t.Fatalf("resolution error leaked %q: %v", marker, err)
				}
			}
		})
	}
}

func TestL3RecoveryResolvedTerminalJobContinuesSharedFinalizer(t *testing.T) {
	script := &l3WorkerScript{
		jobState:         sandboxworker.JobStateSucceeded,
		panicOnForbidden: true,
		pages:            map[uint64]sandboxworker.JobLogsResponse{},
	}
	harness := newL3WorkerHarness(t, script)
	harness.seed("alpha", "run-alpha", "")
	leaseStore := seedL3RecoveryLease(t, "run-alpha", "alpha")

	stdout, stderr, err := runL3SandboxLeaf(
		context.Background(),
		"recover",
		[]string{"alpha", "--run", "run-alpha"},
	)
	if err != nil {
		t.Fatalf("recover resolved terminal job: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	store, err := sandboxexecution.DefaultStore()
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	manifest, err := store.LoadManifest("run-alpha")
	if err != nil {
		t.Fatalf("load finalized manifest: %v", err)
	}
	if manifest.WorkerJob == nil ||
		manifest.WorkerJob.JobID != "job-resolved" ||
		manifest.Finalization == nil ||
		manifest.Finalization.State != sandboxexecution.FinalizationStateCompleted ||
		manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("resolved terminal finalization = %#v", manifest)
	}
	lease, err := leaseStore.Load("lease-run-alpha")
	if err != nil {
		t.Fatalf("load exact lease: %v", err)
	}
	if lease.Status != sandbox.SandboxLeaseStatusReleased {
		t.Fatalf("terminal finalizer lease = %#v, want released", lease)
	}
	requests, forbidden := script.snapshot()
	if len(forbidden) != 0 {
		t.Fatalf("forbidden worker operations = %v", forbidden)
	}
	if len(requests) < 2 ||
		requests[0].operation != sandboxworker.OperationJobResolve ||
		requests[1].operation != sandboxworker.OperationJobStatus {
		t.Fatalf("worker requests = %#v, want resolution before shared finalizer", requests)
	}
}

func TestL3RecoveryNoRunSelectionIncludesResolvableMissingReferencesAndFailsAmbiguous(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())
	now := time.Date(2026, 7, 25, 6, 0, 0, 0, time.UTC)
	saveL3Sandbox(t, "alpha", now)
	store, err := sandboxexecution.DefaultStore()
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	saveL3Manifest(t, store, l3Manifest("run-one", "alpha", now, "", "", 0))

	_, selected, err := selectSandboxL3Execution("alpha", "", sandboxL3SelectionRecover)
	if err != nil {
		t.Fatalf("select resolvable missing reference: %v", err)
	}
	if selected.ID != "run-one" {
		t.Fatalf("selected execution = %q, want run-one", selected.ID)
	}

	saveL3Manifest(t, store, l3Manifest("run-two", "alpha", now.Add(time.Second), "", "", 0))
	_, _, err = selectSandboxL3Execution("alpha", "", sandboxL3SelectionRecover)
	if err == nil || !strings.Contains(err.Error(), "ambiguous_run") ||
		!strings.Contains(err.Error(), "run-one") || !strings.Contains(err.Error(), "run-two") {
		t.Fatalf("ambiguous selection error = %v", err)
	}
}

func TestL3RecoveryMissingReferenceRejectsLegacyAndIncoherentRoutes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*sandboxexecution.Manifest)
	}{
		{name: "legacy", mutate: func(manifest *sandboxexecution.Manifest) { manifest.WorkerRouting = nil }},
		{name: "non worker", mutate: func(manifest *sandboxexecution.Manifest) { manifest.Host.Kind = sandbox.SandboxHostKindSSH }},
		{name: "non rootless", mutate: func(manifest *sandboxexecution.Manifest) {
			manifest.Runtime.Driver = sandbox.SandboxRuntimeDriverSSHMachine
		}},
		{name: "routing host mismatch", mutate: func(manifest *sandboxexecution.Manifest) {
			manifest.WorkerRouting.SelectedWorkerHostID = "worker-other"
		}},
		{name: "routing driver mismatch", mutate: func(manifest *sandboxexecution.Manifest) {
			manifest.WorkerRouting.RuntimeDriverID = sandbox.SandboxRuntimeDriverMicroVM
		}},
		{name: "finished", mutate: func(manifest *sandboxexecution.Manifest) { manifest.Status = sandboxexecution.StatusFailed }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HAL_CONFIG_HOME", t.TempDir())
			now := time.Date(2026, 7, 25, 7, 0, 0, 0, time.UTC)
			saveL3Sandbox(t, "alpha", now)
			store, err := sandboxexecution.DefaultStore()
			if err != nil {
				t.Fatalf("open execution store: %v", err)
			}
			manifest := l3Manifest("run-alpha", "alpha", now, "", "", 0)
			tt.mutate(manifest)
			saveL3Manifest(t, store, manifest)

			_, _, err = selectSandboxL3Execution("alpha", "run-alpha", sandboxL3SelectionRecover)
			if err == nil || !strings.Contains(err.Error(), "worker_job_missing") {
				t.Fatalf("legacy/incoherent selection error = %v, want safe missing-job rejection", err)
			}
		})
	}
}

func TestL3RecoveryConcurrentMissingReferenceResolutionRunsOnce(t *testing.T) {
	script := &l3WorkerScript{
		jobState:         sandboxworker.JobStateRunning,
		panicOnForbidden: true,
		pages:            map[uint64]sandboxworker.JobLogsResponse{},
	}
	harness := newL3WorkerHarness(t, script)
	harness.seed("alpha", "run-alpha", "")

	var start atomic.Int32
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start.Add(1)
			for start.Load() != 2 {
			}
			store, err := sandboxexecution.DefaultStore()
			if err != nil {
				errs <- err
				return
			}
			errs <- finalizeSandboxL3Execution(
				context.Background(),
				store,
				"run-alpha",
				false,
				defaultSandboxL3FinalizationDeps(),
			)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err == nil || !strings.Contains(err.Error(), "job_not_terminal") {
			t.Fatalf("concurrent recovery error = %v, want active-job handoff", err)
		}
	}
	requests, forbidden := script.snapshot()
	if len(forbidden) != 0 {
		t.Fatalf("forbidden worker operations = %v", forbidden)
	}
	var resolves int
	for _, request := range requests {
		if request.operation == sandboxworker.OperationJobResolve {
			resolves++
		}
	}
	if resolves != 1 {
		t.Fatalf("concurrent JobResolve calls = %d, want one", resolves)
	}
}

func TestL3RecoveryMissingReferenceTransportFailureIsSanitized(t *testing.T) {
	script := &l3WorkerScript{
		jobState:         sandboxworker.JobStateRunning,
		panicOnForbidden: true,
		pages:            map[uint64]sandboxworker.JobLogsResponse{},
	}
	harness := newL3WorkerHarness(t, script)
	harness.seed("alpha", "run-alpha", "")
	original := sandboxL3NewWorkerClient
	sandboxL3NewWorkerClient = func(string) (*sandboxworker.Client, error) {
		return nil, errors.New("dial /tmp/private.sock TOKEN=secret")
	}
	t.Cleanup(func() { sandboxL3NewWorkerClient = original })

	_, _, err := runL3SandboxLeaf(context.Background(), "recover", []string{"alpha", "--run", "run-alpha"})
	if err == nil {
		t.Fatal("recovery unexpectedly accepted unavailable worker")
	}
	if strings.Contains(err.Error(), "/tmp/private.sock") || strings.Contains(err.Error(), "TOKEN=secret") {
		t.Fatalf("transport error was not sanitized: %v", err)
	}
}
