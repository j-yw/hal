package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxtarget"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestSandboxCommandConcurrentNoNameSchedulingHonorsDurableHostCapacity(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())
	now := time.Date(2026, 7, 12, 15, 0, 0, 0, time.UTC)
	host := autoSandboxSchedulerLeaseHost("worker-capacity-one", "worker capacity one")
	host.Capacity.MaxConcurrentSandboxes = 1
	projectDir := t.TempDir()

	listLeases := sandboxCommandDefaultLeaseLister(func() time.Time { return now }, false)
	acquireLease := sandboxCommandDefaultLeaseAcquirer(func() time.Time { return now }, false)
	releaseLease := sandboxCommandDefaultLeaseReleaser(func() time.Time { return now }, false)

	const contenders = 16
	ready := make(chan struct{}, contenders)
	releaseSnapshot := make(chan struct{})
	barrierListLeases := func() ([]*sandbox.SandboxLease, error) {
		leases, err := listLeases()
		ready <- struct{}{}
		<-releaseSnapshot
		return leases, err
	}

	type result struct {
		runID  string
		target *sandbox.SandboxState
		err    error
	}
	results := make(chan result, contenders)
	var workers sync.WaitGroup
	for i := 0; i < contenders; i++ {
		runID := fmt.Sprintf("auto-capacity-%02d", i)
		workers.Add(1)
		go func() {
			defer workers.Done()
			target, err := resolveSandboxCommandScheduledTarget(sandboxCommandScheduledTargetRequest{
				Purpose:        sandbox.SandboxLeasePurposeAuto,
				SandboxHostID:  host.ID,
				SandboxRuntime: sandboxruntime.DriverRootlessPodman,
				ProjectDir:     projectDir,
				Branch:         "hal/concurrent-capacity",
				RunID:          runID,
			}, sandboxCommandScheduledTargetDeps{
				listHosts: func() ([]*sandbox.SandboxHost, error) {
					return []*sandbox.SandboxHost{host}, nil
				},
				listLeases:   barrierListLeases,
				now:          func() time.Time { return now },
				acquireLease: acquireLease,
			})
			results <- result{runID: runID, target: target, err: err}
		}()
	}
	for i := 0; i < contenders; i++ {
		<-ready
	}
	close(releaseSnapshot)
	workers.Wait()
	close(results)

	var winner *sandbox.SandboxState
	failures := 0
	for got := range results {
		if got.err == nil {
			if winner != nil {
				t.Fatalf("multiple capacity-one leases succeeded: first=%q second=%q", winner.Lease.RunID, got.runID)
			}
			winner = got.target
			continue
		}
		failures++
		var failure *sandboxtarget.Failure
		if !errors.As(got.err, &failure) {
			t.Fatalf("contender %q error type = %T (%v), want scheduler capacity failure", got.runID, got.err, got.err)
		}
		if failure.Reason != sandboxtarget.FailureReasonCapacityBlocked || !strings.Contains(got.err.Error(), "no available cached capacity") {
			t.Fatalf("contender %q failure = %#v (%v), want capacity_blocked contract", got.runID, failure, got.err)
		}
	}
	if winner == nil || winner.Lease == nil {
		t.Fatal("capacity-one scheduling produced no winning durable lease")
	}
	if failures != contenders-1 {
		t.Fatalf("capacity failures = %d, want %d", failures, contenders-1)
	}

	leases, err := listLeases()
	if err != nil {
		t.Fatalf("list durable leases: %v", err)
	}
	active := 0
	for _, lease := range leases {
		if lease.Status == sandbox.SandboxLeaseStatusActive && lease.ResourceKey == "host:"+host.ID {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("active host leases = %d, want 1", active)
	}

	if _, err := releaseLease(winner.Lease.ID); err != nil {
		t.Fatalf("release winning lease: %v", err)
	}
	next, err := resolveSandboxCommandScheduledTarget(sandboxCommandScheduledTargetRequest{
		Purpose:        sandbox.SandboxLeasePurposeAuto,
		SandboxHostID:  host.ID,
		SandboxRuntime: sandboxruntime.DriverRootlessPodman,
		ProjectDir:     projectDir,
		Branch:         "hal/after-capacity-release",
		RunID:          "auto-capacity-after-release",
	}, sandboxCommandScheduledTargetDeps{
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{host}, nil
		},
		listLeases:   listLeases,
		now:          func() time.Time { return now },
		acquireLease: acquireLease,
	})
	if err != nil {
		t.Fatalf("scheduling after release: %v", err)
	}
	if next == nil || next.Lease == nil || next.Lease.ID != "auto-capacity-after-release" {
		t.Fatalf("post-release target lease = %#v, want replacement lease", next)
	}
}

func TestAutoSandboxExplicitSchedulerAcquiresLeaseAndPersistsManifest(t *testing.T) {
	testAutoSandboxExplicitSchedulerAcquiresLeaseAndPersistsManifest(t, "")
}

func TestAutoSandboxFreshNamedWorkerTargetAcquiresLeaseAndPersistsManifest(t *testing.T) {
	testAutoSandboxExplicitSchedulerAcquiresLeaseAndPersistsManifest(t, "named-auto-worker")
}

func testAutoSandboxExplicitSchedulerAcquiresLeaseAndPersistsManifest(t *testing.T, sandboxName string) {
	t.Helper()

	startedAt := time.Date(2026, 7, 1, 8, 20, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	host := autoSandboxSchedulerLeaseHost("worker-auto-scheduled", "worker auto scheduled")
	var out bytes.Buffer
	var errOut bytes.Buffer
	var acquireCalled bool
	var createCalled bool
	var releaseCalled bool
	var workerResolverCalled bool
	var persistedState *sandbox.SandboxState

	workerDriver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		create: func(_ context.Context, req sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
			if !acquireCalled {
				t.Fatal("runtime Create ran before scheduler lease acquisition")
			}
			if sandboxName != "" && req.Name != sandboxName {
				t.Fatalf("runtime Create name = %q, want %q", req.Name, sandboxName)
			}
			createCalled = true
			return &sandboxruntime.Target{
				ID:     req.Name + "-runtime",
				Name:   req.Name,
				Status: sandbox.StatusStopped,
				Runtime: sandboxruntime.RuntimeState{
					Driver:    sandboxruntime.DriverRootlessPodman,
					RuntimeID: req.Name + "-runtime",
				},
			}, nil
		},
		start: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
			if !acquireCalled {
				t.Fatal("runtime Start ran before scheduler lease acquisition")
			}
			target := req.Target
			target.Status = sandbox.StatusRunning
			target.Runtime.RuntimeID = "runtime-auto-started"
			return &target, nil
		},
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Runtime.WorkerID != "worker-auto-scheduled" {
				t.Fatalf("Exec worker ID = %q, want selected worker host ID", req.Target.Runtime.WorkerID)
			}
			_, _ = io.WriteString(req.Stdout, autoSandboxRemoteSuccessJSON("scheduled auto path")+"\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		SandboxName:           sandboxName,
		SandboxNameChanged:    sandboxName != "",
		SandboxHostID:         "worker-auto-scheduled",
		SandboxHostChanged:    true,
		SandboxRuntime:        sandboxruntime.DriverRootlessPodman,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-scheduler-lease"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return workerRootlessBundlePlan(projectDir), nil
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if sandboxName == "" {
				t.Fatal("loadSandbox should not run for unnamed scheduled target")
			}
			if name != sandboxName {
				t.Fatalf("loadSandbox name = %q, want %q", name, sandboxName)
			}
			return nil, fs.ErrNotExist
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{host}, nil
		},
		listLeases: func() ([]*sandbox.SandboxLease, error) {
			return nil, nil
		},
		acquireLease: func(req sandbox.SandboxLeaseAcquireRequest, ttl time.Duration) (*sandbox.SandboxLease, error) {
			if req.ID != "auto-scheduler-lease" {
				t.Fatalf("lease ID = %q, want execution ID", req.ID)
			}
			if req.ResourceKey != "host:worker-auto-scheduled" {
				t.Fatalf("lease resource key = %q, want selected host resource", req.ResourceKey)
			}
			if req.Purpose != sandbox.SandboxLeasePurposeAuto || req.RunID != "auto-scheduler-lease" {
				t.Fatalf("lease purpose/run = %q/%q, want auto/auto-scheduler-lease", req.Purpose, req.RunID)
			}
			if strings.TrimSpace(req.Holder) == "" {
				t.Fatal("lease holder is empty")
			}
			if ttl != sandboxCommandLeaseTTL {
				t.Fatalf("lease ttl = %v, want %v", ttl, sandboxCommandLeaseTTL)
			}
			acquireCalled = true
			return &sandbox.SandboxLease{
				ID:          req.ID,
				SandboxName: req.SandboxName,
				ResourceKey: req.ResourceKey,
				Holder:      req.Holder,
				Purpose:     req.Purpose,
				RunID:       req.RunID,
				AcquiredAt:  startedAt,
				ExpiresAt:   startedAt.Add(ttl),
				Status:      sandbox.SandboxLeaseStatusActive,
			}, nil
		},
		releaseLease: func(id string) (*sandbox.SandboxLease, error) {
			if id != "auto-scheduler-lease" {
				t.Fatalf("release lease ID = %q, want auto-scheduler-lease", id)
			}
			releaseCalled = true
			return &sandbox.SandboxLease{ID: id, Status: sandbox.SandboxLeaseStatusReleased}, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for scheduled worker target")
			return nil, nil
		},
		resolveWorkerRuntime: func(req sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			workerResolverCalled = true
			if !acquireCalled {
				t.Fatal("worker runtime resolver ran before scheduler lease acquisition")
			}
			if req.Host == nil || req.Host.ID != "worker-auto-scheduled" {
				t.Fatalf("worker resolver host = %#v, want scheduled host", req.Host)
			}
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
				t.Fatalf("worker resolver runtime = %q, want rootless_podman", req.Target.Runtime.Driver)
			}
			if req.Target.Runtime.WorkerID != "worker-auto-scheduled" {
				t.Fatalf("worker resolver worker ID = %q, want selected host ID", req.Target.Runtime.WorkerID)
			}
			return withFakeSandboxWorkerJobs(workerDriver), nil
		},
		persistSandboxState: func(state *sandbox.SandboxState) error {
			persistedState = state
			return nil
		},
		materializeWorkspace: func(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
			return sandboxworkspace.MaterializationResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if !acquireCalled {
		t.Fatal("lease was not acquired")
	}
	if !createCalled {
		t.Fatal("runtime Create was not called")
	}
	if !releaseCalled {
		t.Fatal("lease was not released")
	}
	if !workerResolverCalled {
		t.Fatal("worker runtime resolver was not called")
	}
	if persistedState == nil || persistedState.Lease == nil {
		t.Fatalf("persisted state lease = %#v, want safe lease ref", persistedState)
	}

	manifest, err := store.LoadManifest("auto-scheduler-lease")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("manifest status = %q, want succeeded", manifest.Status)
	}
	if manifest.Purpose != sandboxexecution.PurposeAuto {
		t.Fatalf("manifest purpose = %q, want auto", manifest.Purpose)
	}
	if sandboxName != "" && manifest.SandboxName != sandboxName {
		t.Fatalf("manifest sandbox name = %q, want %q", manifest.SandboxName, sandboxName)
	}
	if manifest.Host == nil || manifest.Host.ID != "worker-auto-scheduled" || manifest.Host.Endpoint != "" {
		t.Fatalf("manifest host = %#v, want safe selected host identity", manifest.Host)
	}
	if manifest.Runtime == nil || manifest.Runtime.Driver != sandboxruntime.DriverRootlessPodman || manifest.Runtime.WorkerID != "worker-auto-scheduled" {
		t.Fatalf("manifest runtime = %#v, want scheduled rootless worker runtime", manifest.Runtime)
	}
	if manifest.WorkerRouting == nil || manifest.WorkerRouting.SelectedWorkerHostID != "worker-auto-scheduled" {
		t.Fatalf("manifest worker routing = %#v, want selected worker route", manifest.WorkerRouting)
	}
	if manifest.Lease == nil {
		t.Fatal("manifest lease = nil, want safe scheduler lease ref")
	}
	if manifest.Lease.ID != "auto-scheduler-lease" ||
		manifest.Lease.HostID != "worker-auto-scheduled" ||
		manifest.Lease.HostName != "worker auto scheduled" ||
		manifest.Lease.RuntimeDriver != sandboxruntime.DriverRootlessPodman ||
		manifest.Lease.ResourceKey != "host:worker-auto-scheduled" ||
		manifest.Lease.Purpose != sandbox.SandboxLeasePurposeAuto ||
		manifest.Lease.RunID != "auto-scheduler-lease" ||
		!manifest.Lease.ExpiresAt.Equal(startedAt.Add(sandboxCommandLeaseTTL)) {
		t.Fatalf("manifest lease = %#v, want selected safe lease ref", manifest.Lease)
	}
	if manifest.Lease.Holder != "" {
		t.Fatalf("manifest lease holder = %q, want redacted", manifest.Lease.Holder)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("json.Marshal(manifest) error: %v", err)
	}
	for _, forbidden := range []string{"unsafe-holder", "unix://", workerSafeUnixEndpoint()} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("manifest leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestAutoSandboxSchedulerFailurePreventsProviderAndRuntimeConstruction(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 8, 25, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		SandboxHostID:         "worker-auto-full",
		SandboxHostChanged:    true,
		SandboxRuntime:        sandboxruntime.DriverRootlessPodman,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-scheduler-blocked"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return workerRootlessBundlePlan(projectDir), nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			host := autoSandboxSchedulerLeaseHost("worker-auto-full", "worker auto full")
			host.Capacity.MaxConcurrentSandboxes = 1
			return []*sandbox.SandboxHost{host}, nil
		},
		listLeases: func() ([]*sandbox.SandboxLease, error) {
			return []*sandbox.SandboxLease{{
				ID:          "active-auto-lease",
				ResourceKey: "host:worker-auto-full",
				Holder:      "other-auto",
				Purpose:     sandbox.SandboxLeasePurposeAuto,
				AcquiredAt:  startedAt.Add(-time.Minute),
				ExpiresAt:   startedAt.Add(time.Minute),
				Status:      sandbox.SandboxLeaseStatusActive,
			}}, nil
		},
		acquireLease: func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
			t.Fatal("lease acquisition should not run after scheduler rejection")
			return nil, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			t.Fatal("provider resolution should not run after scheduler rejection")
			return nil, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("runtime driver should not be constructed after scheduler rejection")
			return nil, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			t.Fatal("worker runtime driver should not be constructed after scheduler rejection")
			return nil, nil
		},
		materializeWorkspace: func(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
			t.Fatal("workspace materialization should not run after scheduler rejection")
			return sandboxworkspace.MaterializationResult{}, nil
		},
	})
	if err == nil {
		t.Fatal("runAutoSandboxWithWriter() error = nil, want scheduler rejection")
	}
	if !strings.Contains(err.Error(), "no available cached capacity") {
		t.Fatalf("error = %q, want capacity-blocked scheduler rejection", err.Error())
	}

	manifest, err := store.LoadManifest("auto-scheduler-blocked")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("manifest status = %q, want failed", manifest.Status)
	}
	if manifest.Lease != nil || manifest.Host != nil || manifest.Runtime != nil {
		t.Fatalf("manifest target metadata = host:%#v runtime:%#v lease:%#v, want none after scheduler rejection", manifest.Host, manifest.Runtime, manifest.Lease)
	}
}

func autoSandboxSchedulerLeaseHost(id, name string) *sandbox.SandboxHost {
	return &sandbox.SandboxHost{
		ID:       id,
		Name:     name,
		Kind:     sandbox.SandboxHostKindWorker,
		Endpoint: workerSafeUnixEndpoint(),
		SupportedRuntimes: []string{
			sandboxruntime.DriverRootlessPodman,
		},
		Capacity: &sandbox.HostCapacity{
			MaxConcurrentSandboxes: 2,
		},
		Health: &sandbox.HostHealth{
			Status: "healthy",
		},
		Security: workerRootlessHostSecurity(),
	}
}
