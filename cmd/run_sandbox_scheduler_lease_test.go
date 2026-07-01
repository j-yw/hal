package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestRunSandboxExplicitSchedulerAcquiresLeaseAndPersistsManifest(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	host := runSandboxSchedulerLeaseHost("worker-scheduled", "worker scheduled")
	var out bytes.Buffer
	var errOut bytes.Buffer
	var acquireCalled bool
	var workerResolverCalled bool
	var persistedState *sandbox.SandboxState

	workerDriver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		start: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
			if !acquireCalled {
				t.Fatal("runtime Start ran before scheduler lease acquisition")
			}
			target := req.Target
			target.Status = sandbox.StatusRunning
			target.Runtime.RuntimeID = "runtime-started"
			return &target, nil
		},
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Runtime.WorkerID != "worker-scheduled" {
				t.Fatalf("Exec worker ID = %q, want selected worker host ID", req.Target.Runtime.WorkerID)
			}
			_, _ = io.WriteString(req.Stdout, "scheduled run path\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		SandboxHostID:         "worker-scheduled",
		SandboxHostChanged:    true,
		SandboxRuntime:        sandboxruntime.DriverRootlessPodman,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-scheduler-lease"
		},
		now:        runSandboxTestClock(startedAt, finishedAt),
		workingDir: func() (string, error) { return projectDir, nil },
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return workerRootlessBundlePlan(projectDir), nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{host}, nil
		},
		listLeases: func() ([]*sandbox.SandboxLease, error) {
			return nil, nil
		},
		acquireLease: func(req sandbox.SandboxLeaseAcquireRequest, ttl time.Duration) (*sandbox.SandboxLease, error) {
			if req.ID != "run-scheduler-lease" {
				t.Fatalf("lease ID = %q, want execution ID", req.ID)
			}
			if req.ResourceKey != "host:worker-scheduled" {
				t.Fatalf("lease resource key = %q, want selected host resource", req.ResourceKey)
			}
			if req.Purpose != sandbox.SandboxLeasePurposeRun || req.RunID != "run-scheduler-lease" {
				t.Fatalf("lease purpose/run = %q/%q, want run/run-scheduler-lease", req.Purpose, req.RunID)
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
			if req.Host == nil || req.Host.ID != "worker-scheduled" {
				t.Fatalf("worker resolver host = %#v, want scheduled host", req.Host)
			}
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
				t.Fatalf("worker resolver runtime = %q, want rootless_podman", req.Target.Runtime.Driver)
			}
			if req.Target.Runtime.WorkerID != "worker-scheduled" {
				t.Fatalf("worker resolver worker ID = %q, want selected host ID", req.Target.Runtime.WorkerID)
			}
			return workerDriver, nil
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
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if !acquireCalled {
		t.Fatal("lease was not acquired")
	}
	if !workerResolverCalled {
		t.Fatal("worker runtime resolver was not called")
	}
	if persistedState == nil || persistedState.Lease == nil {
		t.Fatalf("persisted state lease = %#v, want safe lease ref", persistedState)
	}

	manifest, err := store.LoadManifest("run-scheduler-lease")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("manifest status = %q, want succeeded", manifest.Status)
	}
	if manifest.Host == nil || manifest.Host.ID != "worker-scheduled" || manifest.Host.Endpoint != "" {
		t.Fatalf("manifest host = %#v, want safe selected host identity", manifest.Host)
	}
	if manifest.Runtime == nil || manifest.Runtime.Driver != sandboxruntime.DriverRootlessPodman || manifest.Runtime.WorkerID != "worker-scheduled" {
		t.Fatalf("manifest runtime = %#v, want scheduled rootless worker runtime", manifest.Runtime)
	}
	if manifest.WorkerRouting == nil || manifest.WorkerRouting.SelectedWorkerHostID != "worker-scheduled" {
		t.Fatalf("manifest worker routing = %#v, want selected worker route", manifest.WorkerRouting)
	}
	if manifest.Lease == nil {
		t.Fatal("manifest lease = nil, want safe scheduler lease ref")
	}
	if manifest.Lease.ID != "run-scheduler-lease" ||
		manifest.Lease.HostID != "worker-scheduled" ||
		manifest.Lease.HostName != "worker scheduled" ||
		manifest.Lease.RuntimeDriver != sandboxruntime.DriverRootlessPodman ||
		manifest.Lease.ResourceKey != "host:worker-scheduled" ||
		manifest.Lease.Purpose != sandbox.SandboxLeasePurposeRun ||
		manifest.Lease.RunID != "run-scheduler-lease" ||
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

func TestRunSandboxSchedulerFailurePreventsRuntimeConstruction(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 8, 5, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		SandboxHostID:         "worker-full",
		SandboxHostChanged:    true,
		SandboxRuntime:        sandboxruntime.DriverRootlessPodman,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-scheduler-blocked"
		},
		now:        runSandboxTestClock(startedAt, finishedAt),
		workingDir: func() (string, error) { return projectDir, nil },
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return workerRootlessBundlePlan(projectDir), nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			host := runSandboxSchedulerLeaseHost("worker-full", "worker full")
			host.Capacity.MaxConcurrentSandboxes = 1
			return []*sandbox.SandboxHost{host}, nil
		},
		listLeases: func() ([]*sandbox.SandboxLease, error) {
			return []*sandbox.SandboxLease{{
				ID:          "active-lease",
				ResourceKey: "host:worker-full",
				Holder:      "other-run",
				Purpose:     sandbox.SandboxLeasePurposeRun,
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
		t.Fatal("runRunSandboxWithWriter() error = nil, want scheduler rejection")
	}
	if !strings.Contains(err.Error(), "no available cached capacity") {
		t.Fatalf("error = %q, want capacity-blocked scheduler rejection", err.Error())
	}

	manifest, err := store.LoadManifest("run-scheduler-blocked")
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

func runSandboxSchedulerLeaseHost(id, name string) *sandbox.SandboxHost {
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
