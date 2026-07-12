package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestFactorySandboxExplicitSchedulerAcquiresLeaseAndPersistsRecord(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	startedAt := time.Date(2026, 7, 1, 8, 40, 0, 0, time.UTC)
	projectDir := t.TempDir()
	store := factory.NewStore(t.TempDir())
	host := factorySandboxSchedulerLeaseHost("worker-factory-scheduled", "worker factory scheduled")
	var out bytes.Buffer
	var acquireCalled bool
	var workerResolverCalled bool
	var persistedState *sandbox.SandboxState

	workerDriver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		create: func(_ context.Context, req sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
			if !acquireCalled {
				t.Fatal("runtime Create ran before scheduler lease acquisition")
			}
			return &sandboxruntime.Target{
				ID:     "runtime-factory-created",
				Name:   req.Name,
				Status: sandbox.StatusStopped,
				Runtime: sandboxruntime.RuntimeState{
					Driver:    sandboxruntime.DriverRootlessPodman,
					RuntimeID: "runtime-factory-created",
				},
			}, nil
		},
		start: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
			if !acquireCalled {
				t.Fatal("runtime Start ran before scheduler lease acquisition")
			}
			target := req.Target
			target.Status = sandbox.StatusRunning
			target.Runtime.RuntimeID = "runtime-factory-started"
			return &target, nil
		},
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Runtime.WorkerID != "worker-factory-scheduled" {
				t.Fatalf("Exec worker ID = %q, want selected worker host ID", req.Target.Runtime.WorkerID)
			}
			_, _ = io.WriteString(req.Stdout, "scheduled factory path\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:     projectDir,
		SandboxHostID:  "worker-factory-scheduled",
		SandboxRuntime: sandboxruntime.DriverRootlessPodman,
		RemoteOutput:   &out,
		RunRecord: factory.RunRecord{
			RunID:      "factory-scheduler-lease",
			RepoPath:   projectDir,
			RepoRemote: "git@example.com:org/repo.git",
			BranchName: "feature/factory-scheduled",
			BaseBranch: "main",
		},
		RemoteAuto: factoryRunAutoRequest{BaseBranch: "main"},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) {
			return store, nil
		},
		now: runSandboxTestClock(startedAt, startedAt.Add(time.Second), startedAt.Add(2*time.Second), startedAt.Add(3*time.Second)),
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatal("loadSandbox should not run for unnamed scheduled factory target")
			return nil, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("listSandboxes should not run for unnamed scheduled factory target")
			return nil, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("resolveDefault should not run for unnamed scheduled factory target")
			return nil, "", nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{host}, nil
		},
		listLeases: func() ([]*sandbox.SandboxLease, error) {
			return nil, nil
		},
		acquireLease: func(req sandbox.SandboxLeaseAcquireRequest, ttl time.Duration) (*sandbox.SandboxLease, error) {
			if req.ID != "factory-scheduler-lease" {
				t.Fatalf("lease ID = %q, want run ID", req.ID)
			}
			if req.ResourceKey != "host:worker-factory-scheduled" {
				t.Fatalf("lease resource key = %q, want selected host resource", req.ResourceKey)
			}
			if req.Purpose != sandbox.SandboxLeasePurposeFactory || req.RunID != "factory-scheduler-lease" {
				t.Fatalf("lease purpose/run = %q/%q, want factory/factory-scheduler-lease", req.Purpose, req.RunID)
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
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run for scheduled factory target")
			return nil, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for scheduled worker factory target")
			return nil, nil
		},
		resolveWorkerRuntime: func(req sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			workerResolverCalled = true
			if !acquireCalled {
				t.Fatal("worker runtime resolver ran before scheduler lease acquisition")
			}
			if req.Host == nil || req.Host.ID != "worker-factory-scheduled" {
				t.Fatalf("worker resolver host = %#v, want scheduled host", req.Host)
			}
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
				t.Fatalf("worker resolver runtime = %q, want rootless_podman", req.Target.Runtime.Driver)
			}
			if req.Target.Runtime.WorkerID != "worker-factory-scheduled" {
				t.Fatalf("worker resolver worker ID = %q, want selected host ID", req.Target.Runtime.WorkerID)
			}
			return workerDriver, nil
		},
		persistSandboxState: func(state *sandbox.SandboxState) error {
			persistedState = state
			return nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v\noutput=%s", err, out.String())
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

	record, err := store.LoadRun("factory-scheduler-lease")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Sandbox == nil {
		t.Fatal("record.Sandbox = nil, want scheduled sandbox metadata")
	}
	if record.Sandbox.Host == nil || record.Sandbox.Host.ID != "worker-factory-scheduled" {
		t.Fatalf("record sandbox host = %#v, want selected host identity", record.Sandbox.Host)
	}
	if record.Sandbox.Runtime == nil ||
		record.Sandbox.Runtime.Driver != sandboxruntime.DriverRootlessPodman ||
		record.Sandbox.Runtime.WorkerID != "worker-factory-scheduled" {
		t.Fatalf("record sandbox runtime = %#v, want scheduled rootless worker runtime", record.Sandbox.Runtime)
	}
	if record.Sandbox.WorkerRouting == nil || record.Sandbox.WorkerRouting.SelectedWorkerHostID != "worker-factory-scheduled" {
		t.Fatalf("record worker routing = %#v, want selected worker route", record.Sandbox.WorkerRouting)
	}
	if record.Sandbox.Lease == nil {
		t.Fatal("record sandbox lease = nil, want safe scheduler lease ref")
	}
	if record.Sandbox.Lease.ID != "factory-scheduler-lease" ||
		record.Sandbox.Lease.HostID != "worker-factory-scheduled" ||
		record.Sandbox.Lease.HostName != "worker factory scheduled" ||
		record.Sandbox.Lease.RuntimeDriver != sandboxruntime.DriverRootlessPodman ||
		record.Sandbox.Lease.ResourceKey != "host:worker-factory-scheduled" ||
		record.Sandbox.Lease.Purpose != sandbox.SandboxLeasePurposeFactory ||
		record.Sandbox.Lease.RunID != "factory-scheduler-lease" ||
		!record.Sandbox.Lease.ExpiresAt.Equal(startedAt.Add(sandboxCommandLeaseTTL)) {
		t.Fatalf("record sandbox lease = %#v, want selected safe lease ref", record.Sandbox.Lease)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal(record) error: %v", err)
	}
	for _, forbidden := range []string{"unsafe-holder", "unix://", workerSafeUnixEndpoint()} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("record leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestFactorySandboxSchedulerFailureRecordsFailureBeforeRuntimeConstruction(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	startedAt := time.Date(2026, 7, 1, 8, 45, 0, 0, time.UTC)
	projectDir := t.TempDir()
	store := factory.NewStore(t.TempDir())
	var out bytes.Buffer

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:     projectDir,
		SandboxHostID:  "worker-factory-full",
		SandboxRuntime: sandboxruntime.DriverRootlessPodman,
		RemoteOutput:   &out,
		RunRecord: factory.RunRecord{
			RunID:      "factory-scheduler-blocked",
			RepoPath:   projectDir,
			RepoRemote: "git@example.com:org/repo.git",
			BranchName: "feature/factory-scheduled",
			BaseBranch: "main",
		},
		RemoteAuto: factoryRunAutoRequest{BaseBranch: "main"},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) {
			return store, nil
		},
		now: runSandboxTestClock(startedAt, startedAt.Add(time.Second), startedAt.Add(2*time.Second)),
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatal("loadSandbox should not run after scheduled factory rejection")
			return nil, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("listSandboxes should not run after scheduled factory rejection")
			return nil, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("resolveDefault should not run after scheduled factory rejection")
			return nil, "", nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			host := factorySandboxSchedulerLeaseHost("worker-factory-full", "worker factory full")
			host.Capacity.MaxConcurrentSandboxes = 1
			return []*sandbox.SandboxHost{host}, nil
		},
		listLeases: func() ([]*sandbox.SandboxLease, error) {
			return []*sandbox.SandboxLease{{
				ID:          "active-factory-lease",
				ResourceKey: "host:worker-factory-full",
				Holder:      "other-factory-run",
				Purpose:     sandbox.SandboxLeasePurposeFactory,
				AcquiredAt:  startedAt.Add(-time.Minute),
				ExpiresAt:   startedAt.Add(time.Minute),
				Status:      sandbox.SandboxLeaseStatusActive,
			}}, nil
		},
		acquireLease: func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
			t.Fatal("lease acquisition should not run after scheduler rejection")
			return nil, nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run after scheduler rejection")
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
	})
	if err == nil {
		t.Fatal("runFactorySandboxExecutorWithDeps() error = nil, want scheduler rejection")
	}
	if !strings.Contains(err.Error(), "no available cached capacity") {
		t.Fatalf("error = %q, want capacity-blocked scheduler rejection", err.Error())
	}

	record, err := store.LoadRun("factory-scheduler-blocked")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("record status = %q, want failed", record.Status)
	}
	if record.CurrentStep != "resolve_target" {
		t.Fatalf("record current step = %q, want resolve_target", record.CurrentStep)
	}
	if record.Sandbox != nil {
		t.Fatalf("record sandbox = %#v, want nil after scheduler rejection", record.Sandbox)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal(record) error: %v", err)
	}
	for _, forbidden := range []string{"unix://", workerSafeUnixEndpoint(), "other-factory-run"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("failure record leaked %q: %s", forbidden, encoded)
		}
	}
}

func factorySandboxSchedulerLeaseHost(id, name string) *sandbox.SandboxHost {
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
