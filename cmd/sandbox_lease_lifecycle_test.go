package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestScheduledSandboxCommandsReleaseAcquiredLeaseExactlyOnce(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	runErr := errors.New("remote command failed")

	tests := []struct {
		name    string
		wantErr bool
		run     func(*testing.T, error, func(string) (*sandbox.SandboxLease, error)) error
	}{
		{
			name: "run success",
			run: func(t *testing.T, execErr error, release func(string) (*sandbox.SandboxLease, error)) error {
				return runScheduledRunLeaseLifecycle(t, startedAt, execErr, release)
			},
		},
		{
			name:    "run failure",
			wantErr: true,
			run: func(t *testing.T, _ error, release func(string) (*sandbox.SandboxLease, error)) error {
				return runScheduledRunLeaseLifecycle(t, startedAt, runErr, release)
			},
		},
		{
			name: "auto success",
			run: func(t *testing.T, execErr error, release func(string) (*sandbox.SandboxLease, error)) error {
				return runScheduledAutoLeaseLifecycle(t, startedAt, execErr, release)
			},
		},
		{
			name:    "auto failure",
			wantErr: true,
			run: func(t *testing.T, _ error, release func(string) (*sandbox.SandboxLease, error)) error {
				return runScheduledAutoLeaseLifecycle(t, startedAt, runErr, release)
			},
		},
		{
			name: "factory success",
			run: func(t *testing.T, execErr error, release func(string) (*sandbox.SandboxLease, error)) error {
				return runScheduledFactoryLeaseLifecycle(t, startedAt, execErr, release)
			},
		},
		{
			name:    "factory failure",
			wantErr: true,
			run: func(t *testing.T, _ error, release func(string) (*sandbox.SandboxLease, error)) error {
				return runScheduledFactoryLeaseLifecycle(t, startedAt, runErr, release)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var released []string
			err := tt.run(t, nil, func(id string) (*sandbox.SandboxLease, error) {
				released = append(released, id)
				return &sandbox.SandboxLease{
					ID:     id,
					Status: sandbox.SandboxLeaseStatusReleased,
				}, nil
			})
			if tt.wantErr && err == nil {
				t.Fatal("command error = nil, want failure")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("command unexpected error: %v", err)
			}
			if len(released) != 1 {
				t.Fatalf("released leases = %v, want exactly one release", released)
			}
			if want := strings.ReplaceAll(tt.name, " ", "-") + "-lease"; released[0] != want {
				t.Fatalf("released lease ID = %q, want %q", released[0], want)
			}
		})
	}
}

func TestScheduledSandboxCommandCancellationReleasesLease(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 9, 10, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	var released []string

	err := runScheduledRunLeaseLifecycleWithID(t, ctx, startedAt, "run-canceled-lease", func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
		cancel()
		return nil, ctx.Err()
	}, func(id string) (*sandbox.SandboxLease, error) {
		released = append(released, id)
		return &sandbox.SandboxLease{ID: id, Status: sandbox.SandboxLeaseStatusReleased}, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("command error = %v, want context.Canceled", err)
	}
	if len(released) != 1 || released[0] != "run-canceled-lease" {
		t.Fatalf("released leases = %v, want canceled lease exactly once", released)
	}
}

func TestSandboxCommandDefaultLeaseListerExpiresStaleLeases(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())
	current := time.Date(2026, 7, 1, 9, 20, 0, 0, time.UTC)
	store := sandbox.NewSandboxLeaseStore(func() time.Time { return current })

	current = current.Add(-time.Hour)
	if _, err := store.Acquire(sandbox.SandboxLeaseAcquireRequest{
		ID:          "stale-command-lease",
		ResourceKey: "host:worker-stale",
		Holder:      "run:stale",
		Purpose:     sandbox.SandboxLeasePurposeRun,
		RunID:       "stale-command-lease",
	}, 30*time.Minute); err != nil {
		t.Fatalf("Acquire(stale) error = %v", err)
	}
	current = time.Date(2026, 7, 1, 9, 20, 0, 0, time.UTC)
	if _, err := store.Acquire(sandbox.SandboxLeaseAcquireRequest{
		ID:          "fresh-command-lease",
		ResourceKey: "host:worker-fresh",
		Holder:      "run:fresh",
		Purpose:     sandbox.SandboxLeasePurposeRun,
		RunID:       "fresh-command-lease",
	}, 30*time.Minute); err != nil {
		t.Fatalf("Acquire(fresh) error = %v", err)
	}

	leases, err := sandboxCommandDefaultLeaseLister(func() time.Time { return current }, false)()
	if err != nil {
		t.Fatalf("default lease lister error = %v", err)
	}
	if len(leases) != 2 {
		t.Fatalf("default lease lister returned %d leases, want 2", len(leases))
	}
	stale, err := store.Load("stale-command-lease")
	if err != nil {
		t.Fatalf("Load(stale) error = %v", err)
	}
	if stale.Status != sandbox.SandboxLeaseStatusExpired {
		t.Fatalf("stale lease status = %q, want expired", stale.Status)
	}
	fresh, err := store.Load("fresh-command-lease")
	if err != nil {
		t.Fatalf("Load(fresh) error = %v", err)
	}
	if fresh.Status != sandbox.SandboxLeaseStatusActive {
		t.Fatalf("fresh lease status = %q, want active", fresh.Status)
	}
}

func runScheduledRunLeaseLifecycle(t *testing.T, startedAt time.Time, execErr error, release func(string) (*sandbox.SandboxLease, error)) error {
	id := strings.ReplaceAll(t.Name()[strings.LastIndex(t.Name(), "/")+1:], "_", "-") + "-lease"
	return runScheduledRunLeaseLifecycleWithID(t, context.Background(), startedAt, id, lifecycleExecFunc(sandbox.SandboxLeasePurposeRun, execErr), release)
}

func runScheduledRunLeaseLifecycleWithID(t *testing.T, ctx context.Context, startedAt time.Time, id string, exec func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error), release func(string) (*sandbox.SandboxLease, error)) error {
	t.Helper()

	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	host := runSandboxSchedulerLeaseHost("worker-lifecycle-run", "worker lifecycle run")
	var out bytes.Buffer
	var errOut bytes.Buffer

	return runRunSandboxWithWriter(ctx, nil, nil, runSandboxOptions{
		SandboxHostID:         "worker-lifecycle-run",
		SandboxHostChanged:    true,
		SandboxRuntime:        sandboxruntime.DriverRootlessPodman,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return id
		},
		now:        runSandboxTestClock(startedAt, startedAt.Add(time.Second), startedAt.Add(2*time.Second), startedAt.Add(3*time.Second)),
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
		acquireLease: lifecycleAcquireFunc(t, id, sandbox.SandboxLeasePurposeRun, startedAt),
		releaseLease: release,
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for scheduled run lifecycle target")
			return nil, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			return lifecycleWorkerDriver(exec), nil
		},
		materializeWorkspace: func(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
			return sandboxworkspace.MaterializationResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
	})
}

func runScheduledAutoLeaseLifecycle(t *testing.T, startedAt time.Time, execErr error, release func(string) (*sandbox.SandboxLease, error)) error {
	t.Helper()

	id := strings.ReplaceAll(t.Name()[strings.LastIndex(t.Name(), "/")+1:], "_", "-") + "-lease"
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	host := autoSandboxSchedulerLeaseHost("worker-lifecycle-auto", "worker lifecycle auto")
	var out bytes.Buffer
	var errOut bytes.Buffer

	return runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		SandboxHostID:         "worker-lifecycle-auto",
		SandboxHostChanged:    true,
		SandboxRuntime:        sandboxruntime.DriverRootlessPodman,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return id
		},
		now: runSandboxTestClock(startedAt, startedAt.Add(time.Second), startedAt.Add(2*time.Second), startedAt.Add(3*time.Second)),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return workerRootlessBundlePlan(projectDir), nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{host}, nil
		},
		listLeases: func() ([]*sandbox.SandboxLease, error) {
			return nil, nil
		},
		acquireLease: lifecycleAcquireFunc(t, id, sandbox.SandboxLeasePurposeAuto, startedAt),
		releaseLease: release,
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for scheduled auto lifecycle target")
			return nil, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			return lifecycleWorkerDriver(lifecycleExecFunc(sandbox.SandboxLeasePurposeAuto, execErr)), nil
		},
		materializeWorkspace: func(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
			return sandboxworkspace.MaterializationResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
	})
}

func runScheduledFactoryLeaseLifecycle(t *testing.T, startedAt time.Time, execErr error, release func(string) (*sandbox.SandboxLease, error)) error {
	t.Helper()
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	id := strings.ReplaceAll(t.Name()[strings.LastIndex(t.Name(), "/")+1:], "_", "-") + "-lease"
	projectDir := t.TempDir()
	store := factory.NewStore(t.TempDir())
	host := factorySandboxSchedulerLeaseHost("worker-lifecycle-factory", "worker lifecycle factory")
	var out bytes.Buffer

	return runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:     projectDir,
		SandboxHostID:  "worker-lifecycle-factory",
		SandboxRuntime: sandboxruntime.DriverRootlessPodman,
		RemoteOutput:   &out,
		RunRecord: factory.RunRecord{
			RunID:      id,
			RepoPath:   projectDir,
			RepoRemote: "git@example.com:org/repo.git",
			BranchName: "feature/factory-lifecycle",
			BaseBranch: "main",
		},
		RemoteAuto: factoryRunAutoRequest{BaseBranch: "main"},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) {
			return store, nil
		},
		now: runSandboxTestClock(startedAt, startedAt.Add(time.Second), startedAt.Add(2*time.Second), startedAt.Add(3*time.Second)),
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatal("loadSandbox should not run for scheduled factory lifecycle target")
			return nil, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("listSandboxes should not run for scheduled factory lifecycle target")
			return nil, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("resolveDefault should not run for scheduled factory lifecycle target")
			return nil, "", nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{host}, nil
		},
		listLeases: func() ([]*sandbox.SandboxLease, error) {
			return nil, nil
		},
		acquireLease: lifecycleAcquireFunc(t, id, sandbox.SandboxLeasePurposeFactory, startedAt),
		releaseLease: release,
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run for scheduled factory lifecycle target")
			return nil, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for scheduled factory lifecycle target")
			return nil, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			return lifecycleWorkerDriver(lifecycleExecFunc(sandbox.SandboxLeasePurposeFactory, execErr)), nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
	})
}

func lifecycleAcquireFunc(t *testing.T, id, purpose string, acquiredAt time.Time) func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
	t.Helper()
	return func(req sandbox.SandboxLeaseAcquireRequest, ttl time.Duration) (*sandbox.SandboxLease, error) {
		if req.ID != id {
			t.Fatalf("lease ID = %q, want %q", req.ID, id)
		}
		if req.Purpose != purpose || req.RunID != id {
			t.Fatalf("lease purpose/run = %q/%q, want %q/%q", req.Purpose, req.RunID, purpose, id)
		}
		if !strings.HasPrefix(req.ResourceKey, "host:") {
			t.Fatalf("lease resource key = %q, want host resource", req.ResourceKey)
		}
		return &sandbox.SandboxLease{
			ID:          req.ID,
			SandboxName: req.SandboxName,
			ResourceKey: req.ResourceKey,
			Holder:      req.Holder,
			Purpose:     req.Purpose,
			RunID:       req.RunID,
			AcquiredAt:  acquiredAt,
			ExpiresAt:   acquiredAt.Add(ttl),
			HeartbeatAt: acquiredAt,
			Status:      sandbox.SandboxLeaseStatusActive,
		}, nil
	}
}

func lifecycleWorkerDriver(exec func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error)) sandboxruntime.Driver {
	return fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		start: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
			target := req.Target
			target.Status = sandbox.StatusRunning
			target.Runtime.RuntimeID = "runtime-lifecycle"
			return &target, nil
		},
		exec: exec,
	}
}

func lifecycleExecFunc(purpose string, err error) func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	return func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
		if err != nil {
			return nil, err
		}
		switch purpose {
		case sandbox.SandboxLeasePurposeAuto:
			_, _ = io.WriteString(req.Stdout, autoSandboxRemoteSuccessJSON("lease lifecycle")+"\n")
		default:
			_, _ = fmt.Fprintln(req.Stdout, "lease lifecycle")
		}
		return &sandboxruntime.ExecResult{}, nil
	}
}
