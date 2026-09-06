package cmd

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestRunSandboxLegacyDefaultResolutionDoesNotUseSchedulerOrLeaseMetadata(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	target := schedulerLegacyLeasedWorkerTarget("run-default-scheduler-compat", sandbox.SandboxLeasePurposeRun)
	resolver := &fakeDefaultSandboxResolver{t: t, target: target}

	resolved, err := (runSandboxDeps{
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatal("loadSandbox should not run without an explicit sandbox name")
			return nil, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("listSandboxes should not run for default sandbox resolution when resolveDefault is available")
			return nil, nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			t.Fatal("listHosts should not run without sandbox host/runtime constraints")
			return nil, nil
		},
		resolveDefault: resolver.resolve,
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run when a default running sandbox is selected")
			return nil, nil
		},
	}).resolveRunSandboxTarget(context.Background(), defaultRunSandboxRegressionRequest(t), io.Discard)
	if err != nil {
		t.Fatalf("resolveRunSandboxTarget() unexpected error: %v", err)
	}

	requireSchedulerLegacyDefaultTarget(t, resolved, target.Name)
	if resolver.calls != 1 {
		t.Fatalf("default resolver calls = %d, want 1", resolver.calls)
	}
}

func TestAutoSandboxLegacyDefaultResolutionDoesNotUseSchedulerOrLeaseMetadata(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	projectDir := t.TempDir()
	target := schedulerLegacyLeasedWorkerTarget("auto-default-scheduler-compat", sandbox.SandboxLeasePurposeAuto)
	resolver := &fakeDefaultSandboxResolver{t: t, target: target}

	resolved, err := (autoSandboxDeps{
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatal("loadSandbox should not run without an explicit sandbox name")
			return nil, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("listSandboxes should not run for default sandbox resolution when resolveDefault is available")
			return nil, nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			t.Fatal("listHosts should not run without sandbox host/runtime constraints")
			return nil, nil
		},
		resolveDefault: resolver.resolve,
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run when a default running sandbox is selected")
			return nil, nil
		},
	}).resolveAutoSandboxTarget(context.Background(), defaultAutoSandboxRegressionRequest(t, projectDir), io.Discard)
	if err != nil {
		t.Fatalf("resolveAutoSandboxTarget() unexpected error: %v", err)
	}

	requireSchedulerLegacyDefaultTarget(t, resolved, target.Name)
	if resolver.calls != 1 {
		t.Fatalf("default resolver calls = %d, want 1", resolver.calls)
	}
}

func TestFactorySandboxLegacyDefaultResolutionDoesNotUseSchedulerOrLeaseMetadata(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	target := schedulerLegacyLeasedWorkerTarget("factory-default-scheduler-compat", sandbox.SandboxLeasePurposeFactory)
	resolver := &fakeDefaultSandboxResolver{t: t, target: target}
	record := factory.RunRecord{
		RunID:      "factory-default-scheduler-compat",
		RepoRemote: "git@example.com:org/repo.git",
		BranchName: "feature/factory-default-scheduler-compat",
		BaseBranch: "main",
	}

	resolved, err := resolveFactorySandboxTarget(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:   t.TempDir(),
		RemoteOutput: io.Discard,
		RunRecord:    record,
		RemoteAuto:   factoryRunAutoRequest{BaseBranch: "main"},
	}, &record, record.RepoRemote, factorySandboxExecutorDeps{
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatal("loadSandbox should not run without an explicit sandbox name")
			return nil, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("listSandboxes should not run for default sandbox resolution when resolveDefault is available")
			return nil, nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			t.Fatal("listHosts should not run without sandbox host/runtime constraints")
			return nil, nil
		},
		resolveDefault: resolver.resolve,
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run when a default running sandbox is selected")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("resolveFactorySandboxTarget() unexpected error: %v", err)
	}

	requireSchedulerLegacyDefaultTarget(t, resolved, target.Name)
	if record.Sandbox == nil {
		t.Fatal("record.Sandbox = nil, want default sandbox metadata")
	}
	if record.Sandbox.Lease != nil {
		t.Fatalf("record.Sandbox.Lease = %#v, want nil without scheduler intent", record.Sandbox.Lease)
	}
	if record.Sandbox.WorkerRouting != nil {
		t.Fatalf("record.Sandbox.WorkerRouting = %#v, want nil without explicit worker target flags", record.Sandbox.WorkerRouting)
	}
	if resolver.calls != 1 {
		t.Fatalf("default resolver calls = %d, want 1", resolver.calls)
	}
}

func schedulerLegacyLeasedWorkerTarget(name, purpose string) *sandbox.SandboxState {
	acquiredAt := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	return &sandbox.SandboxState{
		Name:     name,
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Host:     defaultRegressionWorkerHostWithoutEndpoint(),
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			RuntimeID:      "runtime-stale-lease",
			Image:          "localhost/hal:stale-lease",
			WorkerID:       "cached-worker-without-endpoint",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
		Lease: &sandbox.SandboxLeaseRef{
			ID:            "lease-stale-default",
			HostID:        "cached-worker-without-endpoint",
			HostName:      "cached worker",
			RuntimeDriver: sandboxruntime.DriverRootlessPodman,
			ResourceKey:   "host:cached-worker-without-endpoint",
			Holder:        "unsafe-holder",
			Purpose:       purpose,
			RunID:         "previous-explicit-run",
			AcquiredAt:    acquiredAt,
			ExpiresAt:     acquiredAt.Add(30 * time.Minute),
		},
	}
}

func requireSchedulerLegacyDefaultTarget(t *testing.T, target *sandbox.SandboxState, wantName string) {
	t.Helper()
	if target == nil {
		t.Fatal("target = nil")
	}
	if target.Name != wantName {
		t.Fatalf("target.Name = %q, want %q", target.Name, wantName)
	}
	if target.Lease != nil {
		t.Fatalf("target.Lease = %#v, want nil without scheduler intent", target.Lease)
	}
	if target.Runtime == nil || target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("target.Runtime = %#v, want SSH-machine compatibility", target.Runtime)
	}
	if target.Runtime.WorkerID != "" || target.Runtime.RuntimeID != "" || target.Runtime.Image != "" {
		t.Fatalf("target runtime metadata = %#v, want worker metadata stripped", target.Runtime)
	}
	if target.Host == nil || target.Host.ID != "cached-worker-without-endpoint" || target.Host.Endpoint != "" {
		t.Fatalf("target.Host = %#v, want cached worker identity without endpoint", target.Host)
	}
}
