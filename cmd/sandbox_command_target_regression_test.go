package cmd

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestRunSandboxDefaultTargetResolutionStaysCachedAndFakeOnly(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	target := &sandbox.SandboxState{
		Name:     "run-default-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Host:     defaultRegressionWorkerHostWithoutEndpoint(),
	}
	resolver := &fakeDefaultSandboxResolver{t: t, target: target}
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Name != "run-default-box" {
				t.Fatalf("Exec target name = %q, want run-default-box", req.Target.Name)
			}
			_, _ = io.WriteString(req.Stdout, "run default path\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

	var resolvedRuntime sandboxruntime.Target
	var out bytes.Buffer
	result, err := (runSandboxDeps{
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatal("loadSandbox should not run without an explicit sandbox name")
			return nil, nil
		},
		resolveDefault: resolver.resolve,
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			t.Fatal("listHosts should not run without sandbox host/runtime constraints")
			return nil, nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run when a default running sandbox is selected")
			return nil, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			resolvedRuntime = target
			return driver, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
	}).executeRunSandbox(context.Background(), defaultRunSandboxRegressionRequest(t), &out, io.Discard, runSandboxExecutionHooks{})
	if err != nil {
		t.Fatalf("executeRunSandbox() unexpected error: %v", err)
	}
	if resolver.calls != 1 {
		t.Fatalf("default resolver calls = %d, want 1", resolver.calls)
	}
	if result.Result == nil || result.Result.Target.Name != "run-default-box" {
		t.Fatalf("result target = %#v, want run-default-box", result.Result)
	}
	if resolvedRuntime.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("runtime driver = %q, want SSH-machine compatibility", resolvedRuntime.Runtime.Driver)
	}
	if resolvedRuntime.Runtime.WorkerID != "" || resolvedRuntime.Runtime.RuntimeID != "" {
		t.Fatalf("runtime worker metadata = %#v, want empty metadata on unconstrained default path", resolvedRuntime.Runtime)
	}
	if !strings.Contains(out.String(), "run default path") {
		t.Fatalf("stdout = %q, want fake runtime output", out.String())
	}
}

func TestAutoSandboxDefaultTargetResolutionStaysCachedAndFakeOnly(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	projectDir := t.TempDir()
	target := &sandbox.SandboxState{
		Name:     "auto-default-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Host:     defaultRegressionWorkerHostWithoutEndpoint(),
	}
	resolver := &fakeDefaultSandboxResolver{t: t, target: target}
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Name != "auto-default-box" {
				t.Fatalf("Exec target name = %q, want auto-default-box", req.Target.Name)
			}
			_, _ = io.WriteString(req.Stdout, autoSandboxRemoteSuccessJSON("auto default path")+"\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

	var resolvedRuntime sandboxruntime.Target
	var out bytes.Buffer
	result, err := (autoSandboxDeps{
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return autoSandboxTestPlan(projectDir), nil
		},
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatal("loadSandbox should not run without an explicit sandbox name")
			return nil, nil
		},
		resolveDefault: resolver.resolve,
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			t.Fatal("listHosts should not run without sandbox host/runtime constraints")
			return nil, nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run when a default running sandbox is selected")
			return nil, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			resolvedRuntime = target
			return driver, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
	}).executeAutoSandbox(context.Background(), defaultAutoSandboxRegressionRequest(t, projectDir), &out, io.Discard, autoSandboxExecutionHooks{})
	if err != nil {
		t.Fatalf("executeAutoSandbox() unexpected error: %v", err)
	}
	if resolver.calls != 1 {
		t.Fatalf("default resolver calls = %d, want 1", resolver.calls)
	}
	if result.Result == nil || result.Result.Target.Name != "auto-default-box" {
		t.Fatalf("result target = %#v, want auto-default-box", result.Result)
	}
	if resolvedRuntime.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("runtime driver = %q, want SSH-machine compatibility", resolvedRuntime.Runtime.Driver)
	}
	if resolvedRuntime.Runtime.WorkerID != "" || resolvedRuntime.Runtime.RuntimeID != "" {
		t.Fatalf("runtime worker metadata = %#v, want empty metadata on unconstrained default path", resolvedRuntime.Runtime)
	}
	if !strings.Contains(out.String(), "auto default path") {
		t.Fatalf("stdout = %q, want fake runtime output", out.String())
	}
}

func TestFactorySandboxDefaultTargetResolutionStaysCachedAndFakeOnly(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	target := &sandbox.SandboxState{
		Name:     "factory-default-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Host:     defaultRegressionWorkerHostWithoutEndpoint(),
	}
	resolver := &fakeDefaultSandboxResolver{t: t, target: target}
	now := runSandboxTestClock(
		time.Date(2026, 7, 1, 6, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 1, 6, 0, 1, 0, time.UTC),
	)

	var resolvedRuntime sandboxruntime.Target
	var savedRecords []factory.RunRecord
	var out bytes.Buffer
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:   t.TempDir(),
		RemoteOutput: &out,
		RunRecord: factory.RunRecord{
			RunID:      "factory-default-regression",
			RepoRemote: "git@example.com:org/repo.git",
			BranchName: "feature/factory-default",
			BaseBranch: "main",
		},
		RemoteAuto: factoryRunAutoRequest{BaseBranch: "main"},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) {
			return factory.NewStore(t.TempDir()), nil
		},
		now: now,
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatal("loadSandbox should not run without an explicit sandbox name")
			return nil, nil
		},
		resolveDefault: resolver.resolve,
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			t.Fatal("listHosts should not run without sandbox host/runtime constraints")
			return nil, nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run when a default running sandbox is selected")
			return nil, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			resolvedRuntime = target
			return fakeFactorySandboxRuntimeDriver{
				execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					if req.Target.Name != "factory-default-box" {
						t.Fatalf("Exec target name = %q, want factory-default-box", req.Target.Name)
					}
					_, _ = io.WriteString(req.Stdout, "factory default path\n")
					return &sandboxruntime.ExecResult{}, nil
				},
			}, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
		cleanupSandbox: func(context.Context, factorySandboxCleanupRequest) error {
			return nil
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			savedRecords = append(savedRecords, *record)
			return nil
		},
		appendEvent: func(factory.Store, *factory.EventRecord) error {
			return nil
		},
		appendLog: func(factory.Store, *factory.LogChunk) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if resolver.calls != 1 {
		t.Fatalf("default resolver calls = %d, want 1", resolver.calls)
	}
	if resolvedRuntime.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("runtime driver = %q, want SSH-machine compatibility", resolvedRuntime.Runtime.Driver)
	}
	if resolvedRuntime.Runtime.WorkerID != "" || resolvedRuntime.Runtime.RuntimeID != "" {
		t.Fatalf("runtime worker metadata = %#v, want empty metadata on unconstrained default path", resolvedRuntime.Runtime)
	}
	if len(savedRecords) < 2 || savedRecords[1].SandboxName != "factory-default-box" {
		t.Fatalf("saved records = %#v, want selected factory-default-box metadata", savedRecords)
	}
	if !strings.Contains(out.String(), "factory default path") {
		t.Fatalf("remote output = %q, want fake runtime output", out.String())
	}
}

type fakeDefaultSandboxResolver struct {
	t      *testing.T
	target *sandbox.SandboxState
	calls  int
}

func (r *fakeDefaultSandboxResolver) resolve(filter func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
	r.t.Helper()
	r.calls++
	if filter == nil {
		r.t.Fatal("default resolver received nil running-sandbox filter")
	}
	if !filter(r.target) {
		r.t.Fatalf("running-sandbox filter rejected target %#v", r.target)
	}
	stopped := *r.target
	stopped.Status = sandbox.StatusStopped
	if filter(&stopped) {
		r.t.Fatalf("running-sandbox filter accepted stopped target %#v", stopped)
	}
	return r.target, r.target.Name, nil
}

func defaultRegressionWorkerHostWithoutEndpoint() *sandbox.SandboxHost {
	return &sandbox.SandboxHost{
		ID:   "cached-worker-without-endpoint",
		Name: "cached-worker-without-endpoint",
		Kind: sandbox.SandboxHostKindWorker,
		SupportedRuntimes: []string{
			sandboxruntime.DriverRootlessPodman,
		},
	}
}

func defaultRunSandboxRegressionRequest(t *testing.T) runSandboxRequest {
	t.Helper()
	projectDir := t.TempDir()
	return runSandboxRequest{
		ProjectDir:    projectDir,
		RepoRemote:    "git@example.com:org/repo.git",
		BaseBranch:    "main",
		RunBranch:     "feature/run-default",
		WorkDir:       "/root/workspace/repo",
		RemoteCommand: []string{"hal", "run", "--json"},
		Workspace: &sandbox.SandboxWorkspace{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
			Repo:        "git@example.com:org/repo.git",
			Branch:      "feature/run-default",
			SyncRef:     "refs/remotes/origin/feature/run-default",
		},
		Security: runSandboxSecurityRequest(),
	}
}

func defaultAutoSandboxRegressionRequest(t *testing.T, projectDir string) autoSandboxRequest {
	t.Helper()
	return autoSandboxRequest{
		ProjectDir:    projectDir,
		RepoRemote:    "git@example.com:org/repo.git",
		BaseBranch:    "main",
		RunBranch:     "feature/auto-sandbox",
		WorkDir:       "/root/workspace/repo",
		RemoteCommand: []string{"hal", "auto", "--json"},
		Workspace: &sandbox.SandboxWorkspace{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
			Repo:        "git@example.com:org/repo.git",
			Branch:      "feature/auto-sandbox",
			SyncRef:     "refs/remotes/origin/feature/auto-sandbox",
		},
		WorkspacePlan: &sandboxworkspace.Plan{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
			ProjectDir:  projectDir,
			Repository:  "git@example.com:org/repo.git",
			Branch:      "feature/auto-sandbox",
			SyncRef:     "refs/remotes/origin/feature/auto-sandbox",
		},
		Security: runSandboxSecurityRequest(),
	}
}
