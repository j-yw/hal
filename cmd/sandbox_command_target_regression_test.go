package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
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

func TestWorkerMicroVMRunSandboxJSONFailsWithRuntimeUnsupportedClassification(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 7, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		JSON:                  true,
		JSONChanged:           true,
		SandboxHostID:         "worker-1",
		SandboxHostChanged:    true,
		SandboxRuntime:        sandboxruntime.DriverMicroVM,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-worker-microvm-unsupported"
		},
		now:        runSandboxTestClock(startedAt, finishedAt),
		workingDir: func() (string, error) { return projectDir, nil },
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return workerUnsupportedRuntimePlan(projectDir), nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{workerMicroVMHostWithUnsafeEndpoint()}, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("listSandboxes should not run for explicit worker host/runtime selection")
			return nil, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("default sandbox fallback should not run for explicit worker microvm selection")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run for unsupported worker microvm selection")
			return nil, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("runtime driver should not be constructed for unsupported worker microvm selection")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() error = %v, want JSON error result", err)
	}
	var result RunResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	requireWorkerMicroVMUnsupportedMessage(t, result.Error)
	requireWorkerMicroVMNoUnsafeDetails(t, out.String(), errOut.String())
	if result.OK {
		t.Fatalf("RunResult.OK = true, want false")
	}
	manifest, loadErr := store.LoadManifest("run-worker-microvm-unsupported")
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("manifest.Status = %q, want failed", manifest.Status)
	}
}

func TestWorkerMicroVMAutoSandboxJSONFailsWithRuntimeUnsupportedClassification(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 7, 5, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		JSON:                  true,
		JSONChanged:           true,
		SandboxHostID:         "worker-1",
		SandboxHostChanged:    true,
		SandboxRuntime:        sandboxruntime.DriverMicroVM,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-worker-microvm-unsupported"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return workerUnsupportedRuntimePlan(projectDir), nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{workerMicroVMHostWithUnsafeEndpoint()}, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("listSandboxes should not run for explicit worker host/runtime selection")
			return nil, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("default sandbox fallback should not run for explicit worker microvm selection")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run for unsupported worker microvm selection")
			return nil, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("runtime driver should not be constructed for unsupported worker microvm selection")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() error = %v, want JSON error result", err)
	}
	var result AutoResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	requireWorkerMicroVMUnsupportedMessage(t, result.Error)
	requireWorkerMicroVMNoUnsafeDetails(t, out.String(), errOut.String())
	if result.OK {
		t.Fatalf("AutoResult.OK = true, want false")
	}
	manifest, loadErr := store.LoadManifest("auto-worker-microvm-unsupported")
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("manifest.Status = %q, want failed", manifest.Status)
	}
}

func TestWorkerMicroVMFactorySandboxJSONFailsWithRuntimeUnsupportedClassification(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, ".hal"), 0o755); err != nil {
		t.Fatalf("MkdirAll(.hal) error: %v", err)
	}
	writeFile(t, projectDir, ".hal/prd-feature.md", "# PRD: worker microvm\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 7, 1, 7, 10, 0, 0, time.UTC)
	startedAt := createdAt.Add(time.Second)
	failedAt := startedAt.Add(time.Second)
	times := []time.Time{createdAt, startedAt, failedAt, failedAt, failedAt}
	now := func() time.Time {
		if len(times) == 0 {
			return failedAt
		}
		next := times[0]
		times = times[1:]
		return next
	}
	var out bytes.Buffer

	err := runFactoryRunWithDeps(context.Background(), projectDir, factoryRunRequest{
		MarkdownPath:    ".hal/prd-feature.md",
		BaseBranch:      "main",
		Sandbox:         true,
		SandboxHostID:   "worker-1",
		SandboxRuntime:  sandboxruntime.DriverMicroVM,
		JSON:            true,
		ResolvedSecrets: nil,
	}, &out, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-worker-microvm-unsupported", nil },
		now:          now,
		workingDir:   func() (string, error) { return projectDir, nil },
		currentBranch: func(string) (string, error) {
			return "feature/worker-microvm", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@example.com:org/repo.git", nil
		},
		runSandbox: func(ctx context.Context, req factorySandboxExecutorRequest) error {
			return runFactorySandboxExecutorWithDeps(ctx, req, factorySandboxExecutorDeps{
				defaultStore: func() (factory.Store, error) { return store, nil },
				now:          now,
				listHosts: func() ([]*sandbox.SandboxHost, error) {
					return []*sandbox.SandboxHost{workerMicroVMHostWithUnsafeEndpoint()}, nil
				},
				listSandboxes: func() ([]*sandbox.SandboxState, error) {
					t.Fatal("listSandboxes should not run for explicit worker host/runtime selection")
					return nil, nil
				},
				resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
					t.Fatal("default sandbox fallback should not run for explicit worker microvm selection")
					return nil, "", nil
				},
				provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
					t.Fatal("provision should not run for unsupported worker microvm selection")
					return nil, nil
				},
				resolveProvider: func(string) (sandbox.Provider, error) {
					t.Fatal("provider resolution should not run for unsupported worker microvm selection")
					return nil, nil
				},
				resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
					t.Fatal("runtime driver should not be constructed for unsupported worker microvm selection")
					return nil, nil
				},
			})
		},
	})
	if err == nil {
		t.Fatal("runFactoryRunWithDeps() error = nil, want unsupported worker runtime error")
	}
	requireWorkerMicroVMUnsupportedMessage(t, err.Error())
	var resp FactoryRunResponse
	decodeExactlyOneJSONDocument(t, out.Bytes(), &resp)
	if resp.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want failed", resp.Status)
	}
	if resp.Failure == nil {
		t.Fatal("failure should be emitted")
	}
	requireWorkerMicroVMUnsupportedMessage(t, resp.Failure.ErrorMessage)
	requireWorkerMicroVMNoUnsafeDetails(t, out.String())
}

func TestWorkerRootlessRunSandboxJSONMissingEndpointFailsBeforeProvisioning(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 7, 20, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		JSON:                  true,
		JSONChanged:           true,
		SandboxHostID:         "worker-1",
		SandboxHostChanged:    true,
		SandboxRuntime:        sandboxruntime.DriverRootlessPodman,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-worker-rootless-missing-endpoint"
		},
		now:        runSandboxTestClock(startedAt, finishedAt),
		workingDir: func() (string, error) { return projectDir, nil },
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return workerRootlessPlan(projectDir), nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{workerRootlessHostWithEndpoint("")}, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("listSandboxes should not run for explicit worker host/runtime endpoint validation")
			return nil, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("default sandbox fallback should not run for explicit worker host/runtime endpoint validation")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run for missing worker endpoint metadata")
			return nil, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("runtime driver should not be constructed for missing worker endpoint metadata")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() error = %v, want JSON error result", err)
	}
	var result RunResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	requireWorkerEndpointInvalidMessage(t, result.Error, "configured endpoint: none")
	requireWorkerEndpointNoUnsafeDetails(t, out.String(), errOut.String())
	if result.OK {
		t.Fatalf("RunResult.OK = true, want false")
	}
	manifest, loadErr := store.LoadManifest("run-worker-rootless-missing-endpoint")
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("manifest.Status = %q, want failed", manifest.Status)
	}
}

func TestWorkerRootlessAutoSandboxJSONNonLocalEndpointFailsSafely(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 7, 25, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		JSON:                  true,
		JSONChanged:           true,
		SandboxHostID:         "worker-1",
		SandboxHostChanged:    true,
		SandboxRuntime:        sandboxruntime.DriverRootlessPodman,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-worker-rootless-invalid-endpoint"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return workerRootlessPlan(projectDir), nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{workerRootlessHostWithEndpoint(workerUnsafeRemoteEndpoint())}, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("listSandboxes should not run for explicit worker host/runtime endpoint validation")
			return nil, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("default sandbox fallback should not run for explicit worker host/runtime endpoint validation")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run for invalid worker endpoint metadata")
			return nil, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("runtime driver should not be constructed for invalid worker endpoint metadata")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() error = %v, want JSON error result", err)
	}
	var result AutoResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	requireWorkerEndpointInvalidMessage(t, result.Error, "configured endpoint: ssh endpoint")
	requireWorkerEndpointNoUnsafeDetails(t, out.String(), errOut.String())
	if result.OK {
		t.Fatalf("AutoResult.OK = true, want false")
	}
	manifest, loadErr := store.LoadManifest("auto-worker-rootless-invalid-endpoint")
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("manifest.Status = %q, want failed", manifest.Status)
	}
}

func TestWorkerRootlessFactorySandboxJSONNonLocalEndpointFailsSafely(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, ".hal"), 0o755); err != nil {
		t.Fatalf("MkdirAll(.hal) error: %v", err)
	}
	writeFile(t, projectDir, ".hal/prd-feature.md", "# PRD: worker rootless\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 7, 1, 7, 30, 0, 0, time.UTC)
	startedAt := createdAt.Add(time.Second)
	failedAt := startedAt.Add(time.Second)
	times := []time.Time{createdAt, startedAt, failedAt, failedAt, failedAt}
	now := func() time.Time {
		if len(times) == 0 {
			return failedAt
		}
		next := times[0]
		times = times[1:]
		return next
	}
	var out bytes.Buffer

	err := runFactoryRunWithDeps(context.Background(), projectDir, factoryRunRequest{
		MarkdownPath:    ".hal/prd-feature.md",
		BaseBranch:      "main",
		Sandbox:         true,
		SandboxHostID:   "worker-1",
		SandboxRuntime:  sandboxruntime.DriverRootlessPodman,
		JSON:            true,
		ResolvedSecrets: nil,
	}, &out, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-worker-rootless-invalid-endpoint", nil },
		now:          now,
		workingDir:   func() (string, error) { return projectDir, nil },
		currentBranch: func(string) (string, error) {
			return "feature/worker-rootless", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@example.com:org/repo.git", nil
		},
		runSandbox: func(ctx context.Context, req factorySandboxExecutorRequest) error {
			return runFactorySandboxExecutorWithDeps(ctx, req, factorySandboxExecutorDeps{
				defaultStore: func() (factory.Store, error) { return store, nil },
				now:          now,
				listHosts: func() ([]*sandbox.SandboxHost, error) {
					return []*sandbox.SandboxHost{workerRootlessHostWithEndpoint(workerUnsafeRemoteEndpoint())}, nil
				},
				listSandboxes: func() ([]*sandbox.SandboxState, error) {
					t.Fatal("listSandboxes should not run for explicit worker host/runtime endpoint validation")
					return nil, nil
				},
				resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
					t.Fatal("default sandbox fallback should not run for explicit worker host/runtime endpoint validation")
					return nil, "", nil
				},
				provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
					t.Fatal("provision should not run for invalid worker endpoint metadata")
					return nil, nil
				},
				resolveProvider: func(string) (sandbox.Provider, error) {
					t.Fatal("provider resolution should not run for invalid worker endpoint metadata")
					return nil, nil
				},
				resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
					t.Fatal("runtime driver should not be constructed for invalid worker endpoint metadata")
					return nil, nil
				},
			})
		},
	})
	if err == nil {
		t.Fatal("runFactoryRunWithDeps() error = nil, want invalid worker endpoint error")
	}
	requireWorkerEndpointInvalidMessage(t, err.Error(), "configured endpoint: ssh endpoint")
	var resp FactoryRunResponse
	decodeExactlyOneJSONDocument(t, out.Bytes(), &resp)
	if resp.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want failed", resp.Status)
	}
	if resp.Failure == nil {
		t.Fatal("failure should be emitted")
	}
	requireWorkerEndpointInvalidMessage(t, resp.Failure.ErrorMessage, "configured endpoint: ssh endpoint")
	requireWorkerEndpointNoUnsafeDetails(t, out.String())
}

func TestWorkerClientRunSandboxJSONFailureIsSanitized(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 7, 35, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		JSON:                  true,
		JSONChanged:           true,
		SandboxName:           "worker-rootless",
		SandboxNameChanged:    true,
		SandboxHostID:         "worker-1",
		SandboxHostChanged:    true,
		SandboxRuntime:        sandboxruntime.DriverRootlessPodman,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-worker-client-sanitized"
		},
		now:        runSandboxTestClock(startedAt, finishedAt),
		workingDir: func() (string, error) { return projectDir, nil },
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return workerRootlessPlan(projectDir), nil
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			return workerRootlessCachedSandbox(name), nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{workerRootlessHostWithEndpoint(workerSafeUnixEndpoint())}, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("listSandboxes should not run for explicit cached worker sandbox")
			return nil, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("default sandbox fallback should not run for explicit cached worker sandbox")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run for explicit cached worker sandbox")
			return nil, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return nil, unsafeWorkerClientConnectionFailure()
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() error = %v, want JSON error result", err)
	}
	var result RunResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	requireWorkerClientFailureMessage(t, result.Error)
	requireWorkerClientErrorNoUnsafeDetails(t, out.String(), errOut.String())
	if result.OK {
		t.Fatalf("RunResult.OK = true, want false")
	}
	manifest, loadErr := store.LoadManifest("run-worker-client-sanitized")
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("manifest.Status = %q, want failed", manifest.Status)
	}
}

func TestWorkerClientAutoSandboxJSONProtocolFailureIsSanitized(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 7, 40, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		JSON:                  true,
		JSONChanged:           true,
		SandboxName:           "worker-rootless",
		SandboxNameChanged:    true,
		SandboxHostID:         "worker-1",
		SandboxHostChanged:    true,
		SandboxRuntime:        sandboxruntime.DriverRootlessPodman,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-worker-client-sanitized"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return workerRootlessPlan(projectDir), nil
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			return workerRootlessCachedSandbox(name), nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{workerRootlessHostWithEndpoint(workerSafeUnixEndpoint())}, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("listSandboxes should not run for explicit cached worker sandbox")
			return nil, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("default sandbox fallback should not run for explicit cached worker sandbox")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run for explicit cached worker sandbox")
			return nil, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return nil, unsafeWorkerClientProtocolFailure()
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() error = %v, want JSON error result", err)
	}
	var result AutoResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	requireWorkerClientFailureMessage(t, result.Error)
	requireWorkerClientErrorNoUnsafeDetails(t, out.String(), errOut.String())
	if result.OK {
		t.Fatalf("AutoResult.OK = true, want false")
	}
	manifest, loadErr := store.LoadManifest("auto-worker-client-sanitized")
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("manifest.Status = %q, want failed", manifest.Status)
	}
}

func TestWorkerClientFactorySandboxJSONFailureIsSanitized(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projectDir, ".hal"), 0o755); err != nil {
		t.Fatalf("MkdirAll(.hal) error: %v", err)
	}
	writeFile(t, projectDir, ".hal/prd-feature.md", "# PRD: worker client failure\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 7, 1, 7, 45, 0, 0, time.UTC)
	startedAt := createdAt.Add(time.Second)
	failedAt := startedAt.Add(time.Second)
	times := []time.Time{createdAt, startedAt, failedAt, failedAt, failedAt}
	now := func() time.Time {
		if len(times) == 0 {
			return failedAt
		}
		next := times[0]
		times = times[1:]
		return next
	}
	var out bytes.Buffer

	err := runFactoryRunWithDeps(context.Background(), projectDir, factoryRunRequest{
		MarkdownPath:    ".hal/prd-feature.md",
		BaseBranch:      "main",
		Sandbox:         true,
		SandboxHostID:   "worker-1",
		SandboxRuntime:  sandboxruntime.DriverRootlessPodman,
		JSON:            true,
		ResolvedSecrets: nil,
	}, &out, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-worker-client-sanitized", nil },
		now:          now,
		workingDir:   func() (string, error) { return projectDir, nil },
		currentBranch: func(string) (string, error) {
			return "feature/worker-client", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@example.com:org/repo.git", nil
		},
		runSandbox: func(ctx context.Context, req factorySandboxExecutorRequest) error {
			req.SandboxName = "worker-rootless"
			return runFactorySandboxExecutorWithDeps(ctx, req, factorySandboxExecutorDeps{
				defaultStore: func() (factory.Store, error) { return store, nil },
				now:          now,
				loadSandbox: func(name string) (*sandbox.SandboxState, error) {
					return workerRootlessCachedSandbox(name), nil
				},
				listHosts: func() ([]*sandbox.SandboxHost, error) {
					return []*sandbox.SandboxHost{workerRootlessHostWithEndpoint(workerSafeUnixEndpoint())}, nil
				},
				listSandboxes: func() ([]*sandbox.SandboxState, error) {
					t.Fatal("listSandboxes should not run for explicit cached worker sandbox")
					return nil, nil
				},
				resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
					t.Fatal("default sandbox fallback should not run for explicit cached worker sandbox")
					return nil, "", nil
				},
				provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
					t.Fatal("provision should not run for explicit cached worker sandbox")
					return nil, nil
				},
				resolveProvider: func(string) (sandbox.Provider, error) {
					t.Fatal("provider resolution should not run after worker client resolve failure")
					return nil, nil
				},
				resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
					return nil, unsafeWorkerClientConnectionFailure()
				},
			})
		},
	})
	if err == nil {
		t.Fatal("runFactoryRunWithDeps() error = nil, want worker client failure")
	}
	requireWorkerClientFailureMessage(t, err.Error())
	var resp FactoryRunResponse
	decodeExactlyOneJSONDocument(t, out.Bytes(), &resp)
	if resp.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want failed", resp.Status)
	}
	if resp.Failure == nil {
		t.Fatal("failure should be emitted")
	}
	if strings.TrimSpace(resp.Failure.ErrorMessage) == "" {
		t.Fatal("failure error message should be emitted")
	}
	requireWorkerClientErrorNoUnsafeDetails(t, out.String(), err.Error())
}

func TestWorkerRootlessTargetSelectionHumanErrorUsesSafeEndpointSummary(t *testing.T) {
	provisionCalled := false
	_, err := resolveSandboxCommandTarget(context.Background(), sandboxCommandTargetRequest{
		Purpose:        sandbox.SandboxLeasePurposeRun,
		SandboxHostID:  "worker-1",
		SandboxRuntime: sandboxruntime.DriverRootlessPodman,
		ProjectDir:     t.TempDir(),
		Repository:     "git@example.com:org/repo.git",
		Branch:         "feature/worker-rootless",
	}, sandboxCommandTargetDeps{
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{workerRootlessHostWithEndpoint(workerUnsafeRemoteEndpoint())}, nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionCalled = true
			return nil, nil
		},
	})
	if err == nil {
		t.Fatal("resolveSandboxCommandTarget() error = nil, want invalid worker endpoint error")
	}
	requireWorkerEndpointInvalidMessage(t, err.Error(), "configured endpoint: ssh endpoint")
	requireWorkerEndpointNoUnsafeDetails(t, err.Error())
	if provisionCalled {
		t.Fatal("provision should not run for invalid worker endpoint metadata")
	}
}

func TestWorkerMicroVMRuntimeResolverErrorsStayClassifiedAndDoNotFallback(t *testing.T) {
	resolvers := []struct {
		name  string
		build func(func(string) (sandbox.Provider, error)) func(sandboxruntime.Target) (sandboxruntime.Driver, error)
	}{
		{
			name: "run",
			build: func(resolveProvider func(string) (sandbox.Provider, error)) func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
				deps := normalizeRunSandboxDeps(runSandboxDeps{resolveProvider: resolveProvider})
				return deps.resolveRuntimeDriver
			},
		},
		{
			name: "auto",
			build: func(resolveProvider func(string) (sandbox.Provider, error)) func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
				deps := normalizeAutoSandboxDeps(autoSandboxDeps{resolveProvider: resolveProvider})
				return deps.resolveRuntimeDriver
			},
		},
		{
			name: "factory",
			build: func(resolveProvider func(string) (sandbox.Provider, error)) func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
				deps := normalizeFactorySandboxExecutorDeps(factorySandboxExecutorDeps{resolveProvider: resolveProvider})
				return deps.resolveRuntimeDriver
			},
		},
	}

	for _, resolver := range resolvers {
		t.Run(resolver.name, func(t *testing.T) {
			driver, err := resolver.build(func(string) (sandbox.Provider, error) {
				t.Fatal("resolveProvider should not run for unsupported worker runtime metadata")
				return nil, nil
			})(sandboxruntime.Target{
				Provider: "worker",
				Runtime: sandboxruntime.RuntimeState{
					Driver:         sandboxruntime.DriverMicroVM,
					WorkerID:       "worker-1",
					RuntimeID:      "vm-1",
					IsolationLevel: sandbox.SandboxIsolationLevelVM,
				},
			})
			if err == nil {
				t.Fatal("resolveRuntimeDriver() error = nil, want unsupported worker runtime")
			}
			if driver != nil {
				t.Fatalf("driver = %#v, want nil", driver)
			}
			requireWorkerMicroVMUnsupportedMessage(t, err.Error())
		})
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

func workerMicroVMHostWithUnsafeEndpoint() *sandbox.SandboxHost {
	return &sandbox.SandboxHost{
		ID:       "worker-1",
		Name:     "worker one",
		Kind:     sandbox.SandboxHostKindWorker,
		Endpoint: "ssh://deploy:secret@example.test/tmp/private/worker-1.sock?token=secret",
		SupportedRuntimes: []string{
			sandboxruntime.DriverMicroVM,
			sandboxruntime.DriverRootlessPodman,
		},
	}
}

func workerRootlessHostWithEndpoint(endpoint string) *sandbox.SandboxHost {
	return &sandbox.SandboxHost{
		ID:       "worker-1",
		Name:     "worker one",
		Kind:     sandbox.SandboxHostKindWorker,
		Endpoint: endpoint,
		SupportedRuntimes: []string{
			sandboxruntime.DriverRootlessPodman,
		},
	}
}

func workerRootlessCachedSandbox(name string) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		ID:       "sandbox-worker-rootless",
		Name:     name,
		Provider: "worker",
		Status:   sandbox.StatusRunning,
		Host:     workerRootlessHostWithEndpoint(workerSafeUnixEndpoint()),
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			RuntimeID:      "ctr-worker-rootless",
			Image:          "localhost/hal:test",
			WorkerID:       "worker-1",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}
}

func workerSafeUnixEndpoint() string {
	return "unix:///tmp/private/worker-1.sock"
}

func workerUnsafeRemoteEndpoint() string {
	return "ssh://deploy:secret@example.test/tmp/private/worker-1.sock?token=secret"
}

func unsafeWorkerClientFailureDetail() string {
	return "dial ssh://deploy:secret@example.test/tmp/private/worker-1.sock?token=secret failed under /Users/alice/worktree and /workspace/.hal/tmp/session"
}

func unsafeWorkerClientConnectionFailure() error {
	return &sandboxworker.ClientError{
		Operation: "connect",
		Err:       errors.New(unsafeWorkerClientFailureDetail()),
	}
}

func unsafeWorkerClientProtocolFailure() error {
	return &sandboxworker.ClientDriverError{
		Driver:    sandboxruntime.DriverRootlessPodman,
		Operation: sandboxworker.OperationExec,
		Err: &sandboxworker.ProtocolError{
			Operation: sandboxworker.OperationExec,
			Code:      sandboxworker.ErrorCodeDriverFailed,
			Message:   unsafeWorkerClientFailureDetail(),
		},
	}
}

func workerUnsupportedRuntimePlan(projectDir string) sandboxworkspace.Plan {
	return sandboxworkspace.Plan{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
		ProjectDir:  projectDir,
		Repository:  "git@example.com:org/repo.git",
		Branch:      "feature/worker-microvm",
		Upstream:    "origin/feature/worker-microvm",
		SyncRef:     "refs/remotes/origin/feature/worker-microvm",
	}
}

func workerRootlessPlan(projectDir string) sandboxworkspace.Plan {
	return sandboxworkspace.Plan{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
		ProjectDir:  projectDir,
		Repository:  "git@example.com:org/repo.git",
		Branch:      "feature/worker-rootless",
		Upstream:    "origin/feature/worker-rootless",
		SyncRef:     "refs/remotes/origin/feature/worker-rootless",
	}
}

func requireWorkerMicroVMUnsupportedMessage(t *testing.T, message string) {
	t.Helper()
	for _, want := range []string{"runtime_unsupported", "worker-1", sandboxruntime.DriverMicroVM} {
		if !strings.Contains(message, want) {
			t.Fatalf("message = %q, want %q", message, want)
		}
	}
}

func requireWorkerEndpointInvalidMessage(t *testing.T, message, endpointSummary string) {
	t.Helper()
	for _, want := range []string{"worker_endpoint_invalid", "worker-1", sandboxruntime.DriverRootlessPodman, endpointSummary} {
		if !strings.Contains(message, want) {
			t.Fatalf("message = %q, want %q", message, want)
		}
	}
}

func requireWorkerClientFailureMessage(t *testing.T, message string) {
	t.Helper()
	for _, want := range []string{"worker", "failed", "[redacted"} {
		if !strings.Contains(message, want) {
			t.Fatalf("message = %q, want %q", message, want)
		}
	}
}

func requireWorkerMicroVMNoUnsafeDetails(t *testing.T, values ...string) {
	t.Helper()
	combined := strings.Join(values, "\n")
	for _, leaked := range []string{"deploy:secret", "example.test", "token=secret", "/tmp/private/worker-1.sock"} {
		if strings.Contains(combined, leaked) {
			t.Fatalf("output leaked unsafe detail %q: %q", leaked, combined)
		}
	}
}

func requireWorkerEndpointNoUnsafeDetails(t *testing.T, values ...string) {
	t.Helper()
	combined := strings.Join(values, "\n")
	for _, leaked := range []string{"deploy:secret", "example.test", "token=secret", "/tmp/private/worker-1.sock"} {
		if strings.Contains(combined, leaked) {
			t.Fatalf("output leaked unsafe endpoint detail %q: %q", leaked, combined)
		}
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
