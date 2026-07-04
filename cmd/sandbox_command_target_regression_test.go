package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
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

func TestRunSandboxDefaultCommandKeepsWorkerRouteInactiveInManifest(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	startedAt := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{
		Name:     "run-default-worker-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Host:     defaultRegressionWorkerHostWithoutEndpoint(),
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			RuntimeID:      "ctr-default-worker",
			Image:          "localhost/hal:worker",
			WorkerID:       "cached-worker-without-endpoint",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}
	resolver := &fakeDefaultSandboxResolver{t: t, target: target}
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Name != "run-default-worker-box" {
				t.Fatalf("Exec target name = %q, want run-default-worker-box", req.Target.Name)
			}
			if req.Target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
				t.Fatalf("Exec runtime driver = %q, want SSH-machine compatibility", req.Target.Runtime.Driver)
			}
			if req.Target.Runtime.WorkerID != "" || req.Target.Runtime.RuntimeID != "" || req.Target.Runtime.Image != "" {
				t.Fatalf("Exec runtime metadata = %#v, want no worker-backed metadata on default path", req.Target.Runtime)
			}
			_, _ = io.WriteString(req.Stdout, `{"contractVersion":1,"ok":true,"iterations":1,"complete":true,"summary":"default run"}`+"\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

	var resolvedRuntime sandboxruntime.Target
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		JSON:        true,
		JSONChanged: true,
		Base:        "main",
		BaseChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-default-worker-route-inactive"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/run-default-worker", nil },
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
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			t.Fatal("worker runtime resolver should not run without explicit worker target flags")
			return nil, nil
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
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if resolver.calls != 1 {
		t.Fatalf("default resolver calls = %d, want 1", resolver.calls)
	}
	if resolvedRuntime.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("resolved runtime driver = %q, want SSH-machine compatibility", resolvedRuntime.Runtime.Driver)
	}
	if resolvedRuntime.Runtime.WorkerID != "" || resolvedRuntime.Runtime.RuntimeID != "" || resolvedRuntime.Runtime.Image != "" {
		t.Fatalf("resolved runtime metadata = %#v, want worker metadata stripped on default path", resolvedRuntime.Runtime)
	}
	var result RunResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	if !result.OK || result.Summary != "default run" {
		t.Fatalf("RunResult = %#v, want successful default run JSON", result)
	}
	manifest, err := store.LoadManifest("run-default-worker-route-inactive")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if manifest.WorkerRouting != nil {
		t.Fatalf("WorkerRouting = %#v, want nil without explicit worker target flags", manifest.WorkerRouting)
	}
	if manifest.Runtime == nil || manifest.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("manifest runtime = %#v, want SSH-machine-compatible runtime", manifest.Runtime)
	}
	if manifest.Runtime.WorkerID != "" || manifest.Runtime.RuntimeID != "" || manifest.Runtime.Image != "" {
		t.Fatalf("manifest runtime metadata = %#v, want no worker-backed metadata on default path", manifest.Runtime)
	}
	if manifest.Host == nil || manifest.Host.ID != "cached-worker-without-endpoint" || manifest.Host.Endpoint != "" {
		t.Fatalf("manifest host = %#v, want safe worker host identity without endpoint", manifest.Host)
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
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			RuntimeID:      "ctr-auto-default",
			Image:          "localhost/hal:auto-worker",
			WorkerID:       "cached-worker-without-endpoint",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}
	resolver := &fakeDefaultSandboxResolver{t: t, target: target}
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Name != "auto-default-box" {
				t.Fatalf("Exec target name = %q, want auto-default-box", req.Target.Name)
			}
			if req.Target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
				t.Fatalf("Exec runtime driver = %q, want SSH-machine compatibility", req.Target.Runtime.Driver)
			}
			if req.Target.Runtime.WorkerID != "" || req.Target.Runtime.RuntimeID != "" || req.Target.Runtime.Image != "" {
				t.Fatalf("Exec runtime metadata = %#v, want no worker-backed metadata on default path", req.Target.Runtime)
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
	if resolvedRuntime.Runtime.WorkerID != "" || resolvedRuntime.Runtime.RuntimeID != "" || resolvedRuntime.Runtime.Image != "" {
		t.Fatalf("runtime worker metadata = %#v, want empty metadata on unconstrained default path", resolvedRuntime.Runtime)
	}
	if !strings.Contains(out.String(), "auto default path") {
		t.Fatalf("stdout = %q, want fake runtime output", out.String())
	}
}

func TestAutoSandboxDefaultCommandKeepsWorkerRouteInactiveInManifest(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	startedAt := time.Date(2026, 7, 1, 9, 30, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{
		Name:     "auto-default-worker-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Host:     defaultRegressionWorkerHostWithoutEndpoint(),
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			RuntimeID:      "ctr-default-auto-worker",
			Image:          "localhost/hal:auto-worker",
			WorkerID:       "cached-worker-without-endpoint",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}
	resolver := &fakeDefaultSandboxResolver{t: t, target: target}
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Name != "auto-default-worker-box" {
				t.Fatalf("Exec target name = %q, want auto-default-worker-box", req.Target.Name)
			}
			if req.Target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
				t.Fatalf("Exec runtime driver = %q, want SSH-machine compatibility", req.Target.Runtime.Driver)
			}
			if req.Target.Runtime.WorkerID != "" || req.Target.Runtime.RuntimeID != "" || req.Target.Runtime.Image != "" {
				t.Fatalf("Exec runtime metadata = %#v, want no worker-backed metadata on default path", req.Target.Runtime)
			}
			_, _ = io.WriteString(req.Stdout, autoSandboxRemoteSuccessJSON("default auto")+"\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

	var resolvedRuntime sandboxruntime.Target
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		JSON:        true,
		JSONChanged: true,
		Base:        "main",
		BaseChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-default-worker-route-inactive"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
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
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			t.Fatal("worker runtime resolver should not run without explicit worker target flags")
			return nil, nil
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
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if resolver.calls != 1 {
		t.Fatalf("default resolver calls = %d, want 1", resolver.calls)
	}
	if resolvedRuntime.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("resolved runtime driver = %q, want SSH-machine compatibility", resolvedRuntime.Runtime.Driver)
	}
	if resolvedRuntime.Runtime.WorkerID != "" || resolvedRuntime.Runtime.RuntimeID != "" || resolvedRuntime.Runtime.Image != "" {
		t.Fatalf("resolved runtime metadata = %#v, want worker metadata stripped on default path", resolvedRuntime.Runtime)
	}
	var result AutoResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	if !result.OK || result.Summary != "default auto" {
		t.Fatalf("AutoResult = %#v, want successful default auto JSON", result)
	}
	manifest, err := store.LoadManifest("auto-default-worker-route-inactive")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if manifest.WorkerRouting != nil {
		t.Fatalf("WorkerRouting = %#v, want nil without explicit worker target flags", manifest.WorkerRouting)
	}
	if manifest.Runtime == nil || manifest.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("manifest runtime = %#v, want SSH-machine-compatible runtime", manifest.Runtime)
	}
	if manifest.Runtime.WorkerID != "" || manifest.Runtime.RuntimeID != "" || manifest.Runtime.Image != "" {
		t.Fatalf("manifest runtime metadata = %#v, want no worker-backed metadata on default path", manifest.Runtime)
	}
	if manifest.Host == nil || manifest.Host.ID != "cached-worker-without-endpoint" || manifest.Host.Endpoint != "" {
		t.Fatalf("manifest host = %#v, want safe worker host identity without endpoint", manifest.Host)
	}
}

func TestFactorySandboxDefaultTargetResolutionStaysCachedAndFakeOnly(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	target := &sandbox.SandboxState{
		Name:     "factory-default-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Host:     defaultRegressionWorkerHostWithoutEndpoint(),
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			RuntimeID:      "ctr-factory-default",
			Image:          "localhost/hal:factory-worker",
			WorkerID:       "cached-worker-without-endpoint",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
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
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			t.Fatal("worker runtime resolver should not run without explicit worker target flags")
			return nil, nil
		},
		resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			resolvedRuntime = target
			return fakeFactorySandboxRuntimeDriver{
				execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					if req.Target.Name != "factory-default-box" {
						t.Fatalf("Exec target name = %q, want factory-default-box", req.Target.Name)
					}
					if req.Target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
						t.Fatalf("Exec runtime driver = %q, want SSH-machine compatibility", req.Target.Runtime.Driver)
					}
					if req.Target.Runtime.WorkerID != "" || req.Target.Runtime.RuntimeID != "" || req.Target.Runtime.Image != "" {
						t.Fatalf("Exec runtime metadata = %#v, want no worker-backed metadata on default path", req.Target.Runtime)
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
	if resolvedRuntime.Runtime.WorkerID != "" || resolvedRuntime.Runtime.RuntimeID != "" || resolvedRuntime.Runtime.Image != "" {
		t.Fatalf("runtime worker metadata = %#v, want empty metadata on unconstrained default path", resolvedRuntime.Runtime)
	}
	if len(savedRecords) < 2 || savedRecords[1].SandboxName != "factory-default-box" {
		t.Fatalf("saved records = %#v, want selected factory-default-box metadata", savedRecords)
	}
	if savedRecords[1].Sandbox.WorkerRouting != nil {
		t.Fatalf("saved WorkerRouting = %#v, want nil without explicit worker target flags", savedRecords[1].Sandbox.WorkerRouting)
	}
	if savedRecords[1].Sandbox.Runtime == nil || savedRecords[1].Sandbox.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("saved runtime = %#v, want SSH-machine-compatible runtime", savedRecords[1].Sandbox.Runtime)
	}
	if savedRecords[1].Sandbox.Runtime.WorkerID != "" || savedRecords[1].Sandbox.Runtime.RuntimeID != "" || savedRecords[1].Sandbox.Runtime.Image != "" {
		t.Fatalf("saved runtime metadata = %#v, want no worker-backed metadata on default path", savedRecords[1].Sandbox.Runtime)
	}
	if !strings.Contains(out.String(), "factory default path") {
		t.Fatalf("remote output = %q, want fake runtime output", out.String())
	}
}

func TestFactorySandboxDefaultCommandKeepsWorkerRouteInactiveInRecord(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	projectDir := t.TempDir()
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	startedAt := time.Date(2026, 7, 1, 9, 30, 0, 0, time.UTC)
	now := func() time.Time {
		startedAt = startedAt.Add(time.Second)
		return startedAt
	}
	target := &sandbox.SandboxState{
		Name:     "factory-default-worker-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Host:     defaultRegressionWorkerHostWithoutEndpoint(),
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			RuntimeID:      "ctr-factory-default-worker",
			Image:          "localhost/hal:factory-worker",
			WorkerID:       "cached-worker-without-endpoint",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}
	resolver := &fakeDefaultSandboxResolver{t: t, target: target}
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Name != "factory-default-worker-box" {
				t.Fatalf("Exec target name = %q, want factory-default-worker-box", req.Target.Name)
			}
			if req.Target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
				t.Fatalf("Exec runtime driver = %q, want SSH-machine compatibility", req.Target.Runtime.Driver)
			}
			if req.Target.Runtime.WorkerID != "" || req.Target.Runtime.RuntimeID != "" || req.Target.Runtime.Image != "" {
				t.Fatalf("Exec runtime metadata = %#v, want no worker-backed metadata on default path", req.Target.Runtime)
			}
			_, _ = io.WriteString(req.Stdout, "factory default command path\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

	policy := factory.DefaultFactoryPolicy()
	policy.PRCreationAllowed = false

	var resolvedRuntime sandboxruntime.Target
	var out bytes.Buffer
	err := runFactoryRunWithDeps(context.Background(), projectDir, factoryRunRequest{
		BaseBranch: "main",
		Sandbox:    true,
	}, &out, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-factory-default-worker-route-inactive", nil },
		now:          now,
		workingDir:   func() (string, error) { return projectDir, nil },
		currentBranch: func(string) (string, error) {
			return "feature/factory-default-worker", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@example.com:org/repo.git", nil
		},
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		loadEngine: func(string) (string, error) {
			return factory.PolicyEngineCodex, nil
		},
		runPipeline: func(context.Context, factoryRunPipelineRequest) error {
			t.Fatal("local pipeline should not run with --sandbox")
			return nil
		},
		runSandbox: func(ctx context.Context, req factorySandboxExecutorRequest) error {
			return runFactorySandboxExecutorWithDeps(ctx, req, factorySandboxExecutorDeps{
				defaultStore: func() (factory.Store, error) { return store, nil },
				now:          now,
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
				resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
					t.Fatal("worker runtime resolver should not run without explicit worker target flags")
					return nil, nil
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
			})
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "factory-default-worker-box" {
				t.Fatalf("loadSandbox name = %q, want factory-default-worker-box", name)
			}
			return sandboxCommandSSHMachineCompatWorkerTarget(target), nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExecWithEnv: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, _ map[string]string, out io.Writer) error {
			_, _ = io.WriteString(out, `{"schemaVersion":"verify-v1","status":"pass","summary":{"total":0},"checks":[]}`+"\n")
			return nil
		},
		statusSnapshot: func(string) (factorySnapshotArtifact, error) {
			return factorySnapshotArtifact{}, nil
		},
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) {
			return factorySnapshotArtifact{}, nil
		},
		sandboxRequests: func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
			return nil
		},
		cleanupSandbox: func(context.Context, factorySandboxCleanupRequest) error {
			t.Fatal("cleanup should not run with the default preserve policy")
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v\noutput=%s", err, out.String())
	}
	if resolver.calls != 1 {
		t.Fatalf("default resolver calls = %d, want 1", resolver.calls)
	}
	if resolvedRuntime.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("resolved runtime driver = %q, want SSH-machine compatibility", resolvedRuntime.Runtime.Driver)
	}
	if resolvedRuntime.Runtime.WorkerID != "" || resolvedRuntime.Runtime.RuntimeID != "" || resolvedRuntime.Runtime.Image != "" {
		t.Fatalf("resolved runtime metadata = %#v, want worker metadata stripped on default path", resolvedRuntime.Runtime)
	}
	record, loadErr := store.LoadRun("run-factory-default-worker-route-inactive")
	if loadErr != nil {
		t.Fatalf("LoadRun() error: %v", loadErr)
	}
	if record.Status != factory.RunStatusSucceeded {
		t.Fatalf("record.Status = %q, want succeeded", record.Status)
	}
	if record.Sandbox == nil {
		t.Fatal("record.Sandbox = nil, want persisted default sandbox metadata")
	}
	if record.Sandbox.WorkerRouting != nil {
		t.Fatalf("record WorkerRouting = %#v, want nil without explicit worker target flags", record.Sandbox.WorkerRouting)
	}
	if record.Sandbox.Runtime == nil || record.Sandbox.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("record sandbox runtime = %#v, want SSH-machine-compatible runtime", record.Sandbox.Runtime)
	}
	if record.Sandbox.Runtime.WorkerID != "" || record.Sandbox.Runtime.RuntimeID != "" || record.Sandbox.Runtime.Image != "" {
		t.Fatalf("record sandbox runtime metadata = %#v, want no worker-backed metadata on default path", record.Sandbox.Runtime)
	}
	if record.Sandbox.Host == nil || record.Sandbox.Host.ID != "cached-worker-without-endpoint" {
		t.Fatalf("record sandbox host = %#v, want safe cached worker host identity", record.Sandbox.Host)
	}
}

func TestResolveSandboxCommandTargetStrictMicroVMRejectsMissingReadinessBeforeDirectHostCompatibility(t *testing.T) {
	target := strictCommandMicroVMTargetWithoutReadiness("cmd-strict-microvm")
	var provisionCalled bool

	resolved, err := resolveSandboxCommandTarget(context.Background(), sandboxCommandTargetRequest{
		Purpose:             sandbox.SandboxLeasePurposeRun,
		SandboxName:         target.Name,
		SandboxRuntime:      sandbox.SandboxRuntimeDriverMicroVM,
		ProjectDir:          "/Users/alice/private/worktree",
		Repository:          "https://alice:ghp_strict_secret@example.test/org/private-repo.git",
		Branch:              "feature/strict-microvm",
		ProvisionRepository: "https://alice:ghp_strict_secret@example.test/org/private-repo.git",
	}, sandboxCommandTargetDeps{
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loadSandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{strictCommandMicroVMHost()}, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("listSandboxes should not run for explicit strict microVM target selection")
			return nil, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("resolveDefault should not run for explicit strict microVM target selection")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionCalled = true
			return nil, nil
		},
	})

	if err == nil {
		t.Fatalf("resolveSandboxCommandTarget() target = %#v, error = nil, want strict secure-default readiness failure", resolved)
	}
	if resolved != nil {
		t.Fatalf("resolved target = %#v, want nil after strict secure-default rejection", resolved)
	}
	if provisionCalled {
		t.Fatal("provision ran after strict secure-default rejection")
	}
	requireStrictCommandTargetSelectionErrorSafe(t, err.Error(), strictCommandTargetForbiddenFragments()...)
}

func TestRunFactorySandboxExecutorStrictSecureDefaultDoesNotResolveCompatibilityDefaultTargets(t *testing.T) {
	tests := []struct {
		name   string
		target *sandbox.SandboxState
	}{
		{
			name:   "ssh machine",
			target: strictCommandCompatibilityDefaultTarget("factory-strict-ssh", sandbox.SandboxRuntimeDriverSSHMachine, sandbox.SandboxIsolationLevelHost, nil),
		},
		{
			name:   "rootless worker",
			target: strictCommandCompatibilityDefaultTarget("factory-strict-rootless", sandbox.SandboxRuntimeDriverRootlessPodman, sandbox.SandboxIsolationLevelContainer, nil),
		},
		{
			name: "direct host workspace",
			target: strictCommandCompatibilityDefaultTarget("factory-strict-direct", sandbox.SandboxRuntimeDriverMicroVM, sandbox.SandboxIsolationLevelVM, &sandbox.SandboxWorkspace{
				Mode:        sandbox.SandboxWorkspaceModeDirect,
				InputSource: sandbox.SandboxWorkspaceInputSourceCopy,
				Repo:        "https://alice:ghp_strict_secret@example.test/org/private-repo.git",
				Branch:      "feature/direct-host",
				SyncRef:     "/Users/alice/private/worktree",
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := factory.NewStore(t.TempDir())
			now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
			runID := "run-strict-target-" + strings.ReplaceAll(tt.name, " ", "-")
			var resolveDefaultCalls int
			var remoteOutput bytes.Buffer

			err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
				ProjectDir:                "/Users/alice/private/worktree",
				SecurityReadinessGateMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
				RunRecord: factory.RunRecord{
					RunID:      runID,
					RepoRemote: "https://alice:ghp_strict_secret@example.test/org/private-repo.git",
					BaseBranch: "main",
					BranchName: "feature/strict-target-selection",
					Status:     factory.RunStatusRunning,
					Policy: &factory.FactoryPolicy{
						SecurityReadinessGatePolicyMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
					},
				},
				RemoteAuto:          factoryRunAutoRequest{BaseBranch: "main"},
				RemoteOutput:        &remoteOutput,
				DeferSuccessCleanup: true,
			}, factorySandboxExecutorDeps{
				defaultStore: func() (factory.Store, error) { return store, nil },
				now:          func() time.Time { return now },
				resolveDefault: func(filter func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
					resolveDefaultCalls++
					if !filter(tt.target) {
						t.Fatalf("running-sandbox filter rejected fixture target %#v", tt.target)
					}
					return tt.target, tt.target.Name, nil
				},
				listHosts: func() ([]*sandbox.SandboxHost, error) {
					return []*sandbox.SandboxHost{strictCommandMicroVMHost()}, nil
				},
				loadSandbox: func(string) (*sandbox.SandboxState, error) {
					t.Fatal("loadSandbox should not run for strict secure-default default selection")
					return nil, nil
				},
				provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
					t.Fatal("provision should not run for strict secure-default default selection")
					return nil, nil
				},
				resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
					t.Fatal("runtime driver should not be constructed after strict target-selection rejection")
					return nil, nil
				},
				bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
					t.Fatal("bootstrap should not run after strict target-selection rejection")
					return factory.BootstrapResult{}, nil
				},
				engineAuthFiles: func() []factorySandboxAuthFile { return nil },
			})

			if err == nil {
				t.Fatal("runFactorySandboxExecutorWithDeps() error = nil, want strict target-selection rejection")
			}
			requireStrictCommandTargetSelectionErrorSafe(t, err.Error(), strictCommandTargetForbiddenFragments()...)
			if resolveDefaultCalls != 0 {
				t.Fatalf("resolveDefault calls = %d, want 0 so strict secure-default selection cannot fall back to %s compatibility", resolveDefaultCalls, tt.name)
			}
		})
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

func TestWorkerRootlessRunSandboxStartFailuresClassifyAndSanitizeOutput(t *testing.T) {
	failures := []struct {
		name           string
		classification string
		err            error
	}{
		{
			name:           "driver",
			classification: sandboxworker.FailureWorkerLifecycle,
			err: &sandboxworker.ClientDriverError{
				Driver:    sandboxruntime.DriverRootlessPodman,
				Operation: sandboxworker.OperationStart,
				Err: &sandboxworker.ProtocolError{
					Operation: sandboxworker.OperationStart,
					Code:      sandboxworker.ErrorCodeDriverFailed,
					Message:   unsafeWorkerClientFailureDetail(),
				},
			},
		},
		{
			name:           "client",
			classification: sandboxworker.FailureWorkerClient,
			err: &sandboxworker.ClientDriverError{
				Driver:    sandboxruntime.DriverRootlessPodman,
				Operation: sandboxworker.OperationStart,
				Err: &sandboxworker.ClientError{
					Operation: sandboxworker.OperationStart,
					Code:      sandboxworker.ErrorCodeInternal,
					Message:   unsafeWorkerClientFailureDetail(),
				},
			},
		},
	}
	modes := []struct {
		name string
		json bool
	}{
		{name: "json", json: true},
		{name: "human", json: false},
	}

	for _, failure := range failures {
		for _, mode := range modes {
			t.Run(failure.name+"/"+mode.name, func(t *testing.T) {
				startedAt := time.Date(2026, 7, 1, 7, 36, 0, 0, time.UTC)
				finishedAt := startedAt.Add(time.Second)
				projectDir := t.TempDir()
				store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
				var out bytes.Buffer
				var errOut bytes.Buffer
				executionID := "run-worker-start-" + failure.name + "-" + mode.name

				err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
					JSON:                  mode.json,
					JSONChanged:           mode.json,
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
						return executionID
					},
					now:        runSandboxTestClock(startedAt, finishedAt),
					workingDir: func() (string, error) { return projectDir, nil },
					planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
						return workerRootlessPlan(projectDir), nil
					},
					loadSandbox: func(name string) (*sandbox.SandboxState, error) {
						target := workerRootlessCachedSandbox(name)
						target.Status = sandbox.StatusStopped
						return target, nil
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
					resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
						return fakeRunSandboxRuntimeDriver{
							id: sandboxruntime.DriverRootlessPodman,
							start: func(context.Context, sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
								return nil, failure.err
							},
						}, nil
					},
					resolveProvider: func(string) (sandbox.Provider, error) {
						t.Fatal("provider resolution should not run after worker start failure")
						return nil, nil
					},
				})

				var message string
				if mode.json {
					if err != nil {
						t.Fatalf("runRunSandboxWithWriter() error = %v, want JSON error result", err)
					}
					var result RunResult
					decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
					if result.OK {
						t.Fatalf("RunResult.OK = true, want false")
					}
					message = result.Error
				} else {
					if err == nil {
						t.Fatal("runRunSandboxWithWriter() error = nil, want classified human error")
					}
					message = err.Error()
				}
				requireWorkerLifecycleFailureMessage(t, message, failure.classification)
				requireWorkerClientErrorNoUnsafeDetails(t, message, out.String(), errOut.String())

				manifest, loadErr := store.LoadManifest(executionID)
				if loadErr != nil {
					t.Fatalf("LoadManifest() error: %v", loadErr)
				}
				if manifest.Status != sandboxexecution.StatusFailed {
					t.Fatalf("manifest.Status = %q, want failed", manifest.Status)
				}
			})
		}
	}
}

func TestWorkerRootlessRunSandboxFailureRecoveryMetadata(t *testing.T) {
	t.Run("fail-first start failure recovery metadata", func(t *testing.T) {
		t.Setenv("HAL_CONFIG_HOME", t.TempDir())
		unrelatedHost, unrelatedState := writeUnrelatedSandboxRegistryRecords(t)

		startedAt := time.Date(2026, 7, 1, 9, 30, 0, 0, time.UTC)
		finishedAt := startedAt.Add(time.Second)
		projectDir := t.TempDir()
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
		startErr := &sandboxworker.ClientDriverError{
			Driver:    sandboxruntime.DriverRootlessPodman,
			Operation: sandboxworker.OperationStart,
			Err: &sandboxworker.ProtocolError{
				Operation: sandboxworker.OperationStart,
				Code:      sandboxworker.ErrorCodeDriverFailed,
				Message:   "worker start failed at unix:///tmp/private/worker-1.sock for https://deploy:secret@example.test/org/repo.git?token=secret",
			},
		}
		var out bytes.Buffer
		var errOut bytes.Buffer

		err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
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
				return "run-worker-rootless-start-failure-recovery"
			},
			now:        runSandboxTestClock(startedAt, finishedAt),
			workingDir: func() (string, error) { return projectDir, nil },
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				plan := workerRootlessPlan(projectDir)
				plan.Repository = "https://deploy:secret@example.test/org/repo.git?token=secret"
				return plan, nil
			},
			loadSandbox: func(name string) (*sandbox.SandboxState, error) {
				return workerRootlessStoppedSandboxWithoutRuntimeDetails(name), nil
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
			resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
				return fakeRunSandboxRuntimeDriver{
					id: sandboxruntime.DriverRootlessPodman,
					start: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
						return workerRootlessStartedRuntimeTarget(req), startErr
					},
				}, nil
			},
			resolveProvider: func(string) (sandbox.Provider, error) {
				t.Fatal("provider resolution should not run after worker start failure")
				return nil, nil
			},
			persistSandboxState: func(*sandbox.SandboxState) error {
				t.Fatal("start failure recovery must not overwrite durable sandbox state")
				return nil
			},
		})
		if err == nil {
			t.Fatal("runRunSandboxWithWriter() error = nil, want start failure")
		}
		requireWorkerClientErrorNoUnsafeDetails(t, err.Error(), out.String(), errOut.String())

		manifest, loadErr := store.LoadManifest("run-worker-rootless-start-failure-recovery")
		if loadErr != nil {
			t.Fatalf("LoadManifest() error: %v", loadErr)
		}
		if manifest.Status != sandboxexecution.StatusFailed {
			t.Fatalf("manifest.Status = %q, want failed", manifest.Status)
		}
		requireWorkerRootlessFailureManifestMetadata(t, manifest, "worker-rootless")
		requireWorkerFailureRecoveryMetadataSafe(t, map[string]any{
			"sandboxName":   manifest.SandboxName,
			"host":          manifest.Host,
			"runtime":       manifest.Runtime,
			"workerRouting": manifest.WorkerRouting,
		}, "unix://", "/tmp/private/worker-1.sock", "example.test", "deploy:secret", "token=secret", projectDir)
		requireUnrelatedSandboxRegistryRecords(t, unrelatedHost, unrelatedState)
	})
}

func TestWorkerRootlessFactorySandboxFailureRecoveryMetadata(t *testing.T) {
	t.Run("fail-first create failure recovery metadata", func(t *testing.T) {
		t.Setenv("HAL_CONFIG_HOME", t.TempDir())
		unrelatedHost, unrelatedState := writeUnrelatedSandboxRegistryRecords(t)

		now := time.Date(2026, 7, 1, 9, 31, 0, 0, time.UTC)
		createErr := errors.New("worker create failed at unix:///tmp/private/worker-1.sock for https://deploy:secret@example.test/org/repo.git?token=secret")
		store := factory.NewStore(t.TempDir())
		var savedRecords []factory.RunRecord

		err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
			ProjectDir:  "/tmp/private/factory-project",
			SandboxName: "worker-rootless-create",
			RunRecord: factory.RunRecord{
				RunID:       "factory-worker-rootless-create-failure",
				Status:      factory.RunStatusRunning,
				CurrentStep: "run",
				BranchName:  "feature/worker-rootless",
				BaseBranch:  "main",
				RepoRemote:  "https://deploy:secret@example.test/org/repo.git?token=secret",
			},
		}, factorySandboxExecutorDeps{
			defaultStore: func() (factory.Store, error) { return store, nil },
			now:          func() time.Time { return now },
			loadSandbox: func(string) (*sandbox.SandboxState, error) {
				return nil, errFactorySandboxNotExist
			},
			provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
				return workerRootlessCreateFailureSandbox("worker-rootless-create"), createErr
			},
			resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
				t.Fatal("runtime driver resolution should not run after worker create failure")
				return nil, nil
			},
			persistSandboxState: func(*sandbox.SandboxState) error {
				t.Fatal("create failure recovery must not overwrite durable sandbox state")
				return nil
			},
			saveRun: func(_ factory.Store, record *factory.RunRecord) error {
				savedRecords = append(savedRecords, *record)
				return nil
			},
			appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
		})
		if err == nil || !strings.Contains(err.Error(), "worker create failed") {
			t.Fatalf("runFactorySandboxExecutorWithDeps() error = %v, want create failure", err)
		}
		if len(savedRecords) != 2 {
			t.Fatalf("saved records = %d, want initial and failed records", len(savedRecords))
		}
		failed := savedRecords[1]
		if failed.Status != factory.RunStatusFailed || failed.CurrentStep != "provision" {
			t.Fatalf("failed record status/step = %s/%s, want failed/provision", failed.Status, failed.CurrentStep)
		}
		requireWorkerRootlessFailureFactoryMetadata(t, failed.Sandbox, "worker-rootless-create")
		requireWorkerFailureRecoveryMetadataSafe(t, failed.Sandbox, "unix://", "/tmp/private/worker-1.sock", "example.test", "deploy:secret", "token=secret", "/tmp/private/factory-project")
		requireUnrelatedSandboxRegistryRecords(t, unrelatedHost, unrelatedState)
	})

	t.Run("fail-first start failure recovery metadata", func(t *testing.T) {
		t.Setenv("HAL_CONFIG_HOME", t.TempDir())
		unrelatedHost, unrelatedState := writeUnrelatedSandboxRegistryRecords(t)

		now := time.Date(2026, 7, 1, 9, 32, 0, 0, time.UTC)
		startErr := &sandboxworker.ClientDriverError{
			Driver:    sandboxruntime.DriverRootlessPodman,
			Operation: sandboxworker.OperationStart,
			Err: &sandboxworker.ProtocolError{
				Operation: sandboxworker.OperationStart,
				Code:      sandboxworker.ErrorCodeDriverFailed,
				Message:   "worker start failed at unix:///tmp/private/worker-1.sock for https://deploy:secret@example.test/org/repo.git?token=secret",
			},
		}
		store := factory.NewStore(t.TempDir())
		var savedRecords []factory.RunRecord

		err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
			ProjectDir:      "/tmp/private/factory-project",
			SandboxName:     "worker-rootless-start",
			SandboxHostID:   "worker-1",
			SandboxRuntime:  sandboxruntime.DriverRootlessPodman,
			RemoteOutput:    io.Discard,
			ResolvedSecrets: nil,
			RunRecord: factory.RunRecord{
				RunID:       "factory-worker-rootless-start-failure",
				Status:      factory.RunStatusRunning,
				CurrentStep: "run",
				BranchName:  "feature/worker-rootless",
				BaseBranch:  "main",
				RepoRemote:  "https://deploy:secret@example.test/org/repo.git?token=secret",
			},
		}, factorySandboxExecutorDeps{
			defaultStore: func() (factory.Store, error) { return store, nil },
			now:          func() time.Time { return now },
			loadSandbox: func(name string) (*sandbox.SandboxState, error) {
				return workerRootlessStoppedSandboxWithoutRuntimeDetails(name), nil
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
			resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
				return fakeRunSandboxRuntimeDriver{
					id: sandboxruntime.DriverRootlessPodman,
					start: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
						return workerRootlessStartedRuntimeTarget(req), startErr
					},
				}, nil
			},
			resolveProvider: func(string) (sandbox.Provider, error) {
				t.Fatal("provider resolution should not run after worker start failure")
				return nil, nil
			},
			persistSandboxState: func(*sandbox.SandboxState) error {
				t.Fatal("start failure recovery must not overwrite durable sandbox state")
				return nil
			},
			saveRun: func(_ factory.Store, record *factory.RunRecord) error {
				savedRecords = append(savedRecords, *record)
				return nil
			},
			appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
		})
		if err == nil || !strings.Contains(err.Error(), "worker start failed") {
			t.Fatalf("runFactorySandboxExecutorWithDeps() error = %v, want start failure", err)
		}
		if len(savedRecords) != 2 {
			t.Fatalf("saved records = %d, want initial and failed records", len(savedRecords))
		}
		failed := savedRecords[1]
		if failed.Status != factory.RunStatusFailed || failed.CurrentStep != "start" {
			t.Fatalf("failed record status/step = %s/%s, want failed/start", failed.Status, failed.CurrentStep)
		}
		requireWorkerRootlessFailureFactoryMetadata(t, failed.Sandbox, "worker-rootless-start")
		requireWorkerFailureRecoveryMetadataSafe(t, failed.Sandbox, "unix://", "/tmp/private/worker-1.sock", "example.test", "deploy:secret", "token=secret", "/tmp/private/factory-project")
		requireUnrelatedSandboxRegistryRecords(t, unrelatedHost, unrelatedState)
	})
}

func TestWorkerRootlessRunSandboxUsesSharedWorkerRuntimeResolver(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 7, 38, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer
	var workerResolverCalls int
	var materializedWithDriver string

	workerDriver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
				t.Fatalf("Exec runtime driver = %q, want rootless_podman", req.Target.Runtime.Driver)
			}
			if req.Target.Runtime.WorkerID != "worker-1" {
				t.Fatalf("Exec worker ID = %q, want worker-1", req.Target.Runtime.WorkerID)
			}
			_, _ = io.WriteString(req.Stdout, "worker-backed run path\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
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
			return "run-worker-rootless-shared-resolver"
		},
		now:        runSandboxTestClock(startedAt, finishedAt),
		workingDir: func() (string, error) { return projectDir, nil },
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			plan := workerRootlessBundlePlan(projectDir)
			plan.Repository = "https://deploy:secret@example.test/org/repo.git"
			return plan, nil
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
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for explicit worker-backed run execution")
			return nil, nil
		},
		resolveWorkerRuntime: func(req sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			workerResolverCalls++
			if req.Host == nil || req.Host.ID != "worker-1" {
				t.Fatalf("worker resolver host = %#v, want worker-1", req.Host)
			}
			if req.Target.Name != "worker-rootless" {
				t.Fatalf("worker resolver target name = %q, want worker-rootless", req.Target.Name)
			}
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
				t.Fatalf("worker resolver runtime = %q, want rootless_podman", req.Target.Runtime.Driver)
			}
			if req.Target.Runtime.WorkerID != "worker-1" || req.Target.Runtime.RuntimeID != "ctr-worker-rootless" {
				t.Fatalf("worker resolver runtime metadata = %#v, want durable worker metadata", req.Target.Runtime)
			}
			return workerDriver, nil
		},
		materializeWorkspace: func(_ context.Context, prep sandboxexec.PrepareContext, _ sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
			materializedWithDriver = prep.Driver.ID()
			return sandboxworkspace.MaterializationResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if workerResolverCalls != 1 {
		t.Fatalf("worker resolver calls = %d, want 1", workerResolverCalls)
	}
	if materializedWithDriver != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("workspace materialized with driver = %q, want rootless_podman", materializedWithDriver)
	}
	if !strings.Contains(out.String(), "worker-backed run path") {
		t.Fatalf("stdout = %q, want worker-backed runtime output", out.String())
	}
	manifest, loadErr := store.LoadManifest("run-worker-rootless-shared-resolver")
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("manifest.Status = %q, want succeeded", manifest.Status)
	}
	if manifest.Runtime == nil || manifest.Runtime.Driver != sandboxruntime.DriverRootlessPodman || manifest.Runtime.WorkerID != "worker-1" {
		t.Fatalf("manifest runtime = %#v, want selected worker rootless runtime", manifest.Runtime)
	}
	if manifest.Purpose != sandboxexecution.PurposeRun {
		t.Fatalf("manifest.Purpose = %q, want %q", manifest.Purpose, sandboxexecution.PurposeRun)
	}
	requireWorkerRootlessRunManifestWorkspace(t, manifest.Workspace, sandbox.SandboxWorkspaceInputSourceGitBundle)
	requireWorkerRootlessExecutionManifestMetadata(t, manifest)
	requireWorkerManifestNoUnsafeDetails(t, manifest, "unix://", "/tmp/private/worker-1.sock", "deploy:secret", "example.test", "token=secret")
}

func TestWorkerRootlessRunSandboxPersistsSafeSandboxStateMetadata(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	startedAt := time.Date(2026, 7, 1, 7, 38, 30, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer

	workerDriver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		start: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
			target := req.Target
			target.Status = sandbox.StatusRunning
			target.Runtime = sandboxruntime.RuntimeState{
				Driver:         sandboxruntime.DriverRootlessPodman,
				RuntimeID:      "ctr-worker-rootless",
				Image:          "localhost/hal:test",
				WorkerID:       "worker-1",
				IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			}
			return &target, nil
		},
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Runtime.RuntimeID != "ctr-worker-rootless" || req.Target.Runtime.Image != "localhost/hal:test" {
				t.Fatalf("Exec target runtime = %#v, want started worker runtime metadata", req.Target.Runtime)
			}
			_, _ = io.WriteString(req.Stdout, "worker-backed run path\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
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
			return "run-worker-rootless-persist-state"
		},
		now:        runSandboxTestClock(startedAt, finishedAt),
		workingDir: func() (string, error) { return projectDir, nil },
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			plan := workerRootlessPlan(projectDir)
			plan.Repository = "https://deploy:secret@example.test/org/repo.git"
			return plan, nil
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			target := workerRootlessCachedSandbox(name)
			target.Status = sandbox.StatusStopped
			target.Runtime.RuntimeID = ""
			target.Runtime.Image = ""
			target.Runtime.WorkerID = ""
			return target, nil
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
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for explicit worker-backed run execution")
			return nil, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			return workerDriver, nil
		},
		persistSandboxState: sandbox.ForceWriteInstance,
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
		runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}

	loaded, err := sandbox.LoadInstance("worker-rootless")
	if err != nil {
		t.Fatalf("LoadInstance() error: %v", err)
	}
	requireWorkerRootlessPersistedSandboxState(t, loaded)
}

func TestWorkerRootlessAutoSandboxUsesSharedWorkerRuntimeResolver(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 7, 39, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer
	var workerResolverCalls int
	var materializedWithDriver string

	workerDriver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
				t.Fatalf("Exec runtime driver = %q, want rootless_podman", req.Target.Runtime.Driver)
			}
			if req.Target.Runtime.WorkerID != "worker-1" {
				t.Fatalf("Exec worker ID = %q, want worker-1", req.Target.Runtime.WorkerID)
			}
			_, _ = io.WriteString(req.Stdout, autoSandboxRemoteSuccessJSON("worker-backed auto path")+"\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
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
			return "auto-worker-rootless-shared-resolver"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			plan := workerRootlessBundlePlan(projectDir)
			plan.Repository = "https://deploy:secret@example.test/org/repo.git?token=secret"
			return plan, nil
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
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for explicit worker-backed auto execution")
			return nil, nil
		},
		resolveWorkerRuntime: func(req sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			workerResolverCalls++
			if req.Host == nil || req.Host.ID != "worker-1" {
				t.Fatalf("worker resolver host = %#v, want worker-1", req.Host)
			}
			if req.Target.Name != "worker-rootless" {
				t.Fatalf("worker resolver target name = %q, want worker-rootless", req.Target.Name)
			}
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
				t.Fatalf("worker resolver runtime = %q, want rootless_podman", req.Target.Runtime.Driver)
			}
			if req.Target.Runtime.WorkerID != "worker-1" || req.Target.Runtime.RuntimeID != "ctr-worker-rootless" {
				t.Fatalf("worker resolver runtime metadata = %#v, want durable worker metadata", req.Target.Runtime)
			}
			return workerDriver, nil
		},
		materializeWorkspace: func(_ context.Context, prep sandboxexec.PrepareContext, _ sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
			materializedWithDriver = prep.Driver.ID()
			return sandboxworkspace.MaterializationResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if workerResolverCalls != 1 {
		t.Fatalf("worker resolver calls = %d, want 1", workerResolverCalls)
	}
	if materializedWithDriver != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("workspace materialized with driver = %q, want rootless_podman", materializedWithDriver)
	}
	if !strings.Contains(out.String(), "worker-backed auto path") {
		t.Fatalf("stdout = %q, want worker-backed runtime output", out.String())
	}
	manifest, loadErr := store.LoadManifest("auto-worker-rootless-shared-resolver")
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("manifest.Status = %q, want succeeded", manifest.Status)
	}
	if manifest.Runtime == nil || manifest.Runtime.Driver != sandboxruntime.DriverRootlessPodman || manifest.Runtime.WorkerID != "worker-1" {
		t.Fatalf("manifest runtime = %#v, want selected worker rootless runtime", manifest.Runtime)
	}
	if manifest.Purpose != sandboxexecution.PurposeAuto {
		t.Fatalf("manifest.Purpose = %q, want %q", manifest.Purpose, sandboxexecution.PurposeAuto)
	}
	requireWorkerRootlessRunManifestWorkspace(t, manifest.Workspace, sandbox.SandboxWorkspaceInputSourceGitBundle)
	requireWorkerRootlessExecutionManifestMetadata(t, manifest)
	requireWorkerManifestNoUnsafeDetails(t, manifest, "unix://", "/tmp/private/worker-1.sock", "deploy:secret", "example.test", "token=secret")
}

func TestWorkerRootlessRunSandboxStreamsOutputAndSummariesExcludePreparation(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 8, 10, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer

	workerDriver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if isWorkerOutputArtifactGenerationExec(req) {
				return &sandboxruntime.ExecResult{}, nil
			}
			_, _ = io.WriteString(req.Stdout, `{"contractVersion":1,"ok":true,"summary":"worker run stream"}`+"\n")
			_, _ = io.WriteString(req.Stderr, "worker run stderr one\n")
			_, _ = io.WriteString(req.Stderr, "worker run stderr two\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

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
			return "run-worker-rootless-output-stream"
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
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for explicit worker-backed run execution")
			return nil, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			return workerDriver, nil
		},
		bootstrap:              bootstrapWithPreparationOutput(),
		runProviderExecWithEnv: runProviderExecWithPreparationOutput("run preparation output"),
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
		runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	var result RunResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	if !result.OK || result.Summary != "worker run stream" {
		t.Fatalf("RunResult = %#v, want successful remote JSON", result)
	}
	if !strings.Contains(errOut.String(), "run preparation output") {
		t.Fatalf("stderr/setup output = %q, want preparation output", errOut.String())
	}
	manifest, loadErr := store.LoadManifest("run-worker-rootless-output-stream")
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	stdoutSummary := requireSandboxOutputSummaryPayload(t, store, manifest, "output/stdout-summary.txt")
	stderrSummary := requireSandboxOutputSummaryPayload(t, store, manifest, "output/stderr-summary.txt")
	if stdoutSummary != `{"contractVersion":1,"ok":true,"summary":"worker run stream"}`+"\n" {
		t.Fatalf("stdout summary = %q, want only remote JSON output", stdoutSummary)
	}
	if stderrSummary != "worker run stderr one\nworker run stderr two\n" {
		t.Fatalf("stderr summary = %q, want ordered remote stderr lines", stderrSummary)
	}
	if strings.Contains(stdoutSummary+stderrSummary, "preparation output") {
		t.Fatalf("output summaries included preparation output: stdout=%q stderr=%q", stdoutSummary, stderrSummary)
	}
}

func TestWorkerRootlessAutoSandboxStreamsOutputAndSummariesExcludePreparation(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 8, 11, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer

	workerDriver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if isWorkerOutputArtifactGenerationExec(req) {
				return &sandboxruntime.ExecResult{}, nil
			}
			_, _ = io.WriteString(req.Stdout, autoSandboxRemoteSuccessJSON("worker auto stream")+"\n")
			_, _ = io.WriteString(req.Stderr, "worker auto stderr one\n")
			_, _ = io.WriteString(req.Stderr, "worker auto stderr two\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

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
			return "auto-worker-rootless-output-stream"
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
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for explicit worker-backed auto execution")
			return nil, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			return workerDriver, nil
		},
		bootstrap:              bootstrapWithPreparationOutput(),
		runProviderExecWithEnv: runProviderExecWithPreparationOutput("auto preparation output"),
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
		runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	var result AutoResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	if !result.OK || result.Summary != "worker auto stream" {
		t.Fatalf("AutoResult = %#v, want successful remote JSON", result)
	}
	if !strings.Contains(errOut.String(), "auto preparation output") {
		t.Fatalf("stderr/setup output = %q, want preparation output", errOut.String())
	}
	manifest, loadErr := store.LoadManifest("auto-worker-rootless-output-stream")
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	stdoutSummary := requireSandboxOutputSummaryPayload(t, store, manifest, "output/stdout-summary.txt")
	stderrSummary := requireSandboxOutputSummaryPayload(t, store, manifest, "output/stderr-summary.txt")
	if stdoutSummary != autoSandboxRemoteSuccessJSON("worker auto stream")+"\n" {
		t.Fatalf("stdout summary = %q, want only remote JSON output", stdoutSummary)
	}
	if stderrSummary != "worker auto stderr one\nworker auto stderr two\n" {
		t.Fatalf("stderr summary = %q, want ordered remote stderr lines", stderrSummary)
	}
	if strings.Contains(stdoutSummary+stderrSummary, "preparation output") {
		t.Fatalf("output summaries included preparation output: stdout=%q stderr=%q", stdoutSummary, stderrSummary)
	}
}

func TestWorkerRootlessRunSandboxUsesRuntimeCopyForWorkspaceAndArtifacts(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 8, 20, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	bundleDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer
	var copyIns []sandboxruntime.CopyRequest
	var copyOuts []sandboxruntime.CopyRequest
	localGit := &workerRootlessLocalGit{bundleID: "worker-rootless-sync", syncRef: "worker-rootless-sync"}

	workerDriver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
				t.Fatalf("Exec runtime driver = %q, want rootless_podman", req.Target.Runtime.Driver)
			}
			if req.Target.Runtime.WorkerID != "worker-1" {
				t.Fatalf("Exec worker ID = %q, want worker-1", req.Target.Runtime.WorkerID)
			}
			return &sandboxruntime.ExecResult{}, nil
		},
		copyIn: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			copyIns = append(copyIns, req)
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman || req.Target.Runtime.WorkerID != "worker-1" {
				t.Fatalf("CopyIn target runtime = %#v, want selected worker rootless runtime", req.Target.Runtime)
			}
			return nil
		},
		copyOut: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			copyOuts = append(copyOuts, req)
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman || req.Target.Runtime.WorkerID != "worker-1" {
				t.Fatalf("CopyOut target runtime = %#v, want selected worker rootless runtime", req.Target.Runtime)
			}
			return writeWorkerRuntimeCopyOutPayload(req)
		},
	}

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
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
			return "run-worker-rootless-copy-semantics"
		},
		now:        runSandboxTestClock(startedAt, finishedAt),
		workingDir: func() (string, error) { return projectDir, nil },
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return workerRootlessBundlePlan(projectDir), nil
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
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for explicit worker-backed run execution")
			return nil, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			return workerDriver, nil
		},
		materializeWorkspace: func(ctx context.Context, prep sandboxexec.PrepareContext, req sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
			req.BundleDir = bundleDir
			req.LocalGit = localGit
			return sandboxexec.MaterializeBundleWorkspace(ctx, prep, req)
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
		runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if len(localGit.createRequests) != 1 || len(localGit.verifyRequests) != 1 {
		t.Fatalf("local git create/verify calls = %d/%d, want 1/1", len(localGit.createRequests), len(localGit.verifyRequests))
	}
	requireWorkerRuntimeCopyIn(t, copyIns, bundleDir, "/tmp/hal-workspace-bundles/worker-rootless-sync.bundle")
	requireWorkerRuntimeCopyOutSources(t, copyOuts, []string{
		".hal/prd.json",
		".hal/progress.txt",
		".hal/recovery/workspace.patch",
		".hal/reports.tar",
	})
	manifest, loadErr := store.LoadManifest("run-worker-rootless-copy-semantics")
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	requireWorkerCopyManifestNoHostPath(t, manifest, bundleDir, copyIns[0].SourcePath)
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("manifest.Status = %q, want succeeded", manifest.Status)
	}
}

func TestWorkerRootlessAutoSandboxUsesRuntimeCopyForWorkspaceAndArtifacts(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 8, 21, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	bundleDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer
	var copyIns []sandboxruntime.CopyRequest
	var copyOuts []sandboxruntime.CopyRequest
	localGit := &workerRootlessLocalGit{bundleID: "worker-rootless-sync", syncRef: "worker-rootless-sync"}

	workerDriver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
				t.Fatalf("Exec runtime driver = %q, want rootless_podman", req.Target.Runtime.Driver)
			}
			if req.Target.Runtime.WorkerID != "worker-1" {
				t.Fatalf("Exec worker ID = %q, want worker-1", req.Target.Runtime.WorkerID)
			}
			if isWorkerAutoCommandExec(req) {
				_, _ = io.WriteString(req.Stdout, autoSandboxRemoteSuccessJSON("worker auto copy semantics")+"\n")
			}
			return &sandboxruntime.ExecResult{}, nil
		},
		copyIn: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			copyIns = append(copyIns, req)
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman || req.Target.Runtime.WorkerID != "worker-1" {
				t.Fatalf("CopyIn target runtime = %#v, want selected worker rootless runtime", req.Target.Runtime)
			}
			return nil
		},
		copyOut: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			copyOuts = append(copyOuts, req)
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman || req.Target.Runtime.WorkerID != "worker-1" {
				t.Fatalf("CopyOut target runtime = %#v, want selected worker rootless runtime", req.Target.Runtime)
			}
			return writeWorkerRuntimeCopyOutPayload(req)
		},
	}

	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
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
			return "auto-worker-rootless-copy-semantics"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return workerRootlessBundlePlan(projectDir), nil
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
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for explicit worker-backed auto execution")
			return nil, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			return workerDriver, nil
		},
		materializeWorkspace: func(ctx context.Context, prep sandboxexec.PrepareContext, req sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
			req.BundleDir = bundleDir
			req.LocalGit = localGit
			return sandboxexec.MaterializeBundleWorkspace(ctx, prep, req)
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
		runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if len(localGit.createRequests) != 1 || len(localGit.verifyRequests) != 1 {
		t.Fatalf("local git create/verify calls = %d/%d, want 1/1", len(localGit.createRequests), len(localGit.verifyRequests))
	}
	requireWorkerRuntimeCopyIn(t, copyIns, bundleDir, "/tmp/hal-workspace-bundles/worker-rootless-sync.bundle")
	requireWorkerRuntimeCopyOutSources(t, copyOuts, []string{
		".hal/prd.json",
		".hal/progress.txt",
		".hal/auto-state.json",
		".hal/recovery/workspace.patch",
		".hal/reports.tar",
	})
	manifest, loadErr := store.LoadManifest("auto-worker-rootless-copy-semantics")
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	requireWorkerCopyManifestNoHostPath(t, manifest, bundleDir, copyIns[0].SourcePath)
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("manifest.Status = %q, want succeeded", manifest.Status)
	}
}

func TestWorkerRootlessRunSandboxCollectsRecoveryAfterRemoteFailure(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 8, 30, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer
	remoteErr := errors.New("worker run command failed")
	var execCalls []string
	var copyOuts []sandboxruntime.CopyRequest

	workerDriver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman || req.Target.Runtime.WorkerID != "worker-1" {
				t.Fatalf("Exec target runtime = %#v, want selected worker rootless runtime", req.Target.Runtime)
			}
			if isWorkerOutputArtifactGenerationExec(req) {
				execCalls = append(execCalls, "recovery_generation")
				return &sandboxruntime.ExecResult{}, nil
			}
			execCalls = append(execCalls, "remote_run")
			return nil, remoteErr
		},
		copyOut: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			copyOuts = append(copyOuts, req)
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman || req.Target.Runtime.WorkerID != "worker-1" {
				t.Fatalf("CopyOut target runtime = %#v, want selected worker rootless runtime", req.Target.Runtime)
			}
			if err := os.MkdirAll(filepath.Dir(req.DestinationPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(req.DestinationPath, []byte("worker recovery payload"), 0o600)
		},
	}

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
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
			return "run-worker-rootless-failed-recovery"
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
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for explicit worker-backed run execution")
			return nil, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			return workerDriver, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
		runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
			return nil
		},
	})
	if !errors.Is(err, remoteErr) {
		t.Fatalf("runRunSandboxWithWriter() error = %v, want original worker command failure", err)
	}
	if !reflect.DeepEqual(execCalls, []string{"remote_run", "recovery_generation"}) {
		t.Fatalf("exec calls = %#v, want remote failure followed by recovery generation", execCalls)
	}
	requireWorkerRuntimeCopyOutSources(t, copyOuts, []string{".hal/recovery/workspace.patch"})

	manifest, loadErr := store.LoadManifest("run-worker-rootless-failed-recovery")
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("manifest.Status = %q, want failed", manifest.Status)
	}
	if manifest.ArtifactMetadata == nil {
		t.Fatal("ArtifactMetadata = nil, want failed worker recovery metadata")
	}
	if len(manifest.ArtifactMetadata.Collected) != 1 {
		t.Fatalf("collected = %#v, want recovery artifact", manifest.ArtifactMetadata.Collected)
	}
	recovery := manifest.ArtifactMetadata.Collected[0]
	assertRunSandboxCollectedArtifact(t, recovery, ".hal/recovery/workspace.patch", "run-worker-rootless-failed-recovery/recovery/workspace.patch")
	if payload := readRunSandboxStoreFile(t, store, recovery.StoredPath); payload != "worker recovery payload" {
		t.Fatalf("recovery payload = %q, want copied worker recovery payload", payload)
	}
	if len(manifest.ArtifactMetadata.Partial) != 0 || len(manifest.ArtifactMetadata.Warnings) != 0 {
		t.Fatalf("partial/warnings = %#v/%#v, want none after successful recovery", manifest.ArtifactMetadata.Partial, manifest.ArtifactMetadata.Warnings)
	}
	requireWorkerRecoveryMetadataSafe(t, manifest.ArtifactMetadata, projectDir)
}

func TestWorkerRootlessAutoSandboxRecordsRecoveryWarningAfterFailedCopyOut(t *testing.T) {
	startedAt := time.Date(2026, 7, 1, 8, 31, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer
	remoteErr := errors.New("worker auto command failed")
	recoveryErr := errors.New(unsafeWorkerClientFailureDetail())
	var execCalls []string
	var copyOuts []sandboxruntime.CopyRequest

	workerDriver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman || req.Target.Runtime.WorkerID != "worker-1" {
				t.Fatalf("Exec target runtime = %#v, want selected worker rootless runtime", req.Target.Runtime)
			}
			if isWorkerOutputArtifactGenerationExec(req) {
				execCalls = append(execCalls, "recovery_generation")
				return &sandboxruntime.ExecResult{}, nil
			}
			if isWorkerAutoCommandExec(req) {
				execCalls = append(execCalls, "remote_auto")
				return nil, remoteErr
			}
			t.Fatalf("unexpected worker exec args: %#v", req.Args)
			return nil, nil
		},
		copyOut: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			copyOuts = append(copyOuts, req)
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman || req.Target.Runtime.WorkerID != "worker-1" {
				t.Fatalf("CopyOut target runtime = %#v, want selected worker rootless runtime", req.Target.Runtime)
			}
			return recoveryErr
		},
	}

	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
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
			return "auto-worker-rootless-failed-recovery"
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
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for explicit worker-backed auto execution")
			return nil, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			return workerDriver, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
		runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
			return nil
		},
	})
	if !errors.Is(err, remoteErr) {
		t.Fatalf("runAutoSandboxWithWriter() error = %v, want original worker command failure", err)
	}
	if errors.Is(err, recoveryErr) {
		t.Fatalf("runAutoSandboxWithWriter() error = %v, recovery copy-out failure should remain best-effort", err)
	}
	if !reflect.DeepEqual(execCalls, []string{"remote_auto", "recovery_generation"}) {
		t.Fatalf("exec calls = %#v, want remote failure followed by recovery generation", execCalls)
	}
	requireWorkerRuntimeCopyOutSources(t, copyOuts, []string{".hal/recovery/workspace.patch"})

	manifest, loadErr := store.LoadManifest("auto-worker-rootless-failed-recovery")
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("manifest.Status = %q, want failed", manifest.Status)
	}
	if manifest.ArtifactMetadata == nil {
		t.Fatal("ArtifactMetadata = nil, want best-effort recovery warning metadata")
	}
	if len(manifest.ArtifactMetadata.Collected) != 0 {
		t.Fatalf("collected = %#v, want none after recovery copy-out failure", manifest.ArtifactMetadata.Collected)
	}
	if len(manifest.ArtifactMetadata.Partial) != 1 {
		t.Fatalf("partial = %#v, want recovery partial", manifest.ArtifactMetadata.Partial)
	}
	partial := manifest.ArtifactMetadata.Partial[0]
	if partial.Path != ".hal/recovery/workspace.patch" || strings.TrimSpace(partial.StoredPath) != "" {
		t.Fatalf("partial recovery metadata = %#v, want safe display path without stored path", partial)
	}
	if len(manifest.ArtifactMetadata.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want recovery warning", manifest.ArtifactMetadata.Warnings)
	}
	warning := manifest.ArtifactMetadata.Warnings[0]
	if warning.Artifact.Path != ".hal/recovery/workspace.patch" || warning.Phase != "recovery-copyout" || warning.Message != "sandbox execution recovery artifact copy failed" {
		t.Fatalf("warning = %#v, want sanitized recovery copy-out warning", warning)
	}
	requireWorkerRecoveryMetadataSafe(t, manifest.ArtifactMetadata, projectDir, unsafeWorkerClientFailureDetail(), workerUnsafeRemoteEndpoint(), "/tmp/private/worker-1.sock", "/workspace/.hal/tmp/session")
}

func TestWorkerRootlessFactorySandboxUsesSharedWorkerRuntimeResolver(t *testing.T) {
	projectDir := t.TempDir()
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	startedAt := time.Date(2026, 7, 1, 7, 41, 0, 0, time.UTC)
	now := func() time.Time {
		startedAt = startedAt.Add(time.Second)
		return startedAt
	}
	var out bytes.Buffer
	var workerResolverCalls int

	workerDriver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
				t.Fatalf("Exec runtime driver = %q, want rootless_podman", req.Target.Runtime.Driver)
			}
			if req.Target.Runtime.WorkerID != "worker-1" {
				t.Fatalf("Exec worker ID = %q, want worker-1", req.Target.Runtime.WorkerID)
			}
			_, _ = io.WriteString(req.Stdout, "worker-backed factory path\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

	policy := factory.DefaultFactoryPolicy()
	policy.PRCreationAllowed = false

	err := runFactoryRunWithDeps(context.Background(), projectDir, factoryRunRequest{
		BaseBranch:     "main",
		Sandbox:        true,
		SandboxHostID:  "worker-1",
		SandboxRuntime: sandboxruntime.DriverRootlessPodman,
	}, &out, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-factory-worker-rootless-shared-resolver", nil },
		now:          now,
		workingDir:   func() (string, error) { return projectDir, nil },
		currentBranch: func(string) (string, error) {
			return "feature/worker-rootless", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@example.com:org/repo.git", nil
		},
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		loadEngine: func(string) (string, error) {
			return factory.PolicyEngineCodex, nil
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
					return fakeFactorySandboxProvider{}, nil
				},
				resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
					t.Fatal("legacy runtime resolver should not run for explicit worker-backed factory execution")
					return nil, nil
				},
				resolveWorkerRuntime: func(req sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
					workerResolverCalls++
					if req.Host == nil || req.Host.ID != "worker-1" {
						t.Fatalf("worker resolver host = %#v, want worker-1", req.Host)
					}
					if req.Target.Name != "worker-rootless" {
						t.Fatalf("worker resolver target name = %q, want worker-rootless", req.Target.Name)
					}
					if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
						t.Fatalf("worker resolver runtime = %q, want rootless_podman", req.Target.Runtime.Driver)
					}
					if req.Target.Runtime.WorkerID != "worker-1" || req.Target.Runtime.RuntimeID != "ctr-worker-rootless" {
						t.Fatalf("worker resolver runtime metadata = %#v, want durable worker metadata", req.Target.Runtime)
					}
					return workerDriver, nil
				},
				bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
					return factory.BootstrapResult{}, nil
				},
				engineAuthFiles: func() []factorySandboxAuthFile {
					return nil
				},
				runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
					return nil
				},
			})
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			return workerRootlessCachedSandbox(name), nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExecWithEnv: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, _ map[string]string, out io.Writer) error {
			_, _ = io.WriteString(out, `{"schemaVersion":"verify-v1","status":"pass","summary":{"total":0},"checks":[]}`+"\n")
			return nil
		},
		statusSnapshot: func(string) (factorySnapshotArtifact, error) {
			return factorySnapshotArtifact{}, nil
		},
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) {
			return factorySnapshotArtifact{}, nil
		},
		sandboxRequests: func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
			return nil
		},
		cleanupSandbox: func(context.Context, factorySandboxCleanupRequest) error {
			t.Fatal("cleanup should not run for preserved worker-backed factory sandbox")
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v\noutput=%s", err, out.String())
	}
	if workerResolverCalls != 1 {
		t.Fatalf("worker resolver calls = %d, want 1", workerResolverCalls)
	}
	if !strings.Contains(out.String(), "worker-backed factory path") {
		t.Fatalf("output = %q, want worker-backed runtime output", out.String())
	}
	record, loadErr := store.LoadRun("run-factory-worker-rootless-shared-resolver")
	if loadErr != nil {
		t.Fatalf("LoadRun() error: %v", loadErr)
	}
	if record.Status != factory.RunStatusSucceeded {
		t.Fatalf("record.Status = %q, want succeeded", record.Status)
	}
	if record.Sandbox == nil || record.Sandbox.Runtime == nil {
		t.Fatalf("record sandbox runtime metadata = %#v, want selected worker runtime", record.Sandbox)
	}
	if record.Sandbox.Runtime.Driver != sandboxruntime.DriverRootlessPodman || record.Sandbox.Runtime.WorkerID != "worker-1" {
		t.Fatalf("record sandbox runtime = %#v, want selected worker rootless runtime", record.Sandbox.Runtime)
	}
	requireWorkerRootlessFactorySandboxMetadata(t, record.Sandbox)
}

func TestWorkerRootlessFactorySandboxPersistsSafeSandboxMetadata(t *testing.T) {
	projectDir := t.TempDir()
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := runSandboxTestClock(time.Date(2026, 7, 1, 7, 41, 30, 0, time.UTC))
	var out bytes.Buffer

	workerDriver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman ||
				req.Target.Runtime.RuntimeID != "ctr-worker-rootless" ||
				req.Target.Runtime.Image != "localhost/hal:test" ||
				req.Target.Runtime.WorkerID != "worker-1" ||
				req.Target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
				t.Fatalf("Exec target runtime = %#v, want selected worker rootless runtime", req.Target.Runtime)
			}
			_, _ = io.WriteString(req.Stdout, "worker-backed factory metadata\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:     projectDir,
		SandboxName:    "worker-rootless",
		SandboxHostID:  "worker-1",
		SandboxRuntime: sandboxruntime.DriverRootlessPodman,
		RemoteOutput:   &out,
		RunRecord: factory.RunRecord{
			RunID:      "factory-worker-rootless-safe-metadata",
			RepoPath:   filepath.Join(projectDir, "host-temp", "repo"),
			RepoRemote: "https://deploy:secret@example.test/org/repo.git?token=secret",
			BranchName: "feature/worker-rootless",
			BaseBranch: "main",
		},
		RemoteAuto: factoryRunAutoRequest{BaseBranch: "main"},
	}, factorySandboxExecutorDeps{
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
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for explicit worker-backed factory execution")
			return nil, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			return workerDriver, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
		runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v\noutput=%s", err, out.String())
	}

	record, loadErr := store.LoadRun("factory-worker-rootless-safe-metadata")
	if loadErr != nil {
		t.Fatalf("LoadRun() error: %v", loadErr)
	}
	requireWorkerRootlessFactorySandboxMetadata(t, record.Sandbox)
	requireWorkerFactorySandboxNoUnsafeDetails(t, record.Sandbox,
		"unix://",
		"/tmp/private/worker-1.sock",
		"deploy:secret",
		"example.test",
		"token=secret",
		projectDir,
		"host-temp",
	)
}

func TestWorkerRootlessFactorySandboxStreamsOutputInOrder(t *testing.T) {
	projectDir := t.TempDir()
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	startedAt := time.Date(2026, 7, 1, 8, 12, 0, 0, time.UTC)
	now := func() time.Time {
		startedAt = startedAt.Add(time.Second)
		return startedAt
	}
	var out bytes.Buffer

	workerDriver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if req.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
				t.Fatalf("Exec runtime driver = %q, want rootless_podman", req.Target.Runtime.Driver)
			}
			_, _ = io.WriteString(req.Stdout, "factory stdout one\n")
			_, _ = io.WriteString(req.Stderr, "factory stderr one\n")
			_, _ = io.WriteString(req.Stdout, "factory stdout two\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:     projectDir,
		SandboxName:    "worker-rootless",
		SandboxHostID:  "worker-1",
		SandboxRuntime: sandboxruntime.DriverRootlessPodman,
		RemoteOutput:   &out,
		RunRecord: factory.RunRecord{
			RunID:      "factory-worker-rootless-output-stream",
			RepoPath:   projectDir,
			RepoRemote: "git@example.com:org/repo.git",
			BranchName: "feature/worker-rootless",
			BaseBranch: "main",
		},
		RemoteAuto: factoryRunAutoRequest{BaseBranch: "main"},
	}, factorySandboxExecutorDeps{
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
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("legacy runtime resolver should not run for explicit worker-backed factory execution")
			return nil, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			return workerDriver, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
		runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v\noutput=%s", err, out.String())
	}
	wantOutput := "factory stdout one\nfactory stderr one\nfactory stdout two\n"
	if out.String() != wantOutput {
		t.Fatalf("output = %q, want ordered worker output %q", out.String(), wantOutput)
	}
	events, loadErr := store.LoadEvents("factory-worker-rootless-output-stream")
	if loadErr != nil {
		t.Fatalf("LoadEvents() error: %v", loadErr)
	}
	var outputLines []string
	for _, event := range events {
		if event.EventType == factory.EventTypeCommandOutputSummary {
			outputLines = append(outputLines, event.Message)
		}
	}
	wantLines := []string{"factory stdout one", "factory stderr one", "factory stdout two"}
	if strings.Join(outputLines, "\n") != strings.Join(wantLines, "\n") {
		t.Fatalf("output event lines = %#v, want %#v", outputLines, wantLines)
	}
}

func TestWorkerRootlessRunSandboxDefaultResolverBuildsClientDriver(t *testing.T) {
	deps := normalizeRunSandboxDeps(runSandboxDeps{
		resolveProvider: func(string) (sandbox.Provider, error) {
			t.Fatal("generic runtime resolver should not run for explicit worker-backed run execution")
			return nil, nil
		},
	})

	driver, handled, err := deps.resolveRunSandboxRuntimeDriver(runSandboxRequest{
		SandboxHostID:  "worker-1",
		SandboxRuntime: sandboxruntime.DriverRootlessPodman,
	}, sandboxruntime.Target{
		Name: "worker-rootless",
		Runtime: sandboxruntime.RuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			RuntimeID:      "ctr-worker-rootless",
			WorkerID:       "worker-1",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}, workerRootlessCachedSandbox("worker-rootless"))
	if err != nil {
		t.Fatalf("resolveRunSandboxRuntimeDriver() error = %v", err)
	}
	if !handled {
		t.Fatal("resolveRunSandboxRuntimeDriver() handled = false, want true")
	}
	workerDriver, ok := driver.(*sandboxworker.ClientDriver)
	if !ok {
		t.Fatalf("driver type = %T, want *sandboxworker.ClientDriver", driver)
	}
	if workerDriver.ID() != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("driver ID = %q, want rootless_podman", workerDriver.ID())
	}
}

func TestWorkerRootlessAutoSandboxDefaultResolverBuildsClientDriver(t *testing.T) {
	deps := normalizeAutoSandboxDeps(autoSandboxDeps{
		resolveProvider: func(string) (sandbox.Provider, error) {
			t.Fatal("generic runtime resolver should not run for explicit worker-backed auto execution")
			return nil, nil
		},
	})

	driver, handled, err := deps.resolveAutoSandboxRuntimeDriver(autoSandboxRequest{
		SandboxHostID:  "worker-1",
		SandboxRuntime: sandboxruntime.DriverRootlessPodman,
	}, sandboxruntime.Target{
		Name: "worker-rootless",
		Runtime: sandboxruntime.RuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			RuntimeID:      "ctr-worker-rootless",
			WorkerID:       "worker-1",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}, workerRootlessCachedSandbox("worker-rootless"))
	if err != nil {
		t.Fatalf("resolveAutoSandboxRuntimeDriver() error = %v", err)
	}
	if !handled {
		t.Fatal("resolveAutoSandboxRuntimeDriver() handled = false, want true")
	}
	workerDriver, ok := driver.(*sandboxworker.ClientDriver)
	if !ok {
		t.Fatalf("driver type = %T, want *sandboxworker.ClientDriver", driver)
	}
	if workerDriver.ID() != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("driver ID = %q, want rootless_podman", workerDriver.ID())
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

func TestWorkerMicroVMRuntimeResolverSelectsMicroVMAndDoesNotFallback(t *testing.T) {
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
				t.Fatal("resolveProvider should not run for explicit microVM runtime metadata")
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
			if err != nil {
				t.Fatalf("resolveRuntimeDriver() error = %v", err)
			}
			if driver == nil {
				t.Fatal("resolveRuntimeDriver() driver = nil, want microVM driver")
			}
			if driver.ID() != sandboxruntime.DriverMicroVM {
				t.Fatalf("driver ID = %q, want %q", driver.ID(), sandboxruntime.DriverMicroVM)
			}
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

func strictCommandMicroVMHost() *sandbox.SandboxHost {
	return &sandbox.SandboxHost{
		ID:       "strict-microvm-host",
		Name:     "strict microvm host",
		Kind:     sandbox.SandboxHostKindLocal,
		Endpoint: workerUnsafeRemoteEndpoint(),
		SupportedRuntimes: []string{
			sandboxruntime.DriverMicroVM,
		},
		Health: &sandbox.HostHealth{
			Status:  "healthy",
			Message: "token=secret",
		},
	}
}

func strictCommandMicroVMTargetWithoutReadiness(name string) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		Name:     name,
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:       "strict-microvm-host",
			Name:     "strict microvm host",
			Kind:     sandbox.SandboxHostKindLocal,
			Endpoint: workerUnsafeRemoteEndpoint(),
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverMicroVM,
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
			RuntimeID:      "strict-runtime-secret",
			Image:          "ghcr.io/private/raw-strict-microvm-image:latest",
		},
		Workspace: &sandbox.SandboxWorkspace{
			Mode:        sandbox.SandboxWorkspaceModeDirect,
			InputSource: sandbox.SandboxWorkspaceInputSourceCopy,
			Repo:        "https://alice:ghp_strict_secret@example.test/org/private-repo.git",
			Branch:      "feature/direct-host",
			SyncRef:     "/Users/alice/private/worktree",
		},
	}
}

func strictCommandCompatibilityDefaultTarget(name, runtimeDriver, isolationLevel string, workspace *sandbox.SandboxWorkspace) *sandbox.SandboxState {
	hostKind := sandbox.SandboxHostKindSSH
	if runtimeDriver == sandbox.SandboxRuntimeDriverRootlessPodman {
		hostKind = sandbox.SandboxHostKindWorker
	}
	return &sandbox.SandboxState{
		Name:     name,
		Provider: "compat",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:       "strict-compat-host",
			Name:     "strict compat host",
			Kind:     hostKind,
			Endpoint: workerUnsafeRemoteEndpoint(),
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         runtimeDriver,
			IsolationLevel: isolationLevel,
			RuntimeID:      "strict-compat-runtime-secret",
			Image:          "ghcr.io/private/raw-strict-compat-image:latest",
		},
		Workspace: workspace,
	}
}

func requireStrictCommandTargetSelectionErrorSafe(t *testing.T, message string, forbidden ...string) {
	t.Helper()
	if !strings.Contains(message, string(sandbox.SandboxSecurityCapabilityReadinessGateCodeBlocked)) {
		t.Fatalf("target-selection error = %q, want safe strict readiness code %q", message, sandbox.SandboxSecurityCapabilityReadinessGateCodeBlocked)
	}
	if !strictCommandTargetSelectionErrorHasSafeReason(message) {
		t.Fatalf("target-selection error = %q, want a safe strict readiness reason code", message)
	}
	for _, fragment := range forbidden {
		if strings.TrimSpace(fragment) == "" {
			continue
		}
		if strings.Contains(message, fragment) {
			t.Fatalf("target-selection error leaked %q: %s", fragment, message)
		}
	}
}

func strictCommandTargetSelectionErrorHasSafeReason(message string) bool {
	for _, reason := range []string{
		string(sandbox.SandboxSecurityCapabilityReadinessGateReasonReadinessMissing),
		string(sandbox.SandboxSecurityCapabilityReadinessGateReasonCapabilityUnsupported),
		string(sandbox.SandboxSecurityCapabilityReadinessGateReasonCapabilityBlocked),
		string(sandbox.SandboxSecurityCapabilityReasonMetadataEnforcementUnproven),
		string(sandbox.SandboxSecurityCapabilityReasonMicroVMReadinessMissing),
		string(sandbox.SandboxSecurityCapabilityReasonMicroVMSupportMissing),
		string(sandbox.SandboxSecurityCapabilityReasonWorkspaceDirectHostWorktree),
	} {
		if strings.Contains(message, reason) {
			return true
		}
	}
	return false
}

func strictCommandTargetForbiddenFragments() []string {
	return []string{
		"ssh://",
		"deploy:secret",
		"example.test",
		"token=secret",
		"ghp_strict_secret",
		"/tmp/private",
		"/Users/alice",
		"ghcr.io/private",
		"raw-strict-microvm-image",
		"raw-strict-compat-image",
		"strict-runtime-secret",
		"strict-compat-runtime-secret",
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
		Capacity: &sandbox.HostCapacity{MaxConcurrentSandboxes: 1},
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
		Capacity: &sandbox.HostCapacity{MaxConcurrentSandboxes: 1},
		Security: workerRootlessHostSecurity(),
	}
}

func workerRootlessHostSecurity() *sandbox.SandboxSecurity {
	return sandbox.EvaluateSandboxSecurity(sandbox.SecurityEvaluationRequest{
		RuntimeDriver:          sandbox.SandboxRuntimeDriverRootlessPodman,
		RequestedNetworkPolicy: sandbox.SandboxNetworkPolicyDenyByDefault,
		RequestedSecretModes:   []string{sandbox.SandboxSecretModeSSHAgent},
		ActiveSecretModes:      []string{sandbox.SandboxSecretModeEnv},
	})
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

func workerRootlessBundlePlan(projectDir string) sandboxworkspace.Plan {
	plan := workerRootlessPlan(projectDir)
	plan.InputSource = sandbox.SandboxWorkspaceInputSourceGitBundle
	plan.RequiresBundle = true
	return plan
}

type workerRootlessLocalGit struct {
	bundleID       string
	syncRef        string
	createRequests []sandboxworkspace.CreateBundleRequest
	verifyRequests []sandboxworkspace.VerifyBundleRequest
}

func (g *workerRootlessLocalGit) CreateBundle(_ context.Context, req sandboxworkspace.CreateBundleRequest) (sandboxworkspace.CreateBundleResult, error) {
	g.createRequests = append(g.createRequests, req)
	if err := os.WriteFile(req.DestinationPath, []byte("worker rootless bundle"), 0o600); err != nil {
		return sandboxworkspace.CreateBundleResult{}, err
	}
	return sandboxworkspace.CreateBundleResult{
		Path:    req.DestinationPath,
		ID:      firstNonEmptyForTest(g.bundleID, "worker-rootless-sync"),
		SyncRef: firstNonEmptyForTest(g.syncRef, req.Plan.SyncRef),
	}, nil
}

func (g *workerRootlessLocalGit) VerifyBundle(_ context.Context, req sandboxworkspace.VerifyBundleRequest) error {
	g.verifyRequests = append(g.verifyRequests, req)
	return nil
}

func requireWorkerRuntimeCopyIn(t *testing.T, copyIns []sandboxruntime.CopyRequest, bundleDir, wantDestination string) {
	t.Helper()
	if len(copyIns) != 1 {
		t.Fatalf("CopyIn calls = %d, want 1", len(copyIns))
	}
	copyIn := copyIns[0]
	if !strings.HasPrefix(copyIn.SourcePath, bundleDir+string(os.PathSeparator)) {
		t.Fatalf("CopyIn source = %q, want host-local bundle under %q", copyIn.SourcePath, bundleDir)
	}
	if copyIn.DestinationPath != wantDestination {
		t.Fatalf("CopyIn destination = %q, want %q", copyIn.DestinationPath, wantDestination)
	}
}

func requireWorkerRuntimeCopyOutSources(t *testing.T, copyOuts []sandboxruntime.CopyRequest, wantSuffixes []string) {
	t.Helper()
	if len(copyOuts) != len(wantSuffixes) {
		t.Fatalf("CopyOut calls = %d, want %d: %#v", len(copyOuts), len(wantSuffixes), copyOuts)
	}
	for i, wantSuffix := range wantSuffixes {
		source := filepath.ToSlash(copyOuts[i].SourcePath)
		if !strings.HasSuffix(source, wantSuffix) {
			t.Fatalf("CopyOut[%d] source = %q, want suffix %q", i, source, wantSuffix)
		}
		if strings.TrimSpace(copyOuts[i].DestinationPath) == "" {
			t.Fatalf("CopyOut[%d] destination path is empty", i)
		}
	}
}

func requireWorkerCopyManifestNoHostPath(t *testing.T, manifest *sandboxexecution.Manifest, forbidden ...string) {
	t.Helper()
	requireWorkerManifestNoUnsafeDetails(t, manifest, forbidden...)
	if manifest == nil || manifest.Workspace == nil || manifest.Workspace.InputSource != sandbox.SandboxWorkspaceInputSourceGitBundle {
		t.Fatalf("manifest workspace = %#v, want git_bundle workspace metadata", manifest)
	}
}

func requireWorkerManifestNoUnsafeDetails(t *testing.T, manifest *sandboxexecution.Manifest, forbidden ...string) {
	t.Helper()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(manifest) error: %v", err)
	}
	for _, value := range forbidden {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if strings.Contains(string(encoded), value) {
			t.Fatalf("manifest leaked host-local path %q: %s", value, encoded)
		}
	}
}

func requireWorkerRecoveryMetadataSafe(t *testing.T, metadata *sandboxexecution.ArtifactMetadata, forbidden ...string) {
	t.Helper()
	if metadata == nil {
		t.Fatal("ArtifactMetadata = nil, want recovery metadata")
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(ArtifactMetadata) error: %v", err)
	}
	payload := string(encoded)
	for _, value := range forbidden {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if strings.Contains(payload, value) {
			t.Fatalf("artifact metadata leaked unsafe value %q: %s", value, payload)
		}
	}
	for _, value := range []string{"ssh://", "deploy:secret", "token=secret", "/Users/alice", "/tmp/private", "/workspace/.hal/tmp"} {
		if strings.Contains(payload, value) {
			t.Fatalf("artifact metadata leaked unsafe detail %q: %s", value, payload)
		}
	}
}

func requireWorkerRootlessExecutionManifestMetadata(t *testing.T, manifest *sandboxexecution.Manifest) {
	t.Helper()
	if manifest == nil {
		t.Fatal("manifest = nil, want worker-backed execution metadata")
	}
	if manifest.Host == nil {
		t.Fatalf("manifest host = nil, want selected worker host metadata")
	}
	if manifest.Host.ID != "worker-1" || manifest.Host.Name != "worker one" || manifest.Host.Kind != sandbox.SandboxHostKindWorker {
		t.Fatalf("manifest host = %#v, want selected worker host identity", manifest.Host)
	}
	requireWorkerRootlessRuntimeState(t, manifest.Runtime)
	requireWorkerRootlessSandboxSecurity(t, manifest.Security)
	requireWorkerRootlessSandboxSecurity(t, manifest.Host.Security)
	requireWorkerRoutingMetadata(t, manifest.WorkerRouting)
}

func requireWorkerRootlessPersistedSandboxState(t *testing.T, state *sandbox.SandboxState) {
	t.Helper()
	if state == nil {
		t.Fatal("sandbox state = nil, want persisted worker-backed state")
	}
	if state.Host == nil || state.Host.ID != "worker-1" || state.Host.Name != "worker one" || state.Host.Kind != sandbox.SandboxHostKindWorker {
		t.Fatalf("persisted host = %#v, want selected worker host identity", state.Host)
	}
	if state.Host.Endpoint != "" || len(state.Host.SupportedRuntimes) != 0 || state.Host.Security != nil {
		t.Fatalf("persisted host = %#v, want safe sandbox host identity only", state.Host)
	}
	requireWorkerRootlessRuntimeState(t, state.Runtime)
	if state.Workspace == nil {
		t.Fatal("persisted workspace = nil, want selected workspace metadata")
	}
	if state.Workspace.Mode != sandbox.SandboxWorkspaceModeClone ||
		state.Workspace.InputSource != sandbox.SandboxWorkspaceInputSourceRemoteRef ||
		state.Workspace.Branch != "feature/worker-rootless" ||
		state.Workspace.SyncRef != "refs/remotes/origin/feature/worker-rootless" {
		t.Fatalf("persisted workspace = %#v, want selected workspace metadata", state.Workspace)
	}
	if state.Workspace.Repo != "" {
		t.Fatalf("persisted workspace repo = %q, want omitted to avoid credential-bearing URLs", state.Workspace.Repo)
	}
	payloadBytes, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal persisted state: %v", err)
	}
	payload := string(payloadBytes)
	for _, leaked := range []string{"unix://", "/tmp/private/worker-1.sock", "deploy:secret", "example.test", "token=secret"} {
		if strings.Contains(payload, leaked) {
			t.Fatalf("persisted sandbox state leaked unsafe detail %q: %s", leaked, payload)
		}
	}
}

func requireWorkerRootlessRunManifestWorkspace(t *testing.T, workspace *sandbox.SandboxWorkspace, inputSource string) {
	t.Helper()
	if workspace == nil {
		t.Fatal("manifest workspace = nil, want selected workspace metadata")
	}
	if workspace.Mode != sandbox.SandboxWorkspaceModeClone ||
		workspace.InputSource != inputSource ||
		workspace.Branch != "feature/worker-rootless" ||
		workspace.SyncRef != "refs/remotes/origin/feature/worker-rootless" {
		t.Fatalf("manifest workspace = %#v, want selected worker workspace metadata", workspace)
	}
	if workspace.Repo != "" {
		t.Fatalf("manifest workspace repo = %q, want omitted to avoid credential-bearing URLs", workspace.Repo)
	}
}

func requireWorkerRootlessRuntimeState(t *testing.T, runtime *sandbox.SandboxRuntimeState) {
	t.Helper()
	if runtime == nil {
		t.Fatal("runtime = nil, want selected worker rootless runtime")
	}
	if runtime.Driver != sandboxruntime.DriverRootlessPodman ||
		runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer ||
		runtime.RuntimeID != "ctr-worker-rootless" ||
		runtime.Image != "localhost/hal:test" ||
		runtime.WorkerID != "worker-1" {
		t.Fatalf("runtime = %#v, want selected worker rootless runtime metadata", runtime)
	}
}

func requireWorkerRootlessSandboxSecurity(t *testing.T, security *sandbox.SandboxSecurity) {
	t.Helper()
	if security == nil || security.Network == nil || security.Secrets == nil {
		t.Fatalf("security = %#v, want durable worker requested/enforced summaries", security)
	}
	network := security.Network
	if network.PolicyRequested != sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("network policyRequested = %q, want %q", network.PolicyRequested, sandbox.SandboxNetworkPolicyDenyByDefault)
	}
	if network.PolicyEnforced != sandbox.SandboxNetworkPolicyBestEffort {
		t.Fatalf("network policyEnforced = %q, want %q", network.PolicyEnforced, sandbox.SandboxNetworkPolicyBestEffort)
	}
	if network.PolicyEnforced == sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("network policyEnforced overclaims deny-by-default enforcement: %#v", network)
	}
	if network.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("network enforcementMode = %q, want %q", network.EnforcementMode, sandbox.SandboxNetworkEnforcementModeNone)
	}
	if network.EnforcementMode == sandbox.SandboxNetworkEnforcementModeFirewall ||
		network.EnforcementMode == sandbox.SandboxNetworkEnforcementModeProxy ||
		network.EnforcementMode == sandbox.SandboxNetworkEnforcementModeProxyFirewall {
		t.Fatalf("network enforcementMode overclaims worker enforcement: %#v", network)
	}
	if network.PolicyResult == nil {
		t.Fatal("network policyResult = nil, want additive worker policy result")
	}
	if network.PolicyResult.Requested.Preset != sandbox.SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("network policyResult.requested.preset = %q, want %q", network.PolicyResult.Requested.Preset, sandbox.SandboxNetworkPolicyPresetDenyByDefault)
	}
	if network.PolicyResult.Effective.Preset != sandbox.SandboxNetworkPolicyPresetLegacyDefault {
		t.Fatalf("network policyResult.effective.preset = %q, want %q", network.PolicyResult.Effective.Preset, sandbox.SandboxNetworkPolicyPresetLegacyDefault)
	}
	if network.PolicyResult.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("network policyResult.enforcementMode = %q, want %q", network.PolicyResult.EnforcementMode, sandbox.SandboxNetworkEnforcementModeNone)
	}
	if !reflect.DeepEqual(security.Secrets.RequestedModes, []string{sandbox.SandboxSecretModeSSHAgent}) {
		t.Fatalf("requested secret modes = %#v, want durable worker request", security.Secrets.RequestedModes)
	}
	if !reflect.DeepEqual(security.Secrets.ActiveModes, []string{sandbox.SandboxSecretModeEnv}) {
		t.Fatalf("active secret modes = %#v, want durable worker enforcement", security.Secrets.ActiveModes)
	}
	for _, mode := range security.Secrets.ActiveModes {
		if mode == sandbox.SandboxSecretModeHTTPProxy {
			t.Fatalf("active secret modes overclaim credential proxy support: %#v", security.Secrets.ActiveModes)
		}
	}
}

func requireWorkerRootlessFactorySandboxMetadata(t *testing.T, metadata *factory.SandboxMetadata) {
	t.Helper()
	if metadata == nil {
		t.Fatal("factory sandbox metadata = nil, want worker-backed metadata")
	}
	if metadata.Host == nil || metadata.Host.ID != "worker-1" || metadata.Host.Name != "worker one" || metadata.Host.Kind != sandbox.SandboxHostKindWorker {
		t.Fatalf("factory sandbox host = %#v, want selected worker host identity", metadata.Host)
	}
	if metadata.Runtime == nil ||
		metadata.Runtime.Driver != sandboxruntime.DriverRootlessPodman ||
		metadata.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer ||
		metadata.Runtime.RuntimeID != "ctr-worker-rootless" ||
		metadata.Runtime.Image != "localhost/hal:test" ||
		metadata.Runtime.WorkerID != "worker-1" {
		t.Fatalf("factory sandbox runtime = %#v, want selected worker rootless runtime metadata", metadata.Runtime)
	}
	requireWorkerRootlessFactorySecurity(t, metadata.Security)
	requireWorkerRoutingMetadata(t, metadata.WorkerRouting)
	if metadata.Workspace == nil ||
		metadata.Workspace.Mode != sandbox.SandboxWorkspaceModeClone ||
		metadata.Workspace.InputSource != sandbox.SandboxWorkspaceInputSourceRemoteRef ||
		metadata.Workspace.Branch != "feature/worker-rootless" ||
		metadata.Workspace.SyncRef != "main" {
		t.Fatalf("factory sandbox workspace = %#v, want selected worker workspace metadata", metadata.Workspace)
	}
}

func requireWorkerFactorySandboxNoUnsafeDetails(t *testing.T, metadata *factory.SandboxMetadata, forbidden ...string) {
	t.Helper()
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(factory sandbox metadata) error: %v", err)
	}
	payload := string(encoded)
	for _, value := range forbidden {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if strings.Contains(payload, value) {
			t.Fatalf("factory sandbox metadata leaked unsafe value %q: %s", value, payload)
		}
	}
}

func requireWorkerRootlessFactorySecurity(t *testing.T, security *factory.SandboxSecurityMetadata) {
	t.Helper()
	if security == nil || security.Network == nil || security.Secrets == nil {
		t.Fatalf("factory security = %#v, want durable worker requested/enforced summaries", security)
	}
	if security.Network.PolicyRequested != sandbox.SandboxNetworkPolicyDenyByDefault ||
		security.Network.PolicyEnforced != sandbox.SandboxNetworkPolicyBestEffort ||
		security.Network.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("factory network security = %#v, want durable worker network posture", security.Network)
	}
	if security.Network.PolicyEnforced == sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("factory network security overclaims deny-by-default enforcement: %#v", security.Network)
	}
	if security.Network.PolicyResult == nil {
		t.Fatal("factory network policyResult = nil, want additive worker policy result")
	}
	if security.Network.PolicyResult.Requested.Preset != sandbox.SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("factory policyResult.requested.preset = %q, want %q", security.Network.PolicyResult.Requested.Preset, sandbox.SandboxNetworkPolicyPresetDenyByDefault)
	}
	if security.Network.PolicyResult.Effective.Preset != sandbox.SandboxNetworkPolicyPresetLegacyDefault {
		t.Fatalf("factory policyResult.effective.preset = %q, want %q", security.Network.PolicyResult.Effective.Preset, sandbox.SandboxNetworkPolicyPresetLegacyDefault)
	}
	if security.Network.PolicyResult.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("factory policyResult.enforcementMode = %q, want %q", security.Network.PolicyResult.EnforcementMode, sandbox.SandboxNetworkEnforcementModeNone)
	}
	if !reflect.DeepEqual(security.Secrets.RequestedModes, []string{sandbox.SandboxSecretModeSSHAgent}) {
		t.Fatalf("factory requested secret modes = %#v, want durable worker request", security.Secrets.RequestedModes)
	}
	if !reflect.DeepEqual(security.Secrets.ActiveModes, []string{sandbox.SandboxSecretModeEnv}) {
		t.Fatalf("factory active secret modes = %#v, want durable worker enforcement", security.Secrets.ActiveModes)
	}
}

func requireWorkerRoutingMetadata(t *testing.T, routing *sandbox.WorkerRoutingMetadata) {
	t.Helper()
	if routing == nil {
		t.Fatal("workerRouting = nil, want selected worker route metadata")
	}
	if routing.SelectedWorkerHostID != "worker-1" ||
		routing.SelectedWorkerHostName != "worker one" ||
		routing.RuntimeDriverID != sandboxruntime.DriverRootlessPodman ||
		routing.IsolationLevel != sandbox.SandboxIsolationLevelContainer ||
		routing.EndpointSummary != "local Unix socket" {
		t.Fatalf("workerRouting = %#v, want safe selected worker route metadata", routing)
	}
}

func requireWorkerRootlessFailureManifestMetadata(t *testing.T, manifest *sandboxexecution.Manifest, sandboxName string) {
	t.Helper()
	if manifest == nil {
		t.Fatal("manifest = nil, want failed worker recovery metadata")
	}
	if manifest.SandboxName != sandboxName {
		t.Fatalf("manifest.SandboxName = %q, want %q", manifest.SandboxName, sandboxName)
	}
	if manifest.Host == nil || manifest.Host.ID != "worker-1" || manifest.Host.Name != "worker one" || manifest.Host.Kind != sandbox.SandboxHostKindWorker {
		t.Fatalf("manifest host = %#v, want selected worker host identity", manifest.Host)
	}
	requireWorkerRootlessRuntimeState(t, manifest.Runtime)
	requireWorkerRoutingMetadata(t, manifest.WorkerRouting)
}

func requireWorkerRootlessFailureFactoryMetadata(t *testing.T, metadata *factory.SandboxMetadata, sandboxName string) {
	t.Helper()
	if metadata == nil {
		t.Fatal("factory sandbox metadata = nil, want failed worker recovery metadata")
	}
	if metadata.Name != sandboxName {
		t.Fatalf("factory sandbox name = %q, want %q", metadata.Name, sandboxName)
	}
	if metadata.Host == nil || metadata.Host.ID != "worker-1" || metadata.Host.Name != "worker one" || metadata.Host.Kind != sandbox.SandboxHostKindWorker {
		t.Fatalf("factory sandbox host = %#v, want selected worker host identity", metadata.Host)
	}
	if metadata.Runtime == nil ||
		metadata.Runtime.Driver != sandboxruntime.DriverRootlessPodman ||
		metadata.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer ||
		metadata.Runtime.RuntimeID != "ctr-worker-rootless" ||
		metadata.Runtime.Image != "localhost/hal:test" ||
		metadata.Runtime.WorkerID != "worker-1" {
		t.Fatalf("factory sandbox runtime = %#v, want selected worker rootless runtime metadata", metadata.Runtime)
	}
	requireWorkerRoutingMetadata(t, metadata.WorkerRouting)
}

func requireWorkerFailureRecoveryMetadataSafe(t *testing.T, value any, forbidden ...string) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(recovery metadata) error: %v", err)
	}
	payload := string(encoded)
	for _, unsafe := range forbidden {
		if strings.TrimSpace(unsafe) == "" {
			continue
		}
		if strings.Contains(payload, unsafe) {
			t.Fatalf("recovery metadata leaked unsafe value %q: %s", unsafe, payload)
		}
	}
}

func writeUnrelatedSandboxRegistryRecords(t *testing.T) (*sandbox.SandboxHost, *sandbox.SandboxState) {
	t.Helper()
	host := &sandbox.SandboxHost{
		ID:       "unrelated-host",
		Name:     "unrelated host",
		Kind:     sandbox.SandboxHostKindWorker,
		Endpoint: "unix:///tmp/unrelated-worker.sock",
	}
	if err := sandbox.ForceWriteHost(host); err != nil {
		t.Fatalf("ForceWriteHost() error: %v", err)
	}
	state := &sandbox.SandboxState{
		ID:       "unrelated-sandbox-id",
		Name:     "unrelated-sandbox",
		Provider: "worker",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:   host.ID,
			Name: host.Name,
			Kind: host.Kind,
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver: sandboxruntime.DriverSSHMachine,
		},
	}
	if err := sandbox.ForceWriteInstance(state); err != nil {
		t.Fatalf("ForceWriteInstance() error: %v", err)
	}
	return host, state
}

func requireUnrelatedSandboxRegistryRecords(t *testing.T, host *sandbox.SandboxHost, state *sandbox.SandboxState) {
	t.Helper()
	loadedHost, err := sandbox.LoadHost(host.ID)
	if err != nil {
		t.Fatalf("LoadHost(%q) error: %v", host.ID, err)
	}
	if loadedHost.ID != host.ID || loadedHost.Name != host.Name || loadedHost.Kind != host.Kind || loadedHost.Endpoint != host.Endpoint {
		t.Fatalf("loaded host = %#v, want unrelated host preserved", loadedHost)
	}
	loadedState, err := sandbox.LoadActiveInstance(state.Name)
	if err != nil {
		t.Fatalf("LoadActiveInstance(%q) error: %v", state.Name, err)
	}
	if loadedState.ID != state.ID || loadedState.Name != state.Name || loadedState.Provider != state.Provider || loadedState.Status != state.Status {
		t.Fatalf("loaded sandbox state = %#v, want unrelated state preserved", loadedState)
	}
	if loadedState.Host == nil || loadedState.Host.ID != state.Host.ID || loadedState.Host.Name != state.Host.Name || loadedState.Host.Kind != state.Host.Kind {
		t.Fatalf("loaded sandbox host = %#v, want unrelated state host preserved", loadedState.Host)
	}
	if loadedState.Runtime == nil || loadedState.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("loaded sandbox runtime = %#v, want unrelated SSH-machine runtime preserved", loadedState.Runtime)
	}
}

func workerRootlessStoppedSandboxWithoutRuntimeDetails(name string) *sandbox.SandboxState {
	target := workerRootlessCachedSandbox(name)
	target.Status = sandbox.StatusStopped
	target.Runtime = &sandbox.SandboxRuntimeState{
		Driver:         sandboxruntime.DriverRootlessPodman,
		IsolationLevel: sandbox.SandboxIsolationLevelContainer,
	}
	return target
}

func workerRootlessStartedRuntimeTarget(req sandboxruntime.LifecycleRequest) *sandboxruntime.Target {
	target := req.Target
	target.Status = sandbox.StatusRunning
	target.Runtime = sandboxruntime.RuntimeState{
		Driver:         sandboxruntime.DriverRootlessPodman,
		RuntimeID:      "ctr-worker-rootless",
		Image:          "localhost/hal:test",
		WorkerID:       "worker-1",
		IsolationLevel: sandbox.SandboxIsolationLevelContainer,
	}
	return &target
}

func workerRootlessCreateFailureSandbox(name string) *sandbox.SandboxState {
	target := workerRootlessCachedSandbox(name)
	target.Status = sandbox.StatusUnknown
	return target
}

func writeWorkerRuntimeCopyOutPayload(req sandboxruntime.CopyRequest) error {
	if err := os.MkdirAll(filepath.Dir(req.DestinationPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(req.DestinationPath, []byte("copied:"+req.SourcePath), 0o600)
}

func isWorkerAutoCommandExec(req sandboxruntime.ExecRequest) bool {
	if len(req.Args) >= 2 && req.Args[0] == "hal" && req.Args[1] == "auto" {
		return true
	}
	command := strings.Join(req.Args, "\n")
	return strings.Contains(command, "'hal' 'auto'") || strings.Contains(command, "hal auto")
}

func firstNonEmptyForTest(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func isWorkerOutputArtifactGenerationExec(req sandboxruntime.ExecRequest) bool {
	command := strings.Join(req.Args, "\n")
	return strings.Contains(command, ".hal/recovery/workspace.patch") ||
		strings.Contains(command, ".hal/reports.tar")
}

func bootstrapWithPreparationOutput() func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
	return func(ctx context.Context, _ factory.BootstrapRequest, deps factory.BootstrapDeps) (factory.BootstrapResult, error) {
		if deps.Executor == nil {
			return factory.BootstrapResult{}, nil
		}
		_, err := deps.Executor.Run(ctx, factory.BootstrapCommand{Name: "sh", Args: []string{"-c", "true"}})
		if err != nil {
			return factory.BootstrapResult{}, err
		}
		return factory.BootstrapResult{}, nil
	}
}

func runProviderExecWithPreparationOutput(line string) func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error {
	return func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, _ map[string]string, out io.Writer) error {
		_, err := io.WriteString(out, line+"\n")
		return err
	}
}

func requireSandboxOutputSummaryPayload(t *testing.T, store sandboxexecution.Store, manifest *sandboxexecution.Manifest, path string) string {
	t.Helper()
	if manifest == nil {
		t.Fatal("manifest = nil, want output summary metadata")
	}
	if manifest.ArtifactMetadata == nil {
		t.Fatalf("manifest ArtifactMetadata = nil, want collected %s", path)
	}
	for _, artifact := range manifest.ArtifactMetadata.Collected {
		if artifact.Path == path {
			if strings.TrimSpace(artifact.StoredPath) == "" {
				t.Fatalf("artifact %s storedPath is empty", path)
			}
			return readRunSandboxStoreFile(t, store, artifact.StoredPath)
		}
	}
	t.Fatalf("manifest missing collected artifact %s: %#v", path, manifest.ArtifactMetadata.Collected)
	return ""
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

func requireWorkerLifecycleFailureMessage(t *testing.T, message, classification string) {
	t.Helper()
	for _, want := range []string{classification, sandboxruntime.DriverRootlessPodman, sandboxworker.OperationStart, "failed", "[redacted"} {
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
