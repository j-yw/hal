package cmd

import (
	"context"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestExistingSandboxExecutionDefaultResolversStayWorkerOptIn(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:       "registered-worker",
		Name:     "registered-worker",
		Kind:     sandbox.SandboxHostKindWorker,
		Endpoint: "unix:///tmp/private/registered-worker.sock",
		SupportedRuntimes: []string{
			sandboxruntime.DriverRootlessPodman,
			"worker_backed",
		},
		Capacity: &sandbox.HostCapacity{MaxConcurrentSandboxes: 3},
	}); err != nil {
		t.Fatalf("SaveHost(registered worker) error = %v", err)
	}

	originalFactories := defaultSandboxRuntimeDriverFactories
	t.Cleanup(func() {
		defaultSandboxRuntimeDriverFactories = originalFactories
	})
	defaultSandboxRuntimeDriverFactories = func() sandboxRuntimeDriverFactories {
		return sandboxRuntimeDriverFactories{
			sshMachine: func(sandbox.Provider) sandboxruntime.Driver {
				return fakeRuntimeResolverDriver{id: sandboxruntime.DriverSSHMachine}
			},
			rootlessPodman: func() sandboxruntime.Driver {
				return fakeRuntimeResolverDriver{id: sandboxruntime.DriverRootlessPodman}
			},
		}
	}

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

	scenarios := []struct {
		name             string
		runtime          sandboxruntime.RuntimeState
		wantID           string
		wantProviderCall bool
	}{
		{
			name:             "absent runtime metadata",
			wantID:           sandboxruntime.DriverSSHMachine,
			wantProviderCall: true,
		},
		{
			name:             "explicit SSH-machine metadata",
			runtime:          sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverSSHMachine},
			wantID:           sandboxruntime.DriverSSHMachine,
			wantProviderCall: true,
		},
		{
			name:    "explicit rootless Podman metadata",
			runtime: sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverRootlessPodman},
			wantID:  sandboxruntime.DriverRootlessPodman,
		},
		{
			name:             "worker metadata without runtime driver",
			runtime:          sandboxruntime.RuntimeState{WorkerID: "worker-001", RuntimeID: "runtime-dev"},
			wantID:           sandboxruntime.DriverSSHMachine,
			wantProviderCall: true,
		},
		{
			name:             "worker-looking runtime driver string",
			runtime:          sandboxruntime.RuntimeState{Driver: "worker_backed", WorkerID: "worker-001"},
			wantID:           sandboxruntime.DriverSSHMachine,
			wantProviderCall: true,
		},
	}

	for _, resolver := range resolvers {
		for _, scenario := range scenarios {
			t.Run(resolver.name+"/"+scenario.name, func(t *testing.T) {
				providerCalls := 0
				resolveProvider := func(providerName string) (sandbox.Provider, error) {
					providerCalls++
					if !scenario.wantProviderCall {
						t.Fatalf("resolveProvider called for %s", scenario.name)
					}
					if providerName != "test-provider" {
						t.Fatalf("providerName = %q, want test-provider", providerName)
					}
					return fakeFactorySandboxProvider{}, nil
				}

				driver, err := resolver.build(resolveProvider)(sandboxruntime.Target{
					Provider: "test-provider",
					Runtime:  scenario.runtime,
				})
				if err != nil {
					t.Fatalf("resolveRuntimeDriver() error = %v", err)
				}
				if driver == nil {
					t.Fatal("resolveRuntimeDriver() returned nil driver")
				}
				if driver.ID() != scenario.wantID {
					t.Fatalf("driver ID = %q, want %q", driver.ID(), scenario.wantID)
				}
				if _, ok := driver.(*sandboxworker.ClientDriver); ok {
					t.Fatalf("driver type = %T, want existing sandbox execution defaults to stay worker-inactive", driver)
				}

				if scenario.wantProviderCall && providerCalls != 1 {
					t.Fatalf("resolveProvider calls = %d, want 1", providerCalls)
				}
				if !scenario.wantProviderCall && providerCalls != 0 {
					t.Fatalf("resolveProvider calls = %d, want 0", providerCalls)
				}
			})
		}
	}
}

func TestSandboxRuntimeCompatDefaultsToSSHMachineUnlessRootlessExplicit(t *testing.T) {
	originalFactories := defaultSandboxRuntimeDriverFactories
	t.Cleanup(func() {
		defaultSandboxRuntimeDriverFactories = originalFactories
	})
	defaultSandboxRuntimeDriverFactories = func() sandboxRuntimeDriverFactories {
		return sandboxRuntimeDriverFactories{
			sshMachine: func(sandbox.Provider) sandboxruntime.Driver {
				return fakeRuntimeResolverDriver{id: sandboxruntime.DriverSSHMachine}
			},
			rootlessPodman: func() sandboxruntime.Driver {
				return fakeRuntimeResolverDriver{id: sandboxruntime.DriverRootlessPodman}
			},
		}
	}

	tests := []struct {
		name             string
		target           sandboxruntime.Target
		wantID           string
		wantProviderCall bool
	}{
		{
			name: "absent runtime defaults to SSH-machine",
			target: sandboxruntime.Target{
				Provider: "test-provider",
			},
			wantID:           sandboxruntime.DriverSSHMachine,
			wantProviderCall: true,
		},
		{
			name: "blank runtime driver defaults to SSH-machine",
			target: sandboxruntime.Target{
				Provider: "test-provider",
				Runtime:  sandboxruntime.RuntimeState{Driver: " \t\n "},
			},
			wantID:           sandboxruntime.DriverSSHMachine,
			wantProviderCall: true,
		},
		{
			name: "explicit SSH-machine selects SSH-machine",
			target: sandboxruntime.Target{
				Provider: "test-provider",
				Runtime:  sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverSSHMachine},
			},
			wantID:           sandboxruntime.DriverSSHMachine,
			wantProviderCall: true,
		},
		{
			name: "explicit rootless Podman selects rootless Podman",
			target: sandboxruntime.Target{
				Provider: "test-provider",
				Runtime:  sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverRootlessPodman},
			},
			wantID: sandboxruntime.DriverRootlessPodman,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			providerCalls := 0
			resolveProvider := func(providerName string) (sandbox.Provider, error) {
				providerCalls++
				if !tt.wantProviderCall {
					t.Fatalf("resolveProvider called for %s", tt.name)
				}
				if providerName != "test-provider" {
					t.Fatalf("providerName = %q, want test-provider", providerName)
				}
				return fakeFactorySandboxProvider{}, nil
			}

			driver, err := sandboxRuntimeDriverFromTarget(tt.target, resolveProvider)
			if err != nil {
				t.Fatalf("sandboxRuntimeDriverFromTarget() error = %v", err)
			}
			if driver == nil {
				t.Fatal("sandboxRuntimeDriverFromTarget() returned nil driver")
			}
			if driver.ID() != tt.wantID {
				t.Fatalf("driver ID = %q, want %q", driver.ID(), tt.wantID)
			}
			if providerCalls != boolToInt(tt.wantProviderCall) {
				t.Fatalf("resolveProvider calls = %d, want %d", providerCalls, boolToInt(tt.wantProviderCall))
			}
		})
	}
}

func TestSandboxRuntimeCompatWorkerHostMetadataDoesNotSelectRuntime(t *testing.T) {
	target := sandboxRuntimeTargetFromState(&sandbox.SandboxState{
		ID:       "sandbox-001",
		Name:     "factory-dev",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:       "registered-worker",
			Name:     "registered-worker",
			Kind:     sandbox.SandboxHostKindWorker,
			Endpoint: "unix:///tmp/private/registered-worker.sock",
			SupportedRuntimes: []string{
				sandboxruntime.DriverRootlessPodman,
				"worker_backed",
			},
		},
	})
	if target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("runtime target driver = %q, want default %q", target.Runtime.Driver, sandboxruntime.DriverSSHMachine)
	}
	if target.Runtime.WorkerID != "" || target.Runtime.RuntimeID != "" {
		t.Fatalf("runtime target worker metadata = %#v, want empty metadata without explicit runtime state", target.Runtime)
	}

	driver, err := sandboxRuntimeDriverFromTargetWithFactories(target, func(providerName string) (sandbox.Provider, error) {
		if providerName != "test-provider" {
			t.Fatalf("providerName = %q, want test-provider", providerName)
		}
		return fakeFactorySandboxProvider{}, nil
	}, sandboxRuntimeDriverFactories{
		sshMachine: func(sandbox.Provider) sandboxruntime.Driver {
			return fakeRuntimeResolverDriver{id: sandboxruntime.DriverSSHMachine}
		},
		rootlessPodman: func() sandboxruntime.Driver {
			t.Fatal("rootless Podman factory called from worker host metadata")
			return nil
		},
	})
	if err != nil {
		t.Fatalf("sandboxRuntimeDriverFromTargetWithFactories() error = %v", err)
	}
	if driver == nil || driver.ID() != sandboxruntime.DriverSSHMachine {
		t.Fatalf("driver = %#v, want SSH-machine driver", driver)
	}
}

func TestClientDriverSelectedOnlyWhenExplicitlyConstructed(t *testing.T) {
	driver, err := sandboxworker.NewClientDriver(sandboxworker.ClientDriverOptions{
		DriverID: "fake_worker_runtime",
		Client:   fakeWorkerRuntimeDriverClient{},
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}
	if driver == nil || driver.ID() != "fake_worker_runtime" {
		t.Fatalf("worker driver = %#v, want explicitly constructed fake_worker_runtime adapter", driver)
	}
}

type fakeRuntimeResolverDriver struct {
	id string
}

func (driver fakeRuntimeResolverDriver) ID() string {
	return driver.id
}

func (fakeRuntimeResolverDriver) Create(context.Context, sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	return nil, nil
}

func (fakeRuntimeResolverDriver) Start(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return &req.Target, nil
}

func (fakeRuntimeResolverDriver) Stop(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return &req.Target, nil
}

func (fakeRuntimeResolverDriver) Delete(context.Context, sandboxruntime.LifecycleRequest) error {
	return nil
}

func (fakeRuntimeResolverDriver) Inspect(_ context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	return &req.Target, nil
}

func (fakeRuntimeResolverDriver) Exec(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	return &sandboxruntime.ExecResult{}, nil
}

func (fakeRuntimeResolverDriver) CopyIn(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

func (fakeRuntimeResolverDriver) CopyOut(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

type fakeWorkerRuntimeDriverClient struct{}

func (fakeWorkerRuntimeDriverClient) Create(context.Context, string, sandboxworker.CreateRequest) (*sandboxworker.Target, error) {
	return nil, nil
}

func (fakeWorkerRuntimeDriverClient) Start(context.Context, string, sandboxworker.LifecycleRequest) (*sandboxworker.Target, error) {
	return nil, nil
}

func (fakeWorkerRuntimeDriverClient) Stop(context.Context, string, sandboxworker.LifecycleRequest) (*sandboxworker.Target, error) {
	return nil, nil
}

func (fakeWorkerRuntimeDriverClient) Delete(context.Context, string, sandboxworker.LifecycleRequest) error {
	return nil
}

func (fakeWorkerRuntimeDriverClient) Inspect(context.Context, string, sandboxworker.InspectRequest) (*sandboxworker.Target, error) {
	return nil, nil
}

func (fakeWorkerRuntimeDriverClient) Exec(context.Context, string, sandboxworker.ExecRequest) (*sandboxworker.ExecResponse, error) {
	return nil, nil
}

func (fakeWorkerRuntimeDriverClient) CopyIn(context.Context, string, sandboxworker.CopyInRequest) (*sandboxworker.CopyInResponse, error) {
	return nil, nil
}

func (fakeWorkerRuntimeDriverClient) CopyOut(context.Context, string, sandboxworker.CopyOutRequest) (*sandboxworker.CopyOutResponse, error) {
	return nil, nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
