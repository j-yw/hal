package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
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
			microVM: func() sandboxruntime.Driver {
				return fakeRuntimeResolverDriver{id: sandboxruntime.DriverMicroVM}
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
		wantErr          string
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
			name:    "worker-looking runtime driver string",
			runtime: sandboxruntime.RuntimeState{Driver: "worker_backed", WorkerID: "worker-001"},
			wantErr: `runtime driver "worker_backed" is not supported`,
		},
		{
			name: "explicit microVM metadata",
			runtime: sandboxruntime.RuntimeState{
				Driver:         sandboxruntime.DriverMicroVM,
				WorkerID:       "worker-001",
				RuntimeID:      "microvm-dev",
				IsolationLevel: sandbox.SandboxIsolationLevelVM,
			},
			wantID: sandboxruntime.DriverMicroVM,
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
				if scenario.wantErr != "" {
					if err == nil {
						t.Fatalf("resolveRuntimeDriver() error = nil, want %q", scenario.wantErr)
					}
					if !strings.Contains(err.Error(), scenario.wantErr) {
						t.Fatalf("resolveRuntimeDriver() error = %q, want %q", err.Error(), scenario.wantErr)
					}
					if driver != nil {
						t.Fatalf("resolveRuntimeDriver() driver = %#v, want nil on unsupported runtime", driver)
					}
					if providerCalls != 0 {
						t.Fatalf("resolveProvider calls = %d, want 0 for unsupported selected runtime", providerCalls)
					}
					return
				}
				if err != nil {
					t.Fatalf("resolveRuntimeDriver() error = %v", err)
				}
				if driver == nil {
					t.Fatal("resolveRuntimeDriver() returned nil driver")
				}
				if driver.ID() != scenario.wantID {
					t.Fatalf("driver ID = %q, want %q", driver.ID(), scenario.wantID)
				}
				if strings.Contains(fmt.Sprintf("%T", driver), "sandboxworker.ClientDriver") {
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

func TestSandboxRuntimeCompatRejectsUnknownSelectedRuntimeDrivers(t *testing.T) {
	targets := []sandboxruntime.Target{
		{
			Provider: "worker",
			Runtime: sandboxruntime.RuntimeState{
				Driver:   "worker_backed",
				WorkerID: "worker-a",
			},
		},
	}

	for _, target := range targets {
		t.Run(target.Runtime.Driver, func(t *testing.T) {
			driver, err := sandboxRuntimeDriverFromTargetWithFactories(target, func(string) (sandbox.Provider, error) {
				t.Fatal("resolveProvider should not run for unsupported selected runtime metadata")
				return nil, nil
			}, sandboxRuntimeDriverFactories{
				sshMachine: func(sandbox.Provider) sandboxruntime.Driver {
					t.Fatal("SSH-machine factory should not be used for unsupported selected runtime metadata")
					return nil
				},
				rootlessPodman: func() sandboxruntime.Driver {
					t.Fatal("rootless Podman factory should not be used for unsupported selected runtime metadata")
					return nil
				},
				microVM: func() sandboxruntime.Driver {
					t.Fatal("microVM factory should not be used for unsupported selected runtime metadata")
					return nil
				},
			})
			if err == nil {
				t.Fatal("sandboxRuntimeDriverFromTargetWithFactories() error = nil, want unsupported selected runtime")
			}
			if driver != nil {
				t.Fatalf("driver = %#v, want nil on unsupported selected runtime", driver)
			}
			if !strings.Contains(err.Error(), `sandbox runtime driver "`+target.Runtime.Driver+`" is not supported`) {
				t.Fatalf("error = %q, want unsupported runtime driver", err.Error())
			}
		})
	}
}

func TestSandboxRuntimeCompatSelectsMicroVMAndDefersUnavailableToDriver(t *testing.T) {
	target := sandboxruntime.Target{
		Provider: "worker",
		Runtime: sandboxruntime.RuntimeState{
			Driver:         sandboxruntime.DriverMicroVM,
			WorkerID:       "worker-a",
			RuntimeID:      "vm-123",
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
		},
	}

	driver, err := sandboxRuntimeDriverFromTargetWithFactories(target, func(string) (sandbox.Provider, error) {
		t.Fatal("resolveProvider should not run for explicit microVM runtime metadata")
		return nil, nil
	}, sandboxRuntimeDriverFactories{
		sshMachine: func(sandbox.Provider) sandboxruntime.Driver {
			t.Fatal("SSH-machine factory should not be used for explicit microVM runtime metadata")
			return nil
		},
		rootlessPodman: func() sandboxruntime.Driver {
			t.Fatal("rootless Podman factory should not be used for explicit microVM runtime metadata")
			return nil
		},
		microVM: func() sandboxruntime.Driver {
			return microvm.NewDriver(microvm.DriverOptions{
				CapabilityDetector: microvm.CapabilityDetectorFunc(func(microvm.CapabilityDetectionRequest) microvm.CapabilityReport {
					return microvm.CapabilityReport{
						OS:           "linux",
						Architecture: "amd64",
						Availability: microvm.CapabilityAvailabilityUnavailable,
						ReasonCode:   microvm.CapabilityReasonKVMDeviceMissing,
						Error:        microvm.NewUnavailableCapabilityError("detect_capability", microvm.ErrUnavailableCapability),
					}
				}),
			})
		},
	})
	if err != nil {
		t.Fatalf("sandboxRuntimeDriverFromTargetWithFactories() error = %v", err)
	}
	if driver == nil || driver.ID() != sandboxruntime.DriverMicroVM {
		t.Fatalf("driver = %#v, want microVM driver", driver)
	}

	err = driver.Delete(context.Background(), sandboxruntime.LifecycleRequest{Target: target})
	if err == nil {
		t.Fatal("microVM driver Delete() error = nil, want unavailable capability")
	}
	var operationErr *microvm.OperationError
	if !errors.As(err, &operationErr) {
		t.Fatalf("microVM driver Delete() error = %T %v, want microVM operation error", err, err)
	}
	if operationErr.Code != microvm.ErrorCodeUnavailableCapability {
		t.Fatalf("operation error code = %q, want %q", operationErr.Code, microvm.ErrorCodeUnavailableCapability)
	}
	if operationErr.Operation != microvm.OperationDelete {
		t.Fatalf("operation = %q, want %q", operationErr.Operation, microvm.OperationDelete)
	}
}

func TestProductionRuntimeResolverMicroVMFactoryDoesNotConfigureFirecrackerBackend(t *testing.T) {
	target := sandboxruntime.Target{
		Provider: "worker",
		Runtime: sandboxruntime.RuntimeState{
			Driver:         sandboxruntime.DriverMicroVM,
			WorkerID:       "worker-a",
			RuntimeID:      "vm-123",
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
		},
	}

	factoryCalls := 0
	driver, err := sandboxRuntimeDriverFromTargetWithFactories(target, func(string) (sandbox.Provider, error) {
		t.Fatal("resolveProvider should not run for explicit microVM runtime metadata")
		return nil, nil
	}, sandboxRuntimeDriverFactories{
		sshMachine: func(sandbox.Provider) sandboxruntime.Driver {
			t.Fatal("SSH-machine factory should not be used for explicit microVM runtime metadata")
			return nil
		},
		rootlessPodman: func() sandboxruntime.Driver {
			t.Fatal("rootless Podman factory should not be used for explicit microVM runtime metadata")
			return nil
		},
		microVM: func() sandboxruntime.Driver {
			factoryCalls++
			return microvm.NewDriver(microvm.DriverOptions{
				CapabilityDetector: microvm.CapabilityDetectorFunc(func(microvm.CapabilityDetectionRequest) microvm.CapabilityReport {
					return microvm.CapabilityReport{
						OS:               "linux",
						Architecture:     "amd64",
						KVMDevicePresent: true,
						Availability:     microvm.CapabilityAvailabilityAvailable,
						ReasonCode:       microvm.CapabilityReasonAvailable,
					}
				}),
			})
		},
	})
	if err != nil {
		t.Fatalf("sandboxRuntimeDriverFromTargetWithFactories() error = %v", err)
	}
	if factoryCalls != 1 {
		t.Fatalf("microVM factory calls = %d, want 1", factoryCalls)
	}
	if driver == nil {
		t.Fatal("microVM factory returned nil driver")
	}
	if driver.ID() != sandboxruntime.DriverMicroVM {
		t.Fatalf("driver ID = %q, want %q", driver.ID(), sandboxruntime.DriverMicroVM)
	}
	if typeName := fmt.Sprintf("%T", driver); strings.Contains(strings.ToLower(typeName), "firecracker") {
		t.Fatalf("microVM factory returned Firecracker type %q, want backend-neutral microVM driver", typeName)
	}

	microVMDriver, ok := driver.(*microvm.Driver)
	if !ok {
		t.Fatalf("microVM factory returned %T, want *microvm.Driver", driver)
	}
	metadata := microVMDriver.Metadata()
	if metadata.BackendConfigured {
		t.Fatalf("BackendConfigured = true, want false until Firecracker backend is explicitly injected")
	}
	if metadata.Availability != microvm.CapabilityAvailabilityUnavailable {
		t.Fatalf("Availability = %q, want %q without explicit backend", metadata.Availability, microvm.CapabilityAvailabilityUnavailable)
	}
	if metadata.ReasonCode != microvm.DriverReasonBackendNotConfigured {
		t.Fatalf("ReasonCode = %q, want %q", metadata.ReasonCode, microvm.DriverReasonBackendNotConfigured)
	}

	created, createErr := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "firecracker-dev"})
	if createErr == nil {
		t.Fatalf("Create() error = nil with target %#v, want unavailable backend-neutral microVM driver", created)
	}
}

func TestSandboxRuntimeCompatDefaultsToSSHMachineUnlessExplicitRuntimeSelected(t *testing.T) {
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
			microVM: func() sandboxruntime.Driver {
				return fakeRuntimeResolverDriver{id: sandboxruntime.DriverMicroVM}
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
		{
			name: "explicit microVM selects microVM",
			target: sandboxruntime.Target{
				Provider: "test-provider",
				Runtime:  sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverMicroVM},
			},
			wantID: sandboxruntime.DriverMicroVM,
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

func TestSandboxRuntimeTargetFromStatePreservesDurableRuntimeMetadata(t *testing.T) {
	target := sandboxRuntimeTargetFromState(&sandbox.SandboxState{
		ID:       "sandbox-001",
		Name:     "podman-dev",
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			RuntimeID:      "ctr-1",
			Image:          "localhost/hal:test",
			WorkerID:       "worker-a",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	})

	if target.Runtime.Driver != sandboxruntime.DriverRootlessPodman ||
		target.Runtime.RuntimeID != "ctr-1" ||
		target.Runtime.Image != "localhost/hal:test" ||
		target.Runtime.WorkerID != "worker-a" ||
		target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
		t.Fatalf("runtime target metadata = %#v, want durable runtime metadata preserved", target.Runtime)
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
		microVM: func() sandboxruntime.Driver {
			t.Fatal("microVM factory called from worker host metadata")
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

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
