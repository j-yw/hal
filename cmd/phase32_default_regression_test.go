package cmd

import (
	"context"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestPhase32DefaultRuntimeResolversDoNotConstructMicroVMWithoutExplicitRuntime(t *testing.T) {
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
	targets := []struct {
		name   string
		target sandboxruntime.Target
	}{
		{
			name: "missing runtime metadata",
			target: sandboxruntime.Target{
				Provider: "test-provider",
			},
		},
		{
			name: "blank runtime driver",
			target: sandboxruntime.Target{
				Provider: "test-provider",
				Runtime:  sandboxruntime.RuntimeState{Driver: " \t\n "},
			},
		},
		{
			name: "worker metadata without selected driver",
			target: sandboxruntime.Target{
				Provider: "test-provider",
				Runtime: sandboxruntime.RuntimeState{
					WorkerID:  "worker-with-microvm-capability",
					RuntimeID: "fc-cached-runtime",
				},
			},
		},
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
				t.Fatal("rootless Podman factory should not run for default runtime selection")
				return nil
			},
			microVM: func() sandboxruntime.Driver {
				t.Fatal("microVM factory should not run for default runtime selection")
				return nil
			},
		}
	}

	for _, resolver := range resolvers {
		for _, tt := range targets {
			t.Run(resolver.name+"/"+tt.name, func(t *testing.T) {
				providerCalls := 0
				resolveProvider := func(providerName string) (sandbox.Provider, error) {
					providerCalls++
					if providerName != "test-provider" {
						t.Fatalf("providerName = %q, want test-provider", providerName)
					}
					return fakeFactorySandboxProvider{}, nil
				}

				driver, err := resolver.build(resolveProvider)(tt.target)
				if err != nil {
					t.Fatalf("resolve runtime driver error = %v", err)
				}
				if driver == nil || driver.ID() != sandboxruntime.DriverSSHMachine {
					t.Fatalf("driver = %#v, want SSH-machine default", driver)
				}
				if providerCalls != 1 {
					t.Fatalf("resolveProvider calls = %d, want 1", providerCalls)
				}
			})
		}
	}
}

func TestPhase32CommandDefaultsDoNotImportOrConstructFirecracker(t *testing.T) {
	for _, path := range []string{
		"run_sandbox.go",
		"auto_sandbox.go",
		"factory_sandbox_executor.go",
		"sandbox_runtime_compat.go",
		"sandbox_worker_runtime.go",
		"sandboxd.go",
	} {
		t.Run(path, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("ParseFile(%s) error: %v", path, err)
			}
			for _, imported := range file.Imports {
				importPath, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					t.Fatalf("Unquote import path %s in %s: %v", imported.Path.Value, path, err)
				}
				if importPath == "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker" ||
					strings.HasPrefix(importPath, "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker/") {
					t.Fatalf("%s imports %q; command defaults must not register Firecracker without explicit backend injection", path, importPath)
				}
			}

			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile(%s) error: %v", path, err)
			}
			for _, marker := range []string{
				"firecracker.NewBackend",
				"firecracker.Backend",
				"NewBackend(firecracker.",
			} {
				if strings.Contains(string(source), marker) {
					t.Fatalf("%s contains %q; Firecracker backend construction must stay out of default command wiring", path, marker)
				}
			}
		})
	}
}

func TestPhase32DefaultTargetResolutionIgnoresMicroVMCapableCachedHosts(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	runTarget := phase32LegacyMicroVMCapableTarget("phase32-run-default")
	runResolver := &fakeDefaultSandboxResolver{t: t, target: runTarget}
	resolvedRun, err := (runSandboxDeps{
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			t.Fatal("listHosts should not run without explicit sandbox host/runtime flags")
			return nil, nil
		},
		resolveDefault: runResolver.resolve,
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run when a legacy default sandbox is selected")
			return nil, nil
		},
	}).resolveRunSandboxTarget(context.Background(), defaultRunSandboxRegressionRequest(t), os.Stderr)
	if err != nil {
		t.Fatalf("resolveRunSandboxTarget() error = %v", err)
	}
	requirePhase32LegacyDefaultRemainsSSHMachine(t, resolvedRun, runTarget.Name)

	projectDir := t.TempDir()
	autoTarget := phase32LegacyMicroVMCapableTarget("phase32-auto-default")
	autoResolver := &fakeDefaultSandboxResolver{t: t, target: autoTarget}
	resolvedAuto, err := (autoSandboxDeps{
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			t.Fatal("listHosts should not run without explicit sandbox host/runtime flags")
			return nil, nil
		},
		resolveDefault: autoResolver.resolve,
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run when a legacy default sandbox is selected")
			return nil, nil
		},
	}).resolveAutoSandboxTarget(context.Background(), defaultAutoSandboxRegressionRequest(t, projectDir), os.Stderr)
	if err != nil {
		t.Fatalf("resolveAutoSandboxTarget() error = %v", err)
	}
	requirePhase32LegacyDefaultRemainsSSHMachine(t, resolvedAuto, autoTarget.Name)

	factoryTarget := phase32LegacyMicroVMCapableTarget("phase32-factory-default")
	factoryResolver := &fakeDefaultSandboxResolver{t: t, target: factoryTarget}
	record := factory.RunRecord{
		RunID:      "phase32-factory-default",
		RepoRemote: "git@example.com:org/repo.git",
		BranchName: "feature/phase32-factory-default",
		BaseBranch: "main",
	}
	resolvedFactory, err := resolveFactorySandboxTarget(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:   t.TempDir(),
		RemoteOutput: os.Stderr,
		RunRecord:    record,
		RemoteAuto:   factoryRunAutoRequest{BaseBranch: "main"},
	}, &record, record.RepoRemote, factorySandboxExecutorDeps{
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			t.Fatal("listHosts should not run without explicit sandbox host/runtime flags")
			return nil, nil
		},
		resolveDefault: factoryResolver.resolve,
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("provision should not run when a legacy default sandbox is selected")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("resolveFactorySandboxTarget() error = %v", err)
	}
	requirePhase32LegacyDefaultRemainsSSHMachine(t, resolvedFactory, factoryTarget.Name)
	if record.Sandbox == nil {
		t.Fatal("record.Sandbox = nil, want default sandbox metadata")
	}
	if record.Sandbox.WorkerRouting != nil {
		t.Fatalf("record.Sandbox.WorkerRouting = %#v, want nil without explicit worker target flags", record.Sandbox.WorkerRouting)
	}
	if record.Sandbox.Runtime == nil || record.Sandbox.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("record.Sandbox.Runtime = %#v, want SSH-machine compatibility metadata", record.Sandbox.Runtime)
	}
}

func phase32LegacyMicroVMCapableTarget(name string) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		Name:     name,
		Provider: "worker",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:                "phase32-microvm-worker",
			Name:              "phase32 microvm worker",
			Kind:              sandbox.SandboxHostKindWorker,
			SupportedRuntimes: []string{sandboxruntime.DriverMicroVM},
			Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 1},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandboxruntime.DriverMicroVM,
			RuntimeID:      "fc-cached-runtime",
			WorkerID:       "phase32-microvm-worker",
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
		},
	}
}

func requirePhase32LegacyDefaultRemainsSSHMachine(t *testing.T, target *sandbox.SandboxState, wantName string) {
	t.Helper()
	if target == nil {
		t.Fatal("target = nil")
	}
	if target.Name != wantName {
		t.Fatalf("target.Name = %q, want %q", target.Name, wantName)
	}
	if target.Runtime == nil || target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("target.Runtime = %#v, want SSH-machine compatibility metadata", target.Runtime)
	}
	if target.Runtime.RuntimeID != "" || target.Runtime.WorkerID != "" || target.Runtime.Image != "" {
		t.Fatalf("target.Runtime = %#v, want microVM worker metadata stripped from legacy default path", target.Runtime)
	}
	if target.Host == nil || target.Host.ID != "phase32-microvm-worker" {
		t.Fatalf("target.Host = %#v, want safe cached host identity preserved", target.Host)
	}
	if target.Lease != nil {
		t.Fatalf("target.Lease = %#v, want nil without scheduler intent", target.Lease)
	}
}

func TestPhase32CommandDefaultRegressionTestsStayFakeOnly(t *testing.T) {
	for _, path := range []string{
		"phase32_default_regression_test.go",
		"sandbox_runtime_compat_test.go",
		"sandboxd_test.go",
		"sandbox_worker_routing_regression_test.go",
		"sandbox_scheduler_legacy_compat_test.go",
	} {
		t.Run(path, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("ParseFile(%s) error: %v", path, err)
			}
			for _, imported := range file.Imports {
				importPath, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					t.Fatalf("Unquote import path %s in %s: %v", imported.Path.Value, path, err)
				}
				for _, forbidden := range []string{
					"github.com/docker/docker",
					"github.com/containers/podman",
					"github.com/firecracker-microvm",
					"libvirt.org/go/libvirt",
					"google.golang.org/grpc",
				} {
					if importPath == forbidden || strings.HasPrefix(importPath, forbidden+"/") {
						t.Fatalf("%s imports %q; Phase 32 default regression tests must stay fake-only", path, importPath)
					}
				}
			}

			source, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatalf("ReadFile(%s) error: %v", path, err)
			}
			for _, marker := range []string{
				phase32Marker("HAL", "_FIRECRACKER"),
				phase32Marker("HAL", "_PODMAN_TEST_IMAGE"),
				phase32Marker("HAL", "_WORKER_INTEGRATION_"),
				phase32Marker("/dev", "/kvm"),
				phase32Marker("firecracker", ".NewMachine"),
				phase32Marker("net", ".Listen("),
			} {
				if strings.Contains(string(source), marker) {
					t.Fatalf("%s contains %q; Phase 32 default regression tests must not require live runtimes, sockets, or integration env", path, marker)
				}
			}
		})
	}
}

func phase32Marker(parts ...string) string {
	return strings.Join(parts, "")
}
