package cmd

import (
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
	"github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestExistingSandboxExecutionDefaultResolversStayInactiveForWorkerAdapter(t *testing.T) {
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
		runtimeDriver    string
		wantID           string
		wantProviderCall bool
		assertType       func(*testing.T, sandboxruntime.Driver)
	}{
		{
			name:             "absent runtime metadata",
			wantID:           sandboxruntime.DriverSSHMachine,
			wantProviderCall: true,
			assertType: func(t *testing.T, driver sandboxruntime.Driver) {
				t.Helper()
				if _, ok := driver.(*sshmachine.Driver); !ok {
					t.Fatalf("driver type = %T, want *sshmachine.Driver", driver)
				}
			},
		},
		{
			name:             "explicit SSH-machine metadata",
			runtimeDriver:    sandboxruntime.DriverSSHMachine,
			wantID:           sandboxruntime.DriverSSHMachine,
			wantProviderCall: true,
			assertType: func(t *testing.T, driver sandboxruntime.Driver) {
				t.Helper()
				if _, ok := driver.(*sshmachine.Driver); !ok {
					t.Fatalf("driver type = %T, want *sshmachine.Driver", driver)
				}
			},
		},
		{
			name:          "explicit rootless Podman metadata",
			runtimeDriver: sandboxruntime.DriverRootlessPodman,
			wantID:        sandboxruntime.DriverRootlessPodman,
			assertType: func(t *testing.T, driver sandboxruntime.Driver) {
				t.Helper()
				if _, ok := driver.(*rootlesspodman.Driver); !ok {
					t.Fatalf("driver type = %T, want *rootlesspodman.Driver", driver)
				}
			},
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
					Runtime: sandboxruntime.RuntimeState{
						Driver: scenario.runtimeDriver,
					},
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
				scenario.assertType(t, driver)

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
