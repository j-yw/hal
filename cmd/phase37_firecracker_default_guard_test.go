package cmd

import (
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"testing"
)

func TestPhase37RunAutoFactoryDefaultsDoNotSelectFirecrackerRuntime(t *testing.T) {
	runReq, err := parseRunSandboxRequest(nil, runSandboxOptions{})
	if err != nil {
		t.Fatalf("parseRunSandboxRequest() error = %v", err)
	}
	if runReq.SandboxRuntime != "" {
		t.Fatalf("run sandbox default runtime = %q, want empty default", runReq.SandboxRuntime)
	}

	autoReq, err := parseAutoSandboxRequest(nil, autoSandboxOptions{})
	if err != nil {
		t.Fatalf("parseAutoSandboxRequest() error = %v", err)
	}
	if autoReq.SandboxRuntime != "" {
		t.Fatalf("auto sandbox default runtime = %q, want empty default", autoReq.SandboxRuntime)
	}

	factoryReq, err := parseFactoryRunRequestWithTarget([]string{".hal/prd-feature.md"}, "", "main", false, true, sandboxTargetFlagValues{}, "", false, "", false, false, false, "", false)
	if err != nil {
		t.Fatalf("parseFactoryRunRequestWithTarget() error = %v", err)
	}
	if factoryReq.SandboxRuntime != "" {
		t.Fatalf("factory sandbox default runtime = %q, want empty default", factoryReq.SandboxRuntime)
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

	for _, resolver := range resolvers {
		t.Run(resolver.name, func(t *testing.T) {
			providerCalls := 0
			resolveProvider := func(providerName string) (sandbox.Provider, error) {
				providerCalls++
				if providerName != "test-provider" {
					t.Fatalf("providerName = %q, want test-provider", providerName)
				}
				return fakeFactorySandboxProvider{}, nil
			}
			driver, err := resolver.build(resolveProvider)(sandboxruntime.Target{Provider: "test-provider"})
			if err != nil {
				t.Fatalf("resolveRuntimeDriver() error = %v", err)
			}
			if driver == nil || driver.ID() != sandboxruntime.DriverSSHMachine {
				t.Fatalf("driver = %#v, want SSH-machine default", driver)
			}
			if providerCalls != 1 {
				t.Fatalf("resolveProvider calls = %d, want 1 for SSH-machine default", providerCalls)
			}
		})
	}
}
