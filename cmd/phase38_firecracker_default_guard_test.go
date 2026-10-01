package cmd

import (
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxtarget"
	"strings"
	"testing"
	"time"
)

func TestPhase38DefaultSandboxdRegistersOnlyRootlessPodman(t *testing.T) {
	flags := defaultSandboxdFlags()
	if strings.Join(flags.drivers, ",") != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("default sandboxd drivers = %#v, want only rootless_podman", flags.drivers)
	}
}

func TestPhase38RunAutoFactoryDefaultsDoNotSelectFirecrackerRuntimeOrGuestTransport(t *testing.T) {
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
			name: "firecracker-looking metadata without explicit driver",
			target: sandboxruntime.Target{
				Provider: "test-provider",
				Runtime: sandboxruntime.RuntimeState{
					RuntimeID: "fc-cached-runtime",
					Metadata: &sandboxruntime.RuntimeMetadata{
						Backend:          "firecracker",
						CapabilityLabels: []string{"guest_transport"},
					},
				},
			},
		},
	}

	for _, resolver := range phase38DefaultRuntimeResolvers() {
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
}

func TestPhase38SchedulerDefaultRequestDoesNotInferFirecrackerRuntime(t *testing.T) {
	now := time.Date(2026, 7, 3, 6, 30, 0, 0, time.UTC)
	result := sandboxtarget.Schedule(sandboxtarget.SchedulerRequest{
		Purpose: sandboxtarget.PurposeRun,
	}, sandboxtarget.CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{
				{
					ID:                "host-firecracker-capable",
					Name:              "a-firecracker-capable-worker",
					Kind:              sandbox.SandboxHostKindWorker,
					SupportedRuntimes: []string{sandboxruntime.DriverMicroVM},
					Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
				},
				{
					ID:                "host-rootless",
					Name:              "b-rootless-worker",
					Kind:              sandbox.SandboxHostKindWorker,
					SupportedRuntimes: []string{sandboxruntime.DriverRootlessPodman},
					Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
				},
			}, nil
		},
		ListLeases: func() ([]*sandbox.SandboxLease, error) { return nil, nil },
		Now:        func() time.Time { return now },
	})
	if !result.Selected() {
		t.Fatalf("Schedule() selected = false, rejection = %#v", result.Rejection)
	}
	if result.Selection.Runtime != nil {
		t.Fatalf("default scheduler selection Runtime = %#v, want nil until runtime or isolation is explicit", result.Selection.Runtime)
	}
	if result.Selection.Identity.RuntimeDriver != "" || result.Selection.Identity.RuntimeID != "" || result.Selection.Identity.IsolationLevel != "" {
		t.Fatalf("default scheduler identity inferred runtime metadata: %#v", result.Selection.Identity)
	}
}

func phase38DefaultRuntimeResolvers() []struct {
	name  string
	build func(func(string) (sandbox.Provider, error)) func(sandboxruntime.Target) (sandboxruntime.Driver, error)
} {
	return []struct {
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
}
