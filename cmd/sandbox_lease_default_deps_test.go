package cmd

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
)

type normalizedSandboxLeaseDeps struct {
	list    func() ([]*sandbox.SandboxLease, error)
	acquire func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error)
	release func(string) (*sandbox.SandboxLease, error)
}

func TestProductionSandboxDependencyDefaultsUseDurableLeaseStore(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", configHome)
	now := time.Date(2026, 7, 12, 17, 0, 0, 0, time.UTC)

	cases := []struct {
		name      string
		normalize func() normalizedSandboxLeaseDeps
	}{
		{
			name: "run",
			normalize: func() normalizedSandboxLeaseDeps {
				input := defaultRunSandboxDeps
				input.now = func() time.Time { return now }
				deps := normalizeRunSandboxDeps(input)
				return normalizedSandboxLeaseDeps{list: deps.listLeases, acquire: deps.acquireLease, release: deps.releaseLease}
			},
		},
		{
			name: "auto",
			normalize: func() normalizedSandboxLeaseDeps {
				input := defaultAutoSandboxDeps
				input.now = func() time.Time { return now }
				deps := normalizeAutoSandboxDeps(input)
				return normalizedSandboxLeaseDeps{list: deps.listLeases, acquire: deps.acquireLease, release: deps.releaseLease}
			},
		},
		{
			name: "factory",
			normalize: func() normalizedSandboxLeaseDeps {
				input := defaultFactorySandboxExecutorDeps
				input.now = func() time.Time { return now }
				deps := normalizeFactorySandboxExecutorDeps(input)
				return normalizedSandboxLeaseDeps{list: deps.listLeases, acquire: deps.acquireLease, release: deps.releaseLease}
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			deps := tt.normalize()
			leaseID := "production-default-" + tt.name
			lease, err := deps.acquire(sandbox.SandboxLeaseAcquireRequest{
				ID:          leaseID,
				ResourceKey: "host:production-" + tt.name,
				Holder:      tt.name + ":default",
				Purpose:     sandbox.SandboxLeasePurposeRun,
				RunID:       leaseID,
			}, sandboxCommandLeaseTTL)
			if err != nil {
				t.Fatalf("acquire default lease: %v", err)
			}
			if lease == nil || lease.ID != leaseID {
				t.Fatalf("acquired lease = %#v, want ID %q", lease, leaseID)
			}

			leases, err := deps.list()
			if err != nil {
				t.Fatalf("list default leases: %v", err)
			}
			if !sandboxLeaseListContainsID(leases, leaseID) {
				t.Fatalf("default lease list = %#v, want durable lease %q", leases, leaseID)
			}
			if _, err := deps.release(leaseID); err != nil {
				t.Fatalf("release default lease: %v", err)
			}
		})
	}

	leaseFiles, err := filepath.Glob(filepath.Join(configHome, "sandbox-leases", "*.json"))
	if err != nil {
		t.Fatalf("glob durable lease files: %v", err)
	}
	if len(leaseFiles) != len(cases) {
		t.Fatalf("durable lease files = %v, want %d", leaseFiles, len(cases))
	}
}

func TestInjectedCustomExecutionStoresKeepDefaultLeaseStateIsolated(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", configHome)
	now := time.Date(2026, 7, 12, 17, 30, 0, 0, time.UTC)

	cases := []struct {
		name      string
		normalize func() normalizedSandboxLeaseDeps
	}{
		{
			name: "run",
			normalize: func() normalizedSandboxLeaseDeps {
				deps := normalizeRunSandboxDeps(runSandboxDeps{
					defaultStore: func() (sandboxexecution.Store, error) {
						return sandboxexecution.NewStore(filepath.Join(t.TempDir(), "run-executions")), nil
					},
					now: func() time.Time { return now },
				})
				return normalizedSandboxLeaseDeps{list: deps.listLeases, acquire: deps.acquireLease, release: deps.releaseLease}
			},
		},
		{
			name: "auto",
			normalize: func() normalizedSandboxLeaseDeps {
				deps := normalizeAutoSandboxDeps(autoSandboxDeps{
					defaultStore: func() (sandboxexecution.Store, error) {
						return sandboxexecution.NewStore(filepath.Join(t.TempDir(), "auto-executions")), nil
					},
					now: func() time.Time { return now },
				})
				return normalizedSandboxLeaseDeps{list: deps.listLeases, acquire: deps.acquireLease, release: deps.releaseLease}
			},
		},
		{
			name: "factory",
			normalize: func() normalizedSandboxLeaseDeps {
				deps := normalizeFactorySandboxExecutorDeps(factorySandboxExecutorDeps{
					defaultStore: func() (factory.Store, error) {
						return factory.NewStore(filepath.Join(t.TempDir(), "factory")), nil
					},
					now: func() time.Time { return now },
				})
				return normalizedSandboxLeaseDeps{list: deps.listLeases, acquire: deps.acquireLease, release: deps.releaseLease}
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			deps := tt.normalize()
			leaseID := "custom-store-" + tt.name
			lease, err := deps.acquire(sandbox.SandboxLeaseAcquireRequest{
				ID:          leaseID,
				ResourceKey: "host:custom-" + tt.name,
				Holder:      tt.name + ":custom",
				Purpose:     sandbox.SandboxLeasePurposeRun,
				RunID:       leaseID,
			}, sandboxCommandLeaseTTL)
			if err != nil {
				t.Fatalf("acquire isolated lease: %v", err)
			}
			if lease == nil || lease.ID != leaseID {
				t.Fatalf("isolated lease = %#v, want ID %q", lease, leaseID)
			}
			leases, err := deps.list()
			if err != nil {
				t.Fatalf("list isolated leases: %v", err)
			}
			if len(leases) != 0 {
				t.Fatalf("isolated default leases = %#v, want empty in-memory view", leases)
			}
			if _, err := deps.release(leaseID); err != nil {
				t.Fatalf("release isolated lease: %v", err)
			}
		})
	}

	leaseFiles, err := filepath.Glob(filepath.Join(configHome, "sandbox-leases", "*"))
	if err != nil {
		t.Fatalf("glob isolated lease directory: %v", err)
	}
	if len(leaseFiles) != 0 {
		t.Fatalf("custom stores wrote global lease state: %v", leaseFiles)
	}
}

func sandboxLeaseListContainsID(leases []*sandbox.SandboxLease, id string) bool {
	for _, lease := range leases {
		if lease != nil && lease.ID == id {
			return true
		}
	}
	return false
}
