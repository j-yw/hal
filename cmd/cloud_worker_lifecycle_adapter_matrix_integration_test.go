//go:build integration
// +build integration

package cmd

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/cloud/deploy"
)

type workerLifecycleAdapterFixture struct {
	Name  string
	Setup func(t *testing.T) *cloudLifecycleIntegrationHarness
}

var workerLifecycleAdapterFixtures = []workerLifecycleAdapterFixture{
	{
		Name: deploy.AdapterPostgres,
		Setup: func(t *testing.T) *cloudLifecycleIntegrationHarness {
			return setupWorkerLifecycleAdapterHarness(t, deploy.AdapterPostgres)
		},
	},
	{
		Name: deploy.AdapterTurso,
		Setup: func(t *testing.T) *cloudLifecycleIntegrationHarness {
			return setupWorkerLifecycleAdapterHarness(t, deploy.AdapterTurso)
		},
	},
}

type workerLifecycleAdapterScenario struct {
	Adapter workerLifecycleAdapterFixture
	Harness *cloudLifecycleIntegrationHarness
	Runner  *workerLifecycleFlowRunner
}

func setupWorkerLifecycleAdapterHarness(t *testing.T, adapter string) *cloudLifecycleIntegrationHarness {
	t.Helper()

	h := setupCloudLifecycleIntegrationHarness(t)

	switch adapter {
	case deploy.AdapterPostgres:
		t.Setenv(deploy.EnvDBAdapter, deploy.AdapterPostgres)
		t.Setenv(deploy.EnvPostgresDSN, "postgres://hal:hal@localhost:5432/hal_integration?sslmode=disable")
		t.Setenv(deploy.EnvTursoURL, "")
		t.Setenv(deploy.EnvTursoAuthToken, "")
	case deploy.AdapterTurso:
		t.Setenv(deploy.EnvDBAdapter, deploy.AdapterTurso)
		t.Setenv(deploy.EnvTursoURL, "libsql://worker-lifecycle.integration.invalid")
		t.Setenv(deploy.EnvTursoAuthToken, "integration-token")
		t.Setenv(deploy.EnvPostgresDSN, "")
	default:
		t.Fatalf("unsupported worker lifecycle adapter %q", adapter)
	}

	return h
}

func runWorkerLifecycleAdapterMatrix(t *testing.T, scenarioID string, run func(t *testing.T, scenario workerLifecycleAdapterScenario)) {
	t.Helper()

	if strings.TrimSpace(scenarioID) == "" {
		t.Fatal("scenarioID must not be empty")
	}
	if run == nil {
		t.Fatal("scenario runner must not be nil")
	}

	for _, adapter := range workerLifecycleAdapterFixtures {
		adapter := adapter
		t.Run(fmt.Sprintf("%s/%s", adapter.Name, scenarioID), func(t *testing.T) {
			harness := adapter.Setup(t)
			if harness == nil {
				t.Fatalf("adapter %q setup returned nil harness", adapter.Name)
			}

			// Explicit teardown hook at matrix layer; harness teardown is idempotent.
			t.Cleanup(harness.Teardown)

			run(t, workerLifecycleAdapterScenario{
				Adapter: adapter,
				Harness: harness,
				Runner:  newWorkerLifecycleFlowRunner(harness),
			})
		})
	}
}

func TestWorkerLifecycleAdapterMatrixFixtures(t *testing.T) {
	got := make([]string, 0, len(workerLifecycleAdapterFixtures))
	for _, fixture := range workerLifecycleAdapterFixtures {
		if fixture.Name == "" {
			t.Fatal("adapter fixture name must not be empty")
		}
		if fixture.Setup == nil {
			t.Fatalf("adapter fixture %q setup must not be nil", fixture.Name)
		}
		got = append(got, fixture.Name)
	}

	want := []string{deploy.AdapterPostgres, deploy.AdapterTurso}
	if !slices.Equal(got, want) {
		t.Fatalf("adapter fixtures = %v, want %v", got, want)
	}
}

func TestWorkerLifecycleAdapterMatrixRunner_IsolatedSetupAndTeardownPerCase(t *testing.T) {
	origRunStoreFactory := functionPointer(runCloudStoreFactory)
	origAutoStoreFactory := functionPointer(autoCloudStoreFactory)
	origReviewStoreFactory := functionPointer(reviewCloudStoreFactory)

	seenWorkspaces := make(map[string]bool)
	seenHalDirs := make(map[string]bool)
	seenStores := make(map[*cloudLifecycleHarnessStore]bool)

	runWorkerLifecycleAdapterMatrix(t, "isolation", func(t *testing.T, scenario workerLifecycleAdapterScenario) {
		if scenario.Runner == nil {
			t.Fatal("matrix scenario runner must not be nil")
		}
		if scenario.Harness == nil {
			t.Fatal("matrix scenario harness must not be nil")
		}

		if seenWorkspaces[scenario.Harness.WorkspaceDir] {
			t.Fatalf("workspace reused across adapters: %s", scenario.Harness.WorkspaceDir)
		}
		seenWorkspaces[scenario.Harness.WorkspaceDir] = true

		if seenHalDirs[scenario.Harness.HalDir] {
			t.Fatalf("hal directory reused across adapters: %s", scenario.Harness.HalDir)
		}
		seenHalDirs[scenario.Harness.HalDir] = true

		if seenStores[scenario.Harness.Store] {
			t.Fatalf("store reused across adapters: %p", scenario.Harness.Store)
		}
		seenStores[scenario.Harness.Store] = true

		if got := os.Getenv(deploy.EnvDBAdapter); got != scenario.Adapter.Name {
			t.Fatalf("%s = %q, want %q", deploy.EnvDBAdapter, got, scenario.Adapter.Name)
		}

		if got := functionPointer(runCloudStoreFactory); got == origRunStoreFactory {
			t.Fatalf("runCloudStoreFactory was not overridden for adapter case %q", scenario.Adapter.Name)
		}
		if got := functionPointer(autoCloudStoreFactory); got == origAutoStoreFactory {
			t.Fatalf("autoCloudStoreFactory was not overridden for adapter case %q", scenario.Adapter.Name)
		}
		if got := functionPointer(reviewCloudStoreFactory); got == origReviewStoreFactory {
			t.Fatalf("reviewCloudStoreFactory was not overridden for adapter case %q", scenario.Adapter.Name)
		}
	})

	if len(seenWorkspaces) != len(workerLifecycleAdapterFixtures) {
		t.Fatalf("workspace count = %d, want %d", len(seenWorkspaces), len(workerLifecycleAdapterFixtures))
	}
	if len(seenHalDirs) != len(workerLifecycleAdapterFixtures) {
		t.Fatalf("hal dir count = %d, want %d", len(seenHalDirs), len(workerLifecycleAdapterFixtures))
	}
	if len(seenStores) != len(workerLifecycleAdapterFixtures) {
		t.Fatalf("store count = %d, want %d", len(seenStores), len(workerLifecycleAdapterFixtures))
	}

	if got := functionPointer(runCloudStoreFactory); got != origRunStoreFactory {
		t.Fatalf("runCloudStoreFactory was not restored after matrix run")
	}
	if got := functionPointer(autoCloudStoreFactory); got != origAutoStoreFactory {
		t.Fatalf("autoCloudStoreFactory was not restored after matrix run")
	}
	if got := functionPointer(reviewCloudStoreFactory); got != origReviewStoreFactory {
		t.Fatalf("reviewCloudStoreFactory was not restored after matrix run")
	}
}

func TestWorkerLifecycleAdapterMatrixRunner_SubtestNamesIncludeAdapterAndScenario(t *testing.T) {
	const scenarioID = "status_contract"

	runWorkerLifecycleAdapterMatrix(t, scenarioID, func(t *testing.T, scenario workerLifecycleAdapterScenario) {
		testName := t.Name()
		if !strings.Contains(testName, scenario.Adapter.Name) {
			t.Fatalf("subtest name %q must include adapter %q", testName, scenario.Adapter.Name)
		}
		if !strings.Contains(testName, scenarioID) {
			t.Fatalf("subtest name %q must include scenario %q", testName, scenarioID)
		}
	})
}
