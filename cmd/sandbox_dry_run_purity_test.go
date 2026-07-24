package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestRunSandboxDryRunReturnsBeforeForbiddenBoundaries(t *testing.T) {
	projectDir := t.TempDir()
	writeRunSandboxConfig(t, projectDir, `sandbox:
  env:
    RAW_SECRET: "ghp_l1_run_secret_should_not_render"
  networkPolicy:
    preset: allow_listed
    rules:
      - kind: domain
        value: private.run.example
        decision: allow
  secrets:
    requestedModes:
      - env
`)
	storeRoot := filepath.Join(t.TempDir(), "sandbox-executions")
	var out bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, []string{"4"}, runSandboxOptions{
		Base:                  "main",
		BaseChanged:           true,
		DryRun:                true,
		DryRunChanged:         true,
		JSON:                  true,
		JSONChanged:           true,
		SandboxName:           "preview-run",
		SandboxNameChanged:    true,
		SandboxHostID:         "worker-preview",
		SandboxHostChanged:    true,
		SandboxRuntime:        sandboxruntime.DriverRootlessPodman,
		SandboxRuntimeChanged: true,
		SandboxSyncOut:        true,
		SandboxSyncOutChanged: true,
		SandboxApply:          true,
		SandboxApplyChanged:   true,
	}, &out, io.Discard, forbiddenRunSandboxDryRunDeps(projectDir))
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() dry-run error: %v\nstdout=%s", err, out.String())
	}

	assertSandboxDryRunPreview(t, out.Bytes(), "run", "preview-run", "worker-preview", sandboxruntime.DriverRootlessPodman)
	for _, forbidden := range []string{
		"ghp_l1_run_secret_should_not_render",
		"private.run.example",
		projectDir,
		storeRoot,
	} {
		if strings.Contains(out.String(), forbidden) {
			t.Fatalf("dry-run preview leaked forbidden value %q: %s", forbidden, out.String())
		}
	}
	if _, err := os.Stat(storeRoot); !os.IsNotExist(err) {
		t.Fatalf("execution store path exists after dry-run: err=%v", err)
	}
}

func TestAutoSandboxDryRunReturnsBeforeForbiddenBoundaries(t *testing.T) {
	projectDir := t.TempDir()
	writeRunSandboxConfig(t, projectDir, `sandbox:
  env:
    RAW_SECRET: "ghp_l1_auto_secret_should_not_render"
  networkPolicy:
    preset: deny_by_default
    rules:
      - kind: domain
        value: private.auto.example
        decision: deny
  secrets:
    requestedModes:
      - file_tmpfs
`)
	storeRoot := filepath.Join(t.TempDir(), "sandbox-executions")
	var out bytes.Buffer

	err := runAutoSandboxWithWriter(context.Background(), nil, []string{".hal/prd-feature.md"}, projectDir, autoSandboxOptions{
		DryRun:                true,
		DryRunChanged:         true,
		Base:                  "main",
		BaseChanged:           true,
		JSON:                  true,
		JSONChanged:           true,
		SandboxName:           "preview-auto",
		SandboxNameChanged:    true,
		SandboxHostID:         "worker-preview",
		SandboxHostChanged:    true,
		SandboxRuntime:        sandboxruntime.DriverMicroVM,
		SandboxRuntimeChanged: true,
		SandboxSyncOut:        true,
		SandboxSyncOutChanged: true,
		SandboxApply:          true,
		SandboxApplyChanged:   true,
	}, &out, io.Discard, forbiddenAutoSandboxDryRunDeps())
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() dry-run error: %v\nstdout=%s", err, out.String())
	}

	assertSandboxDryRunPreview(t, out.Bytes(), "auto", "preview-auto", "worker-preview", sandboxruntime.DriverMicroVM)
	for _, forbidden := range []string{
		"ghp_l1_auto_secret_should_not_render",
		"private.auto.example",
		projectDir,
		storeRoot,
	} {
		if strings.Contains(out.String(), forbidden) {
			t.Fatalf("dry-run preview leaked forbidden value %q: %s", forbidden, out.String())
		}
	}
	if _, err := os.Stat(storeRoot); !os.IsNotExist(err) {
		t.Fatalf("execution store path exists after dry-run: err=%v", err)
	}
}

func TestSandboxDryRunHumanPreviewDoesNotClaimExistenceOrEnforcement(t *testing.T) {
	tests := []struct {
		name string
		run  func(io.Writer) error
	}{
		{
			name: "run",
			run: func(out io.Writer) error {
				projectDir := t.TempDir()
				return runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
					Base:          "main",
					BaseChanged:   true,
					DryRun:        true,
					DryRunChanged: true,
				}, out, io.Discard, forbiddenRunSandboxDryRunDeps(projectDir))
			},
		},
		{
			name: "auto",
			run: func(out io.Writer) error {
				return runAutoSandboxWithWriter(context.Background(), nil, nil, t.TempDir(), autoSandboxOptions{
					Base:          "main",
					BaseChanged:   true,
					DryRun:        true,
					DryRunChanged: true,
				}, out, io.Discard, forbiddenAutoSandboxDryRunDeps())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := tt.run(&out); err != nil {
				t.Fatalf("sandbox dry-run error: %v\nstdout=%s", err, out.String())
			}
			preview := out.String()
			for _, want := range []string{
				"Sandbox dry-run preview",
				"Target intent:",
				"Workspace intent:",
				"Security intent:",
				"resolution=unresolved",
				"enforcement=unresolved",
				"active=false",
				"Resources created: false",
			} {
				if !strings.Contains(preview, want) {
					t.Fatalf("human preview missing %q:\n%s", want, preview)
				}
			}
			for _, misleading := range []string{
				"status=running",
				"status=succeeded",
				"enforcement=active",
				"Sandbox exists: true",
			} {
				if strings.Contains(preview, misleading) {
					t.Fatalf("human preview contains misleading claim %q:\n%s", misleading, preview)
				}
			}
		})
	}
}

func assertSandboxDryRunPreview(t *testing.T, payload []byte, purpose, sandboxName, hostID, runtimeDriver string) {
	t.Helper()
	var preview struct {
		OK               bool   `json:"ok"`
		DryRun           bool   `json:"dryRun"`
		Purpose          string `json:"purpose"`
		ResourcesCreated bool   `json:"resourcesCreated"`
		Target           struct {
			SandboxName string `json:"sandboxName"`
			HostID      string `json:"hostId"`
			Runtime     string `json:"runtime"`
			Resolution  string `json:"resolution"`
		} `json:"target"`
		Workspace struct {
			Mode       string `json:"mode"`
			Resolution string `json:"resolution"`
		} `json:"workspace"`
		Security struct {
			NetworkPolicy    string   `json:"networkPolicy"`
			RequestedModes   []string `json:"requestedSecretModes"`
			Enforcement      string   `json:"enforcement"`
			Active           bool     `json:"active"`
			NetworkRuleCount int      `json:"networkRuleCount"`
		} `json:"security"`
		UnresolvedRequirements []string `json:"unresolvedRequirements"`
	}
	if err := json.Unmarshal(payload, &preview); err != nil {
		t.Fatalf("decode sandbox dry-run preview: %v\npayload=%s", err, payload)
	}
	if !preview.OK || !preview.DryRun || preview.ResourcesCreated {
		t.Fatalf("preview success/purity flags = ok:%t dryRun:%t resourcesCreated:%t", preview.OK, preview.DryRun, preview.ResourcesCreated)
	}
	if preview.Purpose != purpose {
		t.Fatalf("purpose = %q, want %q", preview.Purpose, purpose)
	}
	if preview.Target.SandboxName != sandboxName || preview.Target.HostID != hostID || preview.Target.Runtime != runtimeDriver {
		t.Fatalf("target = %#v, want sandbox=%q host=%q runtime=%q", preview.Target, sandboxName, hostID, runtimeDriver)
	}
	if preview.Target.Resolution != "unresolved" || preview.Workspace.Resolution != "unresolved" {
		t.Fatalf("target/workspace resolution = %q/%q, want unresolved", preview.Target.Resolution, preview.Workspace.Resolution)
	}
	if preview.Workspace.Mode != sandbox.SandboxWorkspaceModeClone {
		t.Fatalf("workspace mode = %q, want %q", preview.Workspace.Mode, sandbox.SandboxWorkspaceModeClone)
	}
	if preview.Security.Enforcement != "unresolved" || preview.Security.Active {
		t.Fatalf("security enforcement/active = %q/%t, want unresolved/false", preview.Security.Enforcement, preview.Security.Active)
	}
	if preview.Security.NetworkPolicy == "" || preview.Security.NetworkRuleCount != 1 || len(preview.Security.RequestedModes) != 1 {
		t.Fatalf("security intent missing requested policy summary: %#v", preview.Security)
	}
	if len(preview.UnresolvedRequirements) == 0 {
		t.Fatal("unresolvedRequirements is empty")
	}
}

func forbiddenRunSandboxDryRunDeps(projectDir string) runSandboxDeps {
	return runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			panicForbiddenSandboxDryRunBoundary("open execution store")
			return sandboxexecution.Store{}, nil
		},
		newExecutionID: func(time.Time) string {
			panicForbiddenSandboxDryRunBoundary("allocate execution id")
			return ""
		},
		now: func() time.Time {
			panicForbiddenSandboxDryRunBoundary("start durable execution clock")
			return time.Time{}
		},
		workingDir: func() (string, error) {
			return projectDir, nil
		},
		currentBranch: func(string) (string, error) {
			panicForbiddenSandboxDryRunBoundary("resolve workspace branch")
			return "", nil
		},
		repoRemote: func(string) (string, error) {
			panicForbiddenSandboxDryRunBoundary("resolve workspace remote")
			return "", nil
		},
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			panicForbiddenSandboxDryRunBoundary("plan live workspace")
			return sandboxworkspace.Plan{}, nil
		},
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			panicForbiddenSandboxDryRunBoundary("load sandbox")
			return nil, nil
		},
		listSandboxes: func() ([]*sandbox.SandboxState, error) {
			panicForbiddenSandboxDryRunBoundary("list sandboxes")
			return nil, nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			panicForbiddenSandboxDryRunBoundary("list hosts")
			return nil, nil
		},
		listLeases: func() ([]*sandbox.SandboxLease, error) {
			panicForbiddenSandboxDryRunBoundary("list leases")
			return nil, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			panicForbiddenSandboxDryRunBoundary("resolve default target")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			panicForbiddenSandboxDryRunBoundary("provision target")
			return nil, nil
		},
		acquireLease: func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
			panicForbiddenSandboxDryRunBoundary("acquire lease")
			return nil, nil
		},
		releaseLease: func(string) (*sandbox.SandboxLease, error) {
			panicForbiddenSandboxDryRunBoundary("release lease")
			return nil, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			panicForbiddenSandboxDryRunBoundary("resolve provider")
			return nil, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			panicForbiddenSandboxDryRunBoundary("resolve runtime driver")
			return nil, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			panicForbiddenSandboxDryRunBoundary("resolve worker runtime")
			return nil, nil
		},
		persistSandboxState: func(*sandbox.SandboxState) error {
			panicForbiddenSandboxDryRunBoundary("persist sandbox state")
			return nil
		},
		runProviderExecWithEnv: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error {
			panicForbiddenSandboxDryRunBoundary("provider exec")
			return nil
		},
		runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
			panicForbiddenSandboxDryRunBoundary("provider script")
			return nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			panicForbiddenSandboxDryRunBoundary("read engine auth")
			return nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			panicForbiddenSandboxDryRunBoundary("bootstrap workspace")
			return factory.BootstrapResult{}, nil
		},
		materializeWorkspace: func(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
			panicForbiddenSandboxDryRunBoundary("materialize workspace")
			return sandboxworkspace.MaterializationResult{}, nil
		},
		prepareCommandContext: func(context.Context, sandboxexec.PrepareContext, string, string, io.Writer) (sandboxworkspace.MaterializationOperation, error) {
			panicForbiddenSandboxDryRunBoundary("prepare command context")
			return sandboxworkspace.MaterializationOperation{}, nil
		},
		applySyncOut: func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
			panicForbiddenSandboxDryRunBoundary("sync out or apply")
			return sandboxworkspace.SafeApplyResult{}, nil
		},
		execute: func(context.Context, runSandboxRequest, io.Writer, io.Writer, runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
			panicForbiddenSandboxDryRunBoundary("sandbox execution")
			return runSandboxExecutionResult{}, nil
		},
	}
}

func forbiddenAutoSandboxDryRunDeps() autoSandboxDeps {
	runDeps := forbiddenRunSandboxDryRunDeps("")
	return autoSandboxDeps{
		defaultStore:           runDeps.defaultStore,
		newExecutionID:         runDeps.newExecutionID,
		now:                    runDeps.now,
		planWorkspace:          runDeps.planWorkspace,
		loadSandbox:            runDeps.loadSandbox,
		listSandboxes:          runDeps.listSandboxes,
		listHosts:              runDeps.listHosts,
		listLeases:             runDeps.listLeases,
		resolveDefault:         runDeps.resolveDefault,
		provision:              runDeps.provision,
		acquireLease:           runDeps.acquireLease,
		releaseLease:           runDeps.releaseLease,
		resolveProvider:        runDeps.resolveProvider,
		resolveRuntimeDriver:   runDeps.resolveRuntimeDriver,
		resolveWorkerRuntime:   runDeps.resolveWorkerRuntime,
		persistSandboxState:    runDeps.persistSandboxState,
		runProviderExecWithEnv: runDeps.runProviderExecWithEnv,
		runProviderScript:      runDeps.runProviderScript,
		engineAuthFiles:        runDeps.engineAuthFiles,
		bootstrap:              runDeps.bootstrap,
		materializeWorkspace:   runDeps.materializeWorkspace,
		prepareCommandContext:  runDeps.prepareCommandContext,
		applySyncOut:           runDeps.applySyncOut,
		execute: func(context.Context, autoSandboxRequest, io.Writer, io.Writer, autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
			panicForbiddenSandboxDryRunBoundary("sandbox execution")
			return autoSandboxExecutionResult{}, nil
		},
	}
}

func panicForbiddenSandboxDryRunBoundary(name string) {
	panic("sandbox dry-run crossed forbidden boundary: " + name)
}
