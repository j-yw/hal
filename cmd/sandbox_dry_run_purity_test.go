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
    activeModes:
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
    activeModes:
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

func TestAutoSandboxDryRunEntryModeUsesStaticInputIntent(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want autoEntryMode
	}{
		{name: "no input", want: autoEntryModeReportDiscovery},
		{name: "whitespace input", args: []string{" \t "}, want: autoEntryModeReportDiscovery},
		{name: "markdown input", args: []string{".hal/prd-feature.md"}, want: autoEntryModeMarkdownPath},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			err := runAutoSandboxWithWriter(context.Background(), nil, tt.args, t.TempDir(), autoSandboxOptions{
				DryRun: true,
				JSON:   true,
			}, &out, io.Discard, forbiddenAutoSandboxDryRunDeps())
			if err != nil {
				t.Fatalf("runAutoSandboxWithWriter() dry-run error: %v\nstdout=%s", err, out.String())
			}

			var result struct {
				EntryMode string `json:"entryMode"`
			}
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatalf("decode sandbox dry-run preview: %v\npayload=%s", err, out.Bytes())
			}
			if result.EntryMode != string(tt.want) {
				t.Fatalf("entryMode = %q, want %q", result.EntryMode, tt.want)
			}
		})
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

func TestRunSandboxDryRunCommandFlagPathIsPure(t *testing.T) {
	projectDir := t.TempDir()
	writeRunSandboxConfig(t, projectDir, `sandbox:
  networkPolicy:
    preset: allow_listed
    rules:
      - kind: domain
        value: command.run.example
        decision: allow
  secrets:
    requestedModes:
      - env
`)
	t.Chdir(projectDir)

	originalDeps := defaultRunSandboxDeps
	defaultRunSandboxDeps = forbiddenRunSandboxDryRunDeps(projectDir)
	t.Cleanup(func() {
		defaultRunSandboxDeps = originalDeps
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := newRunSandboxTestCommand(&out, &errOut)
	for flag, value := range map[string]string{
		"sandbox":         "true",
		"sandbox-name":    "command-run",
		"sandbox-host":    "worker-command",
		"sandbox-runtime": sandboxruntime.DriverRootlessPodman,
		"dry-run":         "true",
		"json":            "true",
		"base":            "main",
	} {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("set %s: %v", flag, err)
		}
	}

	if err := runRunWithWriter(cmd, nil, &errOut); err != nil {
		t.Fatalf("hal run --sandbox --dry-run error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	assertSandboxDryRunPreview(t, out.Bytes(), "run", "command-run", "worker-command", sandboxruntime.DriverRootlessPodman)
}

func TestAutoSandboxDryRunCommandFlagPathIsPure(t *testing.T) {
	projectDir := t.TempDir()
	writeRunSandboxConfig(t, projectDir, `sandbox:
  networkPolicy:
    preset: deny_by_default
    rules:
      - kind: domain
        value: command.auto.example
        decision: deny
  secrets:
    requestedModes:
      - file_tmpfs
`)

	originalDeps := defaultAutoSandboxDeps
	defaultAutoSandboxDeps = forbiddenAutoSandboxDryRunDeps()
	t.Cleanup(func() {
		defaultAutoSandboxDeps = originalDeps
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := newAutoSandboxTestCommand(&out, &errOut)
	for flag, value := range map[string]string{
		"sandbox":         "true",
		"sandbox-name":    "command-auto",
		"sandbox-host":    "worker-command",
		"sandbox-runtime": sandboxruntime.DriverMicroVM,
		"dry-run":         "true",
		"json":            "true",
		"base":            "main",
	} {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("set %s: %v", flag, err)
		}
	}

	if err := runAutoWithDir(cmd, []string{".hal/prd-feature.md"}, projectDir); err != nil {
		t.Fatalf("hal auto --sandbox --dry-run error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	assertSandboxDryRunPreview(t, out.Bytes(), "auto", "command-auto", "worker-command", sandboxruntime.DriverMicroVM)
}

func TestSandboxDryRunPreviewRedactsUnsafeStaticIntent(t *testing.T) {
	preview := newSandboxDryRunPreview(
		sandbox.SandboxLeasePurposeRun,
		"ghp_l1_preview_target_secret_123456789",
		"203.0.113.42",
		sandboxruntime.DriverRootlessPodman,
		"/home/operator/private/repository",
		sandboxSyncOutOptions{},
		sandbox.SecurityEvaluationRequest{
			RequestedNetworkPolicy: sandbox.SandboxNetworkPolicyDenyByDefault,
			RequestedNetworkPolicyIntent: &sandbox.SandboxNetworkPolicyIntent{
				Preset: sandbox.SandboxNetworkPolicyPresetAllowListed,
				Rules: []sandbox.SandboxNetworkPolicyRule{{
					Kind:     sandbox.SandboxNetworkPolicyRuleKindDomain,
					Value:    "private.preview.example",
					Decision: sandbox.SandboxNetworkPolicyDecisionAllow,
				}},
			},
			RequestedSecretModes: []string{
				sandbox.SandboxSecretModeEnv,
				"ghp_l1_preview_mode_secret_123456789",
			},
		},
		"",
	)
	payload, err := marshalSandboxDryRunPreview(preview)
	if err != nil {
		t.Fatalf("marshalSandboxDryRunPreview() error: %v", err)
	}
	for _, forbidden := range []string{
		"ghp_l1_preview_target_secret_123456789",
		"ghp_l1_preview_mode_secret_123456789",
		"203.0.113.42",
		"/home/operator/private/repository",
		"private.preview.example",
	} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("sandbox preview leaked %q: %s", forbidden, payload)
		}
	}
}

func assertSandboxDryRunPreview(t *testing.T, payload []byte, purpose, sandboxName, hostID, runtimeDriver string) {
	t.Helper()
	var preview struct {
		ContractVersion int    `json:"contractVersion"`
		OK              bool   `json:"ok"`
		DryRun          bool   `json:"dryRun"`
		EntryMode       string `json:"entryMode"`
		Iterations      int    `json:"iterations"`
		Complete        bool   `json:"complete"`
		Steps           map[string]struct {
			Status string `json:"status"`
		} `json:"steps"`
		SandboxPreview struct {
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
		} `json:"sandboxPreview"`
	}
	if err := json.Unmarshal(payload, &preview); err != nil {
		t.Fatalf("decode sandbox dry-run preview: %v\npayload=%s", err, payload)
	}
	if !preview.OK || !preview.DryRun || preview.SandboxPreview.ResourcesCreated {
		t.Fatalf("preview success/purity flags = ok:%t dryRun:%t resourcesCreated:%t", preview.OK, preview.DryRun, preview.SandboxPreview.ResourcesCreated)
	}
	if preview.SandboxPreview.Purpose != purpose {
		t.Fatalf("purpose = %q, want %q", preview.SandboxPreview.Purpose, purpose)
	}
	if preview.SandboxPreview.Target.SandboxName != sandboxName || preview.SandboxPreview.Target.HostID != hostID || preview.SandboxPreview.Target.Runtime != runtimeDriver {
		t.Fatalf("target = %#v, want sandbox=%q host=%q runtime=%q", preview.SandboxPreview.Target, sandboxName, hostID, runtimeDriver)
	}
	if preview.SandboxPreview.Target.Resolution != "unresolved" || preview.SandboxPreview.Workspace.Resolution != "unresolved" {
		t.Fatalf("target/workspace resolution = %q/%q, want unresolved", preview.SandboxPreview.Target.Resolution, preview.SandboxPreview.Workspace.Resolution)
	}
	if preview.SandboxPreview.Workspace.Mode != sandbox.SandboxWorkspaceModeClone {
		t.Fatalf("workspace mode = %q, want %q", preview.SandboxPreview.Workspace.Mode, sandbox.SandboxWorkspaceModeClone)
	}
	if preview.SandboxPreview.Security.Enforcement != "unresolved" || preview.SandboxPreview.Security.Active {
		t.Fatalf("security enforcement/active = %q/%t, want unresolved/false", preview.SandboxPreview.Security.Enforcement, preview.SandboxPreview.Security.Active)
	}
	if preview.SandboxPreview.Security.NetworkPolicy == "" || preview.SandboxPreview.Security.NetworkRuleCount != 1 || len(preview.SandboxPreview.Security.RequestedModes) != 1 {
		t.Fatalf("security intent missing requested policy summary: %#v", preview.SandboxPreview.Security)
	}
	if len(preview.SandboxPreview.UnresolvedRequirements) == 0 {
		t.Fatal("unresolvedRequirements is empty")
	}
	switch purpose {
	case sandbox.SandboxLeasePurposeRun:
		if preview.ContractVersion != 1 || preview.Iterations != 0 || preview.Complete {
			t.Fatalf("run-v1 compatibility fields = version:%d iterations:%d complete:%t", preview.ContractVersion, preview.Iterations, preview.Complete)
		}
	case sandbox.SandboxLeasePurposeAuto:
		if preview.ContractVersion != 2 || preview.EntryMode != string(autoEntryModeMarkdownPath) || len(preview.Steps) != 10 {
			t.Fatalf("auto-v2 compatibility fields = version:%d entryMode:%q steps:%d", preview.ContractVersion, preview.EntryMode, len(preview.Steps))
		}
		for name, step := range preview.Steps {
			if step.Status != string(autoStepStatusSkipped) {
				t.Fatalf("auto-v2 step %q status = %q, want skipped", name, step.Status)
			}
		}
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
