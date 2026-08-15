package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"sort"
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

func TestUS007FactoryStrictSecureDefaultBlockedGatePropagatesDecisionToRunRecord(t *testing.T) {
	now := time.Date(2026, 7, 3, 22, 20, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	fixture := phase26CredentialProxyUnsafeValues()
	securityReq := fixture.SecurityRequest([]string{sandbox.SandboxSecretModeHTTPProxy}, []string{sandbox.SandboxSecretModeHTTPProxy})
	target := us007UnsafeFactoryReadinessTarget(sandbox.EvaluateSandboxSecurity(securityReq))
	record := factory.RunRecord{
		RunID:      "run-us007-factory-strict-blocked",
		RepoRemote: us007UnsafeRemote(),
		RepoPath:   us007UnsafeWorktree(),
		BaseBranch: "main",
		BranchName: "feature/us007-factory-strict-blocked",
		Status:     factory.RunStatusRunning,
		Policy: &factory.FactoryPolicy{
			SecurityReadinessGatePolicyMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		},
	}

	var driverResolved bool
	var remoteOutput bytes.Buffer
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:                us007UnsafeWorktree(),
		SandboxName:               target.Name,
		RunRecord:                 record,
		Security:                  securityReq,
		SecurityReadinessGateMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		NetworkProxySession:       fixture.NetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceFactory, "network-proxy-session-us007-blocked", "policy-snapshot-us007-blocked"),
		NetworkPolicyDecisionLogs: unsafePolicyDecisionLogManifestRecords(sandbox.SandboxNetworkPolicyDecisionSource(" FACTORY ")),
		RemoteAuto:                factoryRunAutoRequest{BaseBranch: "main"},
		RemoteOutput:              &remoteOutput,
		DeferSuccessCleanup:       true,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loadSandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("resolveDefault should not run for explicit factory strict blocked target")
			return nil, "", nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			driverResolved = true
			return fakeFactorySandboxRuntimeDriver{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile { return nil },
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			t.Fatal("bootstrap should not run after strict secure-default gate blocks")
			return factory.BootstrapResult{}, nil
		},
	})
	if err == nil {
		t.Fatal("runFactorySandboxExecutorWithDeps() error = nil, want strict secure-default readiness gate block")
	}
	if driverResolved {
		t.Fatal("runtime driver resolved after strict secure-default readiness gate block")
	}
	storedRun, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error = %v", err)
	}
	if storedRun.Status != factory.RunStatusFailed {
		t.Fatalf("stored run status = %q, want failed", storedRun.Status)
	}
	if storedRun.Sandbox == nil || storedRun.Sandbox.Security == nil || storedRun.Sandbox.Security.CapabilityReadinessDiagnostics == nil {
		t.Fatalf("stored sandbox security = %#v, want readiness diagnostics for blocked decision", storedRun.Sandbox)
	}
	expected := sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		storedRun.Sandbox.Security.CapabilityReadinessDiagnostics,
	)
	gate := us007RequireSecurityReadinessGate(t, "factory blocked run record", storedRun.Sandbox.Security)
	us007AssertSecurityReadinessGateDecision(t, "factory blocked run record", gate, expected)
	us007AssertSecureDefaultDecisionSafe(t, "factory blocked run record", gate, fixture.ForbiddenValues()...)

	event := us007RequireFactoryReadinessGateEvent(t, store, record.RunID)
	us007AssertFactoryPolicyEventMatchesDecision(t, event, expected)
	us007AssertSecureDefaultDecisionSafe(t, "factory blocked policy event", event.Metadata, fixture.ForbiddenValues()...)
}

func TestUS007FactoryStrictSecureDefaultProofCompletePropagatesAllowedDecision(t *testing.T) {
	now := time.Date(2026, 7, 3, 22, 25, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := us007UnsafeFactoryReadinessTarget(&sandbox.SandboxSecurity{
		CapabilityReadiness: us007ProofCompleteReadinessOutput(),
	})
	record := factory.RunRecord{
		RunID:      "run-us007-factory-strict-allowed",
		RepoRemote: us007UnsafeRemote(),
		RepoPath:   us007UnsafeWorktree(),
		BaseBranch: "main",
		BranchName: "feature/us007-factory-strict-allowed",
		Status:     factory.RunStatusRunning,
		Policy: &factory.FactoryPolicy{
			SecurityReadinessGatePolicyMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		},
	}
	req := factorySandboxExecutorRequest{
		ProjectDir:                us007UnsafeWorktree(),
		SandboxName:               target.Name,
		RunRecord:                 record,
		SecurityReadinessGateMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
	}
	record.SandboxName, record.Sandbox = factorySandboxPersistentMetadataFromState(req, record, target)
	record.UpdatedAt = now
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error = %v", err)
	}
	if err := enforceFactorySandboxReadinessGate(store, factorySandboxExecutorDeps{
		now:         func() time.Time { return now },
		appendEvent: appendFactorySandboxTimelineEvent,
	}, req, &record, factory.RunSecretRedactor{}); err != nil {
		t.Fatalf("enforceFactorySandboxReadinessGate() unexpected error for proof-complete strict metadata: %v", err)
	}
	storedRun, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error = %v", err)
	}
	if storedRun.Sandbox == nil || storedRun.Sandbox.Security == nil || storedRun.Sandbox.Security.CapabilityReadinessDiagnostics == nil {
		t.Fatalf("stored sandbox security = %#v, want readiness diagnostics for allowed decision", storedRun.Sandbox)
	}
	expected := sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		storedRun.Sandbox.Security.CapabilityReadinessDiagnostics,
	)
	if expected.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAllowed {
		t.Fatalf("proof-complete fixture decision = %#v, want allowed", expected)
	}
	gate := us007RequireSecurityReadinessGate(t, "factory allowed run record", storedRun.Sandbox.Security)
	us007AssertSecurityReadinessGateDecision(t, "factory allowed run record", gate, expected)
	us007AssertSecureDefaultDecisionSafe(t, "factory allowed run record", gate)

	event := us007RequireFactoryReadinessGateEvent(t, store, record.RunID)
	us007AssertFactoryPolicyEventMatchesDecision(t, event, expected)
}

func TestUS007RunAndAutoDefaultSecureDefaultReadinessPersistsAdvisoryDecision(t *testing.T) {
	startedAt := time.Date(2026, 7, 3, 22, 30, 0, 0, time.UTC)
	runStore := newPrivateSandboxExecutionTestStore(t)
	runReq := runSandboxRequest{
		ExecutionID:   "run-us007-default-advisory",
		ProjectDir:    us007UnsafeWorktree(),
		RemoteCommand: []string{"hal", "run", "--base", "main"},
		WorkDir:       "/workspace/us007",
		Security:      runSandboxSecurityRequest(),
	}
	runTarget := us007UnsafeCommandTarget("run-us007-default-advisory-target", sandbox.SandboxRuntimeDriverSSHMachine)
	if err := saveRunSandboxManifest(runStore, runReq, sandboxexecution.StatusSucceeded, startedAt, &startedAt, runTarget); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}
	runManifest := mustLoadSandboxExecutionManifest(t, runStore, runReq.ExecutionID)
	if runManifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("run manifest status = %q, want succeeded advisory flow", runManifest.Status)
	}
	us007AssertAdvisorySecurityReadinessGate(t, "run default manifest", runManifest.Security)

	autoStore := newPrivateSandboxExecutionTestStore(t)
	autoReq := autoSandboxRequest{
		ExecutionID:   "auto-us007-default-advisory",
		ProjectDir:    us007UnsafeWorktree(),
		RemoteCommand: []string{"hal", "auto", "--base", "main"},
		WorkDir:       "/workspace/us007",
		Security:      runSandboxSecurityRequest(),
	}
	autoTarget := us007UnsafeCommandTarget("auto-us007-default-advisory-target", sandbox.SandboxRuntimeDriverRootlessPodman)
	if err := saveAutoSandboxManifest(autoStore, autoReq, sandboxexecution.StatusSucceeded, startedAt, &startedAt, autoTarget); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}
	autoManifest := mustLoadSandboxExecutionManifest(t, autoStore, autoReq.ExecutionID)
	if autoManifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("auto manifest status = %q, want succeeded advisory flow", autoManifest.Status)
	}
	us007AssertAdvisorySecurityReadinessGate(t, "auto default manifest", autoManifest.Security)
}

func TestUS007RunAndAutoStrictSecureDefaultSelectionBlocksAndPersistsDecision(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	startedAt := time.Date(2026, 7, 3, 22, 35, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := filepath.Join(t.TempDir(), "repo")
	target := us007UnsafeCommandTarget("us007-strict-microvm-target", sandbox.SandboxRuntimeDriverMicroVM)

	runStore := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "run-executions"))
	var runOut bytes.Buffer
	var runErrOut bytes.Buffer
	runErr := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		Base:                  "main",
		BaseChanged:           true,
		SandboxName:           target.Name,
		SandboxNameChanged:    true,
		SandboxRuntime:        sandbox.SandboxRuntimeDriverMicroVM,
		SandboxRuntimeChanged: true,
	}, &runOut, &runErrOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) { return runStore, nil },
		newExecutionID: func(time.Time) string {
			return "run-us007-strict-missing-proof"
		},
		now:        runSandboxTestClock(startedAt, finishedAt),
		workingDir: func() (string, error) { return projectDir, nil },
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return us007WorkspacePlan(projectDir), nil
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("run loadSandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{us007MicroVMHost()}, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("run default target fallback should not run for strict microVM selection")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("run provisioning should not run for strict microVM missing proof")
			return nil, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("run runtime driver should not be constructed after strict secure-default block")
			return nil, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile { return nil },
	})
	if runErr == nil {
		t.Fatalf("runRunSandboxWithWriter() error = nil, want strict secure-default block\nstdout=%s\nstderr=%s", runOut.String(), runErrOut.String())
	}
	runManifest := mustLoadSandboxExecutionManifest(t, runStore, "run-us007-strict-missing-proof")
	if runManifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("run manifest status = %q, want failed strict block", runManifest.Status)
	}
	us007AssertBlockedSecurityReadinessGate(t, "run strict manifest", runManifest.Security)

	autoStore := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "auto-executions"))
	var autoOut bytes.Buffer
	var autoErrOut bytes.Buffer
	autoErr := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		Base:                  "main",
		BaseChanged:           true,
		SandboxName:           target.Name,
		SandboxNameChanged:    true,
		SandboxRuntime:        sandbox.SandboxRuntimeDriverMicroVM,
		SandboxRuntimeChanged: true,
	}, &autoOut, &autoErrOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) { return autoStore, nil },
		newExecutionID: func(time.Time) string {
			return "auto-us007-strict-missing-proof"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return us007WorkspacePlan(projectDir), nil
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("auto loadSandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{us007MicroVMHost()}, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("auto default target fallback should not run for strict microVM selection")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatal("auto provisioning should not run for strict microVM missing proof")
			return nil, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			t.Fatal("auto runtime driver should not be constructed after strict secure-default block")
			return nil, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile { return nil },
	})
	if autoErr == nil {
		t.Fatalf("runAutoSandboxWithWriter() error = nil, want strict secure-default block\nstdout=%s\nstderr=%s", autoOut.String(), autoErrOut.String())
	}
	autoManifest := mustLoadSandboxExecutionManifest(t, autoStore, "auto-us007-strict-missing-proof")
	if autoManifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("auto manifest status = %q, want failed strict block", autoManifest.Status)
	}
	us007AssertBlockedSecurityReadinessGate(t, "auto strict manifest", autoManifest.Security)
}

func TestUS004RunAndAutoConfiguredStrictSecureDefaultBlocksBeforeLiveWork(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	startedAt := time.Date(2026, 7, 4, 0, 40, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	writeUnsupportedRunAutoReadinessGateConfig(t, projectDir, string(sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict))

	t.Run("run", func(t *testing.T) {
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "run-executions"))
		var out bytes.Buffer
		var errOut bytes.Buffer
		err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
			Base:        "main",
			BaseChanged: true,
		}, &out, &errOut, runSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID: func(time.Time) string {
				return "run-us004-configured-strict-missing-readiness"
			},
			now:        runSandboxTestClock(startedAt, finishedAt),
			workingDir: func() (string, error) { return projectDir, nil },
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				return us007WorkspacePlan(projectDir), nil
			},
			loadSandbox: func(string) (*sandbox.SandboxState, error) {
				t.Fatal("run loadSandbox should not run after configured strict secure-default gate blocks missing readiness")
				return nil, nil
			},
			listSandboxes: func() ([]*sandbox.SandboxState, error) {
				t.Fatal("run listSandboxes should not run after configured strict secure-default gate blocks missing readiness")
				return nil, nil
			},
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				t.Fatal("run listHosts should not run after configured strict secure-default gate blocks missing readiness")
				return nil, nil
			},
			resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
				t.Fatal("run default target resolution should not run after configured strict secure-default gate blocks missing readiness")
				return nil, "", nil
			},
			provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
				t.Fatal("run provisioning should not run after configured strict secure-default gate blocks missing readiness")
				return nil, nil
			},
			resolveProvider: func(string) (sandbox.Provider, error) {
				t.Fatal("run provider resolution should not run after configured strict secure-default gate blocks missing readiness")
				return nil, nil
			},
			resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
				t.Fatal("run runtime driver should not be constructed after configured strict secure-default gate blocks missing readiness")
				return nil, nil
			},
			resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
				t.Fatal("run worker runtime resolver should not run after configured strict secure-default gate blocks missing readiness")
				return nil, nil
			},
			engineAuthFiles: func() []factorySandboxAuthFile {
				t.Fatal("run credential discovery should not run after configured strict secure-default gate blocks missing readiness")
				return nil
			},
			bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
				t.Fatal("run bootstrap should not run after configured strict secure-default gate blocks missing readiness")
				return factory.BootstrapResult{}, nil
			},
			runProviderExecWithEnv: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error {
				t.Fatal("run provider exec should not run after configured strict secure-default gate blocks missing readiness")
				return nil
			},
			runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
				t.Fatal("run provider script should not run after configured strict secure-default gate blocks missing readiness")
				return nil
			},
			materializeWorkspace: func(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
				t.Fatal("run workspace materialization should not run after configured strict secure-default gate blocks missing readiness")
				return sandboxworkspace.MaterializationResult{}, nil
			},
		})
		if err == nil {
			t.Fatalf("runRunSandboxWithWriter() error = nil, want configured strict secure-default block\nstdout=%s\nstderr=%s", out.String(), errOut.String())
		}
		us004AssertStrictGateErrorSafe(t, "run strict configured error", err, projectDir)
		manifest := mustLoadSandboxExecutionManifest(t, store, "run-us004-configured-strict-missing-readiness")
		if manifest.Status != sandboxexecution.StatusFailed {
			t.Fatalf("run manifest status = %q, want failed strict block", manifest.Status)
		}
		us004AssertStrictMissingReadinessSecurity(t, "run strict configured manifest", manifest.Security, projectDir, us007UnsafeRemote())
	})

	t.Run("auto", func(t *testing.T) {
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "auto-executions"))
		var out bytes.Buffer
		var errOut bytes.Buffer
		err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
			Base:        "main",
			BaseChanged: true,
		}, &out, &errOut, autoSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID: func(time.Time) string {
				return "auto-us004-configured-strict-missing-readiness"
			},
			now: runSandboxTestClock(startedAt, finishedAt),
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				return us007WorkspacePlan(projectDir), nil
			},
			loadSandbox: func(string) (*sandbox.SandboxState, error) {
				t.Fatal("auto loadSandbox should not run after configured strict secure-default gate blocks missing readiness")
				return nil, nil
			},
			listSandboxes: func() ([]*sandbox.SandboxState, error) {
				t.Fatal("auto listSandboxes should not run after configured strict secure-default gate blocks missing readiness")
				return nil, nil
			},
			listHosts: func() ([]*sandbox.SandboxHost, error) {
				t.Fatal("auto listHosts should not run after configured strict secure-default gate blocks missing readiness")
				return nil, nil
			},
			resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
				t.Fatal("auto default target resolution should not run after configured strict secure-default gate blocks missing readiness")
				return nil, "", nil
			},
			provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
				t.Fatal("auto provisioning should not run after configured strict secure-default gate blocks missing readiness")
				return nil, nil
			},
			resolveProvider: func(string) (sandbox.Provider, error) {
				t.Fatal("auto provider resolution should not run after configured strict secure-default gate blocks missing readiness")
				return nil, nil
			},
			resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
				t.Fatal("auto runtime driver should not be constructed after configured strict secure-default gate blocks missing readiness")
				return nil, nil
			},
			resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
				t.Fatal("auto worker runtime resolver should not run after configured strict secure-default gate blocks missing readiness")
				return nil, nil
			},
			engineAuthFiles: func() []factorySandboxAuthFile {
				t.Fatal("auto credential discovery should not run after configured strict secure-default gate blocks missing readiness")
				return nil
			},
			bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
				t.Fatal("auto bootstrap should not run after configured strict secure-default gate blocks missing readiness")
				return factory.BootstrapResult{}, nil
			},
			runProviderExecWithEnv: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer) error {
				t.Fatal("auto provider exec should not run after configured strict secure-default gate blocks missing readiness")
				return nil
			},
			runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
				t.Fatal("auto provider script should not run after configured strict secure-default gate blocks missing readiness")
				return nil
			},
			materializeWorkspace: func(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
				t.Fatal("auto workspace materialization should not run after configured strict secure-default gate blocks missing readiness")
				return sandboxworkspace.MaterializationResult{}, nil
			},
		})
		if err == nil {
			t.Fatalf("runAutoSandboxWithWriter() error = nil, want configured strict secure-default block\nstdout=%s\nstderr=%s", out.String(), errOut.String())
		}
		us004AssertStrictGateErrorSafe(t, "auto strict configured error", err, projectDir)
		manifest := mustLoadSandboxExecutionManifest(t, store, "auto-us004-configured-strict-missing-readiness")
		if manifest.Status != sandboxexecution.StatusFailed {
			t.Fatalf("auto manifest status = %q, want failed strict block", manifest.Status)
		}
		us004AssertStrictMissingReadinessSecurity(t, "auto strict configured manifest", manifest.Security, projectDir, us007UnsafeRemote())
	})
}

func us007AssertAdvisorySecurityReadinessGate(t *testing.T, label string, security *sandbox.SandboxSecurity) {
	t.Helper()
	if security == nil || security.CapabilityReadinessDiagnostics == nil {
		t.Fatalf("%s security = %#v, want capability readiness diagnostics", label, security)
	}
	expected := sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility,
		security.CapabilityReadinessDiagnostics,
	)
	if expected.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAdvisory {
		t.Fatalf("%s expected decision = %#v, want advisory", label, expected)
	}
	gate := us007RequireSecurityReadinessGate(t, label, security)
	us007AssertSecurityReadinessGateDecision(t, label, gate, expected)
	us007AssertSecureDefaultDecisionSafe(t, label, gate)
}

func us004AssertStrictGateErrorSafe(t *testing.T, label string, err error, extraForbidden ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s error = nil", label)
	}
	message := err.Error()
	for _, want := range []string{
		"security readiness gate blocked",
		string(sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict),
		string(sandbox.SandboxSecurityCapabilityReadinessGateCodeBlocked),
		string(sandbox.SandboxSecurityCapabilityReadinessGateReasonReadinessMissing),
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("%s error = %q, want safe marker %q", label, message, want)
		}
	}
	us007AssertSecureDefaultDecisionSafe(t, label, message, extraForbidden...)
}

func us004AssertStrictMissingReadinessSecurity(t *testing.T, label string, security *sandbox.SandboxSecurity, extraForbidden ...string) {
	t.Helper()
	if security == nil {
		t.Fatalf("%s security = nil, want strict readiness metadata", label)
	}
	if us004StrictBlockedGateIsSafe(security.SecurityReadinessGate) && security.CapabilityReadinessDiagnostics == nil {
		us007AssertSecureDefaultDecisionSafe(t, label, security, extraForbidden...)
		return
	}
	if security.CapabilityReadinessDiagnostics == nil {
		t.Fatalf("%s security = %#v, want capabilityReadinessDiagnostics or strict blocked readiness gate", label, security)
	}
	diagnostics := security.CapabilityReadinessDiagnostics
	if diagnostics.Total == 0 ||
		diagnostics.HighestSeverity != sandbox.SandboxSecurityCapabilityDiagnosticSeverityWarning ||
		!diagnostics.AdvisoryOnly ||
		!diagnostics.WouldBlockStrictGate ||
		len(diagnostics.Items) == 0 {
		t.Fatalf("%s capabilityReadinessDiagnostics = %#v, want strict-blocking diagnostic summary", label, diagnostics)
	}
	for i, item := range diagnostics.Items {
		if item.Code == "" ||
			item.Severity != sandbox.SandboxSecurityCapabilityDiagnosticSeverityWarning ||
			item.Classification == "" ||
			item.ReasonCode == "" ||
			!item.AdvisoryOnly ||
			!item.WouldBlockStrictGate {
			t.Fatalf("%s diagnostic item[%d] = %#v, want safe strict-blocking diagnostic", label, i, item)
		}
	}
	encoded := us007JSONString(t, security)
	for _, field := range []string{"capabilityReadinessDiagnostics", "securityReadinessGate"} {
		if !strings.Contains(encoded, field) {
			t.Fatalf("%s security JSON = %s, want %s", label, encoded, field)
		}
	}
	expected := sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		diagnostics,
	)
	if us004StrictBlockedGateIsSafe(security.SecurityReadinessGate) {
		us007AssertSecureDefaultDecisionSafe(t, label, security, extraForbidden...)
		return
	}
	gate := us007RequireSecurityReadinessGate(t, label, security)
	us007AssertSecurityReadinessGateDecision(t, label, gate, expected)
	us007AssertSecureDefaultDecisionSafe(t, label, security, extraForbidden...)
}

func us004StrictBlockedGateIsSafe(gate *sandbox.SandboxSecurityCapabilityReadinessGateDecision) bool {
	return gate != nil &&
		gate.PolicyMode == sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict &&
		gate.Outcome == sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked &&
		gate.Code == sandbox.SandboxSecurityCapabilityReadinessGateCodeBlocked &&
		gate.Counts != nil &&
		gate.Counts.StrictBlocking > 0 &&
		len(gate.Counts.ReasonCodeCounts) > 0
}

func us007AssertBlockedSecurityReadinessGate(t *testing.T, label string, security *sandbox.SandboxSecurity) {
	t.Helper()
	if security == nil || security.SecurityReadinessGate == nil {
		t.Fatalf("%s security = %#v, want securityReadinessGate decision", label, security)
	}
	if security.SecurityReadinessGate.PolicyMode == sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict &&
		security.SecurityReadinessGate.Outcome == sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked &&
		security.SecurityReadinessGate.Code == sandbox.SandboxSecurityCapabilityReadinessGateCodeBlocked &&
		security.SecurityReadinessGate.Counts != nil &&
		security.SecurityReadinessGate.Counts.StrictBlocking > 0 {
		us007AssertSecureDefaultDecisionSafe(t, label, security.SecurityReadinessGate)
		return
	}
	expected := sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		nil,
	)
	if security != nil && security.CapabilityReadinessDiagnostics != nil {
		expected = sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(
			sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			security.CapabilityReadinessDiagnostics,
		)
	}
	if expected.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked {
		t.Fatalf("%s expected decision = %#v, want blocked", label, expected)
	}
	gate := us007RequireSecurityReadinessGate(t, label, security)
	us007AssertSecurityReadinessGateDecision(t, label, gate, expected)
	us007AssertSecureDefaultDecisionSafe(t, label, gate)
}

func us007RequireSecurityReadinessGate(t *testing.T, label string, security any) map[string]any {
	t.Helper()
	if security == nil {
		t.Fatalf("%s security = nil, want securityReadinessGate decision", label)
	}
	raw := us007JSONMap(t, security)
	gate, ok := raw["securityReadinessGate"].(map[string]any)
	if !ok {
		t.Fatalf("%s securityReadinessGate = %#v, want object; security keys=%v", label, raw["securityReadinessGate"], us007MapKeys(raw))
	}
	return gate
}

func us007AssertSecurityReadinessGateDecision(t *testing.T, label string, gate map[string]any, expected sandbox.SandboxSecurityCapabilityReadinessGateDecision) {
	t.Helper()
	us007AssertStringField(t, label, gate, "code", string(expected.Code))
	us007AssertStringField(t, label, gate, "outcome", string(expected.Outcome))
	us007AssertStringField(t, label, gate, "policyMode", string(expected.PolicyMode))
	us007AssertStringField(t, label, gate, "reason", string(expected.Reason))
	if expected.Counts == nil {
		if _, ok := gate["counts"]; ok {
			t.Fatalf("%s counts = %#v, want omitted", label, gate["counts"])
		}
		return
	}
	counts, ok := gate["counts"].(map[string]any)
	if !ok {
		t.Fatalf("%s counts = %#v, want object", label, gate["counts"])
	}
	us007AssertIntField(t, label, counts, "total", expected.Counts.Total)
	us007AssertIntField(t, label, counts, "ready", expected.Counts.Ready)
	us007AssertIntField(t, label, counts, "advisory", expected.Counts.Advisory)
	us007AssertIntField(t, label, counts, "blocked", expected.Counts.Blocked)
	us007AssertIntField(t, label, counts, "missing", expected.Counts.Missing)
	us007AssertIntField(t, label, counts, "metadataOnly", expected.Counts.MetadataOnly)
	us007AssertIntField(t, label, counts, "unsupported", expected.Counts.Unsupported)
	us007AssertIntField(t, label, counts, "strictBlocking", expected.Counts.StrictBlocking)
	reasonCodeCounts, ok := counts["reasonCodeCounts"].(map[string]any)
	if len(expected.Counts.ReasonCodeCounts) > 0 && !ok {
		t.Fatalf("%s reasonCodeCounts = %#v, want object", label, counts["reasonCodeCounts"])
	}
	for reason, want := range expected.Counts.ReasonCodeCounts {
		us007AssertIntField(t, label, reasonCodeCounts, string(reason), want)
	}
}

func us007AssertFactoryPolicyEventMatchesDecision(t *testing.T, event factory.EventRecord, expected sandbox.SandboxSecurityCapabilityReadinessGateDecision) {
	t.Helper()
	decision := factoryPolicyDecisionFromMetadata(event.Metadata)
	if decision.PolicyField != factorySandboxReadinessGatePolicyField {
		t.Fatalf("policy event field = %q, want %q", decision.PolicyField, factorySandboxReadinessGatePolicyField)
	}
	if decision.Code != expected.Code || decision.PolicyMode != expected.PolicyMode || decision.Reason != string(expected.Reason) {
		t.Fatalf("policy event decision = %#v, want code/mode/reason from %#v", decision, expected)
	}
	if expected.Outcome == sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked {
		if decision.Decision != factory.PolicyDecisionBlockedGate || decision.Outcome != factory.PolicyOutcomeBlocked {
			t.Fatalf("policy event blocked decision = %#v", decision)
		}
	} else if decision.Decision != factory.PolicyDecisionPassedGate || decision.Outcome != factory.PolicyOutcomeAllowed {
		t.Fatalf("policy event allowed decision = %#v", decision)
	}
	if expected.Counts == nil {
		return
	}
	if decision.Counts == nil {
		t.Fatalf("policy event counts = nil, want %#v", expected.Counts)
	}
	if decision.Counts.Total != expected.Counts.Total ||
		decision.Counts.StrictBlocking != expected.Counts.StrictBlocking ||
		decision.Counts.Ready != expected.Counts.Ready {
		t.Fatalf("policy event counts = %#v, want %#v", decision.Counts, expected.Counts)
	}
}

func us007RequireFactoryReadinessGateEvent(t *testing.T, store factory.Store, runID string) factory.EventRecord {
	t.Helper()
	events, err := store.LoadEvents(runID)
	if err != nil {
		t.Fatalf("LoadEvents() error = %v", err)
	}
	for _, event := range events {
		if event.EventType == factory.EventTypePolicyDecision && event.Metadata["policyField"] == factorySandboxReadinessGatePolicyField {
			return event
		}
	}
	t.Fatalf("factory readiness gate policy event not found in %#v", events)
	return factory.EventRecord{}
}

func us007AssertStringField(t *testing.T, label string, values map[string]any, field, want string) {
	t.Helper()
	if got, ok := values[field].(string); !ok || got != want {
		t.Fatalf("%s %s = %#v, want %q", label, field, values[field], want)
	}
}

func us007AssertIntField(t *testing.T, label string, values map[string]any, field string, want int) {
	t.Helper()
	got := us007IntValue(values[field])
	if got != want {
		t.Fatalf("%s %s = %#v, want %d", label, field, values[field], want)
	}
}

func us007IntValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return int(parsed)
	default:
		return 0
	}
}

func us007AssertSecureDefaultDecisionSafe(t *testing.T, label string, decision any, extraForbidden ...string) {
	t.Helper()
	payload := us007JSONString(t, decision)
	for _, forbidden := range append(us007ForbiddenSecureDefaultFragments(), extraForbidden...) {
		if forbidden == "" {
			continue
		}
		if strings.Contains(payload, forbidden) {
			t.Fatalf("%s leaked unsafe secure-default metadata fragment %q: %s", label, forbidden, payload)
		}
	}
}

func us007JSONMap(t *testing.T, value any) map[string]any {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal([]byte(us007JSONString(t, value)), &raw); err != nil {
		t.Fatalf("unmarshal JSON map: %v", err)
	}
	return raw
}

func us007JSONString(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return string(data)
}

func us007MapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func us007UnsafeFactoryReadinessTarget(security *sandbox.SandboxSecurity) *sandbox.SandboxState {
	target := factorySandboxReadinessTarget(security)
	target.Host.Endpoint = us007UnsafeEndpoint()
	target.Host.SupportedRuntimes = []string{sandbox.SandboxRuntimeDriverMicroVM}
	target.Runtime.Driver = sandbox.SandboxRuntimeDriverMicroVM
	target.Runtime.IsolationLevel = sandbox.SandboxIsolationLevelVM
	target.Runtime.Image = "ghcr.io/private/us007-template:latest"
	target.Workspace = &sandbox.SandboxWorkspace{
		Mode:        sandbox.SandboxWorkspaceModeDirect,
		InputSource: sandbox.SandboxWorkspaceInputSourceCopy,
		Repo:        us007UnsafeRemote(),
		Branch:      "feature/us007",
		SyncRef:     us007UnsafeWorktree(),
	}
	return target
}

func us007UnsafeCommandTarget(name, runtimeDriver string) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		ID:       name + "-id",
		Name:     name,
		Provider: "us007-provider",
		Status:   sandbox.StatusRunning,
		Host:     us007MicroVMHost(),
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         runtimeDriver,
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
			RuntimeID:      "runtime-us007",
			Image:          "ghcr.io/private/us007-command-image:latest",
		},
		Workspace: &sandbox.SandboxWorkspace{
			Mode:        sandbox.SandboxWorkspaceModeDirect,
			InputSource: sandbox.SandboxWorkspaceInputSourceCopy,
			Repo:        us007UnsafeRemote(),
			Branch:      "feature/us007",
			SyncRef:     us007UnsafeWorktree(),
		},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
				PolicyEnforced:  sandbox.SandboxNetworkPolicyBestEffort,
				EnforcementMode: sandbox.SandboxNetworkEnforcementModeBestEffort,
			},
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy},
			},
		},
	}
}

func us007MicroVMHost() *sandbox.SandboxHost {
	return &sandbox.SandboxHost{
		ID:                "host-us007-microvm",
		Name:              "us007-microvm-host",
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          us007UnsafeEndpoint(),
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverMicroVM},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
				PolicyEnforced:  sandbox.SandboxNetworkPolicyBestEffort,
				EnforcementMode: sandbox.SandboxNetworkEnforcementModeBestEffort,
			},
		},
	}
}

func us007WorkspacePlan(projectDir string) sandboxworkspace.Plan {
	return sandboxworkspace.Plan{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
		ProjectDir:  projectDir,
		Repository:  us007UnsafeRemote(),
		Branch:      "feature/us007",
		Upstream:    "origin/feature/us007",
		SyncRef:     "refs/remotes/origin/feature/us007",
	}
}

func us007ProofCompleteReadinessOutput() *sandbox.SandboxSecurityCapabilityReadinessOutput {
	return &sandbox.SandboxSecurityCapabilityReadinessOutput{
		Results: []sandbox.SandboxSecurityCapabilityReadinessResult{
			us007ReadyCapability(sandbox.SandboxSecurityCapabilityFamilyIsolation, sandbox.SandboxSecurityCapabilityIsolationMicroVM, sandbox.SandboxSecurityCapabilityReasonMicroVMReadinessConfirmed),
			us007ReadyCapability(sandbox.SandboxSecurityCapabilityFamilyWorkspace, sandbox.SandboxSecurityCapabilityIsolatedWorkspace, sandbox.SandboxSecurityCapabilityReasonWorkspaceIsolationConfirmed),
			us007ReadyCapability(sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy, sandbox.SandboxSecurityCapabilityNetworkDenyByDefault, sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed),
			us007ReadyCapability(sandbox.SandboxSecurityCapabilityFamilySecretDelivery, sandbox.SandboxSecurityCapabilitySecretHTTPProxy, sandbox.SandboxSecurityCapabilityReasonCredentialActivationConfirmed),
			us007ReadyCapability(sandbox.SandboxSecurityCapabilityFamilyTemplate, sandbox.SandboxSecurityCapabilityTemplateLockDigest, sandbox.SandboxSecurityCapabilityReasonTemplateLockDigestConfirmed),
		},
	}
}

func us007ReadyCapability(family sandbox.SandboxSecurityCapabilityFamily, capability sandbox.SandboxSecurityCapabilityName, reason sandbox.SandboxSecurityCapabilityReasonCode) sandbox.SandboxSecurityCapabilityReadinessResult {
	requested := &sandbox.SandboxSecurityCapabilityMetadata{
		Family:     family,
		Capability: capability,
		Source:     sandbox.SandboxSecurityCapabilitySourceRequested,
	}
	metadata := &sandbox.SandboxSecurityCapabilityMetadata{
		Family:     family,
		Capability: capability,
		Source:     sandbox.SandboxSecurityCapabilitySourceRuntime,
		Status:     sandbox.SandboxSecurityCapabilityReadinessReady,
		ReasonCode: reason,
	}
	return sandbox.SandboxSecurityCapabilityReadinessResult{
		State:      sandbox.SandboxSecurityCapabilityReadinessReady,
		Requested:  requested,
		Ready:      metadata,
		ReasonCode: reason,
	}
}

func us007UnsafeEndpoint() string {
	return "unix:///tmp/us007-secure-default-proxy.sock"
}

func us007UnsafeRemote() string {
	return "https://alice:ghp_us007_token@example.invalid/org/private-repo.git"
}

func us007UnsafeWorktree() string {
	return "/Users/alice/private/us007-worktree"
}

func us007ForbiddenSecureDefaultFragments() []string {
	return []string{
		us007UnsafeEndpoint(),
		us007UnsafeRemote(),
		us007UnsafeWorktree(),
		"ghp_us007_token",
		"Authorization: Bearer us007-token",
		"us007-token",
		"us007-credential-value",
		"raw-template-ref:main",
		"iptables -A OUTPUT",
		"nft add rule",
		"proxy.internal.local:8080",
		"ghcr.io/private/us007",
	}
}
