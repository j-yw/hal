package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
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

func TestAutoSandboxManifestOmitsCapabilityReadinessWhenUnavailable(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 0, 0, 0, time.UTC)
	store := sandboxexecution.NewStore(t.TempDir())

	if err := saveAutoSandboxManifest(store, autoSandboxRequest{
		ExecutionID: "auto-readiness-unavailable",
		ProjectDir:  "/repo",
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "auto-readiness-unavailable")
	if manifest.Security != nil && manifest.Security.CapabilityReadiness != nil {
		t.Fatalf("capabilityReadiness = %#v, want omitted without readiness inputs", manifest.Security.CapabilityReadiness)
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(manifest) error = %v", err)
	}
	if strings.Contains(string(payload), "capabilityReadiness") {
		t.Fatalf("manifest JSON included capabilityReadiness without readiness inputs: %s", string(payload))
	}
}

func TestAutoSandboxManifestOmitsReadinessDiagnosticsWhenUnavailable(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 2, 0, 0, time.UTC)
	store := sandboxexecution.NewStore(t.TempDir())

	if err := saveAutoSandboxManifest(store, autoSandboxRequest{
		ExecutionID: "auto-readiness-diagnostics-unavailable",
		ProjectDir:  "/repo",
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "auto-readiness-diagnostics-unavailable")
	if manifest.Security != nil && manifest.Security.CapabilityReadinessDiagnostics != nil {
		t.Fatalf("capabilityReadinessDiagnostics = %#v, want omitted without readiness inputs", manifest.Security.CapabilityReadinessDiagnostics)
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(manifest) error = %v", err)
	}
	if strings.Contains(string(payload), "capabilityReadinessDiagnostics") {
		t.Fatalf("manifest JSON included capabilityReadinessDiagnostics without readiness inputs: %s", string(payload))
	}
}

func TestRunAutoSandboxWithWriterAttachesCapabilityReadinessWithoutChangingExecution(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 5, 0, 0, time.UTC)
	finishedAt := startedAt.Add(4 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(t.TempDir())
	target := autoSandboxCapabilityReadinessTarget()
	wantCommand := []string{"hal", "auto", "--base", "main"}

	var executed bool
	var targetReadyCalled bool
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		Base:                  "main",
		BaseChanged:           true,
		SandboxRuntime:        sandbox.SandboxRuntimeDriverRootlessPodman,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-readiness-execution"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return autoSandboxTestPlan(projectDir), nil
		},
		execute: func(_ context.Context, req autoSandboxRequest, out io.Writer, _ io.Writer, hooks autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
			executed = true
			if !reflect.DeepEqual(req.RemoteCommand, wantCommand) {
				t.Fatalf("RemoteCommand = %#v, want %#v", req.RemoteCommand, wantCommand)
			}
			if strings.Contains(strings.Join(req.RemoteCommand, " "), "readiness") {
				t.Fatalf("RemoteCommand added readiness flag: %#v", req.RemoteCommand)
			}
			if hooks.OnTargetReady == nil {
				t.Fatal("OnTargetReady hook = nil")
			}
			targetReadyCalled = true
			if err := hooks.OnTargetReady(target); err != nil {
				return autoSandboxExecutionResult{}, err
			}
			_, _ = io.WriteString(out, autoSandboxRemoteSuccessJSON("readiness preserved execution")+"\n")
			return autoSandboxExecutionResult{
				Result:          &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
				PreparedCommand: append([]string(nil), req.RemoteCommand...),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if !executed || !targetReadyCalled {
		t.Fatalf("executed=%v targetReadyCalled=%v, want auto execution path to complete", executed, targetReadyCalled)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "auto-readiness-execution")
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if !reflect.DeepEqual(manifest.Command, wantCommand) {
		t.Fatalf("manifest Command = %#v, want %#v", manifest.Command, wantCommand)
	}
	if manifest.WorkerRouting == nil || manifest.WorkerRouting.RuntimeDriverID != sandbox.SandboxRuntimeDriverRootlessPodman {
		t.Fatalf("WorkerRouting = %#v, want unchanged rootless worker routing metadata", manifest.WorkerRouting)
	}
	requireAutoSandboxCapabilityReadinessOutput(t, manifest.Security)
}

func TestAutoSandboxManifestAttachesReadinessDiagnosticsFromSanitizedReadiness(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 7, 0, 0, time.UTC)
	store := sandboxexecution.NewStore(t.TempDir())
	fixture := phase26CredentialProxyUnsafeValues()
	req := autoSandboxRequest{
		ExecutionID:         "auto-readiness-diagnostics-projected",
		ProjectDir:          "/repo",
		NetworkProxySession: fixture.NetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceAuto, "network-proxy-session-01", "policy-snapshot-01"),
		Security:            fixture.SecurityRequest([]string{sandbox.SandboxSecretModeHTTPProxy}, []string{sandbox.SandboxSecretModeHTTPProxy}),
	}
	target := autoSandboxCapabilityReadinessTarget()

	if err := saveAutoSandboxManifest(store, req, sandboxexecution.StatusSucceeded, startedAt, &startedAt, target); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "auto-readiness-diagnostics-projected")
	if manifest.Security == nil || manifest.Security.CapabilityReadiness == nil {
		t.Fatalf("Security = %#v, want sanitized capabilityReadiness for diagnostics", manifest.Security)
	}
	readiness := manifest.Security.CapabilityReadiness
	if sanitized := sandbox.SanitizeSandboxSecurityCapabilityReadinessOutput(*readiness); !reflect.DeepEqual(sanitized, *readiness) {
		t.Fatalf("capabilityReadiness was not sanitized before diagnostics:\nsanitized: %#v\nreadiness: %#v", sanitized, *readiness)
	}
	diagnostics := manifest.Security.CapabilityReadinessDiagnostics
	if diagnostics == nil {
		t.Fatal("capabilityReadinessDiagnostics = nil, want advisory diagnostics")
	}
	want := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*readiness)
	if !reflect.DeepEqual(*diagnostics, want) {
		t.Fatalf("capabilityReadinessDiagnostics not derived from sanitized readiness:\ngot:  %#v\nwant: %#v", *diagnostics, want)
	}
	if diagnostics.Status != sandbox.SandboxSecurityCapabilityDiagnosticSummaryStatusAdvisory ||
		diagnostics.HighestSeverity != sandbox.SandboxSecurityCapabilityDiagnosticSeverityWarning ||
		!diagnostics.AdvisoryOnly {
		t.Fatalf("capabilityReadinessDiagnostics = %#v, want advisory warning summary", diagnostics)
	}
	requireRuntimeCapabilityReadinessDiagnostic(t, diagnostics,
		sandbox.SandboxSecurityCapabilityDiagnosticClassificationUnsupported,
		sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy,
		sandbox.SandboxSecurityCapabilityNetworkDenyByDefault,
		true,
	)
	requireRuntimeCapabilityReadinessDiagnostic(t, diagnostics,
		sandbox.SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly,
		sandbox.SandboxSecurityCapabilityFamilyNetworkProxy,
		sandbox.SandboxSecurityCapabilityNetworkProxyEnforcement,
		true,
	)
	requireRuntimeCapabilityReadinessDiagnostic(t, diagnostics,
		sandbox.SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly,
		sandbox.SandboxSecurityCapabilityFamilyCredentialProxy,
		sandbox.SandboxSecurityCapabilityCredentialProxy,
		true,
	)

	encoded := mustMarshalSandboxSecurityMetadata(t, manifest.Security)
	if !strings.Contains(encoded, "capabilityReadinessDiagnostics") {
		t.Fatalf("security JSON omitted capabilityReadinessDiagnostics: %s", encoded)
	}
	assertPhase26CredentialProxyUnsafeValuesAbsent(t, "auto sandbox readiness diagnostics", encoded, fixture)
	assertPhase26CredentialProxyNoRedactionPlaceholders(t, "auto sandbox readiness diagnostics", diagnostics)
	for _, forbidden := range []string{"unix://", "/tmp/raw-worker-readiness.sock", "ghcr.io/private", "raw-readiness-image"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("capabilityReadinessDiagnostics leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestAutoSandboxReadinessDiagnosticsDoNotBlockOrAlterExecution(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 9, 0, 0, time.UTC)
	finishedAt := startedAt.Add(4 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(t.TempDir())
	target := autoSandboxCapabilityReadinessTarget()
	wantCommand := []string{"hal", "auto", "--base", "main"}

	var executed bool
	var remoteCommand []string
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		Base:                  "main",
		BaseChanged:           true,
		SandboxRuntime:        sandbox.SandboxRuntimeDriverRootlessPodman,
		SandboxRuntimeChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-readiness-diagnostics-nonblocking"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return autoSandboxTestPlan(projectDir), nil
		},
		execute: func(_ context.Context, req autoSandboxRequest, out io.Writer, _ io.Writer, hooks autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
			executed = true
			remoteCommand = append([]string(nil), req.RemoteCommand...)
			if strings.Contains(strings.Join(req.RemoteCommand, " "), "readiness") {
				t.Fatalf("RemoteCommand added diagnostics/readiness flag: %#v", req.RemoteCommand)
			}
			if hooks.OnTargetReady != nil {
				if err := hooks.OnTargetReady(target); err != nil {
					return autoSandboxExecutionResult{}, err
				}
			}
			_, _ = io.WriteString(out, autoSandboxRemoteSuccessJSON("readiness diagnostics preserved execution")+"\n")
			return autoSandboxExecutionResult{
				Result:          &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
				PreparedCommand: append([]string(nil), req.RemoteCommand...),
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if !executed {
		t.Fatal("execute hook was not called")
	}
	if !reflect.DeepEqual(remoteCommand, wantCommand) {
		t.Fatalf("RemoteCommand = %#v, want %#v", remoteCommand, wantCommand)
	}
	if !strings.Contains(out.String(), "readiness diagnostics preserved execution") {
		t.Fatalf("stdout = %q, want remote output unchanged", out.String())
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "auto-readiness-diagnostics-nonblocking")
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if manifest.Security == nil || manifest.Security.CapabilityReadinessDiagnostics == nil {
		t.Fatalf("Security = %#v, want non-blocking readiness diagnostics attached", manifest.Security)
	}
	if !manifest.Security.CapabilityReadinessDiagnostics.WouldBlockStrictGate {
		t.Fatalf("CapabilityReadinessDiagnostics = %#v, want wouldBlockStrictGate", manifest.Security.CapabilityReadinessDiagnostics)
	}
}

func TestAutoSandboxDefaultReadinessGateDoesNotTriggerSchedulerLeaseOrLiveRefresh(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	startedAt := time.Date(2026, 7, 2, 8, 11, 0, 0, time.UTC)
	finishedAt := startedAt.Add(4 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(t.TempDir())
	target := runSandboxCapabilityReadinessTarget(runSandboxSecurityRequest())
	target.Name = "auto-readiness-default-box"
	resolver := &fakeDefaultSandboxResolver{t: t, target: target}

	var execCalled bool
	var resolvedRuntime sandboxruntime.Target
	var out bytes.Buffer
	var errOut bytes.Buffer
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			resolvedRuntime = req.Target
			joinedArgs := strings.Join(req.Args, " ")
			for _, forbidden := range []string{"security-readiness-gate", "readiness-gate", "strict-readiness"} {
				if strings.Contains(joinedArgs, forbidden) {
					t.Fatalf("Exec args added readiness gate marker %q: %#v", forbidden, req.Args)
				}
			}
			if strings.Contains(joinedArgs, "'hal' 'auto'") {
				execCalled = true
				_, _ = io.WriteString(req.Stdout, autoSandboxRemoteSuccessJSON("default advisory readiness auto executed")+"\n")
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}

	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		Base:        "main",
		BaseChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-readiness-default-gate"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return autoSandboxTestPlan(projectDir), nil
		},
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatal("loadSandbox should not run without an explicit sandbox name")
			return nil, nil
		},
		resolveDefault: resolver.resolve,
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			t.Fatal("listHosts should not run for default auto readiness gate evaluation")
			return nil, nil
		},
		listLeases: func() ([]*sandbox.SandboxLease, error) {
			t.Fatal("listLeases should not run for default auto readiness gate evaluation")
			return nil, nil
		},
		acquireLease: func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
			t.Fatal("acquireLease should not run for default auto readiness gate evaluation")
			return nil, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return noLiveRefreshSandboxProvider{t: t}, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			t.Fatal("worker runtime resolver should not run for default auto readiness gate evaluation")
			return nil, nil
		},
		resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			resolvedRuntime = target
			return driver, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if !execCalled {
		t.Fatal("runtime Exec was not called for remote hal auto")
	}
	if resolver.calls != 1 {
		t.Fatalf("default resolver calls = %d, want 1", resolver.calls)
	}
	if resolvedRuntime.Name != "auto-readiness-default-box" {
		t.Fatalf("resolved runtime target = %#v, want selected default target", resolvedRuntime)
	}
	if !strings.Contains(out.String(), "default advisory readiness auto executed") {
		t.Fatalf("stdout = %q, want default execution output", out.String())
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "auto-readiness-default-gate")
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if manifest.Security == nil || manifest.Security.CapabilityReadinessDiagnostics == nil {
		t.Fatalf("Security = %#v, want advisory readiness diagnostics", manifest.Security)
	}
	if !manifest.Security.CapabilityReadinessDiagnostics.WouldBlockStrictGate {
		t.Fatalf("CapabilityReadinessDiagnostics = %#v, want wouldBlockStrictGate", manifest.Security.CapabilityReadinessDiagnostics)
	}
	if manifest.Lease != nil {
		t.Fatalf("Lease = %#v, want nil without scheduler acquisition", manifest.Lease)
	}
	encoded := mustMarshalSandboxSecurityMetadata(t, manifest)
	for _, forbidden := range []string{"security_readiness_gate", "readinessGate", "policyField", "policyMode"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("default auto manifest recorded readiness gate metadata %q: %s", forbidden, encoded)
		}
	}
}

func autoSandboxCapabilityReadinessTarget() *sandbox.SandboxState {
	return &sandbox.SandboxState{
		Name:     "auto-readiness",
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:       "worker-readiness-01",
			Name:     "worker-readiness",
			Kind:     sandbox.SandboxHostKindWorker,
			Endpoint: "unix:///tmp/raw-worker-readiness.sock",
			Security: &sandbox.SandboxSecurity{
				Network: &sandbox.SandboxNetworkSecurity{
					PolicyEnforced:  sandbox.SandboxNetworkPolicyDenyByDefault,
					EnforcementMode: sandbox.SandboxNetworkEnforcementModeFirewall,
				},
				Secrets: &sandbox.SandboxSecretSecurity{
					ActiveModes: []string{sandbox.SandboxSecretModeEnv},
				},
			},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
			RuntimeID:      "runtime-readiness-01",
			Image:          "ghcr.io/private/raw-readiness-image:latest",
			WorkerID:       "worker-readiness-01",
		},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
				PolicyEnforced:  sandbox.SandboxNetworkPolicyBestEffort,
				EnforcementMode: sandbox.SandboxNetworkEnforcementModeNone,
			},
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeEnv},
				ActiveModes:    []string{sandbox.SandboxSecretModeEnv},
			},
		},
	}
}

func requireAutoSandboxCapabilityReadinessOutput(t *testing.T, security *sandbox.SandboxSecurity) {
	t.Helper()
	if security == nil || security.CapabilityReadiness == nil {
		t.Fatalf("Security = %#v, want capabilityReadiness", security)
	}
	readiness := security.CapabilityReadiness
	if len(readiness.Results) == 0 {
		t.Fatal("capabilityReadiness results = empty")
	}
	var sawUnsupported bool
	var sawMetadataOnly bool
	for _, result := range readiness.Results {
		if result.State == sandbox.SandboxSecurityCapabilityReadinessUnsupported {
			sawUnsupported = true
		}
		if result.State == sandbox.SandboxSecurityCapabilityReadinessMetadataOnly {
			sawMetadataOnly = true
		}
	}
	if !sawUnsupported || !sawMetadataOnly {
		t.Fatalf("capabilityReadiness results = %#v, want unsupported request and metadata-only posture", readiness.Results)
	}
	if sanitized := sandbox.SanitizeSandboxSecurityCapabilityReadinessOutput(*readiness); !reflect.DeepEqual(sanitized, *readiness) {
		t.Fatalf("capabilityReadiness was not sanitized:\nsanitized: %#v\nreadiness: %#v", sanitized, *readiness)
	}
	payload, err := json.Marshal(readiness)
	if err != nil {
		t.Fatalf("Marshal(capabilityReadiness) error = %v", err)
	}
	encoded := string(payload)
	for _, forbidden := range []string{"unix://", "/tmp/raw-worker-readiness.sock", "ghcr.io/private", "raw-readiness-image"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("capabilityReadiness leaked %q: %s", forbidden, encoded)
		}
	}
}
