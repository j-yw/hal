package cmd

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestRunSandboxCapabilityReadinessOmittedWhenUnavailable(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 10, 0, 0, time.UTC)
	store := sandboxexecution.NewStore(t.TempDir())

	if err := saveRunSandboxManifest(store, runSandboxRequest{
		ExecutionID: "run-readiness-unavailable",
		ProjectDir:  "/repo",
		Security:    runSandboxSecurityRequest(),
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "run-readiness-unavailable")
	if manifest.Security == nil {
		t.Fatal("Security = nil, want existing run security metadata preserved")
	}
	if manifest.Security.CapabilityReadiness != nil {
		t.Fatalf("capabilityReadiness = %#v, want omitted without run projection inputs", manifest.Security.CapabilityReadiness)
	}
	encoded := mustMarshalSandboxSecurityMetadata(t, manifest.Security)
	if strings.Contains(encoded, "capabilityReadiness") {
		t.Fatalf("security JSON included capabilityReadiness without run projection inputs: %s", encoded)
	}
}

func TestRunSandboxManifestOmitsReadinessDiagnosticsWhenUnavailable(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 12, 0, 0, time.UTC)
	store := sandboxexecution.NewStore(t.TempDir())

	if err := saveRunSandboxManifest(store, runSandboxRequest{
		ExecutionID: "run-readiness-diagnostics-unavailable",
		ProjectDir:  "/repo",
		Security:    runSandboxSecurityRequest(),
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "run-readiness-diagnostics-unavailable")
	if manifest.Security == nil {
		t.Fatal("Security = nil, want existing run security metadata preserved")
	}
	if manifest.Security.CapabilityReadinessDiagnostics != nil {
		t.Fatalf("capabilityReadinessDiagnostics = %#v, want omitted without run readiness inputs", manifest.Security.CapabilityReadinessDiagnostics)
	}
	encoded := mustMarshalSandboxSecurityMetadata(t, manifest.Security)
	if strings.Contains(encoded, "capabilityReadinessDiagnostics") {
		t.Fatalf("security JSON included capabilityReadinessDiagnostics without run readiness inputs: %s", encoded)
	}
}

func TestRunSandboxManifestAttachesSanitizedProjectedCapabilityReadiness(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 15, 0, 0, time.UTC)
	store := sandboxexecution.NewStore(t.TempDir())
	fixture := phase26CredentialProxyUnsafeValues()
	req := runSandboxRequest{
		ExecutionID:         "run-readiness-projected",
		ProjectDir:          "/repo",
		NetworkProxySession: fixture.NetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceRun, "network-proxy-session-01", "policy-snapshot-01"),
		Security:            fixture.SecurityRequest([]string{sandbox.SandboxSecretModeHTTPProxy}, []string{sandbox.SandboxSecretModeHTTPProxy}),
	}
	target := runSandboxCapabilityReadinessTarget(req.Security)

	if err := saveRunSandboxManifest(store, req, sandboxexecution.StatusSucceeded, startedAt, &startedAt, target); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "run-readiness-projected")
	readiness := manifest.Security.CapabilityReadiness
	if readiness == nil {
		t.Fatal("capabilityReadiness = nil, want projected readiness output")
	}
	requireRunSandboxCapabilityReadinessResult(t, readiness,
		sandbox.SandboxSecurityCapabilityReadinessUnsupported,
		sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy,
		sandbox.SandboxSecurityCapabilityNetworkDenyByDefault,
	)
	requireRunSandboxCapabilityReadinessResult(t, readiness,
		sandbox.SandboxSecurityCapabilityReadinessMetadataOnly,
		sandbox.SandboxSecurityCapabilityFamilyNetworkProxy,
		sandbox.SandboxSecurityCapabilityNetworkProxyEnforcement,
	)
	requireRunSandboxCapabilityReadinessResult(t, readiness,
		sandbox.SandboxSecurityCapabilityReadinessMetadataOnly,
		sandbox.SandboxSecurityCapabilityFamilyCredentialProxy,
		sandbox.SandboxSecurityCapabilityCredentialProxy,
	)
	if sanitized := sandbox.SanitizeSandboxSecurityCapabilityReadinessOutput(*readiness); !reflect.DeepEqual(sanitized, *readiness) {
		t.Fatalf("capabilityReadiness was not sanitized:\nsanitized: %#v\nreadiness: %#v", sanitized, *readiness)
	}

	encoded := mustMarshalSandboxSecurityMetadata(t, manifest.Security)
	if !strings.Contains(encoded, "capabilityReadiness") {
		t.Fatalf("security JSON omitted capabilityReadiness: %s", encoded)
	}
	assertPhase26CredentialProxyUnsafeValuesAbsent(t, "run sandbox capability readiness", encoded, fixture)
	assertPhase26CredentialProxyNoRedactionPlaceholders(t, "run sandbox capability readiness", readiness)
}

func TestRunSandboxManifestAttachesSanitizedReadinessDiagnostics(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 17, 0, 0, time.UTC)
	store := sandboxexecution.NewStore(t.TempDir())
	fixture := phase26CredentialProxyUnsafeValues()
	req := runSandboxRequest{
		ExecutionID:         "run-readiness-diagnostics-projected",
		ProjectDir:          "/repo",
		NetworkProxySession: fixture.NetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceRun, "network-proxy-session-02", "policy-snapshot-02"),
		Security:            fixture.SecurityRequest([]string{sandbox.SandboxSecretModeHTTPProxy}, []string{sandbox.SandboxSecretModeHTTPProxy}),
	}
	target := runSandboxCapabilityReadinessTarget(req.Security)

	if err := saveRunSandboxManifest(store, req, sandboxexecution.StatusSucceeded, startedAt, &startedAt, target); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "run-readiness-diagnostics-projected")
	if manifest.Security == nil || manifest.Security.CapabilityReadiness == nil {
		t.Fatalf("Security = %#v, want capabilityReadiness for diagnostics", manifest.Security)
	}
	diagnostics := manifest.Security.CapabilityReadinessDiagnostics
	if diagnostics == nil {
		t.Fatal("capabilityReadinessDiagnostics = nil, want advisory diagnostics")
	}
	want := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*manifest.Security.CapabilityReadiness)
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
	assertPhase26CredentialProxyUnsafeValuesAbsent(t, "run sandbox readiness diagnostics", encoded, fixture)
	assertPhase26CredentialProxyNoRedactionPlaceholders(t, "run sandbox readiness diagnostics", diagnostics)
}

func TestRunSandboxCapabilityReadinessDoesNotBlockOrAlterExecution(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 20, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := runSandboxCapabilityReadinessTarget(runSandboxSecurityRequest())

	var executed bool
	var remoteCommand []string
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		Base:        "main",
		BaseChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-readiness-nonblocking"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/readiness", nil },
		execute: func(_ context.Context, req runSandboxRequest, out io.Writer, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
			executed = true
			remoteCommand = append([]string(nil), req.RemoteCommand...)
			if hooks.OnTargetReady != nil {
				if err := hooks.OnTargetReady(target); err != nil {
					return runSandboxExecutionResult{}, err
				}
			}
			if _, err := io.WriteString(out, "remote-output\n"); err != nil {
				return runSandboxExecutionResult{}, err
			}
			return runSandboxExecutionResult{
				Result: &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if !executed {
		t.Fatal("execute hook was not called")
	}
	wantCommand := []string{"hal", "run", "--base", "main"}
	if !reflect.DeepEqual(remoteCommand, wantCommand) {
		t.Fatalf("RemoteCommand = %#v, want %#v", remoteCommand, wantCommand)
	}
	if out.String() != "remote-output\n" {
		t.Fatalf("stdout = %q, want remote output unchanged", out.String())
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "run-readiness-nonblocking")
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if manifest.Security == nil || manifest.Security.CapabilityReadiness == nil {
		t.Fatalf("Security = %#v, want non-blocking readiness metadata attached", manifest.Security)
	}
}

func TestRunSandboxReadinessDiagnosticsDoNotBlockOrAlterExecution(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 8, 22, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := runSandboxCapabilityReadinessTarget(runSandboxSecurityRequest())

	var executed bool
	var remoteCommand []string
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		Base:        "main",
		BaseChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-readiness-diagnostics-nonblocking"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/readiness-diagnostics", nil },
		execute: func(_ context.Context, req runSandboxRequest, out io.Writer, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
			executed = true
			remoteCommand = append([]string(nil), req.RemoteCommand...)
			if strings.Contains(strings.Join(req.RemoteCommand, " "), "readiness") {
				t.Fatalf("RemoteCommand added diagnostics/readiness flag: %#v", req.RemoteCommand)
			}
			if hooks.OnTargetReady != nil {
				if err := hooks.OnTargetReady(target); err != nil {
					return runSandboxExecutionResult{}, err
				}
			}
			if _, err := io.WriteString(out, "remote-output\n"); err != nil {
				return runSandboxExecutionResult{}, err
			}
			return runSandboxExecutionResult{
				Result: &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if !executed {
		t.Fatal("execute hook was not called")
	}
	wantCommand := []string{"hal", "run", "--base", "main"}
	if !reflect.DeepEqual(remoteCommand, wantCommand) {
		t.Fatalf("RemoteCommand = %#v, want %#v", remoteCommand, wantCommand)
	}
	if out.String() != "remote-output\n" {
		t.Fatalf("stdout = %q, want remote output unchanged", out.String())
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "run-readiness-diagnostics-nonblocking")
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if manifest.Security == nil || manifest.Security.CapabilityReadinessDiagnostics == nil {
		t.Fatalf("Security = %#v, want non-blocking readiness diagnostics attached", manifest.Security)
	}
}

func TestRunSandboxDefaultReadinessGateDoesNotTriggerSchedulerLeaseOrLiveRefresh(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())

	startedAt := time.Date(2026, 7, 2, 8, 24, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := runSandboxCapabilityReadinessTarget(runSandboxSecurityRequest())
	target.Name = "run-readiness-default-box"
	resolver := &fakeDefaultSandboxResolver{t: t, target: target}

	var execCalled bool
	var resolvedRuntime sandboxruntime.Target
	var out bytes.Buffer
	var errOut bytes.Buffer
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			execCalled = true
			resolvedRuntime = req.Target
			if strings.Contains(strings.Join(req.Args, " "), "readiness") {
				t.Fatalf("Exec args added readiness gate flag: %#v", req.Args)
			}
			_, _ = io.WriteString(req.Stdout, "default readiness run executed\n")
			return &sandboxruntime.ExecResult{}, nil
		},
	}

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		Base:        "main",
		BaseChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-readiness-default-gate"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/run-readiness-default", nil },
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatal("loadSandbox should not run without an explicit sandbox name")
			return nil, nil
		},
		resolveDefault: resolver.resolve,
		listHosts: func() ([]*sandbox.SandboxHost, error) {
			t.Fatal("listHosts should not run for default run readiness gate evaluation")
			return nil, nil
		},
		listLeases: func() ([]*sandbox.SandboxLease, error) {
			t.Fatal("listLeases should not run for default run readiness gate evaluation")
			return nil, nil
		},
		acquireLease: func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
			t.Fatal("acquireLease should not run for default run readiness gate evaluation")
			return nil, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return noLiveRefreshSandboxProvider{t: t}, nil
		},
		resolveWorkerRuntime: func(sandboxWorkerRuntimeRequest) (sandboxruntime.Driver, error) {
			t.Fatal("worker runtime resolver should not run for default run readiness gate evaluation")
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
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if !execCalled {
		t.Fatal("runtime Exec was not called")
	}
	if resolver.calls != 1 {
		t.Fatalf("default resolver calls = %d, want 1", resolver.calls)
	}
	if resolvedRuntime.Name != "run-readiness-default-box" {
		t.Fatalf("resolved runtime target = %#v, want selected default target", resolvedRuntime)
	}
	if !strings.Contains(out.String(), "default readiness run executed") {
		t.Fatalf("stdout = %q, want default execution output", out.String())
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "run-readiness-default-gate")
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
			t.Fatalf("default run manifest recorded readiness gate metadata %q: %s", forbidden, encoded)
		}
	}
}

func runSandboxCapabilityReadinessTarget(securityReq sandbox.SecurityEvaluationRequest) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		ID:       "sandbox-readiness-01",
		Name:     "readiness-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:   "host-readiness-01",
			Name: "readiness-host",
			Kind: sandbox.SandboxHostKindSSH,
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverSSHMachine,
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
			RuntimeID:      "runtime-readiness-01",
		},
		Security: sandbox.EvaluateSandboxSecurity(securityReq),
	}
}

func requireRunSandboxCapabilityReadinessResult(t *testing.T, output *sandbox.SandboxSecurityCapabilityReadinessOutput, state sandbox.SandboxSecurityCapabilityReadinessState, family sandbox.SandboxSecurityCapabilityFamily, capability sandbox.SandboxSecurityCapabilityName) {
	t.Helper()
	if output == nil {
		t.Fatal("capabilityReadiness = nil")
	}
	for _, result := range output.Results {
		if result.State != state {
			continue
		}
		for _, metadata := range []*sandbox.SandboxSecurityCapabilityMetadata{result.Metadata, result.Requested, result.Ready} {
			if metadata == nil {
				continue
			}
			if metadata.Family == family && metadata.Capability == capability {
				return
			}
		}
	}
	t.Fatalf("capabilityReadiness missing %s result for %s/%s: %#v", state, family, capability, output.Results)
}

type noLiveRefreshSandboxProvider struct {
	fakeFactorySandboxProvider
	t *testing.T
}

func (p noLiveRefreshSandboxProvider) Status(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	p.t.Helper()
	p.t.Fatal("live provider status refresh should not run for default run readiness gate evaluation")
	return nil
}
