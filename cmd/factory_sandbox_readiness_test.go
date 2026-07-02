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
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestFactorySandboxCapabilityReadinessOmittedByDefault(t *testing.T) {
	target := factorySandboxReadinessTarget(sandbox.EvaluateSandboxSecurity(runSandboxSecurityRequest()))
	_, metadata := factorySandboxPersistentMetadataFromState(factorySandboxExecutorRequest{
		Security: runSandboxSecurityRequest(),
	}, factory.RunRecord{}, target)
	if metadata == nil || metadata.Security == nil {
		t.Fatalf("factory sandbox metadata = %#v, want default security metadata", metadata)
	}
	if metadata.Security.CapabilityReadiness != nil {
		t.Fatalf("capabilityReadiness = %#v, want omitted for default compatibility metadata", metadata.Security.CapabilityReadiness)
	}

	recordPayload := mustMarshalSandboxSecurityMetadata(t, factory.RunRecord{
		RunID:   "run-factory-readiness-default",
		Status:  factory.RunStatusRunning,
		Sandbox: metadata,
	})
	if strings.Contains(recordPayload, "capabilityReadiness") {
		t.Fatalf("factory run record included default capabilityReadiness: %s", recordPayload)
	}

	store := factory.NewStore(t.TempDir())
	record := &factory.RunRecord{RunID: "run-factory-readiness-default", Sandbox: metadata}
	if err := recordFactorySandboxSecurityPolicyEvent(store, factorySandboxExecutorDeps{
		now:         func() time.Time { return time.Date(2026, 7, 2, 9, 50, 0, 0, time.UTC) },
		appendEvent: appendFactorySandboxTimelineEvent,
	}, record, target, nil, factory.RunSecretRedactor{}); err != nil {
		t.Fatalf("recordFactorySandboxSecurityPolicyEvent() error = %v", err)
	}
	events, err := store.LoadEvents("run-factory-readiness-default")
	if err != nil {
		t.Fatalf("LoadEvents() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	timelinePayload := mustMarshalSandboxSecurityMetadata(t, events[0].Metadata)
	if strings.Contains(timelinePayload, "capabilityReadiness") {
		t.Fatalf("factory timeline included default capabilityReadiness: %s", timelinePayload)
	}
}

func TestFactorySandboxMetadataAttachesSanitizedProjectedCapabilityReadiness(t *testing.T) {
	fixture := phase26CredentialProxyUnsafeValues()
	req := factorySandboxExecutorRequest{
		Security:            fixture.SecurityRequest([]string{sandbox.SandboxSecretModeHTTPProxy}, []string{sandbox.SandboxSecretModeHTTPProxy}),
		NetworkProxySession: fixture.NetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceFactory, "network-proxy-session-factory-readiness", "policy-snapshot-factory-readiness"),
		NetworkPolicyDecisionLogs: unsafePolicyDecisionLogManifestRecords(
			sandbox.SandboxNetworkPolicyDecisionSource(" FACTORY "),
		),
	}
	target := factorySandboxReadinessTarget(sandbox.EvaluateSandboxSecurity(req.Security))
	target.Host.Endpoint = "unix:///tmp/raw-factory-readiness.sock"
	target.Runtime.Image = "ghcr.io/private/raw-factory-readiness-image:latest"

	_, metadata := factorySandboxPersistentMetadataFromState(req, factory.RunRecord{}, target)
	if metadata == nil || metadata.Security == nil || metadata.Security.CapabilityReadiness == nil {
		t.Fatalf("factory sandbox metadata = %#v, want projected capabilityReadiness", metadata)
	}
	readiness := metadata.Security.CapabilityReadiness
	requireFactorySandboxCapabilityReadinessResult(t, readiness,
		sandbox.SandboxSecurityCapabilityReadinessUnsupported,
		sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy,
		sandbox.SandboxSecurityCapabilityNetworkDenyByDefault,
	)
	requireFactorySandboxCapabilityReadinessResult(t, readiness,
		sandbox.SandboxSecurityCapabilityReadinessMetadataOnly,
		sandbox.SandboxSecurityCapabilityFamilyNetworkProxy,
		sandbox.SandboxSecurityCapabilityNetworkProxyEnforcement,
	)
	if sanitized := sandbox.SanitizeSandboxSecurityCapabilityReadinessOutput(*readiness); !reflect.DeepEqual(sanitized, *readiness) {
		t.Fatalf("capabilityReadiness was not sanitized:\nsanitized: %#v\nreadiness: %#v", sanitized, *readiness)
	}

	recordPayload := mustMarshalSandboxSecurityMetadata(t, factory.RunRecord{
		RunID:   "run-factory-readiness-projected",
		Status:  factory.RunStatusRunning,
		Sandbox: metadata,
	})
	if !strings.Contains(recordPayload, "capabilityReadiness") {
		t.Fatalf("factory run record omitted capabilityReadiness: %s", recordPayload)
	}
	assertPhase26CredentialProxyUnsafeValuesAbsent(t, "factory readiness record", recordPayload, fixture)
	readinessPayload := mustMarshalSandboxSecurityMetadata(t, readiness)
	for _, forbidden := range []string{"unix:///tmp/raw-factory-readiness.sock", "ghcr.io/private", "raw-factory-readiness-image"} {
		if strings.Contains(readinessPayload, forbidden) {
			t.Fatalf("factory readiness output leaked %q: %s", forbidden, readinessPayload)
		}
	}

	store := factory.NewStore(t.TempDir())
	record := &factory.RunRecord{RunID: "run-factory-readiness-projected", Sandbox: metadata}
	if err := recordFactorySandboxSecurityPolicyEvent(store, factorySandboxExecutorDeps{
		now:         func() time.Time { return time.Date(2026, 7, 2, 9, 55, 0, 0, time.UTC) },
		appendEvent: appendFactorySandboxTimelineEvent,
	}, record, target, req.NetworkPolicyDecisionLogs, factory.RunSecretRedactor{}); err != nil {
		t.Fatalf("recordFactorySandboxSecurityPolicyEvent() error = %v", err)
	}
	events, err := store.LoadEvents("run-factory-readiness-projected")
	if err != nil {
		t.Fatalf("LoadEvents() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	securityMap := requireSandboxSecurityMap(t, events[0].Metadata["security"])
	if _, ok := securityMap["capabilityReadiness"].(map[string]any); !ok {
		t.Fatalf("timeline security metadata = %#v, want capabilityReadiness object", securityMap)
	}
	timelinePayload := mustMarshalSandboxSecurityMetadata(t, events[0])
	assertPhase26CredentialProxyUnsafeValuesAbsent(t, "factory readiness timeline", timelinePayload, fixture)
	for _, forbidden := range []string{"unix:///tmp/raw-factory-readiness.sock", "ghcr.io/private", "raw-factory-readiness-image"} {
		if strings.Contains(timelinePayload, forbidden) {
			t.Fatalf("factory readiness timeline leaked %q: %s", forbidden, timelinePayload)
		}
	}
}

func TestFactorySandboxMetadataAttachesSanitizedReadinessDiagnostics(t *testing.T) {
	fixture, _, metadata, _ := factorySandboxReadinessDiagnosticsFixture(t)
	readiness := metadata.Security.CapabilityReadiness
	diagnostics := metadata.Security.CapabilityReadinessDiagnostics
	requireFactorySandboxReadinessDiagnostics(t, readiness, diagnostics)

	encoded := mustMarshalSandboxSecurityMetadata(t, metadata.Security)
	if !strings.Contains(encoded, "capabilityReadinessDiagnostics") {
		t.Fatalf("factory security metadata omitted capabilityReadinessDiagnostics: %s", encoded)
	}
	assertPhase26CredentialProxyUnsafeValuesAbsent(t, "factory readiness diagnostics metadata", encoded, fixture)
	assertFactorySandboxCredentialProxyPayloadExcludes(t, "factory readiness diagnostics metadata", encoded, factorySandboxReadinessDiagnosticsForbiddenValues(fixture)...)
	assertPhase26CredentialProxyNoRedactionPlaceholders(t, "factory readiness diagnostics metadata", diagnostics)
}

func TestFactorySandboxTimelineAttachesSanitizedReadinessDiagnostics(t *testing.T) {
	fixture, req, metadata, target := factorySandboxReadinessDiagnosticsFixture(t)
	store := factory.NewStore(t.TempDir())
	record := &factory.RunRecord{RunID: "run-factory-readiness-diagnostics-timeline", Sandbox: metadata}
	if err := recordFactorySandboxSecurityPolicyEvent(store, factorySandboxExecutorDeps{
		now:         func() time.Time { return time.Date(2026, 7, 2, 9, 57, 0, 0, time.UTC) },
		appendEvent: appendFactorySandboxTimelineEvent,
	}, record, target, req.NetworkPolicyDecisionLogs, factory.RunSecretRedactor{}); err != nil {
		t.Fatalf("recordFactorySandboxSecurityPolicyEvent() error = %v", err)
	}
	events, err := store.LoadEvents("run-factory-readiness-diagnostics-timeline")
	if err != nil {
		t.Fatalf("LoadEvents() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	securityMap := requireSandboxSecurityMap(t, events[0].Metadata["security"])
	diagnosticsMap, ok := securityMap["capabilityReadinessDiagnostics"].(map[string]any)
	if !ok {
		t.Fatalf("timeline security metadata = %#v, want capabilityReadinessDiagnostics object", securityMap)
	}
	if diagnosticsMap["status"] != string(sandbox.SandboxSecurityCapabilityDiagnosticSummaryStatusAdvisory) {
		t.Fatalf("timeline diagnostics = %#v, want advisory status", diagnosticsMap)
	}
	timelinePayload := mustMarshalSandboxSecurityMetadata(t, events[0])
	assertPhase26CredentialProxyUnsafeValuesAbsent(t, "factory readiness diagnostics timeline", timelinePayload, fixture)
	assertFactorySandboxCredentialProxyPayloadExcludes(t, "factory readiness diagnostics timeline", timelinePayload, factorySandboxReadinessDiagnosticsForbiddenValues(fixture)...)
	assertPhase26CredentialProxyNoRedactionPlaceholders(t, "factory readiness diagnostics timeline", events[0])
}

func TestRunFactorySandboxExecutorCapabilityReadinessDoesNotChangeExecution(t *testing.T) {
	now := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	fixture := phase26CredentialProxyUnsafeValues()
	securityReq := fixture.SecurityRequest([]string{sandbox.SandboxSecretModeHTTPProxy}, []string{sandbox.SandboxSecretModeHTTPProxy})
	target := factorySandboxReadinessTarget(sandbox.EvaluateSandboxSecurity(securityReq))
	record := factory.RunRecord{
		RunID:      "run-factory-readiness-nonblocking",
		RepoRemote: "git@github.com:example/repo.git",
		BaseBranch: "main",
		BranchName: "hal/factory-readiness",
		Status:     factory.RunStatusRunning,
	}
	remoteAuto := factoryRunAutoRequest{BaseBranch: "main"}
	wantArgs := factorySandboxRemoteCommandArgs(record, remoteAuto)

	var execCalled bool
	var gotExecArgs []string
	var remoteOutput bytes.Buffer
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:          t.TempDir(),
		SandboxName:         "factory-readiness",
		RunRecord:           record,
		Security:            securityReq,
		NetworkProxySession: fixture.NetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceFactory, "network-proxy-session-factory-exec", "policy-snapshot-factory-exec"),
		RemoteAuto:          remoteAuto,
		RemoteOutput:        &remoteOutput,
		DeferSuccessCleanup: true,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "factory-readiness" {
				t.Fatalf("load sandbox name = %q, want factory-readiness", name)
			}
			return target, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatal("resolveDefault should not run for explicit factory readiness target")
			return nil, "", nil
		},
		acquireLease: func(sandbox.SandboxLeaseAcquireRequest, time.Duration) (*sandbox.SandboxLease, error) {
			t.Fatal("acquireLease should not run for explicit factory readiness target")
			return nil, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				execCalled = true
				gotExecArgs = append([]string(nil), req.Args...)
				if _, err := io.WriteString(req.Stdout, "factory readiness execution\n"); err != nil {
					return nil, err
				}
				return &sandboxruntime.ExecResult{}, nil
			}}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile { return nil },
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v\noutput=%s", err, remoteOutput.String())
	}
	if !execCalled {
		t.Fatal("runtime Exec was not called")
	}
	if !reflect.DeepEqual(gotExecArgs, wantArgs) {
		t.Fatalf("exec args = %#v, want %#v", gotExecArgs, wantArgs)
	}
	if strings.Contains(strings.Join(gotExecArgs, " "), "readiness") {
		t.Fatalf("exec args added readiness flag: %#v", gotExecArgs)
	}

	storedRun, err := store.LoadRun("run-factory-readiness-nonblocking")
	if err != nil {
		t.Fatalf("LoadRun() error = %v", err)
	}
	if storedRun.Sandbox == nil || storedRun.Sandbox.Security == nil || storedRun.Sandbox.Security.CapabilityReadiness == nil {
		t.Fatalf("stored sandbox metadata = %#v, want non-blocking capabilityReadiness", storedRun.Sandbox)
	}
	payload, err := json.Marshal(storedRun)
	if err != nil {
		t.Fatalf("Marshal(storedRun) error = %v", err)
	}
	assertFactorySandboxCredentialProxyPayloadExcludes(t, "factory readiness executor", string(payload), fixture.ForbiddenValues()...)
}

func factorySandboxReadinessDiagnosticsFixture(t *testing.T) (phase26CredentialProxyUnsafeValueFixture, factorySandboxExecutorRequest, *factory.SandboxMetadata, *sandbox.SandboxState) {
	t.Helper()
	fixture := phase26CredentialProxyUnsafeValues()
	req := factorySandboxExecutorRequest{
		Security:            fixture.SecurityRequest([]string{sandbox.SandboxSecretModeHTTPProxy}, []string{sandbox.SandboxSecretModeHTTPProxy}),
		NetworkProxySession: fixture.NetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceFactory, "network-proxy-session-factory-readiness-diagnostics", "policy-snapshot-factory-readiness-diagnostics"),
		NetworkPolicyDecisionLogs: unsafePolicyDecisionLogManifestRecords(
			sandbox.SandboxNetworkPolicyDecisionSource(" FACTORY "),
		),
	}
	target := factorySandboxReadinessTarget(sandbox.EvaluateSandboxSecurity(req.Security))
	target.Host.Endpoint = "unix:///tmp/raw-factory-readiness-diagnostics.sock"
	target.Runtime.Image = "ghcr.io/private/raw-factory-readiness-diagnostics-image:latest"

	_, metadata := factorySandboxPersistentMetadataFromState(req, factory.RunRecord{}, target)
	if metadata == nil || metadata.Security == nil || metadata.Security.CapabilityReadiness == nil {
		t.Fatalf("factory sandbox metadata = %#v, want readiness metadata", metadata)
	}
	return fixture, req, metadata, target
}

func requireFactorySandboxReadinessDiagnostics(t *testing.T, readiness *sandbox.SandboxSecurityCapabilityReadinessOutput, diagnostics *sandbox.SandboxSecurityCapabilityReadinessDiagnosticSummary) {
	t.Helper()
	if readiness == nil {
		t.Fatal("capabilityReadiness = nil, want readiness output")
	}
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
}

func factorySandboxReadinessDiagnosticsForbiddenValues(fixture phase26CredentialProxyUnsafeValueFixture) []string {
	values := append([]string(nil), fixture.ForbiddenValues()...)
	values = append(values,
		"api.example.com",
		"169.254.169.254",
		"https://user:secret@example.test/path?token=secret",
		"unix:///tmp/private/proxy.sock",
		"/Users/alice/project",
		"Authorization",
		"Bearer",
		"OPENAI_API_KEY",
		"raw-header-token-value",
		"raw body secret value",
		"unix:///tmp/raw-factory-readiness-diagnostics.sock",
		"ghcr.io/private",
		"raw-factory-readiness-diagnostics-image",
	)
	return values
}

func factorySandboxReadinessTarget(security *sandbox.SandboxSecurity) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		Name:     "factory-readiness",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
		Host: &sandbox.SandboxHost{
			ID:   "host-factory-readiness",
			Name: "factory-readiness-host",
			Kind: sandbox.SandboxHostKindSSH,
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverSSHMachine,
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
			RuntimeID:      "runtime-factory-readiness",
		},
		Security: security,
	}
}

func requireFactorySandboxCapabilityReadinessResult(t *testing.T, output *sandbox.SandboxSecurityCapabilityReadinessOutput, state sandbox.SandboxSecurityCapabilityReadinessState, family sandbox.SandboxSecurityCapabilityFamily, capability sandbox.SandboxSecurityCapabilityName) {
	t.Helper()
	if output == nil {
		t.Fatal("capabilityReadiness = nil")
	}
	for _, result := range output.Results {
		if result.State == state && factorySandboxReadinessResultHasCapability(result, family, capability) {
			return
		}
	}
	t.Fatalf("capabilityReadiness results = %#v, want %s/%s/%s", output.Results, state, family, capability)
}

func factorySandboxReadinessResultHasCapability(result sandbox.SandboxSecurityCapabilityReadinessResult, family sandbox.SandboxSecurityCapabilityFamily, capability sandbox.SandboxSecurityCapabilityName) bool {
	for _, metadata := range []*sandbox.SandboxSecurityCapabilityMetadata{result.Metadata, result.Requested, result.Ready} {
		if metadata != nil && metadata.Family == family && metadata.Capability == capability {
			return true
		}
	}
	return false
}
