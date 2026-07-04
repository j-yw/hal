package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/securedefaultfixtures"
)

func TestUS011FactorySandboxRecordsAndTimelineUseSharedSecureDefaultDecision(t *testing.T) {
	tests := []struct {
		name    string
		fixture securedefaultfixtures.EvidenceSet
		wantErr bool
	}{
		{
			name:    "accepted complete evidence",
			fixture: securedefaultfixtures.CompleteAcceptedEvidenceSet(),
		},
		{
			name: "rejected missing network proof",
			fixture: securedefaultfixtures.CompleteAcceptedEvidenceSet(
				securedefaultfixtures.OmitProof(securedefaultfixtures.ProofProxyFirewallEnforcement),
			),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := factory.NewStore(t.TempDir())
			now := time.Date(2026, 7, 4, 19, 11, 0, 0, time.UTC)
			runID := "run-us011-" + us009RunSurfaceSlug(tt.name)
			record := us011FactoryRunRecord(runID)
			target := us011FactorySurfaceTarget(runID, tt.fixture)

			var remoteOutput bytes.Buffer
			err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
				ProjectDir:                "/workspace/us011-safe",
				SandboxName:               target.Name,
				RunRecord:                 record,
				SecurityReadinessGateMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
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
				resolveProvider: func(string) (sandbox.Provider, error) {
					return fakeFactorySandboxProvider{}, nil
				},
				resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
					if tt.wantErr {
						t.Fatal("runtime driver should not be resolved after rejected secure-default decision")
					}
					return fakeFactorySandboxRuntimeDriver{
						id: sandboxruntime.DriverMicroVM,
						execFn: func(_ context.Context, _ sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
							_, _ = io.WriteString(&remoteOutput, "us011 accepted\n")
							return &sandboxruntime.ExecResult{}, nil
						},
					}, nil
				},
				persistSandboxState: func(*sandbox.SandboxState) error { return nil },
				engineAuthFiles:     func() []factorySandboxAuthFile { return nil },
				bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
					return factory.BootstrapResult{}, nil
				},
			})
			if tt.wantErr && err == nil {
				t.Fatalf("runFactorySandboxExecutorWithDeps() error = nil, want rejected secure-default decision")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error = %v\nremote=%s", err, remoteOutput.String())
			}

			storedRun, err := store.LoadRun(runID)
			if err != nil {
				t.Fatalf("LoadRun() error = %v", err)
			}
			if storedRun.Sandbox == nil || storedRun.Sandbox.Security == nil {
				t.Fatalf("stored sandbox security = %#v, want secure-default metadata", storedRun.Sandbox)
			}
			us011AssertFactoryGateMatchesFixture(t, "factory run record", storedRun.Sandbox.Security.SecurityReadinessGate, tt.fixture.Gate)
			us009AssertRunSurfaceSafe(t, "factory run record security", storedRun.Sandbox.Security)

			events, err := store.LoadEvents(runID)
			if err != nil {
				t.Fatalf("LoadEvents() error = %v", err)
			}
			securityGate := us011FactorySecurityTimelineGate(t, events)
			us011AssertFactoryGateMatchesFixture(t, "factory security policy timeline", securityGate, tt.fixture.Gate)
			us009AssertRunSurfaceSafe(t, "factory security policy timeline", events)

			readinessEvent := us007RequireFactoryReadinessGateEvent(t, store, runID)
			us007AssertFactoryPolicyEventMatchesDecision(t, readinessEvent, sandbox.SanitizeSandboxSecurityCapabilityReadinessGateDecision(tt.fixture.Gate))
			us009AssertRunSurfaceSafe(t, "factory readiness policy timeline", readinessEvent)
		})
	}
}

func TestUS011FactoryFailureRecordRedactsSensitiveSandboxDetails(t *testing.T) {
	store := factory.NewStore(t.TempDir())
	now := time.Date(2026, 7, 4, 19, 16, 0, 0, time.UTC)
	runID := "run-us011-failure-redaction"
	target := us011FactorySurfaceTarget(runID, securedefaultfixtures.CompleteAcceptedEvidenceSet())
	us011SeedUnsafeFailureMetadata(target)
	record := us011FactoryRunRecord(runID)
	record.SandboxName, record.Sandbox = factorySandboxPersistentMetadataFromState(factorySandboxExecutorRequest{
		SecurityReadinessGateMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
	}, record, target)

	secretValue := "us011-env-value"
	failureErr := fmt.Errorf(
		"provider detail provider-secret=us011 endpoint %s host path %s socket %s firewall %s registry token %s env GITHUB_TOKEN=%s template %s credential %s",
		us011RawEndpoint(),
		us011RawHostPath(),
		us011RawSocketPath(),
		us011RawFirewallRule(),
		us011RawRegistryToken(),
		secretValue,
		us011RawTemplateReference(),
		us011RawCredential(),
	)

	err := recordFactorySandboxFailure(store, factorySandboxExecutorDeps{
		now:         func() time.Time { return now },
		saveRun:     saveFactorySandboxRunRecord,
		appendEvent: appendFactorySandboxTimelineEvent,
	}, &record, target, "resolve_driver", failureErr, factory.NewRunSecretRedactor([]factory.ResolvedRunSecret{
		{Name: "GITHUB_TOKEN", Source: factory.RunSecretSourceEnv, Value: secretValue},
		{Name: "REGISTRY_TOKEN", Source: factory.RunSecretSourceEnv, Value: us011RawRegistryToken()},
		{Name: "FACTORY_CREDENTIAL", Source: factory.RunSecretSourceEnv, Value: us011RawCredential()},
	}))
	if err != nil {
		t.Fatalf("recordFactorySandboxFailure() unexpected error = %v", err)
	}

	storedRun, err := store.LoadRun(runID)
	if err != nil {
		t.Fatalf("LoadRun() error = %v", err)
	}
	if storedRun.Status != factory.RunStatusFailed {
		t.Fatalf("stored run status = %q, want failed", storedRun.Status)
	}
	us011AssertFactoryFailureSafe(t, "factory failure run record", storedRun)

	events, err := store.LoadEvents(runID)
	if err != nil {
		t.Fatalf("LoadEvents() error = %v", err)
	}
	us011AssertFactoryFailureSafe(t, "factory failure timeline", events)
}

func us011FactoryRunRecord(runID string) factory.RunRecord {
	createdAt := time.Date(2026, 7, 4, 19, 10, 0, 0, time.UTC)
	return factory.RunRecord{
		RunID:        runID,
		Status:       factory.RunStatusRunning,
		ExecutorMode: factory.ExecutorModeSandbox,
		Source:       factory.SourceMetadata{Kind: factory.SourceKindPRD, Path: ".hal/prd.json"},
		RepoPath:     "/workspace/us011-safe",
		RepoRemote:   "https://example.invalid/org/us011-safe-repo.git",
		BranchName:   "hal/us011-factory-surface",
		BaseBranch:   "main",
		CurrentStep:  "prepare_inputs",
		CreatedAt:    createdAt,
		UpdatedAt:    createdAt,
	}
}

func us011FactorySurfaceTarget(name string, fixture securedefaultfixtures.EvidenceSet) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		ID:       name + "-target",
		Name:     name + "-sandbox",
		Provider: "phase60",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:                "us011-host",
			Name:              "us011 host",
			Kind:              sandbox.SandboxHostKindLocal,
			SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverMicroVM},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverMicroVM,
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
			RuntimeID:      "runtime-us011",
			TemplateLock:   fixture.WorkerRuntime.TemplateLock,
		},
		Workspace: fixture.WorkerRuntime.Workspace,
		Security:  fixture.Security(),
	}
}

func us011SeedUnsafeFailureMetadata(target *sandbox.SandboxState) {
	target.Provider = "phase60 provider-secret=us011"
	target.Host.Endpoint = us011RawEndpoint()
	target.Runtime.RuntimeID = us011RawSocketPath()
	target.Runtime.Image = "ghcr.io/private/" + us011RawTemplateReference() + ":" + us011RawRegistryToken()
	target.Runtime.WorkerID = "worker-" + us011RawCredential()
	target.Runtime.TemplateLock = us011UnsafeTemplateLock()
	target.Workspace = &sandbox.SandboxWorkspace{
		Mode:        sandbox.SandboxWorkspaceModeDirect,
		InputSource: sandbox.SandboxWorkspaceInputSourceCopy,
		Repo:        "https://alice:" + us011RawCredential() + "@example.invalid/private/repo.git",
		Branch:      "feature/us011",
		SyncRef:     us011RawHostPath(),
	}
}

func us011FactorySecurityTimelineGate(t *testing.T, events []factory.EventRecord) *sandbox.SandboxSecurityCapabilityReadinessGateDecision {
	t.Helper()
	for _, event := range events {
		if event.EventType != factory.EventTypePolicyDecision || event.Metadata["policyField"] != "sandbox.security" {
			continue
		}
		security, ok := event.Metadata["security"].(map[string]any)
		if !ok {
			t.Fatalf("factory security event metadata = %#v, want security object", event.Metadata)
		}
		gateRaw, ok := security["securityReadinessGate"].(map[string]any)
		if !ok {
			t.Fatalf("factory security event gate = %#v, want object", security["securityReadinessGate"])
		}
		return us011GateFromJSONMap(t, gateRaw)
	}
	t.Fatalf("factory security policy event not found in %#v", events)
	return nil
}

func us011GateFromJSONMap(t *testing.T, raw map[string]any) *sandbox.SandboxSecurityCapabilityReadinessGateDecision {
	t.Helper()
	var gate sandbox.SandboxSecurityCapabilityReadinessGateDecision
	us011DecodeJSONValue(t, raw, &gate)
	return sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(&gate)
}

func us011DecodeJSONValue(t *testing.T, value any, target any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON value: %v", err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal JSON value: %v\nraw=%s", err, data)
	}
}

func us011AssertFactoryGateMatchesFixture(t *testing.T, label string, got *sandbox.SandboxSecurityCapabilityReadinessGateDecision, want sandbox.SandboxSecurityCapabilityReadinessGateDecision) {
	t.Helper()
	sanitizedWant := sandbox.SanitizeSandboxSecurityCapabilityReadinessGateDecision(want)
	sanitizedGot := sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(got)
	if sanitizedGot == nil {
		t.Fatalf("%s securityReadinessGate = nil, want %#v", label, sanitizedWant)
	}
	if !reflect.DeepEqual(*sanitizedGot, sanitizedWant) {
		t.Fatalf("%s securityReadinessGate = %#v, want shared fixture decision %#v", label, *sanitizedGot, sanitizedWant)
	}
}

func us011AssertFactoryFailureSafe(t *testing.T, label string, value any) {
	t.Helper()
	payload := us007JSONString(t, value)
	for _, forbidden := range []string{
		us011RawCredential(),
		us011RawEndpoint(),
		us011RawHostPath(),
		us011RawSocketPath(),
		us011RawFirewallRule(),
		us011RawRegistryToken(),
		us011RawTemplateReference(),
		"provider-secret=us011",
		"GITHUB_TOKEN=us011-env-value",
		"us011-env-value",
		"Authorization",
		"Bearer",
		"iptables",
		"nft ",
		".sock",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("%s leaked forbidden fragment %q: %s", label, forbidden, payload)
		}
	}
}

func us011RawCredential() string {
	return "github_pat_us011Credential1234567890"
}

func us011RawEndpoint() string {
	return "https://provider.example.invalid/tenant/us011?provider-secret=us011"
}

func us011RawHostPath() string {
	return "/Users/alice/private/us011-worktree"
}

func us011RawSocketPath() string {
	return "/private/tmp/us011-runtime.sock"
}

func us011RawFirewallRule() string {
	return "iptables -A OUTPUT -d 203.0.113.42 -j DROP"
}

func us011RawRegistryToken() string {
	return "registry-token-us011"
}

func us011RawTemplateReference() string {
	return "raw-template-ref-us011"
}

func us011UnsafeTemplateLock() *sandbox.SandboxTemplateLockMetadata {
	return &sandbox.SandboxTemplateLockMetadata{
		Document: &sandbox.SandboxTemplateLockEntryMetadata{
			SourceKind:      sandbox.SandboxTemplateLockSourceKindLocalFile,
			ReferenceKind:   sandbox.SandboxTemplateLockReferenceKindLocal,
			Status:          sandbox.SandboxTemplateLockStatusLocked,
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("a", 64),
			WarningCodes:    []string{us011RawTemplateReference(), us011RawCredential()},
			ReasonCode:      sandbox.SandboxTemplateLockReasonDocumentDigest,
		},
		TrustPolicy: &sandbox.SandboxTemplateTrustPolicyMetadata{
			Mode:            sandbox.SandboxTemplateTrustPolicyModeStrict,
			Decision:        sandbox.SandboxTemplateTrustPolicyDecisionTrusted,
			SourceKind:      sandbox.SandboxTemplateLockSourceKindLocalFile,
			ReferenceKind:   sandbox.SandboxTemplateLockReferenceKindLocal,
			Status:          sandbox.SandboxTemplateLockStatusLocked,
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("b", 64),
			WarningCodes:    []string{us011RawEndpoint(), us011RawRegistryToken()},
			ErrorCodes:      []string{us011RawHostPath(), us011RawSocketPath()},
			ReasonCodes:     []string{us011RawTemplateReference(), us011RawFirewallRule()},
		},
	}
}
