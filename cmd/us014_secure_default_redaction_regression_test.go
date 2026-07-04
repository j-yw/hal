package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/jywlabs/hal/internal/securedefaultfixtures"
)

func TestUS014RunAutoCommandJSONAndManifestsRedactSeededSensitiveValues(t *testing.T) {
	raw := us014SensitiveCorpus()

	t.Run("run", func(t *testing.T) {
		t.Setenv("HAL_CONFIG_HOME", t.TempDir())

		startedAt := time.Date(2026, 7, 4, 22, 14, 0, 0, time.UTC)
		finishedAt := startedAt.Add(time.Second)
		projectDir := filepath.Join(t.TempDir(), "repo")
		writeStrictOnlyRunAutoReadinessGateConfig(t, projectDir)
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "run-executions"))
		executionID := "run-us014-redaction"
		target := us014SecureDefaultTarget(executionID, raw)

		var out bytes.Buffer
		var errOut bytes.Buffer
		err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
			JSON:        true,
			JSONChanged: true,
			Base:        "main",
			BaseChanged: true,
		}, &out, &errOut, runSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID: func(time.Time) string {
				return executionID
			},
			now:        runSandboxTestClock(startedAt, finishedAt),
			workingDir: func() (string, error) { return projectDir, nil },
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				return us009RunSurfaceWorkspacePlan(projectDir), nil
			},
			execute: func(_ context.Context, _ runSandboxRequest, stdout io.Writer, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
				if hooks.OnTargetReady != nil {
					if err := hooks.OnTargetReady(target); err != nil {
						return runSandboxExecutionResult{}, err
					}
				}
				if _, err := io.WriteString(stdout, `{"contractVersion":1,"ok":true,"summary":"us014 run redaction"}`+"\n"); err != nil {
					return runSandboxExecutionResult{}, err
				}
				return runSandboxExecutionResult{
					Result:        &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
					RemoteStarted: true,
				}, nil
			},
		})
		if err != nil {
			t.Fatalf("runRunSandboxWithWriter() error = %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
		}

		var result RunResult
		decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
		us014AssertNoSensitiveValues(t, "run command JSON", out.String(), raw)
		us014AssertManifestFileSafe(t, "run manifest file", store, executionID, raw)
		manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
		us014AssertNoSensitiveValues(t, "run manifest", manifest, raw)
	})

	t.Run("auto", func(t *testing.T) {
		t.Setenv("HAL_CONFIG_HOME", t.TempDir())

		startedAt := time.Date(2026, 7, 4, 22, 15, 0, 0, time.UTC)
		finishedAt := startedAt.Add(time.Second)
		projectDir := filepath.Join(t.TempDir(), "repo")
		writeStrictOnlyRunAutoReadinessGateConfig(t, projectDir)
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "auto-executions"))
		executionID := "auto-us014-redaction"
		target := us014SecureDefaultTarget(executionID, raw)

		var out bytes.Buffer
		var errOut bytes.Buffer
		err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
			JSON:        true,
			JSONChanged: true,
			Base:        "main",
			BaseChanged: true,
		}, &out, &errOut, autoSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID: func(time.Time) string {
				return executionID
			},
			now: runSandboxTestClock(startedAt, finishedAt),
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				return us010AutoSurfaceWorkspacePlan(projectDir)
			},
			execute: func(_ context.Context, _ autoSandboxRequest, stdout io.Writer, _ io.Writer, hooks autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
				if hooks.OnTargetReady != nil {
					if err := hooks.OnTargetReady(target); err != nil {
						return autoSandboxExecutionResult{}, err
					}
				}
				if _, err := io.WriteString(stdout, autoSandboxRemoteSuccessJSON("us014 auto redaction")+"\n"); err != nil {
					return autoSandboxExecutionResult{}, err
				}
				return autoSandboxExecutionResult{
					Result:        &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
					RemoteStarted: true,
				}, nil
			},
		})
		if err != nil {
			t.Fatalf("runAutoSandboxWithWriter() error = %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
		}

		var result AutoResult
		decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
		us014AssertNoSensitiveValues(t, "auto command JSON", out.String(), raw)
		us014AssertManifestFileSafe(t, "auto manifest file", store, executionID, raw)
		manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
		us014AssertNoSensitiveValues(t, "auto manifest", manifest, raw)
	})
}

func TestUS014OptionalManifestMetadataRedactsSeededSensitiveValues(t *testing.T) {
	raw := us014SensitiveCorpus()
	startedAt := time.Date(2026, 7, 4, 22, 16, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)

	t.Run("run", func(t *testing.T) {
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "run-manifest"))
		executionID := "run-us014-optional-manifest"
		target := us014SecureDefaultTarget(executionID, raw)
		req := us014RunManifestRequest(executionID, raw)
		if err := saveRunSandboxManifest(store, req, sandboxexecution.StatusSucceeded, startedAt, &finishedAt, target); err != nil {
			t.Fatalf("saveRunSandboxManifest() error = %v", err)
		}
		us014AssertManifestFileSafe(t, "run optional manifest file", store, executionID, raw)
		manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
		us014AssertNoSensitiveValues(t, "run optional manifest", manifest, raw)
	})

	t.Run("auto", func(t *testing.T) {
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "auto-manifest"))
		executionID := "auto-us014-optional-manifest"
		target := us014SecureDefaultTarget(executionID, raw)
		req := us014AutoManifestRequest(executionID, raw)
		if err := saveAutoSandboxManifest(store, req, sandboxexecution.StatusSucceeded, startedAt, &finishedAt, target); err != nil {
			t.Fatalf("saveAutoSandboxManifest() error = %v", err)
		}
		us014AssertManifestFileSafe(t, "auto optional manifest file", store, executionID, raw)
		manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
		us014AssertNoSensitiveValues(t, "auto optional manifest", manifest, raw)
	})
}

func TestUS014FactoryRecordsTimelineAndFailuresRedactSeededSensitiveValues(t *testing.T) {
	raw := us014SensitiveCorpus()
	store := factory.NewStore(t.TempDir())
	now := time.Date(2026, 7, 4, 22, 17, 0, 0, time.UTC)
	runID := "run-us014-factory-redaction"
	target := us014SecureDefaultTarget(runID, raw)
	us014SeedFactoryFailureTarget(target, raw)
	record := us011FactoryRunRecord(runID)
	record.SandboxName, record.Sandbox = factorySandboxPersistentMetadataFromState(factorySandboxExecutorRequest{
		SecurityReadinessGateMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
	}, record, target)

	failureErr := fmt.Errorf(
		"secure-default failure: credential %s endpoint %s path %s socket %s firewall %s provider %s registry %s env %s template %s",
		raw.Credential,
		raw.Endpoint,
		raw.HostPath,
		raw.SocketPath,
		raw.FirewallRule,
		raw.ProviderDetail,
		raw.RegistryToken,
		raw.EnvValue,
		raw.TemplateReference,
	)
	redactor := factory.NewRunSecretRedactor([]factory.ResolvedRunSecret{
		{Name: "US014_CREDENTIAL", Source: factory.RunSecretSourceEnv, Value: raw.Credential},
		{Name: "US014_REGISTRY_TOKEN", Source: factory.RunSecretSourceEnv, Value: raw.RegistryToken},
		{Name: "US014_ENV_VALUE", Source: factory.RunSecretSourceEnv, Value: raw.EnvValue},
	})

	if err := recordFactorySandboxFailure(store, factorySandboxExecutorDeps{
		now:         func() time.Time { return now },
		saveRun:     saveFactorySandboxRunRecord,
		appendEvent: appendFactorySandboxTimelineEvent,
	}, &record, target, "secure_default_validation", failureErr, redactor); err != nil {
		t.Fatalf("recordFactorySandboxFailure() error = %v", err)
	}

	storedRun, err := store.LoadRun(runID)
	if err != nil {
		t.Fatalf("LoadRun() error = %v", err)
	}
	us014AssertNoSensitiveValues(t, "factory run record", storedRun, raw)
	if storedRun.Failure == nil {
		t.Fatal("factory failure = nil, want failure summary")
	}
	us014AssertNoSensitiveValues(t, "factory failure message", storedRun.Failure.Message, raw)

	events, err := store.LoadEvents(runID)
	if err != nil {
		t.Fatalf("LoadEvents() error = %v", err)
	}
	us014AssertNoSensitiveValues(t, "factory timeline events", events, raw)
	for _, event := range events {
		us014AssertNoSensitiveValues(t, "factory timeline message", event.Message, raw)
	}
}

func TestUS014SkipAndFailureJSONMessagesRedactSeededSensitiveValues(t *testing.T) {
	raw := us014SensitiveCorpus()
	errMsg := "secure-default skip/failure: " + strings.Join(raw.Values(), " ")
	gate := us014UnsafeGateDecision(raw)

	var runOut bytes.Buffer
	if err := outputRunJSONErrorWithReadinessGate(&runOut, errMsg, gate); err != nil {
		t.Fatalf("outputRunJSONErrorWithReadinessGate() error = %v", err)
	}
	us014AssertNoSensitiveValues(t, "run failure JSON", runOut.String(), raw)

	var autoOut bytes.Buffer
	if err := outputAutoSandboxJSONErrorWithReadinessGate(&autoOut, nil, autoSandboxOptions{JSON: true}, errMsg, gate); err != nil {
		t.Fatalf("outputAutoSandboxJSONErrorWithReadinessGate() error = %v", err)
	}
	us014AssertNoSensitiveValues(t, "auto failure JSON", autoOut.String(), raw)
}

func TestUS014Phase60DocsExamplesDoNotContainSeededSensitiveValues(t *testing.T) {
	raw := us014SensitiveCorpus()
	matches, err := filepath.Glob(filepath.Join("..", "docs", "design", "*phase60*"))
	if err != nil {
		t.Fatalf("Glob phase60 docs: %v", err)
	}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		us014AssertNoSensitiveValues(t, "phase60 doc example "+path, data, raw)
	}
}

type us014SensitiveValues struct {
	Credential        string
	Endpoint          string
	HostPath          string
	SocketPath        string
	FirewallRule      string
	ProviderDetail    string
	RegistryToken     string
	EnvValue          string
	TemplateReference string
}

func us014SensitiveCorpus() us014SensitiveValues {
	return us014SensitiveValues{
		Credential:        "github_pat_us014CredentialLeakValue1234567890",
		Endpoint:          "https://phase60-provider.internal.invalid/tenant/us014?token=raw",
		HostPath:          "/Users/alice/private/us014-worktree",
		SocketPath:        "/private/tmp/us014-runtime.sock",
		FirewallRule:      "iptables -A OUTPUT -d 203.0.113.60 -j DROP",
		ProviderDetail:    "provider-secret=us014-provider-detail",
		RegistryToken:     "registry-token-us014-sensitive",
		EnvValue:          "us014-secret-env-value-sensitive",
		TemplateReference: "raw-template-ref-us014-sensitive",
	}
}

func (v us014SensitiveValues) Values() []string {
	return []string{
		v.Credential,
		v.Endpoint,
		v.HostPath,
		v.SocketPath,
		v.FirewallRule,
		v.ProviderDetail,
		v.RegistryToken,
		v.EnvValue,
		v.TemplateReference,
	}
}

func us014SecureDefaultTarget(name string, raw us014SensitiveValues) *sandbox.SandboxState {
	fixture := securedefaultfixtures.CompleteAcceptedEvidenceSet()
	target := &sandbox.SandboxState{
		ID:       name + "-target",
		Name:     name + "-sandbox",
		Provider: "phase60",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:                "us014-host",
			Name:              "us014 host",
			Kind:              sandbox.SandboxHostKindLocal,
			SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverMicroVM},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverMicroVM,
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
			RuntimeID:      "runtime-us014",
			TemplateLock:   fixture.WorkerRuntime.TemplateLock,
		},
		Workspace: fixture.WorkerRuntime.Workspace,
		Security:  fixture.Security(),
	}
	us014SeedSensitiveSecureDefaultMetadata(target, raw)
	return target
}

func us014SeedSensitiveSecureDefaultMetadata(target *sandbox.SandboxState, raw us014SensitiveValues) {
	if target == nil {
		return
	}
	target.Workspace = &sandbox.SandboxWorkspace{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
		Repo:        "https://git:" + raw.Credential + "@example.invalid/private/us014.git",
		Branch:      "phase60-secure-default",
		SyncRef:     raw.HostPath,
	}
	if target.Runtime != nil {
		target.Runtime.TemplateLock = us014SensitiveTemplateLock(raw)
	}
	if target.Security == nil {
		target.Security = &sandbox.SandboxSecurity{}
	}
	target.Security.Secrets = &sandbox.SandboxSecretSecurity{
		RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy, raw.EnvValue, raw.Credential},
		ActiveModes:    []string{sandbox.SandboxSecretModeHTTPProxy, raw.RegistryToken, raw.SocketPath},
	}
	target.Security.Network = &sandbox.SandboxNetworkSecurity{
		PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
		PolicyEnforced:  sandbox.SandboxNetworkPolicyDenyByDefault,
		EnforcementMode: sandbox.SandboxNetworkEnforcementModeProxyFirewall,
		PolicyResult:    us014SensitiveNetworkPolicyResult(raw),
	}
	if target.Security.CapabilityReadiness != nil {
		target.Security.CapabilityReadiness.Results = append(target.Security.CapabilityReadiness.Results, sandbox.SandboxSecurityCapabilityReadinessResult{
			State:      sandbox.SandboxSecurityCapabilityReadinessReady,
			ReasonCode: sandbox.SandboxSecurityCapabilityReasonCode(raw.TemplateReference),
			Metadata: &sandbox.SandboxSecurityCapabilityMetadata{
				ID:           raw.Endpoint,
				Family:       sandbox.SandboxSecurityCapabilityFamilyTemplate,
				Capability:   sandbox.SandboxSecurityCapabilitySelectedTemplateTrust,
				Mode:         raw.Credential,
				Source:       sandbox.SandboxSecurityCapabilitySourceWorker,
				Status:       sandbox.SandboxSecurityCapabilityReadinessReady,
				ReasonCode:   sandbox.SandboxSecurityCapabilityReasonCode(raw.ProviderDetail),
				WarningCodes: []sandbox.SandboxSecurityCapabilityWarningCode{sandbox.SandboxSecurityCapabilityWarningCode(raw.FirewallRule)},
			},
		})
	}
	if target.Security.SecurityReadinessGate != nil {
		target.Security.SecurityReadinessGate.Reason = sandbox.SandboxSecurityCapabilityReadinessGateReasonCode(raw.ProviderDetail)
		if target.Security.SecurityReadinessGate.Counts == nil {
			target.Security.SecurityReadinessGate.Counts = &sandbox.SandboxSecurityCapabilityReadinessGateCounts{}
		}
		target.Security.SecurityReadinessGate.Counts.ReasonCodeCounts = map[sandbox.SandboxSecurityCapabilityReasonCode]int{
			sandbox.SandboxSecurityCapabilityReasonCode(raw.Endpoint):          1,
			sandbox.SandboxSecurityCapabilityReasonCode(raw.TemplateReference): 1,
		}
	}
}

func us014SensitiveNetworkPolicyResult(raw us014SensitiveValues) *sandbox.SandboxNetworkPolicyResult {
	return &sandbox.SandboxNetworkPolicyResult{
		Requested: sandbox.SandboxNetworkPolicyIntent{
			Preset: sandbox.SandboxNetworkPolicyPresetDenyByDefault,
			Rules: []sandbox.SandboxNetworkPolicyRule{
				{Kind: sandbox.SandboxNetworkPolicyRuleKindEndpoint, Value: raw.Endpoint, Decision: sandbox.SandboxNetworkPolicyDecisionDeny},
				{Kind: sandbox.SandboxNetworkPolicyRuleKindDomain, Value: raw.RegistryToken, Decision: sandbox.SandboxNetworkPolicyDecisionDeny},
			},
		},
		Effective: sandbox.SandboxNetworkPolicyIntent{
			Preset: sandbox.SandboxNetworkPolicyPresetDenyByDefault,
			Rules: []sandbox.SandboxNetworkPolicyRule{
				{Kind: sandbox.SandboxNetworkPolicyRuleKindEndpoint, Value: raw.FirewallRule, Decision: sandbox.SandboxNetworkPolicyDecisionDeny},
			},
		},
		EnforcementMode: raw.FirewallRule,
		Capability: sandbox.SandboxNetworkPolicyEnforcementCapability{
			Supported:                  true,
			Modes:                      []string{sandbox.SandboxNetworkEnforcementModeProxyFirewall, raw.ProviderDetail, raw.SocketPath},
			SupportsDomainRules:        true,
			SupportsEndpointRules:      true,
			SupportsDefaultDenyPosture: true,
		},
		Warnings: []sandbox.SandboxNetworkPolicyWarning{{
			Code:    sandbox.SandboxNetworkPolicyWarningUnsupportedEnforcement,
			Policy:  raw.TemplateReference,
			Reason:  sandbox.SandboxNetworkPolicyWarningReasonEnforcementUnsupported,
			Message: raw.ProviderDetail,
		}},
	}
}

func us014SensitiveTemplateLock(raw us014SensitiveValues) *sandbox.SandboxTemplateLockMetadata {
	return &sandbox.SandboxTemplateLockMetadata{
		Document: &sandbox.SandboxTemplateLockEntryMetadata{
			SourceKind:      sandbox.SandboxTemplateLockSourceKindLocalFile,
			ReferenceKind:   sandbox.SandboxTemplateLockReferenceKindLocal,
			Status:          sandbox.SandboxTemplateLockStatusLocked,
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("a", 64),
			WarningCodes:    []string{raw.HostPath, raw.TemplateReference},
			ReasonCode:      raw.ProviderDetail,
		},
		TemplateReference: &sandbox.SandboxTemplateLockEntryMetadata{
			SourceKind:      sandbox.SandboxTemplateLockSourceKindTemplateReference,
			ReferenceKind:   sandbox.SandboxTemplateLockReferenceKindOCIArtifact,
			Status:          sandbox.SandboxTemplateLockStatusLocked,
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("b", 64),
			WarningCodes:    []string{raw.RegistryToken},
			ReasonCode:      raw.TemplateReference,
		},
		TrustPolicy: &sandbox.SandboxTemplateTrustPolicyMetadata{
			Mode:            sandbox.SandboxTemplateTrustPolicyModeStrict,
			Decision:        sandbox.SandboxTemplateTrustPolicyDecisionTrusted,
			SourceKind:      sandbox.SandboxTemplateLockSourceKindTemplateReference,
			ReferenceKind:   sandbox.SandboxTemplateLockReferenceKindOCIArtifact,
			Status:          sandbox.SandboxTemplateLockStatusLocked,
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("c", 64),
			WarningCodes:    []string{raw.Endpoint, raw.Credential},
			ErrorCodes:      []string{raw.SocketPath},
			ReasonCodes:     []string{raw.FirewallRule, raw.ProviderDetail},
		},
	}
}

func us014RunManifestRequest(executionID string, raw us014SensitiveValues) runSandboxRequest {
	return runSandboxRequest{
		ExecutionID:               executionID,
		SandboxName:               executionID + "-sandbox",
		ProjectDir:                "/workspace/us014-safe",
		WorkDir:                   "/workspace/us014-safe/work",
		RemoteCommand:             []string{"hal", "run", "--json"},
		Security:                  us014SensitiveSecurityEvaluationRequest(raw),
		SecurityReadinessGateMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		NetworkProxySession:       us014SensitiveNetworkProxySession(raw, sandbox.SandboxNetworkPolicyDecisionSourceRun),
		NetworkPolicyDecisionLogs: us014SensitiveDecisionLogs(raw, sandbox.SandboxNetworkPolicyDecisionSourceRun),
		Workspace: &sandbox.SandboxWorkspace{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
			Branch:      "phase60-secure-default",
			SyncRef:     "refs/heads/phase60-secure-default",
		},
	}
}

func us014AutoManifestRequest(executionID string, raw us014SensitiveValues) autoSandboxRequest {
	return autoSandboxRequest{
		ExecutionID:               executionID,
		SandboxName:               executionID + "-sandbox",
		ProjectDir:                "/workspace/us014-safe",
		WorkDir:                   "/workspace/us014-safe/work",
		RemoteCommand:             []string{"hal", "auto", "--json"},
		Security:                  us014SensitiveSecurityEvaluationRequest(raw),
		SecurityReadinessGateMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		NetworkProxySession:       us014SensitiveNetworkProxySession(raw, sandbox.SandboxNetworkPolicyDecisionSourceAuto),
		NetworkPolicyDecisionLogs: us014SensitiveDecisionLogs(raw, sandbox.SandboxNetworkPolicyDecisionSourceAuto),
		Workspace: &sandbox.SandboxWorkspace{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
			Branch:      "phase60-secure-default",
			SyncRef:     "refs/heads/phase60-secure-default",
		},
	}
}

func us014SensitiveSecurityEvaluationRequest(raw us014SensitiveValues) sandbox.SecurityEvaluationRequest {
	return sandbox.SecurityEvaluationRequest{
		RequestedNetworkPolicyIntent: &sandbox.SandboxNetworkPolicyIntent{
			Preset: sandbox.SandboxNetworkPolicyPresetDenyByDefault,
			Rules: []sandbox.SandboxNetworkPolicyRule{{
				Kind:     sandbox.SandboxNetworkPolicyRuleKindEndpoint,
				Value:    raw.Endpoint,
				Decision: sandbox.SandboxNetworkPolicyDecisionDeny,
			}},
		},
		NetworkPolicyCapability: &sandbox.SandboxNetworkPolicyEnforcementCapability{
			Supported:                  true,
			Modes:                      []string{sandbox.SandboxNetworkEnforcementModeProxyFirewall, raw.FirewallRule},
			SupportsEndpointRules:      true,
			SupportsDefaultDenyPosture: true,
		},
		RequestedSecretModes: []string{sandbox.SandboxSecretModeHTTPProxy, raw.EnvValue, raw.Credential},
		ActiveSecretModes:    []string{sandbox.SandboxSecretModeHTTPProxy, raw.RegistryToken},
	}
}

func us014SensitiveNetworkProxySession(raw us014SensitiveValues, source sandbox.SandboxNetworkPolicyDecisionSource) *sandbox.SandboxNetworkProxySessionMetadata {
	return &sandbox.SandboxNetworkProxySessionMetadata{
		ID:     raw.SocketPath,
		Source: source,
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:        raw.ProviderDetail,
			Version:   raw.Endpoint,
			Preset:    sandbox.SandboxNetworkPolicyPresetDenyByDefault,
			RuleSetID: raw.FirewallRule,
		},
		EnforcementMode: raw.FirewallRule,
	}
}

func us014SensitiveDecisionLogs(raw us014SensitiveValues, source sandbox.SandboxNetworkPolicyDecisionSource) []sandbox.SandboxNetworkPolicyDecisionLogRecord {
	enforced := true
	return []sandbox.SandboxNetworkPolicyDecisionLogRecord{{
		ID:             raw.RegistryToken,
		Source:         source,
		ProxySessionID: raw.SocketPath,
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:        raw.ProviderDetail,
			Version:   raw.TemplateReference,
			Preset:    sandbox.SandboxNetworkPolicyPresetDenyByDefault,
			RuleSetID: raw.FirewallRule,
		},
		Request: &sandbox.SandboxNetworkPolicyRequestSummary{
			ID:                  raw.Credential,
			Operation:           raw.Endpoint,
			DestinationCategory: sandbox.SandboxNetworkPolicyDestinationUnixSocket,
		},
		Outcome:         sandbox.SandboxNetworkPolicyDecisionOutcomeDenied,
		ReasonCode:      sandbox.SandboxNetworkPolicyDecisionReasonCode(raw.ProviderDetail),
		RuleKind:        sandbox.SandboxNetworkPolicyRuleKindEndpoint,
		PolicyPreset:    sandbox.SandboxNetworkPolicyPresetDenyByDefault,
		EnforcementMode: raw.FirewallRule,
		Enforced:        &enforced,
	}}
}

func us014SeedFactoryFailureTarget(target *sandbox.SandboxState, raw us014SensitiveValues) {
	if target == nil {
		return
	}
	target.Provider = raw.ProviderDetail
	target.Host = &sandbox.SandboxHost{
		ID:       "host-" + raw.RegistryToken,
		Name:     "host-" + raw.ProviderDetail,
		Kind:     sandbox.SandboxHostKindLocal,
		Endpoint: raw.Endpoint,
	}
	target.Runtime = &sandbox.SandboxRuntimeState{
		Driver:         sandbox.SandboxRuntimeDriverMicroVM,
		IsolationLevel: sandbox.SandboxIsolationLevelVM,
		RuntimeID:      raw.SocketPath,
		Image:          "ghcr.io/private/" + raw.TemplateReference + ":" + raw.RegistryToken,
		WorkerID:       "worker-" + raw.Credential,
		TemplateLock:   us014SensitiveTemplateLock(raw),
	}
	target.Workspace = &sandbox.SandboxWorkspace{
		Mode:        sandbox.SandboxWorkspaceModeDirect,
		InputSource: sandbox.SandboxWorkspaceInputSourceCopy,
		Repo:        "https://git:" + raw.Credential + "@example.invalid/private/us014.git",
		Branch:      "phase60-secure-default",
		SyncRef:     raw.HostPath,
	}
}

func us014UnsafeGateDecision(raw us014SensitiveValues) *sandbox.SandboxSecurityCapabilityReadinessGateDecision {
	return &sandbox.SandboxSecurityCapabilityReadinessGateDecision{
		Code:       sandbox.SandboxSecurityCapabilityReadinessGateCode(raw.RegistryToken),
		Outcome:    sandbox.SandboxSecurityCapabilityReadinessGateOutcome(raw.ProviderDetail),
		PolicyMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		Reason:     sandbox.SandboxSecurityCapabilityReadinessGateReasonCode(raw.TemplateReference),
		Counts: &sandbox.SandboxSecurityCapabilityReadinessGateCounts{
			Total:          1,
			StrictBlocking: 1,
			ReasonCodeCounts: map[sandbox.SandboxSecurityCapabilityReasonCode]int{
				sandbox.SandboxSecurityCapabilityReasonCode(raw.Endpoint): 1,
			},
		},
	}
}

func us014AssertManifestFileSafe(t *testing.T, label string, store sandboxexecution.Store, executionID string, raw us014SensitiveValues) {
	t.Helper()
	path, err := store.ManifestPath(executionID)
	if err != nil {
		t.Fatalf("ManifestPath(%s) error = %v", executionID, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	us014AssertNoSensitiveValues(t, label, data, raw)
}

func us014AssertNoSensitiveValues(t *testing.T, label string, value any, raw us014SensitiveValues) {
	t.Helper()
	payload := us014PayloadString(t, value)
	for _, forbidden := range raw.Values() {
		if strings.TrimSpace(forbidden) == "" {
			continue
		}
		if strings.Contains(payload, forbidden) {
			t.Fatalf("%s leaked seeded sensitive value %q:\n%s", label, forbidden, payload)
		}
	}
}

func us014PayloadString(t *testing.T, value any) string {
	t.Helper()
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		data, err := json.MarshalIndent(typed, "", "  ")
		if err != nil {
			t.Fatalf("marshal %T: %v", value, err)
		}
		return string(data)
	}
}
