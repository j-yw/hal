package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/credentialdelivery"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
)

func TestPhase46SandboxExecutionManifestRedactionGuards(t *testing.T) {
	fixture := phase46CommandRedactionFixture()
	activation := phase46SanitizedActivationFailure(fixture)
	phase46AssertCommandRawValuesAbsent(t, "sanitized activation failure", phase46MarshalCommandJSON(t, activation), fixture)

	startedAt := time.Date(2026, 7, 3, 13, 0, 0, 0, time.UTC)
	runStore := newPrivateSandboxExecutionTestStore(t)
	if err := saveRunSandboxManifest(runStore, runSandboxRequest{
		ExecutionID:                  "run-phase46-redaction",
		ProjectDir:                   "/repo",
		RemoteCommand:                []string{"hal", "run", "--sandbox"},
		WorkDir:                      "/repo",
		NetworkProxySession:          unsafeProxyManifestSession(sandbox.SandboxNetworkPolicyDecisionSource(" RUN ")),
		NetworkPolicyDecisionLogs:    unsafePolicyDecisionLogManifestRecords(sandbox.SandboxNetworkPolicyDecisionSource(" RUN ")),
		Security:                     fixture.securityRequest(),
		CredentialDeliveryActivation: activation,
	}, sandboxexecution.StatusFailed, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}
	runManifest := mustLoadSandboxExecutionManifest(t, runStore, "run-phase46-redaction")
	phase46AssertCommandManifestRedaction(t, "run manifest", runManifest, fixture)

	autoStore := newPrivateSandboxExecutionTestStore(t)
	if err := saveAutoSandboxManifest(autoStore, autoSandboxRequest{
		ExecutionID:                  "auto-phase46-redaction",
		ProjectDir:                   "/repo",
		RemoteCommand:                []string{"hal", "auto", "--sandbox"},
		WorkDir:                      "/repo",
		NetworkProxySession:          unsafeProxyManifestSession(sandbox.SandboxNetworkPolicyDecisionSource(" AUTO ")),
		NetworkPolicyDecisionLogs:    unsafePolicyDecisionLogManifestRecords(sandbox.SandboxNetworkPolicyDecisionSource(" AUTO ")),
		Security:                     fixture.securityRequest(),
		CredentialDeliveryActivation: activation,
	}, sandboxexecution.StatusFailed, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}
	autoManifest := mustLoadSandboxExecutionManifest(t, autoStore, "auto-phase46-redaction")
	phase46AssertCommandManifestRedaction(t, "auto manifest", autoManifest, fixture)
}

func TestPhase46FactoryJSONAndErrorOutputRedactionGuards(t *testing.T) {
	fixture := phase46CommandRedactionFixture()
	redactor := factory.NewRunSecretRedactor([]factory.ResolvedRunSecret{
		{Name: "PHASE46_SECRET", Source: factory.RunSecretSourceEnv, Required: true, Value: fixture.secretValue},
		{Name: "PHASE46_ENV", Source: factory.RunSecretSourceEnv, Required: true, Value: fixture.envValue},
		{Name: "PHASE46_HEADER", Source: factory.RunSecretSourceEnv, Required: true, Value: fixture.headerValue},
		{Name: "PHASE46_COMMAND", Source: factory.RunSecretSourceEnv, Required: true, Value: fixture.commandLine},
	})
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 7, 3, 13, 10, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-phase46-json", now, now.Add(time.Minute))
	record.ExecutorMode = factory.ExecutorModeSandbox
	record.RepoRemote = "https://git:" + fixture.secretValue + "@github.com/example/repo.git"
	record.BranchName = "hal/" + fixture.envValue
	record.BaseBranch = "main-" + fixture.headerValue
	record.SandboxName = "sandbox-" + fixture.secretValue
	record.Sandbox = &factory.SandboxMetadata{
		Name:           "sandbox-" + fixture.secretValue,
		Provider:       "fake",
		Status:         factory.RunStatusRunning,
		SSHCommand:     "ssh sandbox " + fixture.commandLine,
		CleanupCommand: "cleanup " + fixture.envValue,
		Handoff:        "handoff " + fixture.headerValue,
		NetworkProxySession: &sandbox.SandboxNetworkProxySessionMetadata{
			ID:     " proxy-session-46 ",
			Source: sandbox.SandboxNetworkPolicyDecisionSource(" FACTORY "),
			PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
				ID:        " policy-snapshot-46 ",
				Version:   fixture.rawURL,
				Preset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
				RuleSetID: fixture.localPath,
			},
			EnforcementMode: fixture.socketPath,
		},
		CredentialDelivery: &sandbox.SandboxCredentialDeliveryStatusMetadata{
			ID:             "credential-delivery-46",
			RequestID:      fixture.rawURL,
			PlanID:         fixture.socketPath,
			ActivationID:   fixture.localPath,
			RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy, fixture.commandLine},
			Status:         "failed",
			ReasonCode:     "activation_unavailable",
			ErrorCount:     1,
		},
	}
	record.Failure = &factory.FailureSummary{
		Step:             "run",
		Category:         factory.FailureCategoryRun,
		Message:          "activation failed with " + fixture.secretValue,
		Recoverable:      true,
		SuggestedCommand: "retry " + fixture.commandLine,
	}
	if err := store.SaveRunWithRedactor(&record, redactor); err != nil {
		t.Fatalf("SaveRunWithRedactor() error = %v", err)
	}
	if err := store.AppendEventWithRedactor(&factory.EventRecord{
		Sequence:  1,
		RunID:     record.RunID,
		EventType: factory.EventTypePolicyDecision,
		Timestamp: now.Add(2 * time.Minute),
		Message:   "policy " + fixture.secretValue,
		Summary:   "summary " + fixture.envValue,
		Metadata: map[string]any{
			"policyField": "sandbox.security",
			"decision":    factory.PolicyDecisionBlockedGate,
			"outcome":     factory.PolicyOutcomeBlocked,
			"reason":      "activation failed " + fixture.headerValue,
		},
		NetworkPolicyDecisionLogs: phase46CommandDecisionLogs(fixture),
	}, redactor); err != nil {
		t.Fatalf("AppendEventWithRedactor() error = %v", err)
	}
	if err := store.AppendLogChunkWithRedactor(&factory.LogChunk{
		RunID:     record.RunID,
		Stream:    factory.LogStreamStderr,
		Source:    factory.LogSourceEngine,
		Text:      "log " + fixture.commandLine,
		Summary:   "summary " + fixture.secretValue,
		CreatedAt: now.Add(3 * time.Minute),
	}, redactor); err != nil {
		t.Fatalf("AppendLogChunkWithRedactor() error = %v", err)
	}

	var statusOut bytes.Buffer
	if err := runFactoryStatusWithDeps(&statusOut, record.RunID, true, factoryStatusDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	}); err != nil {
		t.Fatalf("runFactoryStatusWithDeps() error = %v", err)
	}
	phase46AssertCommandRawValuesAbsent(t, "factory status JSON", statusOut.String(), fixture)
	if !strings.Contains(statusOut.String(), factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("factory status JSON missing redaction placeholder: %s", statusOut.String())
	}

	var logsOut bytes.Buffer
	if err := runFactoryLogsWithDeps(&logsOut, record.RunID, true, factoryLogsDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	}); err != nil {
		t.Fatalf("runFactoryLogsWithDeps() error = %v", err)
	}
	phase46AssertCommandRawValuesAbsent(t, "factory logs JSON", logsOut.String(), fixture)

	safeErr := redactFactoryRunError(errors.New("activation failed: "+fixture.secretValue+" "+fixture.envValue+" "+fixture.headerValue+" "+fixture.commandLine), redactor)
	phase46AssertCommandRawValuesAbsent(t, "factory error string", safeErr.Error(), fixture)
	if !strings.Contains(safeErr.Error(), factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("factory error string = %q, want placeholder", safeErr.Error())
	}
}

type phase46CommandFixture struct {
	secretValue string
	envValue    string
	headerValue string
	commandLine string
	rawURL      string
	socketPath  string
	localPath   string
}

func phase46CommandRedactionFixture() phase46CommandFixture {
	return phase46CommandFixture{
		secretValue: "phase46-command-secret-value",
		envValue:    "OPENAI_API_KEY=phase46-command-env",
		headerValue: "Authorization: Bearer phase46-command-token",
		commandLine: "git clone https://phase46-command-token@example.invalid/repo.git",
		rawURL:      "https://user:secret@example.invalid/path?token=phase46-command",
		socketPath:  "unix:///tmp/phase46-command-credential.sock",
		localPath:   "/Users/alice/.config/hal/phase46-command-secret.json",
	}
}

func (f phase46CommandFixture) forbiddenValues() []string {
	values := []string{
		f.secretValue,
		f.envValue,
		f.headerValue,
		f.commandLine,
		f.rawURL,
		f.socketPath,
		f.localPath,
		"phase46-command-env",
		"phase46-command-token",
		"phase46-command-token@example.invalid",
	}
	values = append(values, phase46CommandProxyForbiddenValues()...)
	return values
}

func (f phase46CommandFixture) securityRequest() sandbox.SecurityEvaluationRequest {
	return sandbox.SecurityEvaluationRequest{
		RequestedSecretModes:  []string{sandbox.SandboxSecretModeHTTPProxy, f.envValue, f.headerValue, f.commandLine},
		ActiveSecretModes:     []string{sandbox.SandboxSecretModeHTTPProxy, f.rawURL, f.socketPath, f.localPath},
		CompatibilityAuthSync: true,
	}
}

func phase46SanitizedActivationFailure(f phase46CommandFixture) credentialdelivery.ActivationResult {
	return credentialdelivery.ActivateDelivery(credentialdelivery.ActivationRequest{
		ActivationID: "activation-phase46",
		Plan: credentialdelivery.Plan{
			ID:             "delivery-plan-phase46",
			RequestID:      f.rawURL,
			RequestedModes: []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy, credentialdelivery.Mode(f.commandLine), credentialdelivery.Mode(f.envValue)},
			ActiveModes:    []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy},
			Status:         credentialdelivery.StatusPlanned,
		},
		Bindings: []credentialdelivery.Binding{{
			ID:                    "binding-phase46",
			SecretRef:             "env:GITHUB_TOKEN",
			PolicySnapshotID:      f.localPath,
			NetworkProxySessionID: f.socketPath,
			ServiceID:             f.rawURL,
			DeliveryMode:          credentialdelivery.Mode(f.headerValue),
		}},
	}, phase46FailingActivationAdapter{err: errors.New("provider echoed " + f.secretValue + " " + f.commandLine)})
}

type phase46FailingActivationAdapter struct {
	err error
}

func (a phase46FailingActivationAdapter) ActivateCredentialDelivery(credentialdelivery.SanitizedActivationRequest) (credentialdelivery.ActivationResult, error) {
	return credentialdelivery.ActivationResult{}, a.err
}

func phase46CommandDecisionLogs(f phase46CommandFixture) []sandbox.SandboxNetworkPolicyDecisionLogRecord {
	enforced := true
	return []sandbox.SandboxNetworkPolicyDecisionLogRecord{{
		ID:             " decision-phase46 ",
		Source:         sandbox.SandboxNetworkPolicyDecisionSource(" FACTORY "),
		ProxySessionID: f.rawURL,
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:        " policy-snapshot-phase46 ",
			Version:   f.socketPath,
			Preset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
			RuleSetID: f.localPath,
		},
		Request: &sandbox.SandboxNetworkPolicyRequestSummary{
			ID:                  f.envValue,
			Operation:           f.headerValue,
			DestinationCategory: sandbox.SandboxNetworkPolicyDestinationCategory(" METADATA_SERVICE "),
		},
		Outcome:         sandbox.SandboxNetworkPolicyDecisionOutcome(" DENIED "),
		ReasonCode:      sandbox.SandboxNetworkPolicyDecisionReasonCode(" DEFAULT_DENY "),
		RuleKind:        sandbox.SandboxNetworkPolicyRuleKind(" DOMAIN "),
		PolicyPreset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
		EnforcementMode: sandbox.SandboxNetworkEnforcementModeNone,
		Enforced:        &enforced,
	}}
}

func phase46AssertCommandManifestRedaction(t *testing.T, label string, manifest *sandboxexecution.Manifest, fixture phase46CommandFixture) {
	t.Helper()
	payload := phase46MarshalCommandJSON(t, manifest)
	phase46AssertCommandRawValuesAbsent(t, label, payload, fixture)
	if manifest.CredentialDelivery == nil {
		t.Fatalf("%s credentialDelivery = nil, want sanitized failure metadata", label)
	}
	if manifest.CredentialDelivery.Status != "failed" {
		t.Fatalf("%s credentialDelivery status = %q, want failed", label, manifest.CredentialDelivery.Status)
	}
	if len(manifest.CredentialDelivery.ActiveModes) != 0 {
		t.Fatalf("%s active modes = %#v, want omitted for failed activation", label, manifest.CredentialDelivery.ActiveModes)
	}
	if manifest.CredentialDelivery.ErrorCount == 0 {
		t.Fatalf("%s error count = 0, want sanitized activation failure count", label)
	}
}

func phase46AssertCommandRawValuesAbsent(t *testing.T, label string, payload string, fixture phase46CommandFixture) {
	t.Helper()
	for _, forbidden := range fixture.forbiddenValues() {
		if forbidden == "" {
			continue
		}
		if strings.Contains(payload, forbidden) {
			t.Fatalf("%s leaked raw value %q: %s", label, forbidden, payload)
		}
	}
}

func phase46CommandProxyForbiddenValues() []string {
	return []string{
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
		"https://token@example.com/policy",
		"https://token@example.com/proxy",
		"/Users/private/rules.json",
	}
}

func phase46MarshalCommandJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return string(data)
}
