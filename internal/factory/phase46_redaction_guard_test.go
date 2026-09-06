package factory

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestPhase46FactoryPersistedOutputRedactionGuards(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	fixture := phase46FactoryRedactionFixture()
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "PHASE46_SECRET", Source: RunSecretSourceEnv, Required: true, Value: fixture.secretValue},
		{Name: "PHASE46_ENV", Source: RunSecretSourceEnv, Required: true, Value: fixture.envValue},
		{Name: "PHASE46_HEADER", Source: RunSecretSourceEnv, Required: true, Value: fixture.headerValue},
		{Name: "PHASE46_COMMAND", Source: RunSecretSourceEnv, Required: true, Value: fixture.commandLine},
	})
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

	record := testRunRecord("run-phase46-redaction")
	record.CreatedAt = now
	record.UpdatedAt = now
	record.RepoPath = "/workspace/" + fixture.secretValue
	record.RepoRemote = "https://git:" + fixture.secretValue + "@github.com/example/repo.git"
	record.BranchName = "hal/" + fixture.envValue
	record.BaseBranch = "main-" + fixture.headerValue
	record.SandboxName = "sandbox-" + fixture.secretValue
	record.Sandbox = &SandboxMetadata{
		Name:           "sandbox-" + fixture.secretValue,
		Provider:       "fake",
		Status:         RunStatusRunning,
		SSHCommand:     "ssh sandbox " + fixture.commandLine,
		CleanupCommand: "hal sandbox delete " + fixture.envValue,
		Handoff:        "handoff " + fixture.headerValue,
		Connection: &SandboxConnectionMetadata{
			Address:  "worker-" + fixture.secretValue,
			PublicIP: "worker-" + fixture.envValue,
		},
		NetworkProxySession: fixture.networkProxySession(),
		CredentialProxyPlan: &sandbox.SandboxCredentialProxyPlanMetadata{
			ID:                    "credential-plan-" + fixture.secretValue,
			Source:                sandbox.SandboxCredentialProxySourceFactory,
			SecretBrokerSessionID: "secret-broker-" + fixture.envValue,
			NetworkProxySessionID: "network-proxy-" + fixture.headerValue,
			PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
				ID:        "policy-" + fixture.secretValue,
				Version:   fixture.envValue,
				Preset:    sandbox.SandboxNetworkPolicyPresetDenyByDefault,
				RuleSetID: fixture.headerValue,
			},
			Mode:   sandbox.SandboxCredentialProxyModeBrokeredNetworkReference,
			Status: sandbox.SandboxCredentialProxyStatusActive,
		},
		CredentialDelivery: &sandbox.SandboxCredentialDeliveryStatusMetadata{
			ID:             "credential-delivery-01",
			RequestID:      fixture.rawURL,
			PlanID:         fixture.socketPath,
			ActivationID:   fixture.localPath,
			RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy, fixture.envValue},
			ActiveModes:    []string{sandbox.SandboxSecretModeHTTPProxy, fixture.headerValue},
			Status:         "active",
			ReasonCode:     "requested",
		},
	}
	record.Failure = &FailureSummary{
		Step:             "run",
		Category:         FailureCategoryRun,
		Message:          "activation failed with " + fixture.secretValue,
		Recoverable:      true,
		SuggestedCommand: "retry " + fixture.commandLine,
	}
	record.Artifacts = []ArtifactReference{{
		ID:       "artifact-" + fixture.secretValue,
		Name:     "artifact-" + fixture.envValue,
		Type:     "json",
		Path:     ".hal/reports/" + fixture.headerValue + ".json",
		Summary:  map[string]any{"token": fixture.secretValue, "command": fixture.commandLine},
		Warnings: []string{"warning " + fixture.envValue},
	}}
	record.Secrets = []RunSecretMetadata{{
		Name:     "PHASE46_SECRET",
		Source:   RunSecretSourceEnv,
		Required: true,
		Present:  true,
	}}

	if err := store.SaveRunWithRedactor(&record, redactor); err != nil {
		t.Fatalf("SaveRunWithRedactor() error = %v", err)
	}
	if err := store.AppendEventWithRedactor(&EventRecord{
		Sequence:  1,
		RunID:     record.RunID,
		EventType: EventTypePolicyDecision,
		Timestamp: now.Add(time.Second),
		Message:   "delivery event " + fixture.secretValue,
		Summary:   "summary " + fixture.envValue,
		Metadata: map[string]any{
			"safe":    "kept",
			"header":  fixture.headerValue,
			"command": fixture.commandLine,
		},
		NetworkPolicyDecisionLogs: fixture.decisionLogs(),
	}, redactor); err != nil {
		t.Fatalf("AppendEventWithRedactor() error = %v", err)
	}
	if err := store.AppendLogChunkWithRedactor(&LogChunk{
		RunID:     record.RunID,
		Stream:    LogStreamStderr,
		Source:    LogSourceEngine,
		Text:      "stderr " + fixture.commandLine,
		Summary:   "summary " + fixture.secretValue,
		CreatedAt: now.Add(2 * time.Second),
	}, redactor); err != nil {
		t.Fatalf("AppendLogChunkWithRedactor() error = %v", err)
	}

	safeErr := redactor.RedactError(errors.New("activation failed: " + fixture.secretValue + " " + fixture.envValue + " " + fixture.headerValue + " " + fixture.commandLine))
	phase46AssertFactoryRawValuesAbsent(t, "redacted error", safeErr.Error(), fixture)
	if !strings.Contains(safeErr.Error(), RunSecretRedactionPlaceholder) {
		t.Fatalf("redacted error = %q, want placeholder", safeErr.Error())
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error = %v", err)
	}
	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error = %v", err)
	}
	chunks, err := store.LoadLogChunks(record.RunID)
	if err != nil {
		t.Fatalf("LoadLogChunks() error = %v", err)
	}
	persisted := struct {
		Run      RunRecord     `json:"run"`
		Timeline []EventRecord `json:"timeline"`
		Logs     []LogChunk    `json:"logs"`
	}{
		Run:      *loaded,
		Timeline: events,
		Logs:     chunks,
	}
	payload := phase46MarshalFactoryJSON(t, persisted)
	phase46AssertFactoryRawValuesAbsent(t, "persisted factory surfaces", payload, fixture)
	if !strings.Contains(payload, RunSecretRedactionPlaceholder) {
		t.Fatalf("persisted factory surfaces missing redaction placeholder: %s", payload)
	}

	for _, path := range []string{
		phase46FactoryRunRecordPath(t, store, record.RunID),
		phase46FactoryTimelinePath(t, store, record.RunID),
		phase46FactoryLogPath(t, store, record.RunID),
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%q) error = %v", path, err)
		}
		phase46AssertFactoryRawValuesAbsent(t, path, string(data), fixture)
	}
}

type phase46FactoryFixture struct {
	secretValue string
	envValue    string
	headerValue string
	commandLine string
	rawURL      string
	socketPath  string
	localPath   string
}

func phase46FactoryRedactionFixture() phase46FactoryFixture {
	return phase46FactoryFixture{
		secretValue: "phase46-secret-value-123",
		envValue:    "OPENAI_API_KEY=phase46-env-secret",
		headerValue: "Authorization: Bearer phase46-header-token",
		commandLine: "git clone https://phase46-token@example.invalid/repo.git",
		rawURL:      "https://user:secret@example.invalid/path?token=phase46",
		socketPath:  "unix:///tmp/phase46-credential.sock",
		localPath:   "/Users/alice/.config/hal/phase46-secret.json",
	}
}

func (f phase46FactoryFixture) forbiddenValues() []string {
	return []string{
		f.secretValue,
		f.envValue,
		f.headerValue,
		f.commandLine,
		f.rawURL,
		f.socketPath,
		f.localPath,
		"phase46-env-secret",
		"phase46-header-token",
		"phase46-token@example.invalid",
	}
}

func (f phase46FactoryFixture) networkProxySession() *sandbox.SandboxNetworkProxySessionMetadata {
	return &sandbox.SandboxNetworkProxySessionMetadata{
		ID:     " proxy-session-46 ",
		Source: sandbox.SandboxNetworkPolicyDecisionSource(" FACTORY "),
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:        " policy-snapshot-46 ",
			Version:   f.rawURL,
			Preset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
			RuleSetID: f.localPath,
		},
		EnforcementMode: f.socketPath,
	}
}

func (f phase46FactoryFixture) decisionLogs() []sandbox.SandboxNetworkPolicyDecisionLogRecord {
	enforced := true
	return []sandbox.SandboxNetworkPolicyDecisionLogRecord{{
		ID:             " decision-46 ",
		Source:         sandbox.SandboxNetworkPolicyDecisionSource(" FACTORY "),
		ProxySessionID: f.rawURL,
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:        " policy-snapshot-46 ",
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

func phase46AssertFactoryRawValuesAbsent(t *testing.T, label string, payload string, fixture phase46FactoryFixture) {
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

func phase46MarshalFactoryJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return string(data)
}

func phase46FactoryRunRecordPath(t *testing.T, store Store, runID string) string {
	t.Helper()
	path, err := store.runRecordPath(runID)
	if err != nil {
		t.Fatalf("runRecordPath() error = %v", err)
	}
	return path
}

func phase46FactoryTimelinePath(t *testing.T, store Store, runID string) string {
	t.Helper()
	path, err := store.timelinePath(runID)
	if err != nil {
		t.Fatalf("timelinePath() error = %v", err)
	}
	return path
}

func phase46FactoryLogPath(t *testing.T, store Store, runID string) string {
	t.Helper()
	path, err := store.logPath(runID)
	if err != nil {
		t.Fatalf("logPath() error = %v", err)
	}
	return path
}
