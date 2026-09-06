package cmd

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
)

func TestRunAndAutoSandboxManifestsOmitProxyMetadataByDefault(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 6, 15, 0, 0, time.UTC)

	runStore := newPrivateSandboxExecutionTestStore(t)
	if err := saveRunSandboxManifest(runStore, runSandboxRequest{
		ExecutionID: "run-no-proxy-metadata",
		ProjectDir:  "/repo",
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}
	runManifest := mustLoadSandboxExecutionManifest(t, runStore, "run-no-proxy-metadata")
	assertSandboxManifestOmitsNetworkProxyMetadata(t, runManifest)

	autoStore := newPrivateSandboxExecutionTestStore(t)
	if err := saveAutoSandboxManifest(autoStore, autoSandboxRequest{
		ExecutionID: "auto-no-proxy-metadata",
		ProjectDir:  "/repo",
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}
	autoManifest := mustLoadSandboxExecutionManifest(t, autoStore, "auto-no-proxy-metadata")
	assertSandboxManifestOmitsNetworkProxyMetadata(t, autoManifest)
}

func TestRunAndAutoSandboxManifestsPersistSanitizedProxySessionMetadata(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 6, 20, 0, 0, time.UTC)

	runStore := newPrivateSandboxExecutionTestStore(t)
	if err := saveRunSandboxManifest(runStore, runSandboxRequest{
		ExecutionID:         "run-proxy-metadata",
		ProjectDir:          "/repo",
		NetworkProxySession: unsafeProxyManifestSession(sandbox.SandboxNetworkPolicyDecisionSource(" RUN ")),
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}
	runManifest := mustLoadSandboxExecutionManifest(t, runStore, "run-proxy-metadata")
	assertSandboxManifestSanitizedNetworkProxySession(t, runManifest, sandbox.SandboxNetworkPolicyDecisionSourceRun)

	autoStore := newPrivateSandboxExecutionTestStore(t)
	if err := saveAutoSandboxManifest(autoStore, autoSandboxRequest{
		ExecutionID:         "auto-proxy-metadata",
		ProjectDir:          "/repo",
		NetworkProxySession: unsafeProxyManifestSession(sandbox.SandboxNetworkPolicyDecisionSource(" AUTO ")),
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}
	autoManifest := mustLoadSandboxExecutionManifest(t, autoStore, "auto-proxy-metadata")
	assertSandboxManifestSanitizedNetworkProxySession(t, autoManifest, sandbox.SandboxNetworkPolicyDecisionSourceAuto)
}

func TestRunAndAutoSandboxManifestsPersistSanitizedPolicyDecisionLogs(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 6, 25, 0, 0, time.UTC)

	runStore := newPrivateSandboxExecutionTestStore(t)
	if err := saveRunSandboxManifest(runStore, runSandboxRequest{
		ExecutionID:               "run-decision-log-metadata",
		ProjectDir:                "/repo",
		NetworkPolicyDecisionLogs: unsafePolicyDecisionLogManifestRecords(sandbox.SandboxNetworkPolicyDecisionSource(" RUN ")),
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}
	runManifest := mustLoadSandboxExecutionManifest(t, runStore, "run-decision-log-metadata")
	assertSandboxManifestSanitizedPolicyDecisionLogs(t, runManifest, sandbox.SandboxNetworkPolicyDecisionSourceRun)

	autoStore := newPrivateSandboxExecutionTestStore(t)
	if err := saveAutoSandboxManifest(autoStore, autoSandboxRequest{
		ExecutionID:               "auto-decision-log-metadata",
		ProjectDir:                "/repo",
		NetworkPolicyDecisionLogs: unsafePolicyDecisionLogManifestRecords(sandbox.SandboxNetworkPolicyDecisionSource(" AUTO ")),
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}
	autoManifest := mustLoadSandboxExecutionManifest(t, autoStore, "auto-decision-log-metadata")
	assertSandboxManifestSanitizedPolicyDecisionLogs(t, autoManifest, sandbox.SandboxNetworkPolicyDecisionSourceAuto)
}

func TestRunAndAutoSandboxManifestsStripNonEnforcingDecisionLogClaims(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 6, 28, 0, 0, time.UTC)

	runStore := newPrivateSandboxExecutionTestStore(t)
	if err := saveRunSandboxManifest(runStore, runSandboxRequest{
		ExecutionID:               "run-compat-decision-log",
		ProjectDir:                "/repo",
		NetworkPolicyDecisionLogs: nonEnforcingCompatibilityDecisionLogRecords(sandbox.SandboxNetworkPolicyDecisionSourceRun),
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}
	runManifest := mustLoadSandboxExecutionManifest(t, runStore, "run-compat-decision-log")
	assertSandboxManifestNonEnforcingDecisionLogs(t, runManifest, sandbox.SandboxNetworkPolicyDecisionSourceRun)

	autoStore := newPrivateSandboxExecutionTestStore(t)
	if err := saveAutoSandboxManifest(autoStore, autoSandboxRequest{
		ExecutionID:               "auto-compat-decision-log",
		ProjectDir:                "/repo",
		NetworkPolicyDecisionLogs: nonEnforcingCompatibilityDecisionLogRecords(sandbox.SandboxNetworkPolicyDecisionSourceAuto),
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}
	autoManifest := mustLoadSandboxExecutionManifest(t, autoStore, "auto-compat-decision-log")
	assertSandboxManifestNonEnforcingDecisionLogs(t, autoManifest, sandbox.SandboxNetworkPolicyDecisionSourceAuto)
}

func unsafeProxyManifestSession(source sandbox.SandboxNetworkPolicyDecisionSource) *sandbox.SandboxNetworkProxySessionMetadata {
	return &sandbox.SandboxNetworkProxySessionMetadata{
		ID:     " proxy-session-01 ",
		Source: source,
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:        " policy-snapshot-01 ",
			Version:   "https://token@example.com/policy",
			Preset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
			RuleSetID: "/Users/private/rules.json",
		},
		EnforcementMode: "https://token@example.com/proxy",
	}
}

func unsafePolicyDecisionLogManifestRecords(source sandbox.SandboxNetworkPolicyDecisionSource) []sandbox.SandboxNetworkPolicyDecisionLogRecord {
	enforced := true
	sensitiveValues := []string{
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
	}
	records := make([]sandbox.SandboxNetworkPolicyDecisionLogRecord, 0, len(sensitiveValues))
	for i, sensitive := range sensitiveValues {
		records = append(records, sandbox.SandboxNetworkPolicyDecisionLogRecord{
			ID:             " decision-01 ",
			Source:         source,
			ProxySessionID: sensitive,
			PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
				ID:        " policy-snapshot-01 ",
				Version:   sensitive,
				Preset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
				RuleSetID: sensitive,
			},
			Request: &sandbox.SandboxNetworkPolicyRequestSummary{
				ID:                  sensitive,
				Operation:           sensitive,
				DestinationCategory: sandbox.SandboxNetworkPolicyDestinationCategory(" METADATA_SERVICE "),
			},
			Outcome:         sandbox.SandboxNetworkPolicyDecisionOutcome(" DENIED "),
			ReasonCode:      sandbox.SandboxNetworkPolicyDecisionReasonCode(" DEFAULT_DENY "),
			RuleKind:        sandbox.SandboxNetworkPolicyRuleKind(" DOMAIN "),
			PolicyPreset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
			EnforcementMode: sandbox.SandboxNetworkEnforcementModeNone,
			Enforced:        &enforced,
		})
		if i == 0 {
			records[i].ProxySessionID = " proxy-session-01 "
			records[i].PolicySnapshot.Version = " policy-v1 "
			records[i].PolicySnapshot.RuleSetID = " rules-01 "
			records[i].Request.ID = " request-01 "
			records[i].Request.Operation = " connect "
		}
	}
	return records
}

func nonEnforcingCompatibilityDecisionLogRecords(source sandbox.SandboxNetworkPolicyDecisionSource) []sandbox.SandboxNetworkPolicyDecisionLogRecord {
	enforced := true
	return []sandbox.SandboxNetworkPolicyDecisionLogRecord{
		{
			ID:             "compat-decision-01",
			Source:         source,
			ProxySessionID: "compat-proxy-01",
			PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
				ID:     "compat-policy-01",
				Preset: sandbox.SandboxNetworkPolicyPresetLegacyDefault,
			},
			Request: &sandbox.SandboxNetworkPolicyRequestSummary{
				ID:                  "compat-request-01",
				Operation:           "connect",
				DestinationCategory: sandbox.SandboxNetworkPolicyDestinationPublicInternet,
			},
			Outcome:         sandbox.SandboxNetworkPolicyDecisionOutcomeAuditOnly,
			ReasonCode:      sandbox.SandboxNetworkPolicyDecisionReasonEnforcementUnsupported,
			PolicyPreset:    sandbox.SandboxNetworkPolicyPresetLegacyDefault,
			EnforcementMode: sandbox.SandboxNetworkEnforcementModeBestEffort,
			Enforced:        &enforced,
		},
	}
}

func assertSandboxManifestOmitsNetworkProxyMetadata(t *testing.T, manifest *sandboxexecution.Manifest) {
	t.Helper()
	if manifest.NetworkProxySession != nil {
		t.Fatalf("NetworkProxySession = %#v, want nil by default", manifest.NetworkProxySession)
	}
	if len(manifest.NetworkPolicyDecisionLogs) != 0 {
		t.Fatalf("NetworkPolicyDecisionLogs = %#v, want empty by default", manifest.NetworkPolicyDecisionLogs)
	}
	fields := sandboxManifestJSONFields(t, manifest)
	for _, forbidden := range []string{"networkProxySession", "networkPolicyDecisionLog", "networkPolicyDecisionLogs"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("manifest should omit %q by default: %#v", forbidden, fields)
		}
	}
}

func assertSandboxManifestNonEnforcingDecisionLogs(t *testing.T, manifest *sandboxexecution.Manifest, source sandbox.SandboxNetworkPolicyDecisionSource) {
	t.Helper()
	if len(manifest.NetworkPolicyDecisionLogs) != 1 {
		t.Fatalf("NetworkPolicyDecisionLogs length = %d, want 1", len(manifest.NetworkPolicyDecisionLogs))
	}
	record := manifest.NetworkPolicyDecisionLogs[0]
	if record.Source != source {
		t.Fatalf("decision log source = %q, want %q", record.Source, source)
	}
	if record.Outcome != sandbox.SandboxNetworkPolicyDecisionOutcomeAuditOnly {
		t.Fatalf("decision log outcome = %q, want audit_only", record.Outcome)
	}
	if record.ReasonCode != sandbox.SandboxNetworkPolicyDecisionReasonEnforcementUnsupported {
		t.Fatalf("decision log reason = %q, want enforcement_unsupported", record.ReasonCode)
	}
	if record.PolicyPreset != sandbox.SandboxNetworkPolicyPresetLegacyDefault {
		t.Fatalf("decision log policy preset = %q, want legacy_default", record.PolicyPreset)
	}
	if record.EnforcementMode != sandbox.SandboxNetworkEnforcementModeBestEffort {
		t.Fatalf("decision log enforcement mode = %q, want best_effort", record.EnforcementMode)
	}
	if record.Enforced != nil {
		t.Fatalf("decision log enforced = %#v, want nil for non-enforcing compatibility metadata", record.Enforced)
	}

	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(manifest) error = %v", err)
	}
	encoded := string(payload)
	for _, forbidden := range []string{"\"enforced\":true", string(sandbox.SandboxNetworkPolicyPresetDenyByDefault)} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("manifest overclaimed compatibility enforcement %q: %s", forbidden, encoded)
		}
	}
	for _, want := range []string{
		"networkPolicyDecisionLogs",
		"compat-decision-01",
		string(source),
		string(sandbox.SandboxNetworkPolicyDecisionOutcomeAuditOnly),
		string(sandbox.SandboxNetworkPolicyDecisionReasonEnforcementUnsupported),
		string(sandbox.SandboxNetworkPolicyPresetLegacyDefault),
		sandbox.SandboxNetworkEnforcementModeBestEffort,
	} {
		if !strings.Contains(encoded, want) {
			t.Fatalf("manifest omitted safe non-enforcing metadata %q: %s", want, encoded)
		}
	}
}

func assertSandboxManifestSanitizedNetworkProxySession(t *testing.T, manifest *sandboxexecution.Manifest, source sandbox.SandboxNetworkPolicyDecisionSource) {
	t.Helper()
	session := manifest.NetworkProxySession
	if session == nil {
		t.Fatal("NetworkProxySession = nil, want sanitized proxy session metadata")
	}
	if session.ID != "proxy-session-01" {
		t.Fatalf("proxy session id = %q, want proxy-session-01", session.ID)
	}
	if session.Source != source {
		t.Fatalf("proxy session source = %q, want %q", session.Source, source)
	}
	if session.EnforcementMode != "" {
		t.Fatalf("proxy session enforcement mode = %q, want unsafe value cleared", session.EnforcementMode)
	}
	if session.PolicySnapshot == nil {
		t.Fatal("proxy session policy snapshot = nil, want safe snapshot metadata")
	}
	if session.PolicySnapshot.ID != "policy-snapshot-01" {
		t.Fatalf("policy snapshot id = %q, want policy-snapshot-01", session.PolicySnapshot.ID)
	}
	if session.PolicySnapshot.Preset != sandbox.SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("policy snapshot preset = %q, want %q", session.PolicySnapshot.Preset, sandbox.SandboxNetworkPolicyPresetDenyByDefault)
	}
	if session.PolicySnapshot.Version != "" || session.PolicySnapshot.RuleSetID != "" {
		t.Fatalf("policy snapshot = %#v, want unsafe version and rule set id cleared", session.PolicySnapshot)
	}

	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(manifest) error = %v", err)
	}
	encoded := string(payload)
	for _, forbidden := range []string{
		"token@example.com",
		"/Users/private",
		"https://",
		"ruleSetId",
		"enforcementMode",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("manifest leaked unsafe proxy metadata %q: %s", forbidden, encoded)
		}
	}
	fields := sandboxManifestJSONFields(t, manifest)
	if _, ok := fields["networkProxySession"]; !ok {
		t.Fatalf("manifest JSON omitted networkProxySession: %#v", fields)
	}
}

func assertSandboxManifestSanitizedPolicyDecisionLogs(t *testing.T, manifest *sandboxexecution.Manifest, source sandbox.SandboxNetworkPolicyDecisionSource) {
	t.Helper()
	if len(manifest.NetworkPolicyDecisionLogs) == 0 {
		t.Fatal("NetworkPolicyDecisionLogs is empty, want sanitized decision log records")
	}
	record := manifest.NetworkPolicyDecisionLogs[0]
	if record.ID != "decision-01" {
		t.Fatalf("decision log id = %q, want decision-01", record.ID)
	}
	if record.Source != source {
		t.Fatalf("decision log source = %q, want %q", record.Source, source)
	}
	if record.ProxySessionID != "proxy-session-01" {
		t.Fatalf("decision log proxy session id = %q, want proxy-session-01", record.ProxySessionID)
	}
	if record.PolicySnapshot == nil {
		t.Fatal("decision log policy snapshot = nil, want sanitized snapshot metadata")
	}
	if record.PolicySnapshot.ID != "policy-snapshot-01" || record.PolicySnapshot.Version != "policy-v1" || record.PolicySnapshot.RuleSetID != "rules-01" {
		t.Fatalf("decision log policy snapshot = %#v, want safe snapshot identifiers preserved", record.PolicySnapshot)
	}
	if record.PolicySnapshot.Preset != sandbox.SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("decision log policy snapshot preset = %q, want %q", record.PolicySnapshot.Preset, sandbox.SandboxNetworkPolicyPresetDenyByDefault)
	}
	if record.Request == nil {
		t.Fatal("decision log request = nil, want sanitized request summary")
	}
	if record.Request.ID != "request-01" || record.Request.Operation != "connect" {
		t.Fatalf("decision log request = %#v, want safe request identifiers preserved", record.Request)
	}
	if record.Request.DestinationCategory != sandbox.SandboxNetworkPolicyDestinationMetadataService {
		t.Fatalf("decision log destination category = %q, want %q", record.Request.DestinationCategory, sandbox.SandboxNetworkPolicyDestinationMetadataService)
	}
	if record.Outcome != sandbox.SandboxNetworkPolicyDecisionOutcomeDenied {
		t.Fatalf("decision log outcome = %q, want %q", record.Outcome, sandbox.SandboxNetworkPolicyDecisionOutcomeDenied)
	}
	if record.ReasonCode != sandbox.SandboxNetworkPolicyDecisionReasonDefaultDeny {
		t.Fatalf("decision log reason code = %q, want %q", record.ReasonCode, sandbox.SandboxNetworkPolicyDecisionReasonDefaultDeny)
	}
	if record.RuleKind != sandbox.SandboxNetworkPolicyRuleKindDomain {
		t.Fatalf("decision log rule kind = %q, want %q", record.RuleKind, sandbox.SandboxNetworkPolicyRuleKindDomain)
	}
	if record.PolicyPreset != sandbox.SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("decision log policy preset = %q, want %q", record.PolicyPreset, sandbox.SandboxNetworkPolicyPresetDenyByDefault)
	}
	if record.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("decision log enforcement mode = %q, want %q", record.EnforcementMode, sandbox.SandboxNetworkEnforcementModeNone)
	}
	if record.Enforced != nil {
		t.Fatalf("decision log enforced = %#v, want stripped denied enforcement claim with none mode", record.Enforced)
	}

	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(manifest) error = %v", err)
	}
	encoded := string(payload)
	for _, forbidden := range []string{
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
		"enforced",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("manifest leaked unsafe decision log metadata %q: %s", forbidden, encoded)
		}
	}
	fields := sandboxManifestJSONFields(t, manifest)
	if _, ok := fields["networkPolicyDecisionLogs"]; !ok {
		t.Fatalf("manifest JSON omitted networkPolicyDecisionLogs: %#v", fields)
	}
}

func sandboxManifestJSONFields(t *testing.T, manifest *sandboxexecution.Manifest) map[string]json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(manifest) error = %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatalf("Unmarshal(manifest fields) error = %v", err)
	}
	return fields
}
