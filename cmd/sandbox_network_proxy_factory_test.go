package cmd

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
)

func TestFactorySandboxMetadataOmitsNetworkProxyMetadataByDefault(t *testing.T) {
	_, metadata := factorySandboxPersistentMetadataFromState(factorySandboxExecutorRequest{}, factory.RunRecord{}, &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	})
	if metadata == nil {
		t.Fatal("factorySandboxPersistentMetadataFromState() metadata = nil")
	}
	if metadata.NetworkProxySession != nil {
		t.Fatalf("NetworkProxySession = %#v, want nil by default", metadata.NetworkProxySession)
	}

	data, err := json.Marshal(factory.RunRecord{
		RunID:   "run-no-proxy-metadata",
		Status:  factory.RunStatusRunning,
		Sandbox: metadata,
	})
	if err != nil {
		t.Fatalf("json.Marshal(run record) error = %v", err)
	}
	encoded := string(data)
	for _, forbidden := range []string{"networkProxySession", "networkPolicyDecisionLog", "networkPolicyDecisionLogs"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("factory sandbox record should omit %q by default: %s", forbidden, encoded)
		}
	}
}

func TestFactorySandboxPersistentMetadataSanitizesNetworkProxySession(t *testing.T) {
	_, metadata := factorySandboxPersistentMetadataFromState(factorySandboxExecutorRequest{
		NetworkProxySession: unsafeFactoryNetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSource(" FACTORY ")),
	}, factory.RunRecord{}, &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	})
	if metadata == nil {
		t.Fatal("factorySandboxPersistentMetadataFromState() metadata = nil")
	}
	session := metadata.NetworkProxySession
	if session == nil {
		t.Fatal("NetworkProxySession = nil, want sanitized proxy session metadata")
	}
	if session.ID != "proxy-session-01" {
		t.Fatalf("proxy session id = %q, want proxy-session-01", session.ID)
	}
	if session.Source != sandbox.SandboxNetworkPolicyDecisionSourceFactory {
		t.Fatalf("proxy session source = %q, want factory", session.Source)
	}
	if session.EnforcementMode != "" {
		t.Fatalf("proxy session enforcement mode = %q, want unsafe value cleared", session.EnforcementMode)
	}
	if session.PolicySnapshot == nil {
		t.Fatal("policy snapshot = nil, want sanitized snapshot metadata")
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

	data, err := json.Marshal(factory.RunRecord{
		RunID:   "run-proxy-metadata",
		Status:  factory.RunStatusRunning,
		Sandbox: metadata,
	})
	if err != nil {
		t.Fatalf("json.Marshal(run record) error = %v", err)
	}
	encoded := string(data)
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
		"token@example.com",
		"/Users/private",
		"https://",
		"ruleSetId",
		"enforcementMode",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("factory sandbox record leaked unsafe proxy metadata %q: %s", forbidden, encoded)
		}
	}
	for _, want := range []string{
		"networkProxySession",
		"proxy-session-01",
		"policy-snapshot-01",
		string(sandbox.SandboxNetworkPolicyDecisionSourceFactory),
		string(sandbox.SandboxNetworkPolicyPresetDenyByDefault),
	} {
		if !strings.Contains(encoded, want) {
			t.Fatalf("factory sandbox record omitted safe proxy metadata %q: %s", want, encoded)
		}
	}
}

func TestFactoryTimelineEventSanitizesNetworkPolicyDecisionLogs(t *testing.T) {
	store := factory.NewStore(t.TempDir())
	runID := "run-factory-decision-logs"
	now := time.Date(2026, 7, 2, 6, 35, 0, 0, time.UTC)

	if err := appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType: factory.EventTypePolicyDecision,
		Summary:   "Network policy decisions recorded",
		Metadata: map[string]any{
			"policyField": "sandbox.networkPolicy",
			"decision":    factory.PolicyDecisionAllowedExecution,
			"outcome":     factory.PolicyOutcomeAllowed,
			"source":      "remote_sandbox",
		},
		NetworkPolicyDecisionLogs: unsafePolicyDecisionLogManifestRecords(sandbox.SandboxNetworkPolicyDecisionSource(" FACTORY ")),
	}); err != nil {
		t.Fatalf("appendFactoryRunTimelineEvent() error = %v", err)
	}

	events, err := store.LoadEvents(runID)
	if err != nil {
		t.Fatalf("LoadEvents() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].EventType != factory.EventTypePolicyDecision {
		t.Fatalf("event type = %q, want %q", events[0].EventType, factory.EventTypePolicyDecision)
	}
	assertFactoryTimelineSanitizedPolicyDecisionLogs(t, events[0], sandbox.SandboxNetworkPolicyDecisionSourceFactory)
}

func TestFactoryTimelineStripsNonEnforcingDecisionLogClaims(t *testing.T) {
	store := factory.NewStore(t.TempDir())
	runID := "run-factory-compat-decision-logs"
	now := time.Date(2026, 7, 2, 6, 38, 0, 0, time.UTC)

	if err := appendFactoryRunTimelineEvent(store, runID, now, factoryTimelineEvent{
		EventType:                 factory.EventTypePolicyDecision,
		Summary:                   "Network policy compatibility metadata recorded",
		NetworkPolicyDecisionLogs: nonEnforcingCompatibilityDecisionLogRecords(sandbox.SandboxNetworkPolicyDecisionSourceFactory),
	}); err != nil {
		t.Fatalf("appendFactoryRunTimelineEvent() error = %v", err)
	}

	events, err := store.LoadEvents(runID)
	if err != nil {
		t.Fatalf("LoadEvents() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	assertFactoryTimelineNonEnforcingDecisionLogs(t, events[0], sandbox.SandboxNetworkPolicyDecisionSourceFactory)
}

func TestFactorySandboxSecurityPolicyEventAttachesSanitizedDecisionLogs(t *testing.T) {
	store := factory.NewStore(t.TempDir())
	now := time.Date(2026, 7, 2, 6, 40, 0, 0, time.UTC)
	target := &sandbox.SandboxState{
		Name:     "factory-policy-target",
		Provider: "fake",
		Status:   sandbox.StatusRunning,
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
				PolicyEnforced:  sandbox.SandboxNetworkPolicyDenyByDefault,
				EnforcementMode: sandbox.SandboxNetworkEnforcementModeProxy,
			},
		},
	}

	err := recordFactorySandboxSecurityPolicyEvent(store, factorySandboxExecutorDeps{
		now:         func() time.Time { return now },
		appendEvent: appendFactorySandboxTimelineEvent,
	}, &factory.RunRecord{RunID: "run-factory-policy-logs"}, target,
		unsafePolicyDecisionLogManifestRecords(sandbox.SandboxNetworkPolicyDecisionSource(" FACTORY ")),
		factory.RunSecretRedactor{})
	if err != nil {
		t.Fatalf("recordFactorySandboxSecurityPolicyEvent() error = %v", err)
	}

	events, err := store.LoadEvents("run-factory-policy-logs")
	if err != nil {
		t.Fatalf("LoadEvents() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].Metadata["policyField"] != "sandbox.security" {
		t.Fatalf("policy event metadata = %#v, want sandbox.security policy field", events[0].Metadata)
	}
	assertFactoryTimelineSanitizedPolicyDecisionLogs(t, events[0], sandbox.SandboxNetworkPolicyDecisionSourceFactory)
}

func TestFactoryStatusTimelineNormalizesNetworkPolicyDecisionLogs(t *testing.T) {
	events := normalizeFactoryTimelineEventsForContractV1([]factory.EventRecord{{
		Sequence:                  1,
		RunID:                     "run-status-policy-logs",
		EventType:                 factory.EventTypePolicyDecision,
		Timestamp:                 time.Date(2026, 7, 2, 6, 42, 0, 0, time.UTC),
		NetworkPolicyDecisionLogs: unsafePolicyDecisionLogManifestRecords(sandbox.SandboxNetworkPolicyDecisionSource(" FACTORY ")),
	}})

	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	assertFactoryTimelineSanitizedPolicyDecisionLogs(t, events[0], sandbox.SandboxNetworkPolicyDecisionSourceFactory)
}

func TestFactorySandboxNetworkProxyMetadataPlumbingAvoidsLiveAdapterImports(t *testing.T) {
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "factory_sandbox_executor.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("ParseFile(factory_sandbox_executor.go) error = %v", err)
	}

	forbidden := []struct {
		name  string
		match func(string) bool
	}{
		{name: "worker client package", match: hasImportPrefix("github.com/jywlabs/hal/internal/sandboxworker")},
		{name: "concrete provider adapter package", match: hasImportPrefix("github.com/jywlabs/hal/internal/sandbox/provider")},
		{name: "rootless Podman runtime adapter package", match: hasImportPrefix("github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman")},
		{name: "net/http live proxy package", match: importEquals("net/http")},
		{name: "process execution package", match: importEquals("os/exec")},
		{name: "cloud SDK package", match: importHasAny("cloud.google.com/", "github.com/aws/", "github.com/Azure/", "google.golang.org/api/")},
		{name: "Docker or Podman SDK package", match: importHasAny("docker", "podman")},
		{name: "KVM package", match: importHasAny("kvm", "libvirt")},
		{name: "firewall package", match: importHasAny("firewall", "iptables", "pfctl")},
	}

	for _, spec := range parsed.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("unquote import path %s: %v", spec.Path.Value, err)
		}
		for _, rule := range forbidden {
			if rule.match(importPath) {
				t.Fatalf("factory network proxy metadata plumbing imports forbidden %s %q", rule.name, importPath)
			}
		}
	}
}

func assertFactoryTimelineNonEnforcingDecisionLogs(t *testing.T, event factory.EventRecord, source sandbox.SandboxNetworkPolicyDecisionSource) {
	t.Helper()
	if len(event.NetworkPolicyDecisionLogs) != 1 {
		t.Fatalf("NetworkPolicyDecisionLogs length = %d, want 1", len(event.NetworkPolicyDecisionLogs))
	}
	record := event.NetworkPolicyDecisionLogs[0]
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

	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal(event) error = %v", err)
	}
	encoded := string(payload)
	for _, forbidden := range []string{"\"enforced\":true", string(sandbox.SandboxNetworkPolicyPresetDenyByDefault)} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("factory timeline overclaimed compatibility enforcement %q: %s", forbidden, encoded)
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
			t.Fatalf("factory timeline omitted safe non-enforcing metadata %q: %s", want, encoded)
		}
	}
}

func assertFactoryTimelineSanitizedPolicyDecisionLogs(t *testing.T, event factory.EventRecord, source sandbox.SandboxNetworkPolicyDecisionSource) {
	t.Helper()
	if len(event.NetworkPolicyDecisionLogs) == 0 {
		t.Fatal("NetworkPolicyDecisionLogs is empty, want sanitized decision log records")
	}
	record := event.NetworkPolicyDecisionLogs[0]
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

	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal(event) error = %v", err)
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
			t.Fatalf("factory timeline leaked unsafe decision log metadata %q: %s", forbidden, encoded)
		}
	}
	for _, want := range []string{
		"networkPolicyDecisionLogs",
		"decision-01",
		"factory",
		"policy-snapshot-01",
		"policy-v1",
		"rules-01",
		"metadata_service",
		"denied",
		"default_deny",
		"domain",
		"deny_by_default",
		"none",
	} {
		if !strings.Contains(encoded, want) {
			t.Fatalf("factory timeline omitted safe decision log metadata %q: %s", want, encoded)
		}
	}
}

func unsafeFactoryNetworkProxySession(source sandbox.SandboxNetworkPolicyDecisionSource) *sandbox.SandboxNetworkProxySessionMetadata {
	return &sandbox.SandboxNetworkProxySessionMetadata{
		ID:     " proxy-session-01 ",
		Source: source,
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:        " policy-snapshot-01 ",
			Version:   "https://user:secret@example.test/path?token=secret",
			Preset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
			RuleSetID: "/Users/private/rules.json",
		},
		EnforcementMode: "Bearer",
	}
}

func hasImportPrefix(prefix string) func(string) bool {
	return func(importPath string) bool {
		return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
	}
}

func importEquals(want string) func(string) bool {
	return func(importPath string) bool {
		return importPath == want
	}
}

func importHasAny(markers ...string) func(string) bool {
	return func(importPath string) bool {
		lower := strings.ToLower(importPath)
		for _, marker := range markers {
			if strings.Contains(lower, strings.ToLower(marker)) {
				return true
			}
		}
		return false
	}
}
