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

	runStore := sandboxexecution.NewStore(t.TempDir())
	if err := saveRunSandboxManifest(runStore, runSandboxRequest{
		ExecutionID: "run-no-proxy-metadata",
		ProjectDir:  "/repo",
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}
	runManifest := mustLoadSandboxExecutionManifest(t, runStore, "run-no-proxy-metadata")
	assertSandboxManifestOmitsNetworkProxyMetadata(t, runManifest)

	autoStore := sandboxexecution.NewStore(t.TempDir())
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

	runStore := sandboxexecution.NewStore(t.TempDir())
	if err := saveRunSandboxManifest(runStore, runSandboxRequest{
		ExecutionID:         "run-proxy-metadata",
		ProjectDir:          "/repo",
		NetworkProxySession: unsafeProxyManifestSession(sandbox.SandboxNetworkPolicyDecisionSource(" RUN ")),
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}
	runManifest := mustLoadSandboxExecutionManifest(t, runStore, "run-proxy-metadata")
	assertSandboxManifestSanitizedNetworkProxySession(t, runManifest, sandbox.SandboxNetworkPolicyDecisionSourceRun)

	autoStore := sandboxexecution.NewStore(t.TempDir())
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

func assertSandboxManifestOmitsNetworkProxyMetadata(t *testing.T, manifest *sandboxexecution.Manifest) {
	t.Helper()
	if manifest.NetworkProxySession != nil {
		t.Fatalf("NetworkProxySession = %#v, want nil by default", manifest.NetworkProxySession)
	}
	fields := sandboxManifestJSONFields(t, manifest)
	for _, forbidden := range []string{"networkProxySession", "networkPolicyDecisionLog", "networkPolicyDecisionLogs"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("manifest should omit %q by default: %#v", forbidden, fields)
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
