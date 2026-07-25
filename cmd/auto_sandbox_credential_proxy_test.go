package cmd

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestAutoSandboxManifestPersistsSanitizedCredentialProxyMetadata(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 7, 30, 0, 0, time.UTC)
	store := newPrivateSandboxExecutionTestStore(t)
	fixture := phase26CredentialProxyUnsafeValues()

	req := autoSandboxRequest{
		ExecutionID:         "auto-credential-proxy-metadata",
		ProjectDir:          "/repo",
		NetworkProxySession: fixture.NetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceAuto, "network-proxy-session-01", "policy-snapshot-01"),
		Security:            fixture.SecurityRequest([]string{sandbox.SandboxSecretModeHTTPProxy}, []string{sandbox.SandboxSecretModeHTTPProxy}),
	}
	if err := saveAutoSandboxManifest(store, req, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "auto-credential-proxy-metadata")
	assertAutoSandboxManifestSanitizedCredentialProxyMetadata(t, manifest)
}

func TestAutoSandboxManifestOmitsCredentialProxyMetadataWithoutSafeSources(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 7, 35, 0, 0, time.UTC)
	store := newPrivateSandboxExecutionTestStore(t)
	fixture := phase26CredentialProxyUnsafeValues()

	if err := saveAutoSandboxManifest(store, autoSandboxRequest{
		ExecutionID: "auto-credential-proxy-legacy",
		ProjectDir:  "/repo",
		Security:    fixture.SecurityRequest(nil, nil),
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}

	assertSandboxManifestOmitsCredentialProxyMetadata(t, mustLoadSandboxExecutionManifest(t, store, "auto-credential-proxy-legacy"))
}

func TestAutoSandboxCredentialProxyMetadataStaysOutOfJSONOutput(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 7, 40, 0, 0, time.UTC)
	store := newPrivateSandboxExecutionTestStore(t)
	fixture := phase26CredentialProxyUnsafeValues()
	req := autoSandboxRequest{
		ExecutionID:         "auto-credential-proxy-json",
		ProjectDir:          "/repo",
		NetworkProxySession: fixture.NetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceAuto, "network-proxy-session-01", "policy-snapshot-01"),
		Security:            fixture.SecurityRequest([]string{sandbox.SandboxSecretModeHTTPProxy}, []string{sandbox.SandboxSecretModeHTTPProxy}),
	}
	if err := saveAutoSandboxManifest(store, req, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}
	manifest := mustLoadSandboxExecutionManifest(t, store, "auto-credential-proxy-json")
	manifest.SyncOut = &sandboxworkspace.SyncOutSummary{
		Workspace: sandboxworkspace.SyncOutWorkspaceRef{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
			Branch:      "feature/auto",
		},
		Recovery: sandboxworkspace.SyncOutRecoveryState{Status: sandboxworkspace.SyncOutRecoveryStatusCollected},
		Apply: sandboxworkspace.SyncOutApplyDecision{
			Eligible: false,
			Reasons:  []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact},
		},
	}
	if err := store.SaveManifest(manifest); err != nil {
		t.Fatalf("SaveManifest() error = %v", err)
	}

	var out bytes.Buffer
	if err := outputSandboxSyncOutAugmentedJSON(&out, []byte(autoSandboxRemoteSuccessJSON("remote")+"\n"), store, "auto-credential-proxy-json"); err != nil {
		t.Fatalf("outputSandboxSyncOutAugmentedJSON() error = %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &fields); err != nil {
		t.Fatalf("Unmarshal(auto JSON output) error = %v\n%s", err, out.String())
	}
	if _, ok := fields["syncOut"]; !ok {
		t.Fatalf("auto JSON output omitted syncOut: %s", out.String())
	}
	for _, field := range []string{"credentialProxy", "credentialProxyPlan", "credentialProxySession", "credentialProxyBindings"} {
		if _, ok := fields[field]; ok {
			t.Fatalf("auto JSON output included credential proxy field %q: %s", field, out.String())
		}
	}
	assertAutoSandboxCredentialProxyForbiddenStringsAbsent(t, "auto JSON output", out.String())
}

func assertAutoSandboxManifestSanitizedCredentialProxyMetadata(t *testing.T, manifest *sandboxexecution.Manifest) {
	t.Helper()
	fixture := phase26CredentialProxyUnsafeValues()

	if manifest.CredentialProxyPlan == nil {
		t.Fatal("CredentialProxyPlan = nil, want sanitized plan metadata")
	}
	if manifest.CredentialProxySession == nil {
		t.Fatal("CredentialProxySession = nil, want sanitized session metadata")
	}
	if len(manifest.CredentialProxyBindings) != 0 {
		t.Fatalf("CredentialProxyBindings = %#v, want omitted bindings without safe secret ids", manifest.CredentialProxyBindings)
	}

	plan := manifest.CredentialProxyPlan
	if plan.ID != "auto-credential-proxy-metadata-credential-proxy-plan" {
		t.Fatalf("plan id = %q, want execution-scoped safe id", plan.ID)
	}
	if plan.Source != sandbox.SandboxCredentialProxySourceAuto {
		t.Fatalf("plan source = %q, want auto", plan.Source)
	}
	if plan.Mode != sandbox.SandboxCredentialProxyModeNetworkProxyReference {
		t.Fatalf("plan mode = %q, want network_proxy_reference", plan.Mode)
	}
	if plan.NetworkProxySessionID != "network-proxy-session-01" {
		t.Fatalf("plan network proxy session id = %q, want sanitized id", plan.NetworkProxySessionID)
	}
	if plan.BindingCount != 0 {
		t.Fatalf("plan binding count = %d, want 0 without safe secret ids", plan.BindingCount)
	}
	if plan.PolicySnapshot == nil {
		t.Fatal("plan policy snapshot = nil, want sanitized snapshot identity")
	}
	if plan.PolicySnapshot.ID != "policy-snapshot-01" ||
		plan.PolicySnapshot.Preset != sandbox.SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("plan policy snapshot = %#v, want sanitized snapshot identity", plan.PolicySnapshot)
	}
	if plan.PolicySnapshot.Version != "" || plan.PolicySnapshot.RuleSetID != "" {
		t.Fatalf("plan policy snapshot = %#v, want unsafe optional fields dropped", plan.PolicySnapshot)
	}
	if plan.SecretBrokerSessionID != "" {
		t.Fatalf("plan secret broker session id = %q, want unsafe optional reference dropped", plan.SecretBrokerSessionID)
	}

	session := manifest.CredentialProxySession
	if session.ID != "auto-credential-proxy-metadata-credential-proxy-session" {
		t.Fatalf("session id = %q, want execution-scoped safe id", session.ID)
	}
	if session.PlanID != plan.ID {
		t.Fatalf("session plan id = %q, want %q", session.PlanID, plan.ID)
	}
	if session.Source != sandbox.SandboxCredentialProxySourceAuto {
		t.Fatalf("session source = %q, want auto", session.Source)
	}
	if session.WarningCode != sandbox.SandboxCredentialProxyWarningUnsupportedDeliveryMode ||
		session.ReasonCode != sandbox.SandboxCredentialProxyReasonDeliveryModeUnsupported {
		t.Fatalf("session warning/reason = %#v, want unsupported unsafe delivery mode metadata", session)
	}
	if session.SecretBrokerSessionID != "" {
		t.Fatalf("session secret broker session id = %q, want unsafe optional reference dropped", session.SecretBrokerSessionID)
	}

	fields := sandboxManifestJSONFields(t, manifest)
	for _, want := range []string{"credentialProxyPlan", "credentialProxySession"} {
		if _, ok := fields[want]; !ok {
			t.Fatalf("manifest JSON omitted %q: %#v", want, fields)
		}
	}
	if _, ok := fields["credentialProxyBindings"]; ok {
		t.Fatalf("manifest JSON included empty credentialProxyBindings: %#v", fields)
	}

	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(manifest) error = %v", err)
	}
	encoded := string(payload)
	assertPhase26CredentialProxyUnsafeValuesAbsent(t, "auto sandbox manifest", encoded, fixture)
	assertPhase26CredentialProxyNoRedactionPlaceholders(t, "auto sandbox manifest", manifest)
	assertPhase26CredentialProxyValuesPresent(t, "auto sandbox manifest", encoded,
		"auto-credential-proxy-metadata-credential-proxy-plan",
		"auto-credential-proxy-metadata-credential-proxy-session",
		"network-proxy-session-01",
		"policy-snapshot-01",
		string(sandbox.SandboxCredentialProxySourceAuto),
		string(sandbox.SandboxCredentialProxyModeNetworkProxyReference),
		string(sandbox.SandboxCredentialProxyStatusPlanned),
		string(sandbox.SandboxCredentialProxyStatusReady),
		string(sandbox.SandboxNetworkPolicyPresetDenyByDefault),
		string(sandbox.SandboxCredentialProxyWarningUnsupportedDeliveryMode),
		string(sandbox.SandboxCredentialProxyReasonDeliveryModeUnsupported),
	)
}

func assertAutoSandboxCredentialProxyForbiddenStringsAbsent(t *testing.T, label string, encoded string) {
	t.Helper()

	assertPhase26CredentialProxyUnsafeValuesAbsent(t, label, encoded, phase26CredentialProxyUnsafeValues())
	assertPhase26CredentialProxyNoRedactionPlaceholders(t, label, encoded)
}
