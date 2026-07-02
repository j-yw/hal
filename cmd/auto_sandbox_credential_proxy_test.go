package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestAutoSandboxManifestPersistsSanitizedCredentialProxyMetadata(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 7, 30, 0, 0, time.UTC)
	store := sandboxexecution.NewStore(t.TempDir())

	req := autoSandboxRequest{
		ExecutionID: "auto-credential-proxy-metadata",
		ProjectDir:  "/repo",
		NetworkProxySession: &sandbox.SandboxNetworkProxySessionMetadata{
			ID:     " network-proxy-session-01 ",
			Source: sandbox.SandboxNetworkPolicyDecisionSource(" AUTO "),
			PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
				ID:        " policy-snapshot-01 ",
				Version:   "https://token@example.invalid/policy",
				Preset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
				RuleSetID: "/Users/private/rules.json",
			},
			EnforcementMode: "https://proxy.example.invalid:443/session?token=value",
		},
		Security: sandbox.SecurityEvaluationRequest{
			RequestedSecretModes: []string{
				sandbox.SandboxSecretModeHTTPProxy,
				"Authorization: Bearer request-token",
				"OPENAI_API_KEY=raw-env-value",
			},
			ActiveSecretModes: []string{
				sandbox.SandboxSecretModeHTTPProxy,
				"secretValue=raw-secret",
				"credentialValue=raw-credential",
				"unix:///tmp/private/proxy.sock",
			},
			CompatibilityAuthSync: true,
		},
	}
	if err := saveAutoSandboxManifest(store, req, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "auto-credential-proxy-metadata")
	assertAutoSandboxManifestSanitizedCredentialProxyMetadata(t, manifest)
}

func TestAutoSandboxManifestOmitsCredentialProxyMetadataWithoutSafeSources(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 7, 35, 0, 0, time.UTC)
	store := sandboxexecution.NewStore(t.TempDir())

	if err := saveAutoSandboxManifest(store, autoSandboxRequest{
		ExecutionID: "auto-credential-proxy-legacy",
		ProjectDir:  "/repo",
		Security: sandbox.SecurityEvaluationRequest{
			RequestedSecretModes: []string{"https://token@example.invalid/secret"},
			ActiveSecretModes:    []string{"OPENAI_API_KEY=raw-env-value"},
		},
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}

	assertSandboxManifestOmitsCredentialProxyMetadata(t, mustLoadSandboxExecutionManifest(t, store, "auto-credential-proxy-legacy"))
}

func TestAutoSandboxCredentialProxyMetadataStaysOutOfJSONOutput(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 7, 40, 0, 0, time.UTC)
	store := sandboxexecution.NewStore(t.TempDir())
	req := autoSandboxRequest{
		ExecutionID: "auto-credential-proxy-json",
		ProjectDir:  "/repo",
		NetworkProxySession: &sandbox.SandboxNetworkProxySessionMetadata{
			ID:     "network-proxy-session-01",
			Source: sandbox.SandboxNetworkPolicyDecisionSourceAuto,
			PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
				ID:      "policy-snapshot-01",
				Version: "https://token@example.invalid/policy",
			},
			EnforcementMode: "https://proxy.example.invalid:443/session?token=value",
		},
		Security: sandbox.SecurityEvaluationRequest{
			RequestedSecretModes: []string{
				sandbox.SandboxSecretModeHTTPProxy,
				"Authorization: Bearer request-token",
			},
			ActiveSecretModes: []string{
				"secretValue=raw-secret",
			},
		},
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
	assertAutoSandboxCredentialProxyForbiddenStringsAbsent(t, "manifest", string(payload))
}

func assertAutoSandboxCredentialProxyForbiddenStringsAbsent(t *testing.T, label string, encoded string) {
	t.Helper()

	for _, forbidden := range []string{
		"https://token@example.invalid/policy",
		"https://proxy.example.invalid:443/session?token=value",
		"Authorization: Bearer request-token",
		"secretValue=raw-secret",
		"/Users/private/rules.json",
		"token@example.invalid",
		"proxy.example.invalid",
		":443",
		"raw-secret",
		"raw-credential",
		"request-token",
		"OPENAI_API_KEY",
		"raw-env-value",
		"unix:///tmp/private/proxy.sock",
		"ruleSetId",
		"credentialProxyBindings",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("%s leaked unsafe credential proxy metadata %q: %s", label, forbidden, encoded)
		}
	}
}
