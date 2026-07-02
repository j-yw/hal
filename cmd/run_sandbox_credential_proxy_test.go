package cmd

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
)

func TestRunSandboxManifestPersistsSanitizedCredentialProxyMetadata(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 7, 10, 0, 0, time.UTC)
	store := sandboxexecution.NewStore(t.TempDir())

	req := runSandboxRequest{
		ExecutionID: "run-credential-proxy-metadata",
		ProjectDir:  "/repo",
		NetworkProxySession: &sandbox.SandboxNetworkProxySessionMetadata{
			ID:     " network-proxy-session-01 ",
			Source: sandbox.SandboxNetworkPolicyDecisionSource(" RUN "),
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
	if err := saveRunSandboxManifest(store, req, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "run-credential-proxy-metadata")
	assertRunSandboxManifestSanitizedCredentialProxyMetadata(t, manifest)
}

func TestRunSandboxCredentialProxyManifestSanitizesProjectionBeforePersistence(t *testing.T) {
	projection := sandbox.SandboxCredentialProxyProjection{
		Plan: &sandbox.SandboxCredentialProxyPlanMetadata{
			ID:                    " credential-plan-01 ",
			Source:                sandbox.SandboxCredentialProxySource(" RUN "),
			SecretBrokerSessionID: "https://broker.example.invalid/session?token=value",
			NetworkProxySessionID: " network-proxy-session-01 ",
			PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
				ID:        " policy-snapshot-01 ",
				Version:   "v1",
				Preset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
				RuleSetID: "Authorization: Bearer raw-token",
			},
			Mode:   sandbox.SandboxCredentialProxyMode(" NETWORK_PROXY_REFERENCE "),
			Status: sandbox.SandboxCredentialProxyStatus(" PLANNED "),
		},
		Session: &sandbox.SandboxCredentialProxySessionMetadata{
			ID:                    " credential-session-01 ",
			PlanID:                " credential-plan-01 ",
			Source:                sandbox.SandboxCredentialProxySource(" RUN "),
			SecretBrokerSessionID: "secretValue=raw-secret",
			NetworkProxySessionID: " network-proxy-session-01 ",
			Status:                sandbox.SandboxCredentialProxyStatus(" READY "),
			WarningCode:           sandbox.SandboxCredentialProxyWarningCode(" BINDING_OMITTED "),
			ReasonCode:            sandbox.SandboxCredentialProxyReasonCode(" REQUESTED "),
		},
		Bindings: []sandbox.SandboxCredentialProxyBindingMetadata{
			{
				ID:              " credential-binding-01 ",
				PlanID:          " credential-plan-01 ",
				SessionID:       " credential-session-01 ",
				SecretID:        "env:GITHUB_TOKEN",
				DeliveryMode:    sandbox.SandboxCredentialProxyDeliveryMode(" HTTP_PROXY "),
				RequestCategory: sandbox.SandboxCredentialProxyRequestCategory(" NETWORK_AUTH "),
				Outcome:         sandbox.SandboxCredentialProxyBindingOutcome(" PLANNED "),
				Status:          sandbox.SandboxCredentialProxyStatus(" PLANNED "),
				ReasonCode:      sandbox.SandboxCredentialProxyReasonCode(" REQUESTED "),
			},
			{
				ID:           "credential-binding-02",
				PlanID:       "credential-plan-01",
				SecretID:     "Authorization: Bearer raw-token",
				DeliveryMode: sandbox.SandboxCredentialProxyDeliveryModeEnv,
			},
		},
	}

	sanitized := sandboxManifestSanitizedCredentialProxyProjection(projection)
	if sanitized.Plan == nil {
		t.Fatal("sanitized Plan = nil, want safe plan metadata")
	}
	if sanitized.Session == nil {
		t.Fatal("sanitized Session = nil, want safe session metadata")
	}
	if len(sanitized.Bindings) != 1 {
		t.Fatalf("sanitized bindings = %#v, want only safe binding retained", sanitized.Bindings)
	}
	if sanitized.Plan.Source != sandbox.SandboxCredentialProxySourceRun ||
		sanitized.Plan.Mode != sandbox.SandboxCredentialProxyModeNetworkProxyReference ||
		sanitized.Plan.Status != sandbox.SandboxCredentialProxyStatusPlanned {
		t.Fatalf("sanitized plan enums = %#v, want normalized safe values", sanitized.Plan)
	}
	if sanitized.Plan.SecretBrokerSessionID != "" {
		t.Fatalf("plan secret broker session id = %q, want unsafe reference dropped", sanitized.Plan.SecretBrokerSessionID)
	}
	if sanitized.Plan.NetworkProxySessionID != "network-proxy-session-01" {
		t.Fatalf("plan network proxy session id = %q, want sanitized id", sanitized.Plan.NetworkProxySessionID)
	}
	if sanitized.Plan.PolicySnapshot == nil ||
		sanitized.Plan.PolicySnapshot.ID != "policy-snapshot-01" ||
		sanitized.Plan.PolicySnapshot.RuleSetID != "" {
		t.Fatalf("sanitized policy snapshot = %#v, want unsafe fields dropped", sanitized.Plan.PolicySnapshot)
	}

	encoded := mustMarshalRunSandboxCredentialProxyProjection(t, sanitized)
	for _, forbidden := range []string{
		"https://broker.example.invalid/session?token=value",
		"Authorization: Bearer raw-token",
		"secretValue=raw-secret",
		"raw-token",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("sanitized projection leaked %q: %s", forbidden, encoded)
		}
	}
}

func assertRunSandboxManifestSanitizedCredentialProxyMetadata(t *testing.T, manifest *sandboxexecution.Manifest) {
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
	if plan.ID != "run-credential-proxy-metadata-credential-proxy-plan" {
		t.Fatalf("plan id = %q, want execution-scoped safe id", plan.ID)
	}
	if plan.Source != sandbox.SandboxCredentialProxySourceRun {
		t.Fatalf("plan source = %q, want run", plan.Source)
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
	if session.ID != "run-credential-proxy-metadata-credential-proxy-session" {
		t.Fatalf("session id = %q, want execution-scoped safe id", session.ID)
	}
	if session.PlanID != plan.ID {
		t.Fatalf("session plan id = %q, want %q", session.PlanID, plan.ID)
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
	encoded := string(payload)
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
			t.Fatalf("manifest leaked unsafe credential proxy metadata %q: %s", forbidden, encoded)
		}
	}
}

func mustMarshalRunSandboxCredentialProxyProjection(t *testing.T, projection sandbox.SandboxCredentialProxyProjection) string {
	t.Helper()
	payload, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("Marshal(projection) error = %v", err)
	}
	return string(payload)
}
