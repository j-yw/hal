package cmd

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
)

func TestRunSandboxManifestPersistsSanitizedCredentialProxyMetadata(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 7, 10, 0, 0, time.UTC)
	store := newPrivateSandboxExecutionTestStore(t)
	fixture := phase26CredentialProxyUnsafeValues()

	req := runSandboxRequest{
		ExecutionID:         "run-credential-proxy-metadata",
		ProjectDir:          "/repo",
		NetworkProxySession: fixture.NetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceRun, "network-proxy-session-01", "policy-snapshot-01"),
		Security:            fixture.SecurityRequest([]string{sandbox.SandboxSecretModeHTTPProxy}, []string{sandbox.SandboxSecretModeHTTPProxy}),
	}
	if err := saveRunSandboxManifest(store, req, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}

	manifest := mustLoadSandboxExecutionManifest(t, store, "run-credential-proxy-metadata")
	assertRunSandboxManifestSanitizedCredentialProxyMetadata(t, manifest)
}

func TestRunSandboxCredentialProxyManifestSanitizesProjectionBeforePersistence(t *testing.T) {
	fixture := phase26CredentialProxyUnsafeValues()
	projection := fixture.Projection(sandbox.SandboxCredentialProxySourceRun)

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
		sanitized.Plan.PolicySnapshot.Version != "" ||
		sanitized.Plan.PolicySnapshot.RuleSetID != "" {
		t.Fatalf("sanitized policy snapshot = %#v, want unsafe fields dropped", sanitized.Plan.PolicySnapshot)
	}
	if sanitized.Session.SecretBrokerSessionID != "" {
		t.Fatalf("session secret broker session id = %q, want unsafe reference dropped", sanitized.Session.SecretBrokerSessionID)
	}
	assertPhase26CredentialProxyNoRedactionPlaceholders(t, "sanitized run credential proxy projection", sanitized)

	encoded := mustMarshalRunSandboxCredentialProxyProjection(t, sanitized)
	assertPhase26CredentialProxyUnsafeValuesAbsent(t, "sanitized run credential proxy projection", encoded, fixture)
	assertPhase26CredentialProxyValuesPresent(t, "sanitized run credential proxy projection", encoded,
		"credential-plan-01",
		"credential-session-01",
		"credential-binding-01",
		"network-proxy-session-01",
		"policy-snapshot-01",
		string(sandbox.SandboxCredentialProxySourceRun),
		string(sandbox.SandboxCredentialProxyModeNetworkProxyReference),
		string(sandbox.SandboxCredentialProxyStatusPlanned),
		string(sandbox.SandboxCredentialProxyStatusReady),
		string(sandbox.SandboxCredentialProxyDeliveryModeHTTPProxy),
		string(sandbox.SandboxCredentialProxyRequestNetworkAuth),
		string(sandbox.SandboxCredentialProxyBindingOutcomePlanned),
		string(sandbox.SandboxCredentialProxyReasonRequested),
	)
}

func assertRunSandboxManifestSanitizedCredentialProxyMetadata(t *testing.T, manifest *sandboxexecution.Manifest) {
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
	if plan.SecretBrokerSessionID != "" {
		t.Fatalf("plan secret broker session id = %q, want unsafe optional reference dropped", plan.SecretBrokerSessionID)
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
	assertPhase26CredentialProxyUnsafeValuesAbsent(t, "run sandbox manifest", encoded, fixture)
	assertPhase26CredentialProxyNoRedactionPlaceholders(t, "run sandbox manifest", manifest)
	assertPhase26CredentialProxyValuesPresent(t, "run sandbox manifest", encoded,
		"run-credential-proxy-metadata-credential-proxy-plan",
		"run-credential-proxy-metadata-credential-proxy-session",
		"network-proxy-session-01",
		"policy-snapshot-01",
		string(sandbox.SandboxCredentialProxySourceRun),
		string(sandbox.SandboxCredentialProxyModeNetworkProxyReference),
		string(sandbox.SandboxCredentialProxyStatusPlanned),
		string(sandbox.SandboxCredentialProxyStatusReady),
		string(sandbox.SandboxNetworkPolicyPresetDenyByDefault),
		string(sandbox.SandboxCredentialProxyWarningUnsupportedDeliveryMode),
		string(sandbox.SandboxCredentialProxyReasonDeliveryModeUnsupported),
	)
}

func mustMarshalRunSandboxCredentialProxyProjection(t *testing.T, projection sandbox.SandboxCredentialProxyProjection) string {
	t.Helper()
	payload, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("Marshal(projection) error = %v", err)
	}
	return string(payload)
}
