package credentialdelivery

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestBuildDeliveryPlanReportsRequestedAndActiveModesForEveryDeliveryMode(t *testing.T) {
	tests := []struct {
		name        string
		mode        Mode
		proxyReady  bool
		wantActive  []Mode
		wantWarning WarningCode
		wantReason  ReasonCode
	}{
		{
			name:       "http proxy with safe session binding",
			mode:       ModeHTTPProxy,
			proxyReady: true,
			wantActive: []Mode{ModeHTTPProxy},
		},
		{
			name:        "http proxy without safe session binding",
			mode:        ModeHTTPProxy,
			wantWarning: WarningActivationSkipped,
			wantReason:  ReasonMissingServiceBinding,
		},
		{
			name:        "ssh agent waits for adapter activation",
			mode:        ModeSSHAgent,
			wantWarning: WarningAdapterUnavailable,
			wantReason:  ReasonActivationUnavailable,
		},
		{
			name:        "file tmpfs waits for adapter activation",
			mode:        ModeFileTmpfs,
			wantWarning: WarningAdapterUnavailable,
			wantReason:  ReasonActivationUnavailable,
		},
		{
			name:        "env waits for adapter activation",
			mode:        ModeEnv,
			wantWarning: WarningAdapterUnavailable,
			wantReason:  ReasonActivationUnavailable,
		},
		{
			name:        "legacy auth sync stays compatibility only",
			mode:        ModeLegacyAuthSync,
			proxyReady:  true,
			wantWarning: WarningLegacyAuthCompatibility,
			wantReason:  ReasonCompatibilityMode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binding := planBindingFixture(tt.mode)
			request := planConstructionRequestFixture(binding)
			if tt.proxyReady {
				request.NetworkProxySession = planNetworkProxySessionFixture()
			} else {
				binding.NetworkProxySessionID = ""
				request.Bindings = []Binding{binding}
			}

			got := BuildDeliveryPlan(request)

			assertPlanValid(t, got)
			assertPlanModes(t, got.RequestedModes, []Mode{tt.mode})
			assertPlanModes(t, got.ActiveModes, tt.wantActive)
			if tt.mode == ModeHTTPProxy && tt.proxyReady && got.NetworkProxySessionID != "network-proxy-session-01" {
				t.Fatalf("network proxy session id = %q, want safe active session", got.NetworkProxySessionID)
			}
			if tt.mode == ModeHTTPProxy && !tt.proxyReady && got.NetworkProxySessionID != "" {
				t.Fatalf("network proxy session id = %q, want omitted without safe session binding", got.NetworkProxySessionID)
			}
			if got.BindingCount != 1 {
				t.Fatalf("binding count = %d, want 1", got.BindingCount)
			}
			if tt.wantWarning != "" {
				assertPlanWarning(t, got, tt.wantWarning, tt.wantReason, tt.mode)
			}
			assertPlanNoUnsafeLeak(t, got)
		})
	}
}

func TestBuildDeliveryPlanPrefersHTTPProxyWithSafeCredentialProxySessionBinding(t *testing.T) {
	binding := planBindingFixture(ModeHTTPProxy)
	binding.NetworkProxySessionID = ""

	got := BuildDeliveryPlan(PlanConstructionRequest{
		PlanID:           "delivery-plan-01",
		RequestID:        "delivery-request-01",
		RequestedModes:   []Mode{ModeLegacyAuthSync, ModeHTTPProxy},
		Bindings:         []Binding{binding},
		ResolvedBindings: []ResolvedBindingSecretMetadata{resolvedPlanBindingFixture(binding)},
		PolicySnapshot:   planPolicySnapshotFixture(),
		NetworkProxySession: &sandbox.SandboxNetworkProxySessionMetadata{
			ID:             "network-proxy-session-01",
			Source:         sandbox.SandboxNetworkPolicyDecisionSourceRun,
			PolicySnapshot: planPolicySnapshotFixture(),
		},
		CredentialProxySession: &sandbox.SandboxCredentialProxySessionMetadata{
			ID:                    "credential-proxy-session-01",
			PlanID:                "credential-proxy-plan-01",
			Source:                sandbox.SandboxCredentialProxySourceRun,
			NetworkProxySessionID: "network-proxy-session-01",
			PolicySnapshot:        planPolicySnapshotFixture(),
			Status:                sandbox.SandboxCredentialProxyStatusReady,
		},
		CredentialProxyBindings: []sandbox.SandboxCredentialProxyBindingMetadata{{
			ID:           "credential-proxy-binding-01",
			SessionID:    "credential-proxy-session-01",
			SecretID:     binding.SecretRef,
			DeliveryMode: sandbox.SandboxCredentialProxyDeliveryModeHTTPProxy,
			Outcome:      sandbox.SandboxCredentialProxyBindingOutcomeBound,
			Status:       sandbox.SandboxCredentialProxyStatusReady,
			ReasonCode:   sandbox.SandboxCredentialProxyReasonRequested,
		}},
	})

	assertPlanValid(t, got)
	assertPlanModes(t, got.RequestedModes, []Mode{ModeHTTPProxy, ModeLegacyAuthSync})
	assertPlanModes(t, got.ActiveModes, []Mode{ModeHTTPProxy})
	if got.NetworkProxySessionID != "network-proxy-session-01" {
		t.Fatalf("network proxy session id = %q, want safe credential proxy session network reference", got.NetworkProxySessionID)
	}
	assertPlanWarning(t, got, WarningLegacyAuthCompatibility, ReasonCompatibilityMode, ModeLegacyAuthSync)
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want only legacy compatibility warning", got.Warnings)
	}
	assertPlanNoUnsafeLeak(t, got)
}

func TestBuildDeliveryPlanRecordsHTTPProxyRequestedButInactiveWithoutSafeProxyBinding(t *testing.T) {
	binding := planBindingFixture(ModeHTTPProxy)
	got := BuildDeliveryPlan(PlanConstructionRequest{
		PlanID:           "delivery-plan-01",
		RequestID:        "delivery-request-01",
		RequestedModes:   []Mode{ModeHTTPProxy},
		Bindings:         []Binding{binding},
		ResolvedBindings: []ResolvedBindingSecretMetadata{resolvedPlanBindingFixture(binding)},
		NetworkProxySession: &sandbox.SandboxNetworkProxySessionMetadata{
			ID:     "https://proxy.example.invalid/session?token=value",
			Source: sandbox.SandboxNetworkPolicyDecisionSourceRun,
		},
	})

	assertPlanValid(t, got)
	assertPlanModes(t, got.RequestedModes, []Mode{ModeHTTPProxy})
	if len(got.ActiveModes) != 0 {
		t.Fatalf("active modes = %#v, want http_proxy requested but inactive", got.ActiveModes)
	}
	if got.NetworkProxySessionID != "" {
		t.Fatalf("network proxy session id = %q, want omitted for unsafe proxy metadata", got.NetworkProxySessionID)
	}
	assertPlanWarning(t, got, WarningActivationSkipped, ReasonMissingServiceBinding, ModeHTTPProxy)
	assertPlanNoUnsafeLeak(t, got, "https://proxy.example.invalid/session?token=value", "proxy.example.invalid", "token=value")
}

func planConstructionRequestFixture(binding Binding) PlanConstructionRequest {
	return PlanConstructionRequest{
		PlanID:           "delivery-plan-01",
		RequestID:        "delivery-request-01",
		RequestedModes:   []Mode{binding.DeliveryMode},
		Bindings:         []Binding{binding},
		ResolvedBindings: []ResolvedBindingSecretMetadata{resolvedPlanBindingFixture(binding)},
		PolicySnapshot:   planPolicySnapshotFixture(),
	}
}

func planBindingFixture(mode Mode) Binding {
	binding := safeBindingFixture()
	binding.DeliveryMode = mode
	return binding
}

func resolvedPlanBindingFixture(binding Binding) ResolvedBindingSecretMetadata {
	return ResolvedBindingSecretMetadata{
		BindingID:    binding.ID,
		SecretRef:    binding.SecretRef,
		DeliveryMode: binding.DeliveryMode,
		BrokerSecret: BrokerSecretMetadata{
			ID:       binding.SecretRef,
			Source:   "broker",
			Required: true,
			Present:  true,
		},
	}
}

func planNetworkProxySessionFixture() *sandbox.SandboxNetworkProxySessionMetadata {
	return &sandbox.SandboxNetworkProxySessionMetadata{
		ID:             "network-proxy-session-01",
		Source:         sandbox.SandboxNetworkPolicyDecisionSourceRun,
		PolicySnapshot: planPolicySnapshotFixture(),
	}
}

func planPolicySnapshotFixture() *sandbox.SandboxNetworkPolicySnapshotIdentity {
	return &sandbox.SandboxNetworkPolicySnapshotIdentity{
		ID:      "policy-snapshot-01",
		Version: "v1",
		Preset:  sandbox.SandboxNetworkPolicyPresetDenyByDefault,
	}
}

func assertPlanValid(t *testing.T, plan Plan) {
	t.Helper()

	if plan.ID == "" {
		t.Fatalf("plan = %#v, want durable plan metadata", plan)
	}
	if plan.Status == StatusFailed || len(plan.Errors) != 0 {
		t.Fatalf("plan errors = %#v, status = %q, want valid plan", plan.Errors, plan.Status)
	}
}

func assertPlanModes(t *testing.T, got, want []Mode) {
	t.Helper()

	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("modes = %#v, want %#v", got, want)
	}
}

func assertPlanWarning(t *testing.T, plan Plan, code WarningCode, reason ReasonCode, mode Mode) {
	t.Helper()

	for _, warning := range plan.Warnings {
		if warning.Code == code && warning.ReasonCode == reason && warning.Mode == mode {
			return
		}
	}
	t.Fatalf("warnings = %#v, want code %q reason %q mode %q", plan.Warnings, code, reason, mode)
}

func assertPlanNoUnsafeLeak(t *testing.T, value any, rejectedValues ...string) {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%T) error: %v", value, err)
	}
	payload := string(data)
	for _, forbidden := range []string{
		"https://",
		"example.invalid",
		"/Users/",
		"/tmp/",
		"/var/run/",
		"Authorization",
		"Bearer",
		"X-Api-Key",
		"GITHUB_TOKEN=",
		"ghp_",
		"credentialValue",
		"secretValue",
		"provider_credential",
		"providerCredential",
		"raw_secret",
		"\n",
		"\u001f",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("plan payload leaked unsafe value %q in %s", forbidden, payload)
		}
	}
	for _, rejected := range rejectedValues {
		if rejected == "" {
			continue
		}
		if strings.Contains(payload, rejected) {
			t.Fatalf("plan leaked rejected value %q in %s", rejected, payload)
		}
	}
}
