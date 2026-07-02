package sandbox

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestCredentialProxySanitizeReturnsCopies(t *testing.T) {
	planSnapshot := &SandboxNetworkPolicySnapshotIdentity{ID: "policy-snapshot-01", Version: "v1"}
	plan := SandboxCredentialProxyPlanMetadata{
		ID:                    " credential-plan-01 ",
		Source:                SandboxCredentialProxySource(" RUN "),
		SecretBrokerSessionID: " broker-session-01 ",
		NetworkProxySessionID: " network-proxy-session-01 ",
		PolicySnapshot:        planSnapshot,
		Mode:                  SandboxCredentialProxyMode(" BROKERED_NETWORK_REFERENCE "),
		Status:                SandboxCredentialProxyStatus(" PLANNED "),
	}
	originalPlan := plan
	sanitizedPlan := SanitizeSandboxCredentialProxyPlanMetadata(plan)
	if !reflect.DeepEqual(plan, originalPlan) {
		t.Fatalf("plan input mutated: got %#v, want %#v", plan, originalPlan)
	}
	if sanitizedPlan.PolicySnapshot == planSnapshot {
		t.Fatalf("plan policy snapshot was not copied")
	}
	if sanitizedPlan.ID != "credential-plan-01" || sanitizedPlan.Source != SandboxCredentialProxySourceRun {
		t.Fatalf("sanitized plan = %#v, want normalized safe copy", sanitizedPlan)
	}

	sessionSnapshot := &SandboxNetworkPolicySnapshotIdentity{ID: "policy-snapshot-02", Version: "v2"}
	session := SandboxCredentialProxySessionMetadata{
		ID:                    " credential-session-01 ",
		PlanID:                " credential-plan-01 ",
		Source:                SandboxCredentialProxySource(" FACTORY "),
		SecretBrokerSessionID: " broker-session-01 ",
		NetworkProxySessionID: " network-proxy-session-01 ",
		PolicySnapshot:        sessionSnapshot,
		Status:                SandboxCredentialProxyStatus(" ACTIVE "),
		WarningCode:           SandboxCredentialProxyWarningCode(" BINDING_OMITTED "),
		ReasonCode:            SandboxCredentialProxyReasonCode(" REQUESTED "),
	}
	originalSession := session
	sanitizedSession := SanitizeSandboxCredentialProxySessionMetadata(session)
	if !reflect.DeepEqual(session, originalSession) {
		t.Fatalf("session input mutated: got %#v, want %#v", session, originalSession)
	}
	if sanitizedSession.PolicySnapshot == sessionSnapshot {
		t.Fatalf("session policy snapshot was not copied")
	}
	if sanitizedSession.ID != "credential-session-01" || sanitizedSession.Source != SandboxCredentialProxySourceFactory {
		t.Fatalf("sanitized session = %#v, want normalized safe copy", sanitizedSession)
	}

	binding := SandboxCredentialProxyBindingMetadata{
		ID:                  " credential-binding-01 ",
		PlanID:              " credential-plan-01 ",
		SessionID:           " credential-session-01 ",
		SecretID:            " secret-01 ",
		DeliveryMode:        SandboxCredentialProxyDeliveryMode(" FILE_TMPFS "),
		RequestCategory:     SandboxCredentialProxyRequestCategory(" ARTIFACT_SYNC "),
		DestinationCategory: SandboxNetworkPolicyDestinationCategory(" METADATA_SERVICE "),
		Outcome:             SandboxCredentialProxyBindingOutcome(" AUDIT_ONLY "),
		Status:              SandboxCredentialProxyStatus(" SKIPPED "),
		ReasonCode:          SandboxCredentialProxyReasonCode(" DESTINATION_CATEGORY_SKIPPED "),
	}
	originalBinding := binding
	sanitizedBinding := SanitizeSandboxCredentialProxyBindingMetadata(binding)
	if !reflect.DeepEqual(binding, originalBinding) {
		t.Fatalf("binding input mutated: got %#v, want %#v", binding, originalBinding)
	}
	if sanitizedBinding.ID != "credential-binding-01" || sanitizedBinding.DeliveryMode != SandboxCredentialProxyDeliveryModeFileTmpfs {
		t.Fatalf("sanitized binding = %#v, want normalized safe copy", sanitizedBinding)
	}
}

func TestCredentialProxySanitizeZeroesRecordsWithUnsafeRequiredIDs(t *testing.T) {
	tests := []struct {
		name string
		got  any
		want any
	}{
		{
			name: "plan id missing",
			got: SanitizeSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				Source: SandboxCredentialProxySourceRun,
			}),
			want: SandboxCredentialProxyPlanMetadata{},
		},
		{
			name: "plan id unsafe",
			got: SanitizeSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:     "https://example.invalid/plan?token=value",
				Source: SandboxCredentialProxySourceRun,
			}),
			want: SandboxCredentialProxyPlanMetadata{},
		},
		{
			name: "session plan id unsafe",
			got: SanitizeSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
				ID:     "credential-session-01",
				PlanID: "/Users/alice/plan.json",
				Source: SandboxCredentialProxySourceAuto,
			}),
			want: SandboxCredentialProxySessionMetadata{},
		},
		{
			name: "binding secret id unsafe",
			got: SanitizeSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:           "credential-binding-01",
				PlanID:       "credential-plan-01",
				SecretID:     "secretValue=raw-secret",
				DeliveryMode: SandboxCredentialProxyDeliveryModeEnv,
			}),
			want: SandboxCredentialProxyBindingMetadata{},
		},
		{
			name: "binding parent reference missing after sanitization",
			got: SanitizeSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:           "credential-binding-01",
				PlanID:       "api.example.invalid",
				SecretID:     "secret-01",
				DeliveryMode: SandboxCredentialProxyDeliveryModeEnv,
			}),
			want: SandboxCredentialProxyBindingMetadata{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !reflect.DeepEqual(tt.got, tt.want) {
				t.Fatalf("sanitized record = %#v, want zero value %#v", tt.got, tt.want)
			}
		})
	}
}

func TestCredentialProxySanitizeCollectionsOmitUnsafeRecords(t *testing.T) {
	plans := SanitizeSandboxCredentialProxyPlanMetadataRecords([]SandboxCredentialProxyPlanMetadata{
		{ID: "credential-plan-01", Source: SandboxCredentialProxySourceRun},
		{ID: "https://example.invalid/plan", Source: SandboxCredentialProxySourceRun},
		{ID: "", Source: SandboxCredentialProxySourceAuto},
	})
	if len(plans) != 1 || plans[0].ID != "credential-plan-01" {
		t.Fatalf("sanitized plan records = %#v, want only safe plan", plans)
	}

	sessions := SanitizeSandboxCredentialProxySessionMetadataRecords([]SandboxCredentialProxySessionMetadata{
		{ID: "credential-session-01", PlanID: "credential-plan-01", Source: SandboxCredentialProxySourceRun},
		{ID: "credential-session-02", PlanID: "https://example.invalid/plan", Source: SandboxCredentialProxySourceRun},
	})
	if len(sessions) != 1 || sessions[0].ID != "credential-session-01" {
		t.Fatalf("sanitized session records = %#v, want only safe session", sessions)
	}

	bindings := SanitizeSandboxCredentialProxyBindingMetadataRecords([]SandboxCredentialProxyBindingMetadata{
		{ID: "credential-binding-01", PlanID: "credential-plan-01", SecretID: "secret-01", DeliveryMode: SandboxCredentialProxyDeliveryModeEnv},
		{ID: "credential-binding-02", PlanID: "credential-plan-01", SecretID: "Authorization: Bearer raw-token", DeliveryMode: SandboxCredentialProxyDeliveryModeEnv},
		{ID: "credential-binding-03", PlanID: "api.example.invalid", SecretID: "secret-03", DeliveryMode: SandboxCredentialProxyDeliveryModeEnv},
	})
	if len(bindings) != 1 || bindings[0].ID != "credential-binding-01" {
		t.Fatalf("sanitized binding records = %#v, want only safe binding", bindings)
	}

	if got := SanitizeSandboxCredentialProxyPlanMetadataRecords(nil); got != nil {
		t.Fatalf("nil plan records sanitized to %#v, want nil", got)
	}
	if got := SanitizeSandboxCredentialProxyBindingMetadataRecords([]SandboxCredentialProxyBindingMetadata{}); got != nil {
		t.Fatalf("empty binding records sanitized to %#v, want nil for durable omission", got)
	}
	if got := SanitizeSandboxCredentialProxySessionMetadataRecords([]SandboxCredentialProxySessionMetadata{
		{ID: "https://example.invalid/session", PlanID: "credential-plan-01", Source: SandboxCredentialProxySourceRun},
	}); got != nil {
		t.Fatalf("all-unsafe session records sanitized to %#v, want nil for durable omission", got)
	}
}

func TestCredentialProxySanitizeDropsUnsafeOptionalReferences(t *testing.T) {
	plan := SanitizeSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
		ID:                    "credential-plan-01",
		Source:                SandboxCredentialProxySourceRun,
		SecretBrokerSessionID: "broker.example.invalid",
		NetworkProxySessionID: "/tmp/credential-proxy.sock",
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:        "policy-snapshot-01",
			Version:   "https://example.invalid/policy",
			Preset:    SandboxNetworkPolicyPresetAllowListed,
			RuleSetID: "POLICY_PATH=/Users/alice/rules.json",
		},
	})
	if plan.SecretBrokerSessionID != "" || plan.NetworkProxySessionID != "" {
		t.Fatalf("plan optional references = %#v, want unsafe references dropped", plan)
	}
	if plan.PolicySnapshot == nil {
		t.Fatalf("policy snapshot = nil, want safe snapshot ID preserved")
	}
	if plan.PolicySnapshot.ID != "policy-snapshot-01" || plan.PolicySnapshot.Version != "" || plan.PolicySnapshot.RuleSetID != "" {
		t.Fatalf("policy snapshot = %#v, want unsafe optional references dropped", plan.PolicySnapshot)
	}
	if plan.PolicySnapshot.Preset != SandboxNetworkPolicyPresetAllowListed {
		t.Fatalf("policy preset = %q, want %q", plan.PolicySnapshot.Preset, SandboxNetworkPolicyPresetAllowListed)
	}

	session := SanitizeSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
		ID:                    "credential-session-01",
		PlanID:                "credential-plan-01",
		Source:                SandboxCredentialProxySourceFactory,
		SecretBrokerSessionID: "secretValue=raw-secret",
		NetworkProxySessionID: "https://proxy.example.invalid/session",
		PolicySnapshot:        &SandboxNetworkPolicySnapshotIdentity{ID: "api.example.invalid", Version: "v1"},
	})
	if session.SecretBrokerSessionID != "" || session.NetworkProxySessionID != "" || session.PolicySnapshot != nil {
		t.Fatalf("session optional metadata = %#v, want unsafe optional references dropped", session)
	}

	binding := SanitizeSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
		ID:           "credential-binding-01",
		PlanID:       "https://example.invalid/plan",
		SessionID:    "credential-session-01",
		SecretID:     "secret-01",
		DeliveryMode: SandboxCredentialProxyDeliveryModeEnv,
	})
	if binding.PlanID != "" || binding.SessionID != "credential-session-01" {
		t.Fatalf("binding parent references = %#v, want unsafe optional plan reference dropped", binding)
	}
}

func TestCredentialProxySanitizePreservesSafeMetadata(t *testing.T) {
	plan := SanitizeSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
		ID:                    "credential-plan-01",
		Source:                SandboxCredentialProxySource("AUTO"),
		SecretBrokerSessionID: "broker-session-01",
		NetworkProxySessionID: "network-proxy-session-01",
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:        "policy-snapshot-01",
			Version:   "v1",
			Preset:    SandboxNetworkPolicyPreset("DENY_BY_DEFAULT"),
			RuleSetID: "rules-01",
		},
		BindingCount: 3,
		Mode:         SandboxCredentialProxyMode("BROKERED_NETWORK_REFERENCE"),
		Status:       SandboxCredentialProxyStatus("READY"),
	})
	if plan.Source != SandboxCredentialProxySourceAuto ||
		plan.SecretBrokerSessionID != "broker-session-01" ||
		plan.NetworkProxySessionID != "network-proxy-session-01" ||
		plan.BindingCount != 3 ||
		plan.Mode != SandboxCredentialProxyModeBrokeredNetworkReference ||
		plan.Status != SandboxCredentialProxyStatusReady {
		t.Fatalf("sanitized plan = %#v, want safe metadata preserved", plan)
	}
	if plan.PolicySnapshot == nil ||
		plan.PolicySnapshot.ID != "policy-snapshot-01" ||
		plan.PolicySnapshot.Version != "v1" ||
		plan.PolicySnapshot.Preset != SandboxNetworkPolicyPresetDenyByDefault ||
		plan.PolicySnapshot.RuleSetID != "rules-01" {
		t.Fatalf("policy snapshot = %#v, want safe identity preserved", plan.PolicySnapshot)
	}

	session := SanitizeSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
		ID:          "credential-session-01",
		PlanID:      "credential-plan-01",
		Source:      SandboxCredentialProxySource("WORKER"),
		Status:      SandboxCredentialProxyStatus("COMPLETED"),
		WarningCode: SandboxCredentialProxyWarningCode("BINDING_OMITTED"),
		ReasonCode:  SandboxCredentialProxyReasonCode("REQUESTED"),
	})
	if session.Source != SandboxCredentialProxySourceWorker ||
		session.Status != SandboxCredentialProxyStatusCompleted ||
		session.WarningCode != SandboxCredentialProxyWarningBindingOmitted ||
		session.ReasonCode != SandboxCredentialProxyReasonRequested {
		t.Fatalf("sanitized session = %#v, want safe enum-like metadata preserved", session)
	}

	binding := SanitizeSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
		ID:                  "credential-binding-01",
		PlanID:              "credential-plan-01",
		SecretID:            "secret-01",
		DeliveryMode:        SandboxCredentialProxyDeliveryMode("HTTP_PROXY"),
		RequestCategory:     SandboxCredentialProxyRequestCategory("NETWORK_AUTH"),
		DestinationCategory: SandboxNetworkPolicyDestinationCategory("PRIVATE_NETWORK"),
		Outcome:             SandboxCredentialProxyBindingOutcome("BOUND"),
		Status:              SandboxCredentialProxyStatus("ACTIVE"),
		ReasonCode:          SandboxCredentialProxyReasonCode("NETWORK_PROXY_UNAVAILABLE"),
	})
	if binding.DeliveryMode != SandboxCredentialProxyDeliveryModeHTTPProxy ||
		binding.RequestCategory != SandboxCredentialProxyRequestNetworkAuth ||
		binding.DestinationCategory != SandboxNetworkPolicyDestinationPrivateNetwork ||
		binding.Outcome != SandboxCredentialProxyBindingOutcomeBound ||
		binding.Status != SandboxCredentialProxyStatusActive ||
		binding.ReasonCode != SandboxCredentialProxyReasonNetworkProxyUnavailable {
		t.Fatalf("sanitized binding = %#v, want safe enum-like metadata preserved", binding)
	}
}

func TestCredentialProxySanitizeDoesNotExposeUnsafeValues(t *testing.T) {
	unsafeValues := []string{
		"https://user:pass@example.invalid/path?token=value",
		"api.example.invalid",
		"/Users/alice/.config/key.json",
		"/tmp/credential-proxy.sock",
		"Authorization: Bearer raw-token",
		"TOKEN=value",
		"credentialValue=raw-credential",
		"secretValue=raw-secret",
		"credential-plan-01\nnext",
		"credential-plan-01\x1f",
	}

	plan := SanitizeSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
		ID:                    "credential-plan-01",
		Source:                SandboxCredentialProxySource("https://user:pass@example.invalid/source?token=value"),
		SecretBrokerSessionID: "api.example.invalid",
		NetworkProxySessionID: "/tmp/credential-proxy.sock",
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:        "policy-snapshot-01",
			Version:   "/Users/alice/.config/key.json",
			Preset:    SandboxNetworkPolicyPreset("TOKEN=value"),
			RuleSetID: "Authorization: Bearer raw-token",
		},
		Mode:   SandboxCredentialProxyMode("credentialValue=raw-credential"),
		Status: SandboxCredentialProxyStatus("planned\nnext"),
	})
	assertCredentialProxySanitizeNoUnsafeLeak(t, plan, unsafeValues...)
	assertCredentialProxySanitizeNoErrorLeak(t, ValidateSandboxCredentialProxyPlanMetadata(plan), unsafeValues...)

	session := SanitizeSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
		ID:                    "credential-session-01",
		PlanID:                "credential-plan-01",
		Source:                SandboxCredentialProxySource("Authorization: Bearer raw-token"),
		SecretBrokerSessionID: "secretValue=raw-secret",
		NetworkProxySessionID: "https://proxy.example.invalid/session",
		Status:                SandboxCredentialProxyStatus("secretValue=raw-secret"),
		WarningCode:           SandboxCredentialProxyWarningCode("credential-session-01\x1f"),
		ReasonCode:            SandboxCredentialProxyReasonCode("api.example.invalid"),
	})
	assertCredentialProxySanitizeNoUnsafeLeak(t, session, unsafeValues...)
	assertCredentialProxySanitizeNoErrorLeak(t, ValidateSandboxCredentialProxySessionMetadata(session), unsafeValues...)

	binding := SanitizeSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
		ID:                  "credential-binding-01",
		PlanID:              "credential-plan-01",
		SessionID:           "https://example.invalid/session",
		SecretID:            "secret-01",
		DeliveryMode:        SandboxCredentialProxyDeliveryMode("https://example.invalid/mode"),
		RequestCategory:     SandboxCredentialProxyRequestCategory("Authorization: Bearer raw-token"),
		DestinationCategory: SandboxNetworkPolicyDestinationCategory("api.example.invalid"),
		Outcome:             SandboxCredentialProxyBindingOutcome("credentialValue=raw-credential"),
		Status:              SandboxCredentialProxyStatus("TOKEN=value"),
		ReasonCode:          SandboxCredentialProxyReasonCode("secretValue=raw-secret"),
	})
	assertCredentialProxySanitizeNoUnsafeLeak(t, binding, unsafeValues...)
	assertCredentialProxySanitizeNoErrorLeak(t, ValidateSandboxCredentialProxyBindingMetadata(binding), unsafeValues...)

	records := SanitizeSandboxCredentialProxyBindingMetadataRecords([]SandboxCredentialProxyBindingMetadata{
		{
			ID:           "https://example.invalid/binding?token=value",
			PlanID:       "credential-plan-01",
			SecretID:     "secret-01",
			DeliveryMode: SandboxCredentialProxyDeliveryModeEnv,
		},
		binding,
	})
	assertCredentialProxySanitizeNoUnsafeLeak(t, records, unsafeValues...)
}

func assertCredentialProxySanitizeNoUnsafeLeak(t *testing.T, value any, unsafeValues ...string) {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%T) error: %v", value, err)
	}
	for _, payload := range []string{fmt.Sprintf("%#v", value), string(data)} {
		for _, unsafeValue := range unsafeValues {
			assertCredentialProxySanitizeExcludesRejectedInputs(t, payload, unsafeValue)
		}
	}
}

func assertCredentialProxySanitizeNoErrorLeak(t *testing.T, result SandboxCredentialProxyValidationResult, unsafeValues ...string) {
	t.Helper()

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(validation result) error: %v", err)
	}
	payloads := []string{string(data)}
	for _, validationErr := range result.Errors {
		payloads = append(payloads, string(validationErr.Code), validationErr.Field, validationErr.Message, validationErr.Error())
	}
	for _, payload := range payloads {
		for _, unsafeValue := range unsafeValues {
			assertCredentialProxySanitizeExcludesRejectedInputs(t, payload, unsafeValue)
		}
	}
}

func assertCredentialProxySanitizeExcludesRejectedInputs(t *testing.T, payload string, rejectedValues ...string) {
	t.Helper()

	for _, rejected := range rejectedValues {
		if rejected == "" {
			continue
		}
		for _, forbidden := range []string{rejected, credentialProxySanitizeJSONEscapedStringFragment(t, rejected)} {
			if forbidden == "" {
				continue
			}
			if strings.Contains(payload, forbidden) {
				t.Fatalf("sanitized payload leaked rejected value %q in %s", forbidden, payload)
			}
		}
	}
}

func credentialProxySanitizeJSONEscapedStringFragment(t *testing.T, value string) string {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(rejected value) error: %v", err)
	}
	return strings.TrimSuffix(strings.TrimPrefix(string(data), `"`), `"`)
}
