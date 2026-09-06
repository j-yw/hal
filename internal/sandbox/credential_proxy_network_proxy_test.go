package sandbox

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialProxyReferencesNetworkProxyMetadataBySafeIDs(t *testing.T) {
	proxySession := SandboxNetworkProxySessionMetadata{
		ID:     " network-proxy-session-01 ",
		Source: SandboxNetworkPolicyDecisionSourceFactory,
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:        " policy-snapshot-01 ",
			Version:   " v1 ",
			Preset:    SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
			RuleSetID: " rules-01 ",
		},
		EnforcementMode: "proxy_firewall",
	}

	plan := CredentialProxyPlanMetadataFromNetworkProxySession(NetworkProxyCredentialProxyPlanRequest{
		ID:      "credential-plan-01",
		Source:  SandboxCredentialProxySourceFactory,
		Session: proxySession,
		Status:  SandboxCredentialProxyStatusPlanned,
	})
	session := CredentialProxySessionMetadataFromNetworkProxySession(NetworkProxyCredentialProxySessionRequest{
		ID:      "credential-session-01",
		PlanID:  plan.ID,
		Source:  SandboxCredentialProxySourceFactory,
		Session: proxySession,
		Status:  SandboxCredentialProxyStatusReady,
	})

	if plan.NetworkProxySessionID != "network-proxy-session-01" {
		t.Fatalf("plan network proxy session ID = %q, want sanitized proxy session ID", plan.NetworkProxySessionID)
	}
	if session.NetworkProxySessionID != "network-proxy-session-01" {
		t.Fatalf("session network proxy session ID = %q, want sanitized proxy session ID", session.NetworkProxySessionID)
	}
	if plan.PolicySnapshot == nil || session.PolicySnapshot == nil {
		t.Fatalf("policy snapshots = %#v %#v, want sanitized copies", plan.PolicySnapshot, session.PolicySnapshot)
	}
	if plan.PolicySnapshot == proxySession.PolicySnapshot || session.PolicySnapshot == proxySession.PolicySnapshot {
		t.Fatalf("credential proxy policy snapshots alias source proxy session snapshot")
	}
	if plan.PolicySnapshot.ID != "policy-snapshot-01" ||
		plan.PolicySnapshot.Version != "v1" ||
		plan.PolicySnapshot.Preset != SandboxNetworkPolicyPresetDenyByDefault ||
		plan.PolicySnapshot.RuleSetID != "rules-01" {
		t.Fatalf("plan policy snapshot = %#v, want sanitized safe identity fields", plan.PolicySnapshot)
	}
	if plan.Mode != SandboxCredentialProxyModeNetworkProxyReference {
		t.Fatalf("plan mode = %q, want %q", plan.Mode, SandboxCredentialProxyModeNetworkProxyReference)
	}

	assertCredentialProxyNetworkValidationValid(t, ValidateSandboxCredentialProxyPlanMetadata(plan))
	assertCredentialProxyNetworkValidationValid(t, ValidateSandboxCredentialProxySessionMetadata(session))

	data, err := json.Marshal(struct {
		Plan    SandboxCredentialProxyPlanMetadata    `json:"plan"`
		Session SandboxCredentialProxySessionMetadata `json:"session"`
	}{
		Plan:    plan,
		Session: session,
	})
	if err != nil {
		t.Fatalf("json.Marshal(credential proxy network references) error: %v", err)
	}
	payload := string(data)
	for _, forbidden := range []string{"enforcementMode", "proxy_firewall", "destination", "host", "url", "header", "body"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("credential proxy network reference JSON copied raw proxy metadata %q in %s", forbidden, payload)
		}
	}
}

func TestCredentialProxyNetworkProxyHelperDropsUnsafeNetworkReferences(t *testing.T) {
	rawURL := "https://api.example.invalid:443/path?token=value"
	rawHost := "api.example.invalid"
	rawHeader := "Authorization: Bearer network-token"
	rawBody := `{"credentialValue":"raw-secret"}`

	proxySession := SandboxNetworkProxySessionMetadata{
		ID: rawURL,
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:        rawHost,
			Version:   "443",
			Preset:    SandboxNetworkPolicyPreset(rawBody),
			RuleSetID: rawHeader,
		},
		EnforcementMode: "proxy",
	}

	plan := CredentialProxyPlanMetadataFromNetworkProxySession(NetworkProxyCredentialProxyPlanRequest{
		ID:      "credential-plan-01",
		Source:  SandboxCredentialProxySourceRun,
		Session: proxySession,
		Status:  SandboxCredentialProxyStatusPlanned,
	})
	if plan.NetworkProxySessionID != "" || plan.PolicySnapshot != nil {
		t.Fatalf("plan network references = %#v, want unsafe proxy metadata dropped", plan)
	}

	session := CredentialProxySessionMetadataFromNetworkProxySession(NetworkProxyCredentialProxySessionRequest{
		ID:      "credential-session-01",
		PlanID:  "credential-plan-01",
		Source:  SandboxCredentialProxySourceRun,
		Session: proxySession,
		Status:  SandboxCredentialProxyStatusReady,
	})
	if session.NetworkProxySessionID != "" || session.PolicySnapshot != nil {
		t.Fatalf("session network references = %#v, want unsafe proxy metadata dropped", session)
	}

	data, err := json.Marshal(struct {
		Plan    SandboxCredentialProxyPlanMetadata    `json:"plan"`
		Session SandboxCredentialProxySessionMetadata `json:"session"`
	}{
		Plan:    plan,
		Session: session,
	})
	if err != nil {
		t.Fatalf("json.Marshal(credential proxy network references) error: %v", err)
	}
	assertCredentialProxyNetworkPayloadExcludes(t, string(data), rawURL, rawHost, rawHeader, rawBody, "network-token", "raw-secret")
}

func TestCredentialProxyValidationRejectsRawNetworkDestinationMetadata(t *testing.T) {
	rawDestination := "https://api.example.invalid:443/path?token=value"
	rawHeader := "Authorization: Bearer network-token"
	rawBody := `{"credentialValue":"raw-secret"}`

	tests := []struct {
		name   string
		result SandboxCredentialProxyValidationResult
		code   SandboxCredentialProxyValidationCode
		field  string
		values []string
	}{
		{
			name: "network proxy session id raw destination",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:                    "credential-plan-01",
				Source:                SandboxCredentialProxySourceRun,
				NetworkProxySessionID: rawDestination,
			}),
			code:   SandboxCredentialProxyValidationUnsafeReference,
			field:  "networkProxySessionId",
			values: []string{rawDestination},
		},
		{
			name: "policy snapshot raw host",
			result: ValidateSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
				ID:     "credential-session-01",
				PlanID: "credential-plan-01",
				Source: SandboxCredentialProxySourceRun,
				PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
					ID: rawDestination,
				},
			}),
			code:   SandboxCredentialProxyValidationUnsafeReference,
			field:  "policySnapshot.id",
			values: []string{rawDestination},
		},
		{
			name: "request category raw header",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:              "credential-binding-01",
				SessionID:       "credential-session-01",
				SecretID:        "secret-01",
				DeliveryMode:    SandboxCredentialProxyDeliveryModeHTTPProxy,
				RequestCategory: SandboxCredentialProxyRequestCategory(rawHeader),
			}),
			code:   SandboxCredentialProxyValidationUnsafeMetadata,
			field:  "requestCategory",
			values: []string{rawHeader, "network-token"},
		},
		{
			name: "destination category raw url",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:                  "credential-binding-01",
				SessionID:           "credential-session-01",
				SecretID:            "secret-01",
				DeliveryMode:        SandboxCredentialProxyDeliveryModeHTTPProxy,
				DestinationCategory: SandboxNetworkPolicyDestinationCategory(rawDestination),
			}),
			code:   SandboxCredentialProxyValidationUnsafeMetadata,
			field:  "destinationCategory",
			values: []string{rawDestination},
		},
		{
			name: "policy preset raw body",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:     "credential-plan-01",
				Source: SandboxCredentialProxySourceRun,
				PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
					ID:     "policy-snapshot-01",
					Preset: SandboxNetworkPolicyPreset(rawBody),
				},
			}),
			code:   SandboxCredentialProxyValidationUnsafeMetadata,
			field:  "policySnapshot.preset",
			values: []string{rawBody, "raw-secret"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertCredentialProxyValidationError(t, tt.result, tt.code, tt.field)
			data, err := json.Marshal(tt.result)
			if err != nil {
				t.Fatalf("json.Marshal(validation result) error: %v", err)
			}
			for _, validationErr := range tt.result.Errors {
				assertCredentialProxyNetworkPayloadExcludes(t, validationErr.Error(), tt.values...)
			}
			assertCredentialProxyNetworkPayloadExcludes(t, string(data), tt.values...)
		})
	}
}

func TestCredentialProxySanitizeDropsRawNetworkDestinationMetadata(t *testing.T) {
	rawDestination := "https://api.example.invalid:443/path?token=value"
	rawHeader := "Authorization: Bearer network-token"
	rawBody := `{"credentialValue":"raw-secret"}`

	plan := SanitizeSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
		ID:                    "credential-plan-01",
		Source:                SandboxCredentialProxySourceRun,
		NetworkProxySessionID: rawDestination,
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:        "policy-snapshot-01",
			Version:   "443",
			Preset:    SandboxNetworkPolicyPreset(rawBody),
			RuleSetID: rawHeader,
		},
	})
	if plan.NetworkProxySessionID != "" {
		t.Fatalf("plan network proxy session ID = %q, want unsafe raw destination dropped", plan.NetworkProxySessionID)
	}
	if plan.PolicySnapshot == nil {
		t.Fatalf("policy snapshot = nil, want safe required snapshot ID preserved")
	}
	if plan.PolicySnapshot.Version != "" || plan.PolicySnapshot.Preset != "" || plan.PolicySnapshot.RuleSetID != "" {
		t.Fatalf("policy snapshot = %#v, want raw optional network metadata dropped", plan.PolicySnapshot)
	}

	binding := SanitizeSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
		ID:                  "credential-binding-01",
		SessionID:           "credential-session-01",
		SecretID:            "secret-01",
		DeliveryMode:        SandboxCredentialProxyDeliveryModeHTTPProxy,
		RequestCategory:     SandboxCredentialProxyRequestCategory(rawHeader),
		DestinationCategory: SandboxNetworkPolicyDestinationCategory(rawDestination),
	})
	if binding == (SandboxCredentialProxyBindingMetadata{}) {
		t.Fatalf("binding sanitized to zero value, want safe required IDs preserved")
	}
	if binding.RequestCategory != "" || binding.DestinationCategory != "" {
		t.Fatalf("binding categories = %#v, want raw optional network metadata dropped", binding)
	}

	data, err := json.Marshal(struct {
		Plan    SandboxCredentialProxyPlanMetadata    `json:"plan"`
		Binding SandboxCredentialProxyBindingMetadata `json:"binding"`
	}{
		Plan:    plan,
		Binding: binding,
	})
	if err != nil {
		t.Fatalf("json.Marshal(sanitized credential proxy network metadata) error: %v", err)
	}
	assertCredentialProxyNetworkPayloadExcludes(t, string(data), rawDestination, rawHeader, rawBody, "network-token", "raw-secret")
}

func assertCredentialProxyNetworkValidationValid(t *testing.T, result SandboxCredentialProxyValidationResult) {
	t.Helper()

	if !result.Valid || len(result.Errors) != 0 {
		t.Fatalf("credential proxy validation = %#v, want valid", result)
	}
}

func assertCredentialProxyNetworkPayloadExcludes(t *testing.T, payload string, forbiddenValues ...string) {
	t.Helper()

	for _, forbidden := range forbiddenValues {
		if forbidden == "" {
			continue
		}
		if strings.Contains(payload, forbidden) {
			t.Fatalf("payload leaked forbidden value %q in %s", forbidden, payload)
		}
	}
}
