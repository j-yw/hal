package sandbox

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialProxyValidationAcceptsSafeMetadata(t *testing.T) {
	plan := ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
		ID:                    "credential-plan-01",
		Source:                SandboxCredentialProxySourceRun,
		SecretBrokerSessionID: "broker-session-01",
		NetworkProxySessionID: "network-proxy-session-01",
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:        "policy-snapshot-01",
			Version:   "v1",
			Preset:    SandboxNetworkPolicyPresetAllowListed,
			RuleSetID: "rules-01",
		},
		Mode:   SandboxCredentialProxyModeBrokeredNetworkReference,
		Status: SandboxCredentialProxyStatusPlanned,
	})
	assertCredentialProxyValidationValid(t, plan)

	session := ValidateSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
		ID:                    "credential-session-01",
		PlanID:                "credential-plan-01",
		Source:                SandboxCredentialProxySourceFactory,
		SecretBrokerSessionID: "broker-session-01",
		NetworkProxySessionID: "network-proxy-session-01",
		PolicySnapshot:        &SandboxNetworkPolicySnapshotIdentity{ID: "policy-snapshot-01"},
		Status:                SandboxCredentialProxyStatusActive,
		WarningCode:           SandboxCredentialProxyWarningBindingOmitted,
		ReasonCode:            SandboxCredentialProxyReasonRequested,
	})
	assertCredentialProxyValidationValid(t, session)

	binding := ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
		ID:                  "credential-binding-01",
		SessionID:           "credential-session-01",
		SecretID:            "secret-01",
		DeliveryMode:        SandboxCredentialProxyDeliveryModeHTTPProxy,
		RequestCategory:     SandboxCredentialProxyRequestNetworkAuth,
		DestinationCategory: SandboxNetworkPolicyDestinationPrivateNetwork,
		Outcome:             SandboxCredentialProxyBindingOutcomeBound,
		Status:              SandboxCredentialProxyStatusCompleted,
		ReasonCode:          SandboxCredentialProxyReasonRequested,
	})
	assertCredentialProxyValidationValid(t, binding)
}

func TestCredentialProxyValidationAcceptsSecretBrokerSecretIDs(t *testing.T) {
	got := ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
		ID:           "credential-binding-01",
		SessionID:    "credential-session-01",
		SecretID:     "env:GITHUB_TOKEN",
		DeliveryMode: SandboxCredentialProxyDeliveryModeHTTPProxy,
	})
	assertCredentialProxyValidationValid(t, got)
}

func TestCredentialProxyValidationRejectsMissingRequiredMetadata(t *testing.T) {
	tests := []struct {
		name   string
		result SandboxCredentialProxyValidationResult
		code   SandboxCredentialProxyValidationCode
		field  string
	}{
		{
			name: "plan id",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				Source: SandboxCredentialProxySourceRun,
			}),
			code:  SandboxCredentialProxyValidationMissingRequiredID,
			field: "id",
		},
		{
			name: "plan source",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID: "credential-plan-01",
			}),
			code:  SandboxCredentialProxyValidationMissingRequiredField,
			field: "source",
		},
		{
			name: "session plan id",
			result: ValidateSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
				ID:     "credential-session-01",
				Source: SandboxCredentialProxySourceAuto,
			}),
			code:  SandboxCredentialProxyValidationMissingRequiredID,
			field: "planId",
		},
		{
			name: "policy snapshot id",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:             "credential-plan-01",
				Source:         SandboxCredentialProxySourceRun,
				PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{Version: "v1"},
			}),
			code:  SandboxCredentialProxyValidationMissingRequiredID,
			field: "policySnapshot.id",
		},
		{
			name: "binding parent reference",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:           "credential-binding-01",
				SecretID:     "secret-01",
				DeliveryMode: SandboxCredentialProxyDeliveryModeEnv,
			}),
			code:  SandboxCredentialProxyValidationMissingRequiredField,
			field: "planId",
		},
		{
			name: "binding secret id",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:           "credential-binding-01",
				PlanID:       "credential-plan-01",
				DeliveryMode: SandboxCredentialProxyDeliveryModeEnv,
			}),
			code:  SandboxCredentialProxyValidationMissingRequiredID,
			field: "secretId",
		},
		{
			name: "binding delivery mode",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:       "credential-binding-01",
				PlanID:   "credential-plan-01",
				SecretID: "secret-01",
			}),
			code:  SandboxCredentialProxyValidationMissingRequiredField,
			field: "deliveryMode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertCredentialProxyValidationError(t, tt.result, tt.code, tt.field)
			assertCredentialProxyValidationNoUnsafeLeak(t, tt.result)
		})
	}
}

func TestCredentialProxyValidationRejectsUnsafeIdentifiers(t *testing.T) {
	unsafeValues := []string{
		"https://user:pass@example.invalid/path?token=value",
		"api.example.invalid",
		"443",
		"/Users/alice/.config/key.json",
		"/tmp/credential-proxy.sock",
		"Authorization: Bearer abc",
		"TOKEN=value",
		"credentialValue=value",
		"secretValue=value",
		"credential-plan-01\nnext",
		"credential-plan-01\x1f",
	}

	for _, value := range unsafeValues {
		t.Run(value, func(t *testing.T) {
			got := ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:     value,
				Source: SandboxCredentialProxySourceRun,
			})
			assertCredentialProxyValidationError(t, got, SandboxCredentialProxyValidationUnsafeID, "id")
			assertCredentialProxyValidationNoUnsafeLeak(t, got)
		})
	}
}

func TestCredentialProxyValidationRejectsUnsafeReferences(t *testing.T) {
	tests := []struct {
		name   string
		result SandboxCredentialProxyValidationResult
		field  string
	}{
		{
			name: "secret broker session",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:                    "credential-plan-01",
				Source:                SandboxCredentialProxySourceRun,
				SecretBrokerSessionID: "broker.example.invalid",
			}),
			field: "secretBrokerSessionId",
		},
		{
			name: "network proxy session",
			result: ValidateSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
				ID:                    "credential-session-01",
				PlanID:                "credential-plan-01",
				Source:                SandboxCredentialProxySourceAuto,
				NetworkProxySessionID: "https://proxy.example.invalid/session",
			}),
			field: "networkProxySessionId",
		},
		{
			name: "policy snapshot version",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:     "credential-plan-01",
				Source: SandboxCredentialProxySourceRun,
				PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
					ID:      "policy-snapshot-01",
					Version: "api.example.invalid:443",
				},
			}),
			field: "policySnapshot.version",
		},
		{
			name: "policy snapshot rule set",
			result: ValidateSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
				ID:     "credential-session-01",
				PlanID: "credential-plan-01",
				Source: SandboxCredentialProxySourceFactory,
				PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
					ID:        "policy-snapshot-01",
					RuleSetID: "POLICY_PATH=/Users/alice/rules.json",
				},
			}),
			field: "policySnapshot.ruleSetId",
		},
		{
			name: "binding plan id",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:           "credential-binding-01",
				PlanID:       "/Users/alice/plan.json",
				SecretID:     "secret-01",
				DeliveryMode: SandboxCredentialProxyDeliveryModeEnv,
			}),
			field: "planId",
		},
		{
			name: "binding session id",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:           "credential-binding-01",
				SessionID:    "session.sock",
				SecretID:     "secret-01",
				DeliveryMode: SandboxCredentialProxyDeliveryModeEnv,
			}),
			field: "sessionId",
		},
		{
			name: "binding secret id",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:           "credential-binding-01",
				PlanID:       "credential-plan-01",
				SecretID:     "secretValue=raw-secret",
				DeliveryMode: SandboxCredentialProxyDeliveryModeEnv,
			}),
			field: "secretId",
		},
		{
			name: "binding raw-looking broker secret id",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:           "credential-binding-01",
				PlanID:       "credential-plan-01",
				SecretID:     "env:ghp_raw_secret_value_123",
				DeliveryMode: SandboxCredentialProxyDeliveryModeEnv,
			}),
			field: "secretId",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertCredentialProxyValidationError(t, tt.result, SandboxCredentialProxyValidationUnsafeReference, tt.field)
			assertCredentialProxyValidationNoUnsafeLeak(t, tt.result)
		})
	}
}

func TestCredentialProxyValidationRejectsInvalidEnums(t *testing.T) {
	tests := []struct {
		name   string
		result SandboxCredentialProxyValidationResult
		field  string
	}{
		{
			name: "plan source",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:     "credential-plan-01",
				Source: SandboxCredentialProxySource("sidecar"),
			}),
			field: "source",
		},
		{
			name: "plan mode",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:     "credential-plan-01",
				Source: SandboxCredentialProxySourceRun,
				Mode:   SandboxCredentialProxyMode("sidecar"),
			}),
			field: "mode",
		},
		{
			name: "policy preset",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:     "credential-plan-01",
				Source: SandboxCredentialProxySourceRun,
				PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
					ID:     "policy-snapshot-01",
					Preset: SandboxNetworkPolicyPreset("permissive"),
				},
			}),
			field: "policySnapshot.preset",
		},
		{
			name: "session warning",
			result: ValidateSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
				ID:          "credential-session-01",
				PlanID:      "credential-plan-01",
				Source:      SandboxCredentialProxySourceWorker,
				WarningCode: SandboxCredentialProxyWarningCode("raw_destination_seen"),
			}),
			field: "warningCode",
		},
		{
			name: "binding delivery mode",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:           "credential-binding-01",
				PlanID:       "credential-plan-01",
				SecretID:     "secret-01",
				DeliveryMode: SandboxCredentialProxyDeliveryMode("tmp_file"),
			}),
			field: "deliveryMode",
		},
		{
			name: "binding destination category",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:                  "credential-binding-01",
				SessionID:           "credential-session-01",
				SecretID:            "secret-01",
				DeliveryMode:        SandboxCredentialProxyDeliveryModeHTTPProxy,
				DestinationCategory: SandboxNetworkPolicyDestinationCategory("external_host"),
			}),
			field: "destinationCategory",
		},
		{
			name: "binding outcome",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:           "credential-binding-01",
				PlanID:       "credential-plan-01",
				SecretID:     "secret-01",
				DeliveryMode: SandboxCredentialProxyDeliveryModeEnv,
				Outcome:      SandboxCredentialProxyBindingOutcome("delivered"),
			}),
			field: "outcome",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertCredentialProxyValidationError(t, tt.result, SandboxCredentialProxyValidationInvalidEnum, tt.field)
			assertCredentialProxyValidationNoUnsafeLeak(t, tt.result)
		})
	}
}

func TestCredentialProxyValidationRejectsUnsafeEnumLikeMetadata(t *testing.T) {
	tests := []struct {
		name   string
		result SandboxCredentialProxyValidationResult
		field  string
	}{
		{
			name: "source url",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:     "credential-plan-01",
				Source: SandboxCredentialProxySource("https://example.invalid/source"),
			}),
			field: "source",
		},
		{
			name: "request category control",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:              "credential-binding-01",
				PlanID:          "credential-plan-01",
				SecretID:        "secret-01",
				DeliveryMode:    SandboxCredentialProxyDeliveryModeEnv,
				RequestCategory: SandboxCredentialProxyRequestCategory("network_auth\nheader"),
			}),
			field: "requestCategory",
		},
		{
			name: "destination category raw url",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:                  "credential-binding-01",
				SessionID:           "credential-session-01",
				SecretID:            "secret-01",
				DeliveryMode:        SandboxCredentialProxyDeliveryModeHTTPProxy,
				DestinationCategory: SandboxNetworkPolicyDestinationCategory("https://api.example.invalid"),
			}),
			field: "destinationCategory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertCredentialProxyValidationError(t, tt.result, SandboxCredentialProxyValidationUnsafeMetadata, tt.field)
			assertCredentialProxyValidationNoUnsafeLeak(t, tt.result)
		})
	}
}

func TestCredentialProxyValidationErrorShapeIncludesOnlySafeFields(t *testing.T) {
	recordIndex := 2
	bindingIndex := 4
	result := SandboxCredentialProxyValidationResult{
		Valid: false,
		Errors: []SandboxCredentialProxyValidationError{
			{
				Code:        SandboxCredentialProxyValidationUnsafeReference,
				Field:       "policySnapshot.ruleSetId",
				RecordIndex: &recordIndex,
				Message:     "policy snapshot rule set id must be a safe reference",
			},
			{
				Code:         SandboxCredentialProxyValidationInvalidEnum,
				Field:        "deliveryMode",
				BindingIndex: &bindingIndex,
				Message:      "credential proxy delivery mode is unsupported",
			},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(validation result) error: %v", err)
	}

	var decoded struct {
		Errors []map[string]any `json:"errors"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(validation result) error: %v", err)
	}
	if len(decoded.Errors) != 2 {
		t.Fatalf("errors length = %d, want 2 in %s", len(decoded.Errors), data)
	}
	allowedKeys := map[string]bool{
		"code":         true,
		"field":        true,
		"recordIndex":  true,
		"bindingIndex": true,
		"message":      true,
	}
	for i, errObject := range decoded.Errors {
		for key := range errObject {
			if !allowedKeys[key] {
				t.Fatalf("error %d exposed unexpected key %q in %s", i, key, data)
			}
		}
	}
	if got := decoded.Errors[0]["recordIndex"]; got != float64(recordIndex) {
		t.Fatalf("recordIndex = %#v, want %d in %s", got, recordIndex, data)
	}
	if _, ok := decoded.Errors[0]["bindingIndex"]; ok {
		t.Fatalf("first error unexpectedly included bindingIndex in %s", data)
	}
	if got := decoded.Errors[1]["bindingIndex"]; got != float64(bindingIndex) {
		t.Fatalf("bindingIndex = %#v, want %d in %s", got, bindingIndex, data)
	}
	if _, ok := decoded.Errors[1]["recordIndex"]; ok {
		t.Fatalf("second error unexpectedly included recordIndex in %s", data)
	}

	for _, validationErr := range result.Errors {
		message := validationErr.Error()
		assertCredentialProxyValidationExcludesRejectedInputs(t, message,
			"policySnapshot.ruleSetId=/Users/alice/rules.json",
			"https://api.example.invalid",
			"Authorization: Bearer raw-token",
		)
	}
}

func TestCredentialProxyValidationErrorsDoNotExposeRejectedInputs(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		result SandboxCredentialProxyValidationResult
		code   SandboxCredentialProxyValidationCode
		field  string
	}{
		{
			name:  "url with token",
			value: "https://user:pass@example.invalid/path?token=value",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:     "https://user:pass@example.invalid/path?token=value",
				Source: SandboxCredentialProxySourceRun,
			}),
			code:  SandboxCredentialProxyValidationUnsafeID,
			field: "id",
		},
		{
			name:  "raw hostname",
			value: "api.example.invalid",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:                    "credential-plan-01",
				Source:                SandboxCredentialProxySourceRun,
				SecretBrokerSessionID: "api.example.invalid",
			}),
			code:  SandboxCredentialProxyValidationUnsafeReference,
			field: "secretBrokerSessionId",
		},
		{
			name:  "local path",
			value: "/Users/alice/.config/key.json",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:           "credential-binding-01",
				PlanID:       "/Users/alice/.config/key.json",
				SecretID:     "secret-01",
				DeliveryMode: SandboxCredentialProxyDeliveryModeEnv,
			}),
			code:  SandboxCredentialProxyValidationUnsafeReference,
			field: "planId",
		},
		{
			name:  "socket path",
			value: "/tmp/credential-proxy.sock",
			result: ValidateSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
				ID:                    "credential-session-01",
				PlanID:                "credential-plan-01",
				Source:                SandboxCredentialProxySourceAuto,
				NetworkProxySessionID: "/tmp/credential-proxy.sock",
			}),
			code:  SandboxCredentialProxyValidationUnsafeReference,
			field: "networkProxySessionId",
		},
		{
			name:  "authorization token",
			value: "Authorization: Bearer raw-token",
			result: ValidateSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
				ID:     "credential-session-01",
				PlanID: "Authorization: Bearer raw-token",
				Source: SandboxCredentialProxySourceFactory,
			}),
			code:  SandboxCredentialProxyValidationUnsafeReference,
			field: "planId",
		},
		{
			name:  "credential value marker",
			value: "credentialValue=raw-credential",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:           "credential-binding-01",
				PlanID:       "credential-plan-01",
				SecretID:     "credentialValue=raw-credential",
				DeliveryMode: SandboxCredentialProxyDeliveryModeEnv,
			}),
			code:  SandboxCredentialProxyValidationUnsafeReference,
			field: "secretId",
		},
		{
			name:  "secret value marker",
			value: "secretValue=raw-secret",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:           "credential-binding-01",
				PlanID:       "credential-plan-01",
				SecretID:     "secretValue=raw-secret",
				DeliveryMode: SandboxCredentialProxyDeliveryModeEnv,
			}),
			code:  SandboxCredentialProxyValidationUnsafeReference,
			field: "secretId",
		},
		{
			name:  "control character",
			value: "credential-plan-01\x1f",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:     "credential-plan-01\x1f",
				Source: SandboxCredentialProxySourceRun,
			}),
			code:  SandboxCredentialProxyValidationUnsafeID,
			field: "id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertCredentialProxyValidationError(t, tt.result, tt.code, tt.field)

			data, err := json.Marshal(tt.result)
			if err != nil {
				t.Fatalf("json.Marshal(validation result) error: %v", err)
			}
			assertCredentialProxyValidationExcludesRejectedInputs(t, string(data), tt.value)
			for _, validationErr := range tt.result.Errors {
				assertCredentialProxyValidationExcludesRejectedInputs(t, string(validationErr.Code), tt.value)
				assertCredentialProxyValidationExcludesRejectedInputs(t, validationErr.Field, tt.value)
				assertCredentialProxyValidationExcludesRejectedInputs(t, validationErr.Message, tt.value)
				assertCredentialProxyValidationExcludesRejectedInputs(t, validationErr.Error(), tt.value)
			}
		})
	}
}

func TestCredentialProxyValidationErrorCodesAreDeterministic(t *testing.T) {
	tests := []struct {
		name   string
		result SandboxCredentialProxyValidationResult
		code   SandboxCredentialProxyValidationCode
		field  string
	}{
		{
			name: "missing required id",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				Source: SandboxCredentialProxySourceRun,
			}),
			code:  SandboxCredentialProxyValidationMissingRequiredID,
			field: "id",
		},
		{
			name: "unsafe id",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:     "https://example.invalid/plan",
				Source: SandboxCredentialProxySourceRun,
			}),
			code:  SandboxCredentialProxyValidationUnsafeID,
			field: "id",
		},
		{
			name: "unsafe reference",
			result: ValidateSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
				ID:     "credential-session-01",
				PlanID: "https://example.invalid/plan",
				Source: SandboxCredentialProxySourceFactory,
			}),
			code:  SandboxCredentialProxyValidationUnsafeReference,
			field: "planId",
		},
		{
			name: "invalid enum",
			result: ValidateSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
				ID:     "credential-plan-01",
				Source: SandboxCredentialProxySource("sidecar"),
			}),
			code:  SandboxCredentialProxyValidationInvalidEnum,
			field: "source",
		},
		{
			name: "unsafe optional metadata",
			result: ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:              "credential-binding-01",
				PlanID:          "credential-plan-01",
				SecretID:        "secret-01",
				DeliveryMode:    SandboxCredentialProxyDeliveryModeEnv,
				RequestCategory: SandboxCredentialProxyRequestCategory("network_auth\nheader"),
			}),
			code:  SandboxCredentialProxyValidationUnsafeMetadata,
			field: "requestCategory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertCredentialProxyValidationError(t, tt.result, tt.code, tt.field)
			assertCredentialProxyValidationNoUnsafeLeak(t, tt.result)
		})
	}
}

func TestCredentialProxyValidationDoesNotInferNetworkEnforcement(t *testing.T) {
	got := ValidateSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
		ID:                  "credential-binding-01",
		PlanID:              "credential-plan-01",
		SecretID:            "secret-01",
		DeliveryMode:        SandboxCredentialProxyDeliveryModeHTTPProxy,
		DestinationCategory: SandboxNetworkPolicyDestinationPublicInternet,
	})
	assertCredentialProxyValidationValid(t, got)

	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal(validation result) error: %v", err)
	}
	for _, forbidden := range []string{"enforcement", "enforced", "capability", "destinationValue"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("validation result %s must not infer network metadata %q", data, forbidden)
		}
	}
}

func assertCredentialProxyValidationValid(t *testing.T, result SandboxCredentialProxyValidationResult) {
	t.Helper()

	if !result.Valid {
		t.Fatalf("credential proxy validation valid = false, errors: %#v", result.Errors)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("credential proxy validation errors = %#v, want none", result.Errors)
	}
}

func assertCredentialProxyValidationError(t *testing.T, result SandboxCredentialProxyValidationResult, code SandboxCredentialProxyValidationCode, field string) {
	t.Helper()

	if result.Valid {
		t.Fatalf("credential proxy validation valid = true, want false")
	}
	for _, err := range result.Errors {
		if err.Code == code && err.Field == field {
			return
		}
	}
	t.Fatalf("credential proxy validation errors = %#v, want code %q field %q", result.Errors, code, field)
}

func assertCredentialProxyValidationNoUnsafeLeak(t *testing.T, result SandboxCredentialProxyValidationResult) {
	t.Helper()

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(validation result) error: %v", err)
	}
	payload := string(data)
	for _, forbidden := range []string{
		"https://",
		"example.invalid",
		"/Users/alice",
		"/tmp/",
		"Authorization",
		"Bearer",
		"TOKEN",
		"credentialValue",
		"secretValue",
		"raw-secret",
		"POLICY_PATH",
		"\n",
		"\u001f",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("validation result leaked unsafe value %q in %s", forbidden, payload)
		}
	}
}

func assertCredentialProxyValidationExcludesRejectedInputs(t *testing.T, payload string, rejectedValues ...string) {
	t.Helper()

	for _, rejected := range rejectedValues {
		if rejected == "" {
			continue
		}
		for _, forbidden := range []string{rejected, credentialProxyValidationJSONEscapedStringFragment(t, rejected)} {
			if forbidden == "" {
				continue
			}
			if strings.Contains(payload, forbidden) {
				t.Fatalf("validation payload leaked rejected value %q in %s", forbidden, payload)
			}
		}
	}
}

func credentialProxyValidationJSONEscapedStringFragment(t *testing.T, value string) string {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(rejected value) error: %v", err)
	}
	return strings.TrimSuffix(strings.TrimPrefix(string(data), `"`), `"`)
}
