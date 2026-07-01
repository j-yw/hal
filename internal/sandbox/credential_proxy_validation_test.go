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
