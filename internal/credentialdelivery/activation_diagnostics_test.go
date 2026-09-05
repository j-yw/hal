package credentialdelivery

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestCredentialActivationDiagnosticsCoverDisabledMissingProofUnsupportedFailureAndOptIn(t *testing.T) {
	tests := []struct {
		name        string
		plan        Plan
		activation  ActivationResult
		wantStatus  Status
		wantReason  ReasonCode
		wantMode    Mode
		wantWarning WarningCode
	}{
		{
			name: "activation disabled",
			activation: ActivationResult{
				ID:             "activation-disabled",
				PlanID:         "delivery-plan-disabled",
				RequestedModes: []Mode{ModeEnv},
				Bindings: []BindingActivationResult{{
					BindingID:    "binding-env",
					DeliveryMode: ModeEnv,
					Status:       StatusDisabled,
					ReasonCode:   ReasonDisabled,
				}},
				Status:     StatusDisabled,
				ReasonCode: ReasonDisabled,
				Warnings: []Warning{{
					Code:       WarningActivationSkipped,
					ReasonCode: ReasonDisabled,
					Mode:       ModeEnv,
				}},
			},
			wantStatus:  StatusDisabled,
			wantReason:  ReasonDisabled,
			wantMode:    ModeEnv,
			wantWarning: WarningActivationSkipped,
		},
		{
			name: "missing proof metadata",
			activation: func() ActivationResult {
				binding := planBindingFixture(ModeHTTPProxy)
				return ActivateDelivery(ActivationRequest{
					Plan: Plan{
						ID:             "delivery-plan-missing-proof",
						RequestedModes: []Mode{ModeHTTPProxy},
						ActiveModes:    []Mode{ModeHTTPProxy},
						Status:         StatusPlanned,
					},
					Bindings: []Binding{binding},
				}, &fakeActivationAdapter{})
			}(),
			wantStatus:  StatusSkipped,
			wantReason:  ReasonMissingActivationProof,
			wantMode:    ModeHTTPProxy,
			wantWarning: WarningActivationSkipped,
		},
		{
			name: "unsupported delivery mode",
			activation: ActivateDelivery(ActivationRequest{
				Plan: Plan{
					ID:             "delivery-plan-unsupported",
					RequestedModes: []Mode{Mode("custom_mode")},
					Status:         StatusPlanned,
				},
				Bindings: []Binding{{
					ID:           "binding-unsupported",
					SecretRef:    "env:GITHUB_TOKEN",
					DeliveryMode: Mode("custom_mode"),
				}},
			}, NewFakeActivationAdapter()),
			wantStatus:  StatusFailed,
			wantReason:  ReasonUnsupportedMode,
			wantWarning: WarningUnsupportedMode,
		},
		{
			name: "activation failure",
			activation: func() ActivationResult {
				binding := planBindingFixture(ModeEnv)
				return ActivateDelivery(ActivationRequest{
					Plan: Plan{
						ID:             "delivery-plan-failure",
						RequestedModes: []Mode{ModeEnv},
						Status:         StatusPlanned,
					},
					Bindings: []Binding{binding},
				}, &fakeActivationAdapter{err: errors.New("provider returned ghp_phase51_secret from https://provider.example.invalid")})
			}(),
			wantStatus: StatusFailed,
			wantReason: ReasonActivationUnavailable,
			wantMode:   ModeEnv,
		},
		{
			name: "explicit opt-in required",
			activation: ActivateDelivery(ActivationRequest{
				Plan: Plan{
					ID:             "delivery-plan-opt-in",
					RequestedModes: []Mode{ModeEnv},
					Status:         StatusPlanned,
				},
				Bindings: []Binding{planBindingFixture(ModeEnv)},
			}, nil),
			wantStatus:  StatusSkipped,
			wantReason:  ReasonActivationUnavailable,
			wantMode:    ModeEnv,
			wantWarning: WarningAdapterUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildCredentialActivationDiagnostics(tt.plan, tt.activation)

			if got.Status != tt.wantStatus {
				t.Fatalf("diagnostic status = %q, want %q in %#v", got.Status, tt.wantStatus, got)
			}
			if got.ReasonCode != tt.wantReason {
				t.Fatalf("diagnostic reason = %q, want %q in %#v", got.ReasonCode, tt.wantReason, got)
			}
			if tt.wantMode != "" {
				requireCredentialActivationDiagnosticItem(t, got, tt.wantMode, tt.wantStatus, tt.wantReason)
			}
			if tt.wantWarning != "" {
				requireCredentialActivationDiagnosticWarning(t, got, tt.wantWarning, tt.wantReason)
			}
			assertActivationNoLeak(t, got, "ghp_phase51_secret", "provider.example.invalid")
		})
	}
}

func TestCredentialActivationDiagnosticsContainOnlySafeSummaryFields(t *testing.T) {
	summary := CredentialActivationDiagnosticSummary{
		RequestedModes: []Mode{ModeEnv, ModeHTTPProxy},
		ActiveModes:    []Mode{ModeEnv},
		Status:         StatusActive,
		ReasonCode:     ReasonRequested,
		ProofIDs:       []string{"proof-env-01"},
		Warnings: []Warning{{
			Code:       WarningActivationSkipped,
			ReasonCode: ReasonMissingActivationProof,
			Mode:       ModeHTTPProxy,
		}},
		Items: []CredentialActivationDiagnosticItem{{
			DeliveryMode: ModeEnv,
			Status:       StatusActive,
			ReasonCode:   ReasonRequested,
			ProofID:      "proof-env-01",
		}},
	}

	got := mustMarshalObject(t, summary)
	assertObjectKeys(t, got, []string{
		"requestedModes",
		"activeModes",
		"status",
		"reasonCode",
		"proofIds",
		"warnings",
		"items",
	}, activationSchemaForbiddenFieldNames())
	item := got["items"].([]any)[0].(map[string]any)
	assertObjectKeys(t, item, []string{
		"deliveryMode",
		"status",
		"reasonCode",
		"proofId",
	}, activationSchemaForbiddenFieldNames())
}

func TestCredentialActivationDiagnosticsAndErrorsAreRedactionSafe(t *testing.T) {
	rawValues := []string{
		"ghp_phase51_secret",
		"sk-phase51-secret",
		"PHASE51_SECRET_VALUE",
		"https://provider.example.invalid/credential?token=ghp_phase51_secret",
		"provider.example.invalid",
		"/tmp/credential-delivery.sock",
		"Authorization: Bearer sk-phase51-secret",
	}
	activation := ActivationResult{
		ID:             "activation-redacted",
		PlanID:         "delivery-plan-redacted",
		RequestedModes: []Mode{ModeEnv, Mode(rawValues[0])},
		ActiveModes:    []Mode{ModeEnv, Mode(rawValues[1])},
		Bindings: []BindingActivationResult{
			{
				BindingID:    "binding-env",
				DeliveryMode: ModeEnv,
				Status:       StatusFailed,
				ReasonCode:   ReasonActivationUnavailable,
				ProofRef:     rawValues[5],
			},
			{
				BindingID:    rawValues[0],
				DeliveryMode: ModeEnv,
				Status:       StatusActive,
			},
		},
		ProofRefs: []ActivationProofReference{
			{
				ProofID:      "proof-env-01",
				BindingID:    "binding-env",
				DeliveryMode: ModeEnv,
			},
			{
				ProofID:      rawValues[1],
				BindingID:    "binding-env",
				DeliveryMode: ModeEnv,
			},
		},
		Status:     StatusFailed,
		ReasonCode: ReasonActivationUnavailable,
		Warnings: []Warning{
			{
				Code:       WarningAdapterUnavailable,
				ReasonCode: ReasonActivationUnavailable,
				BindingID:  rawValues[1],
				Mode:       Mode(rawValues[2]),
			},
			{Code: WarningCode(rawValues[3])},
		},
	}

	got := BuildCredentialActivationDiagnostics(Plan{}, activation)
	if len(got.ProofIDs) != 1 || got.ProofIDs[0] != "proof-env-01" {
		t.Fatalf("diagnostic proof IDs = %#v, want only safe proof ID", got.ProofIDs)
	}
	assertCredentialActivationDiagnosticsNoLeak(t, got, rawValues...)

	err := SanitizedError{
		Code:       ErrorActivationFailed,
		Field:      rawValues[3],
		BindingID:  rawValues[0],
		Mode:       Mode(rawValues[1]),
		ReasonCode: ReasonCode(rawValues[2]),
	}
	assertCredentialActivationDiagnosticsNoLeak(t, err.Error(), rawValues...)
}

func TestCredentialActivationDiagnosticsLiveProviderBehaviorRequiresExplicitOptIn(t *testing.T) {
	sourceBytes, err := os.ReadFile("credential_delivery_live_test.go")
	if err != nil {
		t.Fatalf("ReadFile(credential_delivery_live_test.go) error: %v", err)
	}
	source := string(sourceBytes)
	for _, marker := range []string{
		"//go:build credential_delivery_live",
		"HAL_CREDENTIAL_DELIVERY_LIVE",
		"HAL_CREDENTIAL_DELIVERY_LIVE_HTTP_PROXY",
		"HAL_CREDENTIAL_DELIVERY_LIVE_FILE_TMPFS",
		"HAL_CREDENTIAL_DELIVERY_LIVE_SSH_AGENT",
		"HAL_CREDENTIAL_DELIVERY_LIVE_ENV",
		"t.Skip",
		"credential delivery live harness is an opt-in placeholder",
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("credential delivery live harness missing explicit opt-in marker %q", marker)
		}
	}
	for _, forbidden := range []string{
		"net.Listen(",
		"http.ListenAndServe(",
		"exec.Command(",
		"os.WriteFile(",
		"os.Setenv(",
		"agent.NewClient(",
		"MountTmpfs(",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("credential delivery live harness contains forbidden live behavior marker %q", forbidden)
		}
	}
}

func requireCredentialActivationDiagnosticItem(t *testing.T, summary CredentialActivationDiagnosticSummary, mode Mode, status Status, reason ReasonCode) {
	t.Helper()

	for _, item := range summary.Items {
		if item.DeliveryMode == mode && item.Status == status && item.ReasonCode == reason {
			return
		}
	}
	t.Fatalf("diagnostic items = %#v, want mode %q status %q reason %q", summary.Items, mode, status, reason)
}

func requireCredentialActivationDiagnosticWarning(t *testing.T, summary CredentialActivationDiagnosticSummary, code WarningCode, reason ReasonCode) {
	t.Helper()

	for _, warning := range summary.Warnings {
		if warning.Code == code && warning.ReasonCode == reason {
			return
		}
	}
	t.Fatalf("diagnostic warnings = %#v, want code %q reason %q", summary.Warnings, code, reason)
}

func assertCredentialActivationDiagnosticsNoLeak(t *testing.T, value any, rawValues ...string) {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%T) error: %v", value, err)
	}
	payloads := []string{string(data)}
	if text, ok := value.(string); ok {
		payloads = append(payloads, text)
	}
	for _, payload := range payloads {
		for _, raw := range rawValues {
			if raw != "" && strings.Contains(payload, raw) {
				t.Fatalf("credential activation diagnostics leaked raw value %q in %s", raw, payload)
			}
		}
	}
}
