package credentialdelivery

import (
	"testing"
)

func TestCredentialActivationErrorsAreRedactionSafe(t *testing.T) {
	rawValues := []string{
		"ghp_phase51_secret",
		"sk-phase51-secret",
		"PHASE51_SECRET_VALUE",
		"https://provider.example.invalid/credential?token=ghp_phase51_secret",
		"provider.example.invalid",
		"/tmp/credential-delivery.sock",
		"Authorization: Bearer sk-phase51-secret",
	}
	err := SanitizedError{
		Code:       ErrorActivationFailed,
		Field:      rawValues[3],
		BindingID:  rawValues[0],
		Mode:       Mode(rawValues[1]),
		ReasonCode: ReasonCode(rawValues[2]),
	}
	assertActivationNoLeak(t, err.Error(), rawValues...)
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
