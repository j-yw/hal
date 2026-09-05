package cmd

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/credentialdelivery"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestCredentialDeliveryRedactionAcrossDurableSurfaces(t *testing.T) {
	rawValues := credentialDeliveryRawRedactionValues()
	sandboxStatus := sandbox.SanitizeSandboxCredentialDeliveryStatusMetadata(sandbox.SandboxCredentialDeliveryStatusMetadata{
		ID:             "credential-status-01",
		RequestID:      rawValues[0],
		PlanID:         "credential-plan-01",
		ActivationID:   rawValues[1],
		RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy, rawValues[2]},
		ActiveModes:    []string{sandbox.SandboxSecretModeHTTPProxy, rawValues[3]},
		Status:         "active",
		ReasonCode:     rawValues[4],
		WarningCount:   1,
		ErrorCount:     0,
	})
	if sandboxStatus.ID == "" {
		t.Fatal("sanitized sandbox credential delivery status is empty")
	}
	runtimeStatus := &sandboxruntime.RuntimeCredentialDeliveryMetadata{
		ID:             sandboxStatus.ID,
		PlanID:         sandboxStatus.PlanID,
		RequestedModes: sandboxStatus.RequestedModes,
		ActiveModes:    sandboxStatus.ActiveModes,
		Status:         sandboxStatus.Status,
		WarningCount:   sandboxStatus.WarningCount,
	}
	redactor := factory.NewRunSecretRedactor([]factory.ResolvedRunSecret{
		{Name: "RAW_ONE", Source: factory.RunSecretSourceEnv, Value: rawValues[0]},
		{Name: "RAW_TWO", Source: factory.RunSecretSourceEnv, Value: rawValues[1]},
		{Name: "RAW_THREE", Source: factory.RunSecretSourceEnv, Value: rawValues[2]},
		{Name: "RAW_FOUR", Source: factory.RunSecretSourceEnv, Value: rawValues[3]},
		{Name: "RAW_FIVE", Source: factory.RunSecretSourceEnv, Value: rawValues[4]},
	})

	surfaces := map[string]any{
		"sandbox execution manifest": sandboxexecution.Manifest{
			ID:                 "exec-credential-redaction",
			Purpose:            sandboxexecution.PurposeRun,
			Status:             sandboxexecution.StatusSucceeded,
			StartedAt:          time.Date(2026, 7, 3, 1, 0, 0, 0, time.UTC),
			CredentialDelivery: &sandboxStatus,
		},
		"factory run record": redactor.RedactRunRecord(factory.RunRecord{
			RunID:  "run-credential-redaction",
			Status: factory.RunStatusSucceeded,
			Sandbox: &factory.SandboxMetadata{
				Name:               "sandbox-" + rawValues[0],
				Provider:           "worker",
				Status:             "running",
				Handoff:            rawValues[1],
				CredentialDelivery: &sandboxStatus,
			},
		}),
		"factory timeline event": redactor.RedactEventRecord(factory.EventRecord{
			RunID:     "run-credential-redaction",
			Sequence:  1,
			EventType: factory.EventTypePolicyDecision,
			Message:   "credential delivery " + rawValues[2],
			Summary:   "summary " + rawValues[3],
			Metadata: map[string]any{
				"credentialDelivery": sandboxStatus,
				"rawHeader":          rawValues[4],
			},
		}),
		"factory log chunk": redactor.RedactLogChunk(factory.LogChunk{
			RunID:    "run-credential-redaction",
			Sequence: 1,
			Stream:   factory.LogStreamStdout,
			Source:   factory.LogSourceRemoteSandbox,
			Text:     "log " + rawValues[0],
			Summary:  "summary " + rawValues[1],
		}),
		"runtime metadata": sandboxruntime.RuntimeMetadata{
			Backend:            "microvm",
			CredentialDelivery: runtimeStatus,
		},
		"worker security controls": sandboxworker.SecurityControls{
			CredentialModes:    []string{sandboxworker.CredentialModeLegacyAuthSync},
			CredentialDelivery: runtimeStatus,
		},
	}
	for label, value := range surfaces {
		assertCredentialDeliveryRawValuesAbsent(t, label, value, rawValues)
	}
}

func TestCredentialDeliveryActivationRedactionForSuccessAndFailure(t *testing.T) {
	rawValues := credentialDeliveryRawRedactionValues()
	plan := credentialdelivery.Plan{
		ID:                    "credential-plan-01",
		RequestID:             "credential-request-01",
		NetworkProxySessionID: "network-proxy-session-01",
		RequestedModes:        []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy},
		ActiveModes:           []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy},
		Status:                credentialdelivery.StatusPlanned,
	}
	bindings := []credentialdelivery.Binding{{
		ID:                    "credential-binding-01",
		SecretRef:             "env:GITHUB_TOKEN",
		NetworkProxySessionID: "network-proxy-session-01",
		ServiceID:             "service-openai",
		DeliveryMode:          credentialdelivery.ModeHTTPProxy,
	}}
	success := credentialdelivery.ActivateDelivery(credentialdelivery.ActivationRequest{
		ActivationID: "credential-activation-01",
		Plan:         plan,
		Bindings:     bindings,
	}, credentialDeliveryFakeActivationAdapter{})
	failure := credentialdelivery.ActivateDelivery(credentialdelivery.ActivationRequest{
		ActivationID: rawValues[0],
		Plan: credentialdelivery.Plan{
			ID:             "credential-plan-02",
			RequestedModes: []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy},
			Status:         credentialdelivery.StatusPlanned,
		},
		Bindings: []credentialdelivery.Binding{{
			ID:           rawValues[1],
			SecretRef:    rawValues[2],
			DeliveryMode: credentialdelivery.ModeHTTPProxy,
		}},
	}, credentialDeliveryFailingActivationAdapter{})

	assertCredentialDeliveryRawValuesAbsent(t, "successful fake activation", success, rawValues)
	assertCredentialDeliveryRawValuesAbsent(t, "failed fake activation", failure, rawValues)
}

type credentialDeliveryFakeActivationAdapter struct{}

func (credentialDeliveryFakeActivationAdapter) ActivateCredentialDelivery(req credentialdelivery.SanitizedActivationRequest) (credentialdelivery.ActivationResult, error) {
	plan := req.Plan()
	bindings := req.Bindings()
	result := credentialdelivery.ActivationResult{
		ID:             "credential-activation-01",
		PlanID:         plan.ID,
		RequestedModes: plan.RequestedModes,
		ActiveModes:    []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy},
		Status:         credentialdelivery.StatusActive,
	}
	for _, binding := range bindings {
		result.Bindings = append(result.Bindings, credentialdelivery.BindingActivationResult{
			BindingID:    binding.ID,
			DeliveryMode: binding.DeliveryMode,
			Status:       credentialdelivery.StatusActive,
		})
	}
	return result, nil
}

type credentialDeliveryFailingActivationAdapter struct{}

func (credentialDeliveryFailingActivationAdapter) ActivateCredentialDelivery(credentialdelivery.SanitizedActivationRequest) (credentialdelivery.ActivationResult, error) {
	return credentialdelivery.ActivationResult{}, errors.New("provider returned secret-bearing response")
}

func credentialDeliveryRawRedactionValues() []string {
	return []string{
		"ghp_phase43_raw_secret_value_123",
		"sk-phase43-raw-secret",
		"/Users/v/.config/hal/raw-secret.json",
		"Authorization: Bearer phase43-secret",
		"api.raw-secret.example.invalid",
	}
}

func assertCredentialDeliveryRawValuesAbsent(t *testing.T, label string, value any, rawValues []string) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%s) error = %v", label, err)
	}
	encoded := string(payload)
	for _, raw := range rawValues {
		if strings.Contains(encoded, raw) {
			t.Fatalf("%s leaked raw credential delivery value %q in %s", label, raw, encoded)
		}
	}
}
