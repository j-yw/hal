package credentialdelivery

import (
	"errors"
	"testing"
)

func TestActivateDeliveryDowngradesUnavailableAndUnsupportedModes(t *testing.T) {
	binding := planBindingFixture(ModeEnv)
	plan := Plan{
		ID:             "delivery-plan-downgrade",
		RequestID:      "delivery-request-01",
		RequestedModes: []Mode{ModeEnv},
		ActiveModes:    []Mode{ModeEnv},
		Status:         StatusPlanned,
	}

	t.Run("missing adapter skips planned active mode", func(t *testing.T) {
		got := ActivateDelivery(ActivationRequest{
			Plan:     plan,
			Bindings: []Binding{binding},
		}, nil)

		if got.Status != StatusSkipped {
			t.Fatalf("activation status = %q, want skipped", got.Status)
		}
		assertPlanModes(t, got.ActiveModes, nil)
		assertActivationWarning(t, got, WarningAdapterUnavailable, ReasonActivationUnavailable, ModeEnv)
		assertActivationBindingStatus(t, got, binding.ID, ModeEnv, StatusSkipped)
		assertActivationNoLeak(t, got)
	})

	t.Run("unsupported adapter result stays ready without active mode", func(t *testing.T) {
		adapter := &fakeActivationAdapter{
			result: ActivationResult{
				ID:             "activation-ready",
				PlanID:         plan.ID,
				RequestedModes: []Mode{ModeEnv},
				ActiveModes:    []Mode{ModeEnv},
				Bindings: []BindingActivationResult{{
					BindingID:    binding.ID,
					ServiceID:    binding.ServiceID,
					DeliveryMode: ModeEnv,
					Outcome:      StatusReady,
					Status:       StatusReady,
					ReasonCode:   ReasonActivationUnavailable,
				}},
				Status: StatusReady,
				Warnings: []Warning{{
					Code:       WarningActivationSkipped,
					ReasonCode: ReasonActivationUnavailable,
					Mode:       ModeEnv,
				}},
			},
		}

		got := ActivateDelivery(ActivationRequest{
			Plan:     plan,
			Bindings: []Binding{binding},
		}, adapter)

		if got.Status != StatusReady {
			t.Fatalf("activation status = %q, want ready", got.Status)
		}
		assertPlanModes(t, got.ActiveModes, nil)
		assertActivationWarning(t, got, WarningActivationSkipped, ReasonActivationUnavailable, ModeEnv)
		assertActivationBindingStatus(t, got, binding.ID, ModeEnv, StatusReady)
		assertActivationNoLeak(t, got)
	})

	t.Run("failing adapter clears planned active mode", func(t *testing.T) {
		adapter := &fakeActivationAdapter{err: errors.New("raw adapter failed with ghp_raw_secret_value")}

		got := ActivateDelivery(ActivationRequest{
			Plan:     plan,
			Bindings: []Binding{binding},
		}, adapter)

		if got.Status != StatusFailed {
			t.Fatalf("activation status = %q, want failed", got.Status)
		}
		assertPlanModes(t, got.ActiveModes, nil)
		assertActivationError(t, got, ErrorActivationFailed, "adapter")
		assertActivationBindingStatus(t, got, binding.ID, ModeEnv, StatusFailed)
		assertActivationNoLeak(t, got, "raw adapter failed", "ghp_raw_secret_value")
	})
}

func TestActivateDeliveryMalformedModeDowngradesWithSanitizedDiagnostics(t *testing.T) {
	rawUnsupportedMode := Mode("tmp_file")
	rawMalformedMode := Mode("https://tokens.example.invalid/credential?token=ghp_raw_secret_value")
	plan := Plan{
		ID:             "delivery-plan-malformed-modes",
		RequestID:      "delivery-request-01",
		RequestedModes: []Mode{ModeEnv, rawUnsupportedMode, rawMalformedMode},
		ActiveModes:    []Mode{ModeEnv, rawUnsupportedMode, rawMalformedMode},
		Status:         StatusPlanned,
	}
	adapter := &fakeActivationAdapter{
		result: ActivationResult{
			ID:             "activation-malformed-modes",
			PlanID:         plan.ID,
			RequestedModes: []Mode{ModeEnv, rawUnsupportedMode, rawMalformedMode},
			ActiveModes:    []Mode{rawUnsupportedMode, rawMalformedMode},
			Status:         StatusActive,
		},
	}

	got := ActivateDelivery(ActivationRequest{Plan: plan}, adapter)

	if got.Status != StatusFailed {
		t.Fatalf("activation status = %q, want failed for malformed mode metadata", got.Status)
	}
	assertPlanModes(t, got.ActiveModes, nil)
	assertActivationError(t, got, ErrorUnsupportedMode, "plan.requestedModes")
	assertActivationError(t, got, ErrorUnsafeMetadata, "plan.requestedModes")
	assertActivationNoLeak(t, got, string(rawUnsupportedMode), string(rawMalformedMode), "tokens.example.invalid", "ghp_raw_secret_value")
}

func TestActivateDeliveryHTTPProxyMissingPhase45SuccessMetadataStaysNonActive(t *testing.T) {
	binding := planBindingFixture(ModeHTTPProxy)
	request := planConstructionRequestFixture(binding)
	configureHTTPProxyProof(&request)
	plan := BuildDeliveryPlan(request)
	plan.HTTPProxyProof.NetworkEnforcement.ProxyLifecycleStatus = "requested"
	plan.HTTPProxyProof.NetworkEnforcement.ResultOutcome = "planned"
	plan.HTTPProxyProof.NetworkEnforcement.ResultSupported = false

	got := ActivateDelivery(ActivationRequest{
		Plan:     plan,
		Bindings: []Binding{binding},
	}, &fakeActivationAdapter{})

	if got.Status != StatusSkipped {
		t.Fatalf("activation status = %q, want skipped without Phase 45 success proof", got.Status)
	}
	assertPlanModes(t, got.RequestedModes, []Mode{ModeHTTPProxy})
	assertPlanModes(t, got.ActiveModes, nil)
	assertActivationWarning(t, got, WarningActivationSkipped, ReasonMissingServiceBinding, ModeHTTPProxy)
	assertActivationBindingStatus(t, got, binding.ID, ModeHTTPProxy, StatusSkipped)
	assertActivationNoLeak(t, got)
}

func TestStatusMetadataFromActivationNeverCountsLegacyAuthSyncAsActiveDelivery(t *testing.T) {
	got := StatusMetadataFromActivation(Plan{
		ID:             "delivery-plan-legacy",
		RequestID:      "delivery-request-01",
		RequestedModes: []Mode{ModeLegacyAuthSync},
		Status:         StatusPlanned,
	}, ActivationResult{
		ID:             "activation-legacy",
		PlanID:         "delivery-plan-legacy",
		RequestedModes: []Mode{ModeLegacyAuthSync},
		ActiveModes:    []Mode{ModeLegacyAuthSync},
		Status:         StatusActive,
		Warnings: []Warning{{
			Code:       WarningLegacyAuthCompatibility,
			ReasonCode: ReasonCompatibilityMode,
			Mode:       ModeLegacyAuthSync,
		}},
	})

	if got.Status != StatusSkipped {
		t.Fatalf("status metadata status = %q, want skipped compatibility status", got.Status)
	}
	assertPlanModes(t, got.RequestedModes, []Mode{ModeLegacyAuthSync})
	assertPlanModes(t, got.ActiveModes, nil)
	if got.ReasonCode != ReasonCompatibilityMode {
		t.Fatalf("status metadata reason = %q, want %q", got.ReasonCode, ReasonCompatibilityMode)
	}
}
