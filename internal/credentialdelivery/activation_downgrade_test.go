package credentialdelivery

import (
	"testing"
)

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
