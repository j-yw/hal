package credentialdelivery

import "testing"

func TestStatusMetadataFromPlanDoesNotProjectActiveModes(t *testing.T) {
	got := StatusMetadataFromPlan(Plan{
		ID:             " delivery-plan-01 ",
		RequestID:      " delivery-request-01 ",
		RequestedModes: []Mode{ModeHTTPProxy, ModeEnv},
		ActiveModes:    []Mode{ModeHTTPProxy},
		Status:         StatusPlanned,
		Warnings: []Warning{{
			Code:       WarningActivationSkipped,
			ReasonCode: ReasonMissingServiceBinding,
			Mode:       ModeHTTPProxy,
		}},
	})

	if got.ID != "delivery-plan-01" || got.PlanID != "delivery-plan-01" || got.RequestID != "delivery-request-01" {
		t.Fatalf("status identifiers = %#v", got)
	}
	if got.Status != StatusPlanned {
		t.Fatalf("status = %q, want %q", got.Status, StatusPlanned)
	}
	if len(got.RequestedModes) != 2 || got.RequestedModes[0] != ModeHTTPProxy || got.RequestedModes[1] != ModeEnv {
		t.Fatalf("requested modes = %#v", got.RequestedModes)
	}
	if len(got.ActiveModes) != 0 {
		t.Fatalf("active modes = %#v, want omitted for plan-only metadata", got.ActiveModes)
	}
	if got.WarningCount != 1 || got.ErrorCount != 0 {
		t.Fatalf("counts = warnings %d errors %d, want 1/0", got.WarningCount, got.ErrorCount)
	}
}

func TestStatusMetadataFromActivationProjectsActiveModesOnlyForActiveResult(t *testing.T) {
	plan := Plan{
		ID:             "delivery-plan-01",
		RequestID:      "delivery-request-01",
		RequestedModes: []Mode{ModeHTTPProxy},
		Status:         StatusPlanned,
	}
	active := StatusMetadataFromActivation(plan, ActivationResult{
		ID:             "activation-01",
		PlanID:         "delivery-plan-01",
		RequestedModes: []Mode{ModeHTTPProxy},
		ActiveModes:    []Mode{ModeHTTPProxy},
		Status:         StatusActive,
	})
	if len(active.ActiveModes) != 1 || active.ActiveModes[0] != ModeHTTPProxy {
		t.Fatalf("active activation modes = %#v, want http_proxy", active.ActiveModes)
	}

	skipped := StatusMetadataFromActivation(plan, ActivationResult{
		ID:             "activation-02",
		PlanID:         "delivery-plan-01",
		RequestedModes: []Mode{ModeHTTPProxy},
		ActiveModes:    []Mode{ModeHTTPProxy},
		Status:         StatusSkipped,
		Warnings: []Warning{{
			Code:       WarningActivationSkipped,
			ReasonCode: ReasonMissingServiceBinding,
			Mode:       ModeHTTPProxy,
		}},
	})
	if len(skipped.ActiveModes) != 0 {
		t.Fatalf("skipped activation active modes = %#v, want omitted", skipped.ActiveModes)
	}
	if skipped.WarningCount != 1 {
		t.Fatalf("skipped warning count = %d, want 1", skipped.WarningCount)
	}
}
