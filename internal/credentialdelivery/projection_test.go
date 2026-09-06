package credentialdelivery

import (
	"encoding/json"
	"strings"
	"testing"
)

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

func TestUS003StatusMetadataFromActivationRequiresBrokeredProofSummaries(t *testing.T) {
	tests := []struct {
		name       string
		mode       Mode
		proofID    string
		wantSource string
	}{
		{
			name:       "active http proxy",
			mode:       ModeHTTPProxy,
			proofID:    "credential-proxy-binding-01",
			wantSource: "credential_proxy",
		},
		{
			name:       "active ssh agent",
			mode:       ModeSSHAgent,
			proofID:    "ssh-agent-handoff-01",
			wantSource: "handoff",
		},
		{
			name:       "active file tmpfs",
			mode:       ModeFileTmpfs,
			proofID:    "tmpfs-simulation-proof-01",
			wantSource: "simulation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bindingID := "binding-" + strings.ReplaceAll(string(tt.mode), "_", "-")
			plan := Plan{
				ID:             "delivery-plan-" + bindingID,
				RequestID:      "delivery-request-" + bindingID,
				RequestedModes: []Mode{tt.mode},
				Status:         StatusPlanned,
			}
			active := StatusMetadataFromActivation(plan, ActivationResult{
				ID:             "activation-" + bindingID,
				PlanID:         plan.ID,
				RequestedModes: []Mode{tt.mode},
				ActiveModes:    []Mode{tt.mode},
				Bindings: []BindingActivationResult{{
					BindingID:    bindingID,
					DeliveryMode: tt.mode,
					Status:       StatusActive,
					ReasonCode:   ReasonRequested,
					ProofRef:     tt.proofID,
				}},
				ProofRefs: []ActivationProofReference{{
					ProofID:      tt.proofID,
					BindingID:    bindingID,
					DeliveryMode: tt.mode,
				}},
				Status:     StatusActive,
				ReasonCode: ReasonRequested,
			})

			if active.Status != StatusActive {
				t.Fatalf("status = %q, want active in %#v", active.Status, active)
			}
			assertPlanModes(t, active.ActiveModes, []Mode{tt.mode})
			if len(active.ActiveProofs) != 1 {
				t.Fatalf("active proofs = %#v, want one broker proof", active.ActiveProofs)
			}
			proof := active.ActiveProofs[0]
			if proof.ProofID != tt.proofID || proof.BindingID != bindingID || proof.DeliveryMode != string(tt.mode) || proof.Status != string(StatusActive) || proof.Source != tt.wantSource {
				t.Fatalf("active proof = %#v, want sanitized proof/binding/mode/status/source", proof)
			}
			assertStatusMetadataNoLeak(t, active,
				"ghp_raw_secret",
				"/tmp/credential.sock",
				"provider.example.invalid",
				"Authorization",
				"Bearer",
			)
		})
	}
}

func TestUS003StatusMetadataFromActivationRejectsIncompleteAndCompatibilityProof(t *testing.T) {
	tests := []struct {
		name       string
		mode       Mode
		activation ActivationResult
		wantStatus Status
		wantReason ReasonCode
		wantWarns  int
		wantErrors int
	}{
		{
			name: "missing broker proof",
			mode: ModeHTTPProxy,
			activation: ActivationResult{
				ID:             "activation-missing-proof",
				PlanID:         "delivery-plan-missing-proof",
				RequestedModes: []Mode{ModeHTTPProxy},
				ActiveModes:    []Mode{ModeHTTPProxy},
				Status:         StatusActive,
				ReasonCode:     ReasonRequested,
			},
			wantStatus: StatusSkipped,
			wantReason: ReasonMissingActivationProof,
		},
		{
			name: "failed activation",
			mode: ModeHTTPProxy,
			activation: ActivationResult{
				ID:             "activation-failed",
				PlanID:         "delivery-plan-failed",
				RequestedModes: []Mode{ModeHTTPProxy},
				ActiveModes:    []Mode{ModeHTTPProxy},
				Status:         StatusFailed,
				ReasonCode:     ReasonActivationUnavailable,
			},
			wantStatus: StatusFailed,
			wantReason: ReasonActivationUnavailable,
			wantErrors: 1,
		},
		{
			name: "warning-bearing activation",
			mode: ModeSSHAgent,
			activation: ActivationResult{
				ID:             "activation-warning",
				PlanID:         "delivery-plan-warning",
				RequestedModes: []Mode{ModeSSHAgent},
				ActiveModes:    []Mode{ModeSSHAgent},
				Bindings: []BindingActivationResult{{
					BindingID:    "binding-ssh-agent",
					DeliveryMode: ModeSSHAgent,
					Status:       StatusActive,
					ReasonCode:   ReasonRequested,
					ProofRef:     "ssh-agent-handoff-warning",
				}},
				ProofRefs: []ActivationProofReference{{
					ProofID:      "ssh-agent-handoff-warning",
					BindingID:    "binding-ssh-agent",
					DeliveryMode: ModeSSHAgent,
				}},
				Status:     StatusActive,
				ReasonCode: ReasonRequested,
				Warnings: []Warning{{
					Code:       WarningActivationSkipped,
					ReasonCode: ReasonActivationUnavailable,
					Mode:       ModeSSHAgent,
				}},
			},
			wantStatus: StatusActive,
			wantReason: ReasonRequested,
			wantWarns:  1,
		},
		{
			name: "env compatibility",
			mode: ModeEnv,
			activation: ActivationResult{
				ID:             "activation-env",
				PlanID:         "delivery-plan-env",
				RequestedModes: []Mode{ModeEnv},
				ActiveModes:    []Mode{ModeEnv},
				Bindings: []BindingActivationResult{{
					BindingID:    "binding-env",
					DeliveryMode: ModeEnv,
					Status:       StatusActive,
					ReasonCode:   ReasonRequested,
					ProofRef:     "env-proof-01",
				}},
				ProofRefs: []ActivationProofReference{{
					ProofID:      "env-proof-01",
					BindingID:    "binding-env",
					DeliveryMode: ModeEnv,
				}},
				Status:     StatusActive,
				ReasonCode: ReasonCompatibilityMode,
			},
			wantStatus: StatusSkipped,
			wantReason: ReasonCompatibilityMode,
		},
		{
			name: "legacy auth sync compatibility",
			mode: ModeLegacyAuthSync,
			activation: ActivationResult{
				ID:             "activation-legacy",
				PlanID:         "delivery-plan-legacy",
				RequestedModes: []Mode{ModeLegacyAuthSync},
				ActiveModes:    []Mode{ModeLegacyAuthSync},
				Status:         StatusActive,
				ReasonCode:     ReasonCompatibilityMode,
			},
			wantStatus: StatusSkipped,
			wantReason: ReasonCompatibilityMode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := Plan{
				ID:             tt.activation.PlanID,
				RequestID:      "delivery-request-" + string(tt.mode),
				RequestedModes: []Mode{tt.mode},
				Status:         StatusPlanned,
			}

			got := StatusMetadataFromActivation(plan, tt.activation)

			if got.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q in %#v", got.Status, tt.wantStatus, got)
			}
			if got.ReasonCode != tt.wantReason {
				t.Fatalf("reason = %q, want %q in %#v", got.ReasonCode, tt.wantReason, got)
			}
			if got.WarningCount != tt.wantWarns || got.ErrorCount != tt.wantErrors {
				t.Fatalf("counts = warnings %d errors %d, want %d/%d in %#v", got.WarningCount, got.ErrorCount, tt.wantWarns, tt.wantErrors, got)
			}
			if tt.wantStatus != StatusActive && len(got.ActiveProofs) != 0 {
				t.Fatalf("active proofs = %#v, want omitted for non-strict proof", got.ActiveProofs)
			}
			if tt.wantStatus == StatusActive && len(got.ActiveProofs) == 0 {
				t.Fatalf("active proofs = %#v, want sanitized proof retained for warning diagnostics", got.ActiveProofs)
			}
			assertStatusMetadataNoLeak(t, got, "raw-secret", "provider.example.invalid", "/tmp/", "Authorization", "Bearer")
		})
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
	if active.Status != StatusSkipped {
		t.Fatalf("active activation status = %q, want skipped without broker proof", active.Status)
	}
	if len(active.ActiveModes) != 0 || len(active.ActiveProofs) != 0 {
		t.Fatalf("active activation modes/proofs = %#v/%#v, want omitted without broker proof", active.ActiveModes, active.ActiveProofs)
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

func assertStatusMetadataNoLeak(t *testing.T, value any, rejected ...string) {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%T) error = %v", value, err)
	}
	payload := string(data)
	for _, forbidden := range rejected {
		if forbidden == "" {
			continue
		}
		if strings.Contains(payload, forbidden) {
			t.Fatalf("status metadata leaked %q in %s", forbidden, payload)
		}
	}
}
