package sandbox

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestL10StrictCompositionDecisionSanitizesAndCannotCarryLiveAuthority(t *testing.T) {
	decision := SanitizeSandboxStrictCompositionDecision(SandboxStrictCompositionDecision{
		State:         SandboxStrictCompositionStateActive,
		Code:          SandboxStrictCompositionCodeReady,
		CompositionID: "composition-primary",
		ObservedAt:    time.Unix(1_900_000_000, 0),
		ExpiresAt:     time.Unix(1_900_000_030, 0),
		Evidence: []SandboxStrictCompositionEvidence{
			{Kind: SandboxStrictCompositionEvidenceRuntime, State: SandboxStrictCompositionStateActive, Code: SandboxStrictCompositionCodeReady},
			{Kind: SandboxStrictCompositionEvidenceCredential, State: SandboxStrictCompositionStateActive, Code: SandboxStrictCompositionCodeReady},
			{Kind: SandboxStrictCompositionEvidenceTemplate, State: SandboxStrictCompositionStateActive, Code: SandboxStrictCompositionCodeReady},
			{Kind: SandboxStrictCompositionEvidenceWorkspace, State: SandboxStrictCompositionStateActive, Code: SandboxStrictCompositionCodeReady},
			{Kind: "https://unsafe.invalid/token", State: SandboxStrictCompositionStateActive},
		},
	})
	payload, err := json.Marshal(&SandboxSecurity{StrictComposition: &decision})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	encoded := string(payload)
	for _, forbidden := range []string{"unsafe.invalid", "token", "/home/", "credentialValue", "socketPath", "firewallRule"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("strict composition JSON leaked %q: %s", forbidden, encoded)
		}
	}
	if len(decision.Evidence) != 4 {
		t.Fatalf("evidence count = %d, want bounded 4", len(decision.Evidence))
	}
}

func TestL10StrictCompositionDecisionSanitizerEnforcesAuthoritySemantics(t *testing.T) {
	validActive := SandboxStrictCompositionDecision{
		State: SandboxStrictCompositionStateActive, Code: SandboxStrictCompositionCodeReady,
		CompositionID: "composition-primary", ObservedAt: time.Unix(1_900_000_000, 0), ExpiresAt: time.Unix(1_900_000_030, 0),
		Evidence: []SandboxStrictCompositionEvidence{
			{Kind: SandboxStrictCompositionEvidenceRuntime, State: SandboxStrictCompositionStateActive, Code: SandboxStrictCompositionCodeReady},
			{Kind: SandboxStrictCompositionEvidenceCredential, State: SandboxStrictCompositionStateActive, Code: SandboxStrictCompositionCodeReady},
			{Kind: SandboxStrictCompositionEvidenceTemplate, State: SandboxStrictCompositionStateActive, Code: SandboxStrictCompositionCodeReady},
			{Kind: SandboxStrictCompositionEvidenceWorkspace, State: SandboxStrictCompositionStateActive, Code: SandboxStrictCompositionCodeReady},
		},
	}
	tests := []struct {
		name   string
		mutate func(*SandboxStrictCompositionDecision)
	}{
		{name: "active wrong code", mutate: func(d *SandboxStrictCompositionDecision) { d.Code = SandboxStrictCompositionCodeComplete }},
		{name: "active missing composition", mutate: func(d *SandboxStrictCompositionDecision) { d.CompositionID = "" }},
		{name: "active missing evidence", mutate: func(d *SandboxStrictCompositionDecision) { d.Evidence = d.Evidence[:3] }},
		{name: "active duplicate evidence", mutate: func(d *SandboxStrictCompositionDecision) { d.Evidence[3] = d.Evidence[2] }},
		{name: "active invalid expiry", mutate: func(d *SandboxStrictCompositionDecision) { d.ExpiresAt = d.ObservedAt }},
		{name: "complete retains expiry", mutate: func(d *SandboxStrictCompositionDecision) {
			d.State = SandboxStrictCompositionStateComplete
			d.Code = SandboxStrictCompositionCodeComplete
			for index := range d.Evidence {
				d.Evidence[index].State = d.State
				d.Evidence[index].Code = d.Code
			}
		}},
		{name: "blocked uses authority code", mutate: func(d *SandboxStrictCompositionDecision) { d.State = SandboxStrictCompositionStateBlocked }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := validActive
			input.Evidence = append([]SandboxStrictCompositionEvidence(nil), validActive.Evidence...)
			tt.mutate(&input)
			got := SanitizeSandboxStrictCompositionDecision(input)
			if got.State != SandboxStrictCompositionStateBlocked || got.Code != SandboxStrictCompositionCodeIdentityInvalid {
				t.Fatalf("SanitizeSandboxStrictCompositionDecision() = %#v, want blocked identity_invalid", got)
			}
			if got.CompositionID != "" || !got.ObservedAt.IsZero() || !got.ExpiresAt.IsZero() || len(got.Evidence) != 0 {
				t.Fatalf("invalid decision retained authority-shaped fields: %#v", got)
			}
		})
	}

	blocked := validActive
	blocked.State = SandboxStrictCompositionStateBlocked
	blocked.Code = SandboxStrictCompositionCodeWorkspaceProofUnsafe
	got := SanitizeSandboxStrictCompositionDecision(blocked)
	if got.State != blocked.State || got.Code != blocked.Code {
		t.Fatalf("valid blocked decision = %#v, want blocked workspace_proof_unsafe", got)
	}
	if got.CompositionID != "" || !got.ObservedAt.IsZero() || !got.ExpiresAt.IsZero() || len(got.Evidence) != 0 {
		t.Fatalf("blocked decision retained non-authoritative fields: %#v", got)
	}
}
