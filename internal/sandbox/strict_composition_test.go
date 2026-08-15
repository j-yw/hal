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
