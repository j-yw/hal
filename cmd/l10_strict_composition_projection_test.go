package cmd

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestL10StrictCompositionProjectsSanitizedDecisionAcrossCommandFactoryAndStatus(t *testing.T) {
	decision := sandbox.SandboxStrictCompositionDecision{
		State: sandbox.SandboxStrictCompositionStateActive, Code: sandbox.SandboxStrictCompositionCodeReady,
		CompositionID: "composition-l10-projection", ObservedAt: time.Unix(1_900_200_000, 0), ExpiresAt: time.Unix(1_900_200_030, 0),
		Evidence: []sandbox.SandboxStrictCompositionEvidence{
			{Kind: sandbox.SandboxStrictCompositionEvidenceRuntime, State: sandbox.SandboxStrictCompositionStateActive, Code: sandbox.SandboxStrictCompositionCodeReady},
			{Kind: sandbox.SandboxStrictCompositionEvidenceCredential, State: sandbox.SandboxStrictCompositionStateActive, Code: sandbox.SandboxStrictCompositionCodeReady},
			{Kind: sandbox.SandboxStrictCompositionEvidenceTemplate, State: sandbox.SandboxStrictCompositionStateActive, Code: sandbox.SandboxStrictCompositionCodeReady},
			{Kind: sandbox.SandboxStrictCompositionEvidenceWorkspace, State: sandbox.SandboxStrictCompositionStateActive, Code: sandbox.SandboxStrictCompositionCodeReady},
		},
	}
	input := &sandbox.SandboxSecurity{StrictComposition: &decision}

	command := sanitizeCommandSandboxSecurity(input)
	if command == nil || command.StrictComposition == nil || command.StrictComposition.CompositionID != decision.CompositionID {
		t.Fatalf("command strict composition = %#v, want sanitized decision", command)
	}
	status := newSandboxRuntimeSecuritySummary(input)
	if status.StrictComposition == nil || status.StrictComposition.CompositionID != decision.CompositionID {
		t.Fatalf("status strict composition = %#v, want sanitized decision", status.StrictComposition)
	}
	factory := factorySandboxSecurityMetadata(input)
	if factory == nil || factory.StrictComposition == nil || factory.StrictComposition.CompositionID != decision.CompositionID {
		t.Fatalf("factory strict composition = %#v, want sanitized decision", factory)
	}
	timeline := factorySandboxSecurityTimelineMetadata(factory)
	if timeline == nil || timeline["strictComposition"] == nil {
		t.Fatalf("factory timeline = %#v, want strictComposition", timeline)
	}

	decision.Evidence[0].Kind = "https://unsafe.invalid/token"
	if command.StrictComposition.Evidence[0].Kind != sandbox.SandboxStrictCompositionEvidenceRuntime {
		t.Fatal("command projection retained caller-owned evidence storage")
	}
	for label, value := range map[string]any{"command": command, "status": status, "factory": factory, "timeline": timeline} {
		payload, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("json.Marshal(%s) error = %v", label, err)
		}
		for _, forbidden := range []string{"unsafe.invalid", "token=", "/home/", ".sock", "Authorization"} {
			if strings.Contains(string(payload), forbidden) {
				t.Fatalf("%s projection leaked %q: %s", label, forbidden, payload)
			}
		}
	}
}
