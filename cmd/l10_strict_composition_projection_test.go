package cmd

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
)

func TestL10StrictCompositionProjectsSanitizedDecisionAcrossCommandFactoryAndStatus(t *testing.T) {
	observedAt := time.Now().UTC()
	decision := sandbox.SandboxStrictCompositionDecision{
		State: sandbox.SandboxStrictCompositionStateActive, Code: sandbox.SandboxStrictCompositionCodeReady,
		CompositionID: "composition-l10-projection", ObservedAt: observedAt, ExpiresAt: observedAt.Add(30 * time.Second),
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

func TestL10StrictCompositionProjectionsExpireActiveDecisions(t *testing.T) {
	now := time.Now().UTC()
	decision := sandbox.SandboxStrictCompositionDecision{
		State: sandbox.SandboxStrictCompositionStateActive, Code: sandbox.SandboxStrictCompositionCodeReady,
		CompositionID: "composition-l10-expired", ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(-time.Second),
		Evidence: []sandbox.SandboxStrictCompositionEvidence{
			{Kind: sandbox.SandboxStrictCompositionEvidenceRuntime, State: sandbox.SandboxStrictCompositionStateActive, Code: sandbox.SandboxStrictCompositionCodeReady},
			{Kind: sandbox.SandboxStrictCompositionEvidenceCredential, State: sandbox.SandboxStrictCompositionStateActive, Code: sandbox.SandboxStrictCompositionCodeReady},
			{Kind: sandbox.SandboxStrictCompositionEvidenceTemplate, State: sandbox.SandboxStrictCompositionStateActive, Code: sandbox.SandboxStrictCompositionCodeReady},
			{Kind: sandbox.SandboxStrictCompositionEvidenceWorkspace, State: sandbox.SandboxStrictCompositionStateActive, Code: sandbox.SandboxStrictCompositionCodeReady},
		},
	}
	input := &sandbox.SandboxSecurity{StrictComposition: &decision}
	command := sanitizeCommandSandboxSecurity(input)
	status := newSandboxRuntimeSecuritySummary(input)
	factoryMetadata := factorySandboxSecurityMetadata(input)
	timeline := factorySandboxSecurityTimelineMetadata(factoryMetadata)

	projected := map[string]*sandbox.SandboxStrictCompositionDecision{
		"command": command.StrictComposition,
		"status":  status.StrictComposition,
		"factory": factoryMetadata.StrictComposition,
	}
	if value, ok := timeline["strictComposition"].(*sandbox.SandboxStrictCompositionDecision); ok {
		projected["timeline"] = value
	} else {
		t.Fatalf("timeline strict composition = %#v, want decision pointer", timeline["strictComposition"])
	}
	for label, got := range projected {
		if got == nil || got.State != sandbox.SandboxStrictCompositionStateBlocked || got.Code != sandbox.SandboxStrictCompositionCodeAttestationStale {
			t.Fatalf("%s strict composition = %#v, want blocked attestation_stale", label, got)
		}
		if got.CompositionID != "" || !got.ObservedAt.IsZero() || !got.ExpiresAt.IsZero() || len(got.Evidence) != 0 {
			t.Fatalf("%s expired projection retained authority-shaped fields: %#v", label, got)
		}
	}
}

func TestL10FactoryStrictGateRejectsLegacyAllowedMetadataWithoutLiveAuthority(t *testing.T) {
	legacyAllowed := sandbox.SandboxSecurityCapabilityReadinessGateDecision{
		Code:       sandbox.SandboxSecurityCapabilityReadinessGateCodeAllowed,
		Outcome:    sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
		PolicyMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		Reason:     sandbox.SandboxSecurityCapabilityReadinessGateReasonReadinessReady,
	}
	record := &factory.RunRecord{Sandbox: &factory.SandboxMetadata{Security: &factory.SandboxSecurityMetadata{
		SecurityReadinessGate: &legacyAllowed,
	}}}
	got := factorySandboxReadinessGateDecision(factorySandboxExecutorRequest{
		SecurityReadinessGateMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
	}, record)
	if got.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked || got.Code != sandbox.SandboxSecurityCapabilityReadinessGateCodeBlocked {
		t.Fatalf("factory strict decision = %#v, want blocked without live strict-composition authority", got)
	}
}
