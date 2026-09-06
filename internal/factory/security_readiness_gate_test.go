package factory

import (
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestSecurityReadinessGateDecisionReturnsSanitizedClone(t *testing.T) {
	decision := sandbox.SandboxSecurityCapabilityReadinessGateDecision{
		Code:       sandbox.SandboxSecurityCapabilityReadinessGateCodeBlocked,
		Outcome:    sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
		PolicyMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		Reason:     sandbox.SandboxSecurityCapabilityReadinessGateReasonReadinessMissing,
		Counts: &sandbox.SandboxSecurityCapabilityReadinessGateCounts{
			Total:          1,
			Missing:        1,
			StrictBlocking: 1,
			ReasonCodeCounts: map[sandbox.SandboxSecurityCapabilityReasonCode]int{
				sandbox.SandboxSecurityCapabilityReasonReadinessMissing:             1,
				sandbox.SandboxSecurityCapabilityReasonCode("/tmp/raw-secret-path"): 1,
			},
		},
	}
	record := RunRecord{
		Sandbox: &SandboxMetadata{
			Security: &SandboxSecurityMetadata{
				SecurityReadinessGate: &decision,
			},
		},
	}

	got := SecurityReadinessGateDecision(record)
	if got == nil {
		t.Fatal("SecurityReadinessGateDecision() = nil, want sanitized decision")
	}
	if got == &decision {
		t.Fatal("SecurityReadinessGateDecision() returned original pointer, want clone")
	}
	if got.Code != decision.Code || got.Outcome != decision.Outcome || got.PolicyMode != decision.PolicyMode || got.Reason != decision.Reason {
		t.Fatalf("SecurityReadinessGateDecision() = %#v, want stable gate labels from %#v", got, decision)
	}
	if got.Counts == nil || got.Counts.StrictBlocking != 1 || got.Counts.ReasonCodeCounts[sandbox.SandboxSecurityCapabilityReasonReadinessMissing] != 1 {
		t.Fatalf("SecurityReadinessGateDecision() counts = %#v, want sanitized readiness_missing count", got.Counts)
	}
	if _, ok := got.Counts.ReasonCodeCounts[sandbox.SandboxSecurityCapabilityReasonCode("/tmp/raw-secret-path")]; ok {
		t.Fatalf("SecurityReadinessGateDecision() retained unsafe reason-code key: %#v", got.Counts.ReasonCodeCounts)
	}
}

func TestSecurityReadinessGateDecisionReturnsNilWhenUnavailable(t *testing.T) {
	for _, record := range []RunRecord{
		{},
		{Sandbox: &SandboxMetadata{}},
		{Sandbox: &SandboxMetadata{Security: &SandboxSecurityMetadata{}}},
	} {
		if got := SecurityReadinessGateDecision(record); got != nil {
			t.Fatalf("SecurityReadinessGateDecision(%#v) = %#v, want nil", record, got)
		}
	}
}
