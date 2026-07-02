package cmd

import (
	"fmt"
	"strings"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
)

const factorySandboxReadinessGatePolicyField = "factory.policy.securityReadinessGatePolicyMode"

type factorySandboxReadinessGateBlockedError struct {
	decision sandbox.SandboxSecurityCapabilityReadinessGateDecision
}

func (e factorySandboxReadinessGateBlockedError) Error() string {
	return fmt.Sprintf("factory security readiness gate blocked: policyMode=%s outcome=%s code=%s reason=%s",
		e.decision.PolicyMode,
		e.decision.Outcome,
		e.decision.Code,
		e.decision.Reason,
	)
}

func enforceFactorySandboxReadinessGate(store factory.Store, deps factorySandboxExecutorDeps, req factorySandboxExecutorRequest, record *factory.RunRecord, redactor factory.RunSecretRedactor) error {
	if record == nil || strings.TrimSpace(record.RunID) == "" {
		return nil
	}
	decision := sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(
		req.SecurityReadinessGateMode,
		factorySandboxReadinessGateDiagnostics(record),
	)
	if decision.PolicyMode == sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeOff {
		return nil
	}
	metadata := factorySandboxReadinessGatePolicyDecisionMetadata(decision)
	if err := recordFactoryPolicyDecision(store, record.RunID, deps.now().UTC(), metadata); err != nil {
		return fmt.Errorf("record factory sandbox readiness gate policy decision: %w", err)
	}
	if decision.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked {
		return nil
	}
	blockErr := factorySandboxReadinessGateBlockedError{decision: decision}
	_ = recordFactorySandboxFailure(store, deps, record, nil, "prepare_inputs", blockErr, redactor)
	return factorySandboxRecordedError("prepare factory sandbox inputs", nil, blockErr, redactor)
}

func factorySandboxReadinessGateDiagnostics(record *factory.RunRecord) *sandbox.SandboxSecurityCapabilityReadinessDiagnosticSummary {
	if record == nil || record.Sandbox == nil || record.Sandbox.Security == nil {
		return nil
	}
	return record.Sandbox.Security.CapabilityReadinessDiagnostics
}

func factorySandboxReadinessGatePolicyDecisionMetadata(decision sandbox.SandboxSecurityCapabilityReadinessGateDecision) factory.PolicyDecisionMetadata {
	metadata := factory.PolicyDecisionMetadata{
		PolicyField: factorySandboxReadinessGatePolicyField,
		Decision:    factory.PolicyDecisionPassedGate,
		Outcome:     string(decision.Outcome),
		Reason:      string(decision.Reason),
		PolicyMode:  decision.PolicyMode,
		Code:        decision.Code,
		Counts:      cloneFactorySandboxReadinessGateCounts(decision.Counts),
	}
	if decision.Outcome == sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked {
		metadata.Decision = factory.PolicyDecisionBlockedGate
		metadata.Outcome = factory.PolicyOutcomeBlocked
	}
	if decision.Outcome == sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAllowed {
		metadata.Outcome = factory.PolicyOutcomeAllowed
	}
	return metadata
}

func cloneFactorySandboxReadinessGateCounts(counts *sandbox.SandboxSecurityCapabilityReadinessGateCounts) *sandbox.SandboxSecurityCapabilityReadinessGateCounts {
	if counts == nil {
		return nil
	}
	clone := *counts
	return &clone
}
