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
	decision := factorySandboxReadinessGateDecision(req, record)
	if decision.PolicyMode == sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeOff {
		return nil
	}
	if err := recordFactorySandboxReadinessGateDecision(store, record, decision); err != nil {
		return fmt.Errorf("record factory sandbox readiness gate decision metadata: %w", err)
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

func enforceFactoryRunStrictDefaultSandboxReadinessGate(store factory.Store, deps factoryRunDeps, record *factory.RunRecord, redactor factory.RunSecretRedactor) error {
	if record == nil || strings.TrimSpace(record.RunID) == "" {
		return nil
	}
	if record.Sandbox == nil {
		record.Sandbox = &factory.SandboxMetadata{}
	}
	if record.Sandbox.Security == nil {
		record.Sandbox.Security = &factory.SandboxSecurityMetadata{}
	}
	if record.Sandbox.Security.CapabilityReadinessDiagnostics == nil {
		diagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(sandbox.SandboxSecurityCapabilityReadinessOutput{})
		record.Sandbox.Security.CapabilityReadinessDiagnostics = &diagnostics
	}
	return enforceFactorySandboxReadinessGate(store, factorySandboxExecutorDeps{
		now:         deps.now,
		saveRun:     saveFactorySandboxRunRecord,
		appendEvent: appendFactorySandboxTimelineEvent,
	}, factorySandboxExecutorRequest{
		SecurityReadinessGateMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
	}, record, redactor)
}

func factorySandboxReadinessGateDiagnostics(record *factory.RunRecord) *sandbox.SandboxSecurityCapabilityReadinessDiagnosticSummary {
	if record == nil || record.Sandbox == nil || record.Sandbox.Security == nil {
		return nil
	}
	return record.Sandbox.Security.CapabilityReadinessDiagnostics
}

func factorySandboxReadinessGateDecision(req factorySandboxExecutorRequest, record *factory.RunRecord) sandbox.SandboxSecurityCapabilityReadinessGateDecision {
	if req.SecurityReadinessGateMode == sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict {
		// Factory requests do not yet carry the opaque live L10 authority.
		// Durable readiness and strict-composition metadata are status only.
		return sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(
			req.SecurityReadinessGateMode,
			nil,
		)
	}
	if record != nil {
		if decision := factory.SecurityReadinessGateDecision(*record); decision != nil && decision.PolicyMode == req.SecurityReadinessGateMode {
			return *decision
		}
	}
	return sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(
		req.SecurityReadinessGateMode,
		factorySandboxReadinessGateDiagnostics(record),
	)
}

func recordFactorySandboxReadinessGateDecision(store factory.Store, record *factory.RunRecord, decision sandbox.SandboxSecurityCapabilityReadinessGateDecision) error {
	if record == nil || strings.TrimSpace(record.RunID) == "" {
		return nil
	}
	if record.Sandbox == nil {
		record.Sandbox = &factory.SandboxMetadata{}
	}
	if record.Sandbox.Security == nil {
		record.Sandbox.Security = &factory.SandboxSecurityMetadata{}
	}
	record.Sandbox.Security.SecurityReadinessGate = sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(&decision)
	return store.SaveRun(record)
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
	clone := sandboxSecurityReadinessGateCountsClone(*counts)
	return &clone
}
