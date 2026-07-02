package cmd

import (
	"reflect"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
)

func applyFactorySandboxCapabilityReadinessMetadata(req factorySandboxExecutorRequest, metadata *factory.SandboxMetadata, target *sandbox.SandboxState) {
	if metadata == nil {
		return
	}
	if metadata.Security != nil && metadata.Security.CapabilityReadiness != nil {
		applyFactorySandboxCapabilityReadinessDiagnostics(metadata.Security)
		return
	}
	readiness := factorySandboxCapabilityReadiness(req, metadata, target)
	if readiness == nil {
		if metadata.Security != nil {
			metadata.Security.CapabilityReadinessDiagnostics = nil
		}
		return
	}
	if metadata.Security == nil {
		metadata.Security = &factory.SandboxSecurityMetadata{}
	}
	metadata.Security.CapabilityReadiness = readiness
	applyFactorySandboxCapabilityReadinessDiagnostics(metadata.Security)
}

func factorySandboxCapabilityReadiness(req factorySandboxExecutorRequest, metadata *factory.SandboxMetadata, target *sandbox.SandboxState) *sandbox.SandboxSecurityCapabilityReadinessOutput {
	if metadata == nil {
		return nil
	}
	security := factorySandboxReadinessSecurity(metadata.Security)
	var inputs []sandbox.SandboxSecurityCapabilityReadinessInput
	if factorySandboxSecurityRequestHasReadinessIntent(req) && security != nil {
		inputs = append(inputs, sandbox.ProjectSandboxSecurityCapabilityReadinessInput(security))
	}
	if factorySandboxShouldProjectWorkerRuntimeReadiness(req, metadata) {
		inputs = append(inputs, sandbox.ProjectSandboxWorkerRuntimeCapabilityReadinessInput(sandbox.SandboxWorkerRuntimeCapabilityReadinessProjection{
			Host:          factorySandboxReadinessHost(metadata, target),
			Runtime:       factorySandboxReadinessRuntime(metadata, target),
			WorkerRouting: metadata.WorkerRouting,
		}))
	}
	if factorySandboxHasPolicyProxyCredentialReadinessInputs(req, metadata) {
		inputs = append(inputs, sandbox.ProjectSandboxPolicyProxyCredentialCapabilityReadinessInput(sandbox.SandboxPolicyProxyCredentialCapabilityReadinessProjection{
			NetworkPolicyResult:       factorySandboxReadinessPolicyResult(security),
			NetworkProxySession:       metadata.NetworkProxySession,
			NetworkPolicyDecisionLogs: sandbox.SanitizeSandboxNetworkPolicyDecisionLogRecords(req.NetworkPolicyDecisionLogs),
			CredentialProxyPlan:       metadata.CredentialProxyPlan,
			CredentialProxySession:    metadata.CredentialProxySession,
			CredentialProxyBindings:   append([]sandbox.SandboxCredentialProxyBindingMetadata(nil), metadata.CredentialProxyBindings...),
		}))
	}
	if len(inputs) == 0 {
		return nil
	}
	return sandbox.EvaluateProjectedSandboxSecurityCapabilityReadiness(inputs...)
}

func sanitizedFactorySandboxCapabilityReadiness(readiness *sandbox.SandboxSecurityCapabilityReadinessOutput) *sandbox.SandboxSecurityCapabilityReadinessOutput {
	if readiness == nil {
		return nil
	}
	sanitized := sandbox.SanitizeSandboxSecurityCapabilityReadinessOutput(*readiness)
	if len(sanitized.Results) == 0 {
		return nil
	}
	return &sanitized
}

func factorySandboxCapabilityReadinessDiagnostics(readiness *sandbox.SandboxSecurityCapabilityReadinessOutput) *sandbox.SandboxSecurityCapabilityReadinessDiagnosticSummary {
	readiness = sanitizedFactorySandboxCapabilityReadiness(readiness)
	if readiness == nil {
		return nil
	}
	diagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*readiness)
	return &diagnostics
}

func applyFactorySandboxCapabilityReadinessDiagnostics(security *factory.SandboxSecurityMetadata) {
	if security == nil {
		return
	}
	readiness := sanitizedFactorySandboxCapabilityReadiness(security.CapabilityReadiness)
	if readiness == nil {
		security.CapabilityReadiness = nil
		security.CapabilityReadinessDiagnostics = nil
		return
	}
	security.CapabilityReadiness = readiness
	security.CapabilityReadinessDiagnostics = factorySandboxCapabilityReadinessDiagnostics(readiness)
}

func factorySandboxSecurityRequestHasReadinessIntent(req factorySandboxExecutorRequest) bool {
	if emptySandboxSecurityEvaluationRequest(req.Security) {
		return false
	}
	defaultReq := sandboxSecurityRequestFromConfig(nil, req.SandboxRuntime)
	return !reflect.DeepEqual(req.Security, defaultReq)
}

func factorySandboxShouldProjectWorkerRuntimeReadiness(req factorySandboxExecutorRequest, metadata *factory.SandboxMetadata) bool {
	return sandboxWorkerRoutingRequested(req.SandboxHostID, req.SandboxRuntime) ||
		factorySandboxSecurityRequestHasReadinessIntent(req) ||
		factorySandboxHasPolicyProxyCredentialReadinessInputs(req, metadata)
}

func factorySandboxHasPolicyProxyCredentialReadinessInputs(req factorySandboxExecutorRequest, metadata *factory.SandboxMetadata) bool {
	if metadata == nil {
		return false
	}
	return metadata.NetworkProxySession != nil ||
		len(req.NetworkPolicyDecisionLogs) > 0 ||
		metadata.CredentialProxyPlan != nil ||
		metadata.CredentialProxySession != nil ||
		len(metadata.CredentialProxyBindings) > 0
}

func factorySandboxReadinessSecurity(security *factory.SandboxSecurityMetadata) *sandbox.SandboxSecurity {
	if security == nil {
		return nil
	}
	out := &sandbox.SandboxSecurity{
		CapabilityReadiness:            sandbox.CloneSandboxSecurityCapabilityReadinessOutputPtr(security.CapabilityReadiness),
		CapabilityReadinessDiagnostics: factorySandboxCapabilityReadinessDiagnostics(security.CapabilityReadiness),
	}
	if security.Network != nil {
		out.Network = &sandbox.SandboxNetworkSecurity{
			PolicyRequested: security.Network.PolicyRequested,
			PolicyEnforced:  security.Network.PolicyEnforced,
			EnforcementMode: security.Network.EnforcementMode,
			PolicyResult:    sandbox.CloneSandboxNetworkPolicyResultPtr(security.Network.PolicyResult),
		}
	}
	if security.Secrets != nil {
		out.Secrets = &sandbox.SandboxSecretSecurity{
			RequestedModes: append([]string(nil), security.Secrets.RequestedModes...),
			ActiveModes:    append([]string(nil), security.Secrets.ActiveModes...),
		}
	}
	if out.Network == nil && out.Secrets == nil && out.CapabilityReadiness == nil {
		return nil
	}
	return out
}

func factorySandboxReadinessPolicyResult(security *sandbox.SandboxSecurity) *sandbox.SandboxNetworkPolicyResult {
	if security == nil || security.Network == nil {
		return nil
	}
	return security.Network.PolicyResult
}

func factorySandboxReadinessHost(metadata *factory.SandboxMetadata, target *sandbox.SandboxState) *sandbox.SandboxHost {
	if target != nil && target.Host != nil {
		return target.Host
	}
	if metadata == nil || metadata.Host == nil {
		return nil
	}
	return &sandbox.SandboxHost{
		ID:   metadata.Host.ID,
		Name: metadata.Host.Name,
		Kind: metadata.Host.Kind,
	}
}

func factorySandboxReadinessRuntime(metadata *factory.SandboxMetadata, target *sandbox.SandboxState) *sandbox.SandboxRuntimeState {
	if target != nil && target.Runtime != nil {
		return target.Runtime
	}
	if metadata == nil || metadata.Runtime == nil {
		return nil
	}
	return &sandbox.SandboxRuntimeState{
		Driver:         metadata.Runtime.Driver,
		IsolationLevel: metadata.Runtime.IsolationLevel,
		RuntimeID:      metadata.Runtime.RuntimeID,
		Image:          metadata.Runtime.Image,
		WorkerID:       metadata.Runtime.WorkerID,
	}
}
