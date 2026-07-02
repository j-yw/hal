package cmd

import (
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
)

func applyAutoSandboxCapabilityReadinessMetadata(manifest *sandboxexecution.Manifest) {
	if manifest == nil || manifest.Security == nil {
		return
	}
	if manifest.Security.CapabilityReadiness != nil {
		sanitized := sandbox.SanitizeSandboxSecurityCapabilityReadinessOutput(*manifest.Security.CapabilityReadiness)
		if len(sanitized.Results) == 0 {
			manifest.Security.CapabilityReadiness = nil
			manifest.Security.CapabilityReadinessDiagnostics = nil
			return
		}
		manifest.Security.CapabilityReadiness = &sanitized
		applyAutoSandboxReadinessDiagnostics(manifest.Security)
		return
	}

	manifest.Security.CapabilityReadiness = sandbox.EvaluateProjectedSandboxSecurityCapabilityReadiness(
		sandbox.ProjectSandboxSecurityCapabilityReadinessInput(manifest.Security),
		sandbox.ProjectSandboxWorkerRuntimeCapabilityReadinessInput(sandbox.SandboxWorkerRuntimeCapabilityReadinessProjection{
			Host:          manifest.Host,
			Runtime:       manifest.Runtime,
			WorkerRouting: manifest.WorkerRouting,
		}),
		sandbox.ProjectSandboxPolicyProxyCredentialCapabilityReadinessInput(sandbox.SandboxPolicyProxyCredentialCapabilityReadinessProjection{
			NetworkPolicyResult:       autoSandboxManifestNetworkPolicyResult(manifest.Security),
			NetworkProxySession:       manifest.NetworkProxySession,
			NetworkPolicyDecisionLogs: manifest.NetworkPolicyDecisionLogs,
			CredentialProxyPlan:       manifest.CredentialProxyPlan,
			CredentialProxySession:    manifest.CredentialProxySession,
			CredentialProxyBindings:   manifest.CredentialProxyBindings,
		}),
	)
	applyAutoSandboxReadinessDiagnostics(manifest.Security)
}

func applyAutoSandboxReadinessDiagnostics(security *sandbox.SandboxSecurity) {
	if security == nil || security.CapabilityReadiness == nil {
		if security != nil {
			security.CapabilityReadinessDiagnostics = nil
		}
		return
	}
	diagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*security.CapabilityReadiness)
	security.CapabilityReadinessDiagnostics = &diagnostics
}

func autoSandboxManifestNetworkPolicyResult(security *sandbox.SandboxSecurity) *sandbox.SandboxNetworkPolicyResult {
	if security == nil || security.Network == nil {
		return nil
	}
	return security.Network.PolicyResult
}
