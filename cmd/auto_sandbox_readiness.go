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
			return
		}
		manifest.Security.CapabilityReadiness = &sanitized
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
}

func autoSandboxManifestNetworkPolicyResult(security *sandbox.SandboxSecurity) *sandbox.SandboxNetworkPolicyResult {
	if security == nil || security.Network == nil {
		return nil
	}
	return security.Network.PolicyResult
}
