package cmd

import (
	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
)

func loadConfiguredSandboxSecurityRequest(projectDir, runtimeDriver string) (sandbox.SecurityEvaluationRequest, error) {
	cfg, err := compound.LoadSandboxConfig(projectDir)
	if err != nil {
		return sandbox.SecurityEvaluationRequest{}, err
	}
	return sandboxSecurityRequestFromConfig(cfg, runtimeDriver), nil
}

func sandboxSecurityRequestFromConfig(cfg *compound.SandboxConfig, runtimeDriver string) sandbox.SecurityEvaluationRequest {
	intent := sandbox.SandboxSecurityIntent{
		RuntimeDriver:         runtimeDriver,
		CompatibilityAuthSync: true,
	}
	if cfg != nil {
		if cfg.NetworkPolicy != nil {
			networkPolicy := sandbox.CloneSandboxNetworkPolicyIntent(*cfg.NetworkPolicy)
			intent.NetworkPolicy = &networkPolicy
		}
		if cfg.Secrets != nil {
			intent.Secrets = &sandbox.SandboxSecretDeliveryIntent{
				RequestedModes: append([]string(nil), cfg.Secrets.RequestedModes...),
				ActiveModes:    append([]string(nil), cfg.Secrets.ActiveModes...),
			}
		}
	}
	return sandbox.MapSandboxSecurityIntent(intent)
}

func sandboxSecurityRequestOrDefault(req sandbox.SecurityEvaluationRequest, runtimeDriver string) sandbox.SecurityEvaluationRequest {
	if !emptySandboxSecurityEvaluationRequest(req) {
		return req
	}
	return sandboxSecurityRequestFromConfig(nil, runtimeDriver)
}

func emptySandboxSecurityEvaluationRequest(req sandbox.SecurityEvaluationRequest) bool {
	return req.RuntimeDriver == "" &&
		req.RequestedNetworkPolicy == "" &&
		req.RequestedNetworkPolicyIntent == nil &&
		req.NetworkPolicyCapability == nil &&
		len(req.RequestedSecretModes) == 0 &&
		len(req.ActiveSecretModes) == 0 &&
		!req.CompatibilityAuthSync
}
