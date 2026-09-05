package cmd

import (
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func commandSandboxNetworkEnforcementProofFromRuntimeMetadata(metadata *sandboxruntime.RuntimeNetworkEnforcementMetadata) *sandbox.SandboxNetworkEnforcementProofMetadata {
	rawResultOutcome := commandSandboxRuntimeNetworkEnforcementRawResultOutcome(metadata)
	metadata = sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(metadata)
	if metadata == nil || metadata.Result == nil {
		return nil
	}
	proof := sandbox.SandboxNetworkEnforcementProofMetadata{
		ResultOutcome:         metadata.Result.Outcome,
		ResultEnforcementMode: commandSandboxNetworkEnforcementModeLabel(metadata.Result.EnforcementMode),
		ResultSupported:       commandSandboxRuntimeNetworkEnforcementResultSupported(metadata.Result),
		WarningCount:          commandSandboxRuntimeNetworkEnforcementWarningCount(metadata),
	}
	if metadata.Plan != nil {
		proof.NetworkEnforcementPlanID = metadata.Plan.ID
		proof.PolicySnapshotID = metadata.Plan.PolicySnapshotID
	}
	if metadata.Orchestration != nil {
		orchestrationActive := commandSandboxRuntimeNetworkEnforcementOrchestrationActive(metadata.Orchestration)
		if proof.NetworkEnforcementPlanID == "" {
			proof.NetworkEnforcementPlanID = metadata.Orchestration.PlanID
		}
		if proof.PolicySnapshotID == "" {
			proof.PolicySnapshotID = metadata.Orchestration.PolicySnapshotID
		}
		if orchestrationActive && metadata.Orchestration.Proxy != nil {
			proxy := metadata.Orchestration.Proxy
			proof.NetworkProxySessionID = proxy.ID
			proof.ProxyLifecycleStatus = proxy.Status
			proof.ProxyLifecycleReasonCode = proxy.ReasonCode
			if proof.NetworkEnforcementPlanID == "" {
				proof.NetworkEnforcementPlanID = proxy.PlanID
			}
			if proof.PolicySnapshotID == "" {
				proof.PolicySnapshotID = proxy.PolicySnapshotID
			}
		}
		if orchestrationActive && !commandSandboxRuntimeNetworkEnforcementMetadataHasWarnings(metadata) {
			if rule := commandSandboxRuntimeNetworkEnforcementFirewallRule(metadata.Orchestration.Rules); rule != nil {
				proof.FirewallLifecycleStatus = rule.Status
				proof.FirewallLifecycleReasonCode = rule.ReasonCode
				if proof.NetworkEnforcementPlanID == "" {
					proof.NetworkEnforcementPlanID = rule.PlanID
				}
				if proof.PolicySnapshotID == "" {
					proof.PolicySnapshotID = rule.PolicySnapshotID
				}
			}
		}
	}
	if metadata.Result.PolicySnapshotID != "" {
		proof.PolicySnapshotID = metadata.Result.PolicySnapshotID
	}
	if metadata.Result.PlanID != "" {
		proof.NetworkEnforcementPlanID = metadata.Result.PlanID
	}
	if commandSandboxRuntimeNetworkEnforcementMetadataHasWarnings(metadata) {
		proof.ResultOutcome = "best_effort"
		proof.ResultSupported = false
	}
	if commandSandboxRuntimeNetworkEnforcementRawOutcomeIsUnsupported(rawResultOutcome) {
		proof.ResultOutcome = "unsupported"
		proof.ResultSupported = false
	}
	sanitized := sandbox.SanitizeSandboxNetworkEnforcementProofMetadata(proof)
	if sanitized.NetworkProxySessionID == "" &&
		sanitized.PolicySnapshotID == "" &&
		sanitized.NetworkEnforcementPlanID == "" &&
		sanitized.ProxyLifecycleStatus == "" &&
		sanitized.ProxyLifecycleReasonCode == "" &&
		sanitized.FirewallLifecycleStatus == "" &&
		sanitized.FirewallLifecycleReasonCode == "" &&
		sanitized.ResultOutcome == "" &&
		sanitized.ResultEnforcementMode == "" &&
		!sanitized.ResultSupported {
		return nil
	}
	return &sanitized
}

func commandSandboxRuntimeNetworkEnforcementRawResultOutcome(metadata *sandboxruntime.RuntimeNetworkEnforcementMetadata) string {
	if metadata == nil || metadata.Result == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(metadata.Result.Outcome))
}

func commandSandboxRuntimeNetworkEnforcementRawOutcomeIsUnsupported(outcome string) bool {
	switch outcome {
	case "", "success", "best_effort", "unsupported", "failure":
		return false
	default:
		return true
	}
}

func commandSandboxRuntimeNetworkEnforcementResultSupported(result *sandboxruntime.RuntimeNetworkEnforcementResultMetadata) bool {
	if result == nil {
		return false
	}
	capability := sandboxruntime.SanitizeRuntimeNetworkEnforcementCapability(result.Capability)
	return capability != nil && capability.Supported
}

func commandSandboxRuntimeNetworkEnforcementMetadataHasWarnings(metadata *sandboxruntime.RuntimeNetworkEnforcementMetadata) bool {
	return commandSandboxRuntimeNetworkEnforcementWarningCount(metadata) > 0
}

func commandSandboxRuntimeNetworkEnforcementWarningCount(metadata *sandboxruntime.RuntimeNetworkEnforcementMetadata) int {
	if metadata == nil {
		return 0
	}
	count := 0
	if metadata.Result != nil && len(metadata.Result.WarningCodes) > 0 {
		count += len(metadata.Result.WarningCodes)
	}
	if metadata.Orchestration == nil {
		return count
	}
	if len(metadata.Orchestration.WarningCodes) > 0 {
		count += len(metadata.Orchestration.WarningCodes)
	}
	if metadata.Orchestration.Proxy != nil && len(metadata.Orchestration.Proxy.WarningCodes) > 0 {
		count += len(metadata.Orchestration.Proxy.WarningCodes)
	}
	for _, rule := range metadata.Orchestration.Rules {
		if len(rule.WarningCodes) > 0 {
			count += len(rule.WarningCodes)
		}
	}
	return count
}

func commandSandboxRuntimeNetworkEnforcementOrchestrationActive(orchestration *sandboxruntime.RuntimeNetworkEnforcementOrchestrationMetadata) bool {
	return orchestration != nil &&
		orchestration.Status == "active" &&
		orchestration.ReasonCode == "active" &&
		len(orchestration.WarningCodes) == 0
}

func commandSandboxRuntimeNetworkEnforcementFirewallRule(rules []sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata) *sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata {
	for i := range rules {
		rule := &rules[i]
		for _, mechanism := range rule.Mechanisms {
			switch commandSandboxNetworkEnforcementModeLabel(mechanism) {
			case sandbox.SandboxNetworkEnforcementModeFirewall, sandbox.SandboxNetworkEnforcementModeRuntime:
				return rule
			}
		}
	}
	return nil
}
