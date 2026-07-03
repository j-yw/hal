package microvm

import (
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

func networkEnforcementMetadataFromPlanResult(plan *networkenforcement.Plan, result *networkenforcement.Result) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	metadata := &sandboxruntime.RuntimeNetworkEnforcementMetadata{}
	if plan != nil {
		metadata.Plan = networkEnforcementPlanMetadata(*plan)
	}
	if result != nil {
		metadata.Result = networkEnforcementResultMetadata(*result)
	}
	return sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(metadata)
}

func networkEnforcementPlanMetadata(plan networkenforcement.Plan) *sandboxruntime.RuntimeNetworkEnforcementPlanMetadata {
	plan = networkenforcement.SanitizePlan(plan)
	metadata := &sandboxruntime.RuntimeNetworkEnforcementPlanMetadata{
		ID:             plan.ID,
		Source:         string(plan.Source),
		Operation:      plan.Operation,
		PolicyPreset:   networkEnforcementPlanPolicyPreset(plan),
		DefaultPosture: string(plan.DefaultPosture),
		Mechanisms:     networkEnforcementPlanMechanisms(plan),
		Operations:     networkEnforcementPlanOperations(plan),
	}
	if plan.PolicySnapshot != nil {
		metadata.PolicySnapshotID = plan.PolicySnapshot.ID
	}
	return metadata
}

func networkEnforcementPlanPolicyPreset(plan networkenforcement.Plan) string {
	if plan.PolicySnapshot == nil {
		return ""
	}
	return string(plan.PolicySnapshot.Preset)
}

func networkEnforcementPlanMechanisms(plan networkenforcement.Plan) []string {
	var mechanisms []string
	if plan.Proxy != nil && plan.Proxy.Mechanism != "" {
		mechanisms = append(mechanisms, string(plan.Proxy.Mechanism))
	}
	if plan.Firewall != nil && plan.Firewall.Mechanism != "" {
		mechanisms = append(mechanisms, string(plan.Firewall.Mechanism))
	}
	return mechanisms
}

func networkEnforcementPlanOperations(plan networkenforcement.Plan) []string {
	var operations []string
	if plan.Allowlist != nil {
		operations = append(operations, plan.Allowlist.Operations...)
	}
	if plan.Proxy != nil {
		operations = append(operations, plan.Proxy.Operations...)
	}
	if plan.Firewall != nil {
		operations = append(operations, plan.Firewall.Operations...)
	}
	return operations
}

func networkEnforcementResultMetadata(result networkenforcement.Result) *sandboxruntime.RuntimeNetworkEnforcementResultMetadata {
	result = networkenforcement.SanitizeResult(result)
	metadata := &sandboxruntime.RuntimeNetworkEnforcementResultMetadata{
		PlanID:          result.PlanID,
		AdapterID:       result.AdapterID,
		Outcome:         string(result.Outcome),
		EnforcementMode: string(result.EnforcementMode),
		Mechanisms:      networkEnforcementMechanisms(result.Mechanisms),
		Operations:      networkEnforcementStrings(result.Operations),
		PolicyPreset:    networkEnforcementResultPolicyPreset(result),
		Capability:      networkEnforcementCapability(result.Capability),
		ReasonCode:      string(result.ReasonCode),
		WarningCodes:    networkEnforcementWarningCodes(result.WarningCodes),
	}
	if result.PolicySnapshot != nil {
		metadata.PolicySnapshotID = result.PolicySnapshot.ID
	}
	return metadata
}

func networkEnforcementResultPolicyPreset(result networkenforcement.Result) string {
	if result.PolicySnapshot == nil {
		return ""
	}
	return string(result.PolicySnapshot.Preset)
}

func networkEnforcementCapability(capability *networkenforcement.ResultCapability) *sandboxruntime.RuntimeNetworkEnforcementCapability {
	if capability == nil {
		return nil
	}
	return &sandboxruntime.RuntimeNetworkEnforcementCapability{
		Supported:                  capability.Supported,
		Modes:                      networkEnforcementModes(capability.Modes),
		SupportsDomainRules:        capability.SupportsDomainRules,
		SupportsEndpointRules:      capability.SupportsEndpointRules,
		SupportsPrivateRangeRules:  capability.SupportsPrivateRangeRules,
		SupportsMetadataEndpoint:   capability.SupportsMetadataEndpoint,
		SupportsLoopbackRules:      capability.SupportsLoopbackRules,
		SupportsLinkLocalRules:     capability.SupportsLinkLocalRules,
		SupportsDefaultDenyPosture: capability.SupportsDefaultDenyPosture,
	}
}

func networkEnforcementMechanisms(values []networkenforcement.EnforcementMechanism) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func networkEnforcementModes(values []networkenforcement.ResultMode) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func networkEnforcementWarningCodes(values []networkenforcement.ResultWarningCode) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func networkEnforcementStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}
