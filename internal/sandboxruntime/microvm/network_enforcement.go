package microvm

import (
	"context"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

// NetworkEnforcementPlanning is the explicit runtime-owned planning surface
// for network enforcement metadata. A nil value keeps microVM construction
// metadata-only and does not call a planner or adapter.
type NetworkEnforcementPlanning struct {
	Request       networkenforcement.PlanRequest
	Planner       networkenforcement.Planner
	Adapter       networkenforcement.Adapter
	Orchestration *networkenforcement.LiveLifecycleMetadata
}

// NetworkEnforcementLiveOptions configures the fakeable live microVM network
// enforcement path. The caller must provide both a proxy listener adapter and
// a firewall/runtime rule runner, plus explicit build/env gate metadata.
type NetworkEnforcementLiveOptions struct {
	Request              networkenforcement.PlanRequest
	Planner              networkenforcement.Planner
	ProxyListener        networkenforcement.ProxyListenerAdapter
	RuleRunner           networkenforcement.RuleProofStepRunner
	RuleMechanism        networkenforcement.EnforcementMechanism
	RuleAdapterID        string
	RuleCapabilityLabels []string
	RuleGate             networkenforcement.RuleProofLiveGateInput
}

type networkEnforcementLifecycleAdapter interface {
	EnforceNetworkWithLifecycle(context.Context, networkenforcement.SanitizedPlan) networkenforcement.LiveEnforcementRun
}

// NewLiveNetworkEnforcementPlanning builds the default live wiring surface. It
// uses the package build tag state from networkenforcement, so default builds
// remain metadata-only even when caller-supplied environment gates are true.
func NewLiveNetworkEnforcementPlanning(options NetworkEnforcementLiveOptions) *NetworkEnforcementPlanning {
	options.RuleGate.BuildTagEnabled = networkenforcement.RuleProofLiveBuildTagEnabled()
	return NewGatedNetworkEnforcementPlanning(options)
}

// NewGatedNetworkEnforcementPlanning builds the fakeable live wiring surface
// from explicit gate metadata. It is useful for tests and higher-level runtime
// code that has already projected build/env gates into safe booleans.
func NewGatedNetworkEnforcementPlanning(options NetworkEnforcementLiveOptions) *NetworkEnforcementPlanning {
	return &NetworkEnforcementPlanning{
		Request: options.Request,
		Planner: options.Planner,
		Adapter: networkEnforcementLiveAdapter(options),
	}
}

func networkEnforcementMetadataFromDriverOptions(options DriverOptions) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	plan := options.NetworkEnforcementPlan
	orchestration := options.NetworkEnforcementOrchestration
	result := options.NetworkEnforcementResult
	if options.NetworkEnforcement != nil {
		planned, enforced, lifecycle := runNetworkEnforcementPlanning(context.Background(), options.NetworkEnforcement)
		plan = planned
		result = enforced
		if options.NetworkEnforcement.Orchestration != nil {
			orchestration = options.NetworkEnforcement.Orchestration
		} else if lifecycle != nil {
			orchestration = lifecycle
		}
	}
	return networkEnforcementMetadataFromPlanResultOrchestration(plan, orchestration, result)
}

func runNetworkEnforcementPlanning(ctx context.Context, planning *NetworkEnforcementPlanning) (*networkenforcement.Plan, *networkenforcement.Result, *networkenforcement.LiveLifecycleMetadata) {
	if planning == nil {
		return nil, nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	plan := networkenforcement.RunPlanner(planning.Planner, planning.Request)
	result, lifecycle := runNetworkEnforcementAdapter(ctx, planning.Adapter, plan)
	return &plan, &result, lifecycle
}

func runNetworkEnforcementAdapter(ctx context.Context, adapter networkenforcement.Adapter, plan networkenforcement.Plan) (networkenforcement.Result, *networkenforcement.LiveLifecycleMetadata) {
	if liveAdapter, ok := adapter.(networkEnforcementLifecycleAdapter); ok {
		run := liveAdapter.EnforceNetworkWithLifecycle(ctx, networkenforcement.NewSanitizedPlan(plan))
		result := networkenforcement.SanitizeResult(run.Result)
		lifecycle := networkenforcement.SanitizeLiveLifecycleMetadata(run.Lifecycle)
		return result, &lifecycle
	}
	result := networkenforcement.RunAdapter(ctx, adapter, plan)
	return result, nil
}

func networkEnforcementLiveAdapter(options NetworkEnforcementLiveOptions) networkenforcement.Adapter {
	mechanism := networkEnforcementLiveRuleMechanism(options.RuleMechanism)
	if !networkenforcement.RuleProofLiveGateAllows(options.RuleGate, mechanism) ||
		options.ProxyListener == nil ||
		options.RuleRunner == nil {
		return networkenforcement.LiveEnforcementRunner{}
	}
	return networkenforcement.LiveEnforcementRunner{
		Listener: networkenforcement.ProxyListenerLifecycleRunner{
			Adapter: options.ProxyListener,
		},
		Rules: networkenforcement.RuleLifecycleRunner{
			Adapter: networkEnforcementLiveRuleAdapter(options, mechanism),
		},
	}
}

func networkEnforcementLiveRuleAdapter(options NetworkEnforcementLiveOptions, mechanism networkenforcement.EnforcementMechanism) networkenforcement.RuleLifecycleAdapter {
	input := networkenforcement.RuleProofLiveAdapterInput{
		AdapterID:        options.RuleAdapterID,
		Runner:           options.RuleRunner,
		Gate:             options.RuleGate,
		CapabilityLabels: options.RuleCapabilityLabels,
	}
	switch mechanism {
	case networkenforcement.EnforcementMechanismRuntime:
		return networkenforcement.NewGatedRuntimeRuleProofAdapter(input)
	default:
		return networkenforcement.NewGatedFirewallRuleProofAdapter(input)
	}
}

func networkEnforcementLiveRuleMechanism(mechanism networkenforcement.EnforcementMechanism) networkenforcement.EnforcementMechanism {
	switch mechanism {
	case networkenforcement.EnforcementMechanismRuntime:
		return networkenforcement.EnforcementMechanismRuntime
	default:
		return networkenforcement.EnforcementMechanismFirewall
	}
}

func networkEnforcementMetadataFromPlanResult(plan *networkenforcement.Plan, result *networkenforcement.Result) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	return networkEnforcementMetadataFromPlanResultOrchestration(plan, nil, result)
}

func networkEnforcementMetadataFromPlanResultOrchestration(plan *networkenforcement.Plan, orchestration *networkenforcement.LiveLifecycleMetadata, result *networkenforcement.Result) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	metadata := &sandboxruntime.RuntimeNetworkEnforcementMetadata{}
	if plan != nil {
		metadata.Plan = networkEnforcementPlanMetadata(*plan)
	}
	if orchestration != nil {
		metadata.Orchestration = networkEnforcementOrchestrationMetadata(*orchestration)
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

func networkEnforcementOrchestrationMetadata(metadata networkenforcement.LiveLifecycleMetadata) *sandboxruntime.RuntimeNetworkEnforcementOrchestrationMetadata {
	metadata = networkenforcement.SanitizeLiveLifecycleMetadata(metadata)
	out := &sandboxruntime.RuntimeNetworkEnforcementOrchestrationMetadata{
		PlanID:           metadata.PlanID,
		AdapterID:        metadata.AdapterID,
		Status:           string(metadata.Status),
		Mechanisms:       networkEnforcementMechanisms(metadata.Mechanisms),
		Operations:       networkEnforcementStrings(metadata.Operations),
		Proxy:            networkEnforcementProxyLifecycleMetadata(metadata.Proxy),
		Rules:            networkEnforcementRuleLifecycleMetadata(metadata.Rules),
		CapabilityLabels: networkEnforcementStrings(metadata.CapabilityLabels),
		ReasonCode:       string(metadata.ReasonCode),
		WarningCodes:     networkEnforcementLifecycleWarningCodes(metadata.WarningCodes),
	}
	if metadata.PolicySnapshot != nil {
		out.PolicySnapshotID = metadata.PolicySnapshot.ID
		out.PolicyPreset = string(metadata.PolicySnapshot.Preset)
	}
	return out
}

func networkEnforcementProxyLifecycleMetadata(metadata *networkenforcement.ProxyListenerLifecycleMetadata) *sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata {
	if metadata == nil {
		return nil
	}
	sanitized := networkenforcement.SanitizeProxyListenerLifecycleMetadata(*metadata)
	out := &sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata{
		ID:               sanitized.ID,
		PlanID:           sanitized.PlanID,
		AdapterID:        sanitized.AdapterID,
		Status:           string(sanitized.Status),
		Mechanisms:       networkEnforcementMechanisms(sanitized.Mechanisms),
		Operations:       networkEnforcementStrings(sanitized.Operations),
		CapabilityLabels: networkEnforcementStrings(sanitized.CapabilityLabels),
		ReasonCode:       string(sanitized.ReasonCode),
		WarningCodes:     networkEnforcementLifecycleWarningCodes(sanitized.WarningCodes),
	}
	if sanitized.PolicySnapshot != nil {
		out.PolicySnapshotID = sanitized.PolicySnapshot.ID
		out.PolicyPreset = string(sanitized.PolicySnapshot.Preset)
	}
	return out
}

func networkEnforcementRuleLifecycleMetadata(values []networkenforcement.RuleLifecycleMetadata) []sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata {
	if len(values) == 0 {
		return nil
	}
	out := make([]sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata, 0, len(values))
	for _, value := range values {
		sanitized := networkenforcement.SanitizeRuleLifecycleMetadata(value)
		metadata := sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata{
			ID:               sanitized.ID,
			PlanID:           sanitized.PlanID,
			AdapterID:        sanitized.AdapterID,
			Status:           string(sanitized.Status),
			Mechanisms:       networkEnforcementMechanisms(sanitized.Mechanisms),
			Operations:       networkEnforcementStrings(sanitized.Operations),
			CapabilityLabels: networkEnforcementStrings(sanitized.CapabilityLabels),
			ReasonCode:       string(sanitized.ReasonCode),
			WarningCodes:     networkEnforcementLifecycleWarningCodes(sanitized.WarningCodes),
		}
		if sanitized.PolicySnapshot != nil {
			metadata.PolicySnapshotID = sanitized.PolicySnapshot.ID
			metadata.PolicyPreset = string(sanitized.PolicySnapshot.Preset)
		}
		out = append(out, metadata)
	}
	return out
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

func networkEnforcementLifecycleWarningCodes(values []networkenforcement.LifecycleWarningCode) []string {
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
