package networkenforcement

import "context"

const (
	RuleProofLiveBuildTagName       = "network_enforcement_" + "live"
	RuleProofLiveEnvVarName         = "HAL_NETWORK_" + "ENFORCEMENT_LIVE"
	RuleProofLiveFirewallEnvVarName = RuleProofLiveEnvVarName + "_FIREWALL"
	RuleProofLiveRuntimeEnvVarName  = RuleProofLiveEnvVarName + "_RUNTIME"

	defaultFirewallRuleProofAdapterID = "firewall-rule-proof"
	defaultRuntimeRuleProofAdapterID  = "runtime-rule-proof"
)

// RuleProofStepRunner is the fakeable boundary for future firewall or runtime
// rule implementations. It receives only sanitized lifecycle request metadata.
type RuleProofStepRunner interface {
	RunRuleProofStep(context.Context, RuleProofStepRequest) (RuleLifecycleMetadata, error)
}

// RuleProofStepRequest carries sanitized operation context to a fake or future
// live rule proof runner.
type RuleProofStepRequest struct {
	Plan      SanitizedPlan         `json:"plan,omitempty"`
	Operation string                `json:"operation,omitempty"`
	Mechanism EnforcementMechanism  `json:"mechanism,omitempty"`
	Requested RuleLifecycleMetadata `json:"requested,omitempty"`
	Active    RuleLifecycleMetadata `json:"active,omitempty"`
}

// RuleProofAdapterOptions configure a disabled-by-default rule proof adapter.
// Callers must set Enabled and inject a Runner before any step can run.
type RuleProofAdapterOptions struct {
	AdapterID        string
	Enabled          bool
	Runner           RuleProofStepRunner
	CapabilityLabels []string
	WarningCodes     []LifecycleWarningCode
}

// RuleProofLiveGateInput is an explicit, testable live-gate seam. The package
// does not read process environment or build tags directly from this struct.
type RuleProofLiveGateInput struct {
	BuildTagEnabled bool
	NetworkEnabled  bool
	FirewallEnabled bool
	RuntimeEnabled  bool
}

// RuleProofLiveAdapterInput combines live-gate metadata with an injected
// runner. Missing gates produce a disabled adapter, not live mutation.
type RuleProofLiveAdapterInput struct {
	AdapterID        string
	Runner           RuleProofStepRunner
	Gate             RuleProofLiveGateInput
	CapabilityLabels []string
}

type ruleProofAdapter struct {
	adapterID        string
	mechanism        EnforcementMechanism
	enabled          bool
	runner           RuleProofStepRunner
	capabilityLabels []string
	warningCodes     []LifecycleWarningCode
}

// NewFirewallRuleProofAdapter returns a firewall-backed rule lifecycle adapter
// that remains disabled unless explicitly enabled and given a runner.
func NewFirewallRuleProofAdapter(options RuleProofAdapterOptions) RuleLifecycleAdapter {
	return newRuleProofAdapter(defaultFirewallRuleProofAdapterID, EnforcementMechanismFirewall, options)
}

// NewRuntimeRuleProofAdapter returns a runtime-backed rule lifecycle adapter
// that remains disabled unless explicitly enabled and given a runner.
func NewRuntimeRuleProofAdapter(options RuleProofAdapterOptions) RuleLifecycleAdapter {
	return newRuleProofAdapter(defaultRuntimeRuleProofAdapterID, EnforcementMechanismRuntime, options)
}

// NewGatedFirewallRuleProofAdapter returns a firewall adapter only when the
// explicit live gate metadata and runner are present.
func NewGatedFirewallRuleProofAdapter(input RuleProofLiveAdapterInput) RuleLifecycleAdapter {
	return NewFirewallRuleProofAdapter(RuleProofAdapterOptions{
		AdapterID:        input.AdapterID,
		Enabled:          ruleProofLiveGateAllows(input.Gate, EnforcementMechanismFirewall),
		Runner:           input.Runner,
		CapabilityLabels: input.CapabilityLabels,
		WarningCodes:     ruleProofLiveGateWarnings(input.Gate, EnforcementMechanismFirewall),
	})
}

// NewGatedRuntimeRuleProofAdapter returns a runtime adapter only when the
// explicit live gate metadata and runner are present.
func NewGatedRuntimeRuleProofAdapter(input RuleProofLiveAdapterInput) RuleLifecycleAdapter {
	return NewRuntimeRuleProofAdapter(RuleProofAdapterOptions{
		AdapterID:        input.AdapterID,
		Enabled:          ruleProofLiveGateAllows(input.Gate, EnforcementMechanismRuntime),
		Runner:           input.Runner,
		CapabilityLabels: input.CapabilityLabels,
		WarningCodes:     ruleProofLiveGateWarnings(input.Gate, EnforcementMechanismRuntime),
	})
}

func newRuleProofAdapter(defaultID string, mechanism EnforcementMechanism, options RuleProofAdapterOptions) RuleLifecycleAdapter {
	adapterID := sanitizeIdentifier(options.AdapterID)
	if adapterID == "" {
		adapterID = defaultID
	}
	return &ruleProofAdapter{
		adapterID:        adapterID,
		mechanism:        sanitizeRuleLifecycleMechanism(mechanism),
		enabled:          options.Enabled,
		runner:           options.Runner,
		capabilityLabels: sanitizeRuleLifecycleCapabilityLabels(options.CapabilityLabels),
		warningCodes:     sanitizeLifecycleWarningCodeList(options.WarningCodes),
	}
}

func (a *ruleProofAdapter) PlanNetworkRules(ctx context.Context, req RuleLifecycleRequest) (RuleLifecycleMetadata, error) {
	return a.runRuleProofStep(ctx, req, ruleOperationPlan, LifecycleStatusPlanned, LifecycleReasonPrepared)
}

func (a *ruleProofAdapter) ApplyNetworkRules(ctx context.Context, req RuleLifecycleRequest) (RuleLifecycleMetadata, error) {
	return a.runRuleProofStep(ctx, req, ruleOperationApply, LifecycleStatusApplying, LifecycleReasonApplied)
}

func (a *ruleProofAdapter) ActiveNetworkRules(ctx context.Context, req RuleLifecycleRequest) (RuleLifecycleMetadata, error) {
	return a.runRuleProofStep(ctx, req, ruleOperationActive, LifecycleStatusActive, LifecycleReasonActive)
}

func (a *ruleProofAdapter) RollbackNetworkRules(ctx context.Context, req RuleLifecycleRequest) (RuleLifecycleMetadata, error) {
	return a.runRuleProofStep(ctx, req, ruleOperationRollback, LifecycleStatusRollingBack, LifecycleReasonRollbackFailed)
}

func (a *ruleProofAdapter) CleanupNetworkRules(ctx context.Context, req RuleLifecycleRequest) (RuleLifecycleMetadata, error) {
	return a.runRuleProofStep(ctx, req, ruleOperationCleanup, LifecycleStatusStopped, LifecycleReasonStopped)
}

func (a *ruleProofAdapter) runRuleProofStep(ctx context.Context, req RuleLifecycleRequest, operation string, status LifecycleStatus, reason LifecycleReasonCode) (RuleLifecycleMetadata, error) {
	if !a.canRun() {
		metadata := a.ruleProofMetadata(req, RuleLifecycleMetadata{}, operation, LifecycleStatusFailed, LifecycleReasonAdapterUnsupported)
		metadata.WarningCodes = appendLifecycleWarnings(metadata.WarningCodes, LifecycleWarningMetadataOnlyFallback)
		return metadata, ruleProofAdapterError{operation: operation, reason: LifecycleReasonAdapterUnsupported}
	}

	stepReq := RuleProofStepRequest{
		Plan:      NewSanitizedPlan(req.Plan.Plan()),
		Operation: sanitizeIdentifier(operation),
		Mechanism: a.mechanism,
		Requested: sanitizeRuleLifecycleOnlyMetadata(req.Requested),
		Active:    sanitizeRuleLifecycleOnlyMetadata(req.Active),
	}
	metadata, err := a.runner.RunRuleProofStep(ctx, stepReq)
	if err != nil {
		failed := a.ruleProofMetadata(req, metadata, operation, LifecycleStatusFailed, LifecycleReasonAdapterFailed)
		failed.WarningCodes = appendLifecycleWarnings(failed.WarningCodes, LifecycleWarningSanitizedAdapterError)
		return failed, ruleProofAdapterError{operation: operation, reason: LifecycleReasonAdapterFailed}
	}
	return a.ruleProofMetadata(req, metadata, operation, status, reason), nil
}

func (a *ruleProofAdapter) canRun() bool {
	return a != nil &&
		a.enabled &&
		a.runner != nil &&
		sanitizeRuleLifecycleMechanism(a.mechanism) != ""
}

func (a *ruleProofAdapter) ruleProofMetadata(req RuleLifecycleRequest, metadata RuleLifecycleMetadata, operation string, status LifecycleStatus, reason LifecycleReasonCode) RuleLifecycleMetadata {
	plan := req.Plan.Plan()
	out := sanitizeRuleLifecycleOnlyMetadata(metadata)
	if out.ID == "" {
		out.ID = req.Requested.ID
	}
	if out.ID == "" && plan.PolicySnapshot != nil {
		out.ID = plan.PolicySnapshot.RuleSetID
	}
	if out.PlanID == "" {
		out.PlanID = plan.ID
	}
	if out.AdapterID == "" && a != nil {
		out.AdapterID = a.adapterID
	}
	if out.Status == "" || out.Status == LifecycleStatusFailed {
		out.Status = status
	}
	if a != nil && a.mechanism != "" {
		out.Mechanisms = []EnforcementMechanism{a.mechanism}
	} else {
		out.Mechanisms = sanitizeRuleLifecycleMechanisms(out.Mechanisms)
	}
	out.Operations = []string{sanitizeIdentifier(operation)}
	if out.PolicySnapshot == nil {
		out.PolicySnapshot = sanitizePolicySnapshotIdentityPtr(plan.PolicySnapshot)
	}
	if out.Status == LifecycleStatusActive && reason == LifecycleReasonActive {
		out.CapabilityLabels = appendRuleProofCapabilityLabels(ruleProofCapabilityLabelsForPlan(plan), out.CapabilityLabels...)
		if a != nil {
			out.CapabilityLabels = appendRuleProofCapabilityLabels(out.CapabilityLabels, a.capabilityLabels...)
		}
	} else {
		out.CapabilityLabels = nil
	}
	if a != nil {
		out.WarningCodes = appendLifecycleWarnings(out.WarningCodes, a.warningCodes...)
	}
	out.ReasonCode = reason
	return sanitizeRuleLifecycleOnlyMetadata(out)
}

type ruleProofAdapterError struct {
	operation string
	reason    LifecycleReasonCode
}

func (e ruleProofAdapterError) Error() string {
	operation := sanitizeIdentifier(e.operation)
	reason := sanitizeLifecycleReasonCode(e.reason)
	if operation == "" {
		operation = "rule_proof"
	}
	if reason == "" {
		reason = LifecycleReasonAdapterFailed
	}
	return "network rule proof " + operation + " " + string(reason)
}

func (e ruleProofAdapterError) ruleLifecycleReasonCode() LifecycleReasonCode {
	return sanitizeLifecycleReasonCode(e.reason)
}

func ruleProofLiveGateAllows(gate RuleProofLiveGateInput, mechanism EnforcementMechanism) bool {
	if !gate.BuildTagEnabled || !gate.NetworkEnabled {
		return false
	}
	switch sanitizeRuleLifecycleMechanism(mechanism) {
	case EnforcementMechanismFirewall:
		return gate.FirewallEnabled
	case EnforcementMechanismRuntime:
		return gate.RuntimeEnabled
	default:
		return false
	}
}

// RuleProofLiveGateAllows reports whether the explicit live build/env gate is
// complete for a firewall or runtime rule proof adapter.
func RuleProofLiveGateAllows(gate RuleProofLiveGateInput, mechanism EnforcementMechanism) bool {
	return ruleProofLiveGateAllows(gate, mechanism)
}

func ruleProofLiveGateWarnings(gate RuleProofLiveGateInput, mechanism EnforcementMechanism) []LifecycleWarningCode {
	if ruleProofLiveGateAllows(gate, mechanism) {
		return nil
	}
	return []LifecycleWarningCode{LifecycleWarningMetadataOnlyFallback}
}

func ruleProofCapabilityLabelsForPlan(plan Plan) []string {
	var labels []string
	if plan.DefaultPosture == DefaultPostureDenyByDefault {
		labels = appendRuleProofCapabilityLabels(labels, planOperationDefaultDeny)
	}
	if plan.Allowlist != nil {
		for _, category := range plan.Allowlist.RuleCategories {
			switch category {
			case AllowlistRuleCategoryDomain:
				labels = appendRuleProofCapabilityLabels(labels, "domain_rules", planOperationAllowlistDomain)
			case AllowlistRuleCategoryEndpoint:
				labels = appendRuleProofCapabilityLabels(labels, "endpoint_rules", planOperationAllowlistEndpoint)
			case AllowlistRuleCategoryPrivateRange:
				labels = appendRuleProofCapabilityLabels(labels, "private_range_rules", planOperationAllowlistPrivateRange)
			case AllowlistRuleCategoryMetadataEndpoint:
				labels = appendRuleProofCapabilityLabels(labels, "metadata_endpoint", "metadata_endpoint_rules", planOperationAllowlistMetadata)
			case AllowlistRuleCategoryLoopback:
				labels = appendRuleProofCapabilityLabels(labels, "loopback_rules", planOperationAllowlistLoopback)
			case AllowlistRuleCategoryLinkLocal:
				labels = appendRuleProofCapabilityLabels(labels, "link_local_rules", planOperationAllowlistLinkLocal)
			}
		}
	}
	if plan.Category != nil {
		if plan.Category.PrivateNetwork == PostureBlock {
			labels = appendRuleProofCapabilityLabels(labels, "private_range_rules", planOperationBlockPrivateNetwork)
		}
		if plan.Category.MetadataEndpoint == PostureBlock {
			labels = appendRuleProofCapabilityLabels(labels, "metadata_endpoint", "metadata_endpoint_rules", planOperationBlockMetadataEndpoint)
		}
	}
	if plan.RawProtocols != nil &&
		(plan.RawProtocols.TCP == PostureBlock || plan.RawProtocols.UDP == PostureBlock || plan.RawProtocols.ICMP == PostureBlock) {
		labels = appendRuleProofCapabilityLabels(labels, "raw_protocols", planOperationBlockRawProtocols)
	}
	if plan.Firewall != nil {
		for _, operation := range plan.Firewall.Operations {
			switch sanitizeIdentifier(operation) {
			case planOperationDefaultDeny:
				labels = appendRuleProofCapabilityLabels(labels, planOperationDefaultDeny)
			case planOperationBlockPrivateNetwork:
				labels = appendRuleProofCapabilityLabels(labels, "private_range_rules", planOperationBlockPrivateNetwork)
			case planOperationBlockMetadataEndpoint:
				labels = appendRuleProofCapabilityLabels(labels, "metadata_endpoint", "metadata_endpoint_rules", planOperationBlockMetadataEndpoint)
			case planOperationBlockRawProtocols:
				labels = appendRuleProofCapabilityLabels(labels, "raw_protocols", planOperationBlockRawProtocols)
			}
		}
	}
	return sanitizeRuleLifecycleCapabilityLabels(labels)
}

func appendRuleProofCapabilityLabels(existing []string, values ...string) []string {
	out := sanitizeRuleLifecycleCapabilityLabels(existing)
	for _, value := range values {
		for _, current := range sanitizeRuleLifecycleCapabilityLabels([]string{value}) {
			if current == "" || stringSliceContains(out, current) {
				continue
			}
			out = append(out, current)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
