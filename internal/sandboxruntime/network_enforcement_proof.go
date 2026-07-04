package sandboxruntime

// RuntimeNetworkEnforcementProofMetadata is the strict-readiness projection of
// sanitized Phase 56 runtime network enforcement metadata.
type RuntimeNetworkEnforcementProofMetadata struct {
	NetworkProxySessionID       string `json:"networkProxySessionId,omitempty"`
	PolicySnapshotID            string `json:"policySnapshotId,omitempty"`
	NetworkEnforcementPlanID    string `json:"networkEnforcementPlanId,omitempty"`
	ProxyLifecycleStatus        string `json:"proxyLifecycleStatus,omitempty"`
	ProxyLifecycleReasonCode    string `json:"proxyLifecycleReasonCode,omitempty"`
	FirewallLifecycleStatus     string `json:"firewallLifecycleStatus,omitempty"`
	FirewallLifecycleReasonCode string `json:"firewallLifecycleReasonCode,omitempty"`
	ResultOutcome               string `json:"resultOutcome,omitempty"`
	ResultEnforcementMode       string `json:"resultEnforcementMode,omitempty"`
	ResultSupported             bool   `json:"resultSupported,omitempty"`
	WarningCount                int    `json:"warningCount,omitempty"`
}

// ProjectRuntimeNetworkEnforcementProofMetadata extracts the strict-readiness
// evidence surface from runtime network metadata without carrying raw rules,
// sockets, provider names, endpoints, or operation payloads.
func ProjectRuntimeNetworkEnforcementProofMetadata(metadata *RuntimeNetworkEnforcementMetadata) RuntimeNetworkEnforcementProofMetadata {
	sanitized := SanitizeRuntimeNetworkEnforcementMetadata(metadata)
	if sanitized == nil {
		return RuntimeNetworkEnforcementProofMetadata{}
	}

	var proof RuntimeNetworkEnforcementProofMetadata
	if sanitized.Plan != nil {
		proof.NetworkEnforcementPlanID = runtimeNetworkEnforcementFirstSafeID(proof.NetworkEnforcementPlanID, sanitized.Plan.ID)
		proof.PolicySnapshotID = runtimeNetworkEnforcementFirstSafeID(proof.PolicySnapshotID, sanitized.Plan.PolicySnapshotID)
	}
	if sanitized.Orchestration != nil {
		proof.NetworkEnforcementPlanID = runtimeNetworkEnforcementFirstSafeID(proof.NetworkEnforcementPlanID, sanitized.Orchestration.PlanID)
		proof.PolicySnapshotID = runtimeNetworkEnforcementFirstSafeID(proof.PolicySnapshotID, sanitized.Orchestration.PolicySnapshotID)
		proof.WarningCount += len(sanitized.Orchestration.WarningCodes)
		if sanitized.Orchestration.Proxy != nil {
			proxy := sanitized.Orchestration.Proxy
			proof.NetworkProxySessionID = runtimeNetworkEnforcementFirstSafeID(proof.NetworkProxySessionID, proxy.ID)
			proof.NetworkEnforcementPlanID = runtimeNetworkEnforcementFirstSafeID(proof.NetworkEnforcementPlanID, proxy.PlanID)
			proof.PolicySnapshotID = runtimeNetworkEnforcementFirstSafeID(proof.PolicySnapshotID, proxy.PolicySnapshotID)
			proof.ProxyLifecycleStatus = runtimeNetworkEnforcementFirstSafeLabel(proof.ProxyLifecycleStatus, proxy.Status)
			proof.ProxyLifecycleReasonCode = runtimeNetworkEnforcementFirstSafeLabel(proof.ProxyLifecycleReasonCode, proxy.ReasonCode)
			proof.WarningCount += len(proxy.WarningCodes)
		}
		rule := runtimeNetworkEnforcementProofRule(sanitized.Orchestration.Rules)
		if rule != nil {
			proof.NetworkEnforcementPlanID = runtimeNetworkEnforcementFirstSafeID(proof.NetworkEnforcementPlanID, rule.PlanID)
			proof.PolicySnapshotID = runtimeNetworkEnforcementFirstSafeID(proof.PolicySnapshotID, rule.PolicySnapshotID)
			proof.FirewallLifecycleStatus = runtimeNetworkEnforcementFirstSafeLabel(proof.FirewallLifecycleStatus, rule.Status)
			proof.FirewallLifecycleReasonCode = runtimeNetworkEnforcementFirstSafeLabel(proof.FirewallLifecycleReasonCode, rule.ReasonCode)
		}
		for _, rule := range sanitized.Orchestration.Rules {
			proof.WarningCount += len(rule.WarningCodes)
		}
	}
	if sanitized.Result != nil {
		proof.NetworkEnforcementPlanID = runtimeNetworkEnforcementFirstSafeID(proof.NetworkEnforcementPlanID, sanitized.Result.PlanID)
		proof.PolicySnapshotID = runtimeNetworkEnforcementFirstSafeID(proof.PolicySnapshotID, sanitized.Result.PolicySnapshotID)
		proof.ResultOutcome = runtimeNetworkEnforcementFirstSafeLabel(proof.ResultOutcome, sanitized.Result.Outcome)
		proof.ResultEnforcementMode = runtimeNetworkEnforcementFirstSafeLabel(proof.ResultEnforcementMode, sanitized.Result.EnforcementMode)
		proof.ResultSupported = sanitized.Result.Capability != nil && sanitized.Result.Capability.Supported
		proof.WarningCount += len(sanitized.Result.WarningCodes)
	}

	return sanitizeRuntimeNetworkEnforcementProofMetadata(proof)
}

func RuntimeNetworkEnforcementProofHasActiveProxy(proof RuntimeNetworkEnforcementProofMetadata) bool {
	sanitized := sanitizeRuntimeNetworkEnforcementProofMetadata(proof)
	return sanitized.NetworkProxySessionID != "" &&
		sanitized.ProxyLifecycleStatus == "active" &&
		sanitized.ProxyLifecycleReasonCode == "active"
}

func RuntimeNetworkEnforcementProofHasActiveFirewallOrRuntimeRule(proof RuntimeNetworkEnforcementProofMetadata) bool {
	sanitized := sanitizeRuntimeNetworkEnforcementProofMetadata(proof)
	return sanitized.FirewallLifecycleStatus == "active" &&
		sanitized.FirewallLifecycleReasonCode == "active"
}

func RuntimeNetworkEnforcementProofHasWarnings(proof RuntimeNetworkEnforcementProofMetadata) bool {
	return sanitizeRuntimeNetworkEnforcementProofMetadata(proof).WarningCount > 0
}

func RuntimeNetworkEnforcementProofProvesActiveProxyFirewall(proof RuntimeNetworkEnforcementProofMetadata) bool {
	sanitized := sanitizeRuntimeNetworkEnforcementProofMetadata(proof)
	return sanitized.NetworkProxySessionID != "" &&
		sanitized.PolicySnapshotID != "" &&
		sanitized.NetworkEnforcementPlanID != "" &&
		RuntimeNetworkEnforcementProofHasActiveProxy(sanitized) &&
		RuntimeNetworkEnforcementProofHasActiveFirewallOrRuntimeRule(sanitized) &&
		sanitized.ResultOutcome == "success" &&
		sanitized.ResultEnforcementMode == "proxy_firewall" &&
		sanitized.ResultSupported &&
		sanitized.WarningCount == 0
}

func runtimeNetworkEnforcementProofRule(rules []RuntimeNetworkEnforcementLifecycleMetadata) *RuntimeNetworkEnforcementLifecycleMetadata {
	for i := range rules {
		if !runtimeNetworkEnforcementProofRuleMechanism(rules[i]) {
			continue
		}
		if rules[i].Status == "active" && rules[i].ReasonCode == "active" {
			return &rules[i]
		}
	}
	for i := range rules {
		if runtimeNetworkEnforcementProofRuleMechanism(rules[i]) {
			return &rules[i]
		}
	}
	return nil
}

func runtimeNetworkEnforcementProofRuleMechanism(rule RuntimeNetworkEnforcementLifecycleMetadata) bool {
	return runtimeNetworkEnforcementStringListContains(rule.Mechanisms, "firewall") ||
		runtimeNetworkEnforcementStringListContains(rule.Mechanisms, "runtime")
}

func sanitizeRuntimeNetworkEnforcementProofMetadata(proof RuntimeNetworkEnforcementProofMetadata) RuntimeNetworkEnforcementProofMetadata {
	return RuntimeNetworkEnforcementProofMetadata{
		NetworkProxySessionID:       sanitizeRuntimeNetworkEnforcementID(proof.NetworkProxySessionID),
		PolicySnapshotID:            sanitizeRuntimeNetworkEnforcementID(proof.PolicySnapshotID),
		NetworkEnforcementPlanID:    sanitizeRuntimeNetworkEnforcementID(proof.NetworkEnforcementPlanID),
		ProxyLifecycleStatus:        sanitizeRuntimeNetworkEnforcementLifecycleStatus(proof.ProxyLifecycleStatus),
		ProxyLifecycleReasonCode:    sanitizeRuntimeNetworkEnforcementLifecycleReasonCode(proof.ProxyLifecycleReasonCode),
		FirewallLifecycleStatus:     sanitizeRuntimeNetworkEnforcementLifecycleStatus(proof.FirewallLifecycleStatus),
		FirewallLifecycleReasonCode: sanitizeRuntimeNetworkEnforcementLifecycleReasonCode(proof.FirewallLifecycleReasonCode),
		ResultOutcome:               sanitizeRuntimeNetworkEnforcementOutcome(proof.ResultOutcome),
		ResultEnforcementMode:       sanitizeRuntimeNetworkEnforcementMode(proof.ResultEnforcementMode),
		ResultSupported:             proof.ResultSupported,
		WarningCount:                sanitizeRuntimeNetworkEnforcementProofWarningCount(proof.WarningCount),
	}
}

func runtimeNetworkEnforcementFirstSafeID(current string, candidates ...string) string {
	if current != "" {
		return current
	}
	for _, candidate := range candidates {
		if sanitized := sanitizeRuntimeNetworkEnforcementID(candidate); sanitized != "" {
			return sanitized
		}
	}
	return ""
}

func runtimeNetworkEnforcementFirstSafeLabel(current string, candidates ...string) string {
	if current != "" {
		return current
	}
	for _, candidate := range candidates {
		if candidate != "" {
			return candidate
		}
	}
	return ""
}

func sanitizeRuntimeNetworkEnforcementProofWarningCount(count int) int {
	if count < 0 {
		return 0
	}
	if count > 1000 {
		return 1000
	}
	return count
}
