package livegate

// EvaluateGate evaluates one live gate using only the explicit metadata in
// input. It is deterministic and does not inspect process environment, host
// state, files, providers, commands, or network resources.
func EvaluateGate(input GateEvaluationInput) GatePreflightResult {
	gate := SanitizeGate(input.Gate)
	requiredBuildTags := uniqueBuildTags(gate.BuildTags)
	requiredEnvVars := uniqueEnvVars(gate.EnvVars)
	requiredCapabilities := uniqueCapabilities(gate.Capabilities)
	enabledBuildTags := uniqueBuildTags(sanitizeBuildTagList(input.EnabledBuildTags))
	presentEnvVars := uniqueEnvVars(sanitizeEnvVarList(input.PresentEnvVars))
	availableCapabilities := uniqueCapabilities(sanitizeCapabilityIDList(input.AvailableCapabilities))

	result := GatePreflightResult{
		GateID:        gate.ID,
		Category:      gate.Category,
		ActionAllowed: true,
		Status:        RequirementStatusSatisfied,
	}
	var missingBuildTags []BuildTagName
	var missingEnvVars []EnvVarName
	var unavailableCapabilities []CapabilityID
	var firstSkipReason SkipReasonCode

	for _, buildTag := range requiredBuildTags {
		requirement := Requirement{
			Status:   RequirementStatusSatisfied,
			BuildTag: buildTag,
		}
		if !buildTagListContains(enabledBuildTags, buildTag) {
			requirement.Status = RequirementStatusMissing
			requirement.ReasonCode = SkipReasonMissingBuildTag
			missingBuildTags = appendUniqueBuildTag(missingBuildTags, buildTag)
			firstSkipReason = firstNonEmptySkipReason(firstSkipReason, SkipReasonMissingBuildTag)
		}
		result.Requirements = append(result.Requirements, requirement)
	}

	for _, envVar := range requiredEnvVars {
		requirement := Requirement{
			Status: RequirementStatusSatisfied,
			EnvVar: envVar,
		}
		if !envVarListContains(presentEnvVars, envVar) {
			requirement.Status = RequirementStatusMissing
			requirement.ReasonCode = SkipReasonMissingEnvVar
			missingEnvVars = appendUniqueEnvVar(missingEnvVars, envVar)
			firstSkipReason = firstNonEmptySkipReason(firstSkipReason, SkipReasonMissingEnvVar)
		}
		result.Requirements = append(result.Requirements, requirement)
	}

	for _, capability := range requiredCapabilities {
		requirement := CapabilityRequirement{
			ID:     capability,
			Status: RequirementStatusSatisfied,
		}
		if !capabilityListContains(availableCapabilities, capability) {
			requirement.Status = RequirementStatusUnavailable
			requirement.ReasonCode = SkipReasonCapabilityUnavailable
			unavailableCapabilities = appendUniqueCapability(unavailableCapabilities, capability)
			firstSkipReason = firstNonEmptySkipReason(firstSkipReason, SkipReasonCapabilityUnavailable)
		}
		result.CapabilityRequirements = append(result.CapabilityRequirements, requirement)
	}

	if firstSkipReason != "" {
		result.ActionAllowed = false
		result.Status = RequirementStatusSkipped
		result.SkipReason = firstSkipReason
		result.Remediation = gatePreflightRemediation(
			firstSkipReason,
			missingBuildTags,
			missingEnvVars,
			unavailableCapabilities,
		)
	}

	return SanitizeGatePreflightResult(result)
}

// PreflightGate is a semantic alias for EvaluateGate used by callers that want
// to emphasize that the result must be checked before optional live actions.
func PreflightGate(input GateEvaluationInput) GatePreflightResult {
	return EvaluateGate(input)
}

// CanRunLiveAction reports whether the sanitized result permits a live action.
func (r GatePreflightResult) CanRunLiveAction() bool {
	return SanitizeGatePreflightResult(r).ActionAllowed
}

// ShouldSkipLiveAction reports whether the sanitized result blocks a live
// action and should be converted into a test skip or equivalent preflight exit.
func (r GatePreflightResult) ShouldSkipLiveAction() bool {
	return !r.CanRunLiveAction()
}

func gatePreflightRemediation(reason SkipReasonCode, buildTags []BuildTagName, envVars []EnvVarName, capabilities []CapabilityID) *RemediationMetadata {
	remediation := RemediationMetadata{
		ReasonCode:    reason,
		BuildTags:     uniqueBuildTags(buildTags),
		EnvVars:       uniqueEnvVars(envVars),
		Capabilities:  uniqueCapabilities(capabilities),
		CommandLabels: gatePreflightCommandLabels(buildTags, envVars, capabilities),
	}
	remediation.CommandTemplates = gatePreflightCommandTemplates(remediation.BuildTags, remediation.EnvVars)
	sanitized := SanitizeRemediationMetadata(remediation)
	if remediationMetadataEmpty(sanitized) {
		return nil
	}
	return &sanitized
}

func gatePreflightCommandLabels(buildTags []BuildTagName, envVars []EnvVarName, capabilities []CapabilityID) []RemediationCommandLabel {
	var labels []RemediationCommandLabel
	if len(buildTags) > 0 {
		labels = appendUniqueRemediationCommandLabel(labels, RemediationEnableBuildTag)
	}
	if len(envVars) > 0 {
		labels = appendUniqueRemediationCommandLabel(labels, RemediationSetEnvVar)
	}
	if len(capabilities) > 0 {
		labels = appendUniqueRemediationCommandLabel(labels, RemediationInstallCapability)
	}
	return labels
}

func gatePreflightCommandTemplates(buildTags []BuildTagName, envVars []EnvVarName) []RemediationCommandTemplate {
	switch {
	case len(buildTags) > 0 && len(envVars) > 0:
		return []RemediationCommandTemplate{RemediationTemplateGoTestBuildTagsEnvVars}
	case len(buildTags) > 0:
		return []RemediationCommandTemplate{RemediationTemplateGoTestBuildTags}
	case len(envVars) > 0:
		return []RemediationCommandTemplate{RemediationTemplateGoTestEnvVars}
	default:
		return nil
	}
}

func firstNonEmptySkipReason(current, candidate SkipReasonCode) SkipReasonCode {
	if current != "" {
		return current
	}
	return candidate
}

func uniqueBuildTags(values []BuildTagName) []BuildTagName {
	if len(values) == 0 {
		return nil
	}
	out := make([]BuildTagName, 0, len(values))
	for _, value := range values {
		if value == "" || buildTagListContains(out, value) {
			continue
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func uniqueEnvVars(values []EnvVarName) []EnvVarName {
	if len(values) == 0 {
		return nil
	}
	out := make([]EnvVarName, 0, len(values))
	for _, value := range values {
		if value == "" || envVarListContains(out, value) {
			continue
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func uniqueCapabilities(values []CapabilityID) []CapabilityID {
	if len(values) == 0 {
		return nil
	}
	out := make([]CapabilityID, 0, len(values))
	for _, value := range values {
		if value == "" || capabilityListContains(out, value) {
			continue
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func buildTagListContains(values []BuildTagName, target BuildTagName) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func envVarListContains(values []EnvVarName, target EnvVarName) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func capabilityListContains(values []CapabilityID, target CapabilityID) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func appendUniqueBuildTag(values []BuildTagName, value BuildTagName) []BuildTagName {
	if value == "" || buildTagListContains(values, value) {
		return values
	}
	return append(values, value)
}

func appendUniqueEnvVar(values []EnvVarName, value EnvVarName) []EnvVarName {
	if value == "" || envVarListContains(values, value) {
		return values
	}
	return append(values, value)
}

func appendUniqueCapability(values []CapabilityID, value CapabilityID) []CapabilityID {
	if value == "" || capabilityListContains(values, value) {
		return values
	}
	return append(values, value)
}

func appendUniqueRemediationCommandLabel(values []RemediationCommandLabel, value RemediationCommandLabel) []RemediationCommandLabel {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
