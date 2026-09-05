package sandbox

// SanitizeSandboxCredentialProxyPlanMetadata returns a durable-safe copy of
// credential proxy plan metadata. A missing or unsafe required ID returns the
// zero value so callers can omit the record before persistence.
func SanitizeSandboxCredentialProxyPlanMetadata(plan SandboxCredentialProxyPlanMetadata) SandboxCredentialProxyPlanMetadata {
	sanitized := NormalizeSandboxCredentialProxyPlanMetadata(plan)
	sanitized.ID = sanitizeSandboxCredentialProxyIdentifier(sanitized.ID)
	if sanitized.ID == "" {
		return SandboxCredentialProxyPlanMetadata{}
	}
	sanitized.Source = sanitizeSandboxCredentialProxySourceValue(sanitized.Source)
	sanitized.SecretBrokerSessionID = sanitizeSandboxCredentialProxyIdentifier(sanitized.SecretBrokerSessionID)
	sanitized.NetworkProxySessionID = sanitizeSandboxCredentialProxyIdentifier(sanitized.NetworkProxySessionID)
	sanitized.PolicySnapshot = sanitizeSandboxCredentialProxyPolicySnapshotIdentityPtr(sanitized.PolicySnapshot)
	sanitized.Mode = sanitizeSandboxCredentialProxyModeValue(sanitized.Mode)
	sanitized.Status = sanitizeSandboxCredentialProxyStatusValue(sanitized.Status)
	return sanitized
}

// SanitizeSandboxCredentialProxySessionMetadata returns a durable-safe copy of
// credential proxy session metadata. A missing or unsafe session ID or plan ID
// returns the zero value so callers can omit the record before persistence.
func SanitizeSandboxCredentialProxySessionMetadata(session SandboxCredentialProxySessionMetadata) SandboxCredentialProxySessionMetadata {
	sanitized := NormalizeSandboxCredentialProxySessionMetadata(session)
	sanitized.ID = sanitizeSandboxCredentialProxyIdentifier(sanitized.ID)
	sanitized.PlanID = sanitizeSandboxCredentialProxyIdentifier(sanitized.PlanID)
	if sanitized.ID == "" || sanitized.PlanID == "" {
		return SandboxCredentialProxySessionMetadata{}
	}
	sanitized.Source = sanitizeSandboxCredentialProxySourceValue(sanitized.Source)
	sanitized.SecretBrokerSessionID = sanitizeSandboxCredentialProxyIdentifier(sanitized.SecretBrokerSessionID)
	sanitized.NetworkProxySessionID = sanitizeSandboxCredentialProxyIdentifier(sanitized.NetworkProxySessionID)
	sanitized.PolicySnapshot = sanitizeSandboxCredentialProxyPolicySnapshotIdentityPtr(sanitized.PolicySnapshot)
	sanitized.Status = sanitizeSandboxCredentialProxyStatusValue(sanitized.Status)
	sanitized.WarningCode = sanitizeSandboxCredentialProxyWarningCodeValue(sanitized.WarningCode)
	sanitized.ReasonCode = sanitizeSandboxCredentialProxyReasonCodeValue(sanitized.ReasonCode)
	return sanitized
}

// SanitizeSandboxCredentialProxyBindingMetadata returns a durable-safe copy of
// credential proxy binding metadata. Missing or unsafe required IDs return the
// zero value so callers can omit the record before persistence.
func SanitizeSandboxCredentialProxyBindingMetadata(binding SandboxCredentialProxyBindingMetadata) SandboxCredentialProxyBindingMetadata {
	sanitized := NormalizeSandboxCredentialProxyBindingMetadata(binding)
	sanitized.ID = sanitizeSandboxCredentialProxyIdentifier(sanitized.ID)
	sanitized.PlanID = sanitizeSandboxCredentialProxyIdentifier(sanitized.PlanID)
	sanitized.SessionID = sanitizeSandboxCredentialProxyIdentifier(sanitized.SessionID)
	sanitized.SecretID = sanitizeSandboxCredentialProxySecretReference(sanitized.SecretID)
	if sanitized.ID == "" || sanitized.SecretID == "" || (sanitized.PlanID == "" && sanitized.SessionID == "") {
		return SandboxCredentialProxyBindingMetadata{}
	}
	sanitized.DeliveryMode = sanitizeSandboxCredentialProxyDeliveryModeValue(sanitized.DeliveryMode)
	sanitized.RequestCategory = sanitizeSandboxCredentialProxyRequestCategoryValue(sanitized.RequestCategory)
	sanitized.DestinationCategory = sanitizeSandboxCredentialProxyDestinationCategoryValue(sanitized.DestinationCategory)
	sanitized.Outcome = sanitizeSandboxCredentialProxyBindingOutcomeValue(sanitized.Outcome)
	sanitized.Status = sanitizeSandboxCredentialProxyStatusValue(sanitized.Status)
	sanitized.ReasonCode = sanitizeSandboxCredentialProxyReasonCodeValue(sanitized.ReasonCode)
	return sanitized
}

// SanitizeSandboxCredentialProxyPlanMetadataRecords returns durable-safe plan
// metadata records, omitting entries whose required IDs are not safe.
func SanitizeSandboxCredentialProxyPlanMetadataRecords(plans []SandboxCredentialProxyPlanMetadata) []SandboxCredentialProxyPlanMetadata {
	if len(plans) == 0 {
		return nil
	}
	sanitized := make([]SandboxCredentialProxyPlanMetadata, 0, len(plans))
	for _, plan := range plans {
		record := SanitizeSandboxCredentialProxyPlanMetadata(plan)
		if record.ID != "" {
			sanitized = append(sanitized, record)
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

// SanitizeSandboxCredentialProxySessionMetadataRecords returns durable-safe
// session metadata records, omitting entries whose required IDs are not safe.
func SanitizeSandboxCredentialProxySessionMetadataRecords(sessions []SandboxCredentialProxySessionMetadata) []SandboxCredentialProxySessionMetadata {
	if len(sessions) == 0 {
		return nil
	}
	sanitized := make([]SandboxCredentialProxySessionMetadata, 0, len(sessions))
	for _, session := range sessions {
		record := SanitizeSandboxCredentialProxySessionMetadata(session)
		if record.ID != "" {
			sanitized = append(sanitized, record)
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

// SanitizeSandboxCredentialProxyBindingMetadataRecords returns durable-safe
// binding metadata records, omitting entries whose required IDs are not safe.
func SanitizeSandboxCredentialProxyBindingMetadataRecords(bindings []SandboxCredentialProxyBindingMetadata) []SandboxCredentialProxyBindingMetadata {
	if len(bindings) == 0 {
		return nil
	}
	sanitized := make([]SandboxCredentialProxyBindingMetadata, 0, len(bindings))
	for _, binding := range bindings {
		record := SanitizeSandboxCredentialProxyBindingMetadata(binding)
		if record.ID != "" {
			sanitized = append(sanitized, record)
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeSandboxCredentialProxyPolicySnapshotIdentityPtr(snapshot *SandboxNetworkPolicySnapshotIdentity) *SandboxNetworkPolicySnapshotIdentity {
	if snapshot == nil {
		return nil
	}
	sanitized := SandboxNetworkPolicySnapshotIdentity{
		ID:        sanitizeSandboxCredentialProxyIdentifier(snapshot.ID),
		Version:   sanitizeSandboxCredentialProxyIdentifier(snapshot.Version),
		Preset:    sanitizeSandboxCredentialProxyPolicyPresetValue(snapshot.Preset),
		RuleSetID: sanitizeSandboxCredentialProxyIdentifier(snapshot.RuleSetID),
	}
	if sanitized.ID == "" {
		return nil
	}
	return &sanitized
}

func sanitizeSandboxCredentialProxyIdentifier(value string) string {
	if value == "" || unsafeSandboxCredentialProxyIdentifier(value) {
		return ""
	}
	return value
}

func sanitizeSandboxCredentialProxySecretReference(value string) string {
	if value == "" || unsafeSandboxCredentialProxySecretReference(value) {
		return ""
	}
	return value
}

func sanitizeSandboxCredentialProxySourceValue(source SandboxCredentialProxySource) SandboxCredentialProxySource {
	source = normalizeSandboxCredentialProxySource(source)
	if !validSandboxCredentialProxySource(string(source)) {
		return ""
	}
	return source
}

func sanitizeSandboxCredentialProxyModeValue(mode SandboxCredentialProxyMode) SandboxCredentialProxyMode {
	mode = normalizeSandboxCredentialProxyMode(mode)
	if mode != "" && !validSandboxCredentialProxyMode(string(mode)) {
		return ""
	}
	return mode
}

func sanitizeSandboxCredentialProxyStatusValue(status SandboxCredentialProxyStatus) SandboxCredentialProxyStatus {
	status = normalizeSandboxCredentialProxyStatus(status)
	if status != "" && !validSandboxCredentialProxyStatus(string(status)) {
		return ""
	}
	return status
}

func sanitizeSandboxCredentialProxyBindingOutcomeValue(outcome SandboxCredentialProxyBindingOutcome) SandboxCredentialProxyBindingOutcome {
	outcome = normalizeSandboxCredentialProxyBindingOutcome(outcome)
	if outcome != "" && !validSandboxCredentialProxyBindingOutcome(string(outcome)) {
		return ""
	}
	return outcome
}

func sanitizeSandboxCredentialProxyWarningCodeValue(warning SandboxCredentialProxyWarningCode) SandboxCredentialProxyWarningCode {
	warning = normalizeSandboxCredentialProxyWarningCode(warning)
	if warning != "" && !validSandboxCredentialProxyWarningCode(string(warning)) {
		return ""
	}
	return warning
}

func sanitizeSandboxCredentialProxyReasonCodeValue(reason SandboxCredentialProxyReasonCode) SandboxCredentialProxyReasonCode {
	reason = normalizeSandboxCredentialProxyReasonCode(reason)
	if reason != "" && !validSandboxCredentialProxyReasonCode(string(reason)) {
		return ""
	}
	return reason
}

func sanitizeSandboxCredentialProxyDeliveryModeValue(mode SandboxCredentialProxyDeliveryMode) SandboxCredentialProxyDeliveryMode {
	mode = normalizeSandboxCredentialProxyDeliveryMode(mode)
	if !validSandboxCredentialProxyDeliveryMode(string(mode)) {
		return ""
	}
	return mode
}

func sanitizeSandboxCredentialProxyRequestCategoryValue(category SandboxCredentialProxyRequestCategory) SandboxCredentialProxyRequestCategory {
	category = normalizeSandboxCredentialProxyRequestCategory(category)
	if category != "" && !validSandboxCredentialProxyRequestCategory(string(category)) {
		return ""
	}
	return category
}

func sanitizeSandboxCredentialProxyDestinationCategoryValue(category SandboxNetworkPolicyDestinationCategory) SandboxNetworkPolicyDestinationCategory {
	category = normalizeSandboxNetworkPolicyDestinationCategory(category)
	if category != "" && !validSandboxCredentialProxyDestinationCategory(string(category)) {
		return ""
	}
	return category
}

func sanitizeSandboxCredentialProxyPolicyPresetValue(preset SandboxNetworkPolicyPreset) SandboxNetworkPolicyPreset {
	preset = normalizeSandboxNetworkPolicyPreset(preset)
	if preset != "" && !validSandboxCredentialProxyPolicyPreset(string(preset)) {
		return ""
	}
	return preset
}
