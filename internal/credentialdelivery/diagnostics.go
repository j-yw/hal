package credentialdelivery

// BuildCredentialActivationDiagnostics returns a redaction-safe diagnostic
// summary from sanitized activation state. It is intentionally narrower than
// ActivationResult so diagnostic surfaces cannot expose adapter inputs.
func BuildCredentialActivationDiagnostics(plan Plan, activation ActivationResult) CredentialActivationDiagnosticSummary {
	sanitizedPlan := SanitizePlanMetadata(plan)
	sanitizedActivation := SanitizeActivationResultMetadata(activation)
	if sanitizedPlan.ID == "" && sanitizedActivation.ID == "" {
		return CredentialActivationDiagnosticSummary{}
	}

	requestedModes := sanitizedActivation.RequestedModes
	if requestedModes == nil {
		requestedModes = sanitizedPlan.RequestedModes
	}
	warnings := sanitizedActivation.Warnings
	if warnings == nil && sanitizedActivation.ID == "" {
		warnings = sanitizedPlan.Warnings
	}
	status := sanitizedActivation.Status
	if status == "" {
		status = sanitizedPlan.Status
	}
	reason := credentialActivationDiagnosticReason(sanitizedActivation, sanitizedPlan, status, warnings)

	summary := CredentialActivationDiagnosticSummary{
		RequestedModes: requestedModes,
		Status:         status,
		ReasonCode:     reason,
		ProofIDs:       credentialActivationDiagnosticProofIDs(sanitizedActivation),
		Warnings:       warnings,
	}
	if status == StatusActive {
		summary.ActiveModes = secureActiveStatusModes(sanitizedActivation.ActiveModes)
	}
	summary.Items = credentialActivationDiagnosticItems(summary, sanitizedActivation)
	return SanitizeCredentialActivationDiagnosticSummary(summary)
}

// SanitizeCredentialActivationDiagnosticSummary returns a diagnostic summary
// containing only safe metadata fields and values.
func SanitizeCredentialActivationDiagnosticSummary(summary CredentialActivationDiagnosticSummary) CredentialActivationDiagnosticSummary {
	return CredentialActivationDiagnosticSummary{
		RequestedModes: sanitizeOptionalModeRecords(summary.RequestedModes),
		ActiveModes:    secureActiveStatusModes(summary.ActiveModes),
		Status:         sanitizeStatusValue(summary.Status),
		ReasonCode:     sanitizeReasonCodeValue(summary.ReasonCode),
		ProofIDs:       sanitizeCredentialActivationDiagnosticProofIDs(summary.ProofIDs),
		Warnings:       SanitizeWarningMetadataRecords(summary.Warnings),
		Items:          SanitizeCredentialActivationDiagnosticItemRecords(summary.Items),
	}
}

// SanitizeCredentialActivationDiagnosticItem returns one safe diagnostic item.
func SanitizeCredentialActivationDiagnosticItem(item CredentialActivationDiagnosticItem) CredentialActivationDiagnosticItem {
	sanitized := CredentialActivationDiagnosticItem{
		DeliveryMode: sanitizeOptionalModeValue(item.DeliveryMode),
		Status:       sanitizeStatusValue(item.Status),
		ReasonCode:   sanitizeReasonCodeValue(item.ReasonCode),
		ProofID:      sanitizeIdentifier(item.ProofID),
		WarningCode:  sanitizeOptionalWarningCodeValue(item.WarningCode),
	}
	if sanitized.DeliveryMode == "" &&
		sanitized.Status == "" &&
		sanitized.ReasonCode == "" &&
		sanitized.ProofID == "" &&
		sanitized.WarningCode == "" {
		return CredentialActivationDiagnosticItem{}
	}
	return sanitized
}

// SanitizeCredentialActivationDiagnosticItemRecords returns safe diagnostic
// items while preserving nil versus explicit empty slices.
func SanitizeCredentialActivationDiagnosticItemRecords(items []CredentialActivationDiagnosticItem) []CredentialActivationDiagnosticItem {
	if items == nil {
		return nil
	}
	sanitized := make([]CredentialActivationDiagnosticItem, 0, len(items))
	for _, item := range items {
		record := SanitizeCredentialActivationDiagnosticItem(item)
		if record != (CredentialActivationDiagnosticItem{}) {
			sanitized = append(sanitized, record)
		}
	}
	return sanitized
}

func credentialActivationDiagnosticReason(activation ActivationResult, plan Plan, status Status, warnings []Warning) ReasonCode {
	if activation.ReasonCode != "" {
		return activation.ReasonCode
	}
	for _, warning := range SanitizeWarningMetadataRecords(warnings) {
		if warning.ReasonCode != "" {
			return warning.ReasonCode
		}
	}
	if len(plan.Errors) > 0 {
		return activationReasonFromErrors(plan.Errors, ReasonActivationUnavailable)
	}
	return activationReasonForStatus(status, warnings)
}

func credentialActivationDiagnosticProofIDs(activation ActivationResult) []string {
	set := newCredentialActivationDiagnosticStringSet()
	for _, proof := range SanitizeActivationProofReferenceMetadataRecords(activation.ProofRefs) {
		set.add(proof.ProofID)
	}
	for _, binding := range SanitizeBindingActivationResultMetadataRecords(activation.Bindings) {
		set.add(binding.ProofRef)
	}
	return set.values()
}

func credentialActivationDiagnosticItems(summary CredentialActivationDiagnosticSummary, activation ActivationResult) []CredentialActivationDiagnosticItem {
	var items []CredentialActivationDiagnosticItem
	for _, binding := range SanitizeBindingActivationResultMetadataRecords(activation.Bindings) {
		reason := binding.ReasonCode
		if reason == "" {
			reason = summary.ReasonCode
		}
		status := binding.Status
		if status == "" {
			status = summary.Status
		}
		items = append(items, CredentialActivationDiagnosticItem{
			DeliveryMode: binding.DeliveryMode,
			Status:       status,
			ReasonCode:   reason,
			ProofID:      binding.ProofRef,
		})
	}
	for _, warning := range SanitizeWarningMetadataRecords(summary.Warnings) {
		item := CredentialActivationDiagnosticItem{
			DeliveryMode: warning.Mode,
			Status:       summary.Status,
			ReasonCode:   warning.ReasonCode,
			WarningCode:  warning.Code,
		}
		if item.ReasonCode == "" {
			item.ReasonCode = summary.ReasonCode
		}
		if !credentialActivationDiagnosticHasItem(items, item) {
			items = append(items, item)
		}
	}
	if len(items) == 0 {
		for _, mode := range sanitizeOptionalModeRecords(summary.RequestedModes) {
			items = append(items, CredentialActivationDiagnosticItem{
				DeliveryMode: mode,
				Status:       summary.Status,
				ReasonCode:   summary.ReasonCode,
			})
		}
	}
	return items
}

func credentialActivationDiagnosticHasItem(items []CredentialActivationDiagnosticItem, want CredentialActivationDiagnosticItem) bool {
	for _, item := range SanitizeCredentialActivationDiagnosticItemRecords(items) {
		if item.DeliveryMode == want.DeliveryMode &&
			item.Status == want.Status &&
			item.ReasonCode == want.ReasonCode &&
			item.ProofID == want.ProofID &&
			item.WarningCode == want.WarningCode {
			return true
		}
	}
	return false
}

func sanitizeCredentialActivationDiagnosticProofIDs(values []string) []string {
	if values == nil {
		return nil
	}
	set := newCredentialActivationDiagnosticStringSet()
	for _, value := range values {
		set.add(value)
	}
	return set.values()
}

func sanitizeOptionalWarningCodeValue(warning WarningCode) WarningCode {
	warning = normalizeWarningCode(warning)
	if warning != "" && (unsafeCredentialDeliveryFreeformMetadata(string(warning)) || !validWarningCode(warning)) {
		return ""
	}
	return warning
}

type credentialActivationDiagnosticStringSet struct {
	ordered []string
	seen    map[string]struct{}
}

func newCredentialActivationDiagnosticStringSet() *credentialActivationDiagnosticStringSet {
	return &credentialActivationDiagnosticStringSet{seen: make(map[string]struct{})}
}

func (s *credentialActivationDiagnosticStringSet) add(value string) {
	value = sanitizeIdentifier(value)
	if value == "" {
		return
	}
	if _, ok := s.seen[value]; ok {
		return
	}
	s.seen[value] = struct{}{}
	s.ordered = append(s.ordered, value)
}

func (s *credentialActivationDiagnosticStringSet) values() []string {
	if len(s.ordered) == 0 {
		return nil
	}
	out := make([]string, len(s.ordered))
	copy(out, s.ordered)
	return out
}
