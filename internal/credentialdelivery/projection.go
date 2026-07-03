package credentialdelivery

// StatusMetadataFromPlan returns a compact durable summary of a planned
// credential delivery request. Plan-only summaries intentionally never carry
// active modes; active delivery is exposed only from successful activation.
func StatusMetadataFromPlan(plan Plan) StatusMetadata {
	sanitized := SanitizePlanMetadata(plan)
	if sanitized.ID == "" {
		return StatusMetadata{}
	}
	return SanitizeStatusMetadata(StatusMetadata{
		ID:             sanitized.ID,
		RequestID:      sanitized.RequestID,
		PlanID:         sanitized.ID,
		RequestedModes: sanitized.RequestedModes,
		Status:         sanitized.Status,
		WarningCount:   len(sanitized.Warnings),
		ErrorCount:     len(sanitized.Errors),
	})
}

// StatusMetadataFromActivation returns a compact durable activation summary.
// Active modes are projected only when the sanitized activation is active.
func StatusMetadataFromActivation(plan Plan, activation ActivationResult) StatusMetadata {
	sanitizedPlan := SanitizePlanMetadata(plan)
	sanitizedActivation := SanitizeActivationResultMetadata(activation)
	if sanitizedActivation.ID == "" {
		return StatusMetadataFromPlan(sanitizedPlan)
	}
	status := StatusMetadata{
		ID:             sanitizedActivation.ID,
		RequestID:      sanitizedPlan.RequestID,
		PlanID:         sanitizedActivation.PlanID,
		ActivationID:   sanitizedActivation.ID,
		RequestedModes: sanitizedActivation.RequestedModes,
		Status:         sanitizedActivation.Status,
		ReasonCode:     activationStatusReason(sanitizedActivation),
		WarningCount:   len(sanitizedActivation.Warnings),
		ErrorCount:     len(sanitizedActivation.Errors),
	}
	if status.RequestedModes == nil {
		status.RequestedModes = sanitizedPlan.RequestedModes
	}
	if status.PlanID == "" {
		status.PlanID = sanitizedPlan.ID
	}
	activeModes := secureActiveStatusModes(sanitizedActivation.ActiveModes)
	if sanitizedActivation.Status == StatusActive && len(activeModes) == 0 {
		status.Status = StatusSkipped
	}
	if status.Status == StatusActive {
		status.ActiveModes = activeModes
	}
	return SanitizeStatusMetadata(status)
}

func activationStatusReason(activation ActivationResult) ReasonCode {
	if len(activation.Errors) > 0 {
		return activation.Errors[0].ReasonCode
	}
	if len(activation.Warnings) > 0 {
		return activation.Warnings[0].ReasonCode
	}
	return ReasonRequested
}

func secureActiveStatusModes(modes []Mode) []Mode {
	if modes == nil {
		return nil
	}
	active := newPlanModeSet()
	for _, mode := range modes {
		mode = normalizeMode(mode)
		if mode == ModeLegacyAuthSync {
			continue
		}
		active.add(mode)
	}
	return active.ordered()
}
