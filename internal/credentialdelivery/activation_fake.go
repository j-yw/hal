package credentialdelivery

// FakeActivationModeResult configures one safe mode outcome for
// FakeActivationAdapter. Empty status defaults to active.
type FakeActivationModeResult struct {
	Mode       Mode       `json:"mode"`
	Status     Status     `json:"status,omitempty"`
	ReasonCode ReasonCode `json:"reasonCode,omitempty"`
}

// FakeActivationAdapter is a deterministic activation adapter for tests and
// fake-only command paths. It records sanitized requests and returns only
// activation metadata derived from configured mode outcomes.
type FakeActivationAdapter struct {
	modeResults []FakeActivationModeResult
	calls       []ActivationRequest
}

// NewFakeActivationAdapter returns a fake activation adapter. When a requested
// mode has no configured result, it is reported active.
func NewFakeActivationAdapter(results ...FakeActivationModeResult) *FakeActivationAdapter {
	adapter := &FakeActivationAdapter{}
	if len(results) == 0 {
		return adapter
	}
	adapter.modeResults = make([]FakeActivationModeResult, 0, len(results))
	for _, result := range results {
		result = sanitizeFakeActivationModeResult(result)
		if result.Mode == "" {
			continue
		}
		adapter.modeResults = append(adapter.modeResults, result)
	}
	return adapter
}

// Calls returns sanitized activation requests observed by the adapter.
func (a *FakeActivationAdapter) Calls() []ActivationRequest {
	if a == nil || a.calls == nil {
		return nil
	}
	calls := make([]ActivationRequest, len(a.calls))
	for i, call := range a.calls {
		calls[i] = SanitizeActivationRequestMetadata(call)
	}
	return calls
}

// ActivateCredentialDelivery returns fake activation metadata without using
// concrete delivery handles.
func (a *FakeActivationAdapter) ActivateCredentialDelivery(input SanitizedActivationRequest) (ActivationResult, error) {
	request := input.Request()
	if a != nil {
		a.calls = append(a.calls, request)
	}
	if request.ActivationID == "" || request.Plan.ID == "" {
		return ActivationResult{}, nil
	}
	return SanitizeActivationResultMetadata(fakeActivationResultFromRequest(request, a)), nil
}

func sanitizeFakeActivationModeResult(result FakeActivationModeResult) FakeActivationModeResult {
	result.Mode = sanitizeRequiredModeValue(result.Mode)
	result.Status = sanitizeStatusValue(result.Status)
	if result.Status == "" {
		result.Status = StatusActive
	}
	result.ReasonCode = sanitizeReasonCodeValue(result.ReasonCode)
	if result.ReasonCode == "" {
		result.ReasonCode = fakeActivationReasonForStatus(result.Status)
	}
	return result
}

func fakeActivationResultFromRequest(request ActivationRequest, adapter *FakeActivationAdapter) ActivationResult {
	result := ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
	}
	activeModes := newPlanModeSet()
	statuses := fakeActivationStatusCounts{}

	for _, binding := range request.Bindings {
		modeResult := fakeActivationModeResultFor(adapter, binding.DeliveryMode)
		result.Bindings = append(result.Bindings, BindingActivationResult{
			BindingID:    binding.ID,
			ServiceID:    binding.ServiceID,
			DeliveryMode: binding.DeliveryMode,
			Outcome:      modeResult.Status,
			Status:       modeResult.Status,
			ReasonCode:   modeResult.ReasonCode,
		})
		statuses.add(modeResult.Status)
		if modeResult.Status == StatusActive {
			activeModes.add(binding.DeliveryMode)
		}
		if modeResult.Status == StatusSkipped {
			result.Warnings = appendActivationWarningIfMissing(result.Warnings, Warning{
				Code:       WarningActivationSkipped,
				ReasonCode: modeResult.ReasonCode,
				BindingID:  binding.ID,
				Mode:       binding.DeliveryMode,
			})
		}
		if modeResult.Status == StatusFailed {
			result.Errors = append(result.Errors, SanitizedError{
				Code:       ErrorActivationFailed,
				Field:      "adapter",
				BindingID:  binding.ID,
				Mode:       binding.DeliveryMode,
				ReasonCode: modeResult.ReasonCode,
			})
		}
	}

	if len(result.Bindings) == 0 {
		for _, mode := range request.Plan.RequestedModes {
			modeResult := fakeActivationModeResultFor(adapter, mode)
			statuses.add(modeResult.Status)
			if modeResult.Status == StatusActive {
				activeModes.add(mode)
			}
			if modeResult.Status == StatusSkipped {
				result.Warnings = appendActivationWarningIfMissing(result.Warnings, Warning{
					Code:       WarningActivationSkipped,
					ReasonCode: modeResult.ReasonCode,
					Mode:       mode,
				})
			}
			if modeResult.Status == StatusFailed {
				result.Errors = append(result.Errors, SanitizedError{
					Code:       ErrorActivationFailed,
					Field:      "adapter",
					Mode:       mode,
					ReasonCode: modeResult.ReasonCode,
				})
			}
		}
	}

	result.ActiveModes = activeModes.ordered()
	result.Status = statuses.status()
	return result
}

func fakeActivationModeResultFor(adapter *FakeActivationAdapter, mode Mode) FakeActivationModeResult {
	mode = sanitizeRequiredModeValue(mode)
	if mode == "" {
		return FakeActivationModeResult{}
	}
	if adapter != nil {
		for i := len(adapter.modeResults) - 1; i >= 0; i-- {
			if adapter.modeResults[i].Mode == mode {
				return adapter.modeResults[i]
			}
		}
	}
	return FakeActivationModeResult{
		Mode:       mode,
		Status:     StatusActive,
		ReasonCode: ReasonRequested,
	}
}

func fakeActivationReasonForStatus(status Status) ReasonCode {
	switch status {
	case StatusSkipped, StatusFailed:
		return ReasonActivationUnavailable
	default:
		return ReasonRequested
	}
}

type fakeActivationStatusCounts struct {
	failed  bool
	active  bool
	ready   bool
	skipped bool
}

func (c *fakeActivationStatusCounts) add(status Status) {
	switch status {
	case StatusFailed:
		c.failed = true
	case StatusActive:
		c.active = true
	case StatusReady:
		c.ready = true
	case StatusSkipped:
		c.skipped = true
	}
}

func (c fakeActivationStatusCounts) status() Status {
	switch {
	case c.failed:
		return StatusFailed
	case c.active:
		return StatusActive
	case c.ready:
		return StatusReady
	case c.skipped:
		return StatusSkipped
	default:
		return StatusSkipped
	}
}
