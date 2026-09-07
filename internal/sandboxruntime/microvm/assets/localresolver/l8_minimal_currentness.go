package localresolver

import "context"

// ConfirmCurrent rechecks original untransferred ownership without issuing a
// lease. Copies share the same state; a transferred alias cannot use this path.
func (verified VerifiedL8MinimalDistribution) ConfirmCurrent(ctx context.Context) error {
	if verified.state == nil || ctx == nil {
		return minimalDistributionError(ErrInvalidRequest)
	}
	state := verified.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.transferred {
		return minimalDistributionError(ErrInvalidRequest)
	}
	return state.confirmLaunchCurrent(ctx)
}
