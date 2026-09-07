package sandboxruntime

import "context"

// MinimalLaunchRecoveryBinding is a retained cleanup-attempt handle, not prior-
// daemon authorization, a runtime owner, or resource-absence proof. Its selected
// implementation remains unavailable until the behavioral RED is reviewed.
type MinimalLaunchRecoveryBinding struct{}

func (*MinimalLaunchOwnerBinding) Finalize(context.Context) (MinimalLaunchCleanupReceipt, error) {
	return MinimalLaunchCleanupReceipt{}, ErrMinimalLaunchUnavailable
}

func (*MinimalLaunchProviderBinding) BindRecovery(MinimalLaunchIdentity) (*MinimalLaunchRecoveryBinding, error) {
	return nil, ErrMinimalLaunchUnavailable
}

func (*MinimalLaunchRecoveryBinding) Recover(context.Context) (*MinimalLaunchOwnerBinding, error) {
	return nil, ErrMinimalLaunchUnavailable
}
