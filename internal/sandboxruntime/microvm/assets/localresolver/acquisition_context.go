package localresolver

import "context"

// VerifyDistributionBundleContext verifies a parent bundle within the caller's
// acquisition lifetime. Context propagation is introduced by the next GREEN.
func VerifyDistributionBundleContext(ctx context.Context, request DistributionRequest) (VerifiedDistribution, error) {
	return VerifyDistributionBundle(request)
}

// VerifyL8MinimalDistributionBundleContext retains a minimal bundle within the
// caller's acquisition lifetime. Context propagation follows the compiling RED.
func VerifyL8MinimalDistributionBundleContext(ctx context.Context, request L8MinimalDistributionRequest) (VerifiedL8MinimalDistribution, error) {
	return VerifyL8MinimalDistributionBundle(request)
}
