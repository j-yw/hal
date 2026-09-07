package localresolver

import "context"

// ConfirmCurrent is the untransferred distribution currentness boundary.
// This compiling RED scaffold grants no new availability or lease authority.
func (verified VerifiedL8MinimalDistribution) ConfirmCurrent(ctx context.Context) error {
	return minimalDistributionError(ErrInvalidRequest)
}
