//go:build linux

package firecrackerhost

import "github.com/jywlabs/hal/internal/sandboxruntime"

// Preparation belongs to the exact claimed asset owner. There is no caller,
// replacement preparation context/deadline, successful assembly or exec yet.
func (*minimalTemplateAssetOwner) prepareMinimalInputs(*minimalPreexecHost) error {
	return sandboxruntime.ErrMinimalLaunchUnavailable
}
