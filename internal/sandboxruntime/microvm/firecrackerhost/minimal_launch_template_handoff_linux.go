//go:build linux

package firecrackerhost

import (
	"context"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// The compiling claim/handoff checkpoint does not transfer assets or construct
// a runtime. A later implementation must retain genuine partial ownership even
// when the runtime consumer remains unavailable.
func (provider *minimalLaunchProvider) StartMinimalJob(context.Context, *sandboxruntime.MinimalLaunchReservation, sandboxruntime.MinimalLaunchSelection) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	return nil, sandboxruntime.ErrMinimalLaunchUnavailable
}

// Recovery remains cleanup-only and unavailable without its original owner.
func (provider *minimalLaunchProvider) RecoverMinimalJob(context.Context, sandboxruntime.MinimalLaunchIdentity) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	return nil, sandboxruntime.ErrMinimalLaunchUnavailable
}
