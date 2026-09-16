//go:build linux

package firecrackerhost

import (
	"context"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

// Compiling RED: the original authenticated controller supplies no workload
// transport yet. This is deliberately not a new stream or session authority.
func withMinimalWorkloadController(ctx context.Context, transport *minimalControlTransport, admission *minimalControlSupervisorAdmission, deadline time.Time, consume func(*minimalControlController) error) error {
	return withMinimalControlController(ctx, transport, admission, deadline, consume)
}

func (r *minimalControlReadiness) workloadTransport() (guestagent.Transport, error) {
	return nil, errMinimalControlController
}
