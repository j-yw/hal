//go:build linux

package firecrackerhost

import (
	"context"
	"time"
)

// OpenWhenAvailable is the unavailable DESIGN/RED seam for one selected
// startup. The caller must retain admissionDeadline through later authenticated
// readiness; a returned transport alone will not establish that readiness.
func (c *minimalControlTransport) OpenWhenAvailable(ctx context.Context, admissionDeadline time.Time) (*minimalControlStream, error) {
	return nil, errMinimalControlTransport
}
