//go:build linux

package firecrackerhost

import "time"

// Original selected attempt times, not fresh readiness or launch authority.
type minimalControlReleaseWindow struct {
	startedAt time.Time
	deadline  time.Time
}

// Compiling RED seam: the current selected sender retains no release window.
// Implementation follows independent reproduction and approval of that failure.
func (gate *minimalControlGateIO) releaseWindow() (minimalControlReleaseWindow, bool) {
	return minimalControlReleaseWindow{}, false
}
