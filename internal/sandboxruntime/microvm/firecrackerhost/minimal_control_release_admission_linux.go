//go:build linux

package firecrackerhost

import (
	"sync/atomic"
	"time"
)

const (
	minimalPreparationCanceled uint32 = 1 << iota
	minimalPreparationReleaseAdmitted
)

// One monotonic authority: cancellation and release compete on the same word.
// The context is a wakeup mechanism, not a second release admission latch.
type minimalControlPreparationLatch struct{ state atomic.Uint32 }

func (latch *minimalControlPreparationLatch) Load() bool {
	return latch.state.Load()&minimalPreparationCanceled != 0
}

func (latch *minimalControlPreparationLatch) cancel() {
	latch.state.Or(minimalPreparationCanceled)
}

func (latch *minimalControlPreparationLatch) admitRelease() bool {
	return latch.state.CompareAndSwap(0, minimalPreparationReleaseAdmitted)
}

func (latch *minimalControlPreparationLatch) releaseAdmitted() bool {
	return latch.state.Load()&minimalPreparationReleaseAdmitted != 0
}

// Original selected attempt times, not fresh readiness or launch authority.
type minimalControlReleaseWindow struct {
	startedAt time.Time
	deadline  time.Time
}

// Only the originally returned selected Release calls this, after revision 1.
// No new bookkeeping lock spans the actual retained-resource observations.
func (gate *minimalControlGateIO) admitRelease(snapshot minimalControlReleaseSnapshot) error {
	if !gate.matches(snapshot.starter, snapshot.prep) || snapshot.starter.minimalGate != gate || snapshot.current() != nil || !gate.prep.current() {
		return errL8RuntimeOwnerInvalid
	}
	r := time.Now()
	if !r.Before(gate.prep.deadline) || !gate.prep.canceled.admitRelease() {
		return errL8RuntimeOwnerInvalid
	}
	d := r.Add(minimalControlStartupTimeout)
	if gate.prep.deadline.Before(d) {
		d = gate.prep.deadline
	}
	// Capture precedes the CAS; publication may wait but never rebases R/D.
	// Even loss during this wait consumes admission and retains its history.
	gate.starter.mu.Lock()
	defer gate.starter.mu.Unlock()
	gate.window = minimalControlReleaseWindow{startedAt: r, deadline: d}
	if gate.starter.minimalGate != gate || gate.closing || gate.starter.closed || !gate.prep.current() {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

// Historical metadata only, including after cancellation. Not a new authority
// or permission to send; the caller cannot reset an admitted attempt's times.
func (gate *minimalControlGateIO) releaseWindow() (minimalControlReleaseWindow, bool) {
	if gate == nil || gate.starter == nil {
		return minimalControlReleaseWindow{}, false
	}
	gate.starter.mu.Lock()
	defer gate.starter.mu.Unlock()
	return gate.window, !gate.window.startedAt.IsZero()
}
