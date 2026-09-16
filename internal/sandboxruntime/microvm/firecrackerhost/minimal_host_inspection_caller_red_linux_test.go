//go:build linux

package firecrackerhost

import (
	"context"
	"sync/atomic"
	"testing"
)

// Forward every method to the actual caller. Only an Err observation after the
// real sole reader publishes its correlated reply cancels that same caller.
// No response, completion bit, deadline or work owner is supplied by this helper.
type minimalInspectionCompletedCaller struct {
	context.Context
	launch   *minimalControlProducerLaunch
	cancel   context.CancelFunc
	observed atomic.Bool
}

func (ctx *minimalInspectionCompletedCaller) Err() error {
	if ctx.launch.mu.TryLock() {
		op := ctx.launch.active
		complete := op != nil && op.header.operation == minimalInspectionOperation && op.received && len(op.response) > 0
		ctx.launch.mu.Unlock()
		if complete && ctx.observed.CompareAndSwap(false, true) {
			ctx.cancel()
		}
	}
	return ctx.Context.Err()
}

func TestMinimalHostInspectionOriginalCallerLossAfterCompleteReply(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		o, rescue := minimalHostInspectionGuest(t, f)
		defer rescue()
		_, candidate := minimalSupervisorWorkClient(t, f)
		original, cancel := context.WithCancel(context.Background())
		defer cancel()
		caller := &minimalInspectionCompletedCaller{Context: original, launch: f.producer, cancel: cancel}
		response, err := candidate.RoundTrip(caller, minimalHostInspectionCarrier(minimalInspectionOperation))
		defer clear(response.Encoded)
		if o.counts() != [7]int32{2, 2, 2, 2, 1, 0, 0} {
			t.Fatal("actual original fresh inspection did not complete")
		}
		t.Logf("actual fresh reply completed; original-caller completion observation=%t", caller.observed.Load())
		if !caller.observed.Load() || original.Err() != context.Canceled {
			t.Error("final acceptance did not recheck the original caller after the actual complete reply")
		}
		if err == nil || len(response.Encoded) != 0 {
			t.Error("inspection accepted proof without original-caller final acceptance")
		}
		f.producer.retire()
		minimalSupervisorWorkJoined(t, f)
	})
}

type minimalInspectionContextValueObserver struct {
	context.Context
	launch         *minimalControlProducerLaunch
	called, locked atomic.Bool
}

func (ctx *minimalInspectionContextValueObserver) Value(key any) any {
	ctx.called.Store(true)
	if ctx.launch.mu.TryLock() {
		ctx.launch.mu.Unlock()
	} else {
		ctx.locked.Store(true)
	}
	return ctx.Context.Value(key)
}

func TestMinimalHostInspectionDerivesContextOutsideOwnerMutex(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		_, rescue := minimalHostInspectionGuest(t, f)
		defer rescue()
		_, candidate := minimalSupervisorWorkClient(t, f)
		original, cancel := context.WithCancel(context.Background())
		defer cancel()
		caller := &minimalInspectionContextValueObserver{Context: original, launch: f.producer}
		response, err := candidate.RoundTrip(caller, minimalHostInspectionCarrier(minimalInspectionOperation))
		defer clear(response.Encoded)
		if err != nil {
			t.Fatal("actual original inspection control", err)
		}
		t.Logf("actual derived-context Value callback: reached=%t owner-mutex-held=%t", caller.called.Load(), caller.locked.Load())
		if !caller.called.Load() || caller.locked.Load() {
			t.Error("derived context did not invoke caller methods outside original owner mutex")
		}
		f.producer.retire()
		minimalSupervisorWorkJoined(t, f)
	})
}
