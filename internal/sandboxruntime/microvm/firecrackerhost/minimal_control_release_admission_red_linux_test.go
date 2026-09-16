//go:build linux

package firecrackerhost

import (
	"context"
	"testing"
	"time"
)

func TestMinimalReleaseAdmissionRetainsOriginalWindow(t *testing.T) {
	for _, remaining := range []time.Duration{10 * time.Second, time.Minute} {
		t.Run(remaining.String(), func(t *testing.T) {
			deadline := time.Now().Add(remaining)
			withMinimalPreparationFixture(t, deadline, func(f *minimalPreparationFixture) {
				entered, unblock := minimalReleasePauseAtRevisionOne(f)
				done, joined := f.start(t), false
				defer func() {
					unblock()
					if !joined {
						_ = minimalPreparationJoin(t, done)
					}
				}()
				waitMinimalPreparationSignal(t, entered, "actual revision-1 release pause")
				minimalReleaseRequireRevisionOne(t, f, f.tracked)
				prep, gate := f.owned.minimalPreparation, f.owned.selected.starter.minimalGate
				if _, ok := gate.releaseWindow(); ok {
					t.Fatal("window exists before actual release")
				}
				before := time.Now()
				unblock()
				if err := minimalPreparationJoin(t, done); err != nil {
					joined = true
					t.Fatal("actual positive release prerequisite", err)
				}
				joined = true
				after := time.Now()
				packet, err := minimalReleaseReceive(t, f.gatePeer)
				if err != nil || packet.Packet.Opcode != l8RuntimeOwnerOpcodeChildRelease {
					t.Fatal("actual ChildRelease prerequisite", err)
				}
				record, err := f.owned.store.Load(context.Background())
				if err != nil || record.Revision != 2 || record.State != "running" || record.ControllerState != "unclaimed" || !f.owned.selected.starter.released {
					t.Fatal("actual canonical revision-2 prerequisite", err)
				}
				window, ok := gate.releaseWindow()
				if !ok {
					t.Error("actual selected release retained no immutable R/D window")
				} else {
					minimalReleaseAdmissionRequireWindow(t, window, before, after, prep.deadline)
				}
				if prep.deadline.UnixNano() != deadline.UnixNano() || !prep.current() {
					t.Fatal("actual release changed original preparation lifetime")
				}
				// Existing one-send behavior is independent of the missing window.
				if f.owned.selected.starter.release() == nil {
					t.Fatal("successful actual release became repeatable")
				}
				minimalGateIOCheckQueuedPackets(t, f.gatePeer, nil, 0)
			})
		})
	}
}

func TestMinimalReleaseAdmissionWindowPrecedesSendCompletion(t *testing.T) {
	before := time.Now()
	withMinimalGateIOBlockedOperation(t, func(f *minimalPreparationFixture, join func() error) {
		// This helper has observed the exact actual revision-1 bootstrap task
		// blocked in sendmsg, before any loss or queue draining.
		prep, starter := f.owned.minimalPreparation, f.owned.selected.starter
		gate := starter.minimalGate
		window, ok := gate.releaseWindow()
		if !ok {
			t.Error("actual blocked release has no original admission window")
		} else {
			minimalReleaseAdmissionRequireWindow(t, window, before, time.Now(), prep.deadline)
		}
		starter.mu.Lock()
		attempted, released := gate.attempted, starter.released
		starter.mu.Unlock()
		if !attempted || released || !prep.current() {
			t.Fatal("actual in-flight one-attempt prerequisite")
		}
		prep.revoke()
		if err := join(); err == nil {
			t.Fatal("canceled actual send succeeded")
		}
		after, retained := gate.releaseWindow()
		if retained != ok || after != window {
			t.Fatal("cancellation altered the original attempt window")
		}
		if !prep.canceled.Load() || starter.released || starter.release() == nil {
			t.Fatal("ambiguous failed attempt became reusable")
		}
	})
}

func TestMinimalReleaseAdmissionPriorCancellationControl(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		entered, unblock := minimalReleasePauseAtRevisionOne(f)
		done, joined := f.start(t), false
		defer func() {
			unblock()
			if !joined {
				_ = minimalPreparationJoin(t, done)
			}
		}()
		waitMinimalPreparationSignal(t, entered, "actual revision-1 release pause")
		minimalReleaseRequireRevisionOne(t, f, f.tracked)
		prep := f.owned.minimalPreparation
		prep.revoke()
		if !prep.canceled.Load() || prep.current() {
			t.Fatal("original cancellation not published")
		}
		unblock()
		if err := minimalPreparationJoin(t, done); err == nil {
			joined = true
			t.Fatal("prior cancellation admitted actual release")
		}
		joined = true
		if _, ok := f.owned.selected.starter.minimalGate.releaseWindow(); ok {
			t.Fatal("prior cancellation minted an attempt window")
		}
		if f.owned.selected.starter.released {
			t.Fatal("prior cancellation marked gate released")
		}
		minimalGateIOCheckQueuedPackets(t, f.gatePeer, nil, 0)
	})
}

func TestMinimalReleaseAdmissionConcurrentReplayControl(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		if err := minimalPreparationJoin(t, f.start(t)); err != nil {
			t.Fatal("actual successful release prerequisite", err)
		}
		packet, err := minimalReleaseReceive(t, f.gatePeer)
		if err != nil || packet.Packet.Opcode != l8RuntimeOwnerOpcodeChildRelease {
			t.Fatal("actual packet prerequisite", err)
		}
		done := make(chan error, 16)
		for range 16 {
			go func() { done <- f.owned.selected.starter.release() }()
		}
		for range 16 {
			if err := minimalPreparationJoin(t, done); err == nil {
				t.Error("concurrent replay resent a release")
			}
		}
		minimalGateIOCheckQueuedPackets(t, f.gatePeer, nil, 0)
		if !f.owned.minimalPreparation.current() {
			t.Fatal("rejected replay canceled the original lifetime")
		}
	})
}

func minimalReleaseAdmissionRequireWindow(t *testing.T, window minimalControlReleaseWindow, before, after, originalP time.Time) {
	t.Helper()
	if window.startedAt.IsZero() || window.startedAt.Before(before) || window.startedAt.After(after) || !window.startedAt.Before(originalP) {
		t.Error("R is not the conservative original pre-send time")
	}
	want := window.startedAt.Add(15 * time.Second)
	if originalP.Before(want) {
		want = originalP
	}
	if window.deadline.IsZero() || !window.deadline.Equal(want) {
		t.Error("D is not exactly min(original P, original R + 15s)")
	}
}
