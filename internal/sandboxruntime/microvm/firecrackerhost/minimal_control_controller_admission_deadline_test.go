//go:build linux

package firecrackerhost

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

// These complete the real retained Unix/shared guest transcript. The process
// bookkeeping remains a fixture, not a selected supervisor or live VM owner.
func TestMinimalControlControllerReadinessRetainsAdmissionDeadline(t *testing.T) {
	for _, source := range []string{"original-deadline", "prelude-five-second-clamp"} {
		t.Run(source, func(t *testing.T) {
			a := newMinimalControlAdmissionFixture(t)
			code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				f := newMinimalControllerFixture(t, admission)
				defer f.close(t)
				deadline := time.Now().Add(2 * time.Second)
				var earliestClamp, latestClamp, preludeReleased time.Time
				if source == "prelude-five-second-clamp" {
					deadline = time.Now().Add(8 * time.Second)
					var beforeOnce, preludeOnce sync.Once
					f.transport.checks.observe = func(path string) (vsockSocketObservation, error) {
						if minimalStartupStackContains(".(*minimalControlController).authenticate") && minimalStartupStackContains(".(*minimalControlController).admissionCurrent") {
							beforeOnce.Do(func() {
								// The first authenticate observation precedes A's
								// existing time.Now()+5s calculation.
								earliestClamp = time.Now().Add(session.HandshakeDeadline)
							})
						}
						if minimalStartupStackContains("/frame.Write") {
							preludeOnce.Do(func() {
								// A is already installed before this actual write.
								// Delay delivery so reconstruction at Hello/Ready
								// is observably later than the original clamp.
								latestClamp = time.Now().Add(session.HandshakeDeadline)
								timer := time.NewTimer(100 * time.Millisecond)
								<-timer.C
								preludeReleased = time.Now()
							})
						}
						return observeVsockSocketOwner(path)
					}
				}
				err := withMinimalControlController(context.Background(), f.transport, admission, deadline, func(c *minimalControlController) error {
					ready := minimalControllerRequireReady(t, c)
					if f.listener.connects.Load() != 1 || !ready.hardExpiry.After(deadline) {
						t.Fatal("actual transcript or independent hard lifetime prerequisite failed")
					}
					got := ready.admissionDeadline
					if source == "original-deadline" {
						if !got.Equal(deadline) {
							t.Errorf("readiness lost exact original admission deadline: got %v, want %v", got, deadline)
						}
					} else {
						if earliestClamp.IsZero() || latestClamp.IsZero() || latestClamp.Before(earliestClamp) ||
							!preludeReleased.Add(session.HandshakeDeadline).After(latestClamp) || !latestClamp.Before(deadline) {
							t.Fatal("actual prelude clamp/delayed delivery prerequisite failed")
						}
						if got.Before(earliestClamp) || got.After(latestClamp) {
							t.Errorf("readiness lost original prelude admission clamp: got %v, want within [%v, %v]", got, earliestClamp, latestClamp)
						}
					}
					for range 3 {
						timer := time.NewTimer(10 * time.Millisecond)
						<-timer.C
						again := minimalControllerRequireReady(t, c)
						if again != ready || !again.admissionDeadline.Equal(got) {
							t.Error("repeated wait replaced readiness or rebased its admission deadline")
						}
					}
					_ = c.Close()
					minimalControllerRequireJoined(t, c, admission.controllerKey)
					return nil
				})
				if err != nil {
					t.Fatal("actual authenticated controller failed before retained-deadline assertion", err)
				}
				return nil
			})
			if code != 0 {
				t.Fatal("actual admission fixture failed")
			}
		})
	}
}

// The later first producer handoff must enforce A separately. Expiring A must
// not shorten the already-authenticated local stream's independent H lifetime.
func TestMinimalControlControllerReadinessCurrentUsesHardLifetime(t *testing.T) {
	a := newMinimalControlAdmissionFixture(t)
	code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		f := newMinimalControllerFixture(t, admission)
		defer f.close(t)
		deadline := time.Now().Add(750 * time.Millisecond)
		return withMinimalControlController(context.Background(), f.transport, admission, deadline, func(c *minimalControlController) error {
			ready := minimalControllerRequireReady(t, c)
			timer := time.NewTimer(time.Until(deadline) + time.Millisecond)
			<-timer.C
			if time.Now().Before(deadline) || !time.Now().Before(ready.hardExpiry) || !ready.Current() || f.listener.connects.Load() != 1 {
				t.Fatal("local readiness was shortened to admission or lost actual transcript")
			}
			again := minimalControllerRequireReady(t, c)
			if again != ready {
				t.Fatal("post-admission wait replaced the original local readiness")
			}
			_ = c.Close()
			minimalControllerRequireJoined(t, c, admission.controllerKey)
			return nil
		})
	})
	if code != 0 {
		t.Fatal("hard-lifetime compatibility control failed")
	}
}
