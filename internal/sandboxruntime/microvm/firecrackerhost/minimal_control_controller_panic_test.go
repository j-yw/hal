//go:build linux

package firecrackerhost

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestMinimalControlControllerTranscriptObservationPanic(t *testing.T) {
	for _, checkpoint := range []string{"application-state-held", "final-publication"} {
		t.Run(checkpoint, func(t *testing.T) {
			a := newMinimalControlAdmissionFixture(t)
			code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				f := newMinimalControllerFixture(t, admission)
				defer f.close(t)
				var reached atomic.Bool
				f.transport.checks.observe = func(path string) (vsockSocketObservation, error) {
					selected := minimalStartupStackContains(".(*State).WriteApplication")
					if checkpoint == "final-publication" {
						selected = minimalStartupStackContains(".(*minimalControlController).admissionCurrent") &&
							minimalStartupStackContains(".(*minimalControlController).run") &&
							!minimalStartupStackContains(".(*minimalControlController).authenticate")
					}
					if selected && reached.CompareAndSwap(false, true) {
						panic("private transcript observation panic")
					}
					return observeVsockSocketOwner(path)
				}
				err := withMinimalControlController(context.Background(), f.transport, admission, time.Now().Add(3*time.Second), func(c *minimalControlController) error {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					ready, err := c.WaitReady(ctx)
					if err != errMinimalControlController || ready != nil || ctx.Err() != nil {
						t.Error("transcript panic escaped or waited for deadline")
					}
					_ = c.Close()
					minimalControllerRequireJoined(t, c, admission.controllerKey)
					select {
					case <-c.readyDone:
						t.Error("transcript panic published readiness")
					default:
					}
					return nil
				})
				if !reached.Load() || err != errMinimalControlController || f.listener.connects.Load() != 1 {
					t.Fatal("actual authenticated panic checkpoint not exercised")
				}
				return nil
			})
			if code != 0 {
				t.Fatal("transcript panic fixture failed")
			}
		})
	}
}
