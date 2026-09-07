//go:build linux

package firecrackerhost

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

func TestMinimalControlControllerDelayedAdmissionObservation(t *testing.T) {
	for _, checkpoint := range []string{"original-before-prelude", "original-final-publication", "five-second-final-publication"} {
		t.Run(checkpoint, func(t *testing.T) {
			a := newMinimalControlAdmissionFixture(t)
			code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				f := newMinimalControllerRetainedPeerFixture(t, admission)
				public, ok := minimalControlConfigBase64(admission.config.Control.ControllerPublicKey)
				if !ok {
					t.Fatal("invalid fixture public key")
				}
				peerCtx, stopPeer := context.WithCancel(context.Background())
				peerDone, responseSent := make(chan struct{}), make(chan struct{})
				var peerErr error
				go func() {
					defer close(peerDone)
					peerErr = runMinimalControllerSemanticPeer(peerCtx, f, public[:], "matching", responseSent)
				}()
				defer func() { stopPeer(); awaitMinimalTransportREDDone(t, peerDone) }()
				deadline := time.Now().Add(300 * time.Millisecond)
				if checkpoint == "five-second-final-publication" {
					deadline = time.Now().Add(8 * time.Second)
				}
				var delayed sync.Once
				var preludeObserved time.Time // controller task only; checked after join
				crossed, originalStillOpen := false, false
				f.transport.checks.observe = func(path string) (vsockSocketObservation, error) {
					if minimalStartupStackContains("/frame.Write") && preludeObserved.IsZero() {
						preludeObserved = time.Now()
					}
					inAdmission := minimalStartupStackContains(".(*minimalControlController).admissionCurrent")
					inAuthenticate := minimalStartupStackContains(".(*minimalControlController).authenticate")
					inRun := minimalStartupStackContains(".(*minimalControlController).run")
					selected := inAdmission && inRun && !inAuthenticate
					if checkpoint == "original-before-prelude" {
						selected = inAdmission && inAuthenticate
					}
					if selected {
						delayed.Do(func() {
							until := deadline
							if checkpoint == "five-second-final-publication" {
								if preludeObserved.IsZero() {
									t.Error("actual prelude write not observed")
									return
								}
								// A was set immediately before this observed write.
								// Crossing this later timestamp + 5s must cross A.
								until = preludeObserved.Add(session.HandshakeDeadline)
							}
							timer := time.NewTimer(time.Until(until) + time.Millisecond)
							<-timer.C
							crossed = !time.Now().Before(until)
							originalStillOpen = time.Now().Before(deadline)
						})
					}
					return observeVsockSocketOwner(path)
				}
				err := withMinimalControlController(context.Background(), f.transport, admission, deadline, func(c *minimalControlController) error {
					wait, cancel := context.WithTimeout(context.Background(), 9*time.Second)
					defer cancel()
					ready, err := c.WaitReady(wait)
					if err == nil || ready != nil || wait.Err() != nil {
						t.Error("delayed admission accepted readiness or relied on waiter expiry")
					}
					_ = c.Close()
					minimalControllerRequireJoined(t, c, admission.controllerKey)
					select {
					case <-c.readyDone:
						t.Error("expired admission published even transient readiness")
					default:
					}
					return nil
				})
				if !crossed || originalStillOpen != (checkpoint == "five-second-final-publication") || err == nil || f.listener.connects.Load() != 1 {
					t.Fatal("deadline checkpoint not exercised exactly")
				}
				if checkpoint != "original-before-prelude" {
					awaitMinimalTransportREDDone(t, peerDone)
					if peerErr != nil {
						t.Fatal("matching authenticated transcript did not complete before delayed publication", peerErr)
					}
					select {
					case <-responseSent:
					default:
						t.Fatal("final check did not follow an actual authenticated response")
					}
				}
				return nil
			})
			if code != 0 {
				t.Fatal("deadline fixture failed")
			}
		})
	}
}

func TestMinimalControlControllerReadyHardLifetime(t *testing.T) {
	for _, source := range []string{"retained-transport", "owner-deadline"} {
		t.Run(source, func(t *testing.T) {
			a := newMinimalControlAdmissionFixture(t)
			code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				f := newMinimalControllerFixture(t, admission)
				defer f.close(t)
				owner := context.Context(context.Background())
				var cancel context.CancelFunc
				before := time.Now()
				latest := before.Add(500 * time.Millisecond)
				if source == "retained-transport" {
					f.transport.lifetime = 500 * time.Millisecond
				} else {
					owner, cancel = context.WithDeadline(owner, latest)
					defer cancel()
				}
				return withMinimalControlController(owner, f.transport, admission, before.Add(2*time.Second), func(c *minimalControlController) error {
					ready := minimalControllerRequireReady(t, c)
					c.mu.Lock()
					stream := c.stream
					c.mu.Unlock()
					if ready.hardExpiry.Before(latest) || ready.hardExpiry.After(latest.Add(30*time.Millisecond)) || ready.hardExpiry.After(stream.hardDeadline) {
						t.Fatal("hard expiry was rebased or enlarged")
					}
					select {
					case <-c.Loss():
					case <-time.After(time.Second):
						t.Fatal("ready lifetime did not expire")
					}
					if time.Now().Before(ready.hardExpiry) || ready.Current() {
						t.Fatal("readiness loss did not correspond to exact hard expiry")
					}
					_ = c.Close()
					minimalControllerRequireJoined(t, c, admission.controllerKey)
					return nil
				})
			})
			if code != 0 {
				t.Fatal("hard lifetime fixture failed")
			}
		})
	}
}
