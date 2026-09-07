//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// The real shared-crypto peer stops reading after authenticating Finished.
// Test-only filler occupies the actual Unix send buffer immediately before the
// host's application write. It is never interpreted as an authenticated record.
func TestMinimalControlControllerCloseJoinsBlockedApplicationWrite(t *testing.T) {
	for _, operation := range []string{"close", "owner-cancel"} {
		t.Run(operation, func(t *testing.T) {
			a := newMinimalControlAdmissionFixture(t)
			code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				f := newMinimalControllerRetainedPeerFixture(t, admission)
				public, ok := minimalControlConfigBase64(admission.config.Control.ControllerPublicKey)
				if !ok {
					t.Fatal("invalid fixture public key")
				}
				peerCtx, stopPeer := context.WithCancel(context.Background())
				peerDone, peerFinished := make(chan struct{}), make(chan struct{})
				var peerErr error
				go func() {
					defer close(peerDone)
					peerErr = runMinimalControllerObservedPeer(peerCtx, f, public[:], "matching", make(chan struct{}), func() error {
						close(peerFinished)
						<-peerCtx.Done()
						return peerCtx.Err()
					})
				}()
				defer func() { stopPeer(); awaitMinimalTransportREDDone(t, peerDone) }()
				owner, stopOwner := context.WithCancel(context.Background())
				defer stopOwner()
				deadline := time.Now().Add(3 * time.Second)
				var conn *net.UnixConn // written by dial, read only by the same task
				f.transport.dial = func(ctx context.Context, network, path string) (net.Conn, error) {
					raw, err := (&net.Dialer{}).DialContext(ctx, network, path)
					if err == nil {
						conn = raw.(*net.UnixConn)
					}
					return raw, err
				}
				filled := make(chan struct{})
				var fillOnce sync.Once
				f.transport.checks.observe = func(path string) (vsockSocketObservation, error) {
					if minimalStartupStackContains(".(*State).WriteApplication") && minimalStartupStackContains(".(*minimalControlStream).Write") {
						fillOnce.Do(func() {
							select {
							case <-peerFinished:
							case <-time.After(time.Second):
								t.Error("peer did not authenticate Finished before backpressure")
								return
							}
							if err := conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
								t.Error("failed to bound fixture buffer fill", err)
								return
							}
							filler := bytes.Repeat([]byte{0x73}, 4<<20)
							n, err := conn.Write(filler)
							clear(filler)
							if timed, ok := err.(net.Error); !ok || !timed.Timeout() || n <= 0 || n == len(filler) {
								t.Error("fixture did not establish real Unix backpressure", n, err)
								return
							}
							if conn.SetWriteDeadline(deadline) != nil {
								t.Error("fixture failed to restore original admission bound")
								return
							}
							close(filled)
						})
					}
					return observeVsockSocketOwner(path)
				}
				err := withMinimalControlController(owner, f.transport, admission, deadline, func(c *minimalControlController) error {
					awaitMinimalTransportREDDone(t, filled)
					// Require the actual task to be inside the real net write with
					// State.WriteApplication on its stack, not the fixture filler.
					minimalControllerAwaitBlockedApplication(t)
					select {
					case <-c.done:
						t.Fatal("application write did not remain pending")
					case <-c.readyDone:
						t.Fatal("blocked request published readiness")
					default:
					}
					joined := make(chan struct{})
					go func() {
						defer close(joined)
						if operation == "owner-cancel" {
							stopOwner()
							<-c.done
						} else {
							_ = c.Close()
						}
					}()
					select {
					case <-joined:
					case <-time.After(time.Second):
						t.Error("Close waited for State.mu before closing blocked I/O")
						stopOwner() // bounded fixture rescue before deferred joins
						awaitMinimalTransportREDDone(t, joined)
					}
					if !time.Now().Before(deadline) {
						t.Error("join relied on admission expiry")
					}
					minimalControllerRequireJoined(t, c, admission.controllerKey)
					return nil
				})
				stopPeer()
				awaitMinimalTransportREDDone(t, peerDone)
				if err == nil || !errors.Is(peerErr, context.Canceled) || f.listener.connects.Load() != 1 {
					t.Fatal("backpressure result or fixture prerequisite changed", peerErr)
				}
				return nil
			})
			if code != 0 {
				t.Fatal("backpressure fixture failed")
			}
		})
	}
}

func minimalControllerAwaitBlockedApplication(t *testing.T) {
	t.Helper()
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		buffer := make([]byte, 1<<20)
		n := runtime.Stack(buffer, true)
		for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
			if strings.Contains(stack, "session.(*State).WriteApplication") && strings.Contains(stack, "internal/poll.(*FD).Write") &&
				!strings.Contains(stack, "sync.(*Once).doSlow") && !strings.Contains(stack, "firecrackerhost.TestMinimalControlControllerCloseJoinsBlockedApplicationWrite.func") {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("actual authenticated application write did not block")
}
