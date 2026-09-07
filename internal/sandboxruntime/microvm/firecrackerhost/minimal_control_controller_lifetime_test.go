//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func minimalControllerRequireReady(t *testing.T, c *minimalControlController) *minimalControlReadiness {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ready, err := c.WaitReady(ctx)
	if err != nil || !ready.Current() {
		t.Fatal("actual retained transcript failed", err)
	}
	return ready
}

func minimalControllerRequireJoined(t *testing.T, c *minimalControlController, key []byte) {
	t.Helper()
	if c == nil {
		t.Fatal("controller scope was not reached")
	}
	select {
	case <-c.done:
	default:
		t.Fatal("scope returned before task joined")
	}
	select {
	case <-c.loss:
	default:
		t.Fatal("joined controller retained readiness latch")
	}
	if c.ctx.Err() == nil || !bytes.Equal(key, make([]byte, len(key))) {
		t.Fatal("scope retained owner context or borrowed key")
	}
	if c.Close() != nil {
		t.Fatal("repeated Close failed")
	}
}

func TestMinimalControlControllerPreparationLifetime(t *testing.T) {
	for _, name := range []string{"owner-cancel", "callback-return", "callback-panic", "waiter-cancel"} {
		t.Run(name, func(t *testing.T) {
			a := newMinimalControlAdmissionFixture(t)
			var captured *minimalControlController
			var key ed25519.PrivateKey
			code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				f := newMinimalControllerFixture(t, admission)
				defer f.close(t)
				key = admission.controllerKey
				owner, cancel := context.WithCancel(context.Background())
				defer cancel()
				entered, released := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(released) }) }
				defer release()
				// Existing per-instance test observation holds only initial dial.
				// On release the actual caller-UID Unix peer/parent checks still run.
				f.transport.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
					close(entered)
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-released:
					}
					return (&net.Dialer{}).DialContext(ctx, network, address)
				}
				err := withMinimalControlController(owner, f.transport, admission, time.Now().Add(3*time.Second), func(c *minimalControlController) error {
					captured = c
					select {
					case <-entered:
					case <-time.After(2 * time.Second):
						t.Fatal("dial boundary not reached")
					}
					switch name {
					case "owner-cancel":
						cancel()
						ctx, stop := context.WithTimeout(context.Background(), time.Second)
						defer stop()
						if ready, err := c.WaitReady(ctx); err == nil || ready != nil {
							t.Fatal("owner loss accepted readiness")
						}
					case "callback-panic":
						panic("private callback fixture")
					case "waiter-cancel":
						wait, stop := context.WithCancel(context.Background())
						stop()
						if ready, err := c.WaitReady(wait); err == nil || ready != nil || c.ctx.Err() != nil {
							t.Fatal("waiter cancellation became owner cancellation")
						}
						release()
						minimalControllerRequireReady(t, c)
					}
					return nil
				})
				if (err == nil) != (name == "waiter-cancel") {
					t.Fatalf("scope result=%v", err)
				}
				minimalControllerRequireJoined(t, captured, key)
				return nil
			})
			wantCode := 0
			if name == "callback-panic" {
				wantCode = 127
			}
			if code != wantCode || a.admissions != 1 || a.legacy != 0 {
				t.Fatalf("fixture result=%d admissions=%d legacy=%d", code, a.admissions, a.legacy)
			}
			minimalControllerRequireJoined(t, captured, key)
		})
	}
}

func TestMinimalControlControllerReadyLifetimeLoss(t *testing.T) {
	for _, name := range []string{"owner-cancel", "guest-eof", "process-exit", "socket-replacement", "parent-replacement", "callback-return", "callback-panic"} {
		t.Run(name, func(t *testing.T) {
			a := newMinimalControlAdmissionFixture(t)
			var captured *minimalControlController
			var ready *minimalControlReadiness
			var key ed25519.PrivateKey
			code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				f := newMinimalControllerFixture(t, admission)
				defer f.close(t)
				key = admission.controllerKey
				owner, cancel := context.WithCancel(context.Background())
				defer cancel()
				return withMinimalControlController(owner, f.transport, admission, time.Now().Add(3*time.Second), func(c *minimalControlController) error {
					captured = c
					ready = minimalControllerRequireReady(t, c)
					switch name {
					case "owner-cancel":
						cancel()
					case "guest-eof":
						f.cancel()
					case "process-exit":
						f.bridge.process.stop()
					case "socket-replacement":
						path := f.bridge.paths.VsockSocketPath
						if err := os.Rename(path, path+".old"); err != nil {
							t.Fatal(err)
						}
						replacement := l5ListenBridgeSocket(t, path)
						defer replacement.Close()
					case "parent-replacement":
						path := f.bridge.paths.StateDir
						if err := os.Rename(path, path+".old"); err != nil {
							t.Fatal(err)
						}
						if err := os.Mkdir(path, 0o700); err != nil {
							t.Fatal(err)
						}
					case "callback-return":
						return nil
					case "callback-panic":
						panic("private postready callback fixture")
					}
					select {
					case <-c.Loss():
					case <-time.After(time.Second):
						t.Fatal("stream/owner loss was not observed")
					}
					if c.Close() != nil || ready.Current() {
						t.Fatal("lost readiness survived joined Close")
					}
					minimalControllerRequireJoined(t, c, key)
					if name == "socket-replacement" || name == "parent-replacement" {
						path := f.bridge.paths.StateDir
						if name == "socket-replacement" {
							path = f.bridge.paths.VsockSocketPath
						}
						if _, err := os.Lstat(path); err != nil {
							t.Fatal("controller removed successor path")
						}
					}
					return nil
				})
			})
			wantCode := 0
			if name == "callback-panic" {
				wantCode = 127
			}
			if code != wantCode || a.admissions != 1 || a.legacy != 0 {
				t.Fatalf("fixture result=%d admissions=%d legacy=%d", code, a.admissions, a.legacy)
			}
			minimalControllerRequireJoined(t, captured, key)
			if ready == nil || ready.Current() {
				t.Fatal("escaped readiness remained current")
			}
		})
	}
}

func TestMinimalControlControllerConcurrentCloseAndWaiters(t *testing.T) {
	a := newMinimalControlAdmissionFixture(t)
	code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
		f := newMinimalControllerFixture(t, admission)
		defer f.close(t)
		return withMinimalControlController(context.Background(), f.transport, admission, time.Now().Add(3*time.Second), func(c *minimalControlController) error {
			ready := minimalControllerRequireReady(t, c)
			start := make(chan struct{})
			finished := make(chan struct{}, 24)
			for i := range 24 {
				go func() {
					defer func() { finished <- struct{}{} }()
					<-start
					if i%2 == 0 {
						_ = c.Close()
						return
					}
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					_, _ = c.WaitReady(ctx) // May race retirement; no waiter owns it.
				}()
			}
			close(start)
			for range 24 {
				select {
				case <-finished:
				case <-time.After(2 * time.Second):
					t.Fatal("concurrent Close/WaitReady did not join")
				}
			}
			if ready.Current() {
				t.Fatal("concurrent closure retained readiness")
			}
			minimalControllerRequireJoined(t, c, admission.controllerKey)
			return nil
		})
	})
	if code != 0 {
		t.Fatal("concurrent lifetime fixture failed")
	}
}

func TestMinimalControlControllerRejectsStaleTransportAndKey(t *testing.T) {
	for _, name := range []string{"claimed", "handle", "runtime", "exited", "short-key", "inconsistent-key"} {
		t.Run(name, func(t *testing.T) {
			a := newMinimalControlAdmissionFixture(t)
			code := a.run("supervise", func(admission *minimalControlSupervisorAdmission) error {
				f := newMinimalControllerFixture(t, admission)
				defer f.close(t)
				switch name {
				case "claimed":
					f.transport.claimed.Store(true)
				case "handle":
					f.transport.handle.ID += "-stale"
				case "runtime":
					f.transport.runtimeID = "other-runtime"
				case "exited":
					f.bridge.process.stop()
				case "short-key":
					admission.controllerKey = admission.controllerKey[:31]
				case "inconsistent-key":
					admission.controllerKey[0] ^= 1
				}
				err := withMinimalControlController(context.Background(), f.transport, admission, time.Now().Add(3*time.Second), func(c *minimalControlController) error {
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					if ready, err := c.WaitReady(ctx); err == nil || ready != nil {
						t.Error("stale input reached readiness")
					}
					return nil
				})
				if err == nil || f.listener.connects.Load() != 0 || !bytes.Equal(admission.controllerKey, make([]byte, len(admission.controllerKey))) {
					t.Fatal("stale input connected or retained borrowed key")
				}
				return nil
			})
			if code != 0 {
				t.Fatal("stale-input fixture did not complete")
			}
		})
	}
}
