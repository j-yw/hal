//go:build linux

package firecrackerhost

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMinimalHostTransportAdmissionDeadlineIncludesFinalCurrentness(t *testing.T) {
	for _, checkpoint := range []struct {
		name         string
		call         int
		pendingTimer bool
	}{{"after_ack", 1, false}, {"reset_stream_deadline", 2, false}, {"final_currentness", 3, false}, {"timer_not_yet_fired", 3, true}} {
		t.Run(checkpoint.name, func(t *testing.T) {
			fixture, connector := minimalTransportFixture(t)
			connector.handshakeTimeout = 100 * time.Millisecond
			caller := context.Background()
			if checkpoint.pendingTimer {
				// Model a deadline whose cancellation callback has not run yet.
				// No production clock/context dependency is added for this test.
				caller = minimalTransportPendingDeadline{Context: caller, deadline: time.Now().Add(connector.handshakeTimeout)}
			}
			var admission context.Context
			connector.dial = func(ctx context.Context, network, path string) (net.Conn, error) {
				admission = ctx
				return (&net.Dialer{}).DialContext(ctx, network, path)
			}
			var acknowledged atomic.Bool
			var rechecks int
			delayed := false
			deadlineObserved := false
			observe := connector.checks.observe
			connector.checks.observe = func(path string) (vsockSocketObservation, error) {
				// Select the synchronous Open recheck, not its background watcher.
				// The observation remains bounded by the real admission context;
				// this models a slow post-ACK stat without a new production hook.
				if acknowledged.Load() && minimalTransportObservationFromOpen() {
					rechecks++
					if rechecks == checkpoint.call {
						delayed = true
						if checkpoint.pendingTimer {
							deadline, _ := admission.Deadline()
							timer := time.NewTimer(time.Until(deadline) + time.Millisecond)
							<-timer.C
							deadlineObserved = !time.Now().Before(deadline) && admission.Err() == nil
						} else {
							<-admission.Done()
							deadlineObserved = admission.Err() == context.DeadlineExceeded
						}
					}
				}
				return observe(path)
			}
			peerClosed := make(chan struct{})
			minimalTransportServer(t, fixture, func(ctx context.Context, conn net.Conn) {
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil || line != "CONNECT 1025\n" {
					t.Error("missing actual CONNECT transcript")
					return
				}
				acknowledged.Store(true)
				if _, err := io.WriteString(conn, "OK 1\n"); err != nil {
					t.Error("failed actual ACK transcript")
					return
				}
				var one [1]byte
				if n, err := conn.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
					t.Error("expired admission did not close without application bytes")
					return
				}
				close(peerClosed)
				<-ctx.Done()
			})
			before := minimalControlTransportGeneration.Load()
			stream, err := connector.Open(caller)
			if stream != nil {
				_ = stream.Close() // RED cleanup only; a returned stream fails below.
			}
			if !delayed || !deadlineObserved {
				t.Fatal("regression did not cross the admission deadline during currentness")
			}
			if stream != nil || !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("expired final admission returned stream=%v error=%v", stream != nil, err)
			}
			if after := minimalControlTransportGeneration.Load(); after != before {
				t.Error("expired final admission allocated a transport generation")
			}
			awaitMinimalTransportREDDone(t, peerClosed)
			if fixture.bridge.session("fc-production-test") != nil {
				t.Fatal("expired transport published legacy readiness")
			}
		})
	}
}

type minimalTransportPendingDeadline struct {
	context.Context
	deadline time.Time
}

func (ctx minimalTransportPendingDeadline) Deadline() (time.Time, bool) {
	return ctx.deadline, true
}

func minimalTransportObservationFromOpen() bool {
	var callers [16]uintptr
	count := runtime.Callers(2, callers[:])
	frames := runtime.CallersFrames(callers[:count])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, ".(*minimalControlTransport).Open") {
			return true
		}
		if !more {
			return false
		}
	}
}
