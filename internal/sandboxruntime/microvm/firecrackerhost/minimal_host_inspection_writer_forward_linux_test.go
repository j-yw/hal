//go:build linux

package firecrackerhost

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"golang.org/x/sys/unix"
)

func TestMinimalHostInspectionActualBlockedIPCWriterAndPendingLoss(t *testing.T) {
	for _, loss := range []string{"owner", "pending-eof", "pending-extra"} {
		t.Run(loss, func(t *testing.T) {
			withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				o, guestDone, rescue := minimalInspectionForwardGuest(t, f, func(options *server.Options, o *minimalHostInspectionObservations) {
					original := options.WorkloadIsolationVerifier
					options.WorkloadIsolationVerifier = minimalInspectionVerifierFunc(func(ctx context.Context) (server.IsolationProofResult, error) {
						result, err := original.VerifyWorkloadIsolation(ctx)
						if o.process[0].Load() > 1 {
							close(entered)
							select {
							case <-ctx.Done():
								return result, ctx.Err()
							case <-release:
							}
						}
						return result, err
					})
				})
				defer rescue()
				_, candidate := minimalSupervisorWorkClient(t, f)
				serving := f.serving(t)
				serving.mu.Lock()
				pair := serving.server
				serving.mu.Unlock()
				minimalJointAwait(t, pair.commit, "actual original publication commit")
				if pair.conn.SetWriteBuffer(2048) != nil {
					t.Fatal("actual server write buffer bound")
				}
				raw, err := pair.conn.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				finished := make(chan struct{})
				var response guestagent.TransportResponse
				var callErr error
				go func() {
					defer close(finished)
					response, callErr = candidate.RoundTrip(ctx, minimalHostInspectionCarrier(minimalInspectionOperation))
				}()
				locked := false
				defer func() {
					if locked {
						f.producer.mu.Unlock()
					}
					once.Do(func() { close(release) })
					cancel()
					minimalJointAwait(t, finished, "blocked inspection writer caller rescue")
					clear(response.Encoded)
				}()
				minimalJointAwait(t, entered, "actual fresh verifier before original response")
				f.producer.mu.Lock()
				locked = true
				header := f.producer.active.header
				// The original sole producer reader will block on this mutex after
				// its first byte. Bounded junk fills its actual receive queue; this
				// is an adversarial backpressure case, never a fabricated proof.
				full, sends := false, 0
				var sendErr error
				controlErr := raw.Control(func(fd uintptr) {
					var filler [1024]byte
					for sends < 64 {
						_, sendErr = unix.SendmsgN(int(fd), filler[:], nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
						if sendErr == unix.EAGAIN {
							full = true
							return
						}
						if sendErr != nil {
							return
						}
						sends++
					}
				})
				if controlErr != nil || !full || sends == 0 {
					t.Fatal("actual bounded IPC queue did not fill", controlErr, sendErr)
				}
				once.Do(func() { close(release) })
				stack := make([]byte, 256<<10)
				minimalSupervisorWorkObserve(t, "original IPC inspection writer blocked in kernel-backed I/O", func() bool {
					pair.mu.Lock()
					writing := pair.writing && pair.active != nil
					pair.mu.Unlock()
					if !writing {
						return false
					}
					n := runtime.Stack(stack, true)
					for _, goroutine := range strings.Split(string(stack[:n]), "\n\n") {
						if strings.Contains(goroutine, "firecrackerhost.(*minimalControlWorkServer).exchange") &&
							strings.Contains(goroutine, "internal/poll.(*FD).Write") && strings.Contains(goroutine, "[IO wait]") {
							return true
						}
					}
					return false
				})
				if loss != "owner" {
					header.ordinal++
					if writeMinimalWorkFrame(f.producer.conn, header, []byte(minimalInspectionRequest)) != nil {
						t.Fatal("actual pending inspection peer frame")
					}
					minimalSupervisorWorkObserve(t, "one bounded pending inspection beside writer", func() bool {
						pair.mu.Lock()
						defer pair.mu.Unlock()
						return pair.pending != nil && pair.writing && pair.ordinal == 2
					})
				}
				if o.counts() != [7]int32{2, 2, 2, 2, 1, 0, 0} {
					t.Fatal("pending inspection ran alongside blocked writer")
				}
				switch loss {
				case "owner":
					f.owned.minimalPreparation.revoke()
				case "pending-extra":
					if _, err := f.producer.conn.Write([]byte{0}); err != nil {
						t.Fatal("actual excess peer byte", err)
					}
				case "pending-eof":
					peer, err := f.producer.conn.SyscallConn()
					if err != nil {
						t.Fatal(err)
					}
					var shutdown error
					if peer.Control(func(fd uintptr) { shutdown = unix.Shutdown(int(fd), unix.SHUT_RDWR) }) != nil || shutdown != nil {
						t.Fatal("actual inspection peer EOF")
					}
				}
				minimalJointAwait(t, pair.reader, "original sole request reader joined")
				minimalJointAwait(t, pair.worker, "actual blocked inspection writer joined")
				f.producer.mu.Unlock()
				locked = false
				minimalJointAwait(t, finished, "lost inspection caller joined")
				minimalSupervisorWorkJoined(t, f)
				minimalJointAwait(t, guestDone, "original inspection guest joined")
				if callErr == nil || len(response.Encoded) != 0 || o.counts() != [7]int32{2, 2, 2, 2, 1, 0, 0} {
					t.Fatal("blocked/pending inspection returned proof or dispatched extra work")
				}
			})
		})
	}
}
