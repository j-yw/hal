//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"golang.org/x/sys/unix"
)

func TestMinimalHostInspectionFreshFailureRetiresWithoutProof(t *testing.T) {
	for _, fault := range []string{"network-drift", "socket-drift", "error", "panic", "owner-loss"} {
		t.Run(fault, func(t *testing.T) {
			withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
				o, guestDone, rescue := minimalInspectionForwardGuest(t, f, func(options *server.Options, o *minimalHostInspectionObservations) {
					original := options.WorkloadIsolationVerifier
					options.WorkloadIsolationVerifier = minimalInspectionVerifierFunc(func(ctx context.Context) (server.IsolationProofResult, error) {
						result, err := original.VerifyWorkloadIsolation(ctx)
						if o.process[0].Load() > 1 {
							switch fault {
							case "network-drift":
								result.Network.ProxyReachable = false
							case "socket-drift":
								if err := os.Chmod(f.paths.VsockSocketPath, 0o644); err != nil {
									return result, err
								}
							case "error":
								return result, errors.New("private-inspection-failure")
							case "panic":
								panic("private-inspection-panic")
							case "owner-loss":
								f.owned.minimalPreparation.revoke()
							}
						}
						return result, err
					})
				})
				defer rescue()
				_, candidate := minimalSupervisorWorkClient(t, f)
				response, err := candidate.RoundTrip(context.Background(), minimalHostInspectionCarrier(minimalInspectionOperation))
				defer clear(response.Encoded)
				if err == nil || len(response.Encoded) != 0 || o.counts() != [7]int32{2, 2, 2, 2, 1, 0, 0} {
					t.Fatal("failed fresh inspection yielded proof or extra work")
				}
				if !errors.Is(err, errL8RuntimeOwnerInvalid) {
					t.Fatal("inspection failure escaped its fixed sanitized transport error")
				}
				minimalSupervisorWorkJoined(t, f)
				minimalJointAwait(t, guestDone, "failed inspection guest joined")
				if candidate.inspection != (minimalInspectionLifetime{}) {
					t.Fatal("failed inspection cached a successful lifetime pin")
				}
			})
		})
	}
}

func TestMinimalHostInspectionRawReplayAndBindingNegatives(t *testing.T) {
	for _, fault := range []string{"replay", "skipped-ordinal", "session", "binding", "noncanonical-body"} {
		t.Run(fault, func(t *testing.T) {
			withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
				o, rescue := minimalHostInspectionGuest(t, f)
				defer rescue()
				_, candidate := minimalSupervisorWorkClient(t, f)
				response, err := candidate.RoundTrip(context.Background(), minimalHostInspectionCarrier(minimalInspectionOperation))
				defer clear(response.Encoded)
				if err != nil || o.counts() != [7]int32{2, 2, 2, 2, 1, 0, 0} {
					t.Fatal("actual first inspection prerequisite", err)
				}
				header := minimalWorkHeader{direction: minimalWorkRequest, operation: minimalInspectionOperation, ordinal: 2, maximum: 2048,
					session: candidate.event.sessionID, binding: candidate.event.readinessBindingSHA256}
				body := []byte(minimalInspectionRequest)
				defer clear(body)
				switch fault {
				case "replay":
					header.ordinal--
				case "skipped-ordinal":
					header.ordinal++
				case "session":
					header.session[0] ^= 1
				case "binding":
					header.binding[0] ^= 1
				case "noncanonical-body":
					body[2] = 'O'
				}
				if writeMinimalWorkFrame(f.producer.conn, header, body) != nil {
					t.Fatal("actual invalid inspection peer frame")
				}
				minimalSupervisorWorkJoined(t, f)
				if o.counts() != [7]int32{2, 2, 2, 2, 1, 0, 0} {
					t.Fatal("invalid inspection advanced fresh verification")
				}
			})
		})
	}
}

func TestMinimalHostInspectionControllerRejectsMismatchedCarrier(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		o, rescue := minimalHostInspectionGuest(t, f)
		defer rescue()
		_, candidate := minimalSupervisorWorkClient(t, f)
		serving := f.serving(t)
		serving.mu.Lock()
		pair := serving.server
		serving.mu.Unlock()
		minimalJointAwait(t, pair.commit, "actual original publication")
		for _, operation := range []guestagent.Operation{guestagent.OperationExec, guestagent.OperationCopyIn, guestagent.OperationCopyOut} {
			response, err := pair.work.RoundTrip(context.Background(), minimalHostInspectionCarrier(operation))
			clear(response.Encoded)
			if err == nil || !pair.ready.Current() || o.counts() != [7]int32{1, 1, 1, 1, 1, 0, 0} {
				t.Fatal("original controller forwarded mismatched inspection")
			}
		}
		response, err := candidate.RoundTrip(context.Background(), minimalHostInspectionCarrier(minimalInspectionOperation))
		defer clear(response.Encoded)
		if err != nil || o.counts() != [7]int32{2, 2, 2, 2, 1, 0, 0} {
			t.Fatal("controller rejection consumed original inspection owner", err)
		}
		f.producer.retire()
		minimalSupervisorWorkJoined(t, f)
	})
}

func TestMinimalHostInspectionBlockedVerifierLossAndDeadline(t *testing.T) {
	for _, loss := range []string{"caller", "work-eof", "owner", "five-second-budget", "earlier-caller-deadline"} {
		t.Run(loss, func(t *testing.T) {
			withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
				entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var once sync.Once
				o, guestDone, rescue := minimalInspectionForwardGuest(t, f, func(options *server.Options, o *minimalHostInspectionObservations) {
					original := options.WorkloadIsolationVerifier
					options.WorkloadIsolationVerifier = minimalInspectionVerifierFunc(func(ctx context.Context) (server.IsolationProofResult, error) {
						result, err := original.VerifyWorkloadIsolation(ctx)
						if o.process[0].Load() > 1 {
							close(entered)
							<-ctx.Done()
							close(canceled)
							<-release // Explicit trusted callback join, not detached cleanup.
						}
						return result, err
					})
				})
				defer rescue()
				client, candidate := minimalSupervisorWorkClient(t, f)
				caller, cancel := context.WithCancel(context.Background())
				if loss == "earlier-caller-deadline" {
					cancel()
					caller, cancel = context.WithTimeout(context.Background(), time.Second)
				}
				started := time.Now()
				finished := make(chan struct{})
				var response guestagent.TransportResponse
				var callErr error
				go func() {
					defer close(finished)
					response, callErr = candidate.RoundTrip(caller, minimalHostInspectionCarrier(minimalInspectionOperation))
				}()
				defer func() {
					once.Do(func() { close(release) })
					cancel()
					minimalJointAwait(t, finished, "blocked caller rescue joined")
					clear(response.Encoded)
				}()
				minimalJointAwait(t, entered, "actual fresh verifier entered")
				_, busy := candidate.RoundTrip(context.Background(), minimalHostInspectionCarrier(minimalInspectionOperation))
				var protocol *guestagent.ProtocolError
				if !errors.As(busy, &protocol) || protocol.Code != guestagent.ErrorCodeServerBusy {
					t.Fatal("concurrent inspection did not preserve the admitted slot")
				}
				_, busy = client.Exec(context.Background(), minimalJointExecRequest())
				var cause *guestagent.ProtocolError
				if !errors.As(busy, &protocol) || protocol.Code != guestagent.ErrorCodeTransportFailure ||
					!errors.As(errors.Unwrap(busy), &cause) || cause.Code != guestagent.ErrorCodeServerBusy {
					t.Fatal("ordinary work bypassed the original inspection admission slot")
				}
				preCanceled, stop := context.WithCancel(context.Background())
				stop()
				if _, err := client.Exec(preCanceled, minimalJointExecRequest()); err == nil || o.counts() != [7]int32{2, 2, 2, 2, 1, 0, 0} {
					t.Fatal("unadmitted loser advanced inspection/backend work")
				}
				switch loss {
				case "caller":
					cancel()
				case "work-eof":
					raw, err := f.producer.conn.SyscallConn()
					if err != nil {
						t.Fatal(err)
					}
					var shutdown error
					if raw.Control(func(fd uintptr) { shutdown = unix.Shutdown(int(fd), unix.SHUT_RDWR) }) != nil || shutdown != nil {
						t.Fatal("actual original work endpoint shutdown")
					}
				case "owner":
					f.owned.minimalPreparation.revoke()
				}
				select {
				case <-canceled:
				case <-time.After(8 * time.Second):
					t.Fatal("unchanged five-second inspection budget did not cancel the real guest call")
				}
				if loss == "five-second-budget" && time.Since(started) < minimalInspectionTimeout ||
					loss == "earlier-caller-deadline" && time.Since(started) >= minimalInspectionTimeout {
					t.Fatal("inspection rebased or ignored the original operation/caller deadline")
				}
				select {
				case <-guestDone:
					t.Fatal("guest abandoned its still-held inspection callback")
				default:
				}
				if o.backend.closes.Load() != 0 {
					t.Fatal("guest backend closed before inspector joined")
				}
				once.Do(func() { close(release) })
				minimalJointAwait(t, finished, "original inspection call joined")
				minimalSupervisorWorkJoined(t, f)
				minimalJointAwait(t, guestDone, "released inspector and guest joined")
				if callErr == nil || len(response.Encoded) != 0 || o.counts() != [7]int32{2, 2, 2, 2, 1, 0, 0} {
					t.Fatal("lost inspection returned proof or repeated work")
				}
			})
		})
	}
}

func TestMinimalHostInspectionOriginalPublicationGate(t *testing.T) {
	for _, commit := range []bool{true, false} {
		name := "cancel"
		if commit {
			name = "commit"
		}
		t.Run(name, func(t *testing.T) {
			withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
				prep := f.owned.minimalPreparation
				prep.mu.Lock()
				prepLocked, pairLocked := true, false
				var pair *minimalControlWorkServer
				var rescue func()
				var cancel context.CancelFunc
				var finished chan struct{}
				defer func() {
					if pairLocked {
						pair.mu.Unlock()
					}
					if prepLocked {
						prep.mu.Unlock()
					}
					if cancel != nil {
						cancel()
						minimalJointAwait(t, finished, "pending inspection rescue joined")
					}
					if rescue != nil {
						rescue()
					}
				}()
				o, guestRescue := minimalHostInspectionGuest(t, f)
				rescue = guestRescue
				serving := f.serving(t)
				minimalSupervisorWorkObserve(t, "original pair before inspection publication", func() bool {
					serving.mu.Lock()
					defer serving.mu.Unlock()
					pair = serving.server
					return pair != nil
				})
				pair.mu.Lock()
				pairLocked = true
				prep.mu.Unlock()
				prepLocked = false
				_, candidate := minimalSupervisorWorkClient(t, f)
				prep.mu.Lock()
				prepLocked = true
				pair.mu.Unlock()
				pairLocked = false
				ctx, stop := context.WithCancel(context.Background())
				cancel, finished = stop, make(chan struct{})
				var response guestagent.TransportResponse
				var callErr error
				go func() {
					defer close(finished)
					response, callErr = candidate.RoundTrip(ctx, minimalHostInspectionCarrier(minimalInspectionOperation))
				}()
				minimalSupervisorWorkObserve(t, "actual code-4 frame pending before publication", func() bool {
					pair.mu.Lock()
					defer pair.mu.Unlock()
					return pair.pending != nil && pair.pending.header.operation == minimalInspectionOperation && pair.active == nil && pair.ordinal == 1
				})
				select {
				case <-pair.commit:
					t.Fatal("inspection bypassed original publication gate")
				default:
				}
				if o.counts() != [7]int32{1, 1, 1, 1, 1, 0, 0} || prep.canceled.workPublished() {
					t.Fatal("inspection ran before original commit")
				}
				originalP, originalH := prep.deadline, pair.ready.hardExpiry
				if !commit {
					prep.revoke()
				}
				prep.mu.Unlock()
				prepLocked = false
				minimalJointAwait(t, finished, "original pending inspection joined")
				defer clear(response.Encoded)
				if commit {
					if callErr != nil || len(response.Encoded) == 0 || o.counts() != [7]int32{2, 2, 2, 2, 1, 0, 0} {
						t.Fatal("original commit did not dispatch one fresh inspection", callErr)
					}
				} else if callErr == nil || len(response.Encoded) != 0 || o.counts() != [7]int32{1, 1, 1, 1, 1, 0, 0} {
					t.Fatal("canceled publication dispatched inspection")
				}
				if prep.deadline != originalP || pair.ready.hardExpiry != originalH {
					t.Fatal("inspection rebased P/H")
				}
				f.producer.retire()
				minimalSupervisorWorkJoined(t, f)
			})
		})
	}
}

func TestMinimalHostInspectionRawMismatchedCarrierStopsAtServer(t *testing.T) {
	for _, operation := range []guestagent.Operation{guestagent.OperationExec, guestagent.OperationCopyIn, guestagent.OperationCopyOut} {
		t.Run(string(operation), func(t *testing.T) {
			withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
				o, rescue := minimalHostInspectionGuest(t, f)
				defer rescue()
				_, candidate := minimalSupervisorWorkClient(t, f)
				// Malicious bytes use the actual retained endpoint, not an admitted
				// producer call. No fabricated reply or positive proof is supplied.
				header := minimalWorkHeader{direction: minimalWorkRequest, operation: operation, ordinal: 1, maximum: 2048,
					session: candidate.event.sessionID, binding: candidate.event.readinessBindingSHA256}
				if writeMinimalWorkFrame(f.producer.conn, header, []byte(minimalInspectionRequest)) != nil {
					t.Fatal("actual mismatched peer write")
				}
				minimalSupervisorWorkJoined(t, f)
				if o.counts() != [7]int32{1, 1, 1, 1, 1, 0, 0} {
					t.Fatal("server passed mismatched carrier to fresh verification")
				}
			})
		})
	}
}
