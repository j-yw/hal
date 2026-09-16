//go:build linux

package firecrackerhost

import (
	"context"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"golang.org/x/sys/unix"
)

func TestMinimalSupervisorWorkCandidateBeforePublicationCommit(t *testing.T) {
	for _, disposition := range []string{"commit", "cancel", "original-admission-expiry"} {
		t.Run(disposition, func(t *testing.T) {
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
						minimalJointAwait(t, finished, "explicit early-work caller rescue")
					}
					if rescue != nil {
						rescue()
					}
				}()
				backend, verifier, _, guestRescue := f.guest(t, nil)
				rescue = guestRescue
				serving := f.serving(t)
				// Actual authentication constructs and registers the partial pair
				// before sendWorkEndpoint can acquire the original prep mutex.
				minimalSupervisorWorkObserve(t, "original registered pair before original send", func() bool {
					serving.mu.Lock()
					defer serving.mu.Unlock()
					pair = serving.server
					return pair != nil
				})
				pair.mu.Lock()
				pairLocked = true
				prep.mu.Unlock()
				prepLocked = false
				client, candidate := minimalSupervisorWorkClient(t, f)
				// Real RD2 and its FD have arrived. The publisher cannot surrender
				// its local producer alias until this held pair mutex is released.
				prep.mu.Lock()
				prepLocked = true
				pair.mu.Unlock()
				pairLocked = false
				caller, stop := context.WithCancel(context.Background())
				cancel, finished = stop, make(chan struct{})
				var response *guestagent.ExecResponse
				var callErr error
				go func() { defer close(finished); response, callErr = client.Exec(caller, minimalJointExecRequest()) }()
				minimalSupervisorWorkObserve(t, "actual first Client request pending before publication commit", func() bool {
					pair.mu.Lock()
					defer pair.mu.Unlock()
					return pair.pending != nil && pair.active == nil && pair.ordinal == 1
				})
				// The real request reader's original mutex supplies initialization
				// synchronization. Candidate arrival alone was not used as that proof.
				select {
				case <-pair.commit:
					t.Fatal("publication committed while original preparation mutex held")
				default:
				}
				if prep.canceled.workPublished() || backend.calls.Load() != 0 || verifier.calls.Load() != 1 || candidate.launch != f.producer {
					t.Fatal("candidate falsely admitted backend work before original commit")
				}
				t.Log("actual original RD2 candidate and first Client frame reached pending slot with commit open and backend zero")
				ready := pair.ready
				originalP, originalH := prep.deadline, ready.hardExpiry
				originalWindow, ok := f.owned.selected.starter.minimalGate.releaseWindow()
				if !ok {
					t.Fatal("original release window missing")
				}
				bound := earlierMinimalControlTime(originalP, earlierMinimalControlTime(originalWindow.deadline, ready.admissionDeadline))
				switch disposition {
				case "cancel":
					prep.revoke() // Actual cancellation publication is lock-free.
				case "original-admission-expiry":
					if !time.Now().Before(bound) || !bound.Before(originalP) || !bound.Before(originalH) {
						t.Fatal("genuine unspent A/D bound before P/H not reached")
					}
					timer := time.NewTimer(time.Until(bound) + time.Millisecond)
					select {
					case <-prep.ctx.Done():
						timer.Stop()
						t.Fatal("original owner lost before actual admission bound")
					case <-timer.C:
					}
				}
				prep.mu.Unlock()
				prepLocked = false
				minimalJointAwait(t, finished, "actual early first Client call joined")
				if disposition == "commit" {
					minimalJointAwait(t, pair.commit, "actual publication success gate")
					minimalJointAwait(t, prep.observerDone, "actual admission observer joined before dispatch")
					if callErr != nil || response == nil || response.ExitCode != 7 || backend.calls.Load() != 1 || verifier.calls.Load() != 2 || !prep.workCurrent() {
						t.Fatal("genuine early request failed after original commit", callErr)
					}
					f.producer.close()
				} else if callErr == nil || backend.calls.Load() != 0 || verifier.calls.Load() != 1 || prep.canceled.workPublished() {
					t.Fatal("received candidate bypassed failed or expired publication", callErr)
				}
				minimalSupervisorWorkJoined(t, f)
				window, retained := f.owned.selected.starter.minimalGate.releaseWindow()
				if !retained || window != originalWindow || prep.deadline != originalP || ready.hardExpiry != originalH || serving.publishWork(ready) == nil {
					t.Fatal("publication replayed or rebased original R/D/P/H")
				}
				fd, session := f.cleanup(t)
				defer unix.Close(fd)
				minimalSupervisorJointInspect(t, fd, session)
			})
		})
	}
}
