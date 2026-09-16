//go:build linux

package firecrackerhost

import "time"

const minimalPreparationWorkPublished uint32 = 1 << 2

func (latch *minimalControlPreparationLatch) workPublished() bool {
	return latch.state.Load()&minimalPreparationWorkPublished != 0
}

// Keep the existing single cancellation/release authority. Neither this bit nor
// observer completion resets R/D or clears an already observed cancellation.
func (latch *minimalControlPreparationLatch) publishWork() bool {
	return latch.state.CompareAndSwap(minimalPreparationReleaseAdmitted, minimalPreparationReleaseAdmitted|minimalPreparationWorkPublished)
}

func (prep *minimalControlPreparation) workCurrent() bool {
	return prep != nil && prep.ctx != nil && prep.canceled.workPublished() && !prep.canceled.Load() && prep.ctx.Err() == nil
}

// Called only after the original owned send operation has returned and joined.
// No guest/kernel observation or task join is performed under preparation.mu.
func (prep *minimalControlPreparation) commitWorkPublication(ready *minimalControlReadiness, window minimalControlReleaseWindow) error {
	if ready == nil || !ready.Current() || window.startedAt.IsZero() || prep == nil {
		return errL8RuntimeOwnerInvalid
	}
	bound := earlierMinimalControlTime(ready.admissionDeadline, window.deadline)
	bound = earlierMinimalControlTime(bound, prep.deadline)
	prep.mu.Lock()
	if prep.closing || prep.publicationStop == nil || !prep.current() || !time.Now().Before(bound) || !prep.canceled.publishWork() {
		prep.mu.Unlock()
		return errL8RuntimeOwnerInvalid
	}
	close(prep.publicationStop)
	prep.mu.Unlock()
	<-prep.observerDone
	prep.stopPreparation() // Release only the spent admission timer, not prep.ctx.
	if !prep.workCurrent() || !ready.Current() {
		prep.revoke()
		return errL8RuntimeOwnerInvalid
	}
	return nil
}
