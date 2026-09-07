package sandboxworker

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestMinimalLaunchServiceRequestCorrelationAfterPreparation(t *testing.T) {
	for _, action := range []string{"cancel", "service", "authority"} {
		t.Run(action, func(t *testing.T) {
			f := newMinimalLaunchOwnedContextFixture(t, 750*time.Millisecond)
			f.start(t, context.Background())
			want := minimalRequestPair(*f.base.request.JobStartV2)
			waitMinimalLaunchOwnedContext(t, f.provider.ctx)
			if got, err := f.provider.reservation.RequestCorrelation(); err != nil || got != want {
				t.Fatal("P erased actual accepted request correlation")
			}
			switch action {
			case "cancel":
				if response := f.service.HandleAuthenticatedRequest(context.Background(), f.base.principal, f.cancelRequest(t)); response.OK {
					t.Fatal("cancel manufactured completion")
				}
			case "service":
				f.service.Close()
			case "authority":
				f.base.authorizer.Close()
			}
			waitMinimalLaunchOwnedContext(t, f.provider.reservation.OwnedContext())
			if got, err := f.provider.reservation.RequestCorrelation(); err != nil || got != want {
				t.Fatal("revoked service ownership erased original request correlation")
			}
			f.assertRetained(t, action == "cancel")
		})
	}
}

func TestMinimalLaunchServiceRequestCorrelationCancelMemoryAndDisk(t *testing.T) {
	for _, mode := range []string{"memory grant", "memory revision", "disk grant", "disk revision", "disk request key", "caller and partial Start"} {
		t.Run(mode, func(t *testing.T) {
			memory := strings.HasPrefix(mode, "memory")
			f := newMinimalLaunchCancelFixture(t, !memory)
			want := minimalRequestPair(*f.base.request.JobStartV2)
			before := f.recordBytes(t)
			id := f.entered.identity.WorkerJobID
			f.lockManager(t)
			original := cloneStoredJobStateV2(f.service.jobs.states[id])
			changed := cloneStoredJobStateV2(original)
			if strings.HasSuffix(mode, "grant") {
				changed.JobV2.CredentialIntent.AdmissionGrantID = "foreign-original-grant"
			} else if strings.HasSuffix(mode, "revision") {
				changed.JobV2.CredentialIntent.AdmissionGrantRevision++
			} else if mode == "disk request key" {
				changed.RequestKey = "request-v2-" + strings.Repeat("f", 64)
			}
			if memory {
				f.service.jobs.states[id] = changed
			}
			f.service.jobs.mu.Unlock()
			var restoreOnce sync.Once
			restore := func() {
				restoreOnce.Do(func() {
					f.service.jobs.mu.Lock()
					f.service.jobs.states[id] = original
					f.service.jobs.mu.Unlock()
				})
			}
			if memory {
				t.Cleanup(restore)
				response := f.service.HandleAuthenticatedRequest(context.Background(), f.base.principal, f.cancelRequest(t))
				if response.OK || f.entered.reservation.Context().Err() != nil || !bytes.Equal(before, f.recordBytes(t)) {
					t.Fatal("foreign retained credential pair revoked or rewrote original ownership")
				}
				restore()
			} else if strings.HasPrefix(mode, "disk") {
				payload, err := encodeStoredJobStateV2(changed)
				if err != nil || changed.Validate() != nil || os.WriteFile(filepath.Join(f.base.stateDir, id+".json"), payload, 0o600) != nil {
					t.Fatal("could not install valid-shaped disk-only replacement")
				}
				response, done := f.cancelAsync(t, context.Background(), f.base.principal, f.cancelRequest(t))
				waitMinimalLaunchOwnedContext(t, f.entered.reservation.OwnedContext())
				f.unblock()
				if got := waitMinimalLaunchCancelResponse(t, response); got.OK {
					t.Fatal("lost disk correlation manufactured durable cancellation")
				}
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("cancel waiter did not join")
				}
				if !bytes.Equal(payload, f.recordBytes(t)) {
					t.Fatal("local revoke rewrote untrusted disk data")
				}
			} else {
				// Start has already consumed its cloned request and is blocked.
				f.base.request.JobStartV2.AdmissionGrantID = "caller-replacement"
				f.base.request.JobStartV2.AdmissionGrantRevision++
			}
			f.unblock()
			_ = f.waitStart(t)
			if got, err := f.entered.reservation.RequestCorrelation(); err != nil || got != want {
				t.Fatal("pending or failed original owner lost immutable request correlation")
			}
			f.assertRetained(t, !memory)
			f.assertNoCleanup(t)
		})
	}
}

func TestMinimalLaunchServiceRequestCorrelationDuplicateExactness(t *testing.T) {
	for _, mode := range []string{"same request", "changed grant", "changed revision"} {
		t.Run(mode, func(t *testing.T) {
			f := newMinimalLaunchOwnedContextFixture(t, time.Minute)
			f.start(t, context.Background())
			before := f.recordBytes(t)
			want := minimalRequestPair(*f.base.request.JobStartV2)
			request := f.base.request
			start := cloneJobStartRequestV2(*request.JobStartV2)
			request.JobStartV2 = &start
			if mode == "changed grant" {
				start.AdmissionGrantID = "different-admission-grant"
			} else if mode == "changed revision" {
				start.AdmissionGrantRevision++
			}
			response := f.service.HandleAuthenticatedRequest(context.Background(), f.base.principal, request)
			if mode == "same request" {
				if !response.OK || response.JobV2 == nil || response.JobV2.State != JobStateQueued || response.JobV2.FinishedAt != nil || response.JobV2.StartedAt != nil {
					t.Fatal("exact duplicate did not preserve existing queued resolution")
				}
			} else if response.OK {
				t.Fatal("changed original intent reused accepted submission")
			}
			if f.provider.starts != 1 || f.provider.base.resolveCalls != 1 || !bytes.Equal(before, f.recordBytes(t)) {
				t.Fatal("duplicate or conflict allocated/resolved/published again")
			}
			if got, err := f.provider.reservation.RequestCorrelation(); err != nil || got != want {
				t.Fatal("duplicate request relabeled retained original correlation")
			}
		})
	}
}

func minimalRequestPair(request JobStartRequestV2) sandboxruntime.MinimalLaunchRequestCorrelation {
	return sandboxruntime.MinimalLaunchRequestCorrelation{AdmissionGrantID: request.AdmissionGrantID, AdmissionGrantRevision: request.AdmissionGrantRevision}
}
