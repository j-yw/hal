package sandboxworker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestMinimalLaunchCancelConcurrentAndRepeatedRequestsJoinOneDispatch(t *testing.T) {
	f := newMinimalLaunchCancelFixture(t, false)
	var renames atomic.Int32
	rename := f.service.jobs.store.minimalOps.rename
	f.service.jobs.store.minimalOps.rename = func(a, b string) error { renames.Add(1); return rename(a, b) }
	request := f.cancelRequest(t)
	var responses []<-chan Response
	var dones []<-chan struct{}
	for range 8 {
		response, done := f.cancelAsync(t, context.Background(), f.base.principal, request)
		responses, dones = append(responses, response), append(dones, done)
	}
	waitMinimalLaunchCancelRevocation(t, f)
	assertMinimalLaunchCancelPending(t, f)
	pending := f.recordBytes(t)
	for _, done := range dones {
		select {
		case <-done:
			t.Fatal("cancel did not join outstanding dispatch")
		default:
		}
	}
	f.unblock()
	f.waitStart(t)
	for _, response := range responses {
		if got := waitMinimalLaunchCancelResponse(t, response); !reflect.DeepEqual(got, l8ServiceFailureResponse(request)) {
			t.Fatal("cancel manufactured completion")
		}
	}
	if got := f.service.HandleAuthenticatedRequest(context.Background(), f.base.principal, request); !reflect.DeepEqual(got, l8ServiceFailureResponse(request)) {
		t.Fatal("repeat cancel manufactured completion")
	}
	if renames.Load() != 1 || !bytes.Equal(pending, f.recordBytes(t)) {
		t.Fatal("duplicate cancellation republished or changed pending identity")
	}
	f.assertRetained(t, true)
	f.assertNoCleanup(t)
}

func TestMinimalLaunchCancelWaiterCancellationDoesNotAbandonPartialOwner(t *testing.T) {
	f := newMinimalLaunchCancelFixture(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := f.cancelRequest(t)
	response, _ := f.cancelAsync(t, ctx, f.base.principal, request)
	waitMinimalLaunchCancelRevocation(t, f)
	assertMinimalLaunchCancelPending(t, f)
	pending := f.recordBytes(t)
	cancel()
	want, _ := contextErrorResponse(ctx, request)
	if got := waitMinimalLaunchCancelResponse(t, response); !reflect.DeepEqual(got, want) {
		t.Fatal("canceled waiter did not return caller-context failure")
	}
	select {
	case <-f.startDone:
		t.Fatal("waiter cancellation pretended provider had returned")
	default:
	}
	f.base.authorizer.Close() // Withdraw launch scope; retained cleanup still joins.
	second, _ := f.cancelAsync(t, context.Background(), f.base.principal, request)
	f.unblock()
	f.waitStart(t)
	if got := waitMinimalLaunchCancelResponse(t, second); !reflect.DeepEqual(got, l8ServiceFailureResponse(request)) {
		t.Fatal("second waiter manufactured cleanup")
	}
	if !bytes.Equal(pending, f.recordBytes(t)) {
		t.Fatal("waiter cancellation changed durable pending identity")
	}
	f.assertRetained(t, true)
	f.assertNoCleanup(t)
}

func TestMinimalLaunchCancelRetainsCompletedAndUncertainStartResults(t *testing.T) {
	for _, mode := range []string{"owner", "nil", "typed nil", "partial error", "wrong identity", "no claim", "panic"} {
		t.Run(mode, func(t *testing.T) {
			base, service, provider := minimalLaunchMatrixFixture(t)
			provider.mode = mode
			_ = service.HandleAuthenticatedRequest(context.Background(), base.principal, base.request)
			var jobID string
			var entry *minimalLaunchEntry
			for id, value := range service.jobs.minimalLive {
				jobID, entry = id, value
			}
			owner := entry.owner
			request := Request{Operation: OperationJobCancelV2, DriverID: RuntimeDriverMicroVM, JobCancelV2: &JobCancelRequestV2{ContractVersion: JobContractVersionV2, JobID: jobID}}
			if request.Validate() != nil {
				t.Fatal("invalid cancel fixture")
			}
			if got := service.HandleAuthenticatedRequest(context.Background(), base.principal, request); !reflect.DeepEqual(got, l8ServiceFailureResponse(request)) {
				t.Fatal("completed Start was mistaken for completed cleanup")
			}
			state := service.jobs.states[jobID]
			if entry.owner != owner || entry.reservation.Context().Err() == nil || state.MinimalLaunch.Phase != "cleanup_pending" || state.MinimalLaunch.Revision != 3 || !state.JobV2.CancelRequested || state.JobV2.FinishedAt != nil || state.JobV2.ExitCode != nil || len(service.jobs.minimalLive) != 1 || provider.starts != 1 {
				t.Fatal("cancel lost partial owner/occupancy or fabricated completion from uncertain Start")
			}
		})
	}
}

func TestMinimalLaunchCancelRejectsMalformedAndForeignRetainedIdentity(t *testing.T) {
	for _, name := range []string{"missing payload", "wrong contract", "wrong driver", "invalid ID", "missing job", "stored principal", "stored worker", "stored daemon", "stored job ID", "job generation", "launch grant", "runtime generation", "request key", "missing entry", "copied reservation", "copied selection", "missing latch"} {
		t.Run(name, func(t *testing.T) {
			f := newMinimalLaunchCancelFixture(t, false)
			request := f.cancelRequest(t)
			jobID := f.entered.identity.WorkerJobID
			before := f.recordBytes(t)
			f.lockManager(t)
			original := cloneStoredJobStateV2(f.service.jobs.states[jobID])
			entry := f.service.jobs.minimalLive[jobID]
			entryCopy := *entry
			state := cloneStoredJobStateV2(original)
			switch name {
			case "missing payload":
				request.JobCancelV2 = nil
			case "wrong contract":
				request.JobCancelV2.ContractVersion = "foreign"
			case "wrong driver":
				request.DriverID = RuntimeDriverRootlessPodman
			case "invalid ID":
				request.JobCancelV2.JobID = "../job"
			case "missing job":
				request.JobCancelV2.JobID = "job-00000000000000000000000000000000"
			case "stored principal":
				state.PrincipalID = "foreign-principal"
			case "stored worker":
				state.JobV2.WorkerID = "foreign-worker"
			case "stored daemon":
				state.DaemonGeneration = "foreign-daemon"
			case "stored job ID":
				state.JobV2.ID = "job-00000000000000000000000000000000"
			case "job generation":
				state.MinimalLaunch.JobGeneration = "foreign-generation"
			case "launch grant":
				state.MinimalLaunch.LaunchGrantID = "foreign-grant"
			case "runtime generation":
				state.MinimalLaunch.RuntimeGeneration = "foreign-runtime"
			case "request key":
				state.RequestKey = "request-v2-0000000000000000000000000000000000000000000000000000000000000000"
			case "missing entry":
				delete(f.service.jobs.minimalLive, jobID)
			case "copied reservation":
				// Provider is blocked: copy the quiescent fixture only to test
				// its self-identity rejection, never operate a copied mutex.
				copied := new(sandboxruntime.MinimalLaunchReservation)
				reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(entry.reservation).Elem())
				entry.reservation = copied
			case "copied selection":
				copied := new(sandboxruntime.MinimalLaunchPreparedSelection)
				reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(entry.selection).Elem())
				entry.selection = copied
			case "missing latch":
				entry.dispatchDone = nil
			}
			f.service.jobs.states[jobID] = state
			f.service.jobs.mu.Unlock()
			// Restore fixture-only corrupted memory before releasing Start, even
			// if an assertion fails; the original provider still owns its entry.
			var restoreOnce sync.Once
			restore := func() {
				restoreOnce.Do(func() {
					f.service.jobs.mu.Lock()
					*entry = entryCopy
					f.service.jobs.minimalLive[jobID] = entry
					f.service.jobs.states[jobID] = original
					f.service.jobs.mu.Unlock()
				})
			}
			t.Cleanup(restore)
			got := f.service.HandleAuthenticatedRequest(context.Background(), f.base.principal, request)
			if got.OK || got.Error == nil || got.JobV2 != nil || f.entered.reservation.Context().Err() != nil || !bytes.Equal(before, f.recordBytes(t)) {
				t.Fatal("invalid request or foreign retained identity changed the original job")
			}
			restore()
			f.unblock()
			f.waitStart(t)
			f.assertNoCleanup(t)
		})
	}
}

func TestMinimalLaunchCancelStoreFaultRevokesWithoutFalseDurability(t *testing.T) {
	for _, fault := range []string{"root replaced", "record replaced bytes", "record symlink", "record mode", "rename before publication", "rename after publication", "first sync", "final sync", "postrename readback bytes"} {
		t.Run(fault, func(t *testing.T) {
			f := newMinimalLaunchCancelFixture(t, true)
			jobID := f.entered.identity.WorkerJobID
			path := filepath.Join(f.base.stateDir, jobID+".json")
			original := f.recordBytes(t)
			ops := f.service.jobs.store.minimalOps
			rename, sync := ops.rename, ops.sync
			var renames, syncs atomic.Int32
			var fired atomic.Bool
			watch, watchBytes := path, original
			switch fault {
			case "root replaced":
				if err := os.Rename(f.base.stateDir, f.base.stateDir+".held"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(f.base.stateDir, 0o700); err != nil {
					t.Fatal(err)
				}
				watchBytes = []byte("unowned successor must remain unchanged\n")
				if err := os.WriteFile(path, watchBytes, 0o600); err != nil {
					t.Fatal(err)
				}
				fired.Store(true)
			case "record replaced bytes":
				watchBytes = bytes.Replace(original, []byte("runtime-generation-minimal"), []byte("runtime-generation-foreign"), 1)
				if bytes.Equal(original, watchBytes) {
					t.Fatal("record mutation did not match")
				}
				if err := os.WriteFile(path, watchBytes, 0o600); err != nil {
					t.Fatal(err)
				}
				fired.Store(true)
			case "record symlink":
				watch = filepath.Join(t.TempDir(), "original")
				if err := os.Rename(path, watch); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(watch, path); err != nil {
					t.Fatal(err)
				}
				fired.Store(true)
			case "record mode":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
				fired.Store(true)
			}
			ops.rename = func(a, b string) error {
				renames.Add(1)
				if fault == "rename before publication" {
					fired.Store(true)
					return errors.New("fixture publication refused")
				}
				if err := rename(a, b); err != nil {
					return err
				}
				if fault == "rename after publication" {
					fired.Store(true)
					return errors.New("fixture uncertain publication")
				}
				if fault == "postrename readback bytes" {
					data, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					changed := bytes.Replace(data, []byte("runtime-generation-minimal"), []byte("runtime-generation-foreign"), 1)
					if bytes.Equal(data, changed) {
						return errors.New("fixture mutation missed")
					}
					fired.Store(true)
					return os.WriteFile(path, changed, 0o600)
				}
				return nil
			}
			ops.sync = func() error {
				n := syncs.Add(1)
				if fault == "first sync" && n == 1 || fault == "final sync" && n == 2 {
					fired.Store(true)
					return errors.New("fixture directory sync failed")
				}
				return sync()
			}
			request := f.cancelRequest(t)
			response, _ := f.cancelAsync(t, context.Background(), f.base.principal, request)
			waitMinimalLaunchCancelRevocation(t, f)
			f.lockManager(t)
			poisoned := f.service.jobs.minimalPoisoned
			state := cloneStoredJobStateV2(f.service.jobs.states[jobID])
			f.service.jobs.mu.Unlock()
			if !fired.Load() || !poisoned || state.MinimalLaunch.Phase != "dispatching" || state.JobV2.CancelRequested {
				t.Fatal("uncertain store transition became a confirmed pending acknowledgement")
			}
			f.unblock()
			f.waitStart(t)
			if got := waitMinimalLaunchCancelResponse(t, response); !reflect.DeepEqual(got, l8ServiceFailureResponse(request)) {
				t.Fatal("store fault manufactured cancellation success")
			}
			writes := renames.Load()
			_ = f.service.HandleAuthenticatedRequest(context.Background(), f.base.principal, request)
			if renames.Load() != writes {
				t.Fatal("uncertain cancellation retried publication")
			}
			if fault == "root replaced" || fault == "record replaced bytes" || fault == "record symlink" || fault == "record mode" || fault == "rename before publication" {
				data, err := os.ReadFile(watch)
				if err != nil || !bytes.Equal(data, watchBytes) {
					t.Fatal("rejection wrote through an untrusted record/root")
				}
			}
			if fault == "root replaced" {
				entries, err := os.ReadDir(f.base.stateDir)
				if err != nil || len(entries) != 1 {
					t.Fatal("cancel created state/lock/temp in successor root")
				}
			}
			f.assertRetained(t, true)
			f.assertNoCleanup(t)
		})
	}
}

func TestMinimalLaunchCancelStoreCASRequiresExactPriorDispatch(t *testing.T) {
	for _, mutation := range []string{"valid once", "revision", "missing flag", "principal", "daemon", "grant", "submission", "terminal", "backward phase"} {
		t.Run(mutation, func(t *testing.T) {
			f := newMinimalLaunchCancelFixture(t, false)
			before := f.recordBytes(t)
			f.lockManager(t)
			next := cloneStoredJobStateV2(f.service.jobs.states[f.entered.identity.WorkerJobID])
			next.MinimalLaunch.Phase, next.MinimalLaunch.Revision = "cleanup_pending", 3
			next.JobV2.CancelRequested = true
			switch mutation {
			case "revision":
				next.MinimalLaunch.Revision = 4
			case "missing flag":
				next.JobV2.CancelRequested = false
			case "principal":
				next.PrincipalID = "foreign-principal"
			case "daemon":
				next.DaemonGeneration = "foreign-daemon"
			case "grant":
				next.MinimalLaunch.LaunchGrantID = "foreign-grant"
			case "submission":
				next.MinimalLaunch.SubmissionID = "foreign-submission"
			case "terminal":
				next.JobV2.State = JobStateCanceled
			case "backward phase":
				next.MinimalLaunch.Phase, next.MinimalLaunch.Revision, next.JobV2.CancelRequested = "reserved", 1, false
			}
			err := f.service.jobs.store.save(next)
			f.service.jobs.mu.Unlock()
			if mutation == "valid once" {
				if err != nil {
					t.Fatalf("exact pending transition rejected: %v", err)
				}
				pending := f.recordBytes(t)
				f.lockManager(t)
				repeat := f.service.jobs.store.save(next)
				f.service.jobs.mu.Unlock()
				if repeat == nil || bytes.Equal(before, pending) || !bytes.Equal(pending, f.recordBytes(t)) {
					t.Fatal("selected CAS accepted a duplicate or rewrote pending state")
				}
			} else if err == nil || !bytes.Equal(before, f.recordBytes(t)) {
				t.Fatal("selected CAS changed an immutable prior dispatch or accepted invalid pending state")
			}
			f.unblock()
			f.waitStart(t)
			f.assertNoCleanup(t)
		})
	}
}

func TestMinimalLaunchCancelPendingValidationRejectsCompletionProjection(t *testing.T) {
	f := newMinimalLaunchCancelFixture(t, false)
	f.lockManager(t)
	base := cloneStoredJobStateV2(f.service.jobs.states[f.entered.identity.WorkerJobID])
	f.service.jobs.mu.Unlock()
	base.MinimalLaunch.Phase, base.MinimalLaunch.Revision, base.JobV2.CancelRequested = "cleanup_pending", 3, true
	if base.Validate() != nil {
		t.Fatal("valid pending fixture rejected")
	}
	for _, field := range []string{"exit code", "started", "heartbeat", "finished", "missing cancel flag"} {
		t.Run(field, func(t *testing.T) {
			state := cloneStoredJobStateV2(base)
			at := state.JobV2.SubmittedAt.Add(time.Second)
			switch field {
			case "exit code":
				code := 0
				state.JobV2.ExitCode = &code
			case "started":
				state.JobV2.StartedAt = &at
			case "heartbeat":
				state.JobV2.HeartbeatAt = &at
			case "finished":
				state.JobV2.FinishedAt = &at
			case "missing cancel flag":
				state.JobV2.CancelRequested = false
			}
			if state.Validate() == nil {
				t.Fatal("private pending validator accepted fabricated completion or omitted cancellation")
			}
		})
	}
}

func TestMinimalLaunchCancelFailedReservationHandoffIsNotTerminal(t *testing.T) {
	f := newMinimalLaunchDispatchFixture(t)
	s := f.service(t)
	s.jobs.store.minimalOps.sync = func() error { return errors.New("fixture first reservation sync failure") }
	_ = s.HandleAuthenticatedRequest(context.Background(), f.principal, f.request)
	var jobID string
	var entry *minimalLaunchEntry
	for id, value := range s.jobs.minimalLive {
		jobID, entry = id, value
	}
	if entry == nil || f.provider.startCalls != 0 {
		t.Fatal("fixture did not stop at uncertain reserved publication")
	}
	select {
	case <-entry.dispatchDone:
	default:
		t.Fatal("local failed reservation handoff has no completed latch")
	}
	request := Request{Operation: OperationJobCancelV2, DriverID: RuntimeDriverMicroVM, JobCancelV2: &JobCancelRequestV2{ContractVersion: JobContractVersionV2, JobID: jobID}}
	if got := s.HandleAuthenticatedRequest(context.Background(), f.principal, request); !reflect.DeepEqual(got, l8ServiceFailureResponse(request)) {
		t.Fatal("failed reservation became terminal no-dispatch proof")
	}
	state := s.jobs.states[jobID]
	if state.MinimalLaunch.Phase != "reserved" || state.MinimalLaunch.Revision != 1 || state.JobV2.CancelRequested || state.JobV2.FinishedAt != nil || entry.owner != nil || entry.reservation.Context().Err() == nil || len(s.jobs.minimalLive) != 1 || f.provider.recoverCalls != 0 {
		t.Fatal("uncertain reserved record was completed, recovered, or released")
	}
}

func TestMinimalLaunchCancelAndServiceCloseJoinBeforeReleasingStore(t *testing.T) {
	f := newMinimalLaunchCancelFixture(t, true)
	response, _ := f.cancelAsync(t, context.Background(), f.base.principal, f.cancelRequest(t))
	waitMinimalLaunchCancelRevocation(t, f)
	assertMinimalLaunchCancelPending(t, f)
	closed := make(chan struct{})
	go func() { defer close(closed); f.service.Close() }()
	t.Cleanup(func() {
		f.unblock()
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
			t.Error("service close was not joined")
		}
	})
	f.lockManager(t)
	retained := f.service.jobs.stateLock != nil
	f.service.jobs.mu.Unlock()
	if !retained {
		t.Fatal("service close released store while provider still owned handoff")
	}
	select {
	case <-closed:
		t.Fatal("service close did not join blocked Start")
	default:
	}
	f.unblock()
	f.waitStart(t)
	_ = waitMinimalLaunchCancelResponse(t, response)
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("service close did not finish after handoff")
	}
	f.lockManager(t)
	retained = f.service.jobs.stateLock != nil
	f.service.jobs.mu.Unlock()
	if retained {
		t.Fatal("service close did not release joined store lock")
	}
	f.assertRetained(t, true)
	f.assertNoCleanup(t)
}

func waitMinimalLaunchCancelRevocation(t *testing.T, f *minimalLaunchCancelFixture) {
	t.Helper()
	select {
	case <-f.entered.reservation.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("original reservation was not revoked")
	}
}

func assertMinimalLaunchCancelPending(t *testing.T, f *minimalLaunchCancelFixture) {
	t.Helper()
	f.lockManager(t)
	defer f.service.jobs.mu.Unlock()
	state := f.service.jobs.states[f.entered.identity.WorkerJobID]
	if state.MinimalLaunch.Phase != "cleanup_pending" || state.MinimalLaunch.Revision != 3 || !state.JobV2.CancelRequested || state.JobV2.State != JobStateQueued || state.JobV2.FinishedAt != nil || state.JobV2.StartedAt != nil || state.JobV2.ExitCode != nil {
		t.Fatal("pending cancellation invented completion")
	}
}

// Keep the original selection/reservation APIs exercised, rather than a copied
// scalar identity standing in for a cleanup capability.
var _ sandboxruntime.MinimalJobRuntimeProvider = (*minimalLaunchCancelProvider)(nil)
