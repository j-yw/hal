package sandboxworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// The first assertion reaches the actual selected cancel route while a claimed
// provider Start is blocked. Later assertions are not baseline evidence until
// that route revokes the original reservation instead of returning unsupported.
func TestMinimalLaunchCancelRevokesAndJoinsClaimedDispatch(t *testing.T) {
	fixture := newMinimalLaunchCancelFixture(t, true)
	var expected storedJobStateV2
	if err := json.Unmarshal(fixture.recordBytes(t), &expected); err != nil || expected.MinimalLaunch == nil {
		t.Fatalf("read original dispatched identity: %v", err)
	}
	expected.MinimalLaunch.Phase, expected.MinimalLaunch.Revision = "cleanup_pending", 3
	expected.JobV2.CancelRequested = true
	request := fixture.cancelRequest(t)
	response, done := fixture.cancelAsync(t, context.Background(), fixture.base.principal, request)
	select {
	case <-fixture.entered.reservation.Context().Done():
	case got := <-response:
		t.Fatalf("selected cancel returned before revoking claimed reservation: OK=%t error=%v reservationErr=%v", got.OK, got.Error, fixture.entered.reservation.Context().Err())
	case <-time.After(3 * time.Second):
		t.Fatal("selected cancel did not revoke claimed reservation; watchdog is not cancellation proof")
	}

	// Acquiring the bookkeeper lock must not wait for the blocked provider. The
	// planned pending publication is under this lock, before the dispatch join.
	fixture.lockManager(t)
	state := cloneStoredJobStateV2(fixture.service.jobs.states[fixture.entered.identity.WorkerJobID])
	entry := fixture.service.jobs.minimalLive[fixture.entered.identity.WorkerJobID]
	fixture.service.jobs.mu.Unlock()
	if state.MinimalLaunch == nil || state.MinimalLaunch.Phase != "cleanup_pending" || state.MinimalLaunch.Revision != 3 || !state.JobV2.CancelRequested {
		t.Fatal("claimed cancellation did not retain one cleanup_pending revision with CancelRequested")
	}
	if !reflect.DeepEqual(state, expected) {
		t.Fatal("cancel altered original principal, generation, intent, submission, or other immutable fields")
	}
	if state.JobV2.State != JobStateQueued || state.JobV2.StartedAt != nil || state.JobV2.FinishedAt != nil || state.JobV2.ExitCode != nil || state.JobV2.Validate() != nil {
		t.Fatal("pending cancellation invented public runtime completion")
	}
	if entry == nil || entry.reservation != fixture.entered.reservation || entry.owner != nil {
		t.Fatal("cancel replaced the original entry or claimed an owner before Start returned")
	}
	var actual storedJobStateV2
	pending := fixture.recordBytes(t)
	if err := json.Unmarshal(pending, &actual); err != nil || !reflect.DeepEqual(actual, state) {
		t.Fatalf("pending cancellation is not the exact durable state: %v", err)
	}
	select {
	case <-done:
		t.Fatal("cancel returned while the provider could still return a partial owner")
	default:
	}
	fixture.unblock()
	fixture.waitStart(t)
	got := waitMinimalLaunchCancelResponse(t, response)
	if !reflect.DeepEqual(got, l8ServiceFailureResponse(request)) {
		t.Fatalf("pending cleanup response = %#v, want sanitized unavailable without terminal success", got)
	}
	fixture.assertRetained(t, true)
	if !bytes.Equal(pending, fixture.recordBytes(t)) {
		t.Fatal("partial-owner return rewrote pending cancellation or released durable occupancy")
	}
	if _, err := fixture.entered.reservation.ClaimLaunch(context.Background()); err == nil {
		t.Fatal("canceled claimed reservation became reusable")
	}
	fixture.assertNoCleanup(t)
}

// This control independently reaches the real durable dispatch and owner-return
// handoff. It does not depend on the failing cancellation assertion above.
func TestMinimalLaunchCancelFixtureValidStartControl(t *testing.T) {
	fixture := newMinimalLaunchCancelFixture(t, false)
	before := fixture.recordBytes(t)
	fixture.unblock()
	got := fixture.waitStart(t)
	if !reflect.DeepEqual(got, l8ServiceFailureResponse(fixture.base.request)) {
		t.Fatal("initial selected handoff unexpectedly published runtime/job success")
	}
	fixture.assertRetained(t, false)
	if !bytes.Equal(before, fixture.recordBytes(t)) {
		t.Fatal("nonterminal owner handoff changed the durable dispatch record")
	}
	fixture.assertNoCleanup(t)
}

func TestMinimalLaunchCancelRejectsForeignPrincipalWithoutInterference(t *testing.T) {
	for _, name := range []string{"different issuer", "different principal same issuer", "canceled caller before entry"} {
		t.Run(name, func(t *testing.T) {
			fixture := newMinimalLaunchCancelFixture(t, false)
			before := fixture.recordBytes(t)
			request := fixture.cancelRequest(t)
			principal := fixture.base.principal
			ctx := context.Background()
			switch name {
			case "different issuer":
				_, principal = l8D6WorkerPrincipal(t)
			case "different principal same issuer":
				var err error
				principal, err = fixture.base.authority.IssueAuthenticatedWorkerPrincipal("principal-other", 1000, 1000)
				if err != nil {
					t.Fatal(err)
				}
			case "canceled caller before entry":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got := fixture.service.HandleAuthenticatedRequest(ctx, principal, request)
			if got.OK || got.JobV2 != nil || got.Error == nil {
				t.Fatal("invalid cancel request published acceptance")
			}
			if name == "different issuer" && !reflect.DeepEqual(got, l8AuthenticatedPrincipalFailureResponse(request)) {
				t.Fatal("cancel bypassed the original exact issuer check")
			}
			if name == "canceled caller before entry" {
				want, _ := contextErrorResponse(ctx, request)
				if !reflect.DeepEqual(got, want) {
					t.Fatal("cancel bypassed the original request-context check")
				}
			}
			// A same-issuer foreign principal is currently rejected as unsupported.
			// This proves non-interference, not the missing selected cancel validator.
			if fixture.entered.reservation.Context().Err() != nil || !bytes.Equal(before, fixture.recordBytes(t)) {
				t.Fatal("invalid cancel changed another live reservation or its durable bytes")
			}
			fixture.unblock()
			fixture.waitStart(t)
			fixture.assertRetained(t, false)
			fixture.assertNoCleanup(t)
		})
	}
}

type minimalLaunchCancelEntry struct {
	reservation *sandboxruntime.MinimalLaunchReservation
	identity    sandboxruntime.MinimalLaunchIdentity
}

type minimalLaunchCancelFixture struct {
	base      *minimalLaunchDispatchFixture
	service   *L8Service
	provider  *minimalLaunchCancelProvider
	entered   minimalLaunchCancelEntry
	start     chan Response
	startDone chan struct{}
}

func newMinimalLaunchCancelFixture(t *testing.T, partial bool) *minimalLaunchCancelFixture {
	t.Helper()
	fixture := &minimalLaunchCancelFixture{base: newMinimalLaunchDispatchFixture(t), start: make(chan Response, 1), startDone: make(chan struct{})}
	fixture.base.authorizer.Close() // Replace only this unused fixture binding.
	fixture.provider = &minimalLaunchCancelProvider{fixture: fixture, entered: make(chan minimalLaunchCancelEntry, 1), release: make(chan struct{}), partial: partial}
	fixture.base.binding = minimalLaunchDispatchBinding(t, fixture.provider)
	var err error
	fixture.base.authorizer, err = sandboxruntime.NewMinimalLaunchAuthorizer(fixture.base.authority, fixture.base.binding, []sandboxruntime.MinimalLaunchScope{{
		PolicyID: "minimal-launch-policy", Revision: 3, PrincipalID: "principal-l8-worker", WorkerID: "worker-l8-neutral", HostID: "host-minimal", NetworkPolicyID: "network-minimal",
		TemplatePolicyID: fixture.base.request.JobStartV2.TemplatePolicyID, WorkspacePolicyID: fixture.base.request.JobStartV2.WorkspacePolicyID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fixture.base.authorizer.Close)
	fixture.service = fixture.base.service(t)
	// This runs before the service cleanup, including when a RED assertion fails.
	t.Cleanup(func() {
		fixture.unblock()
		select {
		case <-fixture.startDone:
		case <-time.After(3 * time.Second):
			t.Error("fixture Start was not joined during teardown")
		}
	})
	go func() {
		defer close(fixture.startDone)
		fixture.start <- fixture.service.HandleAuthenticatedRequest(context.Background(), fixture.base.principal, fixture.base.request)
	}()
	select {
	case fixture.entered = <-fixture.provider.entered:
	case <-fixture.startDone:
		t.Fatal("fixture did not reach claimed provider entry")
	case <-time.After(3 * time.Second):
		t.Fatal("fixture did not reach provider entry before watchdog")
	}
	return fixture
}

func (fixture *minimalLaunchCancelFixture) cancelRequest(t *testing.T) Request {
	t.Helper()
	request := Request{ProtocolVersion: fixture.base.request.ProtocolVersion, RequestID: "cancel-minimal-test", Operation: OperationJobCancelV2, DriverID: RuntimeDriverMicroVM,
		JobCancelV2: &JobCancelRequestV2{ContractVersion: JobContractVersionV2, JobID: fixture.entered.identity.WorkerJobID}}
	if err := request.Validate(); err != nil {
		t.Fatalf("invalid cancel fixture: %v", err)
	}
	return request
}

func (fixture *minimalLaunchCancelFixture) cancelAsync(t *testing.T, ctx context.Context, principal sandboxruntime.AuthenticatedWorkerPrincipal, request Request) (<-chan Response, <-chan struct{}) {
	t.Helper()
	response, done := make(chan Response, 1), make(chan struct{})
	t.Cleanup(func() {
		fixture.unblock()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("fixture cancel request was not joined during teardown")
		}
	})
	go func() {
		defer close(done)
		response <- fixture.service.HandleAuthenticatedRequest(ctx, principal, request)
	}()
	return response, done
}

func (fixture *minimalLaunchCancelFixture) unblock() {
	fixture.provider.releaseOnce.Do(func() { close(fixture.provider.release) })
}

func (fixture *minimalLaunchCancelFixture) waitStart(t *testing.T) Response {
	t.Helper()
	return waitMinimalLaunchCancelResponse(t, fixture.start)
}

func waitMinimalLaunchCancelResponse(t *testing.T, response <-chan Response) Response {
	t.Helper()
	select {
	case got := <-response:
		return got
	case <-time.After(3 * time.Second):
		t.Fatal("fixture request did not return after release")
		return Response{}
	}
}

func (fixture *minimalLaunchCancelFixture) recordBytes(t *testing.T) []byte {
	t.Helper()
	files := minimalLaunchRecordFiles(t, fixture.base.stateDir)
	if len(files) != 1 {
		t.Fatalf("retained record count = %d, want 1", len(files))
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (fixture *minimalLaunchCancelFixture) lockManager(t *testing.T) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !fixture.service.jobs.mu.TryLock() {
		select {
		case <-deadline.C:
			t.Fatal("manager lock held across blocked provider/cancel join")
		case <-tick.C:
		}
	}
}

func (fixture *minimalLaunchCancelFixture) assertRetained(t *testing.T, canceled bool) {
	t.Helper()
	fixture.lockManager(t)
	defer fixture.service.jobs.mu.Unlock()
	entry := fixture.service.jobs.minimalLive[fixture.entered.identity.WorkerJobID]
	state := fixture.service.jobs.states[fixture.entered.identity.WorkerJobID]
	if entry == nil || entry.reservation != fixture.entered.reservation || entry.owner == nil || entry.selection == nil || entry.reservation.Identity() != fixture.entered.identity || state.MinimalLaunch == nil || len(fixture.service.jobs.minimalLive) != 1 || len(fixture.service.jobs.states) != 1 {
		t.Fatal("dispatch return lost original owner, identity, selection, or occupied runtime record")
	}
	if (entry.reservation.Context().Err() != nil) != canceled {
		t.Fatalf("retained reservation cancellation = %v, want canceled=%t", entry.reservation.Context().Err(), canceled)
	}
}

func (fixture *minimalLaunchCancelFixture) assertNoCleanup(t *testing.T) {
	t.Helper()
	if fixture.provider.starts.Load() != 1 || fixture.provider.recovers.Load() != 0 || fixture.provider.finalizes.Load() != 0 || fixture.base.provider.selection.closed {
		t.Fatal("cancel duplicated dispatch, invoked cleanup/recovery, or released selected ownership")
	}
}

type minimalLaunchCancelProvider struct {
	fixture                     *minimalLaunchCancelFixture
	entered                     chan minimalLaunchCancelEntry
	release                     chan struct{}
	releaseOnce                 sync.Once
	partial                     bool
	starts, recovers, finalizes atomic.Int32
}

func (provider *minimalLaunchCancelProvider) ResolveMinimalSelection(ctx context.Context, hints sandboxruntime.MinimalLaunchSelectionHints) (sandboxruntime.MinimalLaunchSelection, error) {
	return provider.fixture.base.provider.ResolveMinimalSelection(ctx, hints)
}

func (provider *minimalLaunchCancelProvider) StartMinimalJob(ctx context.Context, reservation *sandboxruntime.MinimalLaunchReservation, selection sandboxruntime.MinimalLaunchSelection) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	provider.starts.Add(1)
	base := provider.fixture.base.provider
	if selection != base.selection || base.selection == nil || base.selection.closed || !provider.fixture.service.jobs.mu.TryLock() {
		base.t.Fatal("provider entry did not retain original selection outside manager lock")
	}
	provider.fixture.service.jobs.mu.Unlock()
	identity, err := reservation.ClaimLaunch(ctx)
	if err != nil {
		base.t.Fatalf("actual dispatched reservation could not be claimed: %v", err)
	}
	base.checkDurableDispatch(identity)
	provider.entered <- minimalLaunchCancelEntry{reservation: reservation, identity: identity}
	<-provider.release // Deliberately joined handoff, not a fake cancellation callback.
	owner := &minimalLaunchCancelOwner{identity: identity, finalizes: &provider.finalizes}
	if provider.partial {
		return owner, errors.New("test-only partial owner after dispatch")
	}
	return owner, nil
}

func (provider *minimalLaunchCancelProvider) RecoverMinimalJob(context.Context, sandboxruntime.MinimalLaunchIdentity) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	provider.recovers.Add(1)
	return nil, sandboxruntime.ErrMinimalLaunchUnavailable
}

type minimalLaunchCancelOwner struct {
	identity  sandboxruntime.MinimalLaunchIdentity
	finalizes *atomic.Int32
}

func (owner *minimalLaunchCancelOwner) Identity() sandboxruntime.MinimalLaunchIdentity {
	return owner.identity
}

func (owner *minimalLaunchCancelOwner) Finalize(context.Context) (sandboxruntime.MinimalLaunchCleanupReceipt, error) {
	owner.finalizes.Add(1)
	return sandboxruntime.MinimalLaunchCleanupReceipt{}, sandboxruntime.ErrMinimalLaunchUnavailable
}
