package sandboxworker

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// Successful injected Start returns before P through the actual durable
// service. This is ownership bookkeeping, never a ready/runtime success claim.
func TestMinimalLaunchServiceOwnedContextAfterPreparation(t *testing.T) {
	for _, action := range []string{"explicit cancel", "service close", "authority close"} {
		t.Run(action, func(t *testing.T) {
			f := newMinimalLaunchOwnedContextFixture(t, 750*time.Millisecond)
			f.start(t, context.Background())
			before := f.recordBytes(t)
			owned := f.provider.reservation.OwnedContext()
			waitMinimalLaunchOwnedContext(t, f.provider.ctx)
			if owned == nil || owned.Err() != nil {
				t.Fatalf("actual accepted owner expired at preparation deadline before %s", action)
			}
			if !bytes.Equal(before, f.recordBytes(t)) {
				t.Fatal("preparation expiry fabricated a durable transition")
			}
			switch action {
			case "explicit cancel":
				response := f.service.HandleAuthenticatedRequest(context.Background(), f.base.principal, f.cancelRequest(t))
				if response.OK {
					t.Fatal("pending cancel manufactured completed cleanup")
				}
			case "service close":
				f.service.Close()
			case "authority close":
				f.base.authorizer.Close()
			}
			waitMinimalLaunchOwnedContext(t, owned)
			if owned.Err() != context.Canceled || owned != f.provider.reservation.OwnedContext() {
				t.Fatal("post-P ownership loss was ignored or replaced")
			}
			f.assertRetained(t, action == "explicit cancel")
			if action != "explicit cancel" && !bytes.Equal(before, f.recordBytes(t)) {
				t.Fatal("nonterminal close rewrote the accepted record")
			}
		})
	}
}

// These controls run independently of the deliberately failing post-P cases.
func TestMinimalLaunchServiceOwnedContextControls(t *testing.T) {
	t.Run("exact provider context and stored deadline", func(t *testing.T) {
		f := newMinimalLaunchOwnedContextFixture(t, time.Minute)
		f.start(t, context.Background())
		f.assertRetained(t, false)
	})
	t.Run("initiating client loss after acceptance", func(t *testing.T) {
		f := newMinimalLaunchOwnedContextFixture(t, time.Minute)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sync, calls := f.service.jobs.store.minimalOps.sync, 0
		f.service.jobs.store.minimalOps.sync = func() error {
			calls++
			if calls == 2 {
				cancel() // Existing actual first reservation readback boundary.
			}
			return sync()
		}
		f.start(t, ctx)
		if ctx.Err() == nil || f.provider.ctx.Err() != nil || f.provider.reservation.OwnedContext().Err() != nil {
			t.Fatal("initiating waiter acquired cancellation of accepted ownership")
		}
		f.assertRetained(t, false)
	})
	for _, mode := range []string{"wrong issuer", "wrong principal", "canceled before admission"} {
		t.Run(mode, func(t *testing.T) {
			f := newMinimalLaunchOwnedContextFixture(t, time.Minute)
			f.start(t, context.Background())
			before := f.recordBytes(t)
			principal, ctx := f.base.principal, context.Background()
			var err error
			if mode == "wrong issuer" {
				issuer, createErr := sandboxruntime.NewAuthenticatedWorkerPrincipalAuthority("foreign-owned-authority", "foreign-owned-generation")
				if createErr != nil {
					t.Fatal(createErr)
				}
				principal, err = issuer.IssueAuthenticatedWorkerPrincipal("principal-l8-worker", 1000, 1000)
			} else if mode == "wrong principal" {
				principal, err = f.base.authority.IssueAuthenticatedWorkerPrincipal("foreign-owned-principal", 1000, 1000)
			} else {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			response := f.service.HandleAuthenticatedRequest(ctx, principal, f.cancelRequest(t))
			if response.OK || f.provider.ctx.Err() != nil || f.provider.reservation.OwnedContext().Err() != nil || !bytes.Equal(before, f.recordBytes(t)) {
				t.Fatal("unadmitted cancel changed original ownership or durable bytes")
			}
			f.assertRetained(t, false)
		})
	}
	t.Run("cancel waiter cannot undo owned revoke", func(t *testing.T) {
		f := newMinimalLaunchCancelFixture(t, true)
		owned := f.entered.reservation.OwnedContext()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		response, done := f.cancelAsync(t, ctx, f.base.principal, f.cancelRequest(t))
		waitMinimalLaunchOwnedContext(t, owned)
		cancel()
		if got := waitMinimalLaunchCancelResponse(t, response); got.OK {
			t.Fatal("canceled waiter manufactured terminal success")
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("cancel waiter did not join")
		}
		if owned.Err() != context.Canceled {
			t.Fatal("waiter canceled or replaced the wrong lifetime")
		}
		f.unblock()
		_ = f.waitStart(t)
		f.assertRetained(t, true)
		f.assertNoCleanup(t)
		assertMinimalLaunchCancelPending(t, f)
	})
}

type minimalLaunchOwnedContextFixture struct {
	base     *minimalLaunchDispatchFixture
	service  *L8Service
	provider *minimalLaunchOwnedContextProvider
}

type minimalLaunchOwnedContextProvider struct {
	base        *minimalLaunchDispatchProvider
	ctx         context.Context
	reservation *sandboxruntime.MinimalLaunchReservation
	starts      int
}

func (p *minimalLaunchOwnedContextProvider) ResolveMinimalSelection(ctx context.Context, hints sandboxruntime.MinimalLaunchSelectionHints) (sandboxruntime.MinimalLaunchSelection, error) {
	return p.base.ResolveMinimalSelection(ctx, hints)
}

func (p *minimalLaunchOwnedContextProvider) StartMinimalJob(ctx context.Context, r *sandboxruntime.MinimalLaunchReservation, selected sandboxruntime.MinimalLaunchSelection) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	p.ctx, p.reservation, p.starts = ctx, r, p.starts+1
	if selected != p.base.selection || ctx != r.Context() {
		return nil, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	id, err := r.ClaimLaunch(ctx)
	if err != nil {
		return nil, err
	}
	p.base.checkDurableDispatch(id)
	return &minimalLaunchMatrixOwner{identity: id}, nil
}

func (p *minimalLaunchOwnedContextProvider) RecoverMinimalJob(context.Context, sandboxruntime.MinimalLaunchIdentity) (sandboxruntime.MinimalJobRuntimeOwner, error) {
	p.base.recoverCalls++
	return nil, sandboxruntime.ErrMinimalLaunchUnavailable
}

func newMinimalLaunchOwnedContextFixture(t *testing.T, budget time.Duration) *minimalLaunchOwnedContextFixture {
	t.Helper()
	f := &minimalLaunchOwnedContextFixture{base: newMinimalLaunchDispatchFixture(t)}
	f.base.authorizer.Close()
	f.provider = &minimalLaunchOwnedContextProvider{base: f.base.provider}
	f.base.binding = minimalLaunchDispatchBinding(t, f.provider)
	var err error
	f.base.authorizer, err = sandboxruntime.NewMinimalLaunchAuthorizer(f.base.authority, f.base.binding, []sandboxruntime.MinimalLaunchScope{{PolicyID: "minimal-launch-policy", Revision: 3, PrincipalID: "principal-l8-worker", WorkerID: "worker-l8-neutral", HostID: "host-minimal", NetworkPolicyID: "network-minimal", TemplatePolicyID: f.base.request.JobStartV2.TemplatePolicyID, WorkspacePolicyID: f.base.request.JobStartV2.WorkspacePolicyID}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.base.authorizer.Close)
	options := f.base.options()
	options.MinimalLaunch.PreparationTimeout = budget
	f.service, err = NewL8DurableService(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.service.Close)
	return f
}

func (f *minimalLaunchOwnedContextFixture) start(t *testing.T, ctx context.Context) {
	t.Helper()
	response := f.service.HandleAuthenticatedRequest(ctx, f.base.principal, f.base.request)
	if response.OK || f.provider.starts != 1 || f.provider.reservation == nil || f.service.jobs.minimalPoisoned {
		t.Fatalf("fixture did not reach exactly one successful actual provider handoff: %+v", response.Error)
	}
	entry := f.service.jobs.minimalLive[f.provider.reservation.Identity().WorkerJobID]
	if entry == nil || entry.reservation != f.provider.reservation || entry.owner == nil || entry.reservation.OwnedContext() == nil {
		t.Fatal("exact partial owner/lifetime was not retained")
	}
	select {
	case <-entry.dispatchDone:
	default:
		t.Fatal("successful provider handoff was not joined")
	}
	state := f.service.jobs.states[f.provider.reservation.Identity().WorkerJobID]
	deadline, ok := f.provider.ctx.Deadline()
	if !ok || !deadline.Equal(state.MinimalLaunch.PreparationDeadline) || f.provider.ctx != f.provider.reservation.Context() {
		t.Fatal("actual provider context changed the persisted absolute preparation budget")
	}
}

func (f *minimalLaunchOwnedContextFixture) recordBytes(t *testing.T) []byte {
	t.Helper()
	files := minimalLaunchRecordFiles(t, f.base.stateDir)
	if len(files) != 1 {
		t.Fatal("original occupied job record missing or duplicated")
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (f *minimalLaunchOwnedContextFixture) cancelRequest(t *testing.T) Request {
	t.Helper()
	request := Request{ProtocolVersion: f.base.request.ProtocolVersion, RequestID: "owned-lifetime-cancel", Operation: OperationJobCancelV2, DriverID: RuntimeDriverMicroVM,
		JobCancelV2: &JobCancelRequestV2{ContractVersion: JobContractVersionV2, JobID: f.provider.reservation.Identity().WorkerJobID}}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	return request
}

func (f *minimalLaunchOwnedContextFixture) assertRetained(t *testing.T, canceled bool) {
	t.Helper()
	id := f.provider.reservation.Identity()
	entry, state := f.service.jobs.minimalLive[id.WorkerJobID], f.service.jobs.states[id.WorkerJobID]
	if entry == nil || entry.reservation != f.provider.reservation || entry.owner == nil || entry.reservation.Identity() != id || len(f.service.jobs.minimalLive) != 1 || f.provider.starts != 1 || f.base.provider.recoverCalls != 0 {
		t.Fatal("owned cancellation replaced or released original partial owner")
	}
	phase, revision := "dispatching", uint64(2)
	if canceled {
		phase, revision = "cleanup_pending", 3
	}
	if state.Validate() != nil || state.MinimalLaunch.Phase != phase || state.MinimalLaunch.Revision != revision || state.JobV2.CancelRequested != canceled || state.JobV2.State != JobStateQueued || state.JobV2.StartedAt != nil || state.JobV2.FinishedAt != nil || state.JobV2.ExitCode != nil || f.base.provider.selection.closed {
		t.Fatal("lifetime transition invented completion or released selection")
	}
}

func waitMinimalLaunchOwnedContext(t *testing.T, ctx context.Context) {
	t.Helper()
	if ctx == nil {
		t.Fatal("missing original owned context")
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("context did not end within fixed test bound; watchdog is not cancellation proof")
	}
}
