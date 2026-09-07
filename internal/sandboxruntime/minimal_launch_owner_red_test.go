package sandboxruntime

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These fixtures exercise the existing neutral admission chain. They neither
// launch resources nor turn a provider's receipt fields into cleanup proof.
func TestMinimalLaunchOwnerBindingExistingStartControls(t *testing.T) {
	for _, outcome := range []string{"success", "partial error", "wrong identity", "identity panic", "foreign binding", "copied binding"} {
		t.Run(outcome, func(t *testing.T) {
			f := newMinimalLaunchOwnerFixture(t)
			binding := f.binding
			switch outcome {
			case "partial error":
				f.provider.startErr = errors.New("sensitive start error")
			case "wrong identity":
				f.owner.identity.WorkerJobID = "foreign-job"
			case "identity panic":
				f.owner.inspect = func() MinimalLaunchIdentity { panic("sensitive identity panic") }
			case "foreign binding":
				binding, _ = NewMinimalLaunchProviderBinding(f.provider)
			case "copied binding":
				copied := *binding
				binding = &copied
			}
			got, err := binding.Start(f.reservation, f.selection, func() error { return nil })
			if outcome == "foreign binding" || outcome == "copied binding" {
				if got != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) || f.provider.starts.Load() != 0 {
					t.Fatal("foreign/copy binding entered provider")
				}
				return
			}
			if got == nil || got.owner != f.owner || got.binding != f.binding || got.identity != f.identity || f.provider.starts.Load() != 1 {
				t.Fatal("existing Start lost the original owner/identity")
			}
			if outcome == "success" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrMinimalLaunchUnavailable) || strings.Contains(err.Error(), "sensitive") {
				t.Fatal("partial Start was not a sanitized failure")
			}
			if f.owner.finalizes.Load() != 0 || f.provider.recovers.Load() != 0 {
				t.Fatal("existing Start invoked cleanup")
			}
		})
	}
}

func TestMinimalLaunchOwnerFinalizeUsesOriginalRevokedOwner(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete start", true: "partial start"}[partial], func(t *testing.T) {
			f := newMinimalLaunchOwnerFixture(t)
			if partial {
				f.provider.startErr = errors.New("sensitive partial start")
			}
			owner := f.start(t, partial)
			f.reservation.Revoke()
			f.selection.authorizer.Close()
			if err := f.selection.Close(); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				receipt, err := owner.Finalize(context.Background())
				if err != nil || receipt != f.receipt() {
					t.Fatalf("retained owner did not finalize after preparation revocation: receipt=%t error=%v callbacks=%d", receipt == f.receipt(), err, f.owner.finalizes.Load())
				}
			}
			if f.owner.finalizes.Load() != 1 || f.provider.starts.Load() != 1 || f.provider.recovers.Load() != 0 || f.provider.closes.Load() != 1 {
				t.Fatal("finalization repeated cleanup, replaced the owner, or closed selection again")
			}
		})
	}
}

func TestMinimalLaunchOwnerFinalizeRejectsReachedInvalidResults(t *testing.T) {
	cases := []struct {
		name string
		call func(context.Context, *minimalLaunchOwnerFixture) (MinimalLaunchCleanupReceipt, error)
	}{
		{"error with full receipt", func(_ context.Context, f *minimalLaunchOwnerFixture) (MinimalLaunchCleanupReceipt, error) {
			return f.receipt(), errors.New("sensitive finalization error")
		}},
		{"panic", func(context.Context, *minimalLaunchOwnerFixture) (MinimalLaunchCleanupReceipt, error) {
			panic("sensitive finalization panic")
		}},
		{"missing receipt", func(context.Context, *minimalLaunchOwnerFixture) (MinimalLaunchCleanupReceipt, error) {
			return MinimalLaunchCleanupReceipt{}, nil
		}},
		{"zero revision", func(_ context.Context, f *minimalLaunchOwnerFixture) (MinimalLaunchCleanupReceipt, error) {
			r := f.receipt()
			r.FinalizedRevision = 0
			return r, nil
		}},
		{"malformed commit token", func(_ context.Context, f *minimalLaunchOwnerFixture) (MinimalLaunchCleanupReceipt, error) {
			r := f.receipt()
			r.OwnerCommitID = strings.Repeat("!", 43)
			return r, nil
		}},
		{"noncanonical commit token", func(_ context.Context, f *minimalLaunchOwnerFixture) (MinimalLaunchCleanupReceipt, error) {
			r := f.receipt()
			r.OwnerCommitID = strings.Repeat("A", 42) + "B"
			return r, nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMinimalLaunchOwnerFixture(t)
			owner := f.start(t, false)
			f.owner.finalize = func(ctx context.Context) (MinimalLaunchCleanupReceipt, error) { return tc.call(ctx, f) }
			got, err := owner.Finalize(context.Background())
			assertMinimalOwnerUnavailable(t, got, err)
			if f.owner.finalizes.Load() != 1 {
				t.Fatalf("negative never reached original Finalize callback: got %d calls", f.owner.finalizes.Load())
			}
			if owner.owner != f.owner || owner.identity != f.identity || f.provider.recovers.Load() != 0 {
				t.Fatal("failure lost or replaced partial ownership")
			}
		})
	}
	identityType := reflect.TypeOf(MinimalLaunchIdentity{})
	for index := range identityType.NumField() {
		t.Run("receipt identity "+identityType.Field(index).Name, func(t *testing.T) {
			f := newMinimalLaunchOwnerFixture(t)
			owner := f.start(t, false)
			f.owner.finalize = func(context.Context) (MinimalLaunchCleanupReceipt, error) {
				r := f.receipt()
				field := reflect.ValueOf(&r.Identity).Elem().Field(index)
				if identityType.Field(index).Name == "RequestKey" {
					field.SetString("request-v2-" + strings.Repeat("b", 64))
				} else if field.Kind() == reflect.String {
					field.SetString(field.String() + "x")
				} else {
					field.SetUint(field.Uint() + 1)
				}
				return r, nil
			}
			got, err := owner.Finalize(context.Background())
			assertMinimalOwnerUnavailable(t, got, err)
			if f.owner.finalizes.Load() != 1 {
				t.Fatal("identity negative never reached original Finalize callback")
			}
		})
	}
}

func TestMinimalLaunchOwnerFinalizeCachedResultRechecksIdentityAndCaller(t *testing.T) {
	for _, failure := range []string{"identity mismatch", "identity panic"} {
		t.Run(failure, func(t *testing.T) {
			f := newMinimalLaunchOwnerFixture(t)
			owner := f.start(t, false)
			if got, err := owner.Finalize(context.Background()); err != nil || got != f.receipt() {
				t.Fatalf("initial finalization unavailable: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			before := f.owner.inspections.Load()
			got, err := owner.Finalize(ctx)
			assertMinimalOwnerUnavailable(t, got, err)
			if f.owner.inspections.Load() != before {
				t.Fatal("already-canceled cached request invoked owner")
			}
			f.owner.inspect = func() MinimalLaunchIdentity {
				if failure == "identity panic" {
					panic("sensitive cached identity panic")
				}
				wrong := f.identity
				wrong.JobGeneration = "foreign-generation"
				return wrong
			}
			got, err = owner.Finalize(context.Background())
			assertMinimalOwnerUnavailable(t, got, err)
			f.owner.inspect = nil // Repair must not erase an observed contradiction.
			got, err = owner.Finalize(context.Background())
			assertMinimalOwnerUnavailable(t, got, err)
			if f.owner.finalizes.Load() != 1 || owner.owner != f.owner {
				t.Fatal("cached identity failure repeated cleanup or replaced owner")
			}
		})
	}
}

func TestMinimalLaunchOwnerFinalizePreservesStartIdentityQuarantine(t *testing.T) {
	control := newMinimalLaunchOwnerFixture(t)
	if got, err := control.start(t, false).Finalize(context.Background()); err != nil || got != control.receipt() {
		t.Fatalf("valid callback control unavailable before quarantine assertions: %v", err)
	}
	for _, failure := range []string{"mismatch", "panic"} {
		t.Run(failure, func(t *testing.T) {
			f := newMinimalLaunchOwnerFixture(t)
			f.owner.inspect = func() MinimalLaunchIdentity {
				if failure == "panic" {
					panic("sensitive start identity panic")
				}
				wrong := f.identity
				wrong.RuntimeGeneration = "foreign-generation"
				return wrong
			}
			owner := f.start(t, true)
			f.owner.inspect = nil
			for range 2 {
				got, err := owner.Finalize(context.Background())
				assertMinimalOwnerUnavailable(t, got, err)
			}
			if f.owner.finalizes.Load() != 0 || owner.owner != f.owner {
				t.Fatal("repair erased Start identity quarantine")
			}
		})
	}
}

func TestMinimalLaunchOwnerFinalizeJoinsAndCanceledWaiterDoesNotOwnAttempt(t *testing.T) {
	f := newMinimalLaunchOwnerFixture(t)
	owner := f.start(t, false)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var calls sync.WaitGroup
	t.Cleanup(func() { once.Do(func() { close(release) }); calls.Wait() })
	f.owner.finalize = func(context.Context) (MinimalLaunchCleanupReceipt, error) {
		close(entered)
		<-release
		return f.receipt(), nil
	}
	type result struct {
		receipt MinimalLaunchCleanupReceipt
		err     error
	}
	first := make(chan result, 1)
	calls.Add(1)
	go func() { defer calls.Done(); r, err := owner.Finalize(context.Background()); first <- result{r, err} }()
	select {
	case <-entered:
	case got := <-first:
		t.Fatalf("original Finalize returned without entering callback: %v", got.err)
	case <-time.After(time.Second):
		t.Fatal("original Finalize never entered callback")
	}
	waitBase, cancel := context.WithCancel(context.Background())
	defer cancel()
	waitCtx := &minimalOwnerWaitContext{Context: waitBase, entered: make(chan struct{})}
	waiter := make(chan result, 1)
	calls.Add(1)
	go func() { defer calls.Done(); r, err := owner.Finalize(waitCtx); waiter <- result{r, err} }()
	select {
	case <-waitCtx.entered:
	case got := <-waiter:
		t.Fatalf("waiter returned without joining pending attempt: %v", got.err)
	case <-time.After(time.Second):
		t.Fatal("waiter could not observe cancellation while callback was pending")
	}
	cancel()
	select {
	case got := <-waiter:
		assertMinimalOwnerUnavailable(t, got.receipt, got.err)
	case <-time.After(time.Second):
		t.Fatal("canceled waiter remained blocked behind owned callback")
	}
	if f.owner.finalizes.Load() != 1 {
		t.Fatal("joining waiter reentered callback")
	}
	once.Do(func() { close(release) })
	select {
	case got := <-first:
		if got.err != nil || got.receipt != f.receipt() {
			t.Fatalf("waiter cancellation changed owned result: %v", got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("owned callback did not join")
	}
}

func TestMinimalLaunchOwnerFinalizeRejectsLateSuccessAndRetriesSameOwner(t *testing.T) {
	f := newMinimalLaunchOwnerFixture(t)
	owner := f.start(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.owner.finalize = func(context.Context) (MinimalLaunchCleanupReceipt, error) { cancel(); return f.receipt(), nil }
	got, err := owner.Finalize(ctx)
	assertMinimalOwnerUnavailable(t, got, err)
	if f.owner.finalizes.Load() != 1 {
		t.Fatal("late cancellation negative never reached callback")
	}
	f.owner.finalize = func(context.Context) (MinimalLaunchCleanupReceipt, error) { return f.receipt(), nil }
	got, err = owner.Finalize(context.Background())
	if err != nil || got != f.receipt() || f.owner.finalizes.Load() != 2 || owner.owner != f.owner || f.provider.recovers.Load() != 0 {
		t.Fatal("explicit retry did not use the same retained owner")
	}
}

type minimalLaunchOwnerFixture struct {
	binding     *MinimalLaunchProviderBinding
	selection   *MinimalLaunchPreparedSelection
	reservation *MinimalLaunchReservation
	identity    MinimalLaunchIdentity
	provider    *minimalLaunchOwnerProvider
	owner       *minimalLaunchOwnerRuntime
}

// Done observation makes the waiter exercise the pending-attempt path before
// the test cancels it; canceling before invocation would not test a joined wait.
type minimalOwnerWaitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (ctx *minimalOwnerWaitContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.entered) })
	return ctx.Context.Done()
}

type minimalLaunchOwnerProvider struct {
	selection                MinimalLaunchSelectionIdentity
	owner                    *minimalLaunchOwnerRuntime
	startErr                 error
	recover                  func(context.Context, MinimalLaunchIdentity) (MinimalJobRuntimeOwner, error)
	starts, recovers, closes atomic.Int32
}

func (p *minimalLaunchOwnerProvider) ResolveMinimalSelection(context.Context, MinimalLaunchSelectionHints) (MinimalLaunchSelection, error) {
	return p, nil
}
func (p *minimalLaunchOwnerProvider) Current(context.Context) (MinimalLaunchSelectionIdentity, error) {
	return p.selection, nil
}
func (p *minimalLaunchOwnerProvider) Close() error { p.closes.Add(1); return nil }
func (p *minimalLaunchOwnerProvider) StartMinimalJob(ctx context.Context, r *MinimalLaunchReservation, s MinimalLaunchSelection) (MinimalJobRuntimeOwner, error) {
	p.starts.Add(1)
	if s != p {
		return nil, ErrMinimalLaunchUnavailable
	}
	identity, err := r.ClaimLaunch(ctx)
	if err != nil || identity != r.Identity() {
		return nil, ErrMinimalLaunchUnavailable
	}
	return p.owner, p.startErr
}
func (p *minimalLaunchOwnerProvider) RecoverMinimalJob(ctx context.Context, id MinimalLaunchIdentity) (MinimalJobRuntimeOwner, error) {
	p.recovers.Add(1)
	return p.recover(ctx, id)
}

type minimalLaunchOwnerRuntime struct {
	identity               MinimalLaunchIdentity
	inspect                func() MinimalLaunchIdentity
	finalize               func(context.Context) (MinimalLaunchCleanupReceipt, error)
	inspections, finalizes atomic.Int32
}

func (o *minimalLaunchOwnerRuntime) Identity() MinimalLaunchIdentity {
	o.inspections.Add(1)
	if o.inspect != nil {
		return o.inspect()
	}
	return o.identity
}
func (o *minimalLaunchOwnerRuntime) Finalize(ctx context.Context) (MinimalLaunchCleanupReceipt, error) {
	o.finalizes.Add(1)
	return o.finalize(ctx)
}

func newMinimalLaunchOwnerFixture(t *testing.T) *minimalLaunchOwnerFixture {
	t.Helper()
	f := &minimalLaunchOwnerFixture{}
	authority, err := NewAuthenticatedWorkerPrincipalAuthority("owner-authority", "owner-authority-generation")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := authority.IssueAuthenticatedWorkerPrincipal("owner-principal", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	f.provider = &minimalLaunchOwnerProvider{selection: MinimalLaunchSelectionIdentity{WorkerID: "owner-worker", HostID: "owner-host", RuntimeID: "owner-runtime", RuntimeGeneration: "owner-runtime-generation", PlanID: "owner-plan", TemplatePolicyID: "owner-template", WorkspacePolicyID: "owner-workspace", NetworkPolicyID: "owner-network"}}
	f.binding, err = NewMinimalLaunchProviderBinding(f.provider)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := NewMinimalLaunchAuthorizer(authority, f.binding, []MinimalLaunchScope{{PolicyID: "owner-policy", Revision: 1, PrincipalID: "owner-principal", WorkerID: "owner-worker", HostID: "owner-host", TemplatePolicyID: "owner-template", WorkspacePolicyID: "owner-workspace", NetworkPolicyID: "owner-network"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authorizer.Close)
	f.selection, err = authorizer.ResolveSelection(context.Background(), principal, "owner-worker", MinimalLaunchSelectionHints{SandboxID: "owner-sandbox", ExecutionID: "owner-execution", SubmissionID: "owner-submission", RuntimeID: "owner-runtime", PlanID: "owner-plan", TemplatePolicyID: "owner-template", WorkspacePolicyID: "owner-workspace"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.selection.Close(); err != nil {
			t.Error(err)
		}
	})
	f.reservation, err = f.selection.Reserve(context.Background(), context.Background(), "owner-job", "owner-job-generation", "request-v2-"+strings.Repeat("a", 64), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.reservation.Revoke)
	f.identity = f.reservation.Identity()
	f.owner = &minimalLaunchOwnerRuntime{identity: f.identity}
	f.owner.finalize = func(context.Context) (MinimalLaunchCleanupReceipt, error) { return f.receipt(), nil }
	f.provider.owner = f.owner
	f.provider.recover = func(_ context.Context, id MinimalLaunchIdentity) (MinimalJobRuntimeOwner, error) {
		if id != f.identity {
			return nil, ErrMinimalLaunchUnavailable
		}
		return f.owner, nil
	}
	if err := f.reservation.ArmDispatch(context.Background(), f.identity); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *minimalLaunchOwnerFixture) start(t *testing.T, partial bool) *MinimalLaunchOwnerBinding {
	t.Helper()
	owner, err := f.binding.Start(f.reservation, f.selection, func() error { return nil })
	if owner == nil || owner.owner != f.owner || (partial && !errors.Is(err, ErrMinimalLaunchUnavailable)) || (!partial && err != nil) {
		t.Fatalf("actual Start fixture failed: %v", err)
	}
	return owner
}
func (f *minimalLaunchOwnerFixture) receipt() MinimalLaunchCleanupReceipt {
	return MinimalLaunchCleanupReceipt{Identity: f.identity, OwnerCommitID: strings.Repeat("A", 43), FinalizedRevision: 7}
}
func assertMinimalOwnerUnavailable(t *testing.T, receipt MinimalLaunchCleanupReceipt, err error) {
	t.Helper()
	if receipt != (MinimalLaunchCleanupReceipt{}) || !errors.Is(err, ErrMinimalLaunchUnavailable) || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("unusable result was not a zero receipt with sanitized failure: %v", err)
	}
}
