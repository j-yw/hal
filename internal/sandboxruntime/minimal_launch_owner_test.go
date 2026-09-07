package sandboxruntime

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMinimalLaunchOwnerCleanupRejectsInvalidHandlesAndContexts(t *testing.T) {
	f := newMinimalLaunchOwnerFixture(t)
	owner := f.start(t, false)
	recovery, err := f.binding.BindRecovery(f.identity)
	if err != nil {
		t.Fatal(err)
	}
	// Copy only idle handles, through reflection so vet does not mistake this
	// deliberate invalid-handle probe for an operational mutex-copy pattern.
	copyOwner := new(MinimalLaunchOwnerBinding)
	reflect.ValueOf(copyOwner).Elem().Set(reflect.ValueOf(owner).Elem())
	copyRecovery := new(MinimalLaunchRecoveryBinding)
	reflect.ValueOf(copyRecovery).Elem().Set(reflect.ValueOf(recovery).Elem())
	for _, bad := range []*MinimalLaunchOwnerBinding{nil, {}, copyOwner} {
		r, err := bad.Finalize(context.Background())
		assertMinimalOwnerUnavailable(t, r, err)
	}
	for _, bad := range []*MinimalLaunchRecoveryBinding{nil, {}, copyRecovery} {
		o, err := bad.Recover(context.Background())
		if o != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) {
			t.Fatal("invalid recovery handle admitted")
		}
	}
	copyProvider := *f.binding
	for _, bad := range []*MinimalLaunchProviderBinding{nil, {}, &copyProvider} {
		if got, err := bad.BindRecovery(f.identity); got != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) {
			t.Fatal("invalid provider binding issued recovery")
		}
	}
	if got, err := NewMinimalLaunchProviderBinding((*minimalLaunchOwnerProvider)(nil)); got != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) {
		t.Fatal("typed-nil provider accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	var typedNil *minimalOwnerWaitContext
	for _, ctx := range []context.Context{nil, typedNil, canceled, expired} {
		r, err := owner.Finalize(ctx)
		assertMinimalOwnerUnavailable(t, r, err)
		if got, err := recovery.Recover(ctx); got != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) {
			t.Fatal("invalid caller entered recovery")
		}
	}
	if f.owner.finalizes.Load() != 0 || f.provider.recovers.Load() != 0 || f.owner.inspections.Load() != 1 {
		t.Fatal("invalid admission entered callbacks")
	}
	typedOwner := newMinimalLaunchOwnerFixture(t)
	typedOwner.provider.owner = nil
	if got, err := typedOwner.binding.Start(typedOwner.reservation, typedOwner.selection, func() error { return nil }); got != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) {
		t.Fatal("typed-nil Start owner was retained as authority")
	}
}

func TestMinimalLaunchOwnerCleanupFullIdentityAdmission(t *testing.T) {
	f := newMinimalLaunchOwnerFixture(t)
	typ := reflect.TypeOf(f.identity)
	for index := range typ.NumField() {
		name := typ.Field(index).Name
		values := []string{"", "-leading", ".leading", "_leading", "bad/value", "é", strings.Repeat("x", 65), strings.Repeat("x", 128)}
		if name == "LaunchPolicyRevision" {
			values = []string{"zero"}
		}
		if name == "RequestKey" {
			values = []string{"", "request-v2-" + strings.Repeat("A", 64), "request-v2-" + strings.Repeat("a", 63), "request-v2-" + strings.Repeat("g", 64)}
		}
		for n, value := range values {
			t.Run(name+" invalid "+strconv.Itoa(n), func(t *testing.T) {
				identity := f.identity
				field := reflect.ValueOf(&identity).Elem().Field(index)
				if field.Kind() == reflect.String {
					field.SetString(value)
				} else {
					field.SetUint(0)
				}
				got, err := f.binding.BindRecovery(identity)
				if got != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) {
					t.Fatal("malformed identity issued recovery handle")
				}
			})
		}
		if name == "RequestKey" || name == "LaunchPolicyRevision" {
			continue
		}
		for _, value := range []string{"Z", "Z" + strings.Repeat("_", 63)} {
			t.Run(name+" valid length "+strconv.Itoa(len(value)), func(t *testing.T) {
				identity := f.identity
				reflect.ValueOf(&identity).Elem().Field(index).SetString(value)
				expected := identity
				recovery, err := f.binding.BindRecovery(identity)
				if err != nil || recovery == nil {
					t.Fatal("valid selected boundary rejected")
				}
				identity.WorkerJobID = "caller-changed"
				if recovery.identity != expected {
					t.Fatal("caller mutation changed bound identity")
				}
			})
		}
	}
	duplicate := f.identity
	duplicate.JobGeneration = duplicate.WorkerJobID
	if got, err := f.binding.BindRecovery(duplicate); got != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) {
		t.Fatal("job/generation alias accepted")
	}
	if f.provider.recovers.Load() != 0 || f.provider.starts.Load() != 0 {
		t.Fatal("syntax admission called provider")
	}
}

func TestMinimalLaunchOwnerCleanupEveryOwnerIdentityFieldQuarantines(t *testing.T) {
	typ := reflect.TypeOf(MinimalLaunchIdentity{})
	for index := range typ.NumField() {
		t.Run(typ.Field(index).Name, func(t *testing.T) {
			f := newMinimalLaunchOwnerFixture(t)
			owner := f.start(t, false)
			bad := f.identity
			field := reflect.ValueOf(&bad).Elem().Field(index)
			if typ.Field(index).Name == "RequestKey" {
				field.SetString("request-v2-" + strings.Repeat("b", 64))
			} else if field.Kind() == reflect.String {
				field.SetString(field.String() + "x")
			} else {
				field.SetUint(field.Uint() + 1)
			}
			f.owner.inspect = func() MinimalLaunchIdentity { return bad }
			r, err := owner.Finalize(context.Background())
			assertMinimalOwnerUnavailable(t, r, err)
			f.owner.inspect = nil
			r, err = owner.Finalize(context.Background())
			assertMinimalOwnerUnavailable(t, r, err)
			if f.owner.finalizes.Load() != 0 || owner.owner != f.owner {
				t.Fatal("identity mismatch lost/quarantined wrong owner")
			}
		})
	}
}

func TestMinimalLaunchOwnerCleanupRechecksOwnerAfterFinalizer(t *testing.T) {
	for _, failure := range []string{"mismatch", "panic"} {
		t.Run(failure, func(t *testing.T) {
			f := newMinimalLaunchOwnerFixture(t)
			owner := f.start(t, false)
			f.owner.finalize = func(context.Context) (MinimalLaunchCleanupReceipt, error) {
				f.owner.inspect = func() MinimalLaunchIdentity {
					if failure == "panic" {
						panic("sensitive post-finalize identity")
					}
					return MinimalLaunchIdentity{}
				}
				return f.receipt(), nil
			}
			r, err := owner.Finalize(context.Background())
			assertMinimalOwnerUnavailable(t, r, err)
			f.owner.inspect = nil
			r, err = owner.Finalize(context.Background())
			assertMinimalOwnerUnavailable(t, r, err)
			if f.owner.finalizes.Load() != 1 {
				t.Fatal("post-finalization contradiction was repaired")
			}
		})
	}
}

func TestMinimalLaunchOwnerCleanupCallbacksRunUnlocked(t *testing.T) {
	for _, recoverMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "finalize", true: "recover"}[recoverMode], func(t *testing.T) {
			h := newMinimalCleanupTestHandle(t, recoverMode)
			check := func() {
				if !h.mutex().TryLock() {
					t.Error("callback held bookkeeping mutex")
					return
				}
				h.mutex().Unlock()
			}
			h.f.owner.inspect = func() MinimalLaunchIdentity { check(); return h.f.identity }
			h.callback(func(context.Context) error { check(); return nil })
			got := h.call(context.Background())
			if got.err != nil || !got.valid {
				t.Fatalf("unlocked callback failed: %v", got.err)
			}
		})
	}
}

// This context fixture keeps one fixed deadline. Err/Done notification is
// deliberately delayed; publication must still enforce the absolute deadline.
type minimalCleanupDeadlineContext struct {
	context.Context
	deadline time.Time
	observed chan struct{}
	once     sync.Once
}

func newMinimalCleanupDeadlineContext() *minimalCleanupDeadlineContext {
	return &minimalCleanupDeadlineContext{Context: context.Background(), deadline: time.Now().Add(250 * time.Millisecond), observed: make(chan struct{})}
}
func (ctx *minimalCleanupDeadlineContext) Deadline() (time.Time, bool) {
	ctx.once.Do(func() { close(ctx.observed) })
	return ctx.deadline, true
}
func (ctx *minimalCleanupDeadlineContext) expire() {
	if remaining := time.Until(ctx.deadline); remaining > 0 {
		timer := time.NewTimer(remaining)
		defer timer.Stop()
		<-timer.C
	}
}

func TestMinimalLaunchOwnerCleanupRechecksCallerAfterMutexAdmission(t *testing.T) {
	for _, recoverMode := range []bool{false, true} {
		for _, expired := range []bool{false, true} {
			t.Run(map[bool]string{false: "finalize", true: "recover"}[recoverMode]+map[bool]string{false: " canceled", true: " deadline"}[expired], func(t *testing.T) {
				h := newMinimalCleanupTestHandle(t, recoverMode)
				ctx := newMinimalCleanupDeadlineContext()
				base, cancel := context.WithCancel(context.Background())
				defer cancel()
				ctx.Context = base
				before := h.callbackEvents()
				h.mutex().Lock()
				locked := true
				done := make(chan minimalCleanupTestResult, 1)
				var calls sync.WaitGroup
				calls.Add(1)
				t.Cleanup(func() {
					if locked {
						h.mutex().Unlock()
					}
					calls.Wait()
				})
				go func() { defer calls.Done(); done <- h.call(ctx) }()
				select {
				case <-ctx.observed:
				case <-time.After(time.Second):
					t.Fatal("caller did not reach pre-lock check")
				}
				if expired {
					ctx.expire()
				} else {
					cancel()
				}
				h.mutex().Unlock()
				locked = false
				select {
				case got := <-done:
					if !errors.Is(got.err, ErrMinimalLaunchUnavailable) {
						t.Fatal("invalid caller produced usable result")
					}
				case <-time.After(time.Second):
					t.Fatal("callback admission did not return")
				}
				if h.callbackEvents() != before {
					t.Fatal("expired/canceled caller entered callback after waiting for mutex")
				}
			})
		}
	}
}

func TestMinimalLaunchOwnerCleanupAbsoluteDeadlineAfterCallback(t *testing.T) {
	for _, recoverMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "finalize", true: "recover"}[recoverMode], func(t *testing.T) {
			h := newMinimalCleanupTestHandle(t, recoverMode)
			ctx := newMinimalCleanupDeadlineContext()
			h.callback(func(context.Context) error { ctx.expire(); return nil })
			got := h.call(ctx)
			if !errors.Is(got.err, ErrMinimalLaunchUnavailable) || ctx.Err() != nil || h.callCount() != 1 {
				t.Fatal("absolute expiry was not checked after callback")
			}
			if recoverMode && (got.owner == nil || got.owner.owner != h.f.owner) {
				t.Fatal("expired recovery lost partial owner")
			}
		})
	}
	f := newMinimalLaunchOwnerFixture(t)
	owner := f.start(t, false)
	if r, err := owner.Finalize(context.Background()); err != nil || r != f.receipt() {
		t.Fatal("cache setup failed")
	}
	ctx := newMinimalCleanupDeadlineContext()
	f.owner.inspect = func() MinimalLaunchIdentity { ctx.expire(); return f.identity }
	r, err := owner.Finalize(ctx)
	assertMinimalOwnerUnavailable(t, r, err)
	if f.owner.finalizes.Load() != 1 {
		t.Fatal("cached deadline repeated cleanup")
	}
}

type minimalCleanupPausedDoneContext struct {
	context.Context
	entered, release chan struct{}
	once             sync.Once
}

func (ctx *minimalCleanupPausedDoneContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.entered) })
	<-ctx.release
	return ctx.Context.Done()
}

func TestMinimalLaunchOwnerCleanupWaiterKeepsOriginalAttempt(t *testing.T) {
	for _, recoverMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "finalize", true: "recover"}[recoverMode], func(t *testing.T) {
			h := newMinimalCleanupTestHandle(t, recoverMode)
			firstEntered, secondEntered := make(chan struct{}), make(chan struct{})
			firstRelease, secondRelease := make(chan struct{}), make(chan struct{})
			ctx := &minimalCleanupPausedDoneContext{Context: context.Background(), entered: make(chan struct{}), release: make(chan struct{})}
			var firstOnce, secondOnce, waitOnce sync.Once
			var calls sync.WaitGroup
			t.Cleanup(func() {
				firstOnce.Do(func() { close(firstRelease) })
				secondOnce.Do(func() { close(secondRelease) })
				waitOnce.Do(func() { close(ctx.release) })
				calls.Wait()
			})
			h.callback(func(context.Context) error {
				switch h.callCount() {
				case 1:
					close(firstEntered)
					<-firstRelease
					return errors.New("sensitive original failure")
				case 2:
					close(secondEntered)
					<-secondRelease
					return nil
				default:
					t.Error("unexpected extra callback")
					return ErrMinimalLaunchUnavailable
				}
			})
			launch := func(ctx context.Context) <-chan minimalCleanupTestResult {
				done := make(chan minimalCleanupTestResult, 1)
				calls.Add(1)
				go func() { defer calls.Done(); done <- h.call(ctx) }()
				return done
			}
			first := launch(context.Background())
			select {
			case <-firstEntered:
			case <-time.After(time.Second):
				t.Fatal("first attempt never entered")
			}
			waiter := launch(ctx)
			select {
			case <-ctx.entered:
			case <-time.After(time.Second):
				t.Fatal("waiter never captured pending attempt")
			}
			firstOnce.Do(func() { close(firstRelease) })
			select {
			case got := <-first:
				if !errors.Is(got.err, ErrMinimalLaunchUnavailable) {
					t.Fatal("first attempt failure lost")
				}
			case <-time.After(time.Second):
				t.Fatal("first attempt did not join")
			}
			second := launch(context.Background())
			select {
			case <-secondEntered:
			case <-time.After(time.Second):
				t.Fatal("explicit retry never entered")
			}
			waitOnce.Do(func() { close(ctx.release) })
			select {
			case got := <-waiter:
				if !errors.Is(got.err, ErrMinimalLaunchUnavailable) || got.owner != nil {
					t.Fatal("old waiter rebased onto later result")
				}
			case <-time.After(time.Second):
				t.Fatal("old waiter joined later in-flight attempt")
			}
			secondOnce.Do(func() { close(secondRelease) })
			select {
			case got := <-second:
				if got.err != nil || !got.valid {
					t.Fatal("second explicit attempt did not succeed")
				}
			case <-time.After(time.Second):
				t.Fatal("second attempt did not join")
			}
			if h.callCount() != 2 {
				t.Fatal("waiter started an extra attempt")
			}
		})
	}
}

// This small fixture selects the actual neutral method; it owns no runtime or
// proof. Ordinary RED fixtures still create every successful binding.
type minimalCleanupTestResult struct {
	valid bool
	owner *MinimalLaunchOwnerBinding
	err   error
}
type minimalCleanupTestHandle struct {
	f        *minimalLaunchOwnerFixture
	owner    *MinimalLaunchOwnerBinding
	recovery *MinimalLaunchRecoveryBinding
}

func newMinimalCleanupTestHandle(t *testing.T, recoverMode bool) *minimalCleanupTestHandle {
	h := &minimalCleanupTestHandle{f: newMinimalLaunchOwnerFixture(t)}
	if recoverMode {
		var err error
		h.recovery, err = h.f.binding.BindRecovery(h.f.identity)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		h.owner = h.f.start(t, false)
	}
	return h
}
func (h *minimalCleanupTestHandle) call(ctx context.Context) minimalCleanupTestResult {
	if h.recovery != nil {
		o, err := h.recovery.Recover(ctx)
		return minimalCleanupTestResult{valid: o != nil && o.owner == h.f.owner && o.identity == h.f.identity, owner: o, err: err}
	}
	r, err := h.owner.Finalize(ctx)
	return minimalCleanupTestResult{valid: r == h.f.receipt(), err: err}
}
func (h *minimalCleanupTestHandle) callback(fn func(context.Context) error) {
	if h.recovery != nil {
		h.f.provider.recover = func(ctx context.Context, id MinimalLaunchIdentity) (MinimalJobRuntimeOwner, error) {
			if id != h.f.identity {
				return nil, ErrMinimalLaunchUnavailable
			}
			if err := fn(ctx); err != nil {
				return nil, err
			}
			return h.f.owner, nil
		}
		return
	}
	h.f.owner.finalize = func(ctx context.Context) (MinimalLaunchCleanupReceipt, error) { return h.f.receipt(), fn(ctx) }
}
func (h *minimalCleanupTestHandle) mutex() *sync.Mutex {
	if h.recovery != nil {
		return &h.recovery.mu
	}
	return &h.owner.mu
}
func (h *minimalCleanupTestHandle) callCount() int32 {
	if h.recovery != nil {
		return h.f.provider.recovers.Load()
	}
	return h.f.owner.finalizes.Load()
}
func (h *minimalCleanupTestHandle) callbackEvents() int32 {
	return h.f.owner.inspections.Load() + h.f.owner.finalizes.Load() + h.f.provider.recovers.Load()
}
