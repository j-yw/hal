package sandboxruntime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// This control tests the injected fixture itself, not unavailable wrapper
// admission or trusted prior-daemon recovery authorization.
func TestMinimalLaunchRecoveryInjectedProviderControl(t *testing.T) {
	f := newMinimalLaunchOwnerFixture(t)
	got, err := f.provider.RecoverMinimalJob(context.Background(), f.identity)
	if err != nil || got != f.owner || got.Identity() != f.identity || f.provider.recovers.Load() != 1 {
		t.Fatal("injected recovery fixture did not return its exact original owner")
	}
	if f.provider.starts.Load() != 0 || f.owner.finalizes.Load() != 0 {
		t.Fatal("fixture recovery launched or finalized")
	}
	wrong := f.identity
	wrong.JobGeneration = "foreign-generation"
	got, err = f.provider.RecoverMinimalJob(context.Background(), wrong)
	if got != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) {
		t.Fatal("injected recovery fixture accepted another identity")
	}
}

func TestMinimalLaunchRecoveryRetainsPartialOwnerAndNeverReplacesIt(t *testing.T) {
	f := newMinimalLaunchOwnerFixture(t)
	f.provider.recover = func(_ context.Context, id MinimalLaunchIdentity) (MinimalJobRuntimeOwner, error) {
		if id != f.identity {
			t.Error("recovery remapped identity")
		}
		return f.owner, errors.New("sensitive partial recovery")
	}
	recovery := bindMinimalRecoveryFixture(t, f)
	owner, err := recovery.Recover(context.Background())
	if owner == nil || !errors.Is(err, ErrMinimalLaunchUnavailable) || owner.owner != f.owner || owner.identity != f.identity || owner.binding != f.binding {
		t.Fatalf("partial recovery did not retain the original owner plus error: %v", err)
	}
	f.provider.recover = func(context.Context, MinimalLaunchIdentity) (MinimalJobRuntimeOwner, error) {
		t.Error("retained recovery attempted a replacement provider lookup")
		return &minimalLaunchOwnerRuntime{identity: f.identity}, nil
	}
	for range 2 {
		again, againErr := recovery.Recover(context.Background())
		if again != owner || !errors.Is(againErr, ErrMinimalLaunchUnavailable) {
			t.Fatal("partial recovery changed its original outcome or owner")
		}
	}
	got, err := owner.Finalize(context.Background())
	if err != nil || got != f.receipt() || f.owner.finalizes.Load() != 1 || f.provider.recovers.Load() != 1 || f.provider.starts.Load() != 0 {
		t.Fatalf("exact partial recovery owner could not finalize: %v", err)
	}
	again, err := recovery.Recover(context.Background())
	if again != owner || !errors.Is(err, ErrMinimalLaunchUnavailable) {
		t.Fatal("Finalize manufactured successful recovery admission")
	}
}

func TestMinimalLaunchRecoveryIdentityQuarantineSurvivesRepair(t *testing.T) {
	for _, failure := range []string{"mismatch", "panic"} {
		t.Run(failure, func(t *testing.T) {
			f := newMinimalLaunchOwnerFixture(t)
			recovery := bindMinimalRecoveryFixture(t, f)
			f.owner.inspect = func() MinimalLaunchIdentity {
				if failure == "panic" {
					panic("sensitive recovered identity panic")
				}
				wrong := f.identity
				wrong.WorkerID = "foreign-worker"
				return wrong
			}
			owner, err := recovery.Recover(context.Background())
			if owner == nil || owner.owner != f.owner || !errors.Is(err, ErrMinimalLaunchUnavailable) {
				t.Fatal("wrong/panicking owner was lost instead of quarantined")
			}
			f.owner.inspect = nil
			got, err := owner.Finalize(context.Background())
			assertMinimalOwnerUnavailable(t, got, err)
			again, err := recovery.Recover(context.Background())
			if again != owner || !errors.Is(err, ErrMinimalLaunchUnavailable) || f.owner.finalizes.Load() != 0 || f.provider.recovers.Load() != 1 {
				t.Fatal("identity repair cleared quarantine or replaced the owner")
			}
		})
	}
}

func TestMinimalLaunchRecoveryRetriesUnownedUncertaintyOnly(t *testing.T) {
	for _, failure := range []string{"nil success", "typed nil", "error", "panic"} {
		t.Run(failure, func(t *testing.T) {
			f := newMinimalLaunchOwnerFixture(t)
			recovery := bindMinimalRecoveryFixture(t, f)
			f.provider.recover = func(context.Context, MinimalLaunchIdentity) (MinimalJobRuntimeOwner, error) {
				switch failure {
				case "typed nil":
					return (*minimalLaunchOwnerRuntime)(nil), nil
				case "error":
					return nil, errors.New("sensitive recovery failure")
				case "panic":
					panic("sensitive recovery panic")
				default:
					return nil, nil
				}
			}
			owner, err := recovery.Recover(context.Background())
			if owner != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) || f.provider.recovers.Load() != 1 {
				t.Fatal("unowned uncertainty was not a reached, unavailable recovery")
			}
			f.provider.recover = func(_ context.Context, id MinimalLaunchIdentity) (MinimalJobRuntimeOwner, error) {
				if id != f.identity {
					t.Error("retry replaced recovery identity")
				}
				return f.owner, nil
			}
			owner, err = recovery.Recover(context.Background())
			if err != nil || owner == nil || owner.owner != f.owner || owner.binding != f.binding || f.provider.recovers.Load() != 2 || f.provider.starts.Load() != 0 {
				t.Fatalf("retry did not recover through original provider: %v", err)
			}
		})
	}
}

func TestMinimalLaunchRecoveryCancellationRetainsReturnedOwner(t *testing.T) {
	f := newMinimalLaunchOwnerFixture(t)
	recovery := bindMinimalRecoveryFixture(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.provider.recover = func(context.Context, MinimalLaunchIdentity) (MinimalJobRuntimeOwner, error) {
		cancel()
		return f.owner, nil
	}
	owner, err := recovery.Recover(ctx)
	if owner == nil || owner.owner != f.owner || !errors.Is(err, ErrMinimalLaunchUnavailable) || f.provider.recovers.Load() != 1 {
		t.Fatal("late success after cancellation dropped partial ownership or became success")
	}
	again, err := recovery.Recover(context.Background())
	if again != owner || !errors.Is(err, ErrMinimalLaunchUnavailable) || f.provider.recovers.Load() != 1 {
		t.Fatal("late canceled recovery was silently repeated or blessed")
	}
	got, err := owner.Finalize(context.Background())
	if err != nil || got != f.receipt() {
		t.Fatalf("canceled recovery lost cleanup owner: %v", err)
	}
}

func TestMinimalLaunchRecoveryCanceledWaiterDoesNotReplaceJoinedAttempt(t *testing.T) {
	f := newMinimalLaunchOwnerFixture(t)
	recovery := bindMinimalRecoveryFixture(t, f)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var calls sync.WaitGroup
	t.Cleanup(func() { once.Do(func() { close(release) }); calls.Wait() })
	f.provider.recover = func(ctx context.Context, id MinimalLaunchIdentity) (MinimalJobRuntimeOwner, error) {
		close(entered)
		<-release
		if ctx.Err() != nil || id != f.identity {
			t.Error("waiter changed original recovery context/identity")
		}
		return f.owner, nil
	}
	type result struct {
		owner *MinimalLaunchOwnerBinding
		err   error
	}
	first := make(chan result, 1)
	calls.Add(1)
	go func() { defer calls.Done(); o, err := recovery.Recover(context.Background()); first <- result{o, err} }()
	select {
	case <-entered:
	case got := <-first:
		t.Fatalf("recovery returned before provider entry: %v", got.err)
	case <-time.After(time.Second):
		t.Fatal("recovery did not enter provider")
	}
	waitBase, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &minimalOwnerWaitContext{Context: waitBase, entered: make(chan struct{})}
	waiter := make(chan result, 1)
	calls.Add(1)
	go func() { defer calls.Done(); o, err := recovery.Recover(ctx); waiter <- result{o, err} }()
	select {
	case <-ctx.entered:
	case got := <-waiter:
		t.Fatalf("waiter returned before joining recovery: %v", got.err)
	case <-time.After(time.Second):
		t.Fatal("recovery waiter could not observe cancellation during callback")
	}
	cancel()
	select {
	case got := <-waiter:
		if got.owner != nil || !errors.Is(got.err, ErrMinimalLaunchUnavailable) {
			t.Fatal("canceled waiter manufactured an owner")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled waiter did not stop waiting")
	}
	if f.provider.recovers.Load() != 1 {
		t.Fatal("waiter started another recovery")
	}
	once.Do(func() { close(release) })
	select {
	case got := <-first:
		if got.err != nil || got.owner == nil || got.owner.owner != f.owner {
			t.Fatalf("owned recovery lost result: %v", got.err)
		}
		again, err := recovery.Recover(context.Background())
		if err != nil || again != got.owner || f.provider.recovers.Load() != 1 {
			t.Fatal("joined recovery did not retain one owner")
		}
	case <-time.After(time.Second):
		t.Fatal("owned recovery failed to join")
	}
}

func bindMinimalRecoveryFixture(t *testing.T, f *minimalLaunchOwnerFixture) *MinimalLaunchRecoveryBinding {
	t.Helper()
	recovery, err := f.binding.BindRecovery(f.identity)
	if err != nil || recovery == nil {
		t.Fatalf("original provider's recovery admission unavailable: %v", err)
	}
	if f.provider.recovers.Load() != 0 || f.provider.starts.Load() != 0 {
		t.Fatal("binding recovery invoked provider or started a runtime")
	}
	return recovery
}
