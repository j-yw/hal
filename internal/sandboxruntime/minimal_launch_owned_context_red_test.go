package sandboxruntime

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These go through actual Reserve/Arm/Start/Claim. P expires before the first
// intended RED assertion; later cancellation checks are not RED evidence.
func TestMinimalReservationOwnedContextSurvivesPreparation(t *testing.T) {
	for _, action := range []string{"explicit revoke", "authorizer close", "parent cancel"} {
		t.Run(action, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := newMinimalReservationLifetimeFixture(t, parent, 750*time.Millisecond)
			f.start(t)
			owned := f.reservation.OwnedContext()
			waitMinimalReservationContext(t, f.reservation.Context())
			if !errors.Is(f.provider.ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("actual provider context lost its preparation deadline")
			}
			if owned == nil || owned.Err() != nil {
				t.Fatalf("preparation expiry canceled retained ownership before %s: %v", action, minimalReservationContextError(owned))
			}
			if _, ok := owned.Deadline(); ok {
				t.Fatal("deadline-free owner inherited preparation deadline")
			}
			switch action {
			case "explicit revoke":
				f.reservation.Revoke()
			case "authorizer close":
				f.authorizer.Close()
			case "parent cancel":
				cancel()
			}
			waitMinimalReservationContext(t, owned)
			if owned.Err() != context.Canceled || f.reservation.OwnedContext() != owned || f.provider.starts != 1 {
				t.Fatal("late revocation replaced the original lifetime or launch")
			}
			if _, err := f.reservation.ClaimLaunch(context.Background()); err == nil {
				t.Fatal("expired claimed reservation became reusable")
			}
		})
	}
}

func TestMinimalReservationOwnedContextPreservesParentDeadline(t *testing.T) {
	for _, shorter := range []bool{true, false} {
		name, lifetime := "earlier parent", 750*time.Millisecond
		if !shorter {
			name, lifetime = "later parent", 3*time.Second
		}
		t.Run(name, func(t *testing.T) {
			deadline := time.Now().Add(lifetime)
			parent, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			preparation := 2 * time.Second
			if !shorter {
				preparation = 750 * time.Millisecond
			}
			f := newMinimalReservationLifetimeFixture(t, parent, preparation)
			f.start(t)
			owned := f.reservation.OwnedContext()
			waitMinimalReservationContext(t, f.reservation.Context())
			if owned == nil {
				t.Fatal("original owned context missing")
			}
			if got, ok := owned.Deadline(); !ok || !got.Equal(deadline) {
				t.Fatalf("owned deadline = %v/%t, want original parent %v", got, ok, deadline)
			}
			if !shorter && owned.Err() != nil {
				t.Fatal("P expired the later actual owner deadline")
			}
			waitMinimalReservationContext(t, owned)
			if owned.Err() != context.DeadlineExceeded {
				t.Fatal("actual parent deadline was ignored or changed to cancellation")
			}
		})
	}
}

// Independent controls execute without depending on a post-P assertion.
func TestMinimalReservationOwnedContextControls(t *testing.T) {
	t.Run("provider context and parent values", func(t *testing.T) {
		type key struct{}
		parent := context.WithValue(context.Background(), key{}, "owned-value")
		f := newMinimalReservationLifetimeFixture(t, parent, time.Minute)
		f.start(t)
		if f.provider.ctx != f.reservation.Context() || f.provider.starts != 1 || f.provider.claim != f.reservation.Identity() {
			t.Fatal("provider did not receive the original preparation context and claim")
		}
		if got, ok := f.provider.ctx.Deadline(); !ok || !got.Equal(f.deadline) {
			t.Fatal("Start reset or removed the fixed preparation deadline")
		}
		if f.reservation.OwnedContext() == nil || f.reservation.OwnedContext().Value(key{}) != "owned-value" {
			t.Fatal("owned context discarded parent values")
		}
		f.reservation.Revoke()
		waitMinimalReservationContext(t, f.provider.ctx)
		waitMinimalReservationContext(t, f.reservation.OwnedContext())
	})
	t.Run("nil zero and copied handles", func(t *testing.T) {
		var absent *MinimalLaunchReservation
		if absent.OwnedContext() != nil || new(MinimalLaunchReservation).OwnedContext() != nil {
			t.Fatal("unissued reservation produced an owned context")
		}
		f := newMinimalReservationLifetimeFixture(t, context.Background(), time.Minute)
		copy := new(MinimalLaunchReservation)
		// Deliberate invalid handle copy before concurrent use, including self.
		reflect.ValueOf(copy).Elem().Set(reflect.ValueOf(f.reservation).Elem())
		if copy.OwnedContext() != nil || copy.Context() != nil {
			t.Fatal("copied reservation retained lifetime authority")
		}
		copy.Revoke()
		if f.reservation.Context().Err() != nil || f.reservation.OwnedContext().Err() != nil {
			t.Fatal("copied revoke canceled original")
		}
		f.start(t)
		original := f.reservation.OwnedContext()
		f.reservation.Revoke()
		f.reservation.Revoke()
		if f.reservation.OwnedContext() != original || original.Err() == nil {
			t.Fatal("repeated revoke replaced the lifetime")
		}
	})
	t.Run("initiating waiter is not owner", func(t *testing.T) {
		f := newMinimalReservationLifetimeFixture(t, context.Background(), time.Minute)
		f.waiterCancel()
		f.start(t)
		if f.provider.ctx.Err() != nil || f.reservation.OwnedContext().Err() != nil {
			t.Fatal("accepted reservation inherited request waiter cancellation")
		}
	})
	t.Run("expired or canceled issuance", func(t *testing.T) {
		f := newMinimalReservationLifetimeFixture(t, context.Background(), time.Minute)
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		for _, request := range []struct {
			caller, parent context.Context
			deadline       time.Time
		}{{canceled, context.Background(), time.Now().Add(time.Minute)}, {context.Background(), canceled, time.Now().Add(time.Minute)}, {context.Background(), context.Background(), time.Now().Add(-time.Second)}} {
			got, err := f.selection.Reserve(request.caller, request.parent, "rejected-job", "rejected-generation", "request-v2-"+strings.Repeat("b", 64), request.deadline)
			if got != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) {
				t.Fatal("unusable issuance produced a lifetime")
			}
		}
	})
	t.Run("preparation expiry still rejects arm claim and start", func(t *testing.T) {
		f := newMinimalReservationLifetimeFixture(t, context.Background(), 750*time.Millisecond)
		unarmed, err := f.selection.Reserve(context.Background(), context.Background(), "unarmed-lifetime-job", "unarmed-lifetime-generation", "request-v2-"+strings.Repeat("b", 64), f.deadline)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(unarmed.Revoke)
		waitMinimalReservationContext(t, f.reservation.Context())
		if unarmed.ArmDispatch(context.Background(), unarmed.Identity()) == nil {
			t.Fatal("expired unarmed preparation was armed")
		}
		if _, err := f.reservation.ClaimLaunch(context.Background()); err == nil {
			t.Fatal("expired armed preparation was claimed")
		}
		owner, err := f.binding.Start(f.reservation, f.selection, func() error { return nil })
		if owner != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) || f.provider.starts != 0 {
			t.Fatal("expired armed preparation entered provider")
		}
	})
}

type minimalReservationLifetimeFixture struct {
	binding      *MinimalLaunchProviderBinding
	authorizer   *MinimalLaunchAuthorizer
	selection    *MinimalLaunchPreparedSelection
	reservation  *MinimalLaunchReservation
	provider     *minimalReservationLifetimeProvider
	deadline     time.Time
	waiterCancel context.CancelFunc
}

type minimalReservationLifetimeProvider struct {
	minimalLaunchAttemptProvider
	ctx    context.Context
	claim  MinimalLaunchIdentity
	starts int
}

func (p *minimalReservationLifetimeProvider) StartMinimalJob(ctx context.Context, r *MinimalLaunchReservation, selected MinimalLaunchSelection) (MinimalJobRuntimeOwner, error) {
	p.ctx, p.starts = ctx, p.starts+1
	if selected != &p.minimalLaunchAttemptProvider {
		return nil, ErrMinimalLaunchUnavailable
	}
	id, err := r.ClaimLaunch(ctx)
	if err != nil {
		return nil, err
	}
	p.claim = id
	return &minimalLaunchOwnerRuntime{identity: id}, nil
}

func newMinimalReservationLifetimeFixture(t *testing.T, parent context.Context, preparation time.Duration) *minimalReservationLifetimeFixture {
	t.Helper()
	// Reuse only the valid issuer/selection values, not another reservation.
	authority, err := NewAuthenticatedWorkerPrincipalAuthority("lifetime-authority", "lifetime-authority-generation")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := authority.IssueAuthenticatedWorkerPrincipal("lifetime-principal", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	f := &minimalReservationLifetimeFixture{provider: &minimalReservationLifetimeProvider{}}
	f.provider.identity = MinimalLaunchSelectionIdentity{WorkerID: "lifetime-worker", HostID: "lifetime-host", RuntimeID: "lifetime-runtime", RuntimeGeneration: "lifetime-runtime-generation", PlanID: "lifetime-plan", TemplatePolicyID: "lifetime-template", WorkspacePolicyID: "lifetime-workspace", NetworkPolicyID: "lifetime-network"}
	f.binding, err = NewMinimalLaunchProviderBinding(f.provider)
	if err != nil {
		t.Fatal(err)
	}
	f.authorizer, err = NewMinimalLaunchAuthorizer(authority, f.binding, []MinimalLaunchScope{{PolicyID: "lifetime-policy", Revision: 1, PrincipalID: "lifetime-principal", WorkerID: "lifetime-worker", HostID: "lifetime-host", TemplatePolicyID: "lifetime-template", WorkspacePolicyID: "lifetime-workspace", NetworkPolicyID: "lifetime-network"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.authorizer.Close)
	f.selection, err = f.authorizer.ResolveSelection(context.Background(), principal, "lifetime-worker", MinimalLaunchSelectionHints{SandboxID: "lifetime-sandbox", ExecutionID: "lifetime-execution", SubmissionID: "lifetime-submission", RuntimeID: "lifetime-runtime", PlanID: "lifetime-plan", TemplatePolicyID: "lifetime-template", WorkspacePolicyID: "lifetime-workspace"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.selection.Close() })
	waiter, cancel := context.WithCancel(context.Background())
	f.waiterCancel = cancel
	t.Cleanup(cancel)
	f.deadline = time.Now().Add(preparation)
	f.reservation, err = f.selection.Reserve(waiter, parent, "lifetime-job", "lifetime-job-generation", "request-v2-"+strings.Repeat("a", 64), f.deadline)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.reservation.Revoke)
	if err := f.reservation.ArmDispatch(context.Background(), f.reservation.Identity()); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *minimalReservationLifetimeFixture) start(t *testing.T) {
	t.Helper()
	owner, err := f.binding.Start(f.reservation, f.selection, func() error { return nil })
	if err != nil || owner == nil || f.provider.ctx != f.reservation.Context() || f.provider.starts != 1 || f.provider.claim != f.reservation.Identity() {
		t.Fatalf("actual armed Start/Claim control failed: %v", err)
	}
}

func waitMinimalReservationContext(t *testing.T, ctx context.Context) {
	t.Helper()
	if ctx == nil {
		t.Fatal("missing original context")
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("context did not end within fixed test bound; watchdog is not cancellation proof")
	}
}

func minimalReservationContextError(ctx context.Context) error {
	if ctx == nil {
		return ErrMinimalLaunchUnavailable
	}
	return ctx.Err()
}
