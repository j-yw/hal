package sandboxruntime

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMinimalReservationRequestCorrelationRemainsAfterLoss(t *testing.T) {
	for _, action := range []string{"revoke", "authority", "parent", "selection"} {
		t.Run(action, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			f, want := minimalRequestCorrelationFixture(t, parent, 750*time.Millisecond)
			waitMinimalReservationContext(t, f.reservation.Context())
			if f.reservation.OwnedContext().Err() != nil {
				t.Fatal("preparation expiry revoked owned lifetime")
			}
			if got, err := f.reservation.RequestCorrelation(); err != nil || got != want {
				t.Fatal("P erased original request correlation")
			}
			switch action {
			case "revoke":
				f.reservation.Revoke()
			case "authority":
				f.authorizer.Close()
			case "parent":
				cancel()
			case "selection":
				if err := f.selection.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if action != "selection" {
				waitMinimalReservationContext(t, f.reservation.OwnedContext())
			}
			if got, err := f.reservation.RequestCorrelation(); err != nil || got != want {
				t.Fatal("lost launch authority erased original correlation")
			}
			if _, err := f.reservation.ClaimLaunch(context.Background()); err == nil {
				t.Fatal("correlation observation revived claim authority")
			}
		})
	}
}

func TestMinimalReservationRequestCorrelationCopiesAndConcurrency(t *testing.T) {
	f, want := minimalRequestCorrelationFixture(t, context.Background(), time.Minute)
	copied := new(MinimalLaunchReservation)
	reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(f.reservation).Elem())
	if got, err := copied.RequestCorrelation(); got != (MinimalLaunchRequestCorrelation{}) || !errors.Is(err, ErrMinimalLaunchUnavailable) {
		t.Fatal("copy of populated original became usable")
	}
	const count = 12
	failures, done := make(chan struct{}, count), make(chan struct{})
	var tasks sync.WaitGroup
	for range count {
		tasks.Add(1)
		go func() {
			defer tasks.Done()
			for range 128 {
				got, err := f.reservation.RequestCorrelation()
				if err != nil || got != want {
					failures <- struct{}{}
					return
				}
				got.AdmissionGrantID, got.AdmissionGrantRevision = "copy-only", 0
				f.reservation.Revoke()
				f.authorizer.Close()
			}
		}()
	}
	go func() { tasks.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("correlation observers did not join")
	}
	if len(failures) != 0 {
		t.Fatal("concurrent revoke/observation replaced original values")
	}
}

func TestMinimalReservationRequestCorrelationParentDeadline(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	f, want := minimalRequestCorrelationFixture(t, parent, time.Minute)
	waitMinimalReservationContext(t, f.reservation.OwnedContext())
	if parent.Err() != context.DeadlineExceeded || f.reservation.Context().Err() != context.DeadlineExceeded {
		t.Fatal("fixture did not reach the original owner's earlier deadline")
	}
	if got, err := f.reservation.RequestCorrelation(); err != nil || got != want {
		t.Fatal("real owner deadline erased retained original request correlation")
	}
}

func TestMinimalReservationRequestCorrelationSyntaxAndRevision(t *testing.T) {
	_, selection, _, _ := minimalLaunchAttemptFixture(t)
	for _, fixture := range []struct {
		name, id string
		valid    bool
	}{
		{"trailing punctuation", "Grant._-", true}, {"internal dot", "a..b", true},
		{"uppercase", "GRANT", true}, {"128 bytes", strings.Repeat("g", 128), false},
		{"leading dot", ".grant", false}, {"leading dash", "-grant", false},
		{"slash", "grant/other", false}, {"backslash", `grant\other`, false},
		{"control", "grant\x00", false}, {"newline", "grant\n", false},
		{"unicode", "gránt", false}, {"space", "grant other", false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			// Equal credential/launch policy revisions are legitimate, not aliases.
			want := MinimalLaunchRequestCorrelation{fixture.id, 1}
			r, err := selection.Reserve(context.Background(), context.Background(), "syntax-job", "syntax-generation", "request-v2-"+strings.Repeat("c", 64), time.Now().Add(time.Minute), want)
			if r != nil {
				t.Cleanup(r.Revoke)
			}
			if !fixture.valid {
				if r != nil || !errors.Is(err, ErrMinimalLaunchUnavailable) {
					t.Fatal("invalid original ID became issued correlation")
				}
				return
			}
			if err != nil || r == nil {
				t.Fatal("valid ID/revision correlation rejected")
			}
			if got, err := r.RequestCorrelation(); err != nil || got != want || got.AdmissionGrantRevision != r.Identity().LaunchPolicyRevision {
				t.Fatal("valid original revision was substituted or rejected")
			}
		})
	}
}

func minimalRequestCorrelationFixture(t *testing.T, parent context.Context, budget time.Duration) (*minimalReservationLifetimeFixture, MinimalLaunchRequestCorrelation) {
	t.Helper()
	f := newMinimalReservationLifetimeFixture(t, parent, budget)
	want := MinimalLaunchRequestCorrelation{"retained-original-grant", 17}
	r, err := f.selection.Reserve(context.Background(), parent, "correlation-owned-job", "correlation-owned-generation", "request-v2-"+strings.Repeat("c", 64), f.deadline, want)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Revoke)
	if err := r.ArmDispatch(context.Background(), r.Identity()); err != nil {
		t.Fatal(err)
	}
	f.reservation = r
	f.start(t)
	return f, want
}
