package sandboxruntime

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMinimalReservationRequestCorrelationReachesOriginalClaim(t *testing.T) {
	for _, value := range []MinimalLaunchRequestCorrelation{{"g", 7}, {strings.Repeat("G", 64), ^uint64(0)}} {
		t.Run(value.AdmissionGrantID, func(t *testing.T) {
			f := newMinimalReservationLifetimeFixture(t, context.Background(), time.Minute)
			original := value
			args := []MinimalLaunchRequestCorrelation{value}
			r, err := f.selection.Reserve(context.Background(), context.Background(), "correlation-job", "correlation-generation", "request-v2-"+strings.Repeat("b", 64), f.deadline, args...)
			if err != nil || r == nil {
				t.Fatalf("valid original correlation could not reserve: %v", err)
			}
			t.Cleanup(r.Revoke)
			args[0] = MinimalLaunchRequestCorrelation{"caller-replacement", 99}
			if err := r.ArmDispatch(context.Background(), r.Identity()); err != nil {
				t.Fatal(err)
			}
			f.reservation = r
			f.start(t) // Actual original binding/provider Claim, not decoded metadata.
			got, err := r.RequestCorrelation()
			if err != nil || got != original {
				t.Fatalf("claimed reservation lost original request correlation: got=%+v err=%v", got, err)
			}
			if got.AdmissionGrantID == r.Identity().LaunchGrantID || got.AdmissionGrantRevision == r.Identity().LaunchPolicyRevision {
				t.Fatal("fixture did not distinguish credential and launch correlation")
			}
			got.AdmissionGrantID, got.AdmissionGrantRevision = "returned-copy", 101
			r.Revoke()
			f.authorizer.Close()
			if err := f.selection.Close(); err != nil {
				t.Fatal(err)
			}
			if after, err := r.RequestCorrelation(); err != nil || after != original {
				t.Fatal("revoked exact owner lost its original correlation")
			}
		})
	}
}

func TestMinimalReservationRequestCorrelationRejectsExplicitInvalid(t *testing.T) {
	for _, fixture := range []struct {
		name string
		args []MinimalLaunchRequestCorrelation
	}{
		{"explicit zero", []MinimalLaunchRequestCorrelation{{}}},
		{"missing ID", []MinimalLaunchRequestCorrelation{{AdmissionGrantRevision: 1}}},
		{"missing revision", []MinimalLaunchRequestCorrelation{{AdmissionGrantID: "grant"}}},
		{"multiple values", []MinimalLaunchRequestCorrelation{{"first", 1}, {"second", 2}}},
		{"leading punctuation", []MinimalLaunchRequestCorrelation{{"_grant", 1}}},
		{"whitespace", []MinimalLaunchRequestCorrelation{{"grant ", 1}}},
		{"65 bytes", []MinimalLaunchRequestCorrelation{{strings.Repeat("g", 65), 1}}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			_, selection, _, provider := minimalLaunchAttemptFixture(t)
			r, err := selection.Reserve(context.Background(), context.Background(), "invalid-job", "invalid-generation", "request-v2-"+strings.Repeat("b", 64), time.Now().Add(time.Minute), fixture.args...)
			if r != nil {
				t.Cleanup(r.Revoke)
			}
			if !errors.Is(err, ErrMinimalLaunchUnavailable) || r != nil || provider.calls.Load() != 0 {
				t.Fatal("invalid explicit correlation issued a reservation")
			}
		})
	}
}

func TestMinimalReservationRequestCorrelationCompatibilityControls(t *testing.T) {
	f := newMinimalReservationLifetimeFixture(t, context.Background(), time.Minute)
	f.start(t) // Existing omitted-argument path remains independently operational.
	copied := new(MinimalLaunchReservation)
	reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(f.reservation).Elem())
	for _, fixture := range []struct {
		name string
		r    *MinimalLaunchReservation
	}{{"nil", nil}, {"zero", new(MinimalLaunchReservation)}, {"copy", copied}, {"original omitted", f.reservation}} {
		t.Run(fixture.name, func(t *testing.T) {
			got, err := fixture.r.RequestCorrelation()
			if got != (MinimalLaunchRequestCorrelation{}) || !errors.Is(err, ErrMinimalLaunchUnavailable) {
				t.Fatal("missing original request correlation became consumable")
			}
		})
	}
	if f.reservation.Context().Err() != nil || f.reservation.OwnedContext().Err() != nil || f.provider.starts != 1 {
		t.Fatal("unavailable observation changed existing ownership")
	}
}
