package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

func TestSelectedInspectionRejectsEveryMissingObservationAndRecoversFresh(t *testing.T) {
	for name, change := range map[string]func(*IsolationProofResult){
		"identity":       func(r *IsolationProofResult) { r.RestrictedIdentity = false },
		"capabilities":   func(r *IsolationProofResult) { r.CapabilitiesCleared = false },
		"privileges":     func(r *IsolationProofResult) { r.NoNewPrivileges = false },
		"groups":         func(r *IsolationProofResult) { r.SupplementaryGroupsCleared = false },
		"raw":            func(r *IsolationProofResult) { r.RawPacketSocketDenied = false },
		"network status": func(r *IsolationProofResult) { r.Network.Status = guestagent.IsolationProofStatusUnavailable },
		"interface":      func(r *IsolationProofResult) { r.Network.SingleInterface = false },
		"routes":         func(r *IsolationProofResult) { r.Network.StaticRoutes = false },
		"proxy":          func(r *IsolationProofResult) { r.Network.ProxyReachable = false },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newWorkloadDispatchFixture(t, true, func(_ context.Context, call int32) (IsolationProofResult, error) {
				result := l7VerifiedIsolationResult()
				if call == 2 {
					change(&result)
				}
				return result, nil
			})
			if fixture.server.PrepareWorkload(context.Background()) != nil {
				t.Fatal("initial preparation")
			}
			result, err := fixture.server.InspectWorkloadIsolation(context.Background())
			if err == nil || result != (IsolationProofResult{}) || fixture.server.isolationProven {
				t.Fatal("incomplete inspection escaped as proof")
			}
			result, err = fixture.server.InspectWorkloadIsolation(context.Background())
			if err != nil || result != l7VerifiedIsolationResult() || fixture.verifier.calls.Load() != 3 || fixture.backend.totalOperationCalls() != 1 {
				t.Fatal("fresh inspection failed to release prior permit or performed backend work")
			}
		})
	}
}

func TestSelectedInspectionSharesWorkPermitAndPreCanceledLosers(t *testing.T) {
	entered := make(chan struct{})
	fixture := newWorkloadDispatchFixture(t, true, func(ctx context.Context, call int32) (IsolationProofResult, error) {
		if call == 2 {
			close(entered)
			<-ctx.Done()
		}
		return l7VerifiedIsolationResult(), nil
	})
	if fixture.server.PrepareWorkload(context.Background()) != nil {
		t.Fatal("initial preparation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		result, err := fixture.server.InspectWorkloadIsolation(ctx)
		if result != (IsolationProofResult{}) {
			err = errors.New("late proof escaped")
		}
		done <- err
	}()
	defer func() {
		cancel()
		if done != nil {
			workloadDispatchWait(t, done)
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("inspection not entered")
	}
	if result, err := fixture.server.InspectWorkloadIsolation(context.Background()); !errors.Is(err, errServerBusy) || result != (IsolationProofResult{}) {
		t.Fatal("inspection bypassed shared permit")
	}
	l4RequireResponseCode(t, fixture.work.HandleWorkload(context.Background(), workloadDispatchExec(t, nil)), guestagent.ErrorCodeServerBusy)
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if result, err := fixture.server.InspectWorkloadIsolation(canceled); !errors.Is(err, context.Canceled) || result != (IsolationProofResult{}) {
		t.Fatal("pre-canceled inspection bypassed admission")
	}
	if fixture.verifier.calls.Load() != 2 || fixture.backend.totalOperationCalls() != 1 {
		t.Fatal("loser inspected or performed backend work")
	}
	cancel()
	err := workloadDispatchWait(t, done)
	done = nil
	if !errors.Is(err, context.Canceled) {
		t.Fatal("late canceled inspection did not return cancellation")
	}
	if result, err := fixture.server.InspectWorkloadIsolation(context.Background()); err != nil || result != l7VerifiedIsolationResult() {
		t.Fatal("admitted cancellation retained permit")
	}
}

func TestSelectedInspectionPanicSanitizesAndReleasesOriginalLifetime(t *testing.T) {
	fixture := newWorkloadDispatchFixture(t, true, func(_ context.Context, call int32) (IsolationProofResult, error) {
		if call == 2 {
			panic("private-inspection-panic")
		}
		return l7VerifiedIsolationResult(), nil
	})
	if fixture.server.PrepareWorkload(context.Background()) != nil {
		t.Fatal("initial preparation")
	}
	func() {
		defer func() {
			value := recover()
			if value != errServerNotReady || strings.Contains(value.(error).Error(), "private-") {
				t.Error("inspection panic was not fixed and sanitized")
			}
		}()
		fixture.server.InspectWorkloadIsolation(context.Background())
		t.Error("inspection panic did not reach selected transport boundary")
	}()
	if fixture.server.isolationProven {
		t.Fatal("panic retained cached proof")
	}
	if result, err := fixture.server.InspectWorkloadIsolation(context.Background()); err != nil || result != l7VerifiedIsolationResult() || fixture.backend.totalOperationCalls() != 1 {
		t.Fatal("panic retained operation permit or reached backend")
	}
}

func TestSelectedInspectionShutdownJoinsAndRejectsLateProof(t *testing.T) {
	entered, returned := make(chan struct{}), make(chan struct{})
	var agent *Server
	fixture := newWorkloadDispatchFixture(t, true, func(ctx context.Context, call int32) (IsolationProofResult, error) {
		if call == 2 {
			if agent.State() != StateServing {
				return IsolationProofResult{}, errors.New("state changed")
			}
			close(entered)
			<-ctx.Done()
			close(returned)
		}
		return l7VerifiedIsolationResult(), nil
	})
	agent = fixture.server
	if agent.PrepareWorkload(context.Background()) != nil {
		t.Fatal("initial preparation")
	}
	done := make(chan error, 1)
	go func() {
		result, err := agent.InspectWorkloadIsolation(context.Background())
		if result != (IsolationProofResult{}) {
			err = errors.New("late proof escaped")
		}
		done <- err
	}()
	defer func() {
		if done != nil {
			agent.Shutdown(context.Background())
			workloadDispatchWait(t, done)
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("inspection callback held state mutex")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if agent.Shutdown(ctx) != nil {
		t.Fatal("shutdown failed to join inspection")
	}
	select {
	case <-returned:
	default:
		t.Fatal("shutdown preceded trusted callback return")
	}
	err := workloadDispatchWait(t, done)
	done = nil
	if !errors.Is(err, errServerNotReady) || agent.isolationProven || fixture.backend.closeCalls.Load() != 1 {
		t.Fatal("shutdown retained inspection proof or backend ownership")
	}
}

func TestSelectedInspectionRejectsAbsentModeAndExpiredContext(t *testing.T) {
	var missing *Server
	if result, err := missing.InspectWorkloadIsolation(context.Background()); err == nil || result != (IsolationProofResult{}) {
		t.Fatal("nil server issued proof")
	}
	legacy := newWorkloadDispatchFixture(t, false, nil)
	if result, err := legacy.server.InspectWorkloadIsolation(context.Background()); err == nil || result != (IsolationProofResult{}) || legacy.backend.totalOperationCalls() != 0 {
		t.Fatal("legacy server gained inspection")
	}
	fixture := newWorkloadDispatchFixture(t, true, nil)
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	if result, err := fixture.server.InspectWorkloadIsolation(ctx); !errors.Is(err, context.DeadlineExceeded) || result != (IsolationProofResult{}) || fixture.verifier.calls.Load() != 0 {
		t.Fatal("expired inspection reached verifier")
	}
}

func TestSelectedInspectionLateCancelAndReturnedErrorClearProof(t *testing.T) {
	for _, failure := range []string{"returned error", "late cancel"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fixture := newWorkloadDispatchFixture(t, true, func(_ context.Context, call int32) (IsolationProofResult, error) {
				if call == 2 {
					if failure == "late cancel" {
						cancel()
					} else {
						return l7VerifiedIsolationResult(), errors.New("private-inspection-error")
					}
				}
				return l7VerifiedIsolationResult(), nil
			})
			if fixture.server.PrepareWorkload(context.Background()) != nil {
				t.Fatal("initial preparation")
			}
			result, err := fixture.server.InspectWorkloadIsolation(ctx)
			if err == nil || strings.Contains(err.Error(), "private-") || result != (IsolationProofResult{}) || fixture.server.isolationProven || fixture.backend.totalOperationCalls() != 1 {
				t.Fatal("failed current observation escaped as proof")
			}
		})
	}
}

func TestSelectedInspectionStaleResultCannotReplaceNewerFailedAttempt(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	fixture := newWorkloadDispatchFixture(t, true, func(_ context.Context, call int32) (IsolationProofResult, error) {
		if call == 2 {
			close(entered)
			<-release
		}
		if call == 3 {
			return IsolationProofResult{}, errors.New("newer observation failed")
		}
		return l7VerifiedIsolationResult(), nil
	})
	if fixture.server.PrepareWorkload(context.Background()) != nil {
		t.Fatal("initial preparation")
	}
	done := make(chan error, 1)
	go func() {
		result, err := fixture.server.InspectWorkloadIsolation(context.Background())
		if result != (IsolationProofResult{}) {
			err = errors.New("stale proof escaped")
		}
		done <- err
	}()
	released := false
	defer func() {
		if done != nil {
			if !released {
				close(release)
			}
			workloadDispatchWait(t, done)
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("inspection not reached")
	}
	if fixture.server.PrepareWorkload(context.Background()) == nil {
		t.Fatal("newer failed preparation passed")
	}
	close(release)
	released = true
	err := workloadDispatchWait(t, done)
	done = nil
	if !errors.Is(err, errServerNotReady) || fixture.server.isolationProven {
		t.Fatal("stale inspection replaced newer failed proof")
	}
}
