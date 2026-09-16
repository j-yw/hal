package server

import (
	"context"
	"errors"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

func TestSelectedInspectionOriginalCanceledPanicPrecedence(t *testing.T) {
	for _, prepare := range []bool{false, true} {
		t.Run(map[bool]string{false: "original work", true: "original prepare"}[prepare], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fixture := newWorkloadDispatchFixture(t, true, func(context.Context, int32) (IsolationProofResult, error) {
				cancel()
				panic("private-canceled-inspector-panic")
			})
			if prepare {
				if err := fixture.server.PrepareWorkload(ctx); !errors.Is(err, context.Canceled) {
					t.Error("original Prepare lost cancellation precedence after actual callback panic")
				}
			} else {
				l4RequireResponseCode(t, fixture.work.HandleWorkload(ctx, workloadDispatchExec(t, nil)), guestagent.ErrorCodeRequestCanceled)
			}
			if fixture.verifier.calls.Load() != 1 || fixture.server.isolationProven || fixture.backend.execCalls.Load() != 0 {
				t.Fatal("canceled panic did not reach actual verifier or retained proof/work")
			}
		})
	}
}
