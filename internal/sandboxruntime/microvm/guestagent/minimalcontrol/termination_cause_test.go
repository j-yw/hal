package minimalcontrol

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// The Context and its cause are real. Only scheduling is controlled: Value,
// Deadline and Done are forwarded unchanged; Err publishes cancellation before
// delegating. Cause-first code can snapshot nil and then observe fallback Err.
type terminationPublicationContext struct {
	context.Context
	cancel context.CancelCauseFunc
	cause  error
	once   sync.Once
}

func (ctx *terminationPublicationContext) Err() error {
	ctx.once.Do(func() { ctx.cancel(ctx.cause) })
	return ctx.Context.Err()
}

func TestTerminationCauseKeepsPublishedOwnerAndTimeout(t *testing.T) {
	for _, cause := range []error{ErrTimeout, ErrOwnerLost} {
		t.Run(cause.Error(), func(t *testing.T) {
			original, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			ctx := &terminationPublicationContext{Context: original, cancel: cancel, cause: cause}
			observed := terminationCause(ctx)
			select {
			case <-original.Done():
			default:
				t.Fatal("actual cancellation was not published")
			}
			if context.Cause(original) != cause || original.Err() != context.Canceled {
				t.Fatal("underlying real context did not retain the original cause")
			}
			if observed != cause {
				t.Fatalf("observed %v, retained original cause %v", observed, cause)
			}
		})
	}
}

func TestTerminationCauseConcurrentStandardContextPublication(t *testing.T) {
	for _, cause := range []error{ErrTimeout, ErrOwnerLost} {
		t.Run(cause.Error(), func(t *testing.T) {
			for iteration := range 1024 {
				ctx, cancel := context.WithCancelCause(context.Background())
				start, done := make(chan struct{}), make(chan struct{})
				go func() { <-start; cancel(cause); close(done) }()
				close(start)
				var observed error
				for observed == nil {
					observed = terminationCause(ctx)
					if observed == nil {
						runtime.Gosched()
					}
				}
				<-done // Join the real cancellation before any failure assertion.
				if observed != cause || context.Cause(ctx) != cause {
					t.Fatalf("iteration %d: observed %v, original cause %v", iteration, observed, context.Cause(ctx))
				}
			}
		})
	}
}

func TestTerminationCausePreservesStandardErrorsAndRedactsPrivateCauses(t *testing.T) {
	private := errors.New("private cancellation token/path canary")
	for _, mode := range []string{"active", "cancel", "deadline", "private-cancel", "private-deadline", "same-message", "wrapped-timeout", "joined-owner"} {
		t.Run(mode, func(t *testing.T) {
			var ctx context.Context
			want := error(context.Canceled)
			switch mode {
			case "active":
				ctx, want = context.Background(), nil
			case "deadline", "private-deadline":
				cause := error(context.DeadlineExceeded)
				if mode == "private-deadline" {
					cause = private
				}
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadlineCause(context.Background(), time.Now().Add(-time.Second), cause)
				defer cancel()
				want = context.DeadlineExceeded
			default:
				cause := error(context.Canceled)
				switch mode {
				case "private-cancel":
					cause = private
				case "same-message":
					cause = errors.New(ErrTimeout.Error())
				case "wrapped-timeout":
					cause = errors.Join(ErrTimeout, private)
				case "joined-owner":
					cause = errors.Join(ErrOwnerLost, private)
				}
				var cancel context.CancelCauseFunc
				ctx, cancel = context.WithCancelCause(context.Background())
				cancel(cause)
			}
			got := terminationCause(ctx)
			if got != want || errors.Is(got, private) || got != nil && strings.Contains(got.Error(), "private") {
				t.Fatalf("termination result lost standard identity or exposed private cause: %v", got)
			}
		})
	}
}
