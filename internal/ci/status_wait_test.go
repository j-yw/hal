package ci

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestWaitForChecksWithDeps_DefaultOptions(t *testing.T) {
	t.Parallel()

	pollInterval := time.Duration(0)
	afterDurations := make([]time.Duration, 0, 2)
	ticker := &fakeWaitTicker{ch: make(chan time.Time, 1)}

	result, err := waitForChecksWithDeps(context.Background(), WaitOptions{}, waitForChecksDeps{
		getStatus: func(context.Context) (StatusResult, error) {
			return StatusResult{Status: StatusPassing, ChecksDiscovered: true}, nil
		},
		newTicker: func(d time.Duration) waitTicker {
			pollInterval = d
			return ticker
		},
		after: func(d time.Duration) <-chan time.Time {
			afterDurations = append(afterDurations, d)
			return make(chan time.Time)
		},
	})
	if err != nil {
		t.Fatalf("waitForChecksWithDeps() error = %v", err)
	}

	if pollInterval != defaultWaitPollInterval {
		t.Fatalf("poll interval = %s, want %s", pollInterval, defaultWaitPollInterval)
	}
	if !reflect.DeepEqual(afterDurations, []time.Duration{defaultWaitTimeout, defaultNoChecksGrace}) {
		t.Fatalf("after durations = %v, want [%s %s]", afterDurations, defaultWaitTimeout, defaultNoChecksGrace)
	}
	if !result.Wait {
		t.Fatal("result.Wait = false, want true")
	}
	if result.WaitTerminalReason != WaitTerminalReasonCompleted {
		t.Fatalf("result.WaitTerminalReason = %q, want %q", result.WaitTerminalReason, WaitTerminalReasonCompleted)
	}
	if !ticker.stopped {
		t.Fatal("ticker.Stop() was not called")
	}
}

func TestWaitForChecksWithDeps_Completed(t *testing.T) {
	t.Parallel()

	opts := WaitOptions{
		PollInterval:  time.Second,
		Timeout:       time.Minute,
		NoChecksGrace: 5 * time.Second,
	}
	calls := 0
	afterCalls := 0
	timeoutCh := make(chan time.Time, 1)
	noChecksCh := make(chan time.Time, 1)
	ticker := &fakeWaitTicker{ch: make(chan time.Time, 1)}
	ticker.ch <- time.Now()

	result, err := waitForChecksWithDeps(context.Background(), opts, waitForChecksDeps{
		getStatus: func(context.Context) (StatusResult, error) {
			calls++
			switch calls {
			case 1:
				return StatusResult{Status: StatusPending, ChecksDiscovered: true}, nil
			case 2:
				return StatusResult{Status: StatusPassing, ChecksDiscovered: true}, nil
			default:
				t.Fatalf("unexpected extra status poll #%d", calls)
				return StatusResult{}, nil
			}
		},
		newTicker: func(d time.Duration) waitTicker {
			if d != opts.PollInterval {
				t.Fatalf("poll interval = %s, want %s", d, opts.PollInterval)
			}
			return ticker
		},
		after: func(d time.Duration) <-chan time.Time {
			afterCalls++
			switch afterCalls {
			case 1:
				if d != opts.Timeout {
					t.Fatalf("timeout duration = %s, want %s", d, opts.Timeout)
				}
				return timeoutCh
			case 2:
				if d != opts.NoChecksGrace {
					t.Fatalf("no-checks grace = %s, want %s", d, opts.NoChecksGrace)
				}
				return noChecksCh
			default:
				t.Fatalf("unexpected after() call #%d", afterCalls)
				return make(chan time.Time)
			}
		},
	})
	if err != nil {
		t.Fatalf("waitForChecksWithDeps() error = %v", err)
	}

	if result.Status != StatusPassing {
		t.Fatalf("result.Status = %q, want %q", result.Status, StatusPassing)
	}
	if result.WaitTerminalReason != WaitTerminalReasonCompleted {
		t.Fatalf("result.WaitTerminalReason = %q, want %q", result.WaitTerminalReason, WaitTerminalReasonCompleted)
	}
	if !result.Wait {
		t.Fatal("result.Wait = false, want true")
	}
	if calls != 2 {
		t.Fatalf("status polls = %d, want 2", calls)
	}
	if !ticker.stopped {
		t.Fatal("ticker.Stop() was not called")
	}
}

func TestWaitForChecksWithDeps_Timeout(t *testing.T) {
	t.Parallel()

	opts := WaitOptions{
		PollInterval:  time.Second,
		Timeout:       2 * time.Minute,
		NoChecksGrace: 5 * time.Second,
	}
	calls := 0
	afterCalls := 0
	timeoutCh := make(chan time.Time, 1)
	timeoutCh <- time.Now()
	noChecksCh := make(chan time.Time, 1)
	ticker := &fakeWaitTicker{ch: make(chan time.Time, 1)}

	result, err := waitForChecksWithDeps(context.Background(), opts, waitForChecksDeps{
		getStatus: func(context.Context) (StatusResult, error) {
			calls++
			return StatusResult{Status: StatusPending, ChecksDiscovered: true}, nil
		},
		newTicker: func(d time.Duration) waitTicker {
			if d != opts.PollInterval {
				t.Fatalf("poll interval = %s, want %s", d, opts.PollInterval)
			}
			return ticker
		},
		after: func(d time.Duration) <-chan time.Time {
			afterCalls++
			switch afterCalls {
			case 1:
				if d != opts.Timeout {
					t.Fatalf("timeout duration = %s, want %s", d, opts.Timeout)
				}
				return timeoutCh
			case 2:
				if d != opts.NoChecksGrace {
					t.Fatalf("no-checks grace = %s, want %s", d, opts.NoChecksGrace)
				}
				return noChecksCh
			default:
				t.Fatalf("unexpected after() call #%d", afterCalls)
				return make(chan time.Time)
			}
		},
	})
	if err != nil {
		t.Fatalf("waitForChecksWithDeps() error = %v", err)
	}

	if result.WaitTerminalReason != WaitTerminalReasonTimeout {
		t.Fatalf("result.WaitTerminalReason = %q, want %q", result.WaitTerminalReason, WaitTerminalReasonTimeout)
	}
	if result.Status != StatusPending {
		t.Fatalf("result.Status = %q, want %q", result.Status, StatusPending)
	}
	if !result.Wait {
		t.Fatal("result.Wait = false, want true")
	}
	if calls != 1 {
		t.Fatalf("status polls = %d, want 1", calls)
	}
	if !ticker.stopped {
		t.Fatal("ticker.Stop() was not called")
	}
}

func TestWaitForChecksWithDeps_NoChecksDetected(t *testing.T) {
	t.Parallel()

	opts := WaitOptions{
		PollInterval:  time.Second,
		Timeout:       2 * time.Minute,
		NoChecksGrace: 5 * time.Second,
	}
	calls := 0
	afterCalls := 0
	timeoutCh := make(chan time.Time, 1)
	noChecksCh := make(chan time.Time, 1)
	noChecksCh <- time.Now()
	ticker := &fakeWaitTicker{ch: make(chan time.Time, 1)}

	result, err := waitForChecksWithDeps(context.Background(), opts, waitForChecksDeps{
		getStatus: func(context.Context) (StatusResult, error) {
			calls++
			return StatusResult{Status: StatusPending, ChecksDiscovered: false}, nil
		},
		newTicker: func(d time.Duration) waitTicker {
			if d != opts.PollInterval {
				t.Fatalf("poll interval = %s, want %s", d, opts.PollInterval)
			}
			return ticker
		},
		after: func(d time.Duration) <-chan time.Time {
			afterCalls++
			switch afterCalls {
			case 1:
				if d != opts.Timeout {
					t.Fatalf("timeout duration = %s, want %s", d, opts.Timeout)
				}
				return timeoutCh
			case 2:
				if d != opts.NoChecksGrace {
					t.Fatalf("no-checks grace = %s, want %s", d, opts.NoChecksGrace)
				}
				return noChecksCh
			default:
				t.Fatalf("unexpected after() call #%d", afterCalls)
				return make(chan time.Time)
			}
		},
	})
	if err != nil {
		t.Fatalf("waitForChecksWithDeps() error = %v", err)
	}

	if result.WaitTerminalReason != WaitTerminalReasonNoChecksDetected {
		t.Fatalf("result.WaitTerminalReason = %q, want %q", result.WaitTerminalReason, WaitTerminalReasonNoChecksDetected)
	}
	if result.Status != StatusPending {
		t.Fatalf("result.Status = %q, want %q", result.Status, StatusPending)
	}
	if result.ChecksDiscovered {
		t.Fatal("result.ChecksDiscovered = true, want false")
	}
	if !result.Wait {
		t.Fatal("result.Wait = false, want true")
	}
	if calls != 2 {
		t.Fatalf("status polls = %d, want 2 (initial + no-check confirmation)", calls)
	}
	if !ticker.stopped {
		t.Fatal("ticker.Stop() was not called")
	}
}

type fakeWaitTicker struct {
	ch      chan time.Time
	stopped bool
}

func (t *fakeWaitTicker) Chan() <-chan time.Time {
	return t.ch
}

func (t *fakeWaitTicker) Stop() {
	t.stopped = true
}
