package cloud

import (
	"context"
	"fmt"
	"time"
)

// TimeoutConfig holds configuration for the timeout enforcement service.
type TimeoutConfig struct {
	// IDFunc generates unique IDs for events. If nil, callers must provide
	// an alternative.
	IDFunc func() string
}

// TimeoutService detects and fails runs that have exceeded their deadline_at.
// For each overdue run it transitions the run to failed and emits a run_timeout
// event.
type TimeoutService struct {
	store  Store
	config TimeoutConfig
}

// NewTimeoutService creates a new TimeoutService with the given store and config.
func NewTimeoutService(store Store, config TimeoutConfig) *TimeoutService {
	return &TimeoutService{
		store:  store,
		config: config,
	}
}

// TimeoutResult holds the outcome of a single timeout enforcement pass.
type TimeoutResult struct {
	// TimedOut is the number of runs that were successfully marked as failed.
	TimedOut int
	// Errors collects per-run errors for runs that could not be fully timed out.
	Errors []error
}

// EnforceTimeouts scans for non-terminal runs whose deadline_at has passed,
// transitions each to failed, and emits a run_timeout event.
func (s *TimeoutService) EnforceTimeouts(ctx context.Context, now time.Time) (*TimeoutResult, error) {
	overdue, err := s.store.ListOverdueRuns(ctx, now)
	if err != nil {
		return nil, fmt.Errorf("failed to list overdue runs: %w", err)
	}

	result := &TimeoutResult{}

	for _, run := range overdue {
		if err := s.timeoutRun(ctx, run, now); err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("run %s: %w", run.ID, err))
			continue
		}
		result.TimedOut++
	}

	return result, nil
}

// timeoutRun handles a single overdue run: transitions it to failed and emits
// a run_timeout event.
func (s *TimeoutService) timeoutRun(ctx context.Context, run *Run, now time.Time) error {
	// Determine the current status for the transition.
	// The run may be in queued, claimed, running, or retrying status.
	fromStatus := run.Status

	// Step 1: Transition run to failed.
	if err := s.store.TransitionRun(ctx, run.ID, fromStatus, RunStatusFailed); err != nil {
		return fmt.Errorf("failed to transition run to failed: %w", err)
	}

	// Step 2: Emit run_timeout event.
	eventID := ""
	if s.config.IDFunc != nil {
		eventID = s.config.IDFunc()
	}
	event := &Event{
		ID:        eventID,
		RunID:     run.ID,
		EventType: "run_timeout",
		CreatedAt: now,
	}
	if err := s.store.InsertEvent(ctx, event); err != nil {
		return fmt.Errorf("failed to insert run_timeout event: %w", err)
	}

	return nil
}
