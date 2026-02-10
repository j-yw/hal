package cloud

import (
	"context"
	"fmt"
	"time"
)

// CancellationConfig holds configuration for the cancellation service.
type CancellationConfig struct {
	// IDFunc generates unique IDs for events. If nil, callers must provide
	// an alternative.
	IDFunc func() string
}

// CancellationService enforces cancellation propagation for cloud runs.
// It provides two operations:
//   - RequestCancel sets the cancel_requested flag on a run so workers and
//     the claim query observe the intent.
//   - CheckAndCancel is called by the worker loop on every heartbeat interval
//     to detect cancel intent and terminate the active attempt.
type CancellationService struct {
	store  Store
	config CancellationConfig
}

// NewCancellationService creates a new CancellationService with the given store and config.
func NewCancellationService(store Store, config CancellationConfig) *CancellationService {
	return &CancellationService{
		store:  store,
		config: config,
	}
}

// RequestCancel sets the cancel_requested flag on a run. Returns ErrNotFound
// if the run does not exist. Idempotent — calling on an already
// cancel-requested or terminal-canceled run succeeds without error.
func (s *CancellationService) RequestCancel(ctx context.Context, runID string) error {
	if runID == "" {
		return fmt.Errorf("runID must not be empty")
	}

	return s.store.SetCancelIntent(ctx, runID)
}

// CheckAndCancelResult holds the outcome of a cancel check.
type CheckAndCancelResult struct {
	// Canceled is true if the attempt was terminated due to cancel intent.
	Canceled bool
}

// CheckAndCancel checks whether the run has cancel_requested set. If so, it
// marks the active attempt as canceled, transitions the run to canceled, emits
// a cancel_propagated event, and releases the auth lock. This method is
// designed to be called by the worker loop on every heartbeat interval.
//
// Returns a result indicating whether cancellation was applied. If the run
// does not have cancel_requested set, the result has Canceled=false and the
// method is a no-op.
func (s *CancellationService) CheckAndCancel(ctx context.Context, runID, attemptID, authProfileID string) (*CheckAndCancelResult, error) {
	if runID == "" {
		return nil, fmt.Errorf("runID must not be empty")
	}
	if attemptID == "" {
		return nil, fmt.Errorf("attemptID must not be empty")
	}
	if authProfileID == "" {
		return nil, fmt.Errorf("authProfileID must not be empty")
	}

	// Step 1: Check cancel intent on the run.
	run, err := s.store.GetRun(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("failed to get run: %w", err)
	}

	if !run.CancelRequested {
		return &CheckAndCancelResult{Canceled: false}, nil
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Step 2: Mark attempt as canceled.
	errCode := "canceled"
	errMsg := "canceled by operator request"
	if err := s.store.TransitionAttempt(ctx, attemptID, AttemptStatusCanceled, now, &errCode, &errMsg); err != nil {
		return nil, fmt.Errorf("failed to cancel attempt: %w", err)
	}

	// Step 3: Transition run to canceled.
	if err := s.store.TransitionRun(ctx, runID, run.Status, RunStatusCanceled); err != nil {
		return nil, fmt.Errorf("failed to transition run to canceled: %w", err)
	}

	// Step 4: Emit cancel_propagated event (best-effort).
	eventID := ""
	if s.config.IDFunc != nil {
		eventID = s.config.IDFunc()
	}
	event := &Event{
		ID:        eventID,
		RunID:     runID,
		AttemptID: &attemptID,
		EventType: "cancel_propagated",
		CreatedAt: now,
	}
	_ = s.store.InsertEvent(ctx, event)

	// Step 5: Release auth lock (best-effort, tolerate ErrNotFound).
	err = s.store.ReleaseAuthLock(ctx, authProfileID, runID, now)
	if err != nil && !IsNotFound(err) {
		return nil, fmt.Errorf("failed to release auth lock: %w", err)
	}

	return &CheckAndCancelResult{Canceled: true}, nil
}
