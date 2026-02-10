package cloud

import (
	"context"
	"fmt"
	"time"
)

// ReconcilerConfig holds configuration for the stale-attempt reconciler.
type ReconcilerConfig struct {
	// IDFunc generates unique IDs for events. If nil, callers must provide
	// an alternative.
	IDFunc func() string
}

// ReconcilerService detects and closes stale attempts whose leases have
// expired. For each stale attempt it marks the attempt as terminal with
// error_code stale_attempt, emits a stale_attempt event, and releases the
// associated auth lock lease.
type ReconcilerService struct {
	store  Store
	config ReconcilerConfig
}

// NewReconcilerService creates a new ReconcilerService with the given store and config.
func NewReconcilerService(store Store, config ReconcilerConfig) *ReconcilerService {
	return &ReconcilerService{
		store:  store,
		config: config,
	}
}

// ReconcileResult holds the outcome of a single reconciliation pass.
type ReconcileResult struct {
	// Reconciled is the number of stale attempts that were successfully closed.
	Reconciled int
	// Errors collects per-attempt errors for attempts that could not be fully reconciled.
	Errors []error
}

// Reconcile scans for active attempts whose lease has expired before the
// given cutoff time, marks each as failed with error_code stale_attempt,
// emits a stale_attempt event, and releases the associated auth lock.
func (s *ReconcilerService) Reconcile(ctx context.Context, cutoff time.Time) (*ReconcileResult, error) {
	stale, err := s.store.ListStaleAttempts(ctx, cutoff)
	if err != nil {
		return nil, fmt.Errorf("failed to list stale attempts: %w", err)
	}

	result := &ReconcileResult{}

	for _, attempt := range stale {
		if err := s.reconcileAttempt(ctx, attempt, cutoff); err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("attempt %s: %w", attempt.ID, err))
			continue
		}
		result.Reconciled++
	}

	return result, nil
}

// reconcileAttempt handles a single stale attempt: marks it terminal,
// emits an event, and releases the auth lock.
func (s *ReconcilerService) reconcileAttempt(ctx context.Context, attempt *Attempt, now time.Time) error {
	// Step 1: Mark attempt as failed with error_code stale_attempt.
	errCode := string(FailureStaleAttempt)
	errMsg := "lease expired, attempt reclaimed by reconciler"
	if err := s.store.TransitionAttempt(ctx, attempt.ID, AttemptStatusFailed, now, &errCode, &errMsg); err != nil {
		return fmt.Errorf("failed to transition attempt: %w", err)
	}

	// Step 2: Emit stale_attempt event.
	eventID := ""
	if s.config.IDFunc != nil {
		eventID = s.config.IDFunc()
	}
	event := &Event{
		ID:        eventID,
		RunID:     attempt.RunID,
		AttemptID: &attempt.ID,
		EventType: "stale_attempt",
		CreatedAt: now,
	}
	if err := s.store.InsertEvent(ctx, event); err != nil {
		return fmt.Errorf("failed to insert stale_attempt event: %w", err)
	}

	// Step 3: Release the auth lock for this run.
	// Look up the run to get the auth_profile_id for lock release.
	run, err := s.store.GetRun(ctx, attempt.RunID)
	if err != nil {
		return fmt.Errorf("failed to get run for lock release: %w", err)
	}

	err = s.store.ReleaseAuthLock(ctx, run.AuthProfileID, attempt.RunID, now)
	if err != nil && !IsNotFound(err) {
		return fmt.Errorf("failed to release auth lock: %w", err)
	}

	return nil
}
