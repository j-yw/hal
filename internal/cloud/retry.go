package cloud

import (
	"context"
	"fmt"
	"math"
	"time"
)

// RetryConfig holds configuration for the retry scheduler.
type RetryConfig struct {
	// BaseDelay is the base delay for exponential backoff. Defaults to 30 seconds.
	BaseDelay time.Duration
	// MaxDelay is the maximum delay cap for backoff. Defaults to 30 minutes.
	MaxDelay time.Duration
	// IDFunc generates unique IDs for events. If nil, callers must provide
	// an alternative.
	IDFunc func() string
}

// RetryService handles deterministic retry transitions for failed runs.
// It evaluates whether a failed run is eligible for retry based on its
// failure code (via ClassifyFailure) and remaining attempt budget, then
// transitions the run through failed → retrying → queued.
type RetryService struct {
	store  Store
	config RetryConfig
}

// NewRetryService creates a new RetryService with the given store and config.
func NewRetryService(store Store, config RetryConfig) *RetryService {
	if config.BaseDelay == 0 {
		config.BaseDelay = 30 * time.Second
	}
	if config.MaxDelay == 0 {
		config.MaxDelay = 30 * time.Minute
	}
	return &RetryService{
		store:  store,
		config: config,
	}
}

// RetryResult holds the outcome of a retry evaluation for a single run.
type RetryResult struct {
	// Retried is true if the run was successfully transitioned to queued.
	Retried bool
	// BackoffDelay is the computed backoff delay for this retry attempt.
	BackoffDelay time.Duration
}

// EvaluateRetry checks whether a failed run should be retried and, if eligible,
// transitions it through failed → retrying → queued. The caller provides the
// failure code from the terminal attempt so the scheduler can classify retryability.
//
// A run is NOT eligible for retry when:
//   - The run is not in failed status
//   - The failure code is not retryable (per ClassifyFailure)
//   - The run has exhausted its max_attempts budget
func (s *RetryService) EvaluateRetry(ctx context.Context, runID string, failureCode FailureCode) (*RetryResult, error) {
	if runID == "" {
		return nil, fmt.Errorf("runID must not be empty")
	}

	run, err := s.store.GetRun(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("failed to get run: %w", err)
	}

	// Only failed runs can be retried.
	if run.Status != RunStatusFailed {
		return &RetryResult{Retried: false}, nil
	}

	// Check if the failure code is retryable.
	if !ClassifyFailure(failureCode) {
		return &RetryResult{Retried: false}, nil
	}

	// Check attempt budget.
	if run.AttemptCount >= run.MaxAttempts {
		return &RetryResult{Retried: false}, nil
	}

	// Compute backoff delay.
	backoff := s.computeBackoff(run.AttemptCount)

	// Transition failed → retrying.
	if err := s.store.TransitionRun(ctx, runID, RunStatusFailed, RunStatusRetrying); err != nil {
		return nil, fmt.Errorf("failed to transition run to retrying: %w", err)
	}

	// Emit retry_scheduled event.
	now := time.Now().UTC().Truncate(time.Second)
	eventID := ""
	if s.config.IDFunc != nil {
		eventID = s.config.IDFunc()
	}
	event := &Event{
		ID:        eventID,
		RunID:     runID,
		EventType: "retry_scheduled",
		CreatedAt: now,
	}
	// Best-effort: event failure should not block the retry transition.
	_ = s.store.InsertEvent(ctx, event)

	// Transition retrying → queued.
	if err := s.store.TransitionRun(ctx, runID, RunStatusRetrying, RunStatusQueued); err != nil {
		return nil, fmt.Errorf("failed to transition run to queued: %w", err)
	}

	return &RetryResult{Retried: true, BackoffDelay: backoff}, nil
}

// computeBackoff returns the exponential backoff delay for the given attempt count.
// Uses the formula: min(baseDelay * 2^(attempts-1), maxDelay).
func (s *RetryService) computeBackoff(attemptCount int) time.Duration {
	if attemptCount <= 0 {
		return s.config.BaseDelay
	}
	exp := math.Pow(2, float64(attemptCount-1))
	delay := time.Duration(float64(s.config.BaseDelay) * exp)
	if delay > s.config.MaxDelay {
		delay = s.config.MaxDelay
	}
	return delay
}
